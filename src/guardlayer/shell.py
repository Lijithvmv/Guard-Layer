"""What a shell command actually runs: a small, dependency-free structural view of a command line.

Rules that search the raw text of a command can't tell a command from data: `rm -rf /` inside a Python test string, a
`.env` named in an `echo` or a commit message, and a grep pattern all look like actions. Claude Code and Codex decide on
the *parsed* command instead (subcommands, wrappers, file operands, redirect targets), and fall back to caution when
parsing fails. This module does the same for GuardLayer's rules:

* splits a command into simple commands on `;`, `&&`, `||`, `|`, `&`, newlines and subshell brackets, keeping pipelines;
* pulls out heredocs, `$( )` and backtick substitutions, and analyses substitutions as commands;
* strips wrappers that run their arguments (`timeout`, `nice`, `nohup`, `env`, `sudo`, bare `xargs`, ...);
* recurses into scripts given to `bash -c`, `sh -c`, `eval`, and into Python code given to `python -c` or fed by
  heredoc: Python is parsed with `ast`, and only strings passed to `os.system`, `os.popen` or `subprocess.*` count as
  commands; other string literals are data;
* drops arguments that are data, not actions: `echo`/`printf` text, `git commit -m` messages, grep patterns, the word
  list of a `for` loop, heredoc bodies written to a file.

`analyse()` returns None when it can't parse the command; callers then keep their text rules (fail safe). The result is
a text in which each line is one executed command (pipelines joined with ` | `), so existing rules can run on it.
"""

from __future__ import annotations

import ast
import re
import shlex
from dataclasses import dataclass, field

MAX_COMMAND = 20_000  # longer commands aren't analysed (callers fall back to text rules)
MAX_DEPTH = 6

_HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_SEPARATORS = {";", "&&", "||", "&", "\n", "(", ")", ";;"}
_PIPES = {"|", "|&"}
_REDIRECTS = {">", ">>", "<", "<>", ">|", "&>", "&>>", ">&", "<&", "<<<"}
# `sudo`/`doas` are NOT wrappers here: they change privilege, so they stay in the text the rules see.
_WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob", "exec", "env", "xargs"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_PYTHONS = re.compile(r"^(python|python3|python3\.\d+|py|python\.exe|python3\.exe)$")
_DATA_ONLY = {"echo", "printf", "true", ":"}
_GREP_LIKE = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "findstr", "Select-String"}
_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "case", "esac", "function", "!", "{", "}"}
_PY_NETWORK = {"requests", "urllib", "urllib3", "http", "httpx", "aiohttp", "socket", "smtplib", "ftplib", "paramiko", "websocket", "websockets"}
_PY_EXEC_CALLS = {"system", "popen", "run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}


@dataclass
class Command:
    argv: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)  # (operator, target)
    stdin_from: str | None = None  # program whose output is piped into this one


@dataclass
class ShellView:
    commands: list[list[Command]]  # pipelines

    def text(self) -> str:
        """One line per pipeline; commands in a pipeline joined by ' | '; redirects kept."""
        lines = []
        for pipeline in self.commands:
            parts = []
            for cmd in pipeline:
                words = list(cmd.argv) + [f"{op} {target}" for op, target in cmd.redirects]
                parts.append(" ".join(words))
            if parts:
                lines.append(" | ".join(parts))
        return "\n".join(lines)


def _program(word: str) -> str:
    name = re.split(r"[/\\]", word)[-1]
    return name[:-4] if name.lower().endswith(".exe") else name


def _extract_heredocs(src: str) -> tuple[str, list[tuple[int, str]]]:
    """Remove heredoc bodies; return the command text and (position of the `<<`, body) pairs."""
    bodies: list[tuple[int, str]] = []
    lines = src.split("\n")
    rebuilt: list[str] = []
    pending: list[tuple[str, bool, int]] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        for m in _HEREDOC.finditer(line):
            pending.append((m.group(3), m.group(1) == "-", len("\n".join(rebuilt)) + m.start()))
        rebuilt.append(line)
        idx += 1
        while pending:
            word, strip_tabs, pos = pending.pop(0)
            body = []
            while idx < len(lines):
                candidate = lines[idx].lstrip("\t") if strip_tabs else lines[idx]
                idx += 1
                if candidate.strip() == word:
                    break
                body.append(lines[idx - 1])
            bodies.append((pos, "\n".join(body)))
    return "\n".join(rebuilt), bodies


def _extract_substitutions(src: str) -> tuple[str, list[str]]:
    """Replace `$( )` and backtick substitutions with a placeholder word; return the inner scripts."""
    subs: list[str] = []
    out: list[str] = []
    i, n = 0, len(src)
    quote: str | None = None
    while i < n:
        ch = src[i]
        if quote == "'":
            out.append(ch)
            if ch == "'":
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(src[i : i + 2])
            i += 2
            continue
        if ch == "'" and quote is None:
            quote = "'"
        elif ch == '"':
            quote = None if quote == '"' else '"'
        if src.startswith("$(", i) and not src.startswith("$((", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src[j] == "(":
                    depth += 1
                elif src[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                raise ValueError("unbalanced $(")
            subs.append(src[i + 2 : j - 1])
            out.append("__SUBST__")
            i = j
            continue
        if ch == "`":
            j = src.find("`", i + 1)
            if j < 0:
                raise ValueError("unbalanced backtick")
            subs.append(src[i + 1 : j])
            out.append("__SUBST__")
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), subs


_OPERATORS = ("<<<", "&>>", "&&", "||", "|&", ";;", ">>", "<<", ">&", "<&", "&>", ">|", "<>", ";", "&", "|", "(", ")", "<", ">", "\n")


def _split_operators(tok: str) -> list[str]:
    """shlex returns a run of punctuation as one token (';\\n', '|\\n'): split it into shell operators."""
    out, i = [], 0
    while i < len(tok):
        op = next((o for o in _OPERATORS if tok.startswith(o, i)), tok[i])
        out.append(op)
        i += len(op)
    return out


def _tokens(src: str) -> list[str]:
    # A newline ends a command just like ';'. It must be a punctuation character, not whitespace: shlex otherwise glues
    # the next line onto a word that ends in a quote ('echo "a"\\nrm -rf /' became one echo argument).
    src = re.sub(r"\\\r?\n", " ", src)  # line continuations join lines
    lex = shlex.shlex(src, posix=True, punctuation_chars=";&|()<>\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = "#"
    toks: list[str] = []
    for tok in lex:
        for part in _split_operators(tok) if tok and all(ch in ";&|()<>\n" for ch in tok) else [tok]:
            if part == "\n" and toks and toks[-1] in ("|", "|&", "&&", "||", "\n"):
                continue  # a newline after a pipe or && / || continues the command
            toks.append(part)
    return toks


def _strip_wrappers(argv: list[str]) -> list[str]:
    for _ in range(MAX_DEPTH):
        if not argv:
            return argv
        prog = _program(argv[0])
        if prog not in _WRAPPERS:
            return argv
        rest = argv[1:]
        if prog == "xargs" and rest and rest[0].startswith("-"):
            return argv  # xargs with flags: judged as itself
        if prog == "env":
            while rest and ("=" in rest[0] and not rest[0].startswith("-") or rest[0].startswith("-")):
                rest = rest[1:]
        elif prog == "timeout":
            while rest and rest[0].startswith("-"):
                rest = rest[1:]
            rest = rest[1:] if rest else rest  # the duration
        elif prog in ("nice", "stdbuf"):
            while rest and rest[0].startswith("-"):
                flag = rest[0]
                rest = rest[1:]
                if prog == "nice" and flag == "-n" and rest:
                    rest = rest[1:]
        argv = rest
    return argv


def _python_commands(code: str) -> tuple[list[str], list[str], bool] | None:
    """(command strings run by the code, file paths it opens, whether it can reach the network) or None if it isn't
    valid Python. Code that imports a network library keeps all its text visible: a secret written into it could leave."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    commands: list[str] = []
    opened: list[str] = []
    network = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] in _PY_NETWORK for a in node.names):
            network = True
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in _PY_NETWORK:
            network = True
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
        if name in _PY_EXEC_CALLS and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                commands.append(arg.value)
            elif isinstance(arg, (ast.List, ast.Tuple)) and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in arg.elts):
                commands.append(shlex.join([e.value for e in arg.elts]))  # type: ignore[union-attr]
            else:
                commands.append("__DYNAMIC__")  # built at runtime: can't be checked statically
        elif name in ("open", "read_text", "read_bytes", "Path") and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                opened.append(arg.value)
    return commands, opened, network


def _data_args(prog: str, args: list[str]) -> list[str]:
    """The arguments that describe an action (operands, flags); data-only arguments removed."""
    if prog in _DATA_ONLY:
        return []
    if prog == "git" and args:
        sub = args[0]
        if sub in ("commit", "tag", "notes", "stash") :
            out, skip = [], False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a in ("-m", "--message", "-F"):
                    skip = True
                    continue
                if a.startswith(("-m", "--message=")) and len(a) > 2 and a[:2] == "-m":
                    continue
                out.append(a)
            return out
        if sub in ("ls-files", "check-ignore", "status", "log", "grep"):
            return [a for a in args if a.startswith("-")][:0] + [sub]
    if prog == "find":
        # -name/-path patterns describe what to look for; they don't read or run anything
        out, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-newer"):
                out.append(a)
                skip = True
                continue
            out.append(a)
        return out
    if prog in ("sed", "awk", "gawk") or (prog == "perl" and "-e" in args):
        # the first operand (or -e value) is the program text, not a file; later operands are files
        out, script_given, skip = [], False, False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-e", "--expression", "-f", "--file"):
                skip = True
                script_given = True
                continue
            if a.startswith("-"):
                out.append(a)
                continue
            if not script_given:
                script_given = True
                continue
            out.append(a)
        return out
    if prog in _GREP_LIKE:
        out, pattern_given, skip = [], False, False
        for a in args:
            if skip:
                skip = False
                if a and not pattern_given:
                    pattern_given = True
                continue
            if a in ("-e", "--regexp", "-f", "--file"):
                skip = True
                pattern_given = True
                continue
            if a.startswith("-"):
                out.append(a)
                continue
            if not pattern_given:
                pattern_given = True  # the first operand is the pattern
                continue
            out.append(a)
        return out
    return args


def analyse(command: str, *, depth: int = 0, keep_data: bool = False) -> ShellView | None:
    """The executed structure of a shell command, or None if it can't be parsed.

    `keep_data=True` keeps arguments that are data for the action rules (echo text, commit messages, patterns), for
    analyses that follow values rather than actions (where a credential variable is printed)."""
    if not command or len(command) > MAX_COMMAND or depth > MAX_DEPTH:
        return None
    try:
        text, bodies = _extract_heredocs(command)
        text, subs = _extract_substitutions(text)
        toks = _tokens(text)
    except ValueError:
        return None
    pipelines: list[list[Command]] = []
    pipeline: list[Command] = []
    current: list[str] = []
    redirects: list[tuple[str, str]] = []
    heredoc_iter = iter(bodies)
    nested: list[list[Command]] = []
    i = 0

    def flush(end_pipeline: bool) -> bool:
        nonlocal current, redirects, pipeline
        if current or redirects:
            cmd = _finish(current, redirects, pipeline[-1].argv[0] if pipeline and pipeline[-1].argv else None)
            if cmd is None:
                return False
            if cmd.argv or cmd.redirects:
                pipeline.append(cmd)
        current, redirects = [], []
        if end_pipeline and pipeline:
            pipelines.append(pipeline)
            pipeline = []
        return True

    def _finish(argv: list[str], reds: list[tuple[str, str]], upstream: str | None) -> Command | None:
        # leading variable assignments and shell keywords are not the program
        while argv and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]) or argv[0] in _KEYWORDS):
            argv = argv[1:]
        if argv and argv[0] == "for":
            return Command([], reds)  # `for x in words` : the words are data
        argv = _strip_wrappers(argv)
        if not argv:
            return Command([], reds)
        prog = _program(argv[0])
        args = argv[1:]
        body = None
        if any(op == "<<" for op, _ in reds):
            body = next(heredoc_iter, (0, ""))[1]
        # interpreters and shells that run code given as an argument or on stdin
        if prog in _SHELLS or prog == "eval":
            script = None
            if prog == "eval":
                script = " ".join(args)
            elif "-c" in args or any(a.startswith("-") and "c" in a[1:] and not a.startswith("--") for a in args):
                idx = next(k for k, a in enumerate(args) if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]))
                script = args[idx + 1] if idx + 1 < len(args) else ""
            elif body is not None:
                script = body
            if script is not None:
                inner = analyse(script, depth=depth + 1, keep_data=keep_data)
                if inner is None:
                    return None
                nested.extend(inner.commands)
                return Command([prog, "-c"], [r for r in reds if r[0] != "<<"], upstream)
        if _PYTHONS.match(prog):
            code = None
            if "-c" in args:
                k = args.index("-c")
                code = args[k + 1] if k + 1 < len(args) else ""
                args = args[:k] + ["-c"]
            elif body is not None and (not args or args[0] == "-"):
                code = body
            if code is not None:
                found = _python_commands(code)
                if found is None:
                    return Command([prog, *args, code], reds, upstream)  # not Python: keep it all
                commands, opened, network = found
                if network:
                    nested.append([Command(["__python_network_code__", code])])
                for c in commands:
                    if c == "__DYNAMIC__":
                        nested.append([Command(["__dynamic_command__"])])
                        continue
                    inner = analyse(c, depth=depth + 1, keep_data=keep_data)
                    if inner is None:
                        nested.append([Command([c])])
                    else:
                        nested.extend(inner.commands)
                return Command([prog, *args, *("open " + p for p in opened)], [r for r in reds if r[0] != "<<"], upstream)
        if body is not None and prog == "cat" and not any(op in (">", ">>", ">|") for op, _ in reds):
            # A heredoc printed or piped onward (perhaps into an interpreter) stays visible; one written to a file is
            # file content, judged when (if ever) that file is run.
            nested.append([Command(["__stdin_script__", body])])
        return Command([argv[0], *(args if keep_data else _data_args(prog, args))], [r for r in reds if r[0] != "<<"], upstream)

    while i < len(toks):
        tok = toks[i]
        if tok in _PIPES:
            if not flush(False):
                return None
        elif tok in _SEPARATORS:
            if not flush(True):
                return None
        elif tok in _REDIRECTS or tok == "<<":
            target = toks[i + 1] if i + 1 < len(toks) else ""
            if current and re.fullmatch(r"\d+", current[-1]) and tok.startswith((">", "<")):
                current.pop()  # file descriptor number
            redirects.append((tok, target))
            i += 2
            continue
        else:
            current.append(tok)
        i += 1
    if not flush(True):
        return None
    for sub in subs:
        inner = analyse(sub, depth=depth + 1, keep_data=keep_data)
        if inner is None:
            return None
        nested.extend(inner.commands)
    return ShellView(pipelines + nested)


_COMMAND_KEYS = ("command", "cmd", "script", "shell_command")


def command_view(tool: str, arguments: object) -> tuple[str, str] | None:
    """(argument key, executed-structure text) for a shell tool call, or None to keep text rules.

    PowerShell and cmd syntax aren't POSIX, so those tools keep their text rules."""
    if not isinstance(arguments, dict) or re.search(r"powershell|pwsh|\bcmd\b", tool, re.IGNORECASE):
        return None
    for key in _COMMAND_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            view = analyse(value)
            return (key, view.text()) if view is not None else None
    return None
