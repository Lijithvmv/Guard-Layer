"""Signature rules for the heuristic scanner.

A rule is a regex plus metadata (category, severity, directions). The built-in pack
covers documented prompt-injection, jailbreak, exfiltration and unsafe-command
phrasings. Extra packs can be loaded from JSON or TOML files:

    [[rules]]
    name = "internal_codename"
    pattern = "\\bproject\\s+nightingale\\b"
    category = "policy"
    severity = 0.9
    message = "Mentions a confidential project."
    directions = ["input", "output"]
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardlayer.models import DIRECTIONS, Category

_IN = frozenset({"input", "context"})
_OUT = frozenset({"output"})
_CTX = frozenset({"context"})
_OUT_CTX = frozenset({"output", "context"})
_ALL = frozenset(DIRECTIONS)


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    category: str
    severity: float
    message: str
    directions: frozenset[str] = field(default=_IN)
    ignore_case: bool = True
    multiline: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.severity <= 1.0:
            raise ValueError(f"rule {self.name!r}: severity must be within [0, 1]")
        unknown = set(self.directions) - set(DIRECTIONS)
        if unknown:
            raise ValueError(f"rule {self.name!r}: unknown direction(s) {sorted(unknown)}")
        if isinstance(self.category, Category):
            object.__setattr__(self, "category", self.category.value)
        self.compile()  # fail fast on a bad pattern

    def compile(self) -> re.Pattern[str]:
        flags = (re.IGNORECASE if self.ignore_case else 0) | (re.MULTILINE if self.multiline else 0)
        return re.compile(self.pattern, flags)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        return cls(
            name=data["name"],
            pattern=data["pattern"],
            category=data.get("category", Category.POLICY.value),
            severity=float(data.get("severity", 0.8)),
            message=data.get("message", f"Matched custom rule {data['name']}."),
            directions=frozenset(data.get("directions", _IN)),
            ignore_case=bool(data.get("ignore_case", True)),
            multiline=bool(data.get("multiline", False)),
        )


def load_rules(path: str | Path) -> list[Rule]:
    """Load a rule pack from a .json or .toml file (a top-level `rules` list)."""
    path = Path(path)
    if path.suffix == ".toml":
        from guardlayer.config import load_toml

        data = load_toml(path)
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
    items: Iterable[dict[str, Any]] = data["rules"] if isinstance(data, dict) else data
    return [Rule.from_dict(item) for item in items]


PI = Category.PROMPT_INJECTION.value
JB = Category.JAILBREAK.value
LEAK = Category.SYSTEM_PROMPT_LEAK.value
EXFIL = Category.DATA_EXFILTRATION.value
CMD = Category.UNSAFE_COMMAND.value

DEFAULT_RULES: list[Rule] = [
    # --- Instruction override / prompt injection -------------------------------------------
    Rule(
        "ignore_previous_instructions",
        r"\b(ignore|disregard|forget|skip|override|overrule|bypass)\b[^.\n]{0,40}?\b(previous|preceding|above|prior|earlier|all|any|your|the|these|those|initial|original)\b[^.\n]{0,30}?\b(instructions?|prompts?|rules|directives?|guidelines|commands?|programming|context|orders|tasks|assignments|information)\b",
        PI, 0.9, "Attempt to override prior instructions.",
    ),
    Rule(
        "forget_everything",
        r"\b(ignore|disregard|forget|drop|leave)\b\s+(about\s+)?(everything|all of (that|this|the above)|anything)\b[^.\n]{0,12}?\b(above|before|prior|previous(ly)?|earlier|said|so far|behind|you (were|have been) told)\b",
        PI, 0.85, "Tells the model to discard everything that came before.",
    ),
    Rule(
        "change_instructions",
        r"\b(change|replace|update|rewrite|modify|swap)\s+(your|the|all)\s+(system\s+)?(instructions|rules|directives|prompt|programming)\s+(to|with|for)\b",
        PI, 0.8, "Attempts to rewrite the model's instructions.",
    ),
    Rule(
        "new_instructions",
        r"\b(new|updated|real|actual|revised|override|secret)\s+(system\s+)?(instructions?|directives?)\s*[:\-]",
        PI, 0.6, "Injects a replacement instruction block.",
    ),
    Rule(
        "new_instructions_follow",
        r"\b(now|here)\s+(come|follow)s?\s+(some\s+)?(new|further|different)\s+(instructions?|tasks?|directives?|orders)\b|\b(new|further|different)\s+(instructions?|tasks?|directives?|orders)\s+(now\s+)?(follow|are as follows)\b|\bstart\s+(over|again|anew)\s+with\s+a\s+new\s+task\b",
        PI, 0.6, "Announces a replacement set of instructions.",
    ),
    Rule(
        "from_now_on",
        r"\bfrom now on\b,?[^.\n]{0,20}\b(you|your)\b[^.\n]{0,40}\b(will|must|are|should|shall|only|always|never)\b",
        PI, 0.45, "Attempts to redefine the assistant's future behaviour.",
    ),
    Rule(
        "instruction_priority_claim",
        r"\b(this|these|the following)\s+(instructions?|message|rules?)\s+(takes?|has|have)\s+(priority|precedence)\b|\bhighest[- ]priority\s+instructions?\b",
        PI, 0.7, "Claims precedence over existing instructions.",
    ),
    Rule(
        "fake_special_tokens",
        r"<\|(im_start|im_end|endoftext|system|assistant|user|begin_of_text|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<<\s*/?SYS\s*>>",
        PI, 0.8, "Chat-template control tokens embedded in text.", _ALL,
    ),
    Rule(
        "fake_role_header",
        r"^\s*(#{1,3}\s*)?(system|developer)\s*(message|prompt|instructions?)?\s*:",
        PI, 0.5, "Forged system/developer role header.", _IN, True, True,
    ),
    Rule(
        "ai_directed_instruction",
        r"\b(if you are|attention|note to|message (to|for)|instructions? (to|for)|dear)\s+(an?\s+|the\s+|any\s+)?(ai|a\.i\.|llm|language model|assistant|chatbot|gpt|agent|ai model)s?\b",
        PI, 0.7, "Text addresses an AI reader directly (indirect injection).", _CTX,
    ),
    Rule(
        "ai_must_instruction",
        r"\b(ai|assistant|agent|llm|model|chatbot)s?\b[^.\n]{0,25}\b(must|should|are required to|need to|has to)\b[^.\n]{0,30}\b(ignore|instead|immediately|now|disregard|forget)\b",
        PI, 0.65, "Embedded directive aimed at an AI (indirect injection).", _CTX,
    ),
    Rule(
        "hidden_html_instruction",
        r"<!--[^>]{0,300}?\b(ignore|instructions?|assistant|ai|system prompt|you must)\b",
        PI, 0.6, "Instruction hidden in an HTML comment.", _CTX,
    ),
    Rule(
        "hidden_css_text",
        r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px)?\b|opacity\s*:\s*0(\.0+)?\s*[;\"'])",
        PI, 0.3, "Visually hidden text in markup.", _CTX,
    ),
    Rule(
        "encoded_instruction",
        r"\b(decode|decrypt|base64|rot-?13|hex|reverse|translate)\b[^.\n]{0,50}\b(and|then)\s+(follow|execute|run|do|obey|perform|act on|carry out)\b",
        PI, 0.7, "Asks the model to decode and then act on a payload.",
    ),
    Rule(
        "payload_splitting",
        r"\b(concatenate|combine|join)\b[^.\n]{0,40}\b(strings?|variables?|parts?|pieces|a\s*\+\s*b)\b[^.\n]{0,50}\b(execute|follow|answer|respond to|run|obey)\b",
        PI, 0.5, "Payload-splitting: reassemble fragments then act on them.",
    ),
    Rule(
        "tool_abuse_instruction",
        r"\b(run|execute|call|invoke|use)\b[^.\n]{0,20}\b(the\s+)?(shell|terminal|bash|powershell|cmd|exec|eval|code interpreter|browser|email|http|file)\s*(tool|function|command|plugin)?\b[^.\n]{0,50}\b(rm -rf|curl|wget|delete all|drop table|transfer|send (it|them|this|the|their|all|my|your|his|her)|exfiltrate|upload)\b",
        PI, 0.6, "Directs an agent to misuse a tool.",
    ),
    # --- Non-English instruction override (de, es, fr, pt, it, nl, ru, hr/sr/bs) ---------------
    Rule(
        "ignore_instructions_multilingual",
        r"\b(vergiss|vergesst|vergessen sie|ignorier(e|en sie)?|missachte)\b[^.\n]{0,30}\b(alles|alle[ns]?|vorherigen?|bisherigen?|obigen?)\b[^.\n]{0,30}\b(anweisungen|aufträge|aufgaben|instruktionen|befehle|regeln|informationen|gesagte|davor|vorher|zuvor|bisher)\b"
        r"|\b(olvida|olvide|olviden|ignora|ignore|ignoren)\b[^.\n]{0,25}\b(todo|todas|todos|anteriores?)\b[^.\n]{0,25}\b(instrucciones|órdenes|reglas|lo (que|anterior)|antes|anteriores?)\b"
        r"|\b(oublie[zs]?|ignore[zs]?)\b[^.\n]{0,25}\b(tout|toutes?|précédentes?)\b[^.\n]{0,25}\b(instructions|consignes|règles|ce qui précède|avant)\b"
        r"|\b(esqueça|esquece|ignore|ignora)\b[^.\n]{0,25}\b(tudo|todas|anteriores?)\b[^.\n]{0,25}\b(instruções|regras|ordens|antes)\b"
        r"|\b(dimentica|dimenticate|ignora|ignorate)\b[^.\n]{0,25}\b(tutto|tutte|precedenti)\b[^.\n]{0,25}\b(istruzioni|regole|ordini|prima)\b"
        r"|\b(vergeet|negeer)\b[^.\n]{0,25}\b(alles|alle|vorige)\b[^.\n]{0,25}\b(instructies|regels|opdrachten|hiervoor|daarvoor)\b"
        r"|(забудь(те)?|игнорируй(те)?|проигнорируй(те)?)[^.\n]{0,25}(все|всё|предыдущие)[^.\n]{0,25}(инструкции|указания|правила|что было)"
        r"|\b(zaboravi|zaboravite|ignoriši|ignoriraj)\b[^.\n]{0,25}\b(sve|prethodne)\b[^.\n]{0,25}\b(instrukcije|upute|uputstva|naredbe|pravila)\b",
        PI, 0.9, "Instruction override in a non-English language.",
    ),
    Rule(
        "new_instructions_multilingual",
        r"\b(nun|jetzt)\s+folgen\s+neue\s+(anweisungen|aufgaben)\b|\bneue\s+(anweisungen|aufgabe)\s*:|\bnuevas\s+instrucciones\s*:|\bnouvelles\s+instructions\s*:",
        PI, 0.6, "Announces replacement instructions (non-English).",
    ),
    Rule(
        "reveal_prompt_multilingual",
        r"\b(zeige?|gib|nenne|verrate)\b[^.\n]{0,30}\b(deine[nm]?|ihre[nm]?)\s+(prompt(-texte?)?|system-?prompt|anweisungen|instruktionen)\b|\b(muestra|dime|revela)\b[^.\n]{0,30}\btus\s+(instrucciones|prompt)\b|\b(montre|révèle|donne)[- ]moi\b[^.\n]{0,30}\btes\s+(instructions|prompt)\b",
        LEAK, 0.75, "Asks the model for its own instructions (non-English).",
    ),
    # --- Jailbreaks --------------------------------------------------------------------------
    Rule(
        "unethical_ai_persona",
        r"\b(amoral|immoral|unethical|unfiltered|unfiltred|uncensored|unrestricted|lawless|rogue|evil|criminal|jailbroken)\s+(and\s+\w+\s+)?(ai|a\.i\.|chatbot|bot|language model|llm|assistant|model|version of (yourself|chatgpt|you))\b"
        r"|\b(ai|chatbot|bot|language model|assistant|persona|character)\b[^.\n]{0,60}\b(without|with no|doesn'?t (follow|have|care about)|does not (follow|have|care about)|free (of|from)|devoid of|lacks?)\s+(any\s+)?(ethics|ethical|moral(s|ity| values)?|restrictions|limitations|filters?|guidelines|censorship|boundaries)\b",
        JB, 0.75, "Defines an AI persona without ethics or restrictions.",
    ),
    Rule(
        "has_no_rules",
        r"\b(with|has|have|having)\s+(absolutely\s+)?no\s+(rules|restrictions|limitations|limits|filters|ethics|morals|guidelines|boundaries|censorship)\b",
        JB, 0.5, "Describes the model as having no rules or limits.",
    ),
    Rule(
        "jailbreak_marker",
        r"\[(🔓\s*)?JAILBREAK\]|\[🔓[^\]]{0,20}\]|(^|\s)/jailbreak\b|\bjailbreak(ed)? mode\b",
        JB, 0.8, "Known jailbreak control marker.", _IN, True, True,
    ),
    Rule(
        "jailbreak_persona",
        r"\b(you are|you're|act as|acting as|pretend (to be|you are)|roleplay as|become|simulate)\s+(now\s+)?(in\s+|a |an |the )?(dan|stan|dude|aim|do anything now|unrestricted|uncensored|jailbroken|unfiltered|evil|amoral|unaligned|unbound|developer mode|god mode)\b",
        JB, 0.9, "Persona/role override (jailbreak persona).",
    ),
    Rule(
        "do_anything_now",
        r"\bdo anything now\b",
        JB, 0.85, "Known jailbreak persona reference.",
    ),
    Rule(
        "dan_reference",
        r"\bDAN\s*(mode|prompt|jailbreak|\d+(\.\d+)?)\b",
        JB, 0.6, "References the DAN jailbreak family.",
    ),
    Rule(
        "privileged_mode",
        r"\b(enable|activate|switch (to|into)|enter|turn on|unlock|boot into)\b[^.\n]{0,20}\b(developer|god|sudo|root|jailbreak|jailbroken|unrestricted|unfiltered|uncensored|dan)\s+mode\b",
        JB, 0.7, "Request to enter a privileged/unrestricted mode.",
    ),
    Rule(
        "disable_safety",
        r"\b(bypass|disable|turn off|ignore|deactivate|circumvent|override|switch off|get around)\b[^.\n]{0,25}\b(safety|guardrails?|content filters?|moderation|safety filters?|(content|usage|openai|anthropic|safety|company|ethical) polic(y|ies)|censorship|alignment|ethical guidelines|safeguards?)\b",
        JB, 0.8, "Attempt to disable safety controls.",
    ),
    Rule(
        "hypothetical_framing",
        r"\b(pretend|imagine|roleplay|let'?s say|hypothetically|in a fictional world|write a story where)\b[^.\n]{0,60}\b(no (rules|restrictions|limits|filters|guidelines)|anything is (allowed|permitted)|without (any )?(restrictions|filters|rules|limits)|not bound by)\b",
        JB, 0.7, "Hypothetical framing used to elicit restricted output.",
    ),
    Rule(
        "refusal_suppression",
        r"\b(never|do not|don't|must not|you cannot|you can't|you will not|you won't)\s+(ever\s+)?(refuse|decline|say (no|you can'?t|that you can'?t)|apologi[sz]e|add (any )?(warnings?|disclaimers?)|mention (your )?(guidelines|policies|ethics))\b",
        JB, 0.55, "Refusal suppression.",
    ),
    Rule(
        "no_rules_claim",
        r"\b(free (of|from)|no longer (bound|restricted|limited) by|not (bound|restricted) by|released from)\b[^.\n]{0,20}\b(rules|restrictions|limitations|filters|guidelines|morals|ethics|censorship|polic(y|ies)|openai|anthropic|programming)\b",
        JB, 0.6, "Claims the model is no longer bound by its rules.",
    ),
    Rule(
        "opposite_mode",
        r"\b(opposite|evil|reverse|anti)[- ]?(mode|twin|version of yourself)\b|\bstay in character\b",
        JB, 0.45, "Alternate-persona jailbreak pattern.",
    ),
    # --- System prompt extraction --------------------------------------------------------------
    Rule(
        "reveal_system_prompt",
        r"\b(reveal|show|print|display|output|repeat|dump|leak|give me|tell me|share|what (is|are|was|were))\b[^.\n]{0,40}?(\b(system|hidden|secret|internal|developer|confidential)(\s+system)?\s*(prompt|instructions?|message|rules|directives?|configuration)\b|\bpre-?prompt\b)",
        LEAK, 0.85, "Attempt to extract the system prompt.",
    ),
    Rule(
        "ask_for_own_instructions",
        r"\b(reveal|show|print|display|output|repeat|dump|paste|give me|tell me|share|what (is|are|was|were))\b[^.\n]{0,30}?\byour\s+(initial|original|first|full|exact|complete|underlying)?\s*(prompt|instructions|directives|configuration)\b",
        LEAK, 0.6, "Asks the model for its own instructions.",
    ),
    Rule(
        "repeat_text_above",
        r"\b(repeat|print|output|copy|echo|recite|spell out)\b[^.\n]{0,30}\b(the )?(words|text|everything|content|lines?|all)\b[^.\n]{0,30}\b(above|before this|preceding|prior to this|so far|verbatim)\b",
        LEAK, 0.6, "Asks the model to regurgitate its context.",
    ),
    Rule(
        "prompt_beginning",
        r"\b(written|said|stated|typed|text)\b[^.\n]{0,25}\b(beginning|start|top)\s+of\s+(this|the|your)\s+(prompt|conversation|chat|instructions|context|message)\b",
        LEAK, 0.7, "Asks what came at the start of the prompt.",
    ),
    Rule(
        "system_prompt_disclosure",
        r"\b(my|the)\s+(system prompt|initial instructions|hidden instructions|original instructions|system message)\s+(is|are|says?|reads?|states?)\b|\bi was (instructed|told|programmed) to\b[^.\n]{0,20}:",
        LEAK, 0.6, "Response appears to disclose the system prompt.", _OUT,
    ),
    # --- Exfiltration ----------------------------------------------------------------------------
    Rule(
        "exfiltration_to_destination",
        r"\b(send|post|upload|exfiltrate|leak|forward|email|transmit|append|submit)\b[^.\n]{0,50}\b(secrets?|api[ _-]?keys?|tokens?|passwords?|credentials?|system prompt|conversation|chat history|env(ironment)? variables?|personal data|user data|cookies?)\b[^.\n]{0,40}\b(to|into|via)\s+(https?://|\S+@\S+\.\w+|(an?|the|this|my|our)\s+(url|endpoint|server|webhook|address|link))",
        EXFIL, 0.9, "Instruction to exfiltrate sensitive data to a destination.", _IN | _OUT,
    ),
    Rule(
        "exfiltration_request",
        r"\b(exfiltrate|leak|steal|harvest|dump)\b[^.\n]{0,40}\b(secrets?|api[ _-]?keys?|tokens?|passwords?|credentials?|env(ironment)? variables?|user data|database)\b",
        EXFIL, 0.7, "Request to leak sensitive data.",
    ),
    # --- Jailbreak success markers in outputs -------------------------------------------------
    Rule(
        "jailbreak_success_marker",
        r"\b(DAN|developer mode|jailbreak(ed)?|god mode)\s*(mode\s*)?(enabled|activated|unlocked|successful|on)\b|\[(🔓|JAILBREAK|DAN)\]",
        JB, 0.75, "Response signals a jailbroken persona.", _OUT,
    ),
    # --- Unsafe commands (agent actions, generated code, tool arguments) ----------------------
    Rule(
        "destructive_delete",
        r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*|-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\s+(--no-preserve-root\s+)?(/|~/?|\*|\$HOME/?|/\*)(\s|$|;|&)",
        CMD, 0.85, "Recursive force-delete of a root/home path.", _OUT_CTX, False,
    ),
    Rule(
        "remote_script_pipe",
        r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|\n]{0,200}\|\s*(python3?|perl|ruby|node|iex)\b",
        CMD, 0.7, "Pipes a remote script straight into an interpreter.", _OUT_CTX,
    ),
    Rule(
        "reverse_shell",
        r"\bbash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+|\bnc(at)?\b[^\n]{0,60}\s-e\s+/bin/(ba)?sh|\bsocket\.socket\([^\n]{0,120}subprocess\.(call|Popen)\([^\n]{0,40}/bin/(ba)?sh",
        CMD, 0.9, "Reverse-shell pattern.", _OUT_CTX,
    ),
    Rule(
        "encoded_powershell",
        r"\bpowershell(\.exe)?\b[^\n]{0,60}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\b(IEX|Invoke-Expression)\b[^\n]{0,100}(DownloadString|Net\.WebClient|FromBase64String)",
        CMD, 0.85, "Obfuscated/remote PowerShell execution.", _OUT_CTX,
    ),
    Rule(
        "fork_bomb",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        CMD, 0.9, "Fork bomb.", _OUT_CTX,
    ),
    Rule(
        "disk_wipe",
        r"\bmkfs(\.\w+)?\s+/dev/|\bdd\s+[^\n]{0,60}\bof=/dev/(sd[a-z]|nvme\d|hd[a-z]|disk\d)|\bformat\s+[a-z]:\s*/[qy]",
        CMD, 0.85, "Disk format/wipe command.", _OUT_CTX,
    ),
    Rule(
        "destructive_sql",
        r"\b(drop\s+(table|database|schema)|truncate\s+table)\s+[\w`\"\[]|\bdelete\s+from\s+\w+\s*(;|$)",
        CMD, 0.35, "Destructive SQL statement.", _OUT_CTX, True, True,
    ),
    Rule(
        "world_writable_root",
        r"\bchmod\s+(-R\s+)?(0?777|a\+rwx)\s+/(\s|$)",
        CMD, 0.6, "Makes the filesystem root world-writable.", _OUT_CTX,
    ),
]  # fmt: skip
