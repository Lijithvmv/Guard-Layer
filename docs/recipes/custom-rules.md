# Add your own rules and scanners

## A rule pack

Content rules are regular expressions with a category, a severity and the directions they apply to. Keep your own in a
TOML file:

```toml
# my_rules.toml
[[rules]]
name = "internal_codename"
pattern = "project\\s+nightingale"
category = "policy"
severity = 0.9
message = "Mentions an internal codename."
directions = ["output"]
```

```toml
# guardlayer.toml
[scanners.heuristics]
rules_file = "my_rules.toml"
disabled_rules = ["fake_role_header"]      # and switch off built-ins you don't want
```

Rule packs are trusted input: protect them like code.

## A tool rule

```python
from guardlayer import GuardLayer, ToolPolicy, ToolRule, Verdict

guard = GuardLayer(tool_policy=ToolPolicy(rules=[
    ToolRule("no_prod_db", "block", r"prod-db\.internal", message="Production database from an agent."),
]))
assert guard.scan_tool_call("run_sql", {"dsn": "postgres://prod-db.internal/app"}).verdict is Verdict.BLOCK
```

## A scanner

A scanner is any class with a `name`, the directions it applies to, and a `scan(text, context)` method that returns
detections.

```python
from guardlayer import BaseScanner, GuardLayer, Verdict, default_scanners

class NoCompetitors(BaseScanner):
    name = "competitors"
    default_directions = frozenset({"output"})

    def scan(self, text, context):
        if "acme corp" in text.lower():
            return [self.detection("competitor_mention", "policy", 0.9, "Mentions a competitor.")]
        return []

guard = GuardLayer([*default_scanners(), NoCompetitors()])
assert guard.scan_output("You should try Acme Corp instead.").verdict is Verdict.BLOCK
```

## An LLM judge

Use any model you already call as one more layer, through a callable. It's provider-agnostic and opt-in.

```py
from guardlayer import LLMJudgeScanner, default_scanners
from guardlayer.scanners import build_judge_prompt, parse_judge_score

judge = LLMJudgeScanner(lambda text, ctx: parse_judge_score(my_llm(build_judge_prompt(text))))
guard = GuardLayer([*default_scanners(), judge])
```

## Teach it your attacks

Add attacks you've seen to the similarity corpus, and let blocked prompts be learned automatically:

```toml
[guard]
auto_learn = true

[scanners.similarity]
corpus_file = "our_attacks.txt"    # one attack per line
```
