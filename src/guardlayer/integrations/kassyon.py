"""GuardLayer -> Kassyon connector (data plane -> control plane).

Emits each GuardLayer decision as a signed `guardlayer.decision.v1` record to a Kassyon ingest endpoint, where it
becomes verifiable, control-mapped governance evidence. Design rules:
  * NO payload content or secrets leave — verdict, tool, consequence, rule names and hashes only.
  * FAIL-OPEN to the agent: emission never raises and never blocks; if Kassyon is unreachable, records stay buffered.
  * Async-friendly and BATCHED: off the agent's critical path.
Record integrity in v1 is a SHA-256 over the canonical record; an Ed25519 signature from the audit-log signer is a
follow-up (set `signer=` to supply one). Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

SCHEMA = "guardlayer.decision.v1"

# Rule-category triggers a fired rule can match, mirroring the control plane's agent_evidence.DEFAULT_RULE_MAP
# keys. These are the ONLY triggers a runtime rule can be matched against (the other advisory triggers —
# "approval", "every_decision" — are not rule-driven, so should_tighten never acts on them).
RULE_TRIGGERS = ("exfil", "boundary", "security")

# GuardLayer verdict -> governance verdict
_VERDICT = {"allow": "allow", "review": "require_approval", "block": "deny"}


def _rule_names(result: Any) -> list[str]:
    """The rules behind this decision: every detection that fired (what was enforced), then any rule that was only
    observed (observe mode). Deduplicated, first-seen order. Reading only `observed_rules` -- empty whenever a rule
    is enforced, and a list of plain strings when it is not -- shipped every real block and review with no rule."""
    out: list[str] = []
    for d in list(getattr(result, "detections", None) or []) + list(getattr(result, "observed_rules", None) or []):
        name = d if isinstance(d, str) else (d.get("rule") if isinstance(d, dict) else getattr(d, "rule", None))
        if name and name not in out:
            out.append(name)
    return out


def _verdict(result: Any) -> str:
    v = getattr(getattr(result, "verdict", None), "value", None)
    if v in _VERDICT:
        return _VERDICT[v]
    # fall back to the boolean flags if the enum value is unexpected
    if getattr(result, "is_blocked", False):
        return "deny"
    if getattr(result, "needs_review", False):
        return "require_approval"
    return "allow"


def build_record(
    result: Any,
    *,
    system_id: str,
    framework: str,
    session: str = "",
    tool: str = "",
    consequence: str = "",
    direction: str = "",
    ts: str = "",
    approval: Optional[dict] = None,
    signer: Optional[Callable[[bytes], str]] = None,
) -> dict:
    """Build a canonical `guardlayer.decision.v1` record from a GuardLayer Result. Pure; no network."""
    rec: dict[str, Any] = {
        "schema": SCHEMA,
        "decision_id": str(getattr(result, "id", "") or ""),
        "ts": ts or str(getattr(result, "timestamp", "") or ""),
        "agent": {"system_id": system_id, "framework": framework, "session": session},
        "action": {"tool": tool, "consequence": consequence, "direction": direction or str(getattr(result, "direction", "") or "")},
        "verdict": _verdict(result),
        "rules": _rule_names(result),
        "approval": approval or {"required": _verdict(result) == "require_approval", "granted_by": None, "granted_ts": None},
    }
    canonical = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    rec["record_hash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if signer is not None:
        try:
            rec["signature"] = signer(canonical)
        except Exception:
            rec["signature"] = None
    return rec


def _http_post(url: str, token: str, batch: list[dict], *, timeout: float = 5.0) -> bool:
    body = json.dumps({"decisions": batch}).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return 200 <= r.status < 300


class KassyonEmitter:
    """Buffers decisions and ships them to Kassyon in batches, fail-open.

    transport(url, token, batch) -> bool is injectable for tests; default is an HTTP POST to <url>/agent/decisions.
    `sample_allow` keeps every review/deny and ships only 1-in-N low-signal `allow` decisions (0 = drop all allows,
    1 = keep all).
    """

    def __init__(
        self,
        url: str,
        token: str = "",
        *,
        system_id: str = "default-agent",
        framework: str = "claude-code",
        batch_size: int = 20,
        sample_allow: int = 1,
        transport: Optional[Callable[[str, str, list[dict]], bool]] = None,
        signer: Optional[Callable[[bytes], str]] = None,
    ) -> None:
        self.url = url.rstrip("/") + "/agent/decisions"
        self.token = token
        self.system_id = system_id
        self.framework = framework
        self.batch_size = max(1, batch_size)
        self.sample_allow = sample_allow
        self._transport = transport or _http_post
        self._signer = signer
        self._buffer: list[dict] = []
        self._allow_seen = 0
        self.sent = 0
        self.dropped_allow = 0

    def emit(self, result: Any, **meta: Any) -> None:
        """Record a decision. Never raises. Flushes automatically at batch_size."""
        try:
            rec = build_record(result, system_id=meta.pop("system_id", self.system_id),
                               framework=meta.pop("framework", self.framework), signer=self._signer, **meta)
        except Exception:
            return  # emission must never break the agent
        if rec["verdict"] == "allow":
            self._allow_seen += 1
            if self.sample_allow <= 0 or (self._allow_seen % max(1, self.sample_allow)) != 0:
                self.dropped_allow += 1
                return
        self._buffer.append(rec)
        if len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> int:
        """Ship the buffer. Returns how many were sent; keeps them buffered on failure. Never raises."""
        if not self._buffer:
            return 0
        batch = self._buffer
        try:
            ok = bool(self._transport(self.url, self.token, batch))
        except Exception:
            ok = False
        if ok:
            self.sent += len(batch)
            self._buffer = []
            return len(batch)
        return 0  # fail-open: keep buffered, try again next flush

    @property
    def pending(self) -> int:
        return len(self._buffer)


# --------------------------------------------------------------------------------------------------------------
# Governance-posture consumer (control plane -> data plane): the closing half of the loop.
# Kassyon's GET /agent/policy says where its evidence is thin and recommends an enforcement posture per control.
# This is ADVISORY: we fetch it and expose a predicate; wiring it into runtime policy is the guard's choice, and
# by default we only annotate a decision — we never silently change a verdict here.
# --------------------------------------------------------------------------------------------------------------

def _http_get(url: str, token: str, *, timeout: float = 5.0) -> Optional[dict]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if 200 <= r.status < 300:
            return json.loads(r.read().decode())
    return None


@dataclass(frozen=True)
class PolicyAdvisory:
    """One control's posture, as reported by Kassyon."""
    framework: str
    control_ref: str
    title: str
    trigger: str          # rule-category (exfil/boundary/security), "approval", or "every_decision"
    status: str           # gap | stale | weak | effective
    enforcement: str      # enforce | monitor
    occurrences: int = 0
    last_seen: Optional[str] = None
    fresh: bool = False

    @property
    def enforce(self) -> bool:
        return self.enforcement == "enforce"


class KassyonPolicy:
    """Fetches and caches Kassyon's governance-posture advisory, and answers "should the guard stay strict for
    a rule that fell in category X?". Fail-open: if Kassyon is unreachable, refresh() keeps the last-known
    advisories (none at first) and returns False, so posture can only ever ADD strictness, never remove it by
    failing.

    transport(url, token) -> dict | None is injectable for tests; default is an HTTP GET to <url>/agent/policy.
    """

    def __init__(
        self,
        url: str,
        token: str = "",
        *,
        transport: Optional[Callable[[str, str], Optional[dict]]] = None,
    ) -> None:
        self.url = url.rstrip("/") + "/agent/policy"
        self.token = token
        self._transport = transport or _http_get
        self.advisories: list[PolicyAdvisory] = []
        self.generated_at: str = ""
        self.last_ok: bool = False

    def refresh(self) -> bool:
        """Fetch the latest posture. Never raises; returns True on a good fetch, else keeps the last advisories."""
        try:
            data = self._transport(self.url, self.token)
        except Exception:
            data = None
        if not isinstance(data, dict) or not isinstance(data.get("advisories"), list):
            self.last_ok = False
            return False
        parsed: list[PolicyAdvisory] = []
        for a in data["advisories"]:
            if not isinstance(a, dict):
                continue
            parsed.append(PolicyAdvisory(
                framework=a.get("framework", ""), control_ref=a.get("control_ref", ""),
                title=a.get("title", ""), trigger=a.get("trigger", ""), status=a.get("status", ""),
                enforcement=a.get("enforcement", ""), occurrences=int(a.get("occurrences", 0) or 0),
                last_seen=a.get("last_seen"), fresh=bool(a.get("fresh", False))))
        self.advisories = parsed
        self.generated_at = str(data.get("generated_at", ""))
        self.last_ok = True
        return True

    @property
    def enforced_triggers(self) -> set[str]:
        """Rule-category triggers whose control is currently recommended for enforcement."""
        return {a.trigger for a in self.advisories if a.enforce and a.trigger in RULE_TRIGGERS}

    def should_tighten(self, categories: Iterable[str]) -> bool:
        """True if any of these rule categories backs a control Kassyon currently flags `enforce`. The caller
        passes the categories of the rule(s) that fired (the guard owns its own rule->category taxonomy)."""
        enforced = self.enforced_triggers
        return any(c in enforced for c in categories)

    def advisories_for(self, categories: Iterable[str]) -> list[PolicyAdvisory]:
        """The enforce advisories matching these categories — for recording WHY a decision was flagged."""
        cats = set(categories)
        return [a for a in self.advisories if a.enforce and a.trigger in cats]


# --------------------------------------------------------------------------------------------------------------
# Human approval (data plane -> control plane -> a person): a `review` verdict on a consequential action is held
# and sent to Kassyon's approval queue (POST /agent/approvals); the agent polls GET /agent/approvals/{id} until a
# named approver decides. FAIL-CLOSED, unlike emission: the action runs only on an explicit "approved". Kassyon
# unreachable, a timeout, a rejection or an expired request all mean "do not run". The granted approval is then
# carried on the emitted decision record (approval.granted_by / granted_ts), which is what Kassyon counts as
# human-oversight evidence.
# --------------------------------------------------------------------------------------------------------------

def _http_post_json(url: str, token: str, body: dict, *, timeout: float = 5.0) -> Optional[dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if 200 <= r.status < 300:
            return json.loads(r.read().decode())
    return None


@dataclass(frozen=True)
class ApprovalOutcome:
    """What happened to one held action. `approved` is the only state in which the action may run."""
    status: str                    # approved | rejected | expired | pending (timed out waiting) | unavailable
    request_id: str = ""           # the idempotency key sent to Kassyon
    kassyon_id: str = ""           # Kassyon's request lineage id ("" if it was never accepted)
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None
    note: str = ""

    @property
    def approved(self) -> bool:
        return self.status == "approved" and bool(self.decided_by)

    def as_record_approval(self) -> dict:
        """The `approval` block for build_record / KassyonEmitter.emit(approval=...)."""
        return {"required": True, "granted_by": self.decided_by if self.approved else None,
                "granted_ts": self.decided_at if self.approved else None}


class KassyonApprovals:
    """Client for Kassyon's agent approval queue. Authenticate with the agent key (Bearer agk_...): Kassyon binds
    the request to the key's own system and tenant, and an agent can only read its own requests.

    post(url, token, body) -> dict | None and get(url, token) -> dict | None are injectable for tests; `sleep` too.
    """

    TERMINAL = ("approved", "rejected", "expired")

    def __init__(self, url: str, token: str = "", *, poll_seconds: float = 5.0,
                 post: Optional[Callable[[str, str, dict], Optional[dict]]] = None,
                 get: Optional[Callable[[str, str], Optional[dict]]] = None,
                 sleep: Optional[Callable[[float], None]] = None) -> None:
        import time as _time
        self.base = url.rstrip("/") + "/agent/approvals"
        self.token = token
        self.poll_seconds = max(0.0, poll_seconds)
        self._post = post or _http_post_json
        self._get = get or _http_get
        self._sleep = sleep or _time.sleep
        self._clock = _time.monotonic

    def submit(self, *, tool: str, consequence: str, summary: str = "", rules: Iterable[str] = (),
               request_id: str = "", ttl_minutes: int = 60) -> ApprovalOutcome:
        """Ask for a decision. Idempotent on request_id (Kassyon returns the existing request). Only metadata is
        sent - tool, consequence, a short summary, rule names - never the action's payload."""
        rid = request_id or hashlib.sha256(f"{tool}|{consequence}|{summary}".encode()).hexdigest()[:24]
        body = {"tool": tool, "consequence": consequence, "summary": summary[:300], "rules": list(rules),
                "request_id": rid, "ttl_minutes": int(ttl_minutes)}
        try:
            data = self._post(self.base, self.token, body)
        except Exception:
            data = None
        req = (data or {}).get("request") if isinstance(data, dict) else None
        if not isinstance(req, dict) or not req.get("lineage_id"):
            return ApprovalOutcome("unavailable", request_id=rid)
        return self._outcome(req, rid)

    def status(self, outcome: ApprovalOutcome) -> ApprovalOutcome:
        """Re-read one request. Unreachable keeps the last known status (never upgrades it)."""
        if not outcome.kassyon_id:
            return outcome
        try:
            data = self._get(f"{self.base}/{outcome.kassyon_id}", self.token)
        except Exception:
            data = None
        if not isinstance(data, dict) or not data.get("status"):
            return outcome
        return self._outcome(data, outcome.request_id)

    def wait(self, outcome: ApprovalOutcome, timeout_seconds: float) -> ApprovalOutcome:
        """Poll until a decision or the timeout. A timeout returns status 'pending' - which is NOT approval."""
        deadline = self._clock() + max(0.0, timeout_seconds)
        while outcome.status == "pending" and outcome.kassyon_id:
            if self._clock() >= deadline:
                break
            self._sleep(self.poll_seconds)
            outcome = self.status(outcome)
        return outcome

    def hold(self, *, tool: str, consequence: str, summary: str = "", rules: Iterable[str] = (),
             request_id: str = "", ttl_minutes: int = 60, wait_seconds: float = 0.0) -> ApprovalOutcome:
        """submit + wait: the one call a guard makes for a `review` verdict. Run the action only if
        `.approved`."""
        o = self.submit(tool=tool, consequence=consequence, summary=summary, rules=rules,
                        request_id=request_id, ttl_minutes=ttl_minutes)
        return self.wait(o, wait_seconds) if wait_seconds > 0 else o

    @staticmethod
    def _outcome(req: dict, rid: str) -> ApprovalOutcome:
        st = str(req.get("status", ""))
        return ApprovalOutcome(st if st in ("pending", "approved", "rejected", "expired") else "unavailable",
                               request_id=rid, kassyon_id=str(req.get("lineage_id", "")),
                               decided_by=req.get("decided_by"), decided_at=req.get("decided_at"),
                               note=str(req.get("decision_note", "") or ""))


# --------------------------------------------------------------------------------------------------------------
# File spool: for hosts where every guard decision is a separate short-lived process (Claude Code hooks), records
# are appended to a local JSONL spool (fast, no network on the agent's path) and shipped in batches. Fail-open:
# a failed send leaves the spool in place for the next flush. Only decision metadata is spooled (build_record).
# --------------------------------------------------------------------------------------------------------------

class KassyonSpool:
    def __init__(self, url: str, token: str, directory: str, *, batch_size: int = 200,
                 transport: Optional[Callable[[str, str, list[dict]], bool]] = None) -> None:
        import os as _os
        self.url = url.rstrip("/") + "/agent/decisions"
        self.token = token
        self.dir = _os.path.expanduser(directory)
        self.path = _os.path.join(self.dir, "kassyon-spool.jsonl")
        self.batch_size = max(1, batch_size)
        self._transport = transport or _http_post

    def append(self, record: dict) -> None:
        """Never raises: the agent's work matters more than its evidence."""
        import os as _os
        try:
            _os.makedirs(self.dir, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(",", ":")) + "\n")
        except Exception:
            pass

    def pending(self) -> int:
        try:
            with open(self.path, encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
        except OSError:
            return 0

    def flush(self) -> int:
        """Ship the spool in batches. Claims the file by renaming it (so concurrent hook processes keep appending
        to a fresh spool), sends, and puts back whatever was not delivered. Returns how many were delivered."""
        import os as _os
        import uuid as _uuid
        claim = f"{self.path}.{_uuid.uuid4().hex}.sending"
        try:
            _os.replace(self.path, claim)
        except OSError:
            return 0
        lines: list[str] = []
        try:
            with open(claim, encoding="utf-8") as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
        except OSError:
            pass
        sent, left = 0, []
        for i in range(0, len(lines), self.batch_size):
            chunk = lines[i:i + self.batch_size]
            batch = []
            for ln in chunk:
                try:
                    batch.append(json.loads(ln))
                except ValueError:
                    continue                      # a torn line is dropped, never resent forever
            try:
                ok = bool(self._transport(self.url, self.token, batch)) if batch else True
            except Exception:
                ok = False
            if ok:
                sent += len(batch)
            else:
                left = lines[i:]
                break
        try:
            if left:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write("\n".join(left) + "\n")
            _os.remove(claim)
        except OSError:
            pass
        return sent


def spool_from_env(state_dir: str | None = None) -> "KassyonSpool | None":
    """GUARDLAYER_KASSYON_URL + GUARDLAYER_KASSYON_KEY (an agk_ agent key) turn emission on; nothing is sent without
    both. GUARDLAYER_KASSYON_SPOOL_DIR overrides where records wait (default: the session state dir)."""
    import os as _os
    url, key = _os.environ.get("GUARDLAYER_KASSYON_URL", ""), _os.environ.get("GUARDLAYER_KASSYON_KEY", "")
    if not url or not key:
        return None
    d = _os.environ.get("GUARDLAYER_KASSYON_SPOOL_DIR") or state_dir or _os.environ.get("GUARDLAYER_STATE_DIR") \
        or "~/.guardlayer/sessions"
    return KassyonSpool(url, key, d)
