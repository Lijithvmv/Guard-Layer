"""Tests for the GuardLayer -> Kassyon connector: emitter + governance-posture consumer (no network)."""
from dataclasses import dataclass, field

from guardlayer.integrations.kassyon import KassyonEmitter, KassyonPolicy, SCHEMA, build_record


@dataclass
class _V:
    value: str


@dataclass
class _Result:
    verdict: _V
    id: str = "d1"
    observed_rules: list = field(default_factory=list)
    is_blocked: bool = False
    needs_review: bool = False
    timestamp: str = "2026-10-29T12:00:00Z"
    direction: str = "outbound"


def _res(v, **kw):
    return _Result(verdict=_V(v), is_blocked=(v == "block"), needs_review=(v == "review"), **kw)


def test_record_shape_and_verdict_mapping():
    r = build_record(_res("review", observed_rules=[{"rule": "untrusted_destination"}]),
                     system_id="prod", framework="claude-code", tool="send_money", consequence="irreversible")
    assert r["schema"] == SCHEMA
    assert r["verdict"] == "require_approval"          # review -> require_approval
    assert r["rules"] == ["untrusted_destination"]
    assert r["action"]["tool"] == "send_money"
    assert r["approval"]["required"] is True
    assert r["record_hash"].startswith("sha256:")
    # privacy: no payload/secret text in the record
    blob = str(r)
    assert "payload" not in blob and "secret" not in blob.lower()


def test_verdict_maps():
    assert build_record(_res("allow"), system_id="s", framework="f")["verdict"] == "allow"
    assert build_record(_res("block"), system_id="s", framework="f")["verdict"] == "deny"


def test_batches_at_size():
    sent = []
    em = KassyonEmitter("http://k", batch_size=3, transport=lambda u, t, b: sent.append(len(b)) or True)
    for _ in range(3):
        em.emit(_res("review"))
    assert sent == [3] and em.sent == 3 and em.pending == 0


def test_fail_open_keeps_buffer_and_never_raises():
    def boom(u, t, b):
        raise ConnectionError("kassyon down")
    em = KassyonEmitter("http://k", batch_size=2, transport=boom)
    em.emit(_res("deny")); em.emit(_res("deny"))     # triggers a flush that fails
    assert em.pending == 2 and em.sent == 0          # buffered, not lost, no exception
    # when it comes back, the buffer ships
    ok = []
    em._transport = lambda u, t, b: ok.append(len(b)) or True
    assert em.flush() == 2 and em.pending == 0


def test_sample_allow_keeps_review_drops_allows():
    sent_batches = []
    em = KassyonEmitter("http://k", batch_size=10, sample_allow=0,   # drop all low-signal allows
                        transport=lambda u, t, b: sent_batches.append(b) or True)
    em.emit(_res("allow")); em.emit(_res("allow"))
    em.emit(_res("review"))
    em.flush()
    verdicts = [d["verdict"] for b in sent_batches for d in b]
    assert verdicts == ["require_approval"] and em.dropped_allow == 2


# ---- governance-posture consumer ----------------------------------------------------------------------------

def _policy_payload():
    # mirrors Kassyon GET /agent/policy: security is a gap (enforce), exfil is effective (monitor)
    return {"generated_at": "2026-10-29T12:00:00Z", "summary": {"gap": 1, "effective": 2},
            "advisories": [
                {"framework": "EU AI Act", "control_ref": "Art.15", "title": "Accuracy, robustness and cybersecurity",
                 "trigger": "security", "status": "gap", "enforcement": "enforce", "occurrences": 0,
                 "last_seen": None, "fresh": False},
                {"framework": "NIST 800-53", "control_ref": "AC-4", "title": "Information flow enforcement",
                 "trigger": "exfil", "status": "effective", "enforcement": "monitor", "occurrences": 9,
                 "last_seen": "2026-10-29T11:00:00Z", "fresh": True},
                {"framework": "EU AI Act", "control_ref": "Art.14", "title": "Human oversight",
                 "trigger": "approval", "status": "gap", "enforcement": "enforce", "occurrences": 0,
                 "last_seen": None, "fresh": False}]}


def _policy(payload):
    return KassyonPolicy("http://k", token="agk_x", transport=lambda u, t: payload)


def test_policy_refresh_parses_advisories():
    p = _policy(_policy_payload())
    assert p.refresh() is True and p.last_ok is True and len(p.advisories) == 3
    art15 = next(a for a in p.advisories if a.control_ref == "Art.15")
    assert art15.enforce is True and art15.trigger == "security" and art15.fresh is False


def test_should_tighten_only_for_enforced_rule_category():
    p = _policy(_policy_payload()); p.refresh()
    assert p.should_tighten(["security"]) is True          # Art.15 is a gap -> enforce
    assert p.should_tighten(["exfil"]) is False             # AC-4 is effective -> monitor
    assert p.should_tighten(["boundary"]) is False          # not present -> no basis to tighten


def test_enforced_triggers_excludes_non_rule_triggers():
    # Art.14 is enforce but its trigger is "approval" (not a runtime rule) -> must not appear
    p = _policy(_policy_payload()); p.refresh()
    assert p.enforced_triggers == {"security"}


def test_advisories_for_explains_why():
    p = _policy(_policy_payload()); p.refresh()
    matched = p.advisories_for(["security", "exfil"])
    assert [a.control_ref for a in matched] == ["Art.15"]    # only the enforce one


def test_policy_fail_open_never_raises_and_keeps_last_known():
    good = _policy(_policy_payload()); good.refresh()
    # transport now blows up: refresh returns False, keeps the prior advisories, still answers
    def boom(u, t):
        raise ConnectionError("kassyon down")
    good._transport = boom
    assert good.refresh() is False and good.last_ok is False
    assert good.should_tighten(["security"]) is True         # last-known posture retained (fail-safe toward strict)


def test_policy_bad_shape_is_ignored():
    p = KassyonPolicy("http://k", transport=lambda u, t: {"nope": 1})
    assert p.refresh() is False and p.advisories == []


def test_rules_come_from_real_detections_not_only_observed_rules():
    """Regression, found by replaying recorded AgentDojo runs into a running Kassyon: an ENFORCED block carries its
    rules in `detections`; `observed_rules` is empty unless observe mode is on (and then holds plain strings). The
    v1 emitter read only `observed_rules`, so all 61 real blocks/reviews reached Kassyon with no rule and the
    exfil/boundary/security controls could never be evidenced."""
    from guardlayer.models import Detection, ScanResult, Verdict
    blocked = ScanResult(verdict=Verdict.BLOCK, score=0.9, direction="output", detections=[
        Detection(scanner="session", rule="untrusted_destination", category="prompt_injection", severity=0.9, message="m"),
        Detection(scanner="pii", rule="iban", category="pii", severity=0.6, message="m"),
        Detection(scanner="pii", rule="iban", category="pii", severity=0.6, message="dup")])
    r = build_record(blocked, system_id="s", framework="agentdojo")
    assert r["verdict"] == "deny"
    assert r["rules"] == ["untrusted_destination", "iban"]          # enforced rules, deduplicated, in order
    observed = ScanResult(verdict=Verdict.ALLOW, score=0.1, direction="output", observed_rules=["sensitive_data_egress"])
    assert build_record(observed, system_id="s", framework="x")["rules"] == ["sensitive_data_egress"]  # plain strings too


# ---- approval client (fail-closed) ----
from guardlayer.integrations.kassyon import ApprovalOutcome, KassyonApprovals  # noqa: E402


class _FakeQueue:
    """Kassyon's approval queue in memory: idempotent on request_id; a person decides via .decide()."""

    def __init__(self):
        self.rows, self.posts, self.gets = {}, [], 0

    def post(self, url, token, body):
        self.posts.append((url, token, body))
        rid = body["request_id"]
        row = self.rows.setdefault(rid, {"lineage_id": "L" + rid[:6], "status": "pending", "decided_by": None,
                                         "decided_at": None, "decision_note": ""})
        return {"request": dict(row), "created": True}

    def get(self, url, token):
        self.gets += 1
        lid = url.rsplit("/", 1)[1]
        return next((dict(r) for r in self.rows.values() if r["lineage_id"] == lid), None)

    def decide(self, rid, status, who="pat"):
        self.rows[rid].update(status=status, decided_by=who, decided_at="2026-11-04T10:00:00+00:00")


def _client(q, **kw):
    return KassyonApprovals("http://k", "agk_x", post=q.post, get=q.get, sleep=lambda s: None, **kw)


def test_approval_runs_only_after_a_named_person_approves():
    q = _FakeQueue()
    c = _client(q)
    o = c.hold(tool="send_money", consequence="irreversible", summary="pay vendor", rules=["untrusted_destination"],
               request_id="r1")
    assert o.status == "pending" and not o.approved
    url, tok, body = q.posts[0]
    assert url == "http://k/agent/approvals" and tok == "agk_x"
    assert set(body) == {"tool", "consequence", "summary", "rules", "request_id", "ttl_minutes"}   # metadata only
    q.decide("r1", "approved")
    o = c.status(o)
    assert o.approved and o.decided_by == "pat"
    assert o.as_record_approval() == {"required": True, "granted_by": "pat", "granted_ts": "2026-11-04T10:00:00+00:00"}
    rec = build_record(_res("review"), system_id="s", framework="f", approval=o.as_record_approval())
    assert rec["approval"]["granted_by"] == "pat" and rec["verdict"] == "require_approval"


def test_rejected_expired_timeout_and_unreachable_never_approve():
    q = _FakeQueue()
    c = _client(q)
    for st in ("rejected", "expired"):
        o = c.submit(tool="t", consequence="outbound", request_id=st)
        q.decide(st, st)
        o = c.status(o)
        assert o.status == st and not o.approved and o.as_record_approval()["granted_by"] is None
    o = c.hold(tool="t", consequence="outbound", request_id="slow", wait_seconds=0.001)
    assert o.status == "pending" and not o.approved                      # timed out waiting: not approval

    def down(*a, **k):
        raise OSError("connection refused")
    dead = KassyonApprovals("http://k", post=down, get=down, sleep=lambda s: None)
    o = dead.hold(tool="t", consequence="irreversible", wait_seconds=1)
    assert o.status == "unavailable" and not o.approved
    # an approved status with no named approver is not approval either
    assert not ApprovalOutcome("approved", decided_by=None).approved


def test_wait_polls_until_decided_and_unreachable_poll_keeps_last_status():
    q = _FakeQueue()
    c = _client(q, poll_seconds=0)
    o = c.submit(tool="t", consequence="irreversible", request_id="w")
    calls = {"n": 0}
    real_get = q.get

    def get(url, token):
        calls["n"] += 1
        if calls["n"] == 2:
            q.decide("w", "approved")
        if calls["n"] == 1:
            raise OSError("blip")                                       # transient failure: keep pending
        return real_get(url, token)
    c._get = get
    o = c.wait(o, timeout_seconds=60)
    assert o.approved and calls["n"] == 2


def test_submit_is_idempotent_on_request_id():
    q = _FakeQueue()
    c = _client(q)
    a = c.submit(tool="t", consequence="irreversible", request_id="same")
    b = c.submit(tool="t", consequence="irreversible", request_id="same")
    assert a.kassyon_id == b.kassyon_id and len(q.rows) == 1
    auto = c.submit(tool="t", consequence="irreversible", summary="x")  # derived id is stable for the same action
    again = c.submit(tool="t", consequence="irreversible", summary="x")
    assert auto.request_id == again.request_id
