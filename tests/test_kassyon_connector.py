"""Tests for the GuardLayer -> Kassyon connector emitter (no network)."""
from dataclasses import dataclass, field

from guardlayer.integrations.kassyon import KassyonEmitter, SCHEMA, build_record


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
