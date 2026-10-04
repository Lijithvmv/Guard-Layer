"""The second-stage judge: answer parsing, and failing closed when the model is unavailable."""

from __future__ import annotations

import io
import json
from unittest import mock

from guardlayer.judge import OllamaJudge


def _reply(text: str) -> io.BytesIO:
    return io.BytesIO(json.dumps({"message": {"content": text}}).encode())


def _ask(text: str):  # type: ignore[no-untyped-def]
    with mock.patch("urllib.request.urlopen", return_value=_reply(text)):
        return OllamaJudge()(["Pay my rent"], "send_money", {"recipient": "X", "amount": 100})


def test_yes_and_no_are_parsed_with_reason() -> None:
    yes = _ask("YES - the user asked to pay rent.")
    assert yes.requested is True and "pay rent" in yes.reason
    no = _ask("no. The recipient was never mentioned.")
    assert no.requested is False and "recipient" in no.reason


def test_unparseable_or_unavailable_never_approves() -> None:
    assert _ask("Maybe, it depends.").requested is None
    with mock.patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        j = OllamaJudge()(["hi"], "send_email", {"to": "a@b.c"})
    assert j.requested is None and "unavailable" in j.reason


def test_judge_sees_only_user_messages_and_the_action() -> None:
    seen = {}

    def fake(req, timeout):  # type: ignore[no-untyped-def]
        seen["body"] = json.loads(req.data)
        return _reply("YES fine")

    with mock.patch("urllib.request.urlopen", side_effect=fake):
        OllamaJudge()(["Summarise my inbox"], "send_email", {"to": "boss@example.com"})
    prompt = seen["body"]["messages"][0]["content"]
    assert "Summarise my inbox" in prompt and "boss@example.com" in prompt
    assert seen["body"]["options"]["temperature"] == 0


# --- the judge inside GuardLayer (opt-in) ---------------------------------------------------------------------
from guardlayer import GuardLayer, SessionPolicy  # noqa: E402
from guardlayer.judge import Judgement  # noqa: E402


class FakeJudge:
    def __init__(self, answer):  # type: ignore[no-untyped-def]
        self.answer, self.asked = answer, []

    def __call__(self, prompts, tool, arguments):  # type: ignore[no-untyped-def]
        self.asked.append((list(prompts), tool))
        return Judgement(self.answer, "test")


def _guard(answer, **policy):  # type: ignore[no-untyped-def]
    g = GuardLayer(session_policy=SessionPolicy(default_integrity="untrusted", **policy))
    g.judge = FakeJudge(answer)
    return g


def _rules(r):  # type: ignore[no-untyped-def]
    return {d.rule for d in r.detections if d.action}


def test_judge_is_asked_only_where_the_rules_cant_see_the_harm():
    g = _guard(False)
    s = g.session()
    s.scan_input("Summarise my statements")
    assert "not_the_users_goal" not in _rules(s.scan_tool_call("update_password", {"password": "x"}))  # nothing untrusted read yet
    s.scan_tool_result("read_statement", "Statement: rent 1200, groceries 300")
    r = s.scan_tool_call("update_password", {"password": "new-pass-1"})
    assert "not_the_users_goal" in _rules(r) and r.needs_review
    assert g.judge.asked[-1] == (["Summarise my statements"], "update_password")
    n = len(g.judge.asked)
    s.scan_tool_call("write_file", {"path": "summary.md"})  # local: never asked
    s.scan_tool_call("http_get", {"url": "http://localhost:5173/"})  # this machine: never asked
    assert len(g.judge.asked) == n


def test_judge_yes_lets_it_run_and_unavailable_holds_unless_configured():
    g = _guard(True)
    s = g.session()
    s.scan_input("Change my password to something strong")
    s.scan_tool_result("read_statement", "Statement")
    assert not s.scan_tool_call("update_password", {"password": "x"}).needs_review
    g2 = _guard(None)
    s2 = g2.session()
    s2.scan_tool_result("read_statement", "Statement")
    assert "judge_unavailable" in _rules(s2.scan_tool_call("update_password", {"password": "x"}))
    g2.judge_unavailable = "allow"
    assert not s2.scan_tool_call("update_password", {"password": "x"}).needs_review


def test_prompts_are_kept_only_with_a_judge_first_two_and_latest_three():
    plain = GuardLayer().session()
    plain.scan_input("hello")
    assert plain.state.user_prompts == []
    s = _guard(True).session()
    for i in range(8):
        s.scan_input(f"message {i}")
    assert s.state.user_prompts == ["message 0", "message 1", "message 5", "message 6", "message 7"]
