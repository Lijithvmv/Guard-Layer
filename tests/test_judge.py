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
