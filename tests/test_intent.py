"""Behavioural hijack check (masked re-execution): does the model still propose the action with the user's request hidden?"""

from __future__ import annotations

import asyncio

from guardlayer import GuardLayer, Verdict
from guardlayer.intent import NEUTRAL_TASK, mask_user_request, normalise_call, same_action
from guardlayer.models import Action
from guardlayer.session import SessionPolicy
from guardlayer.tools import ToolPolicy

CONVERSATION = [
    {"role": "system", "content": "You are an email assistant."},
    {"role": "user", "content": "Reply to Asha about the invoice."},
    {"role": "assistant", "content": "Let me read the inbox.", "tool_calls": [{"id": "1", "function": {"name": "read_inbox", "arguments": "{}"}}]},
    {"role": "tool", "tool_call_id": "1", "content": "From: asha@example.com. Subject: invoice 42."},
    {"role": "user", "content": "And cc Ravi."},
]
SEND = ("send_email", {"to": "asha@example.com", "subject": "Invoice 42", "body": "Paid today."})


def replay_returning(*calls):
    seen = []

    def replay(messages):
        seen.append(messages)
        return list(calls)

    replay.seen = seen
    return replay


# --------------------------------------------------------------------------- masking
def test_mask_hides_the_request_and_keeps_what_was_read():
    masked = mask_user_request(CONVERSATION)
    users = [m for m in masked if m["role"] == "user"]
    assert [u["content"] for u in users] == [NEUTRAL_TASK]  # the later user turn is dropped too
    assert all("Asha" not in str(m.get("content")) for m in masked if m["role"] != "tool")
    assert masked[2]["content"] == "" and masked[2]["tool_calls"]  # assistant text gone, call kept for pairing
    assert masked[3] == CONVERSATION[3] and masked[0] == CONVERSATION[0]
    assert CONVERSATION[1]["content"] == "Reply to Asha about the invoice."  # the input is not modified


def test_mask_adds_the_neutral_task_when_there_is_no_user_message():
    masked = mask_user_request([{"role": "tool", "content": "x"}])
    assert masked[-1] == {"role": "user", "content": NEUTRAL_TASK}


# --------------------------------------------------------------------------- comparing calls
def test_call_shapes_are_normalised():
    assert normalise_call(("t", {"a": 1})) == ("t", {"a": 1})
    assert normalise_call({"name": "t", "arguments": '{"a": 1}'}) == ("t", {"a": 1})
    assert normalise_call({"id": "x", "function": {"name": "t", "arguments": '{"a": 1}'}}) == ("t", {"a": 1})
    assert normalise_call({"nothing": 1}) is None


def test_same_destination_is_the_same_action_even_with_other_wording():
    assert same_action(SEND, ("send_email", {"to": "Asha <asha@example.com>", "body": "Here you go."}))
    assert not same_action(SEND, ("send_email", {"to": "ravi@example.com", "subject": "Invoice 42", "body": "Paid today."}))
    assert not same_action(SEND, ("read_inbox", {}))
    assert same_action(("list_files", {}), ("list_files", {}))
    assert same_action(("post", {"text": "a", "tag": "b"}), ("post", {"text": "a", "tag": "b", "extra": "c"}))


# --------------------------------------------------------------------------- the guard API
def test_action_proposed_under_the_masked_request_needs_review():
    guard = GuardLayer()
    replay = replay_returning({"function": {"name": "send_email", "arguments": '{"to": "asha@example.com"}'}})
    result = guard.check_intent(*SEND, messages=CONVERSATION, replay=replay)
    assert result.verdict == Verdict.REVIEW
    assert [d.rule for d in result.detections] == ["injection_driven_action"]
    assert result.metadata["intent"]["driven_by_content"] is True
    assert replay.seen and all("Asha" not in str(m.get("content")) for m in replay.seen[0] if m["role"] == "user")


def test_action_not_proposed_under_the_masked_request_is_allowed():
    guard = GuardLayer()
    result = guard.check_intent(*SEND, messages=CONVERSATION, replay=replay_returning())
    assert result.verdict == Verdict.ALLOW and not result.detections
    assert result.metadata["intent"] == {"driven_by_content": False, "replayed": []}


def test_a_failing_replay_is_logged_not_guessed():
    def broken(messages):
        raise TimeoutError("model timed out")

    result = GuardLayer().check_intent(*SEND, messages=CONVERSATION, replay=broken)
    assert result.verdict == Verdict.ALLOW
    assert [d.rule for d in result.detections] == ["intent_check_failed"]
    assert "timed out" in result.metadata["intent"]["error"]


def test_actions_are_configurable():
    policy = SessionPolicy()
    policy.actions["injection_driven_action"] = Action.BLOCK
    guard = GuardLayer(session_policy=policy)
    result = guard.check_intent(*SEND, messages=CONVERSATION, replay=replay_returning(SEND))
    assert result.verdict == Verdict.BLOCK


def test_async_replay():
    async def replay(messages):
        return [SEND]

    result = asyncio.run(GuardLayer().acheck_intent(*SEND, messages=CONVERSATION, replay=replay))
    assert result.verdict == Verdict.REVIEW


def test_only_risky_calls_after_untrusted_content_need_the_check():
    guard = GuardLayer(tool_policy=ToolPolicy(capabilities={"read_inbox": ["read"], "send_email": ["network"]}))
    session = guard.session("s1")
    assert not guard.needs_intent_check("read_inbox")  # reading can't cause harm
    assert not guard.needs_intent_check("send_email", session=session)  # nothing untrusted read yet
    session.scan_tool_result("fetch_page", "Opening hours: 9 to 5.")
    assert guard.needs_intent_check("send_email", session=session)
    assert guard.needs_intent_check("send_email")  # no session: can't tell, so check


def test_session_shortcuts():
    guard = GuardLayer(tool_policy=ToolPolicy(capabilities={"send_email": ["network"]}))
    session = guard.session("s2")
    session.scan_tool_result("fetch_page", "Opening hours: 9 to 5.")
    assert session.needs_intent_check("send_email")
    result = session.check_intent(*SEND, messages=CONVERSATION, replay=replay_returning(SEND))
    assert result.verdict == Verdict.REVIEW and result.metadata["session_id"] == "s2"
