"""Task profiles (0.8): the tools and argument values a task may use, chosen by trusted code per request."""

import pytest

from guardlayer import FileSessionStore, GuardLayer, SessionPolicy, Verdict
from guardlayer.config import build_guard
from guardlayer.tasks import TaskProfile

TASKS = {
    "summarise_inbox": {"tools": ["list_emails", "read_email"]},
    "reply_to_customer": {
        "tools": ["read_email", "get_customer", "send_email"],
        "arguments": [{"tool": "send_email", "argument": "to", "allow": ["{task.customer_email}"]}],
    },
    "triage": {"tools": ["read_email"]},
}


def guard(**kw):
    return GuardLayer(session_policy=SessionPolicy(tasks=TASKS), **kw)


def rules(result):
    return {d.rule for d in result.detections}


def test_tools_outside_the_task_need_review_whatever_the_wording():
    s = guard().session(task="summarise_inbox")
    assert "out_of_task" not in rules(s.scan_tool_call("read_email", {"id": 7}))
    r = s.scan_tool_call("send_email", {"to": "x@outside.example", "body": "hi"})  # whatever text asked for it
    assert r.verdict is Verdict.REVIEW and "out_of_task" in rules(r)
    assert r.metadata["session"]["task"] == "summarise_inbox"


def test_arguments_are_bound_to_the_trusted_request():
    s = guard().session(task="reply_to_customer", task_args={"customer_email": "asha@example.com"})
    ok = s.scan_tool_call("send_email", {"to": "Asha <ASHA@example.com>", "body": "Thanks"})
    other = s.scan_tool_call("send_email", {"to": "asha@example.com, someone@outside.example", "body": "Thanks"})
    assert not {"out_of_task", "task_argument_not_allowed"} & rules(ok)
    assert "task_argument_not_allowed" in rules(other) and other.verdict is Verdict.REVIEW


def test_no_task_changes_nothing():
    s = guard().session()
    assert not {"out_of_task", "task_argument_not_allowed"} & rules(s.scan_tool_call("send_email", {"to": "a@b.example"}))


def test_tasks_only_narrow_without_approval():
    s = guard().session(task="reply_to_customer", task_args={"customer_email": "asha@example.com"})
    s.set_task("triage")  # narrower: fine
    assert s.state.task_tools == ["read_email"]
    with pytest.raises(PermissionError):
        s.set_task("summarise_inbox")  # list_emails is new: widening
    s.set_task("summarise_inbox", approved=True)
    assert "widened (approved): summarise_inbox" in s.state.task_log
    s.narrow(["read_email", "delete_everything"])  # never adds a tool
    assert s.state.task_tools == ["read_email"]
    with pytest.raises(PermissionError):
        s.clear_task()
    s.clear_task(approved=True)
    assert s.state.task_tools is None


def test_task_errors_surface_early():
    g = guard()
    with pytest.raises(KeyError):
        g.session(task="nope")
    with pytest.raises(ValueError):
        g.session(task="reply_to_customer")  # {task.customer_email} not given
    with pytest.raises(ValueError):
        g.session().narrow(["read_email"])  # no task to narrow
    with pytest.raises(ValueError):
        TaskProfile.from_dict("t", {"tools": []})
    with pytest.raises(ValueError):
        TaskProfile.from_dict("t", {"tools": ["a"], "tool": ["b"]})


def test_tasks_in_config_and_across_processes(tmp_path):
    config = {"tasks": TASKS, "session": {"store": "file", "dir": str(tmp_path)}}
    one, two = build_guard(config), build_guard(config)  # e.g. two hook processes
    one.session("s1", task="summarise_inbox")
    r = two.session("s1").scan_tool_call("send_email", {"to": "x@outside.example"})
    assert "out_of_task" in rules(r)
    one.session("s1").set_task("triage")  # a newer, narrower version wins when copies merge
    assert two.session("s1").state.task_tools == ["read_email"]
    assert isinstance(two.sessions, FileSessionStore)
