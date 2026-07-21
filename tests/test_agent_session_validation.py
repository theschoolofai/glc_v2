"""/v1/chat's `agent`/`session` fields were fully free-form and written
straight into the cost ledger (glc/db.py::log_call) with no validation,
letting a caller attribute their own spend to an arbitrary agent/session
label (invariant 5: every stored fact must record its actual source).
"""

from __future__ import annotations


def test_oversized_session_is_rejected(app_client):
    r = app_client.post("/v1/chat", json={"prompt": "hi", "session": "x" * 500})
    assert r.status_code == 422


def test_malformed_agent_label_is_rejected(app_client):
    r = app_client.post(
        "/v1/chat",
        json={"prompt": "hi", "agent": "not a valid label; DROP TABLE calls;"},
    )
    assert r.status_code == 422


def test_reasonable_agent_and_session_still_validate(app_client):
    r = app_client.post(
        "/v1/chat",
        json={"prompt": "hi", "agent": "coding-assistant", "session": "run-42"},
    )
    # No providers configured in the test env, so this won't succeed end to
    # end — the point is it must not be rejected at validation (422).
    assert r.status_code != 422


def test_vision_route_validates_the_same_fields(app_client):
    """/v1/vision builds an inner ChatRequest from its own agent/session,
    so the same validation must hold there too."""
    r = app_client.post(
        "/v1/vision",
        json={
            "image": "data:image/png;base64,aGVsbG8=",
            "prompt": "describe",
            "agent": "not a valid label; DROP TABLE calls;",
        },
    )
    assert r.status_code == 422
