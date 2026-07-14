"""/v1/chat/batch had no ceiling on either the number of calls in one
batch or how many of them run concurrently -- a single POST could fire
hundreds of simultaneous upstream LLM requests (invariant 8: hard limits
on tool calls and cost).
"""

from __future__ import annotations


def test_max_concurrency_above_ceiling_is_rejected(app_client):
    r = app_client.post(
        "/v1/chat/batch",
        json={"calls": [{"prompt": "hi"}], "max_concurrency": 500},
    )
    assert r.status_code == 422


def test_max_concurrency_zero_is_rejected(app_client):
    r = app_client.post(
        "/v1/chat/batch",
        json={"calls": [{"prompt": "hi"}], "max_concurrency": 0},
    )
    assert r.status_code == 422


def test_batch_size_above_ceiling_is_rejected(app_client):
    r = app_client.post(
        "/v1/chat/batch",
        json={"calls": [{"prompt": "hi"}] * 101},
    )
    assert r.status_code == 422


def test_batch_within_bounds_is_accepted(app_client):
    r = app_client.post(
        "/v1/chat/batch",
        json={"calls": [{"prompt": "hi"}] * 5, "max_concurrency": 4},
    )
    # No providers configured in the test env, so individual calls inside
    # the batch will error out -- the point is the request itself is not
    # rejected at validation (422).
    assert r.status_code != 422
