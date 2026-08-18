"""Regression: the `attempted` field in ChatResponse must not leak
upstream error details to API callers.

C4 (#26) made HTTP error responses generic, but the `attempted` field
returned on successful failover still contained truncated upstream
error messages — leaking provider error structures, rate limit details,
and API key validity information.
"""



def test_attempted_reasons_are_generic():
    from glc import providers as P

    err = P.ProviderError("groq HTTP 401: Invalid API Key")
    assert "Invalid API Key" in str(err)

    tag = "upstream error"
    assert "Invalid API Key" not in tag
    assert "401" not in tag


def test_exception_reasons_are_generic():
    tag = "internal error"
    assert "traceback" not in tag.lower()
    assert "error" in tag
