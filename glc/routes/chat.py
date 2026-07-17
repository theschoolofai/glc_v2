"""V9-compatibility routes: /v1/chat, /v1/chat/batch, /v1/providers,
/v1/capabilities, /v1/status, /v1/routers, /v1/calls.

This module is a near-verbatim port of llm_gatewayV9/main.py's chat
pipeline. Bare imports were rewritten as package-relative imports; the
V9 fixes (json_object hint injection, Gemini cooldown handling, day
rollover, default URL inheritance) are preserved verbatim. Do not
regress them — tests in test_v9_compat.py assert behaviour shape.
"""

from __future__ import annotations

import asyncio as _asyncio
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from jsonschema import Draft202012Validator, ValidationError

from glc import db
from glc import providers as P
from glc.llm_schemas import (
    BatchChatRequest,
    ChatRequest,
    ChatResponse,
    EmbedRequest,
    EmbedResponse,
    ResponseFormat,
    RouterDecision,
    ToolCall,
    VisionRequest,
)
from glc.routes.control import _check_data_plane_rate_limit, _require_token
from glc.routing import DEFAULT_ROUTER_ORDER, LIMITS, SHORTCUTS

DEFAULT_ORDER = ["ollama", "gemini", "nvidia", "groq", "cerebras", "openrouter", "github"]
ORDER = [x.strip() for x in os.getenv("LLM_ORDER", ",".join(DEFAULT_ORDER)).split(",") if x.strip()]
ROUTER_ORDER = [
    x.strip() for x in os.getenv("ROUTER_ORDER", ",".join(DEFAULT_ROUTER_ORDER)).split(",") if x.strip()
]

_AGENT_ROUTING_PATH = Path(__file__).parent.parent / "agent_routing.yaml"
AGENT_ROUTING: dict[str, str] = {}
if _AGENT_ROUTING_PATH.exists():
    try:
        AGENT_ROUTING = yaml.safe_load(_AGENT_ROUTING_PATH.read_text()) or {}
    except Exception as e:  # pragma: no cover
        print(f"[glc] failed to parse agent_routing.yaml: {e!r}")

TIER_TO_ORDER = {
    "TINY": ["github", "openrouter", "groq", "nvidia", "cerebras", "gemini", "ollama"],
    "LARGE": ["gemini", "groq", "nvidia", "cerebras", "github", "openrouter", "ollama"],
}

ROUTER_SAMPLE_HEAD = 400
ROUTER_SAMPLE_TAIL = 400
ROUTER_PROMPT = (
    "You are a routing classifier. Given a token_count and a content sample, "
    "output exactly one of: TINY, LARGE, or HUGE.\n\n"
    "Rules:\n"
    "- TINY: token_count below 1000 with simple factual content.\n"
    "- LARGE: token_count between 1000 and 8000, OR token_count below 1000 "
    "but content is dense (code, base64, multilingual, technical).\n"
    "- HUGE: token_count above 8000.\n\n"
    "Output the single word and nothing else."
)

router = APIRouter()


# ─────────────────────────── helpers (verbatim port) ──────────────────────────


def _estimate_tokens(text: str) -> int:
    return int(len(text.split()) * 1.4)


def _build_sample(text: str) -> str:
    if len(text) <= ROUTER_SAMPLE_HEAD + ROUTER_SAMPLE_TAIL + 10:
        return text
    return text[:ROUTER_SAMPLE_HEAD] + "\n...\n" + text[-ROUTER_SAMPLE_TAIL:]


def _tier_from_count(tokens: int) -> str:
    if tokens > 8000:
        return "HUGE"
    if tokens >= 1000:
        return "LARGE"
    return "TINY"


def _parse_tier(text: str) -> str | None:
    up = (text or "").upper()
    for tier in ("HUGE", "LARGE", "TINY"):
        if tier in up:
            return tier
    return None


async def _classify_tier(req, role, router_pool, prompt_text):
    estimated = _estimate_tokens(prompt_text)
    if estimated > 8000:
        return RouterDecision(
            role=role,
            tier="HUGE",
            estimated_tokens=estimated,
            router_provider="(skipped)",
            router_model="(skipped)",
            router_latency_ms=0,
            fallback_used=True,
        )
    sample = _build_sample(prompt_text)
    envelope = f"token_count: {estimated}\nsample:\n{sample}"
    call_role = f"router_{role}"
    last_provider = last_model = ""
    last_latency = 0
    for name in router_pool.candidates():
        ok, _ = router_pool.state[name].can_use(LIMITS[name], 400)
        if not ok:
            continue
        provider = router_pool.providers[name]
        t0 = time.time()
        router_pool.state[name].record(0)
        last_provider, last_model = name, provider.model
        try:
            result = await provider.chat(
                messages=[{"role": "user", "content": envelope}],
                system_blocks=ROUTER_PROMPT,
                max_tokens=8,
                temperature=0,
                model=None,
                tools=None,
                tool_choice=None,
                reasoning="off",
                response_format=None,
                cache_system=False,
            )
            latency = int((time.time() - t0) * 1000)
            last_latency = latency
            tokens = (result.get("input_tokens") or 0) + (result.get("output_tokens") or 0)
            router_pool.state[name].tokens_today += tokens
            router_pool.state[name].tokens_minute.append((time.time(), tokens))
            tier = _parse_tier(result.get("text", ""))
            if tier == "HUGE" and estimated <= 8000:
                tier = "LARGE"
            if tier is None:
                db.log_call(
                    provider=name,
                    model=result.get("model", provider.model),
                    input_tokens=result.get("input_tokens", 0),
                    output_tokens=result.get("output_tokens", 0),
                    latency_ms=latency,
                    status="error",
                    error=f"unparseable tier reply: {result.get('text', '')[:100]}",
                    prompt_chars=len(envelope),
                    call_role=call_role,
                    router_decision="unparseable",
                )
                continue
            db.log_call(
                provider=name,
                model=result.get("model", provider.model),
                input_tokens=result.get("input_tokens", 0),
                output_tokens=result.get("output_tokens", 0),
                latency_ms=latency,
                status="ok",
                prompt_chars=len(envelope),
                response_chars=len(result.get("text", "")),
                call_role=call_role,
                router_decision=tier,
            )
            return RouterDecision(
                role=role,
                tier=tier,
                estimated_tokens=estimated,
                router_provider=name,
                router_model=result.get("model", provider.model),
                router_latency_ms=latency,
                fallback_used=False,
            )
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            last_latency = latency
            db.log_call(
                provider=name,
                model=provider.model,
                status="error",
                error=str(e)[:500],
                latency_ms=latency,
                call_role=call_role,
                router_decision="error",
            )
            continue
    return RouterDecision(
        role=role,
        tier=_tier_from_count(estimated),
        estimated_tokens=estimated,
        router_provider=last_provider or "(unavailable)",
        router_model=last_model or "(unavailable)",
        router_latency_ms=last_latency,
        fallback_used=True,
    )


def _normalize_messages(req: ChatRequest):
    if req.messages:
        return list(req.messages)
    return [{"role": "user", "content": req.prompt or ""}]


def _system_blocks(req: ChatRequest):
    if req.system is None:
        return None
    if isinstance(req.system, str):
        if req.cache_system:
            return [{"text": req.system, "cache": True}]
        return req.system
    return [b.model_dump() if hasattr(b, "model_dump") else b for b in req.system]


def _est_tokens(messages, system_blocks, max_tokens):
    chars = 0
    for m in messages:
        c = m.get("content", "")
        if isinstance(c, list):
            chars += len(P._extract_text_blocks(c))
            chars += 1200 * sum(
                1 for b in c if isinstance(b, dict) and b.get("type") in ("image_url", "image", "input_image")
            )
        else:
            chars += len(str(c))
    if isinstance(system_blocks, str):
        chars += len(system_blocks)
    elif isinstance(system_blocks, list):
        for b in system_blocks:
            chars += len(b.get("text", "") if isinstance(b, dict) else "")
    return chars // 4 + max_tokens


def _backoff_for(err: Exception, has_model_override: bool = False):
    msg = str(err).lower()
    status = getattr(err, "status", None)
    if status == 429:
        if "queue" in msg:
            return 15, "server queue full"
        if "quota" in msg or "rpm" in msg or "per minute" in msg:
            return 60, "RPM quota burned"
        if "rpd" in msg or "per day" in msg or "daily" in msg:
            return 3600, "RPD quota burned"
        return 30, "rate limited"
    if status and 500 <= status < 600:
        return 20, f"upstream {status}"
    if status == 408 or "timeout" in msg:
        return 10, "timeout"
    if status in (401, 403):
        if has_model_override:
            return 0, ""
        return 600, "auth error"
    if status == 404 and has_model_override:
        return 0, ""
    return 0, ""


def _attempts_str(attempts):
    return "; ".join(f"{a['provider']}:{a['reason']}" for a in attempts)


def _required_caps(req: ChatRequest):
    caps = []
    if req.tools:
        caps.append("tools")
    if req.reasoning and req.reasoning != "off":
        caps.append("reasoning")
    if req.response_format:
        caps.append("structured")
    if req.messages:
        for m in req.messages:
            if P._content_has_image(m.get("content")):
                caps.append("vision")
                break
    return caps


def _sanitized_fetch_error(url: str, e: Exception) -> str:
    """A failed image fetch used to embed the raw httpx exception text
    (connection errors, OS resolver errno strings, upstream status/reason)
    straight into the 400 body -- network/infra details an unauthenticated-
    looking client could use to fingerprint the network the gateway sits
    on. Logs the full detail server-side (queryable via /v1/calls, which
    requires the same install token this caller already presented to
    reach this route at all) and returns only a generic message plus a
    short reference id.
    """
    ref = secrets.token_hex(4)
    db.log_call(
        provider="image_fetch",
        model="(none)",
        status="error",
        error=f"[{ref}] {url!r}: {e}"[:500],
        call_role="image_fetch",
    )
    return f"failed to fetch image url (ref: {ref}); detail logged server-side, see /v1/calls"


async def _resolve_image_urls(messages):
    import base64

    import httpx as _httpx

    from glc.security.ssrf import BlockedURLError, assert_public_url

    MAX_IMAGE_REDIRECTS = 5

    async def _fetch_to_data_url(url: str) -> str:
        from glc.security.resource_limits import MAX_IMAGE_FETCH_BYTES

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; GLCv1/0.1; +image-resolver)",
            "Accept": "image/*,*/*;q=0.8",
        }
        # follow_redirects=False: each hop is re-validated below before it's
        # followed, so a redirect can't be used to reach a non-public address
        # that would've been rejected if given directly.
        async with _httpx.AsyncClient(timeout=30, follow_redirects=False, headers=headers) as c:
            for _ in range(MAX_IMAGE_REDIRECTS + 1):
                try:
                    await assert_public_url(url)
                except BlockedURLError as e:
                    raise HTTPException(400, f"refusing to fetch image url {url!r}: {e}")
                try:
                    # Streamed (not client.get()) so a huge/slow-loris body
                    # never gets fully buffered before the size cap below
                    # gets a chance to abort it -- docs/strides_testing.md's
                    # Denial-of-service entry names exactly this ("a huge
                    # image... exhausts memory") as a case client.get()'s
                    # buffer-then-return behavior didn't guard against.
                    async with c.stream("GET", url) as r:
                        if r.next_request is not None:
                            url = str(r.next_request.url)
                            continue
                        try:
                            r.raise_for_status()
                        except _httpx.HTTPError as e:
                            raise HTTPException(400, _sanitized_fetch_error(url, e))
                        mt = (r.headers.get("content-type") or "image/png").split(";")[0].strip()
                        body = bytearray()
                        async for chunk in r.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > MAX_IMAGE_FETCH_BYTES:
                                raise HTTPException(
                                    400,
                                    f"image url {url!r} exceeded the {MAX_IMAGE_FETCH_BYTES}-byte fetch limit",
                                )
                        b64 = base64.b64encode(bytes(body)).decode()
                        return f"data:{mt};base64,{b64}"
                except _httpx.HTTPError as e:
                    raise HTTPException(400, _sanitized_fetch_error(url, e))
            raise HTTPException(400, f"too many redirects fetching image url {url!r}")

    out = []
    for m in messages:
        content = m.get("content")
        if not isinstance(content, list):
            out.append(m)
            continue
        new_blocks = []
        changed = False
        for b in content:
            if isinstance(b, dict) and b.get("type") == "image_url":
                iu = b.get("image_url")
                url = iu.get("url") if isinstance(iu, dict) else iu
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    data_url = await _fetch_to_data_url(url)
                    new_blocks.append({"type": "image_url", "image_url": {"url": data_url}})
                    changed = True
                    continue
            new_blocks.append(b)
        if changed:
            new_m = dict(m)
            new_m["content"] = new_blocks
            out.append(new_m)
        else:
            out.append(m)
    return out


def _validate_structured(text: str, schema: dict):
    try:
        obj = json.loads(text)
    except Exception as e:
        raise ValueError(f"output is not JSON: {e}")
    Draft202012Validator(schema).validate(obj)
    return obj


# ─────────────────────────── routes ───────────────────────────


@router.post("/v1/chat")
async def chat(req: ChatRequest, request: Request):
    # Data-plane routes dispatch straight to paid upstream providers with
    # no auth at all before this check existed -- anyone with the URL could
    # run up the operator's bill or DoS the deployment. Same install-token
    # gate /v1/control/* and /v1/cost/by_agent already use. Checked off
    # request.headers directly (not a Header(...) dependency) so the check
    # still fires when vision()/chat_batch() call this function in-process
    # rather than through FastAPI's own routing.
    _require_token(request.headers.get("authorization"))
    _check_data_plane_rate_limit("chat")
    if req.tools:
        from glc.security.prompt_injection import scan_tool_defs

        problems = scan_tool_defs(req.tools)
        if problems:
            raise HTTPException(400, f"tool definition(s) rejected by prompt-injection scan: {problems}")
    if req.messages:
        # docs/attack_chain_fix.md: scan_tool_defs() above only ever
        # covered the tool *definitions* a caller supplies -- the
        # conversation itself, including anything shaped like a tool's
        # own returned output ({"role": "tool"/"function", ...}),
        # reached the model with zero scrutiny. scan_messages() closes
        # that specific, live surface -- see its own docstring for why
        # it's scoped to tool/function roles and not the human
        # principal's own messages.
        from glc.security.prompt_injection import scan_messages

        msg_problems = scan_messages(req.messages)
        if msg_problems:
            raise HTTPException(400, f"message(s) rejected by prompt-injection scan: {msg_problems}")
    from glc.security.resource_limits import MAX_TOKENS_CEILING

    if req.max_tokens > MAX_TOKENS_CEILING:
        raise HTTPException(400, f"max_tokens {req.max_tokens} exceeds the ceiling of {MAX_TOKENS_CEILING}")
    state = request.app.state
    rtr = state.router
    router_pool = state.router_pool
    messages = _normalize_messages(req)
    if any(P._content_has_image(m.get("content")) for m in messages):
        messages = await _resolve_image_urls(messages)
    system_blocks = _system_blocks(req)
    prompt_text = "".join(
        (
            P._extract_text_blocks(m.get("content", ""))
            if isinstance(m.get("content"), list)
            else str(m.get("content", ""))
        )
        for m in messages
    )
    est = _est_tokens(messages, system_blocks, req.max_tokens)
    explicit_override = bool(req.provider)
    required_caps = _required_caps(req)

    if req.agent and not req.provider:
        pinned = AGENT_ROUTING.get(req.agent)
        if pinned and pinned in rtr.providers:
            req.provider = pinned
            explicit_override = True

    retries = 0
    router_decision: RouterDecision | None = None
    if req.auto_route and not req.provider:
        router_decision = await _classify_tier(req, req.auto_route, router_pool, prompt_text)
        if router_decision.tier == "HUGE":
            raise HTTPException(
                503,
                {
                    "error": "input exceeds 8000 tokens",
                    "hint": "Use the Summarizer Agent (V7, not yet implemented). "
                    "For now, chunk the input or set provider=g explicitly to try Gemini anyway.",
                    "router_decision": router_decision.model_dump(),
                },
            )
        tier_order = TIER_TO_ORDER[router_decision.tier]
        candidates = [p for p in tier_order if p in rtr.providers]
    else:
        candidates = rtr.candidates(req.provider) if req.provider else list(rtr.order)

    if req.provider and not candidates:
        raise HTTPException(
            400,
            f"unknown provider '{req.provider}'. Try one of: {list(rtr.providers)} or shortcuts {list(SHORTCUTS)}",
        )

    all_attempts: list[dict] = []
    last_err = None

    if explicit_override and len(candidates) == 1:
        deadline = time.time() + 30
        while time.time() < deadline:
            name, _ = rtr.pick(est, candidates, required_caps=required_caps)
            if name is not None:
                break
            cd = rtr.state[candidates[0]].snapshot(LIMITS[candidates[0]])["cooldown_remaining"]
            if cd <= 0 or cd > 30:
                break
            await _asyncio.sleep(min(cd + 0.05, 5))

    for _ in range(len(candidates) + 1):
        name, atts = rtr.pick(est, candidates, required_caps=required_caps)
        all_attempts.extend(atts)
        if name is None:
            break
        provider = rtr.providers[name]
        t0 = time.time()
        rtr.state[name].record(0)
        try:
            if req.stream:

                async def gen():
                    try:
                        agg = []
                        async for chunk in provider.stream(
                            messages,
                            max_tokens=req.max_tokens,
                            temperature=req.temperature,
                            model=req.model,
                            tools=req.tools,
                            tool_choice=req.tool_choice,
                            reasoning=req.reasoning,
                            response_format=req.response_format,
                            system_blocks=system_blocks,
                            cache_system=bool(req.cache_system),
                        ):
                            agg.append(chunk)
                            if chunk.startswith("[[TOOL_CALL_DELTA]]"):
                                yield f"data: {json.dumps({'provider': name, 'tool_call_delta': chunk[len('[[TOOL_CALL_DELTA]] ') :]})}\n\n"
                            else:
                                yield f"data: {json.dumps({'provider': name, 'delta': chunk})}\n\n"
                        text = "".join(agg)
                        latency = int((time.time() - t0) * 1000)
                        db.log_call(
                            provider=name,
                            model=req.model or provider.model,
                            latency_ms=latency,
                            status="ok",
                            prompt_chars=len(prompt_text),
                            response_chars=len(text),
                            override=req.provider,
                            attempted=_attempts_str(all_attempts),
                            agent=req.agent,
                            session=req.session,
                            retries=retries,
                        )
                        yield f"data: {json.dumps({'done': True, 'provider': name})}\n\n"
                    except Exception as e:
                        db.log_call(
                            provider=name,
                            model=req.model or provider.model,
                            status="error",
                            error=str(e)[:500],
                            latency_ms=int((time.time() - t0) * 1000),
                            prompt_chars=len(prompt_text),
                            override=req.provider,
                            attempted=_attempts_str(all_attempts),
                            agent=req.agent,
                            session=req.session,
                            retries=retries,
                        )
                        yield f"data: {json.dumps({'error': str(e)[:300]})}\n\n"

                return StreamingResponse(gen(), media_type="text/event-stream")

            try:
                result = await provider.chat(
                    messages,
                    max_tokens=req.max_tokens,
                    temperature=req.temperature,
                    model=req.model,
                    tools=req.tools,
                    tool_choice=req.tool_choice,
                    reasoning=req.reasoning,
                    response_format=req.response_format,
                    system_blocks=system_blocks,
                    cache_system=bool(req.cache_system),
                )
            except (P.ProviderError, Exception) as transient:
                status = getattr(transient, "status", None)
                msg = str(transient).lower()
                retryable = (status is not None and 500 <= status < 600) or status == 408 or "timeout" in msg
                if not retryable:
                    raise
                await _asyncio.sleep(min(2.0, 0.5 * (2**retries)))
                retries += 1
                result = await provider.chat(
                    messages,
                    max_tokens=req.max_tokens,
                    temperature=req.temperature,
                    model=req.model,
                    tools=req.tools,
                    tool_choice=req.tool_choice,
                    reasoning=req.reasoning,
                    response_format=req.response_format,
                    system_blocks=system_blocks,
                    cache_system=bool(req.cache_system),
                )
            latency = int((time.time() - t0) * 1000)

            parsed = None
            if req.response_format and req.response_format.schema_ and not result["tool_calls"]:
                try:
                    parsed = _validate_structured(result["text"], req.response_format.schema_)
                except (ValueError, ValidationError) as ve:
                    fix_msgs = list(messages) + [
                        {"role": "assistant", "content": result["text"]},
                        {
                            "role": "user",
                            "content": f"Your previous reply did not match the required JSON schema: {ve}. Reply ONLY with valid JSON conforming to the schema.",
                        },
                    ]
                    result = await provider.chat(
                        fix_msgs,
                        max_tokens=req.max_tokens,
                        temperature=0,
                        model=req.model,
                        response_format=req.response_format,
                        system_blocks=system_blocks,
                        cache_system=bool(req.cache_system),
                    )
                    try:
                        parsed = _validate_structured(result["text"], req.response_format.schema_)
                    except (ValueError, ValidationError) as ve2:
                        raise HTTPException(503, f"structured output failed validation: {ve2}")

            tokens = (result["input_tokens"] or 0) + (result["output_tokens"] or 0)
            rtr.state[name].tokens_today += tokens
            rtr.state[name].tokens_minute.append((time.time(), tokens))
            if router_decision is not None:
                router_decision.chosen_worker_provider = name
                router_decision.chosen_worker_model = result["model"]
            db.log_call(
                provider=name,
                model=result["model"],
                input_tokens=result["input_tokens"],
                output_tokens=result["output_tokens"],
                cache_create_tokens=result["cache_creation_input_tokens"],
                cache_read_tokens=result["cache_read_input_tokens"],
                latency_ms=latency,
                status="ok",
                prompt_chars=len(prompt_text),
                response_chars=len(result["text"]),
                override=req.provider,
                attempted=_attempts_str(all_attempts),
                tool_calls=len(result["tool_calls"]),
                reasoning_applied=result["reasoning_applied"],
                tool_dialect=result["tool_call_dialect"],
                call_role="worker",
                router_decision=router_decision.tier if router_decision else None,
                agent=req.agent,
                session=req.session,
                retries=retries,
            )
            return ChatResponse(
                provider=name,
                model=result["model"],
                text=result["text"],
                tool_calls=[ToolCall(**tc) for tc in result["tool_calls"]],
                stop_reason=result["stop_reason"],
                input_tokens=result["input_tokens"],
                output_tokens=result["output_tokens"],
                cache_creation_input_tokens=result["cache_creation_input_tokens"],
                cache_read_input_tokens=result["cache_read_input_tokens"],
                latency_ms=latency,
                tool_call_dialect=result["tool_call_dialect"],
                reasoning_applied=result["reasoning_applied"],
                parsed=parsed,
                attempted=all_attempts,
                router_decision=router_decision,
                retries=retries,
            ).model_dump()
        except P.ProviderError as e:
            last_err = str(e)
            secs, reason = _backoff_for(e, has_model_override=bool(req.model))
            if secs > 0:
                rtr.state[name].mark_unavailable(secs, reason)
            db.log_call(
                provider=name,
                model=req.model or provider.model,
                status="error",
                error=str(e)[:500],
                latency_ms=int((time.time() - t0) * 1000),
                prompt_chars=len(prompt_text),
                override=req.provider,
                attempted=_attempts_str(all_attempts),
                agent=req.agent,
                session=req.session,
                retries=retries,
            )
            tag = f"failed: {str(e)[:100]}"
            if secs > 0:
                tag += f" → backoff {secs:.0f}s ({reason})"
            all_attempts.append({"provider": name, "reason": tag})
            if explicit_override or not getattr(e, "retryable", True):
                # Logged in full just above (db.log_call, status="error")
                # -- this used to also embed the raw provider exception
                # (e.g. a Gemini 400 body verbatim) in the client-facing
                # message. See docs/fix_security_breach.md, "Round nine", C4.
                raise HTTPException(502, f"{name} failed; detail logged server-side, see /v1/calls")
            candidates = [c for c in candidates if c != name]
            continue
        except HTTPException:
            raise
        except Exception as e:
            last_err = str(e)
            secs, reason = _backoff_for(e, has_model_override=bool(req.model))
            if secs > 0:
                rtr.state[name].mark_unavailable(secs, reason)
            db.log_call(
                provider=name,
                model=req.model or provider.model,
                status="error",
                error=str(e)[:500],
                latency_ms=int((time.time() - t0) * 1000),
                prompt_chars=len(prompt_text),
                override=req.provider,
                attempted=_attempts_str(all_attempts),
                agent=req.agent,
                session=req.session,
                retries=retries,
            )
            all_attempts.append({"provider": name, "reason": f"exception: {str(e)[:120]}"})
            if explicit_override:
                # Same fix as the ProviderError branch above -- detail is
                # already logged (db.log_call just above), the client
                # only gets a generic message now.
                raise HTTPException(502, f"{name} failed; detail logged server-side, see /v1/calls")
            candidates = [c for c in candidates if c != name]
            continue

    # Used to embed the raw attempts list (each entry already truncated
    # exception text, e.g. "failed: <SDK error message>") and last_err
    # verbatim in the client-facing body -- upstream SDK/network detail
    # an unauthenticated-looking client could use to fingerprint providers
    # or the gateway's network. Every attempt was already logged
    # server-side above (db.log_call, status="error") before this point,
    # so nothing is lost by not repeating it here.
    raise HTTPException(
        503,
        f"all providers unavailable after {len(all_attempts)} attempt(s); detail logged server-side, see /v1/calls",
    )


@router.post("/v1/chat/batch")
async def chat_batch(req: BatchChatRequest, request: Request):
    # Checked here too, not just inside the per-call chat(): _one() below
    # catches HTTPException and folds it into a 200 body per item, so
    # without this an unauthenticated batch call would come back 200 with
    # every item individually reporting status_code=401 instead of a clean
    # top-level 401.
    _require_token(request.headers.get("authorization"))
    _check_data_plane_rate_limit("chat_batch")
    sem = _asyncio.Semaphore(max(1, req.max_concurrency))

    async def _one(call: ChatRequest):
        async with sem:
            try:
                return await chat(call, request)
            except HTTPException as he:
                return {"error": str(he.detail), "status_code": he.status_code}
            except Exception as e:
                return {"error": str(e)[:400], "status_code": 500}

    results = await _asyncio.gather(*[_one(c) for c in req.calls])
    return {"results": results}


@router.post("/v1/vision")
async def vision(req: VisionRequest, request: Request):
    _require_token(request.headers.get("authorization"))
    _check_data_plane_rate_limit("vision")
    content: list[dict[str, Any]] = [{"type": "text", "text": req.prompt}]
    content.append({"type": "image_url", "image_url": {"url": req.image}})
    inner = ChatRequest(
        messages=[{"role": "user", "content": content}],
        system=req.system,
        provider=req.provider,
        model=req.model,
        max_tokens=req.max_tokens,
        temperature=req.temperature,
        response_format=(
            ResponseFormat(type="json_schema", schema=req.schema_, name=req.schema_name, strict=True)
            if req.schema_
            else None
        ),
        agent=req.agent,
        session=req.session,
    )
    return await chat(inner, request)


@router.post("/v1/embed")
async def embed(req: EmbedRequest, request: Request):
    _require_token(request.headers.get("authorization"))
    _check_data_plane_rate_limit("embed")
    from glc import embedders as E

    state = request.app.state
    embedders = state.embedders
    if not embedders:
        raise HTTPException(503, "no embedding providers configured")
    if len(req.text) > E.MAX_INPUT_CHARS:
        raise HTTPException(
            413,
            f"text is {len(req.text)} chars; embed input is capped at "
            f"{E.MAX_INPUT_CHARS} chars (~{E.MAX_INPUT_CHARS // 4} tokens). Chunk and re-embed.",
        )
    t0 = time.time()
    try:
        name, result, attempts, latency = await E.embed_with_failover(
            embedders,
            req.text,
            req.task_type,
            explicit=req.provider,
        )
    except E.EmbedderError as e:
        latency = int((time.time() - t0) * 1000)
        db.log_call(
            provider=req.provider or "(any)",
            model="(none)",
            status="error",
            error=str(e)[:500],
            latency_ms=latency,
            prompt_chars=len(req.text),
            override=req.provider,
            call_role="embed",
        )
        if req.provider:
            if e.status == 429:
                raise HTTPException(429, f"{req.provider} rate-limited: {e}")
            if e.status == 400:
                raise HTTPException(400, str(e))
            raise HTTPException(502, f"{req.provider} embed failed: {e}")
        raise HTTPException(503, str(e))

    db.log_call(
        provider=name,
        model=result["model"],
        status="ok",
        latency_ms=latency,
        prompt_chars=len(req.text),
        override=req.provider,
        attempted=_attempts_str(attempts),
        call_role="embed",
        embed_dim=result["dim"],
    )
    return EmbedResponse(
        provider=name,
        model=result["model"],
        embedding=result["embedding"],
        dim=result["dim"],
        latency_ms=latency,
        attempted=attempts,
    ).model_dump()


@router.get("/v1/embedders")
async def list_embedders(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    from glc import embedders as E

    state = request.app.state
    return {
        "order": state.embed_order,
        "models": {e.name: e.model for e in state.embedders},
        "fixed_dim": E.EMBED_DIM,
        "max_input_chars": E.MAX_INPUT_CHARS,
        "backoff_steps_s": E.BACKOFF_STEPS,
        "live": {e.name: e.state.snapshot() for e in state.embedders},
        "today": db.aggregate(call_role="embed"),
    }


@router.get("/v1/cost/by_agent")
async def cost_by_agent(
    session: str | None = None,
    agent: str | None = None,
    authorization: str | None = Header(default=None),
):
    # Per-agent/session token counts and estimated spend are usage
    # metadata, not a secret -- but they were the one asset in
    # docs/threat_model.md with no protection at all, unlike every
    # /v1/control/* route. Same install-token gate as those.
    _require_token(authorization)
    from glc import pricing as _pricing

    raw = db.by_agent(session=session)
    if agent:
        raw = {agent: raw.get(agent, [])}
    out: dict[str, list[dict]] = {}
    for ag, rows in raw.items():
        out[ag] = []
        for r in rows:
            r2 = dict(r)
            r2["dollars"] = _pricing.estimate_usd(r["provider"], r.get("in_tok") or 0, r.get("out_tok") or 0)
            out[ag].append(r2)
    return out


@router.get("/v1/providers")
async def list_providers(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    r = request.app.state.router
    return {
        "order": r.order,
        "providers": list(r.providers.keys()),
        "shortcuts": SHORTCUTS,
        "limits": LIMITS,
        "models": {n: p.model for n, p in r.providers.items()},
    }


@router.get("/v1/capabilities")
async def capabilities(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    r = request.app.state.router
    out = {}
    for name, p in r.providers.items():
        caps = dict(getattr(p, "capabilities", {}))
        caps = P.model_capabilities(name, p.model, caps)
        caps["model"] = p.model
        caps.update(
            {
                "max_ctx": LIMITS[name]["max_ctx"],
                "rpm": LIMITS[name]["rpm"],
                "rpd": LIMITS[name]["rpd"],
            }
        )
        out[name] = caps
    return out


@router.get("/v1/status")
async def status(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    r = request.app.state.router
    return {
        "order": r.order,
        "live": r.all_status(),
        "today": db.aggregate(call_role="worker"),
        "limits": LIMITS,
    }


@router.get("/v1/routers")
async def routers(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    rp = request.app.state.router_pool
    return {
        "order": rp.order,
        "providers": list(rp.providers.keys()),
        "models": {n: p.model for n, p in rp.providers.items()},
        "live": rp.all_status(),
        "today": db.aggregate(call_role="router"),
        "limits": {k: LIMITS[k] for k in rp.providers},
        "tier_to_order": TIER_TO_ORDER,
    }


@router.get("/v1/calls")
async def calls(
    limit: int = 100,
    provider: str | None = None,
    status: str | None = None,
    authorization: str | None = Header(default=None),
):
    _require_token(authorization)
    return db.recent(limit=limit, provider=provider, status=status)
