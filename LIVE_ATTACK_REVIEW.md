# Live attack review — hosted gateway

Target: `https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run`  
Date: 2026-07-16

## Before latest fix (found by attacking host)

| Attack | Result | Verdict |
|--------|--------|---------|
| Anon `POST /v1/chat` etc. | 401 | A1 closed |
| Anon `/v1/status` `/providers` | 401 | A2 closed |
| `/docs` `/openapi.json` | 404 | A2 closed |
| Empty webhook verify | 403 | Part 2 Bug A closed on host |
| SSRF `127.0.0.1` / `169.254.169.254` + token | 400 blocked | C1 closed |
| WS no token / `?token=` | 403 | C3 closed |
| WS spoof `channel=discord` on `/telegram` | mismatch error | C2/L9 closed |
| **Anon `POST …/telegram/webhook` `{}`** | **500** | **BUG — fixed** |
| **Anon `POST …/discord/webhook` `{}`** | **500** | **BUG — fixed** |
| **Anon `POST …/slack/webhook` `{}`** | **200 ok** (accepted junk) | **BUG — fixed** |
| XFF rotates RPM identity | spoofable | **BUG — fixed** (ignore XFF) |
| Chat + install token | 503 no providers | Expected (keys off ASGI) |

## After redeploy (re-hack)

| Attack | Expected |
|--------|----------|
| telegram/discord junk webhook | **400** not 500 |
| slack junk webhook | **200** `{"status":"ok"}` with no message (drop) |
| anon data plane | 401 |
| docs | 404 |
| SSRF private IPs | 400 |
| empty verify | 403 |

## Remaining Part 2 hunts (not §6/7)

1. WhatsApp Meta HMAC **replay** (no message id dedup) — best next PR  
2. DNS-rebinding residual if pin incomplete against exotic redirects  
3. Channel webhooks still **unauthenticated by design** (provider sig) — missing sig on Slack is a separate claim if still open after junk reject  

## Mistakes corrected this pass

1. Webhook route leaked ValidationError as 500  
2. Slack adapter treated gateway `{raw_body,headers}` as a message  
3. Rate limit trusted client `X-Forwarded-For`  
4. SSRF resolved DNS twice (TOCTOU) — now pins IP + Host header  
