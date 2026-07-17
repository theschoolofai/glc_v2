**Ready for review**Select text to add comments on the plan

Sandbox the 7 voice STT/TTS providers (closes leak 1 for this surface, leak 7 for whisper\_cpp, leak 6 for this surface)
========================================================================================================================

Context
-------

docs/fix\_security\_breach.md ("Round ten") and the exploit console's keyisolation/rung4inherited cards both carry the same accepted exception: channel adapters run in an isolated subprocess with no gateway secrets (round three), but voice STT/TTS providers are explicitly excluded — "they're supposed to hold a real provider key" — and run in the gateway's own interpreter. That's true for the _one_ key each legitimately needs, but nothing stops any of them, if compromised (a poisoned dependency is exactly the threat class round three's own addendum already named), from calling glc.providers.get\_provider\_key() for any of the other five gateway keys too — the accessor has no per-caller scoping. This plan closes that the same way round three closed it for channel adapters: real process isolation, minted per call, with only the one credential and one upstream host each provider actually needs.

Scope, per this session's decisions: **voice providers only** (channel adapters stay on today's local-subprocess isolation, unchanged — a separate follow-up given the injected-client ambiguity found for 11 of the 15 channels), and **one fresh Sandbox per call**, no pooling — matching round three's own "no reuse" isolation philosophy exactly.

Source-verified facts driving the design
----------------------------------------

Grepped, not assumed (see the Explore agent's audit this session):

ProviderReal key source todayUpstream hostSandbox networkstt/groq\_whisperget\_provider\_key("GROQ\_API\_KEY") — shared gateway keyapi.groq.comoutbound\_domain\_allowlist=\["api.groq.com"\]stt/gemini\_liveget\_provider\_key("GEMINI\_API\_KEY") — shared gateway keygenerativelanguage.googleapis.com (wss)outbound\_domain\_allowlist=\["generativelanguage.googleapis.com"\]tts/gemini\_livesamesamesametts/cartesiaos.getenv("CARTESIA\_API\_KEY") — dedicatedapi.cartesia.aioutbound\_domain\_allowlist=\["api.cartesia.ai"\]tts/elevenlabsos.environ.get("ELEVENLABS\_API\_KEY") — dedicatedapi.elevenlabs.iooutbound\_domain\_allowlist=\["api.elevenlabs.io"\]stt/whisper\_cppnonenone (local whisper-cli subprocess)block\_network=Truetts/kokorononenone (local inference)block\_network=Truetts/system\_fallbacknonenone (local say/pyttsx3)block\_network=True

groq\_whisper and gemini\_live are where this actually matters: they already read a **shared** gateway key via the sanctioned get\_provider\_key() accessor (round two's mechanism, built for exactly this legitimate need) — but that accessor doesn't check _which_ provider is asking, so in-process, either could call get\_provider\_key("NVIDIA\_API\_KEY") too. cartesia/elevenlabs use their own dedicated env vars already, so the improvement for them is narrower (still real: nothing today stops them from calling get\_provider\_key() for a gateway key if compromised, since they share the interpreter).

Every prefer= value in both glc/voice/stt/router.py and glc/voice/tts/router.py resolves to one bounded async call (provider.transcribe()/.synthesize()) — there is no long-lived streaming session reachable through POST /v1/transcribe//v1/speak today (the STT router's own docstring: real Gemini Live duplex audio is routed to a WebSocket session that doesn't exist as running code yet — "S12 deliverable"). So all 7 providers fit the same one-shot Sandbox-exec shape; nothing needs to be carved out as unsupported.

log\_call check (this session's audit): zero call sites inside any voice provider file today — confirms this plan doesn't need to touch leak 10 at all, and that finding stays exactly what round nine already recorded (an inert rung-4 ceiling, no live path).

Design
------

Mirrors glc/channels/isolation.py / isolation\_worker.py's existing, already-tested pattern — same JSON-line-over-stdin/stdout protocol, same one-process(-equivalent)-per-call philosophy, same stdout-redirection trick for stray print()s — swapping asyncio.create\_subprocess\_exec for modal.Sandbox.create() + sandbox.exec().

**New: glc/voice/sandbox.py**

*   SANDBOX\_SPEC: dict\[str, ProviderSandboxSpec\] — the table above, keyed by "stt:groq\_whisper", "tts:cartesia", etc. Each entry names its secret env-var names (resolved via get\_provider\_key() for the two gateway-key providers, os.environ.get() for the two dedicated-key providers, empty for the three local-only ones) and its outbound\_domain\_allowlist (or block\_network=True).
    
*   async def run\_in\_sandbox(modal\_app, image, kind, name, method, payload) -> dict — builds a throwaway modal.Secret.from\_dict(...) containing _only_ that spec's vars, calls modal.Sandbox.create(app=modal\_app, image=image, secrets=\[secret\], timeout=60, \*\*spec.network\_kwargs), then sandbox.exec(sys.executable, "-m", "glc.voice.sandbox\_worker", kind, name, method, ...), writes the JSON request to stdin, reads one JSON line back, calls sandbox.terminate() in a finally (no idle\_timeout reuse — explicit teardown, matching the "fresh per call" decision). Raises a new SandboxProcessError on timeout/crash/ non-JSON output, mirroring AdapterProcessError.
    

**New: glc/voice/sandbox\_worker.py** — child entrypoint, same shape as isolation\_worker.py: sys.argv = \[kind, name, method\], reads one JSON line from stdin ({"audio\_b64": ...} or {"text": ..., "voice\_id": ...}), imports glc.voice.{stt,tts}.providers..adapter directly (bypassing the router — dispatch decision already made by the caller), instantiates Provider(), awaits the call, prints exactly one {"ok": true, "result": {...}} or {"ok": false, "error": ...} line. Redirects its own sys.stdout to sys.stderr for the call duration, same reason isolation\_worker.py does.

**Modified: glc/voice/stt/router.py::transcribe() and glc/voice/tts/router.py::synthesize()** — gain an optional modal\_app=None, modal\_image=None parameter. When both are provided _and_ PREFER\_TO\_PROVIDER\[prefer\] has a SANDBOX\_SPEC entry, dispatch through glc.voice.sandbox.run\_in\_sandbox(...) instead of \_load\_provider(name)...; otherwise fall back to today's in-process call unchanged. This is the local-dev/test escape hatch: pytest never sets modal\_app, so the entire existing test suite keeps exercising the in-process path with zero changes.

**Modified: glc/routes/transcribe.py / glc/routes/speak.py** — pass request.app.state.modal\_app / request.app.state.modal\_image (both None unless running under modal\_app.py) through to transcribe()/synthesize().

**Modified: modal\_app.py** — right after from glc.main import app as web\_app, set web\_app.state.modal\_app = app and web\_app.state.modal\_image = image, so the real deployment (and only the real deployment) has what it needs to spawn Sandboxes. No change to the image/secrets/volume config itself.

Tests
-----

*   tests/voice/test\_sandbox\_spec.py (new): every SANDBOX\_SPEC entry has either a non-empty outbound\_domain\_allowlist or block\_network=True (never neither), and the secret-var list for groq\_whisper/gemini\_live matches GATEWAY\_PROVIDER\_KEY\_ENV\_VARS membership while cartesia/elevenlabs don't.
    
*   tests/voice/test\_sandbox\_worker.py (new): runs glc/voice/sandbox\_worker.py as a real local subprocess (Modal-free, same technique tests/test\_channel\_process\_isolation.py already uses for isolation\_worker.py) against a test-double provider, confirming the one-JSON-line protocol and the stdout-redirection guard.
    
*   tests/voice/test\_sandbox\_dispatch.py (new): mocks modal.Sandbox.create/.exec (no real Modal API calls, so this runs in CI) and asserts run\_in\_sandbox() constructs the Secret with exactly the right keys and the right network kwargs per provider — this is the regression test that would catch a future edit accidentally widening a provider's allowlist or leaking an extra key into its Secret.
    
*   Existing tests/voice/\*\* suite: unaffected (no modal\_app passed in any existing test's TestClient, so the in-process fallback path is what they've always exercised — verify with a full uv run pytest -q run before and after).
    

Live verification (after modal deploy)
--------------------------------------

Reusing this session's modal shell modal\_app.py::fastapi\_app -c "echo $B64 | base64 -d | python3" recipe (remember cwd="/root" — this session's own false-alarm investigation into why that matters):

1.  POST /v1/transcribe and /v1/speak with a real install token for each sandboxable prefer= value — confirm normal success responses, proving the Sandbox path works end-to-end and isn't just faster to fail closed.
    
2.  The key-isolation check that matters: from inside a groq\_whisper Sandbox call (or by inspecting sandbox\_worker.py's env directly via a diagnostic one-off), confirm GEMINI\_API\_KEY/NVIDIA\_API\_KEY/etc. are absent and only GROQ\_API\_KEY is present — the same shape as this session's derive\_adapter\_env() verification for channel adapters, applied to the new surface.
    
    Done: not via `modal shell modal_app.py::fastapi_app` (that lands in the gateway function's own container, which legitimately holds all six keys -- proves nothing) and not reachable by name anyway, since `run_in_sandbox()` tears its Sandbox down right after each call. Instead, a local script looks up the deployed `glc-v1-gateway` app, builds the same `SANDBOX_SPEC["stt:groq_whisper"]`-scoped `modal.Secret`, spawns a real Sandbox from `sandbox_image`, and `exec`s a diagnostic snippet in place of `sandbox_worker`. Full recipe in `docs/how_to_test.md`, "The `keyisolation` card for voice providers, made concrete"; result recorded in `docs/fix_security_breach.md`, "Round eleven":
    
    ```
    ['GROQ_API_KEY']
    None
    ```
    
    Only `GROQ_API_KEY` present (the mock value from `.env`), `GEMINI_API_KEY` absent.
    
3.  Cold-start latency measured, not assumed — record real POST /v1/transcribe round-trip time before/after this change so the tradeoff (accepted this session in exchange for real isolation) is documented with a number, not a guess.
    

Docs to update
--------------

*   docs/fix\_security\_breach.md — new "Round eleven" section, same structure as round ten's (finding, fix, tests, verification, what's-still-open).
    
*   docs/tools/exploit\_console.html — the keyisolation card's copy currently says voice providers are "a different trust class... out of scope entirely"; update once this ships. rung4inherited's B1 bullet (= keydump) is unaffected — the _gateway's own_ interpreter still holds the live snapshot; this plan narrows who else can reach it via get\_provider\_key(), not the keydump finding itself.
    
*   docs/threat\_model.md — §1 principal 2's row and §7 invariant 1's evidence currently scope isolation to "the paths audited" (channel adapters); extend to name voice providers as covered too, with the same "not a full OS wall against rung 4 in the gateway's own process" caveat isolation.py's docstring already carries.