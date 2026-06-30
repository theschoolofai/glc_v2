# Adapter guide

This guide walks through the end-to-end workflow for the Session 11
assignment: claim a slot, implement the adapter, pass CI, merge.

## 0. Slot types

There are **two** kinds of slots a group can claim. They share the
same workflow and the same seven-test rubric.

| Kind            | Lives at                                  | Examples                                                  |
|-----------------|-------------------------------------------|-----------------------------------------------------------|
| Channel adapter | `glc/channels/catalogue/<channel>/`       | telegram, discord, slack, … (15 total)                    |
| Voice provider  | `glc/voice/{stt,tts}/providers/<name>/`   | groq_whisper, kokoro, elevenlabs, cartesia, gemini_live, … |

`system_fallback` is **not** a claimable slot — it ships fully
implemented so `/v1/speak?prefer=fallback` works on day one.

## 1. Claim

Open a PR that replaces `(unclaimed)` with your group name for one
row in `CLAIMS.md`. Claims are first-come, first-served. CI rejects
PRs that claim a slot twice.

Once your CLAIMS.md PR merges, the slot is yours for the session.
The `Owned paths` column in CLAIMS.md is what the **boundary check**
([`scripts/check_pr_boundaries.py`](../scripts/check_pr_boundaries.py))
enforces — your implementation PR can only touch files inside those
paths. PRs that stray fail CI before any tests run.

## 2. The seven-test rubric

Each channel has **seven** tests under `tests/channels/test_<channel>.py`.
The first six are structural — they assert the envelope contract holds.
The seventh is channel-specific — it asserts a behaviour that requires
the adapter to understand the real wire format.

The structural tests are the contract rubric. The behavioural test is
the architectural rubric. Both must pass to merge.

### The six structural tests (every channel)

| # | Test                                                          | What it asserts                                                                                                                                                                  |
|--:|---------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | `test_on_message_owner_returns_valid_envelope`                | Parsing a real wire-format event from the paired owner produces a valid `ChannelMessage` with `trust_level == owner_paired`.                                                     |
| 2 | `test_on_message_stranger_is_untrusted`                       | An identical event from an unknown sender produces `trust_level == untrusted`.                                                                                                   |
| 3 | `test_send_emits_valid_wire_payload`                          | `send(ChannelReply(...))` dispatches a payload whose field names and shape match the channel's real outbound API (e.g. `chat_id` + `text` for Telegram, not arbitrary JSON).     |
| 4 | `test_disconnect_is_handled`                                  | After `mock.force_disconnect()`, the next `on_message` call returns cleanly — no raise.                                                                                          |
| 5 | `test_rate_limit_propagates_429`                              | A rate-limited send returns a structured error code (HTTP 429, Twilio 20429, SMTP 421, signal-cli -32603 — channel-specific).                                                    |
| 6 | `test_allowlist_silently_drops_stranger_in_public`            | In a public-channel context (`config["is_public_channel"]=True`), an unknown sender either yields no envelope or `trust_level == untrusted` (default `mention_only_in_public`).  |

### The channel-specific behavioural test

| Channel        | Test name                                                       | What it asserts                                                                                                                                                                                                                                |
|----------------|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| telegram       | `test_channel_specific_behaviour_photo_attachment`              | A photo Update is resolved via `mock.get_file(file_id)`; the resolved `file_path` lands in an `Attachment(kind="image")`.                                                                                                                      |
| discord        | `test_channel_specific_behaviour_mention_resolution`            | `<@user_id>` in `content` is resolved via `mock.get_user(id)`; the resolved username appears in `metadata["mentions"]`.                                                                                                                        |
| slack          | `test_channel_specific_behaviour_thread_continuity`             | `thread_ts` on inbound becomes `ChannelMessage.thread_id`; on outbound it propagates back into `chat.postMessage` as `thread_ts`.                                                                                                              |
| whatsapp       | `test_channel_specific_behaviour_signature_verification`        | Unsigned and tampered `X-Hub-Signature-256` webhooks are rejected (return `None`); only correctly-signed bodies produce a `ChannelMessage`.                                                                                                    |
| teams          | `test_channel_specific_behaviour_adaptive_card`                 | An Adaptive Card attachment (`application/vnd.microsoft.card.adaptive`) has its `TextBlock` body lifted into `ChannelMessage.text`; the raw card lives under `metadata["adaptive_card"]`.                                                      |
| matrix         | `test_channel_specific_behaviour_mxc_media_download`            | An `m.image` event with an `mxc://` URL is dereferenced via `mock.download_media`; the resolved bytes handle (not the raw mxc URI) lands in the `Attachment`.                                                                                  |
| line           | `test_channel_specific_behaviour_reply_token_then_push`         | First outbound consumes the inbound `replyToken` via `/v2/bot/message/reply`; the second falls back to `/v2/bot/message/push` (counting against the monthly quota only when no token is in flight).                                            |
| signal         | `test_channel_specific_behaviour_group_vs_dm_dispatch`          | Inbound `groupInfo.groupId` lands in `metadata["signal_group_id"]`; outbound to a group sets `{params: {groupId}}`; outbound DM sets `{params: {recipient}}`.                                                                                  |
| gmail          | `test_channel_specific_behaviour_pubsub_to_text_plain`          | The Pub/Sub push `historyId` is dereferenced via `history_list` + `messages_get`; the multipart body is parsed and the `text/plain` part (not `text/html`) reaches `ChannelMessage.text`.                                                      |
| imap           | `test_channel_specific_behaviour_pdf_attachment_to_artifact`    | A `multipart/mixed` message with a PDF attachment surfaces an `Attachment(kind="file", mime="application/pdf")` whose `ref` is `art:<sha>`; the bytes land in the artifact store.                                                              |
| twilio_sms     | `test_channel_specific_behaviour_mms_media_persists_as_artifact`| `NumMedia >= 1` triggers a download via `mock.download(url)`; the bytes persist as `art:<sha>` and the outbound reply with an `Attachment(kind="image")` adds `MediaUrl` to the `messages.create` body.                                        |
| twilio_voice   | `test_channel_specific_behaviour_call_to_twiml_then_media`      | A call webhook produces TwiML with `<Connect><Stream>` (or `<Start><Stream>`); subsequent media-stream frames are decoded, transcribed via `mock.transcribe()`, persisted, and surface as `voice_audio_ref` plus `text`.                       |
| webui          | `test_channel_specific_behaviour_typing_indicator`              | A reply emits two frames in order: `{type: "agent_reply", typing: true, text: ""}` then `{type: "agent_reply", typing: false, text: "<reply>"}`.                                                                                               |
| webhook        | `test_channel_specific_behaviour_signed_replay_window`          | Unsigned bodies, expired-timestamp bodies, and valid-fresh bodies are sorted correctly; only the third produces a `ChannelMessage`.                                                                                                            |
| local_mic      | `test_channel_specific_behaviour_silence_vs_speech`             | `silence.wav` produces no envelope; `hello.wav` is transcribed via the patched `/v1/transcribe` and produces a `ChannelMessage` with `voice_audio_ref` set; a reply round-trips through `/v1/speak` (patched) into `mock.play(bytes)`.          |

## 3. Read the test suite first

Open `tests/channels/test_<channel>.py` and the matching
`tests/channels/mocks/<channel>_mock.py` before writing any adapter
code. The mock's docstring cites the upstream wire-format source
(Telegram Bot API, Discord developer portal, Slack Events API,
RFC 5322, etc.) — that page is your reference.

## 4. Implement

Two files under `glc/channels/catalogue/<channel>/`:

```python
# adapter.py
from datetime import datetime, timezone
from glc.channels.base import ChannelAdapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.trust_level import classify

class Adapter(ChannelAdapter):
    name = "telegram"

    async def on_message(self, raw):
        mock = self.config.get("mock")
        if mock is not None and mock.pop_disconnect():
            # Surface a reconnect envelope; do NOT raise.
            return ChannelMessage(...)
        # Parse the real wire payload — for Telegram that means
        # raw["message"]["from"]["id"], not raw["channel_user_id"].
        ...

    async def send(self, reply):
        body = {...}  # construct the channel's native send body
        mock = self.config.get("mock")
        if mock is not None:
            return await mock.send(body)
        return body
```

The `config` dict is passed by `glc.channels.registry.instantiate()`
and is also what the test suite injects (`{"mock": <FakeAPI>}`).
When `config["mock"]` is set, use it; when not, hit the real wire API.

`schemas.py` is for channel-specific Pydantic types you need (e.g.
Telegram's `InlineKeyboardMarkup` shape). The canonical envelope
lives in `glc.channels.envelope`; do **not** redefine `ChannelMessage`
or `ChannelReply` locally — `scripts/validate_envelope.py` will
reject your PR if you do.

## 5. Run the tests locally

```sh
uv run pytest tests/channels/test_telegram.py -v
```

When all seven tests pass, you are CI-ready. The `adapter-pr.yml`
workflow runs the same seven tests in CI and gates merge.

## 6. WebUI protocol spec

The WebUI channel is course-defined since there is no upstream
authoritative wire format. The protocol is plain JSON over a
WebSocket:

**Inbound (client → adapter):**
```json
{"type": "user_message", "session_id": "browser-...", "user_id": "owner",
 "user_handle": "owner", "text": "...", "attachments": [], "client_ts": <ms>}
```

**Outbound typing pre-frame (adapter → client):**
```json
{"type": "agent_reply", "text": "", "typing": true}
```

**Outbound final frame (adapter → client):**
```json
{"type": "agent_reply", "text": "<reply>", "typing": false}
```

Both outbound frames must be sent in order for the same `session_id`
so the client can render the typing indicator while the agent is
working.

## 7. Open the PR

Use the PR template. The required fields:

- Group name, members, channel.
- YouTube demo link (one per group).
- A short paragraph on the channel's wire quirks (auth, rate limit,
  trust posture).

A teaching assistant reviews for adapter discipline before merge:

- Does the adapter call `trust_level.classify()` before constructing
  the envelope?
- Does it consult `allowed()` in public-channel contexts?
- Does it avoid holding long-lived credentials in code?
- Does the behavioural test pass — i.e. does the adapter understand
  the channel's actual wire format, not just the envelope contract?
- Are imports minimal — no LangChain, no third-party agent framework?

## 8. After merge

Your adapter registers automatically on the next gateway boot.
Channel adapters register through `glc.channels.registry.discover()`
(which scans `glc/channels/catalogue/`). Voice providers register
lazily via the dispatcher when `/v1/transcribe` or `/v1/speak` is
first called with the matching `prefer=` value.

## 9. Voice provider slots — the same seven-test rubric

Voice providers follow the same shape as channels:

- One stub `adapter.py` per provider under
  `glc/voice/stt/providers/<name>/` or
  `glc/voice/tts/providers/<name>/`.
- One mock-fake per provider under
  `tests/voice/stt/mocks/<name>_mock.py` or
  `tests/voice/tts/mocks/<name>_mock.py`.
- Seven tests per provider in `tests/voice/{stt,tts}/test_<name>.py`:
  6 structural (provider name matches; result shape; passes
  audio/text to upstream; records duration/sample-rate; propagates
  upstream error; handles empty input) plus 1 behavioural.

### Voice behavioural tests at a glance

| Slot              | Behavioural test name                            | What it asserts                                                                                              |
|-------------------|--------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| groq_whisper      | `openai_multipart_shape`                         | POST is multipart/form-data with `model=whisper-large-v3-turbo`, `response_format=verbose_json`.             |
| whisper_cpp       | `vad_skips_silent_input`                         | Silent audio short-circuits before the `whisper-cli` subprocess fires.                                       |
| gemini_live (STT) | `setup_frame_first`                              | The `BidiGenerateContentSetup` frame is the first WS frame sent.                                             |
| kokoro            | `pipeline_reuse`                                 | The pipeline loads once and is reused across calls.                                                          |
| elevenlabs        | `free_tier_quota_tracking`                       | The adapter fails-fast with status=429 when the 10,000-char/month free tier is spent.                        |
| cartesia          | `time_to_first_audio`                            | The first audio byte arrives early — adapters must not buffer the entire response.                           |
| gemini_live (TTS) | `response_modalities_audio`                      | The setup frame declares `responseModalities: ["AUDIO"]`.                                                    |
| system_fallback   | `ships_working_without_mock`                     | (Maintainer test, not a group slot.) The real provider produces audio with zero configuration.               |

## 10. Per-PR scorecard

When you open your implementation PR, the
[`scorecard`](../.github/workflows/adapter-pr.yml) job in the
adapter-PR workflow auto-generates a per-group comment summarising:

- structural-test passes (0–6 pts)
- behavioural-test passes (0–2 pts)
- `ruff` clean on your owned paths (0.5 pt)
- `mypy` clean on your owned paths (0.5 pt)
- PR template completeness (0.5 pt)
- adapter-discipline checks (0.5 pt)

Total out of 10. The scorecard is informational — merge is gated by
the test suite and CODEOWNER review, not by the score. The score is
there so the TA's review starts from a known baseline instead of a
checklist walk.

## 11. Isolation guarantees

The single-repo + many-groups setup is enforced by five small
mechanisms — none of them block legitimate work:

| Layer                        | Mechanism                                                 | What it prevents                                              |
|------------------------------|-----------------------------------------------------------|---------------------------------------------------------------|
| Per-PR test scope            | `adapter-pr.yml` runs only the changed slot's tests       | Group B's broken code failing Group A's PR                    |
| Per-PR write scope           | `check_pr_boundaries.py` enforces `CLAIMS.md` `Owned paths` | Students editing each other's code                            |
| Catalogue tolerance          | `registry.discover()` try/excepts each adapter import     | One broken module killing gateway boot                        |
| Defensive test collection    | `tests/{channels,voice}/conftest.py` skips files whose adapter won't import | One syntax error polluting the failure list                |
| Merge serialisation          | GitHub merge queue (repo setting, not code)               | Two green PRs colliding on main                               |
