# Laptop microphone (local voice-first)

This is a **group assignment** in Session 11. Implement the local_mic adapter
to make the test suite at `tests/channels/test_local_mic.py` pass.

## What you build

Two files under this directory:

- `adapter.py` — subclass `glc.channels.base.ChannelAdapter` and implement
  `on_message(raw) -> ChannelMessage` and `send(reply) -> Any`.
- `schemas.py` — any channel-specific Pydantic types you need.

## Required environment variables

_None._

## Free-tier limits

Free — uses local mic, local Whisper (whisper.cpp) and local Kokoro.

## Wire-format quirks to expect

PortAudio / sounddevice access on macOS requires the Microphone permission to be granted to the terminal/host process. Voice activity detection trims silence before STT.

## Tests you need to pass

The failing tests live at `tests/channels/test_local_mic.py`. They cover:

1. `on_message` builds a valid `ChannelMessage` for owner and stranger inputs.
2. Trust level resolves to `owner_paired` / `user_paired` / `untrusted` correctly.
3. `send` produces a valid wire-format payload and reaches the mock.
4. The adapter handles forced disconnects without raising.
5. Rate-limit responses propagate to the caller as a 429.
6. In public channels with the default `mention_only_in_public: true`, the
   adapter consults the allowlist before processing strangers.

The mock-API fake at `tests/channels/mocks/local_mic_mock.py` is your contract
surface. Do **not** edit the mock or the test file — they are fixed.

## Submission

Open a PR that:

- Adds your `adapter.py` and `schemas.py`.
- Passes `pytest tests/channels/test_local_mic.py`.
- Updates `CLAIMS.md` if you have not already claimed this channel.

CI gates merge through branch protection. A TA reviews before merge.
