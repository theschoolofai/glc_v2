# Gemini Live (realtime full-duplex)

Group assignment in Session 11. Implement the realtime full-duplex
TTS bridge using BidiGenerateContent. Pairs naturally with the
matching STT provider — one WebSocket session carries both legs.

## What you build

- `adapter.py` — subclass `TTSProvider`. Open the WebSocket, send
  the setup frame with `responseModalities: ["AUDIO"]`, send the
  text as a `clientContent.turns[].parts[].text` frame, accumulate
  `serverContent.modelTurn.parts[].inlineData.data` chunks until
  `turnComplete`, then close.

## Required environment

- `GEMINI_API_KEY`.

## Quirks

- Audio comes back as 24 kHz mono base64 PCM chunks. Concatenate
  and wrap as a WAV before returning.
- The session is full-duplex by design — the server may interleave
  partial responses with usage metadata frames.
- For S11 the synthesize() surface is non-streaming; the eventual
  WebUI voice mode opens its own WS through this provider.

## Tests you need to pass

`tests/voice/tts/test_gemini_live_tts.py` — six structural tests
plus `test_channel_specific_behaviour_response_modalities_audio`:
the setup frame must include `responseModalities: ["AUDIO"]`. Setup
frames defaulting to TEXT cause the server to emit text-only
responses, which the adapter would silently treat as empty audio.
