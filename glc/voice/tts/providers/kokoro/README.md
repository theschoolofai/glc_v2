# Kokoro-82M

Group assignment in Session 11. Implement the default-path local TTS
provider using the open-weights Kokoro-82M model.

## What you build

- `adapter.py` — subclass `TTSProvider`. Lazy-load the pipeline once
  on first call and reuse it across calls.
- `runner.py` (already in this directory) hosts the Kokoro pipeline
  loader. Extend it if you need extra knobs.

## Required environment

- `uv pip install kokoro` (~300 MB on disk after first call).
- Optional: `GLC_KOKORO_MODEL_DIR` to override the model location.

## Quirks

- The `kokoro` package wraps `KPipeline(lang_code="a")` — first call
  downloads weights to `~/.cache/huggingface/`. Cache that pipeline
  instance; don't re-init per call.
- Voice ids are short strings like `af_bella`, `af_sky`, `am_adam`.
- The pipeline yields float32 samples at 24 kHz mono. Wrap as a WAV
  byte string and base64-encode for transport.

## Tests you need to pass

`tests/voice/tts/test_kokoro.py` — six structural tests plus
`test_channel_specific_behaviour_pipeline_reuse`: the adapter must
lazy-load the pipeline once and reuse it across calls. The mock
counts pipeline constructions and asserts the second call does not
trigger another load.
