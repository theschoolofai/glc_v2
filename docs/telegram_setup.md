# Enabling the Telegram adapter against a real bot

Log of enabling `glc/channels/catalogue/telegram/adapter.py` against a
real Telegram bot, on an operator machine that had just finished the
Signal adapter setup (`docs/testing_signal_adapter.md`).

## The question

> how do enable telegram adapter from this framework, I have telegram
> imnstalled in this machine

## Telegram doesn't work like Signal

Signal's setup needed a local daemon (`signal-cli`) installed on the
machine, linked to an account, and a bridge script talking to it over
a Unix socket. Telegram doesn't have an equivalent — checked for a
local CLI/daemon (`telegram-cli`, `tdlib`, ...) and found none
installed, which is expected: the Telegram adapter talks to Telegram's
**Bot API** over plain HTTPS using a bot token. "Telegram installed on
this machine" doesn't factor into the setup at all — the bot token can
be created from the Telegram app on any device (phone, desktop, web),
not necessarily this one.

The other difference from Signal: the bridge script already existed.
`glc/channels/catalogue/telegram/dev/live_poll.py` shipped with the
repo (unlike `signal/dev/live_bridge.py`, which had to be written this
session) — enabling Telegram is pure configuration, no new code.

## Steps

1. **Create a bot and get a token.** In the Telegram app, message
   [@BotFather](https://t.me/BotFather):
   ```
   /newbot
   ```
   Follow the prompts (display name, then a username ending in `bot`).
   It replies with a token shaped like `123456789:AAH...` —
   `TELEGRAM_BOT_TOKEN`.

2. **Get your own Telegram user ID**, to auto-pair yourself as owner.
   Message [@userinfobot](https://t.me/userinfobot); it replies with
   your numeric ID — `TELEGRAM_OWNER_ID`.

3. **Enable the channel.** The packaged default ships
   `telegram: {enabled: false}` (`glc/channels.yaml`). Override at
   `~/.glc/channels.yaml`:
   ```yaml
   channels:
     telegram: {enabled: true}
   ```

4. **Set env vars and run it:**
   ```sh
   export TELEGRAM_BOT_TOKEN="123456789:AAH..."
   export TELEGRAM_OWNER_ID="your-numeric-id"
   uv run glc serve &
   uv run python -m glc.channels.catalogue.telegram.dev.live_poll
   ```
   `live_poll.py` long-polls Telegram's `getUpdates` API (no webhook or
   public URL needed), translates each update through the real
   `Adapter` class, forwards it to the gateway over the WS channel
   path (`channel_ws`), and posts replies back via `sendMessage`.

5. **Test it.** Open the bot in Telegram (search its `@username`) and
   send a message. `live_poll.py` should print
   `Received Telegram Update ID: ...`, and the gateway's echo reply
   should arrive back in the chat.

## Not yet done

The env vars and bridge startup haven't actually been dry-run against
a real bot token in this session — the steps above are the documented
procedure, not yet verified live the way the Signal setup was (QR
code, `403` diagnosis, re-link, `receive` confirmation). Next step, if
picked back up: get a real `TELEGRAM_BOT_TOKEN`, run `live_poll.py`,
and confirm a message round-trips end to end the same way
`docs/testing_signal_adapter.md` did for Signal.

## Addendum: `.env` in the wrong directory

Follow-up session, in the parent `week12` workspace this repo is
checked out into (`main.py`/`.env` live one level above `glc_v1/`).
`uv run python glc/channels/catalogue/telegram/dev/live_poll.py`
failed immediately with:

```
Error: TELEGRAM_BOT_TOKEN environment variable not set.
Please set it in your environment or a .env file.
```

even though `TELEGRAM_BOT_TOKEN` was present in a `.env` file on disk.

**Cause:** the `.env` file had been created at `glc_v1/glc/.env`, one
directory too deep. Both loaders resolve the repo `.env` relative to
`__file__`, and both land one level above `glc/`:

- `glc/main.py`: `ROOT = Path(__file__).parent` (`glc_v1/glc`), then
  `load_dotenv(ROOT.parent / ".env")` → `glc_v1/.env`.
- `glc/dev_env.py`: `_REPO_ROOT = Path(__file__).resolve().parent.parent`
  → `glc_v1/.env` again.

So `glc_v1/.env` is the one true location; `glc_v1/glc/.env` is never
read by anything.

**Fix:** `mv glc/.env .env` (run from `glc_v1/`). Re-ran `live_poll.py`
— the token check passed (no error printed) and the script moved on
to actually polling, confirming the fix without needing a live
gateway running. `.gitignore`'s `.env` rule (no leading slash) still
matches at the new path, so it stays untracked.

**Unrelated finding, same session:** the parent `week12` workspace
(outside this repo) had a `telegram.txt` with a live bot token and
personal Telegram profile info pasted in plaintext — untracked, in a
git repo with no commits yet, so nothing would have stopped a future
`git add .` from committing it. Removed by the operator after being
flagged.
