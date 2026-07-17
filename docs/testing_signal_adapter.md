# Testing the Signal adapter against a real signal-cli install

Log of getting `glc/channels/catalogue/signal/adapter.py` talking to a
real Signal account via signal-cli, on an operator machine that already
had `signal-cli` and `java` installed. Kept as a runbook — the dead
ends are left in, because the fixes only make sense with them.

## Context: no live bridge script existed

Unlike Telegram, LINE, Discord, and Twilio SMS, `glc/channels/catalogue/signal/`
shipped with only `adapter.py` + `schemas.py` (implemented against the
mock in `tests/channels/mocks/signal_mock.py`) and a README describing
the group assignment. Nothing in the repo actually talked to a running
signal-cli process.

`glc/channels/catalogue/signal/dev/live_bridge.py` was added to fill
that gap, mirroring `telegram/dev/live_poll.py`'s shape: connects to
signal-cli's JSON-RPC service over a Unix socket (signal-cli itself
runs as a separately-managed background daemon, not spawned by the
script), translates inbound `receive` notifications through the real
`Adapter` class, forwards the resulting `ChannelMessage` to the gateway
over the same WS path (`channel_ws`) the other channels' bridges use,
and writes the adapter's outbound `send` JSON-RPC request back to the
socket on a reply. One detail worth remembering: `adapter.send()` only
*builds* the JSON-RPC payload — unlike Telegram's adapter, it never
talks to signal-cli itself. The bridge script owns the actual socket
write.

Enabling the channel needs one more thing: the packaged
`channels.yaml` ships `signal: {enabled: false}` — override it in
`~/.glc/channels.yaml`.

## Generating the QR code

`signal-cli link -n "<device name>"` prints an `sgnl://linkdevice?...`
URI to stdout and blocks until a phone scans and confirms it.
signal-cli doesn't render a QR code itself — pipe it into `qrencode`
(already installed on this machine):

```sh
signal-cli link -n "my-desktop" | qrencode -t ansiutf8
```

or, if terminal rendering is unreliable, write a PNG instead:

```sh
signal-cli link -n "my-desktop" | qrencode -o ~/signal-link.png
xdg-open ~/signal-link.png
```

Worth flagging: that URI is effectively a one-time credential — whoever
scans it first completes the link. Keep it local to `qrencode`, never
a web-based QR generator.

## "It is not generating the QR code"

Ran the exact pipeline directly to check whether the tools themselves
were the problem:

```
$ timeout 8 signal-cli link -n "diagnostic-test"
sgnl://linkdevice?uuid=QHtePdqG-vSIMzxLH-GM6A%3D%3D&pub_key=BRJ3xcvmAUQaIzj4E8WiLgoYUTS1Ibt16zesoqDI4egk

$ echo "<that URI>" | qrencode -t ansiutf8
<clean, correctly-formed QR block output, exit 0>
```

Both tools worked in isolation, which narrowed it down. Asked the
operator what "not generating" actually looked like; answer was **no
output / hangs** — not an error, not a garbled QR.

Checked `signal-cli listAccounts` for other clues and found the real
cause: **this signal-cli config already had a linked account**
(`Number: +919886709102`). Re-running `link` against a config that
already has a device link doesn't cleanly produce a fresh URI the
normal way — that's the actual explanation for the hang, not a
buffering or tooling issue. First recommendation at this point (which
turned out to be *slightly* wrong, see below): skip `link` entirely and
start the daemon directly —

```sh
signal-cli -a +919886709102 daemon --socket ~/.signal-cli/socket &
```

## The account was linked locally, but not authorized server-side

Before wiring up the daemon, sanity-checked with a one-shot receive:

```
$ timeout 10 signal-cli -a +919886709102 receive
Error while checking account +919886709102: [403] Authorization failed!
```

A `403` here means signal-cli's *local* record of being linked no
longer matches a valid session on Signal's servers — most commonly
because the device was unlinked from the phone's Signal app, the
linked-device limit was hit, or the session expired. This is unrelated
to daemon vs. one-shot mode; neither would have worked. So the original
instinct (re-run `link`) was actually right — the account just needed a
**genuine, successful** re-link, not merely a config directory that
remembered an old one.

Re-ran:

```sh
signal-cli link -n "my-desktop" | qrencode -t ansiutf8
```

interactively, scanned it from the phone, and it completed.

## Verifying the fix

```
$ signal-cli listAccounts
Number: +919886709102

$ timeout 10 signal-cli -a +919886709102 receive
...
Envelope from: "deep hazar" +919886709102 (device: 1) to +919886709102
...
Received sync sent message
  To: "deep hazar" +919886709102
  Body: Hello sir
```

`receive` now works — the `403` is gone. The message shown was a
**sync message**, not an inbound message from another party: it
appeared because the operator sent "Hello sir" from the phone's Signal
app (Note to Self), and Signal's multi-device sync copied it to this
now-properly-linked signal-cli device. That's expected and confirms the
link is genuinely live end-to-end, but it's a different shape from what
`Adapter.on_message` actually parses — a real inbound message looks
like `Envelope from: <sender> ... Message timestamp ... Body: <text>`
without the "Received sync sent message" wrapper.

## Next: outbound send

To test the outbound direction (signal-cli sending, from this
machine), the command is:

```sh
signal-cli -a +919886709102 send -m "<message text>" <recipient number>
```

Sending to the account's own number is Note-to-Self, useful as a
self-contained round-trip test. **Not yet run** — the operator
interrupted before this step to capture the session here instead, so
this is the next thing to actually try, followed by starting the
daemon and running `live_bridge.py` for the full gateway round trip.
