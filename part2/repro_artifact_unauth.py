#!/usr/bin/env python3
"""Part 2 finding: the Twilio MMS sidecar serves stored artifact bytes with no
authentication.

twilio_sms/webhook.py mounts GET /artifacts/{sha} on a PUBLIC FastAPI app
(reachable at GLC_PUBLIC_BASE / the ngrok URL Twilio fetches from). It returns
the stored media bytes for any valid 16-hex sha, with no bearer token, no
signed URL, and no binding to the sender/session that owns the blob. The only
barrier is guessing a 16-hex (64-bit) content hash -- and for media the
attacker themselves sent, or whose bytes they can hash, the handle is known
outright.

Stored artifacts are inbound MMS media (private user content). Serving them to
any anonymous caller breaks:
  * invariant 2 - data returned without checking the requesting principal.
  * invariant 5 - one user's stored content is reachable by another with no
    ownership/provenance check.

Attacker role: OUTSIDER on the public internet (no credentials).

Run:  uv run python part2/repro_artifact_unauth.py
Exit: 2 if bytes come back unauthenticated, 0 if the endpoint requires auth.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc_p2art_"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_ARTIFACTS_DIR"] = str(_TMP / "artifacts")

from fastapi.testclient import TestClient  # noqa: E402

from glc.channels.catalogue.twilio_sms import artifacts, webhook  # noqa: E402

SECRET_MEDIA = b"PRIVATE-MMS-PHOTO-BYTES-user-A-sent-this"


def main() -> int:
    # A victim's inbound MMS media has been stored by the adapter.
    ref = artifacts.put(SECRET_MEDIA, content_type="image/jpeg", source="twilio_sms")
    sha = ref.removeprefix("art:")

    app = webhook.build_app(serve_artifacts=True)
    client = TestClient(app)

    # Attacker is an anonymous outsider: no Authorization header at all.
    resp = client.get(f"/artifacts/{sha}")

    print("=== Part 2: unauthenticated artifact read on Twilio MMS sidecar ===")
    print(f"stored ref            = {ref}")
    print(f"GET /artifacts/{sha}  (no auth header)")
    print(f"  status              = {resp.status_code}")
    got = resp.content if resp.status_code == 200 else b""
    print(f"  leaked bytes match  = {got == SECRET_MEDIA}")

    if resp.status_code == 200 and got == SECRET_MEDIA:
        print(
            "\nVULNERABLE: an anonymous outsider fetched another user's stored "
            "MMS media with no credential. The endpoint has no auth and no "
            "owner binding (invariants 2 and 5)."
        )
        return 2
    if resp.status_code in (401, 403):
        # Confirm the legitimate path (a gateway-minted signed URL) still works.
        signed = webhook.sign_artifact_token(sha)
        ok_resp = client.get(f"/artifacts/{sha}?token={signed}")
        legit_ok = ok_resp.status_code == 200 and ok_resp.content == SECRET_MEDIA
        print(
            "\nHARDENED: anonymous read refused (status "
            f"{resp.status_code}). Signed-URL fetch still works: {legit_ok}."
        )
        return 0 if legit_ok else 1
    print(f"\nUNEXPECTED status {resp.status_code}; inspect manually.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
