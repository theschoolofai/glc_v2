#!/usr/bin/env python3
"""Reproduce / verify: audit DB must follow GLC_CONFIG_DIR (Modal volume).

Bug (unfixed main): ``glc/audit/store.py`` defaults to ``~/.glc/audit.sqlite``
and ignores ``GLC_CONFIG_DIR``. Modal sets ``GLC_CONFIG_DIR=/data/glc`` on a
persistent Volume for the install token, but audit writes stay on the
ephemeral container filesystem and vanish on scale-to-zero / cold start.

After the fix: with only ``GLC_CONFIG_DIR`` set, audit lands under that dir.

Usage (from a fresh checkout)::

    uv sync
    uv run python scripts/repro_audit_config_dir.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg = root / "config"
        home = root / "home"
        cfg.mkdir()
        home.mkdir()
        os.environ["GLC_CONFIG_DIR"] = str(cfg)
        os.environ.pop("GLC_AUDIT_DB", None)
        os.environ["HOME"] = str(home)
        os.environ["USERPROFILE"] = str(home)

        # Import after env is set so DEFAULT_DIR expanduser sees fake home
        # if anything still references it; _resolve_path uses getenv at call time.
        from glc.audit import store as audit_store

        audit_store._singleton = None
        audit_store.DEFAULT_DIR = home / ".glc"

        resolved = Path(audit_store._resolve_path())
        print(f"[info] GLC_CONFIG_DIR={cfg}")
        print(f"[info] resolved audit path={resolved}")
        under_config = resolved.parent.resolve() == cfg.resolve()
        print(f"[info] under_config={under_config}")

        audit_store.init_store()
        audit_store.append(
            channel="webui",
            channel_user_id="u1",
            trust_level="owner_paired",
            event_type="inbound_message",
            params={"text": "trail"},
        )
        on_volume = (cfg / "audit.sqlite").exists()
        on_ephemeral = (home / ".glc" / "audit.sqlite").exists()
        print(f"[info] config_has_db={on_volume} ephemeral_has_db={on_ephemeral}")

        if not under_config or not on_volume or on_ephemeral:
            print(
                "\n[FAIL] audit DB did not follow GLC_CONFIG_DIR — "
                "Modal volume would lose the trail on cold start."
            )
            return 1
        print("\n[OK] audit DB is under GLC_CONFIG_DIR")
        print("\nAll checks passed.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
