# Findings — reproduction environment

Every finding under `findings/<id>-<slug>/` was reproduced against an **isolated** gateway
instance, never against the real `~/.glc` install. `GLC_CONFIG_DIR` alone does **not** isolate a
gateway instance in this codebase — it only relocates `install_token`, `policy.yaml`, and
`channels.yaml` (`glc/config.py`). The audit log, pairing store, and cost ledger each hardcode
their own default of `~/.glc/{audit,pairings,gateway}.sqlite` and only respect their own separate
override variables (`glc/audit/store.py`, `glc/security/pairing.py`, `glc/db.py`). All four must be
set together to fully isolate a test run:

```bash
export GLC_CONFIG_DIR=/path/to/scratch
export GLC_AUDIT_DB=/path/to/scratch/audit.sqlite
export GLC_PAIRING_DB=/path/to/scratch/pairings.sqlite
export GLC_GATEWAY_DB=/path/to/scratch/gateway.sqlite
uv run glc serve
```

`GLC_GATEWAY_DB`'s value is read once at import time (`glc/db.py`'s `DB_PATH` is a module-level
constant), so it must be exported **before** the process starts — setting it after import has no
effect.

Standard setup used for every finding below:

```bash
export SCRATCH=/path/to/a/throwaway/directory   # never ~/.glc
export GLC_CONFIG_DIR="$SCRATCH"
export GLC_AUDIT_DB="$SCRATCH/audit.sqlite"
export GLC_PAIRING_DB="$SCRATCH/pairings.sqlite"
export GLC_GATEWAY_DB="$SCRATCH/gateway.sqlite"
uv run glc serve   # gateway on http://127.0.0.1:8111

# the install token the reproductions authenticate with:
cat "$SCRATCH/install_token"
```

Verified before starting any reproduction: this isolation actually holds — the real `~/.glc`
directory's four files (`audit.sqlite`, `gateway.sqlite`, `install_token`, `pairings.sqlite`) were
checked before and after each server run and their modification times never changed.

Each finding's own `repro.py` docstring gives the exact reproduction steps and expected
before/after results, and its commit message gives the invariant broken and the fix; this file
only documents the environment they all share.
