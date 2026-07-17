"""Discover adapter modules under glc/channels/catalogue/<name>/adapter.py.

An adapter module is registered if it exposes a `class Adapter(ChannelAdapter)`.
Registration is best-effort: a broken adapter logs a warning and is skipped
so one bad student PR cannot break the gateway boot.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from glc.channels.base import ChannelAdapter

CATALOGUE_PACKAGE = "glc.channels.catalogue"


def discover() -> dict[str, type[ChannelAdapter]]:
    """Returns {channel_name: Adapter class}. Channels whose adapter is
    still a stub (raises NotImplementedError at class load time)
    register fine; instantiation works, calls fail with a clear message."""
    out: dict[str, type[ChannelAdapter]] = {}
    pkg = importlib.import_module(CATALOGUE_PACKAGE)
    for _, name, ispkg in pkgutil.iter_modules(pkg.__path__):
        if not ispkg:
            continue
        try:
            mod = importlib.import_module(f"{CATALOGUE_PACKAGE}.{name}.adapter")
        except Exception as e:  # pragma: no cover
            print(f"[glc.registry] failed to import {name}: {e!r}")
            continue
        cls = getattr(mod, "Adapter", None)
        if isinstance(cls, type) and issubclass(cls, ChannelAdapter):
            out[name] = cls
    return out


def get(name: str) -> type[ChannelAdapter] | None:
    return discover().get(name)


def list_channels() -> list[str]:
    return sorted(discover().keys())


def declared_channel_names() -> set[str]:
    """Subpackage names under the catalogue, without importing any of
    them. Unlike discover()/get()/list_channels(), this never runs a
    single line of adapter code -- it only lists directory entries via
    pkgutil, the same way `import glc.channels.catalogue` (which every
    caller of this module has already paid for) doesn't import its
    subpackages either.

    Exists so callers that only need to know "is this a real channel
    slot" (e.g. glc.routes.channels.channel_webhook's 404 check) don't
    have to import all 15 catalogue adapters into their own process just
    to answer that question. See docs/fix_security_breach.md, round
    three addendum.
    """
    pkg = importlib.import_module(CATALOGUE_PACKAGE)
    return {name for _, name, ispkg in pkgutil.iter_modules(pkg.__path__) if ispkg}


def instantiate(name: str, config: dict[str, Any] | None = None) -> ChannelAdapter:
    cls = get(name)
    if cls is None:
        raise KeyError(f"unknown channel '{name}'")
    return cls(config=config)
