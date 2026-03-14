
from __future__ import annotations

import importlib.metadata
import logging
from typing import Any

logger = logging.getLogger(__name__)

def load_plugins(group: str) -> dict[str, type]:
    plugins: dict[str, type] = {}
    try:
        eps = importlib.metadata.entry_points()
        if hasattr(eps, "select"):
            group_eps = eps.select(group=group)
        else:
            group_eps = eps.get(group, [])
        for ep in group_eps:
            try:
                cls = ep.load()
                plugins[ep.name] = cls
                logger.debug("Loaded plugin %s=%s from group %s", ep.name, cls, group)
            except Exception:
                logger.warning(
                    "Failed to load entry point %s from group %s",
                    ep.name,
                    group,
                    exc_info=True,
                )
    except Exception:
        logger.warning("Failed to enumerate entry points for group %s", group, exc_info=True)
    return plugins

def discover_plugins() -> dict[str, dict[str, type]]:
    groups = (
        "aegisrt.probes",
        "aegisrt.detectors",
        "aegisrt.generators",
        "aegisrt.converters",
    )
    return {g.split(".")[-1]: load_plugins(g) for g in groups}
