
from __future__ import annotations

import logging
import sys

_CONFIGURED = False

def setup_logging(verbose: bool = False) -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger("aegisrt")

    if _CONFIGURED:
        if verbose:
            logger.setLevel(logging.DEBUG)
        return logger

    if verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logger.setLevel(level)

    handler: logging.Handler
    try:
        from rich.logging import RichHandler

        handler = RichHandler(
            level=level,
            rich_tracebacks=True,
            show_time=True,
            show_path=verbose,
        )
    except ImportError:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        handler.setLevel(level)

    logger.addHandler(handler)
    _CONFIGURED = True
    return logger

def get_logger(name: str) -> logging.Logger:
    global _CONFIGURED
    if not _CONFIGURED:
        setup_logging()
    return logging.getLogger(f"aegisrt.{name}")
