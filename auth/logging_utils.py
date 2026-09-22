"""Structured decision logging.

Tests run with ``pytest -s`` so the log lines (key inputs + decision
basis) are visible. No external logging service is used.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any

LOGGER_NAME = "auth.test"

_logger: logging.Logger | None = None


def get_logger() -> logging.Logger:
    """Return the shared auth test logger (created lazily)."""
    global _logger
    if _logger is None:
        _logger = logging.getLogger(LOGGER_NAME)
        _logger.setLevel(logging.DEBUG)
        _logger.propagate = False
    return _logger


def configure_test_logging(level: int = logging.DEBUG) -> logging.Logger:
    """Attach a stdout handler exactly once; used by tests/conftest."""
    logger = get_logger()
    if not any(getattr(h, "_auth_handler", False) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler._auth_handler = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def _json_default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return repr(value)


def log_decision(stage: str, decision: str, **fields: Any) -> None:
    """Log ``stage`` -> ``decision`` with the key inputs that caused it."""
    payload = {"stage": stage, "decision": decision, **fields}
    get_logger().info(json.dumps(payload, default=_json_default, sort_keys=True))
