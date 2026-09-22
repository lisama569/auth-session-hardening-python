"""Pytest bootstrap: make the project root importable and enable logs."""
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auth.logging_utils import configure_test_logging  # noqa: E402

configure_test_logging(logging.INFO)
