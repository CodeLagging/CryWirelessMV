"""Structured logging for CryWirelessMV.

The app has always printed coloured status lines to the console via the
`debug()` helper. That is great for a live operator but useless for forensic
review after the fact. This module adds a rotating file log with levels and
timestamps, wired in alongside the console output, so a run leaves an auditable
trail without changing what the operator sees on screen.

`configure_logging()` is called once at startup (from `main.py`). Until it is
called the logger has only a NullHandler, so importing this module — e.g. in
tests — writes nothing anywhere.
"""

import logging
import logging.handlers
import os
from pathlib import Path

LOGGER_NAME = "cwmv"

# Maps the app's own level names (including "ok", which has no stdlib analogue)
# onto the standard logging levels.
_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "ok": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

_logger = logging.getLogger(LOGGER_NAME)
_logger.setLevel(logging.DEBUG)
_logger.addHandler(logging.NullHandler())  # silent until configured

_configured = False


def _default_log_dir() -> Path:
    env = os.environ.get("CWMV_LOG_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".cwmv" / "logs"


def configure_logging(level=logging.INFO, log_dir=None, console=False):
    """Attach a rotating file handler (and optionally a console handler).

    Idempotent: calling it again returns the already-configured logger without
    adding duplicate handlers.
    """
    global _configured
    if _configured:
        return _logger

    directory = Path(log_dir) if log_dir else _default_log_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            directory / "cwmv.log", maxBytes=1_000_000, backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
        _logger.addHandler(file_handler)
    except OSError:
        # File logging is best-effort; a read-only home must not break the app.
        pass

    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        _logger.addHandler(console_handler)

    _configured = True
    return _logger


def get_logger():
    return _logger


def log_at(level_name, message):
    """Emit `message` at the app level named by `level_name`.

    Safe to call before configure_logging(): with only the NullHandler attached
    nothing is written, so the legacy console `debug()` output is unaffected.
    """
    _logger.log(_LEVEL_MAP.get(str(level_name).lower(), logging.INFO), message)
