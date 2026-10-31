import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import log_config


def _reset():
    log_config._configured = False
    lg = log_config.get_logger()
    for h in list(lg.handlers):
        if not isinstance(h, logging.NullHandler):
            lg.removeHandler(h)


def test_level_map_covers_app_levels():
    assert log_config._LEVEL_MAP["ok"] == logging.INFO
    assert log_config._LEVEL_MAP["info"] == logging.INFO
    assert log_config._LEVEL_MAP["warn"] == logging.WARNING
    assert log_config._LEVEL_MAP["error"] == logging.ERROR
    assert log_config._LEVEL_MAP["critical"] == logging.CRITICAL


def test_configure_logging_writes_rotating_file(tmp_path):
    _reset()
    log_config.configure_logging(log_dir=tmp_path)
    log_config.log_at("error", "boom happened")
    for h in log_config.get_logger().handlers:
        h.flush()
    logfile = tmp_path / "cwmv.log"
    assert logfile.exists()
    content = logfile.read_text()
    assert "boom happened" in content
    assert "ERROR" in content
    _reset()


def test_configure_logging_is_idempotent(tmp_path):
    _reset()
    lg = log_config.configure_logging(log_dir=tmp_path)
    count = len(lg.handlers)
    log_config.configure_logging(log_dir=tmp_path)
    assert len(lg.handlers) == count  # no duplicate handlers added
    _reset()


def test_unknown_level_defaults_to_info(tmp_path):
    _reset()
    log_config.configure_logging(log_dir=tmp_path)
    log_config.log_at("not-a-level", "fallback line")
    for h in log_config.get_logger().handlers:
        h.flush()
    content = (tmp_path / "cwmv.log").read_text()
    assert "INFO" in content and "fallback line" in content
    _reset()


def test_log_at_before_configure_is_silent(capsys):
    _reset()
    log_config.log_at("info", "should stay silent")
    captured = capsys.readouterr()
    assert "should stay silent" not in captured.out
    assert "should stay silent" not in captured.err


# --- privileged-path integration -------------------------------------------

def test_bluetooth_warn_emits_warning_record(caplog):
    """A simulated BT failure routes through structured logging at WARNING."""
    from core.BT_HCI.bluetooth import _warn
    with caplog.at_level(logging.WARNING, logger="cwmv"):
        _warn("simulated dbus failure")
    assert any(r.levelno == logging.WARNING and "simulated dbus failure" in r.message
               for r in caplog.records)


def test_scanner_error_event_logs_warning(caplog, tmp_path):
    """A '[!]'-prefixed scanner event is logged at WARNING level."""
    from core.WIFI.scanner import Scanner
    s = Scanner("wlan0", savepath=str(tmp_path))
    with caplog.at_level(logging.INFO, logger="cwmv"):
        s._log_event("[!] simulated monitor-mode failure")
    assert any(r.levelno == logging.WARNING for r in caplog.records)
