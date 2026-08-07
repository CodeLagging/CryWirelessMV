# core/WIFI/probe_dos.py
from debugs import debug

from .probe_flood import probe_dos as core_probe_dos


def probe_dos(interface, channel):
    pps = input("Packets per second (default 1000): ").strip()
    try:
        pps = int(pps) if pps else 1000
    except ValueError:
        debug("warn", "Invalid input for pps, using default 1000")
        pps = 1000

    debug("ok", f"Starting Probe Flood DoS with {pps} pps... Press Ctrl+C to stop.")
    try:
        core_probe_dos(interface, channel, pps)
    except KeyboardInterrupt:
        debug("info", "Probe Flood DoS interrupted by user")
    except Exception as e:
        debug("critical", f"Probe Flood DoS error: {e}")
