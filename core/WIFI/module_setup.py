# core/WIFI/module_setup.py
import os
import signal
import subprocess
import threading
import time

from scapy.all import sniff
from scapy.error import Scapy_Exception
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

import banner
from debugs import debug

from .attack_module import AttackModule


class ModuleSetup:
    def __init__(self):
        self.networks = {}
        self.stop_sniff = False
        self.scan_threads = []
        self.monitor_mode_enabled = False
        self.original_interface = None
        self.interface = None

    def cleanup_monitor_mode(self):
        if not self.monitor_mode_enabled:
            return

        debug("info", "Cleaning up monitor mode...")

        try:
            if self.interface:
                debug("info", f"Stopping monitor mode on {self.interface}")
                subprocess.run(["ip", "link", "set", self.interface, "down"], check=False, capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", self.interface, "set", "type", "managed"], check=False, capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", self.interface, "up"], check=False, capture_output=True, timeout=5)

            nm_status = subprocess.run(
                ["systemctl", "is-active", "NetworkManager"],
                check=False,
                capture_output=True,
                text=True,
            )

            if nm_status.stdout.strip() != "active":
                debug("info", "Restarting NetworkManager...")
                os.system("systemctl start NetworkManager > /dev/null 2>&1")

            self.monitor_mode_enabled = False
            debug("ok", "Monitor mode disabled successfully")
        except (subprocess.SubprocessError, OSError) as e:
            debug("error", f"Error during cleanup: {e}")

    def enable_monitor_mode(self, interface):
        debug("info", f"Enabling monitor mode on {interface}...")

        try:
            result = subprocess.run(["iwconfig", interface], check=False, capture_output=True, text=True, timeout=5)
            if "Mode:Monitor" in result.stdout:
                debug("ok", f"{interface} already in monitor mode")
                self.monitor_mode_enabled = True
                return interface

            self.original_interface = interface
            result = subprocess.run(
                ["iw", "dev", interface, "set", "type", "monitor"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                subprocess.run(["ip", "link", "set", interface, "up"], check=False, capture_output=True, timeout=5)
                debug("ok", f"Monitor mode enabled on {interface}")
                self.monitor_mode_enabled = True
                return interface
            else:
                debug("warn", "Failed to set monitor mode directly, trying airmon-ng...")
                result = subprocess.run(
                    ["airmon-ng", "start", interface],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    debug("ok", f"Monitor mode enabled on {interface}")
                    self.monitor_mode_enabled = True
                    return interface
                else:
                    debug("warn", "Could not confirm monitor mode, trying anyway...")
                    self.monitor_mode_enabled = True
                    return interface

        except (subprocess.SubprocessError, OSError) as e:
            debug("critical", f"Monitor mode failed: {e}")
            return None

    def signal_handler(self, sig, frame):
        self.stop_sniff = True
        debug("warn", "Stopping scan...")

    def restore_default_signal(self):
        signal.signal(signal.SIGINT, signal.default_int_handler)

    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            raw_bssid = pkt[Dot11].addr2
            if not raw_bssid:
                return
            bssid = raw_bssid.upper()
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")

            channel = None
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                try:
                    if elt.ID == 3 and len(elt.info) >= 1 or elt.ID == 61 and len(elt.info) >= 1:
                        channel = elt.info[0]
                        break
                    elif elt.ID == 192 and len(elt.info) >= 2:
                        channel = elt.info[1]
                        break
                except (IndexError, TypeError, AttributeError):
                    debug("warn", f"Could not parse channel element (ID={getattr(elt, 'ID', '?')})")
                elt = elt.payload.getlayer(Dot11Elt)

            if bssid not in self.networks:
                self.networks[bssid] = {"ssid": ssid, "channel": channel}
                print(f"{ssid or '<Hidden>'} - {bssid} (Ch {channel or '?'})")

    def set_channel(self, channel):
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                capture_output=True,
                timeout=2,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            debug("warn", f"Failed to set channel {channel} on {self.interface}")
    def pause(self):
        try:
            input("\nPress Enter to continue...")
        except (EOFError, KeyboardInterrupt):
            pass
    def scan_worker(self):
        debug("info", f"Scan worker started on {self.interface}")
        packet_count = 0

        while not self.stop_sniff:
            try:
                sniff(iface=self.interface, prn=self.packet_handler, timeout=2, store=False)
                packet_count += 1

                if packet_count % 10 == 0 and len(self.networks) > 0:
                    debug("info", f"Scanning... {len(self.networks)} networks found")
            except ValueError as e:
                debug("critical", f"Interface error: {e}")
                break
            except PermissionError:
                debug("critical", "Permission denied. Please run with sudo")
                break
            except OSError as e:
                debug("critical", f"OS Error: {e}. Check if interface exists and is in monitor mode")
                break
            except Scapy_Exception as e:
                debug("error", f"Scan error: {e}")
                time.sleep(1)

        debug("info", "Scan worker stopped")

    def channel_hopper(self, channels, delay):
        debug("info", f"Channel hopper started on {self.interface}")
        hop_count = 0

        while not self.stop_sniff:
            for ch in channels:
                if self.stop_sniff:
                    break
                self.set_channel(ch)
                time.sleep(delay)
                hop_count += 1

                if hop_count % 50 == 0:
                    debug("info", f"Hopping... currently on channel ~{ch}")

        debug("info", "Channel hopper stopped")

    def start_channel_hop_scan(self):
        self.stop_sniff = False
        self.scan_threads = []

        channels_24 = list(range(1, 14))
        channels_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
        channels = channels_24 + channels_5

        t_hopper = threading.Thread(target=self.channel_hopper, args=(channels, 0.3))
        t_sniff = threading.Thread(target=self.scan_worker)
        self.scan_threads.extend([t_hopper, t_sniff])

        for t in self.scan_threads:
            t.daemon = True
            t.start()

        time.sleep(0.2)
        debug("ok", "Threads started, scanning in progress...")

        while not self.stop_sniff:
            time.sleep(0.1)

        debug("info", "Waiting for threads to finish...")
        for t in self.scan_threads:
            t.join(timeout=3)

    def wifi_attack_menu(self, chosen_bssid, ssid):
        self.restore_default_signal()
        while True:
            os.system("clear")
            channel = self.networks.get(chosen_bssid, {}).get("channel")
            banner.wifi_attack()
            self.set_channel(channel=channel)
            print(f"Successfully changed channel to {channel}")
            print(f"\nTarget Network: {ssid or '<Hidden>'}")
            print(f"BSSID: {chosen_bssid}")
            print(f"Channel: {channel or '?'}")
            print("\nAttack Modes Available:")
            print("1. Authentication Denial of Service")
            print("2. Michael Countermeasures DoS")
            print("3. Deauth Denial of Service")
            print("4. Probe Flood DoS")
            print("5. Disassociation Denial of Service")
            print("6. Targeted Channel Switch Announcement")
            print("7. Action Frames")
            print("8. Bad Message Targeted")
            print("9. Quiet Targeted")
            print("0. Exit")
            atkmode = input("\nAttack Mode: ").strip()

            if atkmode == "0":
                break
            running = False
            try:
                if atkmode == "1" or atkmode.lower() == "authentication denial of service":
                    AttackModule.auth_dos(self.interface, chosen_bssid, channel)
                    running = True
                elif atkmode == "2" or atkmode.lower() == "michael countermeasures dos":
                    AttackModule.michael_mic_dos(self.interface, chosen_bssid, channel)
                    running = True
                elif atkmode == "3" or atkmode.lower() == "deauthentication denial of service":
                    AttackModule.deauth_all(self.interface, chosen_bssid)
                    running = True
                elif atkmode == "4" or atkmode.lower() == "probe flood dos":
                    try:
                        channel = int(channel)
                    except (ValueError, TypeError):
                        debug("warn", "Invalid channel detected. please enter channel manually")
                    while True:
                        try:
                            channel = int(input("Target Channel: "))
                            break
                        except ValueError:
                            debug("warn", "Still an Invalid channel")
                    AttackModule.probe_dos(self.interface, channel)
                    running = True
                elif AttackModule.disassoc_all and (atkmode == "5" or atkmode.lower() == "disassociation denial of service"):
                    AttackModule.disassoc_all(self.interface, chosen_bssid)
                    running = True
                elif AttackModule.flood_csa and (atkmode == "6" or atkmode.lower() == "targeted channel switch announcement"):
                    try:
                        channel = int(channel)
                    except (ValueError, TypeError):
                        debug("warn", "Invalid channel detected. please enter channel manually")
                    while True:
                        try:
                            channel = int(input("Target Channel: "))
                            break
                        except ValueError:
                            debug("warn", "Still an Invalid channel")
                    debug("info", "Targeted CSA running... If you meant to Flood CSA please go to 'Other Attacks' option")
                    AttackModule.targeted_csa(self.interface, chosen_bssid, ssid, channel)
                    running = True
                elif AttackModule.action_frame_flood and (atkmode == "7" or atkmode.lower() == "action frames"):
                    AttackModule.action_frame_flood(self.interface, chosen_bssid)
                    running = True
                elif AttackModule.bad_message_targeted and (atkmode == "8" or atkmode.lower() == "bad message targeted"):
                    debug("info", "Bad Message Targeted running... If you meant to Bad Message Flood please go to 'Other Attacks' option")
                    AttackModule.bad_message_targeted(self.interface, chosen_bssid, ssid)
                    running = True
                elif AttackModule.quiet_targeted and (atkmode == "9" or atkmode.lower() == "quiet targeted"):
                    debug("info", "Quiet Targeted running... If you meant to Quiet Flood please go to 'Other Attacks' option")
                    if channel is not None:
                        try:
                            channel = int(channel)
                        except (TypeError, ValueError):
                            channel = None
                    AttackModule.quiet_targeted(self.interface, chosen_bssid, ssid, channel)
                    running = True
            except KeyboardInterrupt:
                debug("info", "Attack interrupted")
            finally:
                if running:
                    self.pause()
    def run(self):
        try:
            signal.signal(signal.SIGINT, self.signal_handler)
            self.interface = input("Which WiFi interface to use: ")
            self.interface = self.enable_monitor_mode(self.interface)

            print("\nWhat would you like to do?")
            print("1. Scan Networks and Attack")
            print("2. Other Attacks (no scan needed)")
            print("0. Exit")
            mode = input("\nMode: ").strip()

            if mode == "0":
                debug("info", "Exiting...")
                return
            elif mode == "2" or mode.lower() == "other attacks":
                self.restore_default_signal()
                banner.other_attacks()
                print("1. Network Flood")
                print("2. Probe Flood DoS")
                print("3. Flooded Channel Switch Announcement")
                print("4. Bad Message Flood")
                print("5. Quiet Time Flood")
                print("0. Back")
                others = input("\nAttack Mode: ").strip()

                if others == "0":
                    return
                elif others == "1" or others.lower() == "network flood":
                    AttackModule.access_point_flood(self.interface)
                    self.pause()
                    return
                elif others == "2" or others.lower() == "probe flood dos":
                    try:
                        pchannel = int(input("Target Channel: "))
                    except ValueError:
                        debug("warn", "Invalid channel")
                        return
                    AttackModule.probe_dos(self.interface, pchannel)
                    self.pause()
                    return
                elif others == "3" or others.lower() == "flooded channel switch announcement":
                    debug("info", "Flooded CSA running... If you meant Targeted CSA, use 'Scan Networks and Attack'")
                    debug("info", "Channel target: 'common', 'all', a number, or a comma list (1,6,11)")
                    band_raw = input("Target Band (2/5/dual): ").strip().lower() or "dual"
                    target_raw = input("Target Channel: ").strip().lower() or "common"
                    if band_raw == "dual":
                        band = None
                    elif band_raw in ("2", "5"):
                        band = int(band_raw)
                    else:
                        debug("warn", "Invalid band, defaulting to dual")
                        band = None
                    if target_raw in ("all", "common"):
                        channel_target = target_raw
                    else:
                        try:
                            if "," in target_raw:
                                channel_target = [int(c.strip()) for c in target_raw.split(",")]
                            else:
                                channel_target = int(target_raw)
                        except ValueError:
                            debug("warn", f"Invalid channel target '{target_raw}', defaulting to common")
                            channel_target = "common"
                    debug("ok", "Setting looks valid! Flood-CSA is now being executed, it will take 30 seconds before effect due to scanning")
                    AttackModule.flood_csa(iface=self.interface, channel_target=channel_target, band=band, timeout=30)
                    self.pause()
                    return
                elif others == "4" or others.lower() == "bad message flood":
                    debug("info", "Bad Message Flood running... If you meant Targeted Bad Message, use 'Scan Networks and Attack'")
                    AttackModule.bad_message_flood(iface=self.interface)
                    self.pause()
                    return
                elif others == "5" or others.lower() == "quiet time flood":
                    debug("info", "Quiet Flood running... If you meant Targeted Quiet, use 'Scan Networks and Attack'")
                    debug("info", "Channel target: 'all', a number (6), or a comma list (1,6,11)")
                    raw = input("Target Channel [all]: ").strip().lower() or "all"
                    if raw == "all":
                        channel_target = "all"
                    else:
                        try:
                            if "," in raw:
                                channel_target = [int(c.strip()) for c in raw.split(",")]
                            else:
                                channel_target = int(raw)
                        except ValueError:
                            debug("warn", f"Invalid channel target '{raw}', defaulting to all")
                            channel_target = "all"
                    AttackModule.quiet_flood(iface=self.interface, channel_target=channel_target)
                    self.pause()
                    return
            debug("info", "Scanning for networks using DUAL BAND mode...")
            debug("info", "Starting channel hopping... Press Ctrl+C to stop.")
            debug("info", "If no networks appear after 30 seconds, press Ctrl+C and check your interface")
            time.sleep(2)
            self.start_channel_hop_scan()

            debug("info", "All networks found:")
            if not self.networks:
                debug("critical", "No networks detected. This could mean:")
                debug("error", "1. Your wireless card doesn't support monitor mode properly")
                debug("error", "2. The interface is not in monitor mode")
                debug("error", "3. There are no WiFi networks in range")
                debug("error", "4. You need to run with sudo")
            else:
                for i, (bssid, info) in enumerate(self.networks.items(), 1):
                    ssid = info["ssid"] or "<Hidden>"
                    ch = info["channel"] or "?"
                    print(f"{i}) {ssid} - {bssid} (Ch {ch})")

                pick = int(input("Pick a network number: "))
                chosen_bssid = list(self.networks.keys())[pick - 1]
                chosen_info = self.networks[chosen_bssid]
                chosen_ssid = chosen_info["ssid"]
                chosen_channel = chosen_info["channel"]

                debug("ok", f"Selected BSSID: {chosen_bssid}")
                debug("info", f"SSID: {chosen_ssid or '<Hidden>'}")
                debug("info", f"Channel: {chosen_channel or '?'}")
                self.wifi_attack_menu(chosen_bssid, chosen_ssid)

        except KeyboardInterrupt:
            debug("warn", "Interrupted by user")
        except Exception as e:  # noqa: BLE001
            debug("error", f"Error: {e}")
        finally:
            self.cleanup_monitor_mode()
            debug("ok", "WiFi module cleanup complete.")