import re
import time
import errno
import threading
from datetime import datetime
from pathlib import Path

from scapy.all import sniff, PcapWriter, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, Ether

LOG_CATEGORIES = [
    "dns",
    "tls_sni",
    "new_device",
    "malformed",
    "traffic",
]


def _extract_sni(raw_bytes):
    try:
        if len(raw_bytes) < 5 or raw_bytes[0] != 0x16:
            return None
        pos = 5
        if raw_bytes[pos] != 0x01:
            return None
        pos += 4 + 2 + 32
        sess_len = raw_bytes[pos]
        pos += 1 + sess_len
        cs_len = int.from_bytes(raw_bytes[pos:pos+2], "big")
        pos += 2 + cs_len
        comp_len = raw_bytes[pos]
        pos += 1 + comp_len
        ext_total_len = int.from_bytes(raw_bytes[pos:pos+2], "big")
        pos += 2
        end = pos + ext_total_len
        while pos < end:
            ext_type = int.from_bytes(raw_bytes[pos:pos+2], "big")
            ext_len = int.from_bytes(raw_bytes[pos+2:pos+4], "big")
            if ext_type == 0:
                sni_pos = pos + 4 + 2 + 1 + 2
                name_len = int.from_bytes(raw_bytes[pos+4+2+1:pos+4+2+3], "big")
                return raw_bytes[sni_pos:sni_pos+name_len].decode(errors="replace")
            pos += 4 + ext_len
    except Exception:
        return None
    return None


def _extract_http_host_path(raw_bytes):
    try:
        text = raw_bytes[:2048].decode("latin-1", errors="replace")
        if not text.startswith(("GET ", "POST ", "HEAD ", "PUT ",
                                 "DELETE ", "OPTIONS ", "PATCH ")):
            return None, None
        line_end = text.find("\r\n")
        if line_end == -1:
            return None, None
        parts = text[:line_end].split(" ")
        if len(parts) < 2:
            return None, None
        path = parts[1]
        m = re.search(r"\r\nHost:\s*([^\r\n]+)", text, re.IGNORECASE)
        if not m:
            return None, None
        return m.group(1).strip(), path
    except Exception:
        return None, None


class APLogger:
    def __init__(self, iface, session_dir, client_manager, debug, domain_filter=None):
        self.iface = iface
        self.session_dir = Path(session_dir)
        self.client_manager = client_manager
        self.debug = debug



        self.domain_filter = domain_filter








        self.full_address = False
        self.show_device = False

        self.enabled_categories = set()
        self.recording = False
        self.display_on = False
        self.display_buffer = []
        self._display_lock = threading.Lock()

        self.txt_fh = None
        self.pcap_writer = None
        self._known_devices = set()

        self._sniff_thread = None
        self._stop = threading.Event()

    def start_recording(self):
        if self.recording:
            return
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.txt_fh = open(self.session_dir / "activity.txt", "a", buffering=1)
        self.pcap_writer = PcapWriter(str(self.session_dir / "traffic.pcap"),
                                       append=True, sync=True)
        self.recording = True
        self.txt_fh.write(f"=== Recording started {datetime.now().isoformat()} ===\n")

    def stop_recording(self):
        self.recording = False
        for fh in (self.txt_fh,):
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
        self.txt_fh = None
        self.pcap_writer = None

    def clear_display(self):
        with self._display_lock:
            self.display_buffer.clear()

    def _mac_of(self, pkt):
        if pkt.haslayer(Ether):
            return pkt[Ether].src
        return "??:??:??:??:??:??"

    def _emit(self, category, line, pkt=None):
        if category not in self.enabled_categories:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        full = f"[{ts}] [{category}] {line}"
        if self.recording:
            if self.txt_fh:
                self.txt_fh.write(full + "\n")
            if self.pcap_writer and pkt is not None:
                try:
                    self.pcap_writer.write(pkt)
                except Exception:
                    pass
        if self.display_on:
            with self._display_lock:
                self.display_buffer.append(full)
                if len(self.display_buffer) > 500:
                    self.display_buffer.pop(0)

    def _is_domain_filtered(self, domain):
        if self.domain_filter is None:
            return False
        try:
            return self.domain_filter.is_filtered(domain)
        except Exception:


            return False

    def _device_label(self, mac):
        if self.show_device:
            try:
                name = self.client_manager.get_device_name(mac)
            except Exception:
                name = None
            if name:
                return name
        return mac

    def _handle_packet(self, pkt):
        mac = self._mac_of(pkt)
        if self.client_manager.is_filtered(mac):
            return





        if self.recording and self.pcap_writer:
            try:
                self.pcap_writer.write(pkt)
            except Exception:
                pass

        if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            return

        label = self._device_label(mac)

        if "new_device" in self.enabled_categories and mac not in self._known_devices:
            self._known_devices.add(mac)
            self._emit("new_device", f"New device seen: {label}")

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and "dns" in self.enabled_categories:
            try:




                qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                if not self._is_domain_filtered(qname):
                    self._emit("dns", f"{label} looked up: {qname}")
            except Exception:
                pass

        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and "tls_sni" in self.enabled_categories:
            raw = bytes(pkt[Raw].load)
            domain = _extract_sni(raw)
            path = None
            if domain is None and self.full_address:



                domain, path = _extract_http_host_path(raw)
            if domain and not self._is_domain_filtered(domain):
                if self.full_address:





                    scheme = "http" if path else "https"
                    self._emit("tls_sni", f"{label} visited: {scheme}://{domain}{path or ''}")
                else:
                    self._emit("tls_sni", f"{label} visited (TLS SNI): {domain}")

        if "traffic" in self.enabled_categories and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
            dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
            proto = "TCP" if pkt.haslayer(TCP) else "UDP"
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
            self._emit("traffic", f"{label} {proto} {src}:{sport} -> {dst}:{dport}")

        if "malformed" in self.enabled_categories:
            try:
                bytes(pkt)
            except Exception as e:
                self._emit("malformed", f"{label} malformed packet: {e}")

    def start_sniff(self):
        self._stop.clear()

        def loop():
            was_failing = False
            while not self._stop.is_set():
                try:
                    sniff(iface=self.iface, prn=self._handle_packet,
                          store=False, timeout=1)
                    if was_failing:
                        self.debug("ok", f"{self.iface}: interface was "
                                          "disconnected but successfully "
                                          "rebind.")
                        was_failing = False
                except OSError as e:
                    if e.errno == errno.ENODEV:








                        if not was_failing:
                            still_exists = Path(f"/sys/class/net/{self.iface}").exists()
                            if still_exists:
                                self.debug("info",
                                           f"{self.iface}: temporarily "
                                           "unavailable, retrying rebind...")
                            else:
                                self.debug("warn",
                                           f"{self.iface}: disconnected, "
                                           "retrying...")
                        was_failing = True
                        time.sleep(1)
                        continue
                    self.debug("error", f"AP sniff error: {e}")
                    was_failing = True
                    time.sleep(1)
                except Exception as e:
                    self.debug("error", f"AP sniff error: {e}")
                    was_failing = True
                    time.sleep(1)
        self._sniff_thread = threading.Thread(target=loop, daemon=True)
        self._sniff_thread.start()

    def stop_sniff(self):
        self._stop.set()
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2)
