
import http.server
import json
import threading
from pathlib import Path

STATE_FILENAME = "domain_control.json"


class DomainControl:
    def __init__(self, save_dir):
        self.save_dir = Path(save_dir)
        self._lock = threading.RLock()
        self.blocked = set()
        self.redirects = {}
        self.block_files = set()
        self.timeout_macs = set()
        self._load()






    def _state_path(self):
        return self.save_dir / STATE_FILENAME

    def _load(self):
        try:
            data = json.loads(self._state_path().read_text())
        except Exception:
            data = {}
        self.blocked = set(data.get("blocked", []))
        self.redirects = dict(data.get("redirects", {}))
        self.block_files = set(data.get("block_files", []))
        self.timeout_macs = set(data.get("timeout_macs", []))

    def _save(self):
        try:
            self.save_dir.mkdir(parents=True, exist_ok=True)
            self._state_path().write_text(json.dumps({
                "blocked": sorted(self.blocked),
                "redirects": self.redirects,
                "block_files": sorted(self.block_files),
                "timeout_macs": sorted(self.timeout_macs),
            }, indent=2))
        except Exception:
            pass





    def add_block(self, domain: str):
        domain = domain.strip().rstrip(".").lower()
        with self._lock:
            if domain in self.redirects:
                return "conflict", self.redirects[domain]
            self.blocked.add(domain)
            self._save()
            return "ok", None

    def add_redirect(self, domain: str, target: str):
        domain = domain.strip().rstrip(".").lower()
        with self._lock:
            if domain in self.blocked:
                return "conflict", None
            self.redirects[domain] = target
            self._save()
            return "ok", None

    def reset(self, name: str):
        with self._lock:
            found = False
            if name in self.block_files:
                self.block_files.discard(name)
                found = True
            if name in self.blocked:
                self.blocked.discard(name)
                found = True
            if name in self.redirects:
                del self.redirects[name]
                found = True
            if found:
                self._save()
                return "ok"
            return "not_found"

    def set_block_file_enabled(self, filename: str, enabled: bool):
        with self._lock:
            if enabled:
                self.block_files.add(filename)
            else:
                self.block_files.discard(filename)
            self._save()

    def set_timeout(self, mac: str, enabled: bool):
        mac = mac.lower()
        with self._lock:
            if enabled:
                self.timeout_macs.add(mac)
            else:
                self.timeout_macs.discard(mac)
            self._save()





    def _literal_domains_from_files(self, domain_filter):
        domains = set()
        skipped = 0
        with self._lock:
            block_files = set(self.block_files)
        for fname in block_files:
            for raw in domain_filter.raw_patterns_for_file(fname):
                if "*" in raw:
                    skipped += 1
                    continue
                domains.add(raw.strip().rstrip(".").lower())
        return domains, skipped

    def generate_dnsmasq_lines(self, domain_filter, gateway_ip: str):
        with self._lock:
            blocked = set(self.blocked)
            redirects = dict(self.redirects)
        file_domains, _skipped = self._literal_domains_from_files(domain_filter)




        all_blocked = (blocked | file_domains) - set(redirects)
        lines = [f"address=/{d}/" for d in sorted(all_blocked)]
        lines += [f"address=/{d}/{gateway_ip}" for d in sorted(redirects)]
        return lines

    def summary(self, domain_filter) -> str:
        with self._lock:
            blocked = sorted(self.blocked)
            redirects = dict(self.redirects)
            block_files = set(self.block_files)
            timeout_macs = sorted(self.timeout_macs)
        file_domains, skipped = self._literal_domains_from_files(domain_filter)

        lines = []
        lines.append(f"Blocked domains ({len(blocked)}):")
        if blocked:
            lines.extend(f"  - {d}" for d in blocked)
        else:
            lines.append("  (none)")
        lines.append("")

        lines.append(f"Redirected domains ({len(redirects)}):")
        if redirects:
            lines.extend(f"  - {d} -> {t}" for d, t in sorted(redirects.items()))
        else:
            lines.append("  (none)")
        lines.append("")

        all_files = domain_filter.describe_files()
        enabled_file_rows = [(f, c) for f, _e, c, _err in all_files if f in block_files]
        lines.append(f"Blocking via files ({len(enabled_file_rows)} enabled):")
        if enabled_file_rows:




            for fname, count in enabled_file_rows:
                lines.append(f"  [x] {fname}  ({count} domain{'s' if count != 1 else ''})")
        else:
            lines.append("  (none enabled)")
        if skipped:
            lines.append(f"  ({skipped} wildcard pattern(s) in enabled files skipped — "
                          "dnsmasq can only enforce exact domains, not this tool's own "
                          "wildcard syntax; they still work fine for log-hiding)")
        lines.append("")

        lines.append(f"Available filter files ({domain_filter.directory}):")
        if all_files:
            for fname, _enabled, count, _err in all_files:
                tag = " [blocking]" if fname in block_files else ""
                lines.append(f"  {fname}  ({count} patterns){tag}")
        else:
            lines.append("  (none found)")

        if timeout_macs:
            lines.append("")
            lines.append(f"Timed-out clients ({len(timeout_macs)}):")
            lines.extend(f"  - {m}" for m in timeout_macs)

        return "\n".join(lines)


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    domain_control = None

    def _handle(self):
        host = self.headers.get("Host", "").split(":")[0].strip().rstrip(".").lower()
        target = None
        if self.domain_control and host:








            labels = host.split(".")
            for i in range(len(labels)):
                suffix = ".".join(labels[i:])
                if suffix in self.domain_control.redirects:
                    target = self.domain_control.redirects[suffix]
                    break
        if target:
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, fmt, *args):
        pass


class RedirectServer:

    def __init__(self, domain_control, debug):
        self.domain_control = domain_control
        self.debug = debug
        self._server = None
        self._thread = None

    def start(self, gateway_ip: str):
        self.stop()
        if not self.domain_control.redirects:
            return
        handler = type("_BoundRedirectHandler", (_RedirectHandler,),
                        {"domain_control": self.domain_control})
        try:
            self._server = http.server.ThreadingHTTPServer((gateway_ip, 80), handler)
        except OSError as e:
            self.debug("warn", f"Could not start the redirect server on "
                                f"{gateway_ip}:80: {e}")
            self._server = None
            return
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.debug("info", f"Redirect server listening on {gateway_ip}:80 for "
                            f"{len(self.domain_control.redirects)} domain(s).")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
