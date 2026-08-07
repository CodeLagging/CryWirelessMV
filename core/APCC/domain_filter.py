
import json
import re
import threading
from pathlib import Path

_WILDCARD_CLASSES = {
    "0": "[A-Za-z0-9]*",
    "1": "[0-9]*",
    "2": "[A-Za-z]*",
}



_TOKEN_RE = re.compile(r"\*[012]?")




_HOSTS_PREFIX_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(.+)$")

STATE_FILENAME = ".filter_state.json"


class BadPattern(ValueError):
    pass


def compile_pattern(pattern: str) -> re.Pattern:
    cleaned = pattern.strip().rstrip(".").lower()
    if not cleaned:
        raise BadPattern("empty pattern")

    out = []
    pos = 0
    for m in _TOKEN_RE.finditer(cleaned):
        out.append(re.escape(cleaned[pos:m.start()]))
        cls = m.group()[1:]
        out.append(_WILDCARD_CLASSES.get(cls, ".*"))
        pos = m.end()
    out.append(re.escape(cleaned[pos:]))

    try:
        return re.compile("^" + "".join(out) + "$")
    except re.error as e:
        raise BadPattern(str(e))


def _flatten_json(data):
    out = []
    if isinstance(data, str):
        out.append(data)
    elif isinstance(data, list):
        for item in data:
            out.extend(_flatten_json(item))
    elif isinstance(data, dict):
        for v in data.values():
            out.extend(_flatten_json(v))
    return out


def _parse_text_line(line: str):
    s = line.split("#", 1)[0].strip()
    if not s:
        return []
    m = _HOSTS_PREFIX_RE.match(s)
    if m:
        return m.group(1).split()
    return [s]


class DomainFilter:
    def __init__(self, directory):
        self.directory = Path(directory)
        self._lock = threading.RLock()
        self._file_patterns = {}
        self._file_errors = {}
        self._sources = {}
        self.disabled_files = set()
        self._load_state()
        self.load()





    def _state_path(self):
        return self.directory / STATE_FILENAME

    def _load_state(self):
        try:
            data = json.loads(self._state_path().read_text())
            self.disabled_files = set(data.get("disabled", []))
        except Exception:
            self.disabled_files = set()

    def _save_state(self):
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._state_path().write_text(
                json.dumps({"disabled": sorted(self.disabled_files)}))
        except Exception:
            pass

    def set_file_enabled(self, filename: str, enabled: bool):
        with self._lock:
            if enabled:
                self.disabled_files.discard(filename)
            else:
                self.disabled_files.add(filename)
            self._save_state()





    def _candidate_files(self):
        if not self.directory.is_dir():
            return []
        return sorted(p for p in self.directory.iterdir()
                      if p.is_file() and p.name != STATE_FILENAME)

    def _lines_from_file(self, path, errors_out):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            errors_out.append(f"could not read: {e}")
            return []

        if path.suffix.lower() == ".json":
            try:
                return _flatten_json(json.loads(text))
            except Exception as e:
                errors_out.append(f"invalid JSON: {e}")
                return []

        lines = []
        for raw in text.splitlines():
            lines.extend(_parse_text_line(raw))
        return lines

    def load(self):
        with self._lock:
            file_patterns = {}
            file_errors = {}
            sources = {}
            for path in self._candidate_files():
                try:
                    sources[str(path)] = path.stat().st_mtime
                except OSError:
                    sources[str(path)] = None
                errs = []
                pats = []
                for raw in self._lines_from_file(path, errs):
                    try:
                        pats.append((raw, compile_pattern(raw)))
                    except BadPattern as e:
                        errs.append(f"'{raw}': {e}")
                file_patterns[path.name] = pats
                if errs:
                    file_errors[path.name] = errs
            self._file_patterns = file_patterns
            self._file_errors = file_errors
            self._sources = sources

    def reload_if_changed(self) -> bool:
        if not self.directory.is_dir():
            changed = bool(self._sources)
        else:
            current = {}
            for path in self._candidate_files():
                try:
                    current[str(path)] = path.stat().st_mtime
                except OSError:
                    current[str(path)] = None
            with self._lock:
                changed = current != self._sources
        if changed:
            self.load()
        return changed





    @staticmethod
    def _suffixes(domain: str):
        labels = domain.split(".")
        for i in range(len(labels)):
            yield ".".join(labels[i:])

    def is_filtered(self, domain: str) -> bool:
        if not domain:
            return False
        domain = domain.strip().rstrip(".").lower()
        with self._lock:
            file_patterns = self._file_patterns
            disabled = self.disabled_files
        suffixes = list(self._suffixes(domain))
        for fname, patterns in file_patterns.items():
            if fname in disabled or not patterns:
                continue
            for suffix in suffixes:
                for _raw, regex in patterns:
                    if regex.fullmatch(suffix):
                        return True
        return False







    def raw_patterns_for_file(self, filename: str):
        with self._lock:
            return [raw for raw, _regex in self._file_patterns.get(filename, [])]

    def count(self) -> int:
        with self._lock:
            return sum(len(pats) for fname, pats in self._file_patterns.items()
                       if fname not in self.disabled_files)

    def describe_files(self):
        with self._lock:
            out = []
            for fname in sorted(self._file_patterns):
                enabled = fname not in self.disabled_files
                out.append((fname, enabled, len(self._file_patterns[fname]),
                            len(self._file_errors.get(fname, []))))
            return out
