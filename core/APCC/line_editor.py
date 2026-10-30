import os
import sys

from core.APCC import settings as settings_mod
from core.APCC.logging_ap import LOG_CATEGORIES
from core.APCC.termkeys import (
    BACKSPACE,
    CTRL_A,
    CTRL_E,
    CTRL_K,
    CTRL_L,
    CTRL_U,
    CTRL_W,
    DELETE,
    DOWN,
    END,
    HOME,
    LEFT,
    RIGHT,
    UP,
)


class LineEditorMixin:
    """Readline-style line editor for the APCC interactive prompt."""

    def _prompt_text(self):
        return "APCC> "

    def _render_line(self):
        buf = "".join(self._input_buf)
        out = "\r\033[2K" + self._prompt_text() + buf
        tail = len(self._input_buf) - self._cursor
        if tail > 0:
            out += f"\033[{tail}D"
        sys.stdout.write(out)
        sys.stdout.flush()

    def _read_line(self, kr):
        with self._log_lock:
            self._input_buf = []
            self._cursor = 0
            self._prompt_active = True
            sys.stdout.write(self._prompt_text())
            sys.stdout.flush()
        hist_pos = len(self._history)
        stash = ""
        try:
            while self.running:
                ch = kr.getch(timeout=0.3)
                if ch is None:
                    continue
                with self._log_lock:
                    if ch in ("\r", "\n"):
                        line = "".join(self._input_buf)
                        sys.stdout.write("\n")
                        sys.stdout.flush()
                        self._prompt_active = False
                        if line.strip() and (not self._history or self._history[-1] != line):
                            self._history.append(line)
                        return line
                    hist_pos, stash = self._handle_edit_key(ch, hist_pos, stash)
        except KeyboardInterrupt:
            with self._log_lock:
                sys.stdout.write("^C\n")
                sys.stdout.flush()
                self._input_buf = []
                self._cursor = 0
                self._prompt_active = False
            return None
        with self._log_lock:
            self._prompt_active = False
        return None

    def _handle_edit_key(self, ch, hist_pos, stash):
        buf = self._input_buf
        if ch == BACKSPACE:
            if self._cursor > 0:
                del buf[self._cursor - 1]
                self._cursor -= 1
                self._render_line()
        elif ch == DELETE:
            if self._cursor < len(buf):
                del buf[self._cursor]
                self._render_line()
        elif ch == LEFT:
            if self._cursor > 0:
                self._cursor -= 1
                self._render_line()
        elif ch == RIGHT:
            if self._cursor < len(buf):
                self._cursor += 1
                self._render_line()
        elif ch in (HOME, CTRL_A):
            self._cursor = 0
            self._render_line()
        elif ch in (END, CTRL_E):
            self._cursor = len(buf)
            self._render_line()
        elif ch == CTRL_U:
            del buf[:self._cursor]
            self._cursor = 0
            self._render_line()
        elif ch == CTRL_K:
            del buf[self._cursor:]
            self._render_line()
        elif ch == CTRL_W:
            i = self._cursor
            while i > 0 and buf[i - 1] == " ":
                i -= 1
            while i > 0 and buf[i - 1] != " ":
                i -= 1
            del buf[i:self._cursor]
            self._cursor = i
            self._render_line()
        elif ch == CTRL_L:
            sys.stdout.write("\033[2J\033[H")
            self._render_line()
        elif ch in (UP, DOWN):
            hist_pos, stash = self._history_step(ch, hist_pos, stash)
        elif ch == "\t":
            self._complete_buffer()
        elif isinstance(ch, str) and len(ch) == 1 and ch.isprintable():
            buf.insert(self._cursor, ch)
            self._cursor += 1
            self._render_line()
        return hist_pos, stash

    def _history_step(self, direction, hist_pos, stash):
        if not self._history:
            return hist_pos, stash
        if direction == UP:
            if hist_pos == len(self._history):
                stash = "".join(self._input_buf)
            if hist_pos > 0:
                hist_pos -= 1
                self._set_buffer(self._history[hist_pos])
        else:
            if hist_pos < len(self._history):
                hist_pos += 1
                text = stash if hist_pos == len(self._history) else self._history[hist_pos]
                self._set_buffer(text)
        return hist_pos, stash

    def _set_buffer(self, text):
        self._input_buf = list(text)
        self._cursor = len(self._input_buf)
        self._render_line()

    def _complete_buffer(self):
        self._cursor = len(self._input_buf)
        buf = "".join(self._input_buf)
        prefix, cands = self._completion_candidates(buf)
        if not cands:
            return
        if len(cands) == 1:
            completion = cands[0][len(prefix):] + " "
        else:
            common = os.path.commonprefix(cands)
            completion = common[len(prefix):]
        if completion:
            self._input_buf.extend(completion)
            self._cursor = len(self._input_buf)
            self._render_line()
        elif len(cands) > 1:
            sys.stdout.write("\n  " + "   ".join(cands) + "\n")
            self._render_line()

    def _completion_candidates(self, buf):
        trailing_space = buf.endswith(" ")
        tokens = buf.split()
        if not tokens or (len(tokens) == 1 and not trailing_space):
            prefix = tokens[0] if tokens else ""
            names = []
            for c in self.router.commands():
                names.append(c.name)
                names.extend(c.aliases)
            return prefix, sorted(n for n in set(names) if n.startswith(prefix))
        cmd, _err = self.router.resolve(tokens[0])
        if cmd is None:
            return "", []
        args = tokens[1:]
        prefix = "" if trailing_space else tokens[-1]
        pos = len(args) if trailing_space else len(args) - 1
        cands = self._arg_candidates(cmd.name, args, pos)
        return prefix, sorted(c for c in cands if c.startswith(prefix))

    def _arg_candidates(self, name, args, pos):
        onoff = ["off", "on"]
        if name in ("radio", "ap", "dhcp", "record", "display", "bridge"):
            return onoff if pos == 0 else []
        if name == "help":
            return [c.name for c in self.router.commands()] if pos == 0 else []
        if name == "show":
            return self._setting_keys() if pos == 0 else []
        if name in ("get", "set"):
            if pos == 0:
                return self._setting_keys()
            if name == "set" and pos == 1 and args:
                key = self._resolve_setting_key(args[0])
                if key:
                    _k, _l, kind, options, _g = next(
                        f for f in settings_mod.FIELDS if f[0] == key)
                    if kind == "choice":
                        return list(options)
                    if kind == "bool":
                        return onoff
            return []
        if name == "client":
            if pos == 0:
                return [c["mac"] for c in self.client_mgr.list_clients()]
            if pos == 1:
                return ["block", "deauth", "ip", "log", "timeout"]
            if pos == 2 and len(args) >= 2 and args[1].lower() in ("log", "timeout", "block"):
                return onoff
            return []
        if name == "filter":
            if pos == 0:
                return ["cat", "file", "fulladdr", "reload", "showdevice"]
            sub = args[0].lower() if args else ""
            if sub == "cat":
                return list(LOG_CATEGORIES) if pos == 1 else (onoff if pos == 2 else [])
            if sub == "file":
                if pos == 1:
                    return [f[0] for f in self.domain_filter.describe_files()]
                return onoff if pos == 2 else []
            if sub in ("fulladdr", "showdevice") and pos == 1:
                return onoff
            return []
        if name == "blockfile":
            if pos == 0:
                return [f[0] for f in self.domain_filter.describe_files()]
            return onoff if pos == 1 else []
        if name == "unblock" and pos == 0:
            return sorted(set(self.domain_control.blocked)
                          | set(self.domain_control.redirects))
        return []

    def _run_command_line(self, line, kr):
        cmd, args = self.router.parse(line)
        if cmd is None:
            if isinstance(args, str):
                print(args)
            return
        self._safe_run(cmd, args, kr)
