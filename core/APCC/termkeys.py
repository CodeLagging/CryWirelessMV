import os
import select
import sys
import termios
import tty

UP, DOWN, LEFT, RIGHT = "UP", "DOWN", "LEFT", "RIGHT"
HOME, END, DELETE = "HOME", "END", "DELETE"
BACKSPACE = "BACKSPACE"

# Ctrl keys surfaced to the line editor (readline-style).
CTRL_A, CTRL_E, CTRL_K, CTRL_L, CTRL_U, CTRL_W = (
    "\x01", "\x05", "\x0b", "\x0c", "\x15", "\x17")
_CTRL_KEYS = {0x01, 0x05, 0x0b, 0x0c, 0x15, 0x17}

# Final byte (CSI/SS3) -> key name. Covers both "ESC[" and "ESCO" prefixes and
# the "ESC[<n>~" forms, so arrows/Home/End/Delete work across terminals.
ESCAPE_MAP = {
    "A": UP, "B": DOWN, "C": RIGHT, "D": LEFT,
    "H": HOME, "F": END,
    "1~": HOME, "7~": HOME, "4~": END, "8~": END, "3~": DELETE,
}


def is_back(key) -> bool:
    return key == "ESC" or (isinstance(key, str) and key.lower() == "q")


class TermKeys:

    def __init__(self):
        self.fd = sys.stdin.fileno()
        self.old_settings = None

    def __enter__(self):
        try:
            self.old_settings = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        except termios.error:
            self.old_settings = None
        return self

    def __exit__(self, *a):
        if self.old_settings:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)

    def getch(self, timeout=0.2):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return None
        first = os.read(self.fd, 1)
        if not first:
            return None
        b = first[0]

        if first == b"\x1b":
            return self._read_escape_sequence()












        if first == b"\x03":
            raise KeyboardInterrupt

        if b in (0x7f, 0x08):
            return BACKSPACE
        if b == 0x09:
            return "\t"
        if b in _CTRL_KEYS:
            return first.decode(errors="replace")
        if b < 0x20 and first not in (b"\r", b"\n"):
            return None

        return first.decode(errors="replace")

    def _read_escape_sequence(self):
        r2, _, _ = select.select([self.fd], [], [], 0.3)
        if not r2:
            return "ESC"
        nxt = os.read(self.fd, 1)
        if not nxt:
            return "ESC"
        if nxt not in (b"[", b"O"):




            return "ESC"

        collected = b""
        for _ in range(16):
            r3, _, _ = select.select([self.fd], [], [], 0.3)
            if not r3:
                break
            byte = os.read(self.fd, 1)
            if not byte:
                break
            collected += byte
            if 0x40 <= byte[0] <= 0x7e:
                break

        return ESCAPE_MAP.get(collected.decode(errors="replace"), "ESC")

    def prompt_line_cancelable(self, msg, hide=False, seed=""):
        sys.stdout.write(msg)
        buf = [c for c in seed if c.isprintable()]
        if buf:
            sys.stdout.write("*" * len(buf) if hide else "".join(buf))
        sys.stdout.flush()
        while True:
            select.select([self.fd], [], [], None)
            ch_bytes = os.read(self.fd, 1)
            if not ch_bytes:
                continue
            ch = ch_bytes.decode(errors="replace")
            if ch == "\x1b":










                self._read_escape_sequence()
                sys.stdout.write("\n")
                sys.stdout.flush()
                return None, True
            elif ch in ("\r", "\n"):
                sys.stdout.write("\n")
                sys.stdout.flush()
                return "".join(buf), False
            elif ch in ("\x7f", "\x08"):
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == "\x03":
                raise KeyboardInterrupt
            elif ch.isprintable():
                buf.append(ch)
                sys.stdout.write("*" if hide else ch)
                sys.stdout.flush()

    def prompt_line(self, msg, hide=False):
        if self.old_settings:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)
        try:
            if hide:
                import getpass
                val = getpass.getpass(msg)
            else:
                val = input(msg)
        finally:
            try:
                tty.setcbreak(self.fd)
                termios.tcflush(self.fd, termios.TCIFLUSH)
            except termios.error:
                pass
        return val
