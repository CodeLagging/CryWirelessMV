"""Terminal raw-key reader for the interactive scanner.

Puts stdin into cbreak mode for single-keystroke reads, restores it on exit,
and can temporarily drop back to cooked mode to prompt for a full line.
"""

import select
import sys
import termios
import tty


class RawKeyReader:
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
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if r:
            return sys.stdin.read(1)
        return None

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
