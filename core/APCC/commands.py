import difflib
import shlex


class Command:
    def __init__(self, name, fn, help, usage="", aliases=(), interactive=False):
        self.name = name
        self.fn = fn
        self.help = help
        self.usage = usage
        self.aliases = tuple(aliases)
        self.interactive = interactive


class CommandRouter:
    """Typed-command dispatcher: exact name, alias, or unique prefix match."""

    def __init__(self):
        self._cmds = {}
        self._alias = {}

    def register(self, name, fn, help, usage="", aliases=(), interactive=False):
        cmd = Command(name, fn, help, usage, aliases, interactive)
        self._cmds[name] = cmd
        for a in aliases:
            self._alias[a] = name
        return cmd

    def _candidates(self, token):
        names = set()
        for n in self._cmds:
            if n.startswith(token):
                names.add(n)
        for a, target in self._alias.items():
            if a.startswith(token):
                names.add(target)
        return names

    def resolve(self, token):
        token = token.lower()
        if token in self._cmds:
            return self._cmds[token], None
        if token in self._alias:
            return self._cmds[self._alias[token]], None
        names = self._candidates(token)
        if len(names) == 1:
            return self._cmds[next(iter(names))], None
        if not names:
            pool = list(self._cmds) + list(self._alias)
            guesses = difflib.get_close_matches(token, pool, n=3, cutoff=0.5)
            if guesses:
                return None, (f"unknown command: {token} — did you mean: "
                              f"{', '.join(guesses)}?")
            return None, f"unknown command: {token} (try 'help')"
        return None, (f"ambiguous command '{token}' — matches: "
                      f"{', '.join(sorted(names))}")

    def parse(self, line):
        """Return (command, args_list) on success, (None, None) for a blank
        line, or (None, error_string) for an error."""
        line = (line or "").strip()
        if not line:
            return None, None
        try:
            parts = shlex.split(line)
        except ValueError as e:
            return None, f"parse error: {e}"
        cmd, err = self.resolve(parts[0])
        if err:
            return None, err
        return cmd, parts[1:]

    def commands(self):
        return [self._cmds[n] for n in sorted(self._cmds)]
