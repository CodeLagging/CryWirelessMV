from .settings import FIELDS, save_settings, validate_settings
from .termkeys import UP, DOWN, LEFT, RIGHT, is_back


def _redraw(settings, idx):
    print("\033[2J\033[H", end="")
    print("--- AP Settings --- (Up/Down: move, Left/Right: change value,")
    print("                      Enter: type value, S: save & exit, Esc/Q: cancel & exit)\n")
    for i, (key, label, kind, options, grayed_fn) in enumerate(FIELDS):
        grayed = bool(grayed_fn and grayed_fn(settings))
        marker = "> " if i == idx else "  "
        val = settings.get(key, "")
        if grayed:
            line = f"{marker}{label:<24} [skipped/default]"
        else:
            line = f"{marker}{label:<24} {val}"
        print(line)
    print()


def run_settings_editor(kr, settings: dict, save_dir):
    idx = 0
    working = dict(settings)

    while True:
        _redraw(working, idx)
        key = None
        while key is None:
            key = kr.getch(timeout=0.5)

        field_key, label, kind, options, grayed_fn = FIELDS[idx]
        grayed = bool(grayed_fn and grayed_fn(working))

        if key == UP:
            idx = (idx - 1) % len(FIELDS)
        elif key == DOWN:
            idx = (idx + 1) % len(FIELDS)
        elif key in (LEFT, RIGHT) and not grayed:
            if kind == "choice":
                cur = working.get(field_key)
                pos = options.index(cur) if cur in options else 0
                pos = (pos + (1 if key == RIGHT else -1)) % len(options)
                working[field_key] = options[pos]
            elif kind == "bool":
                working[field_key] = not working.get(field_key, False)
            elif kind == "int":
                step = 1 if key == RIGHT else -1
                try:
                    working[field_key] = int(working.get(field_key, 0)) + step
                except (ValueError, TypeError):
                    working[field_key] = 0
        elif key in ("\r", "\n") and not grayed:
            if kind in ("str", "int"):
                raw, cancelled = kr.prompt_line_cancelable(
                    f"  {label} (leave empty for default, Esc to cancel): ")
                if not cancelled:
                    raw = raw.strip()
                    if raw:
                        if kind == "int":
                            try:
                                working[field_key] = int(raw)
                            except ValueError:
                                pass
                        else:
                            working[field_key] = raw

            elif kind == "bool":
                working[field_key] = not working.get(field_key, False)
            elif kind == "choice":
                cur = working.get(field_key)
                pos = options.index(cur) if cur in options else 0
                pos = (pos + 1) % len(options)
                working[field_key] = options[pos]
        elif key and isinstance(key, str) and key.lower() == "s":
            corrected, warnings = validate_settings(working)
            save_settings(save_dir, corrected)
            print("\033[2J\033[H", end="")
            print("Settings saved.")
            if warnings:
                print("\nAuto-corrected conflicts:")
                for w in warnings:
                    print(f"  - {w}")
                print()
            return corrected
        elif is_back(key):
            print("\033[2J\033[H", end="")
            return settings
