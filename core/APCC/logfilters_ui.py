from .logging_ap import LOG_CATEGORIES
from .termkeys import UP, DOWN, is_back

_PAGE = 20




ADV_TOGGLES = [
    ("full_address", "Full DNS/TLS_SNI  (show full addr incl. path, where visible)"),
    ("show_device", "ShowDevice  (resolve MAC to device name in log lines)"),
]


def _redraw_categories(enabled, idx, has_advanced):
    print("\033[2J\033[H", end="")
    hint = "F: advanced filter, " if has_advanced else ""
    print("--- Log Filters: Categories --- "
          f"(Up/Down: move, Space/Enter: toggle, {hint}S: save & exit, Esc/Q: cancel)\n")
    for i, cat in enumerate(LOG_CATEGORIES):
        marker = "> " if i == idx else "  "
        box = "[x]" if cat in enabled else "[ ]"
        print(f"{marker}{box} {cat}")
    print()


def _build_rows(domain_filter, toggles):
    rows = []
    for attr, label in ADV_TOGGLES:
        rows.append({"kind": "toggle", "attr": attr, "label": label,
                     "enabled": toggles[attr]})
    files = domain_filter.describe_files()
    if not files:
        rows.append({"kind": "empty",
                      "label": f"(no filter files in {domain_filter.directory} — "
                                "drop .txt/.json/hosts-style lists in there)",
                      "enabled": False})
    else:
        for fname, enabled, count, errcount in files:
            label = f"{fname}  ({count} pattern{'s' if count != 1 else ''}"
            if errcount:
                label += f", {errcount} error{'s' if errcount != 1 else ''}"
            label += ")"
            rows.append({"kind": "file", "filename": fname, "label": label,
                         "enabled": enabled})
    return rows


def _redraw_advanced(domain_filter, rows, idx, scroll):
    print("\033[2J\033[H", end="")
    print("--- Log Filters: Advanced Filter --- "
          "(Up/Down: move, Space/Enter: toggle, "
          "R: reload, C: categories, S: save & exit, Esc/Q: cancel)\n")

    page = rows[scroll:scroll + _PAGE]
    for i, row in enumerate(page):
        absolute_i = scroll + i
        marker = "> " if absolute_i == idx else "  "
        box = "[x]" if row["enabled"] else "[ ]"
        print(f"{marker}{box} {row['label']}")
    if len(rows) > _PAGE:
        print(f"\n  (row {idx + 1} of {len(rows)})")
    print(f"\n  Files load from: {domain_filter.directory}")
    print("  A disabled file stays on disk — it just stops being applied.")
    print()


def run_logfilters_editor(kr, enabled_categories: set, domain_filter=None,
                           full_address=False, show_device=False):
    idx = 0
    scroll = 0
    view = "categories"
    cat_idx = 0

    working_categories = set(enabled_categories)
    working_toggles = {"full_address": full_address, "show_device": show_device}

    def save_result():
        print("\033[2J\033[H", end="")
        return {"categories": working_categories, **working_toggles}

    def cancel_result():
        print("\033[2J\033[H", end="")
        return {"categories": enabled_categories,
                "full_address": full_address, "show_device": show_device}

    while True:
        if view == "categories":
            _redraw_categories(working_categories, cat_idx, domain_filter is not None)
        else:
            rows = _build_rows(domain_filter, working_toggles)
            idx = min(idx, len(rows) - 1)
            _redraw_advanced(domain_filter, rows, idx, scroll)

        key = None
        while key is None:
            key = kr.getch(timeout=0.5)
        klow = key.lower() if isinstance(key, str) else key

        if view == "categories":
            if key == UP:
                cat_idx = (cat_idx - 1) % len(LOG_CATEGORIES)
            elif key == DOWN:
                cat_idx = (cat_idx + 1) % len(LOG_CATEGORIES)
            elif key in (" ", "\r", "\n"):
                cat = LOG_CATEGORIES[cat_idx]
                if cat in working_categories:
                    working_categories.discard(cat)
                else:
                    working_categories.add(cat)
            elif klow == "f" and domain_filter is not None:
                domain_filter.load()
                view = "advanced"
                idx = 0
                scroll = 0
            elif klow == "s":
                return save_result()
            elif is_back(key):
                return cancel_result()

        else:
            rows = _build_rows(domain_filter, working_toggles)
            if key == UP:
                idx = max(0, idx - 1)
            elif key == DOWN:
                idx = min(len(rows) - 1, idx + 1)
            elif key in (" ", "\r", "\n") and rows:
                row = rows[idx]
                if row["kind"] == "toggle":
                    working_toggles[row["attr"]] = not working_toggles[row["attr"]]
                elif row["kind"] == "file":
                    domain_filter.set_file_enabled(row["filename"], not row["enabled"])
            elif klow == "r":
                domain_filter.load()
                idx = 0
                scroll = 0
            elif klow == "c":
                view = "categories"
            elif klow == "s":
                return save_result()
            elif is_back(key):
                return cancel_result()

            if idx < scroll:
                scroll = idx
            elif idx >= scroll + _PAGE:
                scroll = idx - _PAGE + 1
