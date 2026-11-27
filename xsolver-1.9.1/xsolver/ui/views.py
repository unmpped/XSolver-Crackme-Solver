from __future__ import annotations

try:
    import curses
except ImportError:
    curses = None
from pathlib import Path

def put(win, row: int, col: int, text: str, attr: int = 0) -> None:
    try:
        if attr:
            win.addstr(row, col, text, attr)
        else:
            win.addstr(row, col, text)
    except curses.error:
        pass

def hide_cursor() -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass

CREDIT = "dev by @unmpped and his team"

def draw_header(stdscr, title: str) -> int:
    height, width = stdscr.getmaxyx()
    put(stdscr, 0, 0, "XSOLVER".ljust(width - 1), curses.A_BOLD | curses.A_REVERSE)
    if width > len(CREDIT) + 14:
        put(stdscr, 0, width - 2 - len(CREDIT), CREDIT, curses.A_REVERSE)
    put(stdscr, 1, 0, title.ljust(width - 1)[:width - 1], curses.A_BOLD)
    put(stdscr, 2, 0, "-" * (width - 1))
    return 3

def draw_footer(stdscr, text: str) -> None:
    height, width = stdscr.getmaxyx()
    put(stdscr, height - 1, 0, text.ljust(width - 1)[:width - 1], curses.A_DIM)
    try:
        stdscr.attrset(curses.A_NORMAL)
    except curses.error:
        pass

def select_menu(stdscr, title: str, options: list[str], footer: str = "up/down, ENTER select, Q quit") -> int | None:
    selected = 0
    hide_cursor()
    while True:
        stdscr.erase()
        top = draw_header(stdscr, title)
        for i, option in enumerate(options):
            attr = curses.A_REVERSE if i == selected else curses.A_NORMAL
            marker = "> " if i == selected else "  "
            put(stdscr, top + i, 0, f"{marker}{option}", attr)
        draw_footer(stdscr, footer)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(options)
        elif key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(options)
        elif key in (curses.KEY_ENTER, 10, 13):
            return selected
        elif key in (ord("q"), ord("Q"), 27):
            return None

def browse_file(stdscr, start_dir: str, select_dirs: bool = False) -> str | None:
    current = Path(start_dir).resolve()
    selected = 0

    while True:
        try:
            entries = sorted(
                current.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower()),
            )
        except PermissionError:
            entries = []

        display_entries = [".. (parent)"] + [
            f"{e.name}/" if e.is_dir() else e.name for e in entries
        ]

        stdscr.erase()
        top = draw_header(stdscr, f"Browse: {current}")
        height, width = stdscr.getmaxyx()
        visible_rows = height - top - 2

        start_index = max(0, selected - visible_rows + 1)
        for row, idx in enumerate(range(start_index, min(len(display_entries), start_index + visible_rows))):
            attr = curses.A_REVERSE if idx == selected else curses.A_NORMAL
            marker = "> " if idx == selected else "  "
            put(stdscr, top + row, 0, f"{marker}{display_entries[idx]}"[:width - 1], attr)

        footer = "up/down, ENTER open, W Windows file picker, BKSP up, Q back"
        draw_footer(stdscr, footer)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("w"), ord("W")):
            from xsolver.ui.app import _windows_picker
            picked = _windows_picker(select_dirs=select_dirs)
            if picked is not None:
                return picked
            continue
        if key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(display_entries)
        elif key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(display_entries)
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            current = current.parent
            selected = 0
        elif key in (curses.KEY_ENTER, 10, 13):
            if selected == 0:
                current = current.parent
                selected = 0
                continue
            target = entries[selected - 1]
            if target.is_dir():
                if select_dirs and key in (curses.KEY_ENTER, 10, 13) and _confirm_select(stdscr, target):
                    return str(target)
                current = target
                selected = 0
            else:
                return str(target)
        elif key in (ord("q"), ord("Q"), 27):
            return None

def _confirm_select(stdscr, path: Path) -> bool:
    height, width = stdscr.getmaxyx()
    prompt = f"select this dir? [{path}]  (y/n)"
    put(stdscr, height - 2, 0, prompt[:width - 1], curses.A_BOLD)
    stdscr.refresh()
    while True:
        key = stdscr.getch()
        if key in (ord("y"), ord("Y")):
            return True
        if key in (ord("n"), ord("N"), 27):
            return False

def edit_settings(stdscr, fields: list[tuple[str, float, float, float, float]]) -> list[float]:
    values = [f[1] for f in fields]
    selected = 0

    while True:
        stdscr.erase()
        top = draw_header(stdscr, "Settings")
        for i, (label, _default, minimum, maximum, step) in enumerate(fields):
            attr = curses.A_REVERSE if i == selected else curses.A_NORMAL
            marker = "> " if i == selected else "  "
            put(stdscr, top + i, 0, f"{marker}{label:<28} {values[i]:g}", attr)
        draw_footer(stdscr, "up/down, left/right adjust, ENTER ok, Q back")
        stdscr.refresh()

        key = stdscr.getch()
        label, _default, minimum, maximum, step = fields[selected]
        if key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(fields)
        elif key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(fields)
        elif key == curses.KEY_LEFT:
            values[selected] = max(minimum, values[selected] - step)
        elif key == curses.KEY_RIGHT:
            values[selected] = min(maximum, values[selected] + step)
        elif key in (curses.KEY_ENTER, 10, 13):
            return values
        elif key in (ord("q"), ord("Q"), 27):
            return [f[1] for f in fields]

def show_message(stdscr, title: str, lines: list[str], footer: str = "any key to continue") -> None:
    stdscr.erase()
    top = draw_header(stdscr, title)
    height, width = stdscr.getmaxyx()
    for i, line in enumerate(lines[:height - top - 2]):
        put(stdscr, top + i, 0, line[:width - 1])
    draw_footer(stdscr, footer)
    stdscr.refresh()
    stdscr.getch()
