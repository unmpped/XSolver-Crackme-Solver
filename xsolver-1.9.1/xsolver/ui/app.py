from __future__ import annotations

try:
    import curses
except ImportError:
    curses = None
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path

from xsolver.analysis.antidebug import detect_timing_checks
from xsolver.analysis.selfmod import detect_self_modifying_code
from xsolver.analysis.static_extract import extract_candidate_keys
from xsolver.analysis.triage import triage
from xsolver.analysis.vmdetect import detect_vm_dispatchers
from xsolver.core.report import SolveReport
from xsolver.orchestrator import SolveOptions, solve
from xsolver.ui.views import (browse_file, draw_footer, draw_header, edit_settings, hide_cursor,
                              put, select_menu, show_message)

_SETTINGS_FIELDS = [
    ("seconds per strategy", 20.0, 2.0, 300.0, 2.0),
    ("seconds per run", 2.0, 0.2, 10.0, 0.2),
    ("max brute length", 4, 1, 8, 1),
    ("max timing length", 10, 1, 20, 1),
    ("max instr length", 16, 1, 32, 1),
]

class AppState:
    def __init__(self, start_dir: str):
        self.start_dir = start_dir
        self.budget = 20.0
        self.timeout = 2.0
        self.max_length = 4
        self.oracle_max_length = 10
        self.instr_oracle_max_length = 16

    def to_options(self) -> SolveOptions:
        return SolveOptions(
            per_strategy_budget_seconds=self.budget,
            timeout_per_run=self.timeout,
            brute_force_max_length=int(self.max_length),
            timing_oracle_max_length=int(self.oracle_max_length),
            instruction_oracle_max_length=int(self.instr_oracle_max_length),
        )

def _set_title(text: str) -> None:
    import os

    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleTitleW(text)
    except Exception:
        pass

def run_tui(start_dir: str) -> None:
    _set_title("dev by @unmpped and his team")
    if curses is None:
        from xsolver.ui.plain import run_plain

        print("curses missing, text mode (pip install windows-curses for the full ui)")
        run_plain(start_dir)
        return
    curses.wrapper(_main, start_dir)

def _main(stdscr, start_dir: str) -> None:
    hide_cursor()
    stdscr.keypad(True)
    state = AppState(start_dir)

    while True:
        choice = select_menu(
            stdscr,
            "xsolver",
            [
                "Solve",
                "Inspect",
                "Batch",
                "Settings",
                "About",
                "Quit",
            ],
        )
        if choice is None or choice == 5:
            return
        if choice == 0:
            _flow_solve_single(stdscr, state)
        elif choice == 1:
            _flow_inspect(stdscr, state)
        elif choice == 2:
            _flow_batch(stdscr, state)
        elif choice == 3:
            _flow_settings(stdscr, state)
        elif choice == 4:
            _flow_about(stdscr)

def _flow_about(stdscr) -> None:
    show_message(stdscr, "About xsolver", [
        "Project: @unmpped",
        "Discord: https://discord.com/users/1406271025972510730",
        "GitHub: https://github.com/unmpped",
        "Portfolio: http://unmpped.is-a.dev",
        "",
        "Credits:",
        "@unmpped Discord: https://discord.com/users/1406271025972510730",
        "GitHub: https://github.com/unmpped",
        "@l8mz Discord: https://discord.com/users/1323233677781499977",
        "@not_abackroomsguy Discord:",
        "https://discord.com/users/1173296895301533737",
        "GitHub: https://github.com/abackroomsguy",
        "@chocolife13 Discord:",
        "https://discord.com/users/997783100828434452",
        "GitHub: https://github.com/chocolife13",
    ])

def _windows_picker(select_dirs: bool = False) -> str | None:
    powershell = shutil.which("powershell.exe")
    wslpath = shutil.which("wslpath")
    if not powershell or not wslpath:
        return None
    if select_dirs:
        script = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "$d=New-Object System.Windows.Forms.FolderBrowserDialog; "
            "if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) "
            "{[Console]::WriteLine($d.SelectedPath)}"
        )
    else:
        script = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "$d=New-Object System.Windows.Forms.OpenFileDialog; "
            "$d.Title='Choose a target binary'; "
            "$d.Filter='Targets (*.exe;*.elf;*.bin)|*.exe;*.elf;*.bin|All files (*.*)|*.*'; "
            "if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) "
            "{[Console]::WriteLine($d.FileName)}"
        )
    try:
        picked = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-STA", "-Command", script],
            check=False, capture_output=True, text=True,
        ).stdout.strip()
        if not picked:
            return None
        converted = subprocess.run(
            [wslpath, "-u", picked], check=True, capture_output=True, text=True,
        ).stdout.strip()
        return converted or None
    except (OSError, subprocess.SubprocessError):
        return None

def _flow_settings(stdscr, state: AppState) -> None:
    fields = [
        ("seconds per strategy", state.budget, 2.0, 300.0, 2.0),
        ("seconds per run", state.timeout, 0.2, 10.0, 0.2),
        ("max brute length", state.max_length, 1, 8, 1),
        ("max timing length", state.oracle_max_length, 1, 20, 1),
        ("max instr length", state.instr_oracle_max_length, 1, 32, 1),
    ]
    values = edit_settings(stdscr, fields)
    state.budget, state.timeout, state.max_length, state.oracle_max_length, state.instr_oracle_max_length = (
        values[0], values[1], int(values[2]), int(values[3]), int(values[4]),
    )

def _flow_inspect(stdscr, state: AppState) -> None:
    if shutil.which("powershell.exe") and shutil.which("wslpath"):
        target = _windows_picker()
    else:
        target = browse_file(stdscr, state.start_dir)
    if target is None:
        return
    try:
        result = triage(target)
    except Exception as exc:
        show_message(stdscr, "inspect failed", [str(exc)])
        return

    profile = result.profile
    lines = [
        f"Target         : {profile.path}",
        f"Format         : {profile.format}",
        f"Architecture   : {profile.arch}",
        f"File size      : {profile.file_size} bytes",
        f"Entry point    : 0x{profile.entry_point:x}",
        f"Overall entropy: {profile.overall_entropy:.2f}",
        f"Packer likely  : {profile.packer_suspected}",
        f"Input mode     : {result.likely_input_mode}",
        "",
        "Notes:",
    ] + [f"  - {n}" for n in result.notes] + [
        "",
        f"Top candidate strings ({min(12, len(result.strings))} of {len(result.strings)}):",
    ] + [f"  [{s.score:>3}] {s.value!r}" for s in result.strings[:12]]

    try:
        static_candidates = extract_candidate_keys(profile)
    except Exception:
        static_candidates = []
    if static_candidates:
        lines += ["", f"static candidates ({len(static_candidates)}):"]
        lines += [f"  {c!r}" for c in static_candidates]

    try:
        timing_checks = detect_timing_checks(profile)
    except Exception:
        timing_checks = []
    if timing_checks:
        lines += ["", f"Anti-debug/timing checks ({len(timing_checks)}):"]
        lines += [f"  [{c.function}] {c.detail}" for c in timing_checks]

    try:
        selfmod_findings = detect_self_modifying_code(profile)
    except Exception:
        selfmod_findings = []
    if selfmod_findings:
        lines += ["", f"self-modifying code ({len(selfmod_findings)}):"]
        lines += [f"  {f}" for f in selfmod_findings]

    try:
        vm_findings = detect_vm_dispatchers(profile)
    except Exception:
        vm_findings = []
    if vm_findings:
        lines += ["", f"bytecode VM ({len(vm_findings)}):"]
        lines += [f"  {f}" for f in vm_findings]

    show_message(stdscr, f"Inspect: {Path(target).name}", lines)

def _flow_solve_single(stdscr, state: AppState) -> None:
    if shutil.which("powershell.exe") and shutil.which("wslpath"):
        target = _windows_picker()
    else:
        target = browse_file(stdscr, state.start_dir)
    if target is None:
        return
    report = _run_with_progress(stdscr, target, state)
    if report is not None:
        _show_report(stdscr, report)

def _flow_batch(stdscr, state: AppState) -> None:
    if shutil.which("powershell.exe") and shutil.which("wslpath"):
        directory = _windows_picker(select_dirs=True)
    else:
        directory = browse_file(stdscr, state.start_dir, select_dirs=True)
    if directory is None:
        return
    targets = sorted(p for p in Path(directory).iterdir() if p.is_file())
    if not targets:
        show_message(stdscr, "Batch solve", ["no files here"])
        return

    reports: list[SolveReport] = []
    for target in targets:
        report = _run_with_progress(stdscr, str(target), state, batch_label=f"({len(reports) + 1}/{len(targets)})")
        if report is None:
            return
        reports.append(report)

    solved = sum(1 for r in reports if r.status == "solved")
    lines = [f"Solved {solved}/{len(reports)} binaries", ""]
    for r in reports:
        key_part = f"key={r.key_found!r}" if r.key_found else "no key"
        lines.append(f"  {Path(r.target).name:<24} {r.status:<12} {key_part}")
    show_message(stdscr, "Batch results", lines)

def _run_with_progress(stdscr, target: str, state: AppState, batch_label: str = "") -> SolveReport | None:
    progress_queue: queue.Queue = queue.Queue()
    result_holder: dict = {}

    def progress_callback(stage: str, message: str) -> None:
        progress_queue.put((stage, message))

    def worker() -> None:
        try:
            report = solve(target, options=state.to_options(), progress=progress_callback)
            result_holder["report"] = report
        except Exception as exc:
            result_holder["error"] = str(exc)
        progress_queue.put(("done", "finished"))

    thread = threading.Thread(target=worker, daemon=True)
    start_time = time.monotonic()
    thread.start()

    log_lines: list[str] = []
    live_strings: list[str] = []
    stdscr.timeout(150)

    while True:
        try:
            stage, message = progress_queue.get(timeout=0.1)
            if stage == "string":
                live_strings.append(message)
            elif stage != "done":
                log_lines.append(f"[{stage}] {message}")
            if stage == "done":
                break
        except queue.Empty:
            pass

        stdscr.erase()
        title = f"Solving: {Path(target).name} {batch_label}".strip()
        top = draw_header(stdscr, title)
        height, width = stdscr.getmaxyx()
        elapsed = time.monotonic() - start_time
        put(stdscr, top, 0, f"Elapsed: {elapsed:.1f}s", curses.A_BOLD)
        string_rows = min(6, max(1, (height - top - 8) // 3))
        put(stdscr, top + 2, 0, f"Live strings ({len(live_strings)} found)", curses.A_BOLD)
        for row, line in enumerate(live_strings[:string_rows]):
            put(stdscr, top + 3 + row, 0, line[:width - 1])
        progress_heading = top + 3 + string_rows
        put(stdscr, progress_heading, 0, "Progress", curses.A_BOLD)
        progress_top = progress_heading + 1
        visible_rows = max(1, height - progress_top - 2)
        for row, line in enumerate(log_lines[-visible_rows:]):
            put(stdscr, progress_top + row, 0, line[:width - 1])
        draw_footer(stdscr, "ESC abandons")
        stdscr.refresh()

        key = stdscr.getch()
        if key == 27:
            return None

    stdscr.timeout(-1)
    if "error" in result_holder:
        show_message(stdscr, "Solve failed", [result_holder["error"]])
        return None
    return result_holder.get("report")

def _show_report(stdscr, report: SolveReport) -> None:
    lines = [
        f"Target   : {report.target}",
        f"Status   : {report.status}",
    ]
    if report.key_found:
        lines.append(f"Key      : {report.key_found!r}")
        lines.append(f"Strategy : {report.winning_strategy}")
        lines.append(f"Mode     : {report.input_mode}")
    if report.anti_debug_patches:
        lines.append(f"Anti-debug: neutralized {len(report.anti_debug_patches)} check(s)")
        for detail in report.anti_debug_patches:
            lines.append(f"  - {detail}")
    lines.append(f"Duration : {report.total_duration_seconds:.2f}s")
    lines.append("")
    lines.append("Attempts:")
    for attempt in report.attempts:
        lines.append(
            f"  {attempt.strategy:<22} {attempt.outcome:<10} "
            f"{attempt.candidates_tried:>7} tried  {attempt.duration_seconds:.2f}s"
        )
        lines.append(f"    {attempt.detail}")

    while True:
        choice = select_menu(
            stdscr,
            f"Result: {report.status.upper()}",
            ["Details", "Save JSON", "Back to menu"],
            footer="up/down move, ENTER select, Q back",
        )
        if choice is None or choice == 2:
            return
        if choice == 0:
            show_message(stdscr, "Full report", lines)
        elif choice == 1:
            output_path = Path(report.target).with_suffix(".xsolver.json")
            report.save(output_path)
            show_message(stdscr, "Saved", [f"Report written to {output_path}"])
