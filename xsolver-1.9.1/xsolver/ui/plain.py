from __future__ import annotations

from pathlib import Path

from xsolver.core.report import SolveReport
from xsolver.orchestrator import SolveOptions, solve

def _ask(prompt: str, default: str = "") -> str:
    try:
        answer = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    return answer or default

def _settings() -> SolveOptions:
    budget = _ask("seconds per strategy [20]: ", "20")
    timeout = _ask("seconds per run [2]: ", "2")
    try:
        return SolveOptions(per_strategy_budget_seconds=float(budget),
                            timeout_per_run=float(timeout),
                            parallel_workers=3)
    except ValueError:
        return SolveOptions()

def _show(report: SolveReport) -> None:
    print()
    print(f"Target   : {report.target}")
    print(f"Status   : {report.status}")
    if report.key_found:
        print(f"Key      : {report.key_found!r}")
        print(f"Strategy : {report.winning_strategy}")
        print(f"Mode     : {report.input_mode}")
    print(f"Duration : {report.total_duration_seconds:.2f}s")
    print()

def _progress(stage: str, message: str) -> None:
    print(f"[{stage:>10}] {message}")

def _solve_one(options: SolveOptions) -> None:
    target = _ask("binary path: ")
    if not target:
        return
    path = Path(target).expanduser()
    if not path.is_file():
        print(f"not a file: {path}")
        return
    _show(solve(str(path), options=options, progress=_progress))

def _solve_dir(options: SolveOptions) -> None:
    folder = Path(_ask("folder: ", ".")).expanduser()
    if not folder.is_dir():
        print(f"not a folder: {folder}")
        return
    targets = sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in
                     {".exe", ".elf", ".bin", ""} and p.stat().st_size > 512)
    if not targets:
        print("no candidate binaries")
        return
    solved = 0
    for index, target in enumerate(targets[:50], start=1):
        print(f"[{index}/{min(len(targets), 50)}] {target.name}")
        report = solve(str(target), options=options, progress=None)
        if report.status == "solved":
            solved += 1
        key = report.key_found if report.key_found else "-"
        print(f"  {report.status:<12} {key}")
    print(f"solved {solved}/{min(len(targets), 50)}")

def run_plain(start_dir: str) -> None:
    options = SolveOptions()
    while True:
        print()
        print("XSOLVER text mode - dev by @unmpped and his team")
        print("1) solve a binary")
        print("2) solve a folder")
        print("3) settings")
        print("0) quit")
        choice = _ask("choice [0]: ", "0")
        if choice == "1":
            _solve_one(options)
        elif choice == "2":
            _solve_dir(options)
        elif choice == "3":
            options = _settings()
            print(f"budget {options.per_strategy_budget_seconds:g}s, "
                  f"run timeout {options.timeout_per_run:g}s")
        elif choice.strip().lower() in {"q", "quit", "0", ""}:
            return
        else:
            _solve_one(options) if Path(choice).is_file() else print("unknown choice")
