from __future__ import annotations

import argparse
import sys
from pathlib import Path

from xsolver.analysis.antidebug import detect_timing_checks
from xsolver.analysis.selfmod import detect_self_modifying_code
from xsolver.analysis.vmdetect import detect_vm_dispatchers
from xsolver.analysis.static_extract import extract_candidate_keys
from xsolver.analysis.triage import triage
from xsolver.core.report import SolveReport
from xsolver.orchestrator import SolveOptions, solve

def _print_progress(stage: str, message: str) -> None:
    print(f"[{stage:>10}] {message}", file=sys.stderr)

def cmd_solve(args: argparse.Namespace) -> int:
    options = SolveOptions(
        strategy_names=args.strategy,
        per_strategy_budget_seconds=args.budget,
        timeout_per_run=args.timeout,
        brute_force_max_length=args.max_length,
        timing_oracle_max_length=args.oracle_max_length,
        instruction_oracle_max_length=args.instr_oracle_max_length,
        pe_instruction_oracle=getattr(args, "pe_oracle", False),
        parallel_workers=getattr(args, "workers", 3),
        neutralize_anti_debug=not getattr(args, "no_antidebug", False),
    )
    report = solve(args.target, options=options, progress=None if args.quiet else _print_progress)
    _print_report(report)
    if args.output:
        report.save(args.output)
        print(f"report written to {args.output}", file=sys.stderr)
    return 0 if report.status == "solved" else 1

def cmd_inspect(args: argparse.Namespace) -> int:
    result = triage(args.target)
    profile = result.profile
    print(f"Target        : {profile.path}")
    print(f"Format        : {profile.format}")
    print(f"Architecture  : {profile.arch}")
    print(f"File size     : {profile.file_size} bytes")
    print(f"Entry point   : 0x{profile.entry_point:x}")
    print(f"Overall entropy: {profile.overall_entropy:.2f}")
    print(f"Packer suspected: {profile.packer_suspected}")
    print(f"Likely input mode: {result.likely_input_mode}")
    if result.notes:
        print("Notes:")
        for note in result.notes:
            print(f"  - {note}")
    print(f"Top candidate strings ({min(10, len(result.strings))} of {len(result.strings)}):")
    for s in result.strings[:10]:
        print(f"  [{s.score:>3}] {s.value!r}")

    try:
        static_candidates = extract_candidate_keys(profile)
    except Exception as exc:
        static_candidates = []
        print(f"disassembly unavailable ({exc})")
    if static_candidates:
        print(f"static candidates ({len(static_candidates)}):")
        for candidate in static_candidates:
            print(f"  {candidate!r}")

    try:
        timing_checks = detect_timing_checks(profile)
    except Exception:
        timing_checks = []
    if timing_checks:
        print(f"anti-debug checks ({len(timing_checks)}):")
        for check in timing_checks:
            print(f"  [{check.function}] {check.detail}")

    try:
        selfmod_findings = detect_self_modifying_code(profile)
    except Exception:
        selfmod_findings = []
    if selfmod_findings:
        print(f"self-modifying code ({len(selfmod_findings)}):")
        for finding in selfmod_findings:
            print(f"  {finding}")

    try:
        vm_findings = detect_vm_dispatchers(profile)
    except Exception:
        vm_findings = []
    if vm_findings:
        print(f"bytecode VM ({len(vm_findings)}):")
        for finding in vm_findings:
            print(f"  {finding}")
    return 0

def cmd_batch(args: argparse.Namespace) -> int:
    target_dir = Path(args.directory)
    from xsolver.core.runtime import TargetRuntime

    targets = []
    for candidate in sorted(p for p in target_dir.iterdir() if p.is_file()):
        try:
            profile = TargetRuntime.for_path(candidate).profile
        except Exception:
            continue
        if profile.format.startswith(("PE", "ELF")):
            targets.append(candidate)
    options = SolveOptions(
        strategy_names=args.strategy,
        per_strategy_budget_seconds=args.budget,
        timeout_per_run=args.timeout,
        brute_force_max_length=args.max_length,
        timing_oracle_max_length=args.oracle_max_length,
        instruction_oracle_max_length=args.instr_oracle_max_length,
        pe_instruction_oracle=getattr(args, "pe_oracle", False),
        parallel_workers=getattr(args, "workers", 3),
        neutralize_anti_debug=not getattr(args, "no_antidebug", False),
    )
    solved = 0
    results: list[SolveReport] = []
    for target in targets:
        print(f"=== {target.name} ===", file=sys.stderr)
        try:
            report = solve(target, options=options, progress=None if args.quiet else _print_progress)
        except Exception as exc:
            print(f"Skipped {target.name}: {exc}", file=sys.stderr)
            continue
        results.append(report)
        if report.status == "solved":
            solved += 1
        _print_report(report)

    print(f"\nSolved {solved}/{len(results)} binaries", file=sys.stderr)

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for report in results:
            name = Path(report.target).name
            report.save(out_dir / f"{name}.json")

    return 0

def _print_report(report: SolveReport) -> None:
    print()
    print(f"Target   : {report.target}")
    print(f"Status   : {report.status}")
    if report.notes:
        print(f"Notes    : {report.notes}")
    if report.anti_debug_patches:
        print(f"Anti-debug: neutralized {len(report.anti_debug_patches)} check(s) before solving")
        for detail in report.anti_debug_patches:
            print(f"  - {detail}")
    if report.key_found:
        print(f"Key      : {report.key_found!r}")
        print(f"Strategy : {report.winning_strategy}")
        print(f"Mode     : {report.input_mode}")
    print(f"Duration : {report.total_duration_seconds:.2f}s")
    print("Attempts :")
    for attempt in report.attempts:
        print(f"  {attempt.strategy:<22} {attempt.outcome:<10} {attempt.candidates_tried:>6} tried  {attempt.duration_seconds:.2f}s  {attempt.detail}")
    print()

def cmd_tui(args: argparse.Namespace) -> int:
    from xsolver.ui.app import run_tui
    run_tui(args.directory)
    return 0

def _runtime_for(target: str):
    from xsolver.core.runtime import TargetRuntime

    return TargetRuntime.for_path(target)

def cmd_keygen(args: argparse.Namespace) -> int:
    from xsolver.symbolic.attacks import ReadSpec, solve_keygenme

    runtime = _runtime_for(args.target)
    if not args.quiet:
        print(f"target   : {args.target}")
        print(f"runtime  : {runtime.runner}")
        print(f"name     : {args.name!r}")
        print(f"format   : {args.serial}")

    def verify(serial: bytes) -> bool:
        if args.no_verify:
            return True
        data = args.name.encode() + b"\n" + serial + b"\n"
        result = runtime.run(stdin_data=data)
        text = (result.stdout + result.stderr).decode("latin-1", "replace")
        if not args.quiet:
            tail = text.strip().splitlines()[-1][:80] if text.strip() else "no output"
            print(f"  verification {serial!r} -> {tail}")
        if args.expect:
            return args.expect in text
        lowered = text.lower()
        return not any(word in lowered for word in ("fail", "wrong", "incorrect", "invalid", "denied", "nope"))

    read = None
    if args.read:
        read = ReadSpec(template=args.serial, call=args.call, address=int(args.read, 0))
    outcome = solve_keygenme(
        args.target,
        template=args.serial,
        prefix=args.name.encode(),
        read=read,
        hex_parser=int(args.hex, 0) if args.hex else None,
        timeout=args.timeout,
        verify=verify,
    )
    print()
    for name in ("read", "hex", "call"):
        if name in outcome.hooks:
            value = outcome.hooks[name]
            print(f"hook {name:<5}: {hex(value) if isinstance(value, int) else value}")
    print(f"serial   : {outcome.serial!r}")
    print(f"verified : {outcome.verified}")
    print(f"detail   : {outcome.detail}")
    return 0 if outcome.serial and (outcome.verified or args.no_verify) else 1

def cmd_symbolic(args: argparse.Namespace) -> int:
    from xsolver.core.runtime import TargetRuntime
    from xsolver.symbolic.engine import SymbolicEngine

    runtime = TargetRuntime.for_path(args.target)
    engine = SymbolicEngine(args.target, max_len=max(args.max_length, 16))

    def verify(data: bytes) -> bool:
        if args.no_verify:
            return True
        payload = data if data.endswith(b"\n") else data + b"\n"
        result = runtime.run(stdin_data=payload)
        text = (result.stdout + result.stderr).decode("latin-1", "replace")
        if not args.quiet:
            tail = text.strip().splitlines()[-1][:80] if text.strip() else "no output"
            print(f"  verification {data!r} -> {tail}")
        if args.expect:
            return args.expect in text
        lowered = text.lower()
        return not any(word in lowered for word in ("fail", "wrong", "incorrect", "invalid", "denied", "nope"))

    lengths = [int(value, 0) for value in args.lengths.split(",")] if args.lengths else None
    outcome = engine.solve(
        prefix=args.prefix.encode(),
        suffix=b"\n",
        lengths=lengths,
        timeout=args.timeout,
        verify=verify,
    )
    print()
    print(f"success  : {[hex(a) for a in outcome.win_addresses]}")
    print(f"failure  : {[hex(a) for a in outcome.lose_addresses]}")
    print(f"key      : {outcome.input_data!r}")
    print(f"duration : {outcome.elapsed:.1f}s ({outcome.attempts} attempts)")
    print(f"detail   : {outcome.detail}")
    return 0 if outcome.found else 1

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="xsolver", description="automatic crackme solver - dev by @unmpped and his team")
    subparsers = parser.add_subparsers(dest="command", required=True)

    solve_parser = subparsers.add_parser("solve", help="Solve a single binary")
    solve_parser.add_argument("target", help="target binary")
    solve_parser.add_argument("--strategy", action="append", help="strategy to run (repeatable)")
    solve_parser.add_argument("--budget", type=float, default=20.0, help="seconds per strategy")
    solve_parser.add_argument("--timeout", type=float, default=2.0, help="seconds per run")
    solve_parser.add_argument("--max-length", type=int, default=4, help="max brute length")
    solve_parser.add_argument("--oracle-max-length", type=int, default=10, help="max timing length")
    solve_parser.add_argument("--instr-oracle-max-length", type=int, default=16, help="max instr-count length")
    solve_parser.add_argument("--no-antidebug", action="store_true",
                              help="do not neutralise anti-debug checks")
    solve_parser.add_argument("--pe-oracle", action="store_true",
                              help="allow the count oracle on PE targets (slow under wine)")
    solve_parser.add_argument("--workers", type=int, default=3,
                              help="strategy workers kept alive at once")
    solve_parser.add_argument("--output", help="write JSON report here")
    solve_parser.add_argument("--quiet", action="store_true", help="quiet")
    solve_parser.set_defaults(func=cmd_solve)

    inspect_parser = subparsers.add_parser("inspect", help="static triage only")
    inspect_parser.add_argument("target", help="target binary")
    inspect_parser.set_defaults(func=cmd_inspect)

    batch_parser = subparsers.add_parser("batch", help="solve a directory")
    batch_parser.add_argument("directory", help="target directory")
    batch_parser.add_argument("--strategy", action="append", help="strategy to run (repeatable)")
    batch_parser.add_argument("--budget", type=float, default=20.0, help="seconds per strategy")
    batch_parser.add_argument("--timeout", type=float, default=2.0, help="seconds per run")
    batch_parser.add_argument("--max-length", type=int, default=4, help="max brute length")
    batch_parser.add_argument("--oracle-max-length", type=int, default=10, help="max timing length")
    batch_parser.add_argument("--instr-oracle-max-length", type=int, default=16, help="max instr-count length")
    batch_parser.add_argument("--no-antidebug", action="store_true",
                              help="do not neutralise anti-debug checks")
    batch_parser.add_argument("--pe-oracle", action="store_true",
                              help="allow the count oracle on PE targets (slow under wine)")
    batch_parser.add_argument("--workers", type=int, default=3,
                              help="strategy workers kept alive at once")
    batch_parser.add_argument("--output-dir", help="write JSON reports here")
    batch_parser.add_argument("--quiet", action="store_true", help="quiet")
    batch_parser.set_defaults(func=cmd_batch)

    keygen_parser = subparsers.add_parser(
        "keygen", help="solve a name -> serial keygenme"
    )
    keygen_parser.add_argument("target", help="Path to the binary")
    keygen_parser.add_argument("--name", default="", help="fixed name for the program")
    keygen_parser.add_argument("--serial", required=True,
                               help="serial template, e.g. ML-XXXX-YYYY-ZZZZ")
    keygen_parser.add_argument("--call", type=int, default=1, help="read index (0 = first)")
    keygen_parser.add_argument("--read", help="read function address (auto)")
    keygen_parser.add_argument("--hex", help="hex parser address (auto)")
    keygen_parser.add_argument("--expect", help="success text (auto)")
    keygen_parser.add_argument("--timeout", type=float, default=300.0, help="total seconds")
    keygen_parser.add_argument("--no-verify", action="store_true", help="no execution")
    keygen_parser.add_argument("--quiet", action="store_true", help="terse output")
    keygen_parser.set_defaults(func=cmd_keygen)

    symbolic_parser = subparsers.add_parser(
        "symbolic", help="symbolic search on stdin"
    )
    symbolic_parser.add_argument("target", help="Path to the binary")
    symbolic_parser.add_argument("--prefix", default="", help="concrete prefix")
    symbolic_parser.add_argument("--lengths", help="lengths, comma separated")
    symbolic_parser.add_argument("--max-length", type=int, default=64, help="max symbolic length")
    symbolic_parser.add_argument("--expect", help="success text")
    symbolic_parser.add_argument("--timeout", type=float, default=240.0, help="seconds")
    symbolic_parser.add_argument("--no-verify", action="store_true", help="no execution")
    symbolic_parser.add_argument("--quiet", action="store_true", help="terse output")
    symbolic_parser.set_defaults(func=cmd_symbolic)

    tui_parser = subparsers.add_parser("tui", help="terminal interface")
    tui_parser.add_argument("directory", nargs="?", default=".", help="Directory to browse for targets")
    tui_parser.set_defaults(func=cmd_tui)

    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
