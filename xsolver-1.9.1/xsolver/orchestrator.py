from __future__ import annotations

import multiprocessing as mp
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import psutil

from xsolver.analysis.antidebug import neutralize_timing_checks, write_patched_copy
from xsolver.analysis.triage import TriageResult, triage
from xsolver.core.report import SolveReport, StrategyAttempt
from xsolver.core.runtime import RuntimeUnavailable, prepare_execution, run_on_target
from xsolver.core.runner import RunnerLimits, run_candidate, stdin_payload
from xsolver.strategies.base import Strategy, default_success_detector
from xsolver.strategies.registry import resolve_strategies

ProgressCallback = Callable[[str, str], None]

@dataclass
class SolveOptions:
    strategy_names: list[str] | None = None
    per_strategy_budget_seconds: float = 20.0
    timeout_per_run: float = 2.0
    max_memory_bytes: int = 256 * 1024 * 1024
    brute_force_charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    brute_force_max_length: int = 5
    timing_oracle_max_length: int = 10
    instruction_oracle_max_length: int = 16
    pe_instruction_oracle: bool = False
    neutralize_anti_debug: bool = True
    gui_probe: bool = True
    parallel_workers: int = 3

_NEGATIVE_CACHE: dict[tuple[str, float], list] = {}

def _negative_samples_cached(binary_path: Path, limits: RunnerLimits) -> list:
    key = (str(binary_path), limits.timeout_seconds)
    if key not in _NEGATIVE_CACHE:
        _NEGATIVE_CACHE[key] = _negative_samples(binary_path, limits)
    return _NEGATIVE_CACHE[key]

def _negative_samples(binary_path: Path, limits: RunnerLimits) -> list:
    jobs = [
        {"stdin_data": (wrong + "\n").encode()}
        for wrong in ("zzqqzz", "A1b2C3d4", "x")
    ] + [{"argv": [wrong]} for wrong in ("zzqqzz", "A1b2C3d4", "x")] \
      + [{"argv": ["player", wrong]} for wrong in ("zzqqzz", "A1b2C3d4")]
    from concurrent.futures import ThreadPoolExecutor

    def one(kwargs):
        try:
            return run_on_target(binary_path, limits=limits, **kwargs)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        results = list(pool.map(one, jobs))
    return [result for result in results if result is not None]

def _prompt_hits(blob: bytes, prompts: list[str]) -> int:
    lowered = blob.lower()
    return sum(1 for prompt in prompts if prompt.lower().encode("latin-1", "replace") in lowered)

def _probe_input_mode(binary_path: Path, limits: RunnerLimits, baseline,
                      fallback: str = "stdin", prompts: list[str] | None = None) -> str:
    reference = _probe_output(baseline)
    probes = {
        "stdin": {"stdin_data": b"zzqqzz\n"},
        "argv": {"argv": ["zzqqzz"]},
        "argv2": {"argv": ["player", "zzqqzz"]},
    }
    try:
        one_line = run_on_target(binary_path, stdin_data=b"zzqqzz\n", limits=limits)
        two_line = run_on_target(binary_path, stdin_data=b"player\nzzqqzz\n", limits=limits)
        if not (two_line.timed_out or two_line.crashed or one_line.timed_out):
            first = (one_line.stdout + one_line.stderr).strip()
            both = (two_line.stdout + two_line.stderr).strip()
            if first and both.startswith(first) and len(both) > len(first) + 8:
                return "stdin2"
            if prompts and len(prompts) >= 2 and _prompt_hits(both, prompts) >= 2:
                return "stdin2"
    except Exception:
        pass
    from concurrent.futures import ThreadPoolExecutor

    def one(item):
        mode, kwargs = item
        try:
            result = run_on_target(binary_path, limits=limits, **kwargs)
        except Exception:
            return None
        if result.timed_out or result.crashed:
            return None
        return mode if _probe_output(result) != reference else None

    with ThreadPoolExecutor(max_workers=len(probes)) as pool:
        for found in pool.map(one, probes.items()):
            if found:
                return found
    return fallback

_STARTUP_FAULT_MARKERS = (
    b"unhandled page fault",
    b"unhandled exception",
    b"segmentation fault",
    b"illegal instruction",
    b"bus error",
)

_WINE_NOISE = (
    b"wine:",
    b"winedbg",
    b"err:winediag",
    b"fixme:",
    b"couldn't get first exception",
    b"starting debugger",
    b"application tried to create a window",
)

_BROKEN_RUNTIME = (
    (b"wine32 is missing", "no 32-bit wine"),
    (b"syswow64\\ntdll", "no 32-bit wine"),
    (b"no application associated with the specified file", "wine cannot start it"),
    (b"could not load kernel32.dll", "wine cannot start it"),
)

_GUI_APIS = (
    b"MessageBoxA", b"MessageBoxW", b"DialogBoxParamA", b"DialogBoxParamW",
    b"CreateWindowExA", b"CreateWindowExW", b"SetTimer", b"GetMessageW",
)

def _gui_stage(binary_path: Path, triage_result: TriageResult, limits: RunnerLimits,
              budget: float, emit) -> tuple[str, StrategyAttempt] | None:
    from xsolver.strategies.gui_probe import GuiProbeStrategy, available, looks_graphical

    if not available() or not looks_graphical(triage_result.profile):
        return None
    emit("gui", "window automaton: driving the dialog")
    strategy = GuiProbeStrategy(binary_path=binary_path, triage=triage_result,
                                limits=limits, budget_seconds=budget)
    result = strategy.run(lambda _result: False)
    emit("gui", f"{result.attempt.outcome}: {result.attempt.detail}")
    if result.found and result.key:
        return result.key, result.attempt
    return None

def _dialog_only(profile, result) -> bool:
    if not profile.format.startswith("PE"):
        return False
    if _strip_runtime_noise((result.stdout or b"") + (result.stderr or b"")):
        return False
    return sum(1 for api in _GUI_APIS if api in profile.raw) >= 2

def _runtime_broken(result) -> str | None:
    blob = ((result.stdout or b"") + b"\n" + (result.stderr or b"")).lower()
    for marker, message in _BROKEN_RUNTIME:
        if marker in blob:
            return message
    return None

def _strip_runtime_noise(blob: bytes) -> bytes:
    kept = [
        line for line in blob.lower().splitlines()
        if line.strip() and not any(noise in line for noise in _WINE_NOISE)
    ]
    return b"\n".join(kept).strip()

def _startup_fault(result) -> str | None:
    produced = _strip_runtime_noise((result.stdout or b"") + (result.stderr or b""))
    if getattr(result, "crashed", False):
        return None if produced else "signal"
    blob = ((result.stdout or b"") + b"\n" + (result.stderr or b"")).lower()
    for marker in _STARTUP_FAULT_MARKERS:
        index = blob.find(marker)
        if index == -1:
            continue
        if not _strip_runtime_noise(blob[:index]):
            return marker.decode()
    return None

def _probe_output(result) -> bytes:
    return b" ".join((result.stdout + result.stderr).lower().split()) + b"|" + str(result.exit_code).encode()

def _normalize_output(result) -> bytes:
    return b" ".join((result.stdout + result.stderr).lower().split())

def _worker_entry(strategy_cls, binary_path, triage_result, limits, budget, baseline_result, queue, extra_kwargs, negatives=None):
    from xsolver.strategies.base import default_success_detector as make_detector
    detector = make_detector(baseline_result, negatives)
    kwargs = extra_kwargs or {}
    strategy: Strategy = strategy_cls(
        binary_path=binary_path,
        triage=triage_result,
        limits=limits,
        budget_seconds=budget,
        **kwargs,
    )
    result = strategy.run(detector)
    queue.put((strategy_cls.name, result))

def solve(binary_path: str | Path, options: SolveOptions | None = None, progress: ProgressCallback | None = None) -> SolveReport:
    options = options or SolveOptions()
    binary_path = Path(binary_path)
    start_time = time.monotonic()

    def emit(stage: str, message: str):
        if progress:
            progress(stage, message)

    emit("triage", f"loading {binary_path.name}")
    triage_result = triage(binary_path)
    profile = triage_result.profile
    for candidate in triage_result.strings[:40]:
        emit("string", f"[{candidate.score:>2}] {candidate.value!r}")

    binary_path.chmod(binary_path.stat().st_mode | 0o111)

    execution_path = binary_path
    anti_debug_patches: list[str] = []
    if options.neutralize_anti_debug:
        try:
            patch_result = neutralize_timing_checks(profile)
        except Exception:
            patch_result = None
        if patch_result:
            patched_bytes, applied = patch_result
            execution_path = write_patched_copy(profile, patched_bytes)
            anti_debug_patches = [p.detail for p in applied]
            emit("antidebug", f"{len(applied)} anti-debug checks patched")

    if options.neutralize_anti_debug:
        try:
            from xsolver.core.antidebug import patched_apis, patched_for

            patched_target = patched_for(binary_path)
        except Exception:
            patched_target = None
        if patched_target is not None:
            execution_path = patched_target
            anti_debug_patches = patched_apis(binary_path)
            emit("antidebug",
                 f"{len(anti_debug_patches)} anti-debug checks neutralised (PE patch)")

    limits = RunnerLimits(
        timeout_seconds=options.timeout_per_run,
        max_memory_bytes=options.max_memory_bytes,
    )

    try:
        runner_kind = prepare_execution(execution_path)
        if runner_kind == "none":
            emit("runtime", "no wine, PE targets cannot run")
    except Exception:
        pass

    emit("baseline", "baseline run, no input")
    try:
        baseline = run_on_target(execution_path, argv=[], limits=limits)
        negatives = _negative_samples(execution_path, limits)
    except RuntimeUnavailable as exc:
        emit("runtime", f"no execution: {exc}")
        return SolveReport(
            target=str(binary_path),
            format=profile.format,
            arch=profile.arch,
            file_size=profile.file_size,
            packer_suspected=profile.packer_suspected,
            status="unrunnable",
            key_found=None,
            winning_strategy=None,
            input_mode=None,
            total_duration_seconds=time.monotonic() - start_time,
            attempts=[],
            anti_debug_patches=anti_debug_patches,
        )
    broken_runtime = _runtime_broken(baseline)
    if broken_runtime is not None:
        emit("runtime", broken_runtime)
        return SolveReport(
            target=str(binary_path),
            format=profile.format,
            arch=profile.arch,
            file_size=profile.file_size,
            packer_suspected=profile.packer_suspected,
            status="unrunnable",
            key_found=None,
            winning_strategy=None,
            input_mode=None,
            total_duration_seconds=time.monotonic() - start_time,
            attempts=[],
            anti_debug_patches=anti_debug_patches,
            notes=broken_runtime,
        )

    emit("baseline", f"{len(negatives)} failure outputs referenced")

    if _dialog_only(profile, baseline):
        dialog = ""
        try:
            from xsolver.core.runtime import capture_dialog
            dialog = capture_dialog(binary_path)
        except Exception:
            dialog = ""
        emit("baseline", f"dialog only: {dialog}" if dialog else "dialog only, no console output")
        note = f"dialog only: {dialog}" if dialog else "dialog only, no console output"
        if options.gui_probe:
            driven = _gui_stage(binary_path, triage_result, limits,
                                max(20.0, options.per_strategy_budget_seconds), emit)
            if driven is not None:
                key, attempt = driven
                return SolveReport(
                    target=str(binary_path),
                    format=profile.format,
                    arch=profile.arch,
                    file_size=profile.file_size,
                    packer_suspected=profile.packer_suspected,
                    status="solved",
                    key_found=key,
                    winning_strategy="gui-probe",
                    input_mode="gui",
                    total_duration_seconds=time.monotonic() - start_time,
                    attempts=[attempt],
                    anti_debug_patches=anti_debug_patches,
                    notes=f"key typed into the dialog and accepted ({attempt.detail})",
                )
        return SolveReport(
            target=str(binary_path),
            format=profile.format,
            arch=profile.arch,
            file_size=profile.file_size,
            packer_suspected=profile.packer_suspected,
            status="gui_only",
            key_found=None,
            winning_strategy=None,
            input_mode=None,
            total_duration_seconds=time.monotonic() - start_time,
            attempts=[],
            anti_debug_patches=anti_debug_patches,
            notes=note,
        )

    fault = _startup_fault(baseline)
    if fault is not None:
        emit("baseline", f"crash at startup ({fault}), no input read - stopping")
        return SolveReport(
            target=str(binary_path),
            format=profile.format,
            arch=profile.arch,
            file_size=profile.file_size,
            packer_suspected=profile.packer_suspected,
            status="target_crashed",
            key_found=None,
            winning_strategy=None,
            input_mode=None,
            total_duration_seconds=time.monotonic() - start_time,
            attempts=[],
            anti_debug_patches=anti_debug_patches,
            notes=f"crash at startup ({fault}), validator unreachable",
        )

    probed_mode = _probe_input_mode(execution_path, limits, baseline,
                                    fallback=triage_result.likely_input_mode,
                                    prompts=triage_result.prompts)
    if probed_mode != triage_result.likely_input_mode:
        emit("baseline", f"input channel: {probed_mode} (triage : {triage_result.likely_input_mode})")
        triage_result.likely_input_mode = probed_mode

    strategy_classes = resolve_strategies(options.strategy_names)

    emit("strategies", f"{len(strategy_classes)} strategies in parallel")

    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    processes = []

    def start_next_worker() -> None:
        while pending and len(running) < max(1, options.parallel_workers):
            strategy_cls = pending.pop(0)
            extra_kwargs = {}
            if strategy_cls.name == "bounded-brute-force":
                extra_kwargs = {
                    "charset": options.brute_force_charset,
                    "max_length": options.brute_force_max_length,
                }
            elif strategy_cls.name == "timing-oracle":
                extra_kwargs = {
                    "max_length": options.timing_oracle_max_length,
                }
            elif strategy_cls.name == "instruction-count-oracle":
                extra_kwargs = {
                    "max_length": options.instruction_oracle_max_length,
                    "allow_pe": options.pe_instruction_oracle,
                }
            p = ctx.Process(
                target=_worker_entry,
                args=(strategy_cls, execution_path, triage_result, limits,
                      options.per_strategy_budget_seconds, baseline, queue, extra_kwargs, negatives),
            )
            p.start()
            running.append(p)
            processes.append(p)
            time.sleep(0.12)

    pending = list(strategy_classes)
    running: list = []
    start_next_worker()

    attempts: list[StrategyAttempt] = []
    raw_winning_key = None
    winning_key = None
    winning_strategy = None
    winning_mode = None
    winning_steps: list[str] | None = None
    winning_verify_path: Path | None = None
    waves = max(1, -(-len(strategy_classes) // max(1, options.parallel_workers)))
    deadline = time.monotonic() + options.per_strategy_budget_seconds * waves + 5

    received = 0
    while received < len(strategy_classes) and time.monotonic() < deadline:
        try:
            name, result = queue.get(timeout=1.0)
        except Exception:
            continue
        received += 1
        if running:
            running.pop(0)
        start_next_worker()
        attempts.append(result.attempt)
        emit("result", f"{name}: {result.attempt.outcome} ({result.attempt.candidates_tried} tried)")
        if result.found and winning_key is None:
            emit("race", f"{name} proposes a key, verifying")
            verify_target = getattr(result, "verify_path", None) or execution_path
            _signal_workers(processes, _SIGSTOP)
            try:
                verified = _verify(verify_target, result.key, result.input_mode, limits,
                                   steps=getattr(result, "steps", None))
            finally:
                _signal_workers(processes, _SIGCONT)
            if verified:
                winning_key = _display_key(result.key)
                raw_winning_key = result.key
                winning_strategy = name
                winning_mode = result.input_mode
                winning_steps = getattr(result, "steps", None)
                winning_verify_path = verify_target
                emit("race", f"{name} won, stopping others")
                break
            result.attempt.outcome = "rejected"
            result.attempt.detail = (
                f"{result.attempt.detail} - rejected (false positive)"
            )
            emit("race", f"{name} rejected: verification failed")

    for p in processes:
        if p.is_alive():
            try:
                _terminate_process_tree(p)
            except Exception:
                pass
        try:
            p.join(timeout=2)
        except Exception:
            pass

    status = "solved" if winning_key else "unresolved"
    gui_verified = False

    if not winning_key and options.gui_probe:
        driven = _gui_stage(binary_path, triage_result, limits,
                            max(20.0, options.per_strategy_budget_seconds * 2), emit)
        if driven is not None:
            winning_key, attempt = driven
            winning_strategy = "gui-probe"
            winning_mode = "gui"
            gui_verified = True
            status = "solved"
            attempts.append(attempt)
            emit("gui", f"accepted by the window: {winning_key}")

    if winning_key and not gui_verified:
        emit("verify", "verifying key")
        final_target = winning_verify_path or binary_path
        verified = _verify(final_target, winning_key, winning_mode, limits, steps=winning_steps)
        if not verified and raw_winning_key and raw_winning_key != winning_key:
            verified = _verify(final_target, raw_winning_key, winning_mode, limits,
                               steps=winning_steps)
            if verified:
                winning_key = raw_winning_key
        if not verified:
            status = "unverified"

    report = SolveReport(
        target=str(binary_path),
        format=profile.format,
        arch=profile.arch,
        file_size=profile.file_size,
        packer_suspected=profile.packer_suspected,
        status=status,
        key_found=winning_key,
        winning_strategy=winning_strategy,
        input_mode=winning_mode,
        total_duration_seconds=time.monotonic() - start_time,
        attempts=attempts,
        anti_debug_patches=anti_debug_patches,
        steps=winning_steps,
    )
    return report

def _display_key(key: str) -> str:
    if len(key) > 1 and key.endswith("\n"):
        return key[:-1]
    return key

_SIGSTOP = getattr(signal, "SIGSTOP", None)
_SIGCONT = getattr(signal, "SIGCONT", None)

def _signal_workers(processes, sig: int | None) -> None:
    if sig is None:
        return
    for process in processes:
        if process.pid is None:
            continue
        try:
            os.kill(process.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            continue

def _terminate_process_tree(process: mp.process.BaseProcess) -> None:
    try:
        parent = psutil.Process(process.pid)
        targets = parent.children(recursive=True) + [parent]
    except (psutil.Error, OSError):
        targets = []
        try:
            process.terminate()
        except Exception:
            pass
        return

    for target in targets:
        try:
            target.terminate()
        except (psutil.Error, OSError):
            pass
    for target in targets:
        try:
            target.wait(timeout=1)
        except (psutil.Error, OSError):
            pass
    for target in targets:
        try:
            if target.is_running():
                target.kill()
        except (psutil.Error, OSError):
            pass

def _verify(binary_path: Path, key: str, mode: str, limits: RunnerLimits,
            attempts: int = 3, steps: list[str] | None = None) -> bool:
    for _ in range(max(1, attempts)):
        if _verify_once(binary_path, key, mode, limits, steps=steps):
            return True
    return False

_VERIFY_TIMEOUT_SECONDS = 10.0

def _verify_once(binary_path: Path, key: str, mode: str, limits: RunnerLimits,
                 steps: list[str] | None = None) -> bool:
    from dataclasses import replace

    from xsolver.core.verify import isolated_success

    limits = replace(limits, timeout_seconds=max(limits.timeout_seconds, _VERIFY_TIMEOUT_SECONDS))
    baseline = run_on_target(binary_path, argv=[], limits=limits)
    detector = default_success_detector(baseline, _negative_samples_cached(binary_path, limits))

    if steps:
        prefix = list(steps[:-1])

        def replay(text: str):
            payload = ("\n".join(prefix + [text]) + "\n").encode("latin-1", "replace")
            return run_on_target(binary_path, stdin_data=payload, limits=limits)

        result = replay(steps[-1])
        if not detector(result):
            return False
        return isolated_success(replay, steps[-1], result)

    if mode.startswith("file:"):
        name = mode.split(":", 1)[1]
        chosen = None
        for tail in ("", "\n", "\r\n"):
            feed = lambda text, tail=tail: run_on_target(
                binary_path, stdin_data=b"", limits=limits,
                side_files={name: (text + tail).encode("latin-1", "replace")})
            candidate_result = feed(key)
            if detector(candidate_result):
                chosen = (tail, candidate_result)
                break
        if chosen is None:
            return False
        tail, result = chosen
        return isolated_success(
            lambda text: run_on_target(binary_path, stdin_data=b"", limits=limits,
                                       side_files={name: (text + tail).encode("latin-1", "replace")}),
            key, result)

    def run(text: str):
        from xsolver.core.modes import argv_for, payload_for

        argv = argv_for(mode, text)
        if argv is not None:
            return run_on_target(binary_path, argv=argv, limits=limits)
        return run_on_target(binary_path, stdin_data=payload_for(mode, text), limits=limits)

    result = run(key)
    if not detector(result):
        return False
    return isolated_success(run, key, result)
