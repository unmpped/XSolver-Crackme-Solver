from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from xsolver.strategies.base import Strategy

_STRATEGY_SPECS: list[tuple[str, str]] = [
    ("static-constant", "xsolver.strategies.static_constant:StaticConstantStrategy"),
    ("string-dictionary", "xsolver.strategies.string_dictionary:StringDictionaryStrategy"),
    ("unpacked-strings", "xsolver.strategies.unpacked_strings:UnpackedStringsStrategy"),
    ("cmp-interception", "xsolver.strategies.cmp_intercept:ComparisonInterceptionStrategy"),
    ("win-cmp-trace", "xsolver.strategies.win_compare:WindowsCompareTraceStrategy"),
    ("xor-strings", "xsolver.strategies.xor_strings:XorStringsStrategy"),
    ("timing-oracle", "xsolver.strategies.byte_oracle:TimingOracleStrategy"),
    ("instruction-count-oracle",
     "xsolver.strategies.instruction_oracle:InstructionCountOracleStrategy"),
    ("bounded-brute-force", "xsolver.strategies.brute_force:BruteForceStrategy"),
    ("symbolic-injection", "xsolver.strategies.symbolic_injection:SymbolicInjectionStrategy"),
    ("side-file", "xsolver.strategies.side_file:SideFileStrategy"),
    ("inline-synthesis", "xsolver.strategies.inline_synthesis:InlineSynthesisStrategy"),
    ("dialogue-probe", "xsolver.strategies.dialogue_probe:DialogueProbeStrategy"),
    ("maze-probe", "xsolver.strategies.maze_probe:MazeProbeStrategy"),
    ("gui-probe", "xsolver.strategies.gui_probe:GuiProbeStrategy"),
    ("vm-bytecode", "xsolver.strategies.vm_bytecode:VmBytecodeStrategy"),
    ("idiv-table", "xsolver.strategies.idiv_table:IdivTableStrategy"),
    ("const-fold", "xsolver.strategies.const_fold:ConstFoldStrategy"),
    ("xor-loop", "xsolver.strategies.xor_loop:XorLoopStrategy"),
    ("str-concat", "xsolver.strategies.str_concat:StrConcatStrategy"),
    ("int-cmp", "xsolver.strategies.int_cmp:IntCmpStrategy"),
    ("go-keystream", "xsolver.strategies.go_keystream:GoKeystreamStrategy"),
    ("runtime-random", "xsolver.strategies.runtime_random:RuntimeRandomStrategy"),
]

GUI_ONLY_STRATEGY = "gui-probe"

_CACHE: dict[str, type] = {}

def _load(spec: str) -> type:
    module_name, _, class_name = spec.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, class_name)

def available_names() -> list[str]:
    return [name for name, _ in _STRATEGY_SPECS]

def load_strategy(name: str) -> type:
    if name not in _CACHE:
        for candidate_name, spec in _STRATEGY_SPECS:
            if candidate_name == name:
                _CACHE[name] = _load(spec)
                break
        else:
            raise ValueError(f"Unknown strategy: {name}. Available: {available_names()}")
    return _CACHE[name]

def all_strategies() -> list[type]:
    return [load_strategy(name) for name, _spec in _STRATEGY_SPECS
            if name != GUI_ONLY_STRATEGY]

def resolve_strategies(names: list[str] | None) -> list[type]:
    if not names:
        return all_strategies()
    return [load_strategy(name) for name in names]
