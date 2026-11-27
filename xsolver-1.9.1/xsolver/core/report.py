from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

@dataclass
class StrategyAttempt:
    strategy: str
    candidates_tried: int
    duration_seconds: float
    outcome: str
    detail: str = ""

@dataclass
class SolveReport:
    target: str
    format: str
    arch: str
    file_size: int
    packer_suspected: bool
    status: str
    key_found: str | None
    winning_strategy: str | None
    input_mode: str | None
    total_duration_seconds: float
    attempts: list[StrategyAttempt] = field(default_factory=list)
    anti_debug_patches: list[str] = field(default_factory=list)
    steps: list[str] | None = None
    notes: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_json(self) -> str:
        data = asdict(self)
        return json.dumps(data, indent=2, ensure_ascii=False)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")
