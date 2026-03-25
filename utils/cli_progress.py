from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass


def _progress_enabled() -> bool:
    value = os.getenv("SECUREMAIL_NO_PROGRESS", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return False
    return True


@dataclass
class ProgressBar:
    total: int
    label: str = "Progress"
    width: int = 28

    def __post_init__(self) -> None:
        self.total = max(1, int(self.total))
        self.current = 0
        self._enabled = _progress_enabled()
        self._last_render = 0.0
        self._render(force=True)

    def update(self, value: int = 1, force: bool = False) -> None:
        if not self._enabled:
            return
        self.current = max(0, min(self.total, self.current + int(value)))
        self._render(force=force)

    def done(self, suffix: str = "done") -> None:
        if not self._enabled:
            return
        self.current = self.total
        self._render(force=True, suffix=suffix)
        sys.stdout.write("\n")
        sys.stdout.flush()

    def _render(self, force: bool = False, suffix: str = "") -> None:
        if not self._enabled:
            return
        now = time.monotonic()
        if not force and now - self._last_render < 0.06:
            return
        self._last_render = now
        ratio = self.current / self.total
        filled = int(self.width * ratio)
        bar = "#" * filled + "-" * (self.width - filled)
        percent = int(ratio * 100)
        tail = f" | {suffix}" if suffix else ""
        sys.stdout.write(f"\r{self.label}: [{bar}] {percent:3d}% ({self.current}/{self.total}){tail}")
        sys.stdout.flush()


@dataclass
class StepProgress:
    total_steps: int
    label: str = "Steps"

    def __post_init__(self) -> None:
        self.total_steps = max(1, int(self.total_steps))
        self.current = 0
        self._enabled = _progress_enabled()

    def next(self, message: str) -> None:
        self.current = min(self.total_steps, self.current + 1)
        if not self._enabled:
            return
        print(f"[{self.current}/{self.total_steps}] {self.label}: {message}")

    def done(self, message: str = "complete") -> None:
        if not self._enabled:
            return
        print(f"[{self.total_steps}/{self.total_steps}] {self.label}: {message}")
