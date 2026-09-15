"""Resolved runtime model aliases shared by legacy modules during migration."""

from __future__ import annotations

import sys
from pathlib import Path

from .config import load_orchestrator_config


def _application_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[1]


RUNTIME_ORCHESTRATOR_CONFIG = load_orchestrator_config(_application_base_dir())
VOICE_MODEL = RUNTIME_ORCHESTRATOR_CONFIG.models.voice.name
ROUTINE_MODEL = RUNTIME_ORCHESTRATOR_CONFIG.models.routine.name
PLANNER_MODEL = RUNTIME_ORCHESTRATOR_CONFIG.models.planner.name
REVIEWER_MODEL = RUNTIME_ORCHESTRATOR_CONFIG.models.reviewer.name
COMPUTER_USE_MODEL = RUNTIME_ORCHESTRATOR_CONFIG.models.computer_use.name
