"""Runtime-configurable detection thresholds.

A single :class:`Thresholds` instance is the source of truth for every
tunable in the detection / decision / alerting path. It can be replaced at
runtime (``PUT /api/v1/config/thresholds``) and is persisted to a JSON
file so operator tuning survives restarts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # Alerting
    alert_min_risk: float = Field(default=4.0, ge=0.0, le=10.0)
    dedupe_window_s: int = Field(default=60, ge=1, le=3600)

    # Severity cut points on the 0-10 risk scale
    sev_critical: float = Field(default=8.5, ge=0.0, le=10.0)
    sev_high: float = Field(default=6.5, ge=0.0, le=10.0)
    sev_medium: float = Field(default=4.0, ge=0.0, le=10.0)
    sev_low: float = Field(default=2.0, ge=0.0, le=10.0)

    # Decision tiers
    high_risk: float = Field(default=7.0, ge=0.0, le=10.0)
    low_risk: float = Field(default=3.0, ge=0.0, le=10.0)
    high_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    low_confidence: float = Field(default=0.40, ge=0.0, le=1.0)

    # Vector detectors
    port_scan_min_ports: int = Field(default=10, ge=2, le=1000)
    port_scan_seq: float = Field(default=0.7, ge=0.0, le=1.0)
    stuffing_min_users: int = Field(default=8, ge=2, le=1000)
    stuffing_fail_ratio: float = Field(default=0.8, ge=0.0, le=1.0)
    lowslow_min_ips: int = Field(default=5, ge=2, le=1000)
    lowslow_fail_ratio: float = Field(default=0.8, ge=0.0, le=1.0)
    lowslow_min_gap_s: float = Field(default=0.0, ge=0.0, le=3600.0)

    # Statistical baseline
    zscore_fire: float = Field(default=2.0, ge=0.0, le=10.0)
    zscore_max: float = Field(default=4.0, ge=0.1, le=20.0)
    baseline_warmup: int = Field(default=10, ge=1, le=10000)

    # Campaign clustering
    campaign_min_ips: int = Field(default=6, ge=2, le=10000)
    campaign_min_subnets: int = Field(default=3, ge=1, le=10000)
    campaign_min_fail_ratio: float = Field(default=0.5, ge=0.0, le=1.0)

    # Isolation forest
    if_contamination: float = Field(default=0.05, gt=0.0, le=0.5)
    if_retrain_s: int = Field(default=300, ge=10, le=86400)


_PATH: Path = Path("thresholds.json")
_current: Optional[Thresholds] = None


def _load_from_disk() -> Thresholds:
    if _PATH.exists():
        try:
            return Thresholds.model_validate(json.loads(_PATH.read_text()))
        except Exception:
            pass
    return Thresholds()


def get_thresholds() -> Thresholds:
    global _current
    if _current is None:
        _current = _load_from_disk()
    return _current


def set_thresholds(new: Thresholds) -> Thresholds:
    global _current
    _current = new
    _PATH.write_text(json.dumps(new.model_dump(), indent=2))
    return _current


def reset_thresholds() -> Thresholds:
    global _current
    _current = Thresholds()
    if _PATH.exists():
        _PATH.unlink()
    return _current


def configure_path(path: str) -> None:
    """Point persistence at ``path`` (called from app startup)."""
    global _PATH, _current
    _PATH = Path(path)
    _current = None
