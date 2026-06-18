from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORTS_DIR = PROJECT_ROOT / "reports"
RULES_DIR = PROJECT_ROOT / "rules"


def get_project_root() -> Path:
    return PROJECT_ROOT


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_parent_dirs(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def init_project_dirs() -> None:
    for directory in [
        PROJECT_ROOT / "data" / "raw",
        PROJECT_ROOT / "data" / "processed",
        PROJECT_ROOT / "reports",
        PROJECT_ROOT / "screenshots",
        PROJECT_ROOT / "dashboard",
        PROJECT_ROOT / "src",
        PROJECT_ROOT / "rules",
    ]:
        ensure_directory(directory)


def require_file_exists(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"缺少必要文件: {path}")
    return path


def write_csv_utf8sig(df: pd.DataFrame, path: Path) -> Path:
    ensure_parent_dirs(path)
    df.to_csv(path, index=False, encoding="utf-8-sig")
    return path


def read_csv_safe(path: Path, **kwargs: Any) -> pd.DataFrame:
    require_file_exists(path)
    return pd.read_csv(path, **kwargs)


def load_yaml_safe(path: Path) -> dict[str, Any]:
    require_file_exists(path)
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML 格式不正确: {path}")
    return data


def to_datetime_series(series: pd.Series) -> pd.Series:
    parsed = pd.to_datetime(series, errors="coerce")
    if getattr(parsed.dt, "tz", None) is not None:
        parsed = parsed.dt.tz_localize(None)
    return parsed


def safe_fillna_text(series: pd.Series, default: str = "") -> pd.Series:
    return series.fillna(default).astype(str)


def log_step(message: str) -> None:
    print(f"[INFO] {message}")
