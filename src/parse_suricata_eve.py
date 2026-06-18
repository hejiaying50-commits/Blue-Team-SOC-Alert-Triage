from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.utils import require_file_exists, to_datetime_series


def parse_suricata_eve(path: Path) -> pd.DataFrame:
    require_file_exists(path)
    records: list[dict[str, object]] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            raw_message = line.strip()
            if not raw_message:
                continue
            item = json.loads(raw_message)
            alert_info = item.get("alert", {})
            records.append(
                {
                    "event_time": item.get("timestamp"),
                    "src_ip": item.get("src_ip"),
                    "dst_ip": item.get("dest_ip"),
                    "log_source": "suricata_eve",
                    "event_type": item.get("event_type"),
                    "signature": alert_info.get("signature"),
                    "severity": alert_info.get("severity"),
                    "proto": item.get("proto"),
                    "raw_message": raw_message,
                }
            )

    df = pd.DataFrame(records)
    if df.empty:
        return pd.DataFrame(
            columns=[
                "event_time",
                "src_ip",
                "dst_ip",
                "log_source",
                "event_type",
                "signature",
                "severity",
                "proto",
                "raw_message",
            ]
        )
    df["event_time"] = to_datetime_series(df["event_time"])
    return df
