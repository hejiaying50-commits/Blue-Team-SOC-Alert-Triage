from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from src.utils import require_file_exists, to_datetime_series


AUTH_LOG_PATTERN = re.compile(
    r"^(?P<event_time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"src_ip=(?P<src_ip>\S+) dst_ip=(?P<dst_ip>\S+) "
    r"username=(?P<username>\S+) auth_result=(?P<auth_result>\S+)$"
)


def parse_auth_log(path: Path) -> pd.DataFrame:
    require_file_exists(path)
    records: list[dict[str, object]] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            raw_message = line.strip()
            if not raw_message:
                continue
            match = AUTH_LOG_PATTERN.match(raw_message)
            if not match:
                continue
            item = match.groupdict()
            records.append(
                {
                    "event_time": item["event_time"],
                    "src_ip": item["src_ip"],
                    "dst_ip": item["dst_ip"],
                    "log_source": "auth_log",
                    "username": item["username"],
                    "auth_result": item["auth_result"],
                    "raw_message": raw_message,
                }
            )

    df = pd.DataFrame(records)
    if df.empty:
        return pd.DataFrame(
            columns=["event_time", "src_ip", "dst_ip", "log_source", "username", "auth_result", "raw_message"]
        )
    df["event_time"] = to_datetime_series(df["event_time"])
    return df
