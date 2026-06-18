from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from src.utils import require_file_exists, to_datetime_series


ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<src_ip>\S+) \S+ \S+ \[(?P<event_time>[^\]]+)\] '
    r'"(?P<request_method>[A-Z]+) (?P<request_uri>.*?) (?P<http_version>[^"]+)" '
    r"(?P<status_code>\d{3}) (?P<response_size>\S+) "
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" "(?P<dst_ip>[^"]+)"$'
)


def parse_access_log(path: Path) -> pd.DataFrame:
    require_file_exists(path)
    records: list[dict[str, object]] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            raw_message = line.strip()
            if not raw_message:
                continue
            match = ACCESS_LOG_PATTERN.match(raw_message)
            if not match:
                continue
            item = match.groupdict()
            records.append(
                {
                    "event_time": item["event_time"],
                    "src_ip": item["src_ip"],
                    "dst_ip": item["dst_ip"],
                    "log_source": "access_log",
                    "request_method": item["request_method"],
                    "request_uri": item["request_uri"],
                    "status_code": int(item["status_code"]),
                    "user_agent": item["user_agent"],
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
                "request_method",
                "request_uri",
                "status_code",
                "user_agent",
                "raw_message",
            ]
        )
    df["event_time"] = pd.to_datetime(df["event_time"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce").dt.tz_localize(None)
    return df
