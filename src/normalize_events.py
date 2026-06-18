from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.utils import read_csv_safe, to_datetime_series


NORMALIZED_COLUMNS = [
    "event_time",
    "src_ip",
    "dst_ip",
    "asset_name",
    "business_level",
    "exposure",
    "log_source",
    "event_type",
    "request_method",
    "request_uri",
    "status_code",
    "user_agent",
    "username",
    "auth_result",
    "signature",
    "severity",
    "raw_message",
]


def _prepare_frame(df: pd.DataFrame, defaults: dict[str, object]) -> pd.DataFrame:
    prepared = df.copy()
    for column, value in defaults.items():
        if column not in prepared.columns:
            prepared[column] = value
    for column in NORMALIZED_COLUMNS:
        if column not in prepared.columns:
            prepared[column] = pd.NA
    return prepared[NORMALIZED_COLUMNS]


def build_normalized_events(
    access_df: pd.DataFrame,
    auth_df: pd.DataFrame,
    suricata_df: pd.DataFrame,
    assets_path: Path,
) -> pd.DataFrame:
    access_prepared = _prepare_frame(
        access_df,
        {
            "event_type": "web_request",
            "username": pd.NA,
            "auth_result": pd.NA,
            "signature": pd.NA,
            "severity": pd.NA,
        },
    )
    auth_prepared = _prepare_frame(
        auth_df,
        {
            "event_type": "authentication",
            "request_method": pd.NA,
            "request_uri": pd.NA,
            "status_code": pd.NA,
            "user_agent": pd.NA,
            "signature": pd.NA,
            "severity": pd.NA,
        },
    )
    suricata_prepared = _prepare_frame(
        suricata_df,
        {
            "request_method": pd.NA,
            "request_uri": pd.NA,
            "status_code": pd.NA,
            "user_agent": pd.NA,
            "username": pd.NA,
            "auth_result": pd.NA,
        },
    )
    assets_df = read_csv_safe(assets_path)
    assets_df = assets_df.rename(columns={"ip": "dst_ip"})
    assets_df = assets_df[["dst_ip", "asset_name", "business_level", "exposure"]].drop_duplicates()

    combined = pd.concat([access_prepared, auth_prepared, suricata_prepared], ignore_index=True)
    combined["event_time"] = to_datetime_series(combined["event_time"])
    combined = combined.drop(columns=["asset_name", "business_level", "exposure"], errors="ignore")
    combined = combined.merge(assets_df, on="dst_ip", how="left")
    combined["asset_name"] = combined["asset_name"].fillna("Unknown")
    combined["business_level"] = combined["business_level"].fillna("unknown")
    combined["exposure"] = combined["exposure"].fillna("unknown")
    combined = combined[NORMALIZED_COLUMNS].sort_values("event_time").reset_index(drop=True)
    return combined
