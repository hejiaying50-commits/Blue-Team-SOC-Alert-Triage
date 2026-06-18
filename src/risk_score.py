from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.utils import read_csv_safe, to_datetime_series


ATTACK_BASE_SCORES = {
    "SQL Injection Probe": 40,
    "File Upload Probe": 40,
    "Brute Force Login": 40,
    "IDS Alert": 35,
    "XSS Probe": 25,
    "Directory Brute Force": 25,
    "Sensitive File Scan": 25,
    "Automated Scanner": 20,
}


def _risk_level(score: int) -> str:
    if score <= 29:
        return "低危"
    if score <= 59:
        return "中危"
    if score <= 79:
        return "高危"
    return "严重"


def score_alerts(alerts_path: Path, normalized_path: Path) -> pd.DataFrame:
    alerts_df = read_csv_safe(alerts_path)
    normalized_df = read_csv_safe(normalized_path)
    if alerts_df.empty:
        return pd.DataFrame(
            columns=[
                "alert_id",
                "event_time",
                "src_ip",
                "dst_ip",
                "asset_name",
                "attack_type",
                "rule_id",
                "risk_score",
                "risk_level",
                "evidence",
                "recommendation",
            ]
        )

    alerts_df["event_time"] = to_datetime_series(alerts_df["event_time"])
    normalized_df["event_time"] = to_datetime_series(normalized_df["event_time"])
    context_df = normalized_df.drop_duplicates(subset=["raw_message"])[
        ["raw_message", "exposure", "status_code", "user_agent"]
    ]
    merged = alerts_df.merge(context_df, on="raw_message", how="left")
    src_alert_counts = merged["src_ip"].value_counts()
    merged["src_ip_alert_count"] = merged["src_ip"].map(src_alert_counts).fillna(0).astype(int)

    def calculate_score(row: pd.Series) -> int:
        score = ATTACK_BASE_SCORES.get(row["attack_type"], 10)
        if row.get("business_level") == "core":
            score += 20
        elif row.get("business_level") == "high":
            score += 10
        if row.get("exposure") == "public":
            score += 10
        if pd.to_numeric(row.get("status_code"), errors="coerce") == 500:
            score += 15
        user_agent = str(row.get("user_agent", "") or "").lower()
        if any(keyword in user_agent for keyword in ["sqlmap", "nikto", "dirbuster"]):
            score += 20
        if int(row.get("src_ip_alert_count", 0)) > 10:
            score += 15
        return min(score, 100)

    merged["risk_score"] = merged.apply(calculate_score, axis=1)
    merged["risk_level"] = merged["risk_score"].apply(_risk_level)

    output_df = merged[
        [
            "alert_id",
            "event_time",
            "src_ip",
            "dst_ip",
            "asset_name",
            "attack_type",
            "rule_id",
            "risk_score",
            "risk_level",
            "evidence",
            "recommendation",
        ]
    ].sort_values(["risk_score", "event_time"], ascending=[False, True])
    return output_df.reset_index(drop=True)
