from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.utils import read_csv_safe, to_datetime_series


DISPOSITION_MAP = {
    "SQL Injection Probe": "疑似 SQL 注入探测，需检查数据库错误日志和参数过滤。",
    "XSS Probe": "疑似 XSS 探测，需检查输入过滤和输出编码。",
    "Sensitive File Scan": "疑似敏感文件探测，需检查 Web 根目录是否存在敏感文件。",
    "File Upload Probe": "疑似文件上传攻击探测，需检查上传目录和 WebShell 风险。",
    "Brute Force Login": "疑似弱口令爆破，需检查账号登录失败记录和异常源 IP。",
    "Directory Brute Force": "疑似目录扫描，需检查敏感路径暴露情况。",
    "IDS Alert": "IDS 高危告警，需结合日志进一步确认攻击是否成功。",
    "Automated Scanner": "疑似自动化扫描行为，需结合访问频率和命中路径进一步确认。",
}

RISK_LEVEL_ORDER = {"低危": 1, "中危": 2, "高危": 3, "严重": 4}


def aggregate_incidents(risk_path: Path, alerts_path: Path) -> pd.DataFrame:
    risk_df = read_csv_safe(risk_path)
    alerts_df = read_csv_safe(alerts_path)
    if risk_df.empty:
        return pd.DataFrame(
            columns=[
                "incident_id",
                "first_seen",
                "last_seen",
                "src_ip",
                "dst_ip",
                "asset_name",
                "attack_type",
                "alert_count",
                "rule_ids",
                "max_risk_score",
                "risk_level",
                "evidence_summary",
                "disposition",
                "recommendation",
            ]
        )

    merged = risk_df.merge(
        alerts_df[["alert_id", "raw_message"]],
        on="alert_id",
        how="left",
    )
    merged["event_time"] = to_datetime_series(merged["event_time"])
    merged["time_bucket"] = merged["event_time"].dt.floor("10min")

    grouped_rows: list[dict[str, object]] = []
    group_columns = ["src_ip", "dst_ip", "asset_name", "attack_type", "time_bucket"]
    for _, group in merged.sort_values("event_time").groupby(group_columns):
        highest_level = max(group["risk_level"], key=lambda level: RISK_LEVEL_ORDER.get(level, 0))
        attack_type = group["attack_type"].iloc[0]
        evidence_values = [str(item) for item in group["evidence"].dropna().unique().tolist()[:3]]
        recommendation_values = [str(item) for item in group["recommendation"].dropna().unique().tolist()]
        grouped_rows.append(
            {
                "first_seen": group["event_time"].min(),
                "last_seen": group["event_time"].max(),
                "src_ip": group["src_ip"].iloc[0],
                "dst_ip": group["dst_ip"].iloc[0],
                "asset_name": group["asset_name"].iloc[0],
                "attack_type": attack_type,
                "alert_count": int(len(group)),
                "rule_ids": ",".join(sorted(group["rule_id"].astype(str).unique().tolist())),
                "max_risk_score": int(group["risk_score"].max()),
                "risk_level": highest_level,
                "evidence_summary": " | ".join(evidence_values),
                "disposition": DISPOSITION_MAP.get(attack_type, "需进一步研判事件影响。"),
                "recommendation": "；".join(recommendation_values[:3]),
            }
        )

    incidents_df = pd.DataFrame(grouped_rows).sort_values(["max_risk_score", "first_seen"], ascending=[False, True])
    incidents_df.insert(0, "incident_id", [f"INC-{index:06d}" for index in range(1, len(incidents_df) + 1)])
    return incidents_df.reset_index(drop=True)
