from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.incident_aggregation import DISPOSITION_MAP, RISK_LEVEL_ORDER
from src.utils import read_csv_safe, require_file_exists, to_datetime_series


IMPACT_MAP = {
    "SQL Injection Probe": "该行为可能导致数据库信息泄露、认证绕过或远程命令执行，应重点关注数据库异常查询和报错信息。",
    "XSS Probe": "该行为可能用于窃取用户 Cookie、会话令牌或诱导前端执行恶意脚本，需关注受影响页面和响应内容。",
    "Sensitive File Scan": "该行为可能导致环境变量、代码仓库配置或备份文件泄露，进而被用于横向移动或进一步入侵。",
    "File Upload Probe": "该行为可能尝试投递 WebShell 或恶意脚本，一旦上传校验薄弱可能直接导致服务器失陷。",
    "Brute Force Login": "该行为可能导致弱口令账号被接管，进而造成后台访问、数据泄露或权限提升。",
    "Directory Brute Force": "该行为可能用于枚举后台入口、备份目录和调试接口，为后续利用做准备。",
    "IDS Alert": "该告警说明网络侧已观察到高风险攻击特征，需要结合主机和应用日志判断攻击是否成功。",
    "Automated Scanner": "该行为表明源端可能正在进行自动化信息收集和暴露面枚举，存在持续攻击前兆。",
}

ATTACK_PRIORITY = {
    "SQL Injection Probe": 8,
    "File Upload Probe": 7,
    "Brute Force Login": 6,
    "IDS Alert": 5,
    "XSS Probe": 4,
    "Directory Brute Force": 3,
    "Sensitive File Scan": 2,
    "Automated Scanner": 1,
}


def _level_rank(level: str) -> int:
    return RISK_LEVEL_ORDER.get(level, 0)


def generate_reports(
    normalized_path: Path,
    alerts_path: Path,
    risk_path: Path,
    incident_path: Path,
    reports_dir: Path,
) -> dict[str, Path]:
    for path in [normalized_path, alerts_path, risk_path, incident_path]:
        require_file_exists(path)

    normalized_df = read_csv_safe(normalized_path)
    alerts_df = read_csv_safe(alerts_path)
    risk_df = read_csv_safe(risk_path)
    incidents_df = read_csv_safe(incident_path)

    risk_df["event_time"] = to_datetime_series(risk_df["event_time"])
    incidents_df["first_seen"] = to_datetime_series(incidents_df["first_seen"])
    incidents_df["last_seen"] = to_datetime_series(incidents_df["last_seen"])

    summary_df = pd.DataFrame(
        [
            {"metric": "日志总量", "value": int(len(normalized_df))},
            {"metric": "告警总数", "value": int(len(alerts_df))},
            {"metric": "安全事件总数", "value": int(len(incidents_df))},
            {
                "metric": "高危/严重事件数",
                "value": int(incidents_df["risk_level"].isin(["高危", "严重"]).sum()) if not incidents_df.empty else 0,
            },
            {"metric": "攻击源 IP 数量", "value": int(risk_df["src_ip"].nunique()) if not risk_df.empty else 0},
            {"metric": "目标资产数量", "value": int(risk_df["asset_name"].nunique()) if not risk_df.empty else 0},
            {
                "metric": "最高风险事件",
                "value": incidents_df.iloc[0]["incident_id"] if not incidents_df.empty else "N/A",
            },
        ]
    )
    attack_distribution_df = risk_df["attack_type"].value_counts().rename_axis("attack_type").reset_index(name="count")
    risk_distribution_df = risk_df["risk_level"].value_counts().rename_axis("risk_level").reset_index(name="count")
    top_source_ip_df = risk_df["src_ip"].value_counts().head(10).rename_axis("src_ip").reset_index(name="count")
    top_target_asset_df = risk_df["asset_name"].value_counts().head(10).rename_axis("asset_name").reset_index(name="count")
    high_risk_incidents_df = incidents_df[incidents_df["risk_level"].isin(["高危", "严重"])]

    reports_dir.mkdir(parents=True, exist_ok=True)
    excel_path = reports_dir / "daily_security_report.xlsx"
    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        attack_distribution_df.to_excel(writer, sheet_name="Attack_Type_Distribution", index=False)
        risk_distribution_df.to_excel(writer, sheet_name="Risk_Level_Distribution", index=False)
        top_source_ip_df.to_excel(writer, sheet_name="Top_Source_IP", index=False)
        top_target_asset_df.to_excel(writer, sheet_name="Top_Target_Asset", index=False)
        high_risk_incidents_df.to_excel(writer, sheet_name="High_Risk_Incidents", index=False)
        incidents_df.to_excel(writer, sheet_name="Incident_Detail", index=False)

    markdown_path = reports_dir / "incident_report.md"
    if incidents_df.empty:
        markdown_path.write_text("# 安全事件应急响应报告\n\n当前未检测到安全事件。\n", encoding="utf-8")
        return {"excel_path": excel_path, "markdown_path": markdown_path}

    ranked_incidents = incidents_df.copy()
    ranked_incidents["rank_value"] = ranked_incidents["risk_level"].apply(_level_rank)
    ranked_incidents["attack_priority"] = ranked_incidents["attack_type"].map(ATTACK_PRIORITY).fillna(0)
    ranked_incidents = ranked_incidents.sort_values(
        ["rank_value", "max_risk_score", "attack_priority", "alert_count", "first_seen"],
        ascending=[False, False, False, False, True],
    )
    top_incident = ranked_incidents.iloc[0]
    asset_level = "unknown"
    asset_match = normalized_df[
        (normalized_df["asset_name"] == top_incident["asset_name"]) & (normalized_df["dst_ip"] == top_incident["dst_ip"])
    ]
    if not asset_match.empty:
        asset_level = str(asset_match["business_level"].iloc[0])

    alert_context_df = risk_df.merge(
        alerts_df[["alert_id", "log_source", "matched_value", "raw_message"]],
        on="alert_id",
        how="left",
    )
    incident_events = alert_context_df[
        (alert_context_df["src_ip"] == top_incident["src_ip"])
        & (alert_context_df["dst_ip"] == top_incident["dst_ip"])
        & (alert_context_df["asset_name"] == top_incident["asset_name"])
        & (alert_context_df["attack_type"] == top_incident["attack_type"])
        & (alert_context_df["event_time"] >= top_incident["first_seen"])
        & (alert_context_df["event_time"] <= top_incident["last_seen"])
    ].copy()

    sources = "、".join(sorted(incident_events["log_source"].dropna().unique().tolist())) or "未知日志源"
    evidence_lines = []
    for _, row in incident_events.head(6).iterrows():
        evidence_lines.append(
            f"- 规则 `{row['rule_id']}` 命中，时间 {row['event_time']}，证据：{row['evidence']}"
        )
    if not evidence_lines:
        evidence_lines.append(f"- 事件聚合证据：{top_incident['evidence_summary']}")

    report_text = f"""# 安全事件应急响应报告

## 一、事件概述

- 事件编号：{top_incident['incident_id']}
- 首次发现时间：{top_incident['first_seen']}
- 最后发现时间：{top_incident['last_seen']}
- 攻击源 IP：{top_incident['src_ip']}
- 目标资产：{top_incident['asset_name']}（{top_incident['dst_ip']}）
- 攻击类型：{top_incident['attack_type']}
- 风险等级：{top_incident['risk_level']}（最高分 {top_incident['max_risk_score']}）

## 二、告警来源

本次事件主要由 {sources} 触发，说明该行为已在应用访问、认证或 IDS 网络侧被观测到，具备较强的研判价值。

## 三、研判依据

{chr(10).join(evidence_lines)}
- 关联规则：{top_incident['rule_ids']}
- 目标资产等级：{asset_level}
- 处置建议摘要：{top_incident['recommendation']}

## 四、影响分析

{IMPACT_MAP.get(top_incident['attack_type'], '该事件可能对业务系统造成安全影响，需结合主机、网络和应用日志进一步排查。')}

## 五、处置建议

- {top_incident['recommendation']}
- 对源 IP {top_incident['src_ip']} 开展临时封禁、限速或访问控制。
- 核查目标资产 {top_incident['asset_name']} 的访问日志、应用日志和主机日志，确认是否存在成功利用迹象。

## 六、复盘与加固建议

- 完善日志集中化采集与告警闭环，确保 Web、认证、IDS 日志可以统一关联分析。
- 对高频异常访问启用访问控制、WAF 策略、目录暴露收敛与敏感文件清理。
- 针对登录场景启用登录限速、验证码、MFA 和异常 IP 风险拦截。
- 针对文件上传场景加强文件类型校验、上传目录隔离和恶意脚本检测。
- 定期复盘本次事件命中的规则与阈值，优化误报与漏报控制。
"""
    markdown_path.write_text(report_text, encoding="utf-8")
    return {"excel_path": excel_path, "markdown_path": markdown_path}
