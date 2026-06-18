from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.utils import load_yaml_safe, read_csv_safe, safe_fillna_text, to_datetime_series


ALERT_COLUMNS = [
    "alert_id",
    "event_time",
    "src_ip",
    "dst_ip",
    "asset_name",
    "business_level",
    "log_source",
    "attack_type",
    "rule_id",
    "rule_name",
    "matched_field",
    "matched_value",
    "severity",
    "evidence",
    "recommendation",
    "raw_message",
]


def _build_alert_row(
    row: pd.Series,
    rule: dict[str, object],
    matched_field: str,
    matched_value: str,
    evidence: str,
) -> dict[str, object]:
    return {
        "event_time": row.get("event_time"),
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "asset_name": row.get("asset_name"),
        "business_level": row.get("business_level"),
        "log_source": row.get("log_source"),
        "attack_type": rule["attack_type"],
        "rule_id": rule["rule_id"],
        "rule_name": rule["name"],
        "matched_field": matched_field,
        "matched_value": matched_value,
        "severity": rule["severity"],
        "evidence": evidence,
        "recommendation": rule["recommendation"],
        "raw_message": row.get("raw_message"),
    }


def _keyword_match_alerts(events_df: pd.DataFrame, rules: list[dict[str, object]]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    for rule in rules:
        keywords = [str(keyword).lower() for keyword in rule.get("keywords", [])]
        match_fields = rule.get("match_fields", [])
        if not keywords or not match_fields:
            continue
        for _, row in events_df.iterrows():
            for field in match_fields:
                field_value = str(row.get(field, "") or "")
                lowered = field_value.lower()
                matched_keyword = next((keyword for keyword in keywords if keyword in lowered), None)
                if matched_keyword:
                    evidence = (
                        f"字段 {field} 命中关键字 '{matched_keyword}'；"
                        f"请求状态码={row.get('status_code', '')}；"
                        f"User-Agent={row.get('user_agent', '')}"
                    )
                    alerts.append(_build_alert_row(row, rule, field, field_value, evidence))
                    break
    return alerts


def _rolling_count_flags(group: pd.DataFrame, time_col: str, window: str) -> pd.Series:
    indexed = group.set_index(time_col)
    flags = indexed.assign(counter=1)["counter"].rolling(window).sum()
    return flags.reindex(indexed.index).fillna(0).astype(int)


def _apply_window_count(target_df: pd.DataFrame, window: str) -> pd.DataFrame:
    counted = target_df.copy()
    counted["window_count"] = 0
    for _, group in counted.groupby("src_ip"):
        counts = _rolling_count_flags(group, "event_time", window)
        counted.loc[group.index, "window_count"] = counts.to_numpy()
    return counted


def _frequency_rule_alerts(events_df: pd.DataFrame, rule: dict[str, object]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    if rule["rule_id"] == "AUTH-001":
        target_df = events_df[
            (events_df["log_source"] == "auth_log") & (safe_fillna_text(events_df["auth_result"]).str.lower() == "failed")
        ].copy()
        if target_df.empty:
            return alerts
        target_df = target_df.sort_values(["src_ip", "event_time"])
        target_df = _apply_window_count(target_df, "5min")
        matched = target_df[target_df["window_count"] >= 10]
        for _, row in matched.iterrows():
            evidence = f"同一源 IP 在 5 分钟内失败登录次数={int(row['window_count'])}；用户名={row.get('username', '')}"
            alerts.append(_build_alert_row(row, rule, "auth_result", str(row.get("auth_result", "")), evidence))
    elif rule["rule_id"] == "WEB-005":
        target_df = events_df[
            (events_df["log_source"] == "access_log") & (pd.to_numeric(events_df["status_code"], errors="coerce") == 404)
        ].copy()
        if target_df.empty:
            return alerts
        target_df = target_df.sort_values(["src_ip", "event_time"])
        target_df = _apply_window_count(target_df, "5min")
        matched = target_df[target_df["window_count"] >= 20]
        for _, row in matched.iterrows():
            evidence = (
                f"同一源 IP 在 5 分钟内产生 404 次数={int(row['window_count'])}；"
                f"URI={row.get('request_uri', '')}"
            )
            alerts.append(_build_alert_row(row, rule, "status_code", str(row.get("status_code", "")), evidence))
    return alerts


def _ids_rule_alerts(events_df: pd.DataFrame, rule: dict[str, object]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    target_df = events_df[
        (events_df["log_source"] == "suricata_eve")
        & (pd.to_numeric(events_df["severity"], errors="coerce") <= 2)
    ].copy()
    for _, row in target_df.iterrows():
        evidence = (
            f"Suricata 高危告警；signature={row.get('signature', '')}；"
            f"severity={row.get('severity', '')}；proto={row.get('proto', '')}"
        )
        alerts.append(_build_alert_row(row, rule, "severity", str(row.get("severity", "")), evidence))
    return alerts


def run_detection(normalized_path: Path, rules_path: Path) -> pd.DataFrame:
    events_df = read_csv_safe(normalized_path)
    events_df["event_time"] = to_datetime_series(events_df["event_time"])
    rules = load_yaml_safe(rules_path).get("rules", [])

    keyword_rules = [rule for rule in rules if rule.get("keywords")]
    frequency_rules = [rule for rule in rules if rule.get("rule_id") in {"AUTH-001", "WEB-005"}]
    ids_rules = [rule for rule in rules if rule.get("rule_id") == "IDS-001"]

    alerts = []
    alerts.extend(_keyword_match_alerts(events_df, keyword_rules))
    for rule in frequency_rules:
        alerts.extend(_frequency_rule_alerts(events_df, rule))
    for rule in ids_rules:
        alerts.extend(_ids_rule_alerts(events_df, rule))

    alerts_df = pd.DataFrame(alerts)
    if alerts_df.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    alerts_df = alerts_df.sort_values(["event_time", "rule_id", "src_ip"]).reset_index(drop=True)
    alerts_df.insert(0, "alert_id", [f"ALT-{index:06d}" for index in range(1, len(alerts_df) + 1)])
    return alerts_df[ALERT_COLUMNS]
