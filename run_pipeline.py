from __future__ import annotations

from pathlib import Path

from src.detection_engine import run_detection
from src.generate_sample_data import generate_all_sample_data
from src.incident_aggregation import aggregate_incidents
from src.normalize_events import build_normalized_events
from src.parse_access_log import parse_access_log
from src.parse_auth_log import parse_auth_log
from src.parse_suricata_eve import parse_suricata_eve
from src.report_generator import generate_reports
from src.risk_score import score_alerts
from src.utils import PROCESSED_DIR, PROJECT_ROOT, RAW_DIR, REPORTS_DIR, RULES_DIR, init_project_dirs, log_step, write_csv_utf8sig


def main() -> None:
    init_project_dirs()
    log_step("开始生成本地模拟数据")
    generation_summary = generate_all_sample_data(PROJECT_ROOT)

    access_path = RAW_DIR / "access.log"
    auth_path = RAW_DIR / "auth.log"
    suricata_path = RAW_DIR / "suricata_eve.json"
    assets_path = RAW_DIR / "assets.csv"
    rules_path = RULES_DIR / "detection_rules.yaml"

    log_step("解析 access.log")
    access_df = parse_access_log(access_path)

    log_step("解析 auth.log")
    auth_df = parse_auth_log(auth_path)

    log_step("解析 suricata_eve.json")
    suricata_df = parse_suricata_eve(suricata_path)

    log_step("标准化三类日志事件")
    normalized_df = build_normalized_events(access_df, auth_df, suricata_df, assets_path)
    normalized_path = PROCESSED_DIR / "normalized_events.csv"
    write_csv_utf8sig(normalized_df, normalized_path)

    log_step("执行检测规则引擎")
    alerts_df = run_detection(normalized_path, rules_path)
    alerts_path = PROCESSED_DIR / "detected_alerts.csv"
    write_csv_utf8sig(alerts_df, alerts_path)

    log_step("执行风险评分")
    risk_df = score_alerts(alerts_path, normalized_path)
    risk_path = PROCESSED_DIR / "risk_scored_events.csv"
    write_csv_utf8sig(risk_df, risk_path)

    log_step("执行安全事件聚合")
    incident_df = aggregate_incidents(risk_path, alerts_path)
    incident_path = PROCESSED_DIR / "incident_summary.csv"
    write_csv_utf8sig(incident_df, incident_path)

    log_step("生成日报和单事件应急响应报告")
    report_paths = generate_reports(
        normalized_path=normalized_path,
        alerts_path=alerts_path,
        risk_path=risk_path,
        incident_path=incident_path,
        reports_dir=REPORTS_DIR,
    )

    high_risk_count = int(incident_df["risk_level"].isin(["高危", "严重"]).sum()) if not incident_df.empty else 0
    total_log_count = len(normalized_df)
    generated_log_count = generation_summary["access"]["count"] + generation_summary["auth"]["count"] + generation_summary["suricata"]["count"]

    print("\n=== Pipeline Finished ===")
    print(f"生成日志数量: {generated_log_count}（标准化事件总量: {total_log_count}）")
    print(f"检测到告警数量: {len(alerts_df)}")
    print(f"聚合事件数量: {len(incident_df)}")
    print(f"高危/严重事件数量: {high_risk_count}")
    print(f"报告路径: {report_paths['excel_path']} | {report_paths['markdown_path']}")
    print("仪表盘启动命令: streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
