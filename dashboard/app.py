from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


@st.cache_data
def load_data() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    incident_path = PROCESSED_DIR / "incident_summary.csv"
    risk_path = PROCESSED_DIR / "risk_scored_events.csv"
    normalized_path = PROCESSED_DIR / "normalized_events.csv"

    if not incident_path.exists() or not risk_path.exists():
        raise FileNotFoundError("缺少处理结果文件，请先运行 python run_pipeline.py")

    incidents_df = pd.read_csv(incident_path, encoding="utf-8-sig")
    risk_df = pd.read_csv(risk_path, encoding="utf-8-sig")
    normalized_df = pd.read_csv(normalized_path, encoding="utf-8-sig") if normalized_path.exists() else pd.DataFrame()

    if "event_time" in risk_df.columns:
        risk_df["event_time"] = pd.to_datetime(risk_df["event_time"], errors="coerce")
    if "first_seen" in incidents_df.columns:
        incidents_df["first_seen"] = pd.to_datetime(incidents_df["first_seen"], errors="coerce")
    if "last_seen" in incidents_df.columns:
        incidents_df["last_seen"] = pd.to_datetime(incidents_df["last_seen"], errors="coerce")

    return incidents_df, risk_df, normalized_df


def render_metric_cards(log_count: int, alert_count: int, incident_count: int, high_risk_count: int, src_ip_count: int) -> None:
    columns = st.columns(5)
    metrics = [
        ("日志总量", log_count),
        ("告警总数", alert_count),
        ("安全事件总数", incident_count),
        ("高危/严重事件数", high_risk_count),
        ("攻击源 IP 数量", src_ip_count),
    ]
    for column, metric in zip(columns, metrics):
        with column:
            st.metric(metric[0], metric[1])


def main() -> None:
    st.set_page_config(
        page_title="蓝队 SOC 告警研判与 Web 攻击日志应急响应平台",
        layout="wide",
    )
    st.markdown(
        """
        <style>
        .main {
            background: linear-gradient(180deg, #f7fafc 0%, #eef3f8 100%);
        }
        .block-container {
            padding-top: 1.6rem;
            padding-bottom: 2rem;
        }
        h1, h2, h3 {
            color: #12344d;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.title("蓝队 SOC 告警研判与 Web 攻击日志应急响应平台")
    st.caption("模拟 SOC 值守场景下的轻量级告警研判、风险评分、事件聚合与安全态势展示")

    try:
        incidents_df, risk_df, normalized_df = load_data()
    except FileNotFoundError as error:
        st.error(str(error))
        return

    log_count = int(len(normalized_df)) if not normalized_df.empty else int(len(risk_df))
    alert_count = int(len(risk_df))
    incident_count = int(len(incidents_df))
    high_risk_count = int(incidents_df["risk_level"].isin(["高危", "严重"]).sum()) if not incidents_df.empty else 0
    src_ip_count = int(risk_df["src_ip"].nunique()) if not risk_df.empty else 0

    render_metric_cards(log_count, alert_count, incident_count, high_risk_count, src_ip_count)

    if risk_df.empty:
        st.warning("当前没有可展示的告警数据。")
        return

    risk_level_options = ["全部"] + sorted(risk_df["risk_level"].dropna().unique().tolist())
    attack_type_options = ["全部"] + sorted(risk_df["attack_type"].dropna().unique().tolist())
    src_ip_options = ["全部"] + sorted(risk_df["src_ip"].dropna().unique().tolist())

    with st.sidebar:
        st.header("事件过滤")
        selected_risk_level = st.selectbox("风险等级", risk_level_options)
        selected_attack_type = st.selectbox("攻击类型", attack_type_options)
        selected_src_ip = st.selectbox("源 IP", src_ip_options)

    filtered_df = risk_df.copy()
    if selected_risk_level != "全部":
        filtered_df = filtered_df[filtered_df["risk_level"] == selected_risk_level]
    if selected_attack_type != "全部":
        filtered_df = filtered_df[filtered_df["attack_type"] == selected_attack_type]
    if selected_src_ip != "全部":
        filtered_df = filtered_df[filtered_df["src_ip"] == selected_src_ip]

    attack_distribution = filtered_df["attack_type"].value_counts().rename_axis("attack_type").reset_index(name="count")
    risk_distribution = filtered_df["risk_level"].value_counts().rename_axis("risk_level").reset_index(name="count")
    top_src_ip = filtered_df["src_ip"].value_counts().head(10).rename_axis("src_ip").reset_index(name="count")
    top_asset = filtered_df["asset_name"].value_counts().head(10).rename_axis("asset_name").reset_index(name="count")
    trend_df = (
        filtered_df.assign(time_bucket=filtered_df["event_time"].dt.floor("1h"))
        .groupby("time_bucket")
        .size()
        .reset_index(name="count")
    )

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.subheader("攻击类型分布")
        fig_attack = px.bar(
            attack_distribution,
            x="attack_type",
            y="count",
            color="attack_type",
            color_discrete_sequence=px.colors.sequential.Tealgrn,
        )
        fig_attack.update_layout(showlegend=False, xaxis_title="", yaxis_title="数量")
        st.plotly_chart(fig_attack, use_container_width=True)
    with chart_col2:
        st.subheader("风险等级分布")
        fig_risk = px.pie(
            risk_distribution,
            names="risk_level",
            values="count",
            color="risk_level",
            color_discrete_map={"低危": "#90cdf4", "中危": "#f6ad55", "高危": "#ed8936", "严重": "#e53e3e"},
        )
        st.plotly_chart(fig_risk, use_container_width=True)

    chart_col3, chart_col4 = st.columns(2)
    with chart_col3:
        st.subheader("Top 10 攻击源 IP")
        fig_src = px.bar(top_src_ip, x="src_ip", y="count", color="count", color_continuous_scale="Blues")
        fig_src.update_layout(xaxis_title="源 IP", yaxis_title="告警数", coloraxis_showscale=False)
        st.plotly_chart(fig_src, use_container_width=True)
    with chart_col4:
        st.subheader("Top 10 被攻击资产")
        fig_asset = px.bar(top_asset, x="asset_name", y="count", color="count", color_continuous_scale="Aggrnyl")
        fig_asset.update_layout(xaxis_title="资产", yaxis_title="告警数", coloraxis_showscale=False)
        st.plotly_chart(fig_asset, use_container_width=True)

    st.subheader("攻击事件时间趋势")
    fig_trend = px.line(trend_df, x="time_bucket", y="count", markers=True, color_discrete_sequence=["#0f766e"])
    fig_trend.update_layout(xaxis_title="时间", yaxis_title="告警数")
    st.plotly_chart(fig_trend, use_container_width=True)

    st.subheader("事件详情表")
    detail_columns = [
        "event_time",
        "risk_level",
        "risk_score",
        "attack_type",
        "src_ip",
        "dst_ip",
        "asset_name",
        "rule_id",
        "evidence",
        "recommendation",
    ]
    display_df = filtered_df[detail_columns].sort_values(["risk_score", "event_time"], ascending=[False, False])
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    if not incidents_df.empty:
        st.subheader("聚合事件概览")
        st.dataframe(
            incidents_df.sort_values(["max_risk_score", "first_seen"], ascending=[False, True]),
            use_container_width=True,
            hide_index=True,
        )


if __name__ == "__main__":
    main()
