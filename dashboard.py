# dashboard.py
# AutoShield Live Threat Intelligence Dashboard

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime
import json

# ── PAGE CONFIG ───────────────────────────────────────────────
st.set_page_config(
    page_title="AutoShield Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── STYLING ───────────────────────────────────────────────────
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: #1e2130;
        border-radius: 10px;
        padding: 20px;
        border-left: 4px solid #e74c3c;
    }
    .stMetric label { color: #aaaaaa !important; }
    </style>
""", unsafe_allow_html=True)

# ── DATA LOADING ──────────────────────────────────────────────
@st.cache_data(ttl=60)  # refresh every 60 seconds
def load_data():
    """Load the latest processed threat data."""
    parquet_path = Path("data/processed/threats_latest.parquet")
    if not parquet_path.exists():
        return pd.DataFrame()
    df = pd.read_parquet(parquet_path)
    return df

@st.cache_data(ttl=60)
def load_run_history():
    """Load pipeline run history."""
    history_path = Path("logs/run_history.json")
    if not history_path.exists():
        return []
    with open(history_path) as f:
        return json.load(f)

@st.cache_data(ttl=60)
def load_alerts():
    """Load recent alerts."""
    alert_path = Path("logs/alerts.jsonl")
    if not alert_path.exists():
        return []
    alerts = []
    with open(alert_path) as f:
        for line in f.readlines()[-50:]:  # last 50 alerts
            try:
                alerts.append(json.loads(line.strip()))
            except Exception:
                pass
    return alerts

# ── SIDEBAR ───────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=80)
    st.title("AutoShield")
    st.caption("Adaptive Threat Intelligence Pipeline")
    st.divider()

    st.subheader("⚙️ Controls")
    auto_refresh = st.toggle("Auto Refresh (60s)", value=True)
    if st.button("🔄 Refresh Now"):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.subheader("🔍 Filters")
    severity_filter = st.multiselect(
        "Severity",
        ["critical", "high", "medium", "low", "info"],
        default=["critical", "high", "medium", "low", "info"]
    )
    source_filter = st.multiselect(
        "Source",
        ["abuseipdb", "otx", "virustotal", "nvd"],
        default=["abuseipdb", "otx", "virustotal", "nvd"]
    )

    st.divider()
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

# ── LOAD DATA ─────────────────────────────────────────────────
df = load_data()
history = load_run_history()
alerts = load_alerts()

# ── HEADER ────────────────────────────────────────────────────
st.title("🛡️ AutoShield — Threat Intelligence Dashboard")
st.caption("Real-time cybersecurity threat monitoring powered by Kafka + Python")
st.divider()

if df.empty:
    st.error("No data found. Make sure the pipeline has run at least once.")
    st.info("Run: `python pipeline.py` or `python streaming/kafka_pipeline.py --run-once`")
    st.stop()

# Apply filters
filtered_df = df[
    df["severity"].isin(severity_filter) &
    df["source"].isin(source_filter)
]

# ── KPI METRICS ───────────────────────────────────────────────
st.subheader("📊 Overview")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "Total Threats",
        f"{len(filtered_df):,}",
        delta=f"{len(filtered_df) - len(df)} filtered"
    )

with col2:
    critical = len(filtered_df[filtered_df["severity"] == "critical"])
    st.metric("🔴 Critical", f"{critical:,}")

with col3:
    high = len(filtered_df[filtered_df["severity"] == "high"])
    st.metric("🟠 High", f"{high:,}")

with col4:
    avg_score = round(filtered_df["severity_score"].mean(), 2) if not filtered_df.empty else 0
    st.metric("Avg Score", f"{avg_score}/10")

with col5:
    sources = filtered_df["source"].nunique()
    st.metric("Active Sources", f"{sources}/4")

st.divider()

# ── CHARTS ROW 1 ──────────────────────────────────────────────
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("🎯 Threats by Severity")
    severity_counts = filtered_df["severity"].value_counts().reset_index()
    severity_counts.columns = ["severity", "count"]

    color_map = {
        "critical": "#e74c3c",
        "high":     "#e67e22",
        "medium":   "#f1c40f",
        "low":      "#2ecc71",
        "info":     "#3498db"
    }

    fig = px.pie(
        severity_counts,
        values="count",
        names="severity",
        color="severity",
        color_discrete_map=color_map,
        hole=0.4
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        legend=dict(font=dict(color="white"))
    )
    st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.subheader("📡 Threats by Source")
    source_counts = filtered_df["source"].value_counts().reset_index()
    source_counts.columns = ["source", "count"]

    fig2 = px.bar(
        source_counts,
        x="source",
        y="count",
        color="source",
        color_discrete_sequence=["#e74c3c", "#3498db", "#2ecc71", "#f39c12"],
        text="count"
    )
    fig2.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        showlegend=False,
        xaxis=dict(color="white"),
        yaxis=dict(color="white")
    )
    st.plotly_chart(fig2, use_container_width=True)

# ── CHARTS ROW 2 ──────────────────────────────────────────────
col_left2, col_right2 = st.columns(2)

with col_left2:
    st.subheader("⚠️ Threats by Type")
    type_counts = filtered_df["threat_type"].value_counts().reset_index()
    type_counts.columns = ["threat_type", "count"]

    fig3 = px.bar(
        type_counts,
        x="count",
        y="threat_type",
        orientation="h",
        color="count",
        color_continuous_scale="Reds",
        text="count"
    )
    fig3.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        xaxis=dict(color="white"),
        yaxis=dict(color="white"),
        coloraxis_showscale=False
    )
    st.plotly_chart(fig3, use_container_width=True)

with col_right2:
    st.subheader("🌍 Top 10 Countries")
    country_counts = filtered_df[filtered_df["country"] != ""]["country"].value_counts().head(10).reset_index()
    country_counts.columns = ["country", "count"]

    fig4 = px.bar(
        country_counts,
        x="country",
        y="count",
        color="count",
        color_continuous_scale="Oranges",
        text="count"
    )
    fig4.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        xaxis=dict(color="white"),
        yaxis=dict(color="white"),
        coloraxis_showscale=False
    )
    st.plotly_chart(fig4, use_container_width=True)

st.divider()

# ── ALERTS FEED ───────────────────────────────────────────────
st.subheader("🚨 Recent Alerts")

if alerts:
    alert_df = pd.DataFrame(alerts[-20:])
    alert_df = alert_df[["severity", "indicator_type", "indicator_value", "severity_score", "alert_timestamp"]].copy()
    alert_df = alert_df.sort_values("alert_timestamp", ascending=False)

    def color_severity(val):
        colors = {
            "critical": "background-color: #e74c3c; color: white",
            "high":     "background-color: #e67e22; color: white",
            "medium":   "background-color: #f1c40f; color: black",
        }
        return colors.get(val, "")

    st.dataframe(
        alert_df.style.applymap(color_severity, subset=["severity"]),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No alerts yet — run the pipeline to generate alerts.")

st.divider()

# ── LIVE THREAT TABLE ─────────────────────────────────────────
st.subheader("📋 Live Threat Records")

col_search, col_type = st.columns([3, 1])
with col_search:
    search = st.text_input("🔍 Search indicator", placeholder="e.g. CVE-2024, 192.168...")
with col_type:
    ind_type = st.selectbox("Indicator Type", ["all", "ip", "cve", "domain", "url", "file_hash"])

display_df = filtered_df.copy()
if search:
    display_df = display_df[display_df["indicator_value"].str.contains(search, case=False, na=False)]
if ind_type != "all":
    display_df = display_df[display_df["indicator_type"] == ind_type]

st.dataframe(
    display_df[[
        "source", "indicator_type", "indicator_value",
        "threat_type", "severity", "severity_score", "country", "last_seen"
    ]].head(100),
    use_container_width=True,
    hide_index=True
)

st.caption(f"Showing {min(100, len(display_df))} of {len(display_df)} records")

st.divider()

# ── PIPELINE RUN HISTORY ──────────────────────────────────────
st.subheader("⏱️ Pipeline Run History")

if history:
    history_df = pd.DataFrame(history[-10:])
    history_df = history_df[["run_start", "duration_seconds", "status"]].copy()
    history_df["run_start"] = pd.to_datetime(history_df["run_start"]).dt.strftime("%Y-%m-%d %H:%M")
    history_df.columns = ["Run Time", "Duration (s)", "Status"]
    history_df = history_df.sort_values("Run Time", ascending=False)
    st.dataframe(history_df, use_container_width=True, hide_index=True)
else:
    st.info("No run history yet.")

# ── AUTO REFRESH ──────────────────────────────────────────────
if auto_refresh:
    import time
    time.sleep(60)
    st.rerun()