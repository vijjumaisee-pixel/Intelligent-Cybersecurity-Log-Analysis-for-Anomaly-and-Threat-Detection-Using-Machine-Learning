import streamlit as st
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns
import folium
from streamlit_folium import st_folium

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Cyber AI Agent PRO", layout="wide")
st.title("🛡️ Cybersecurity Log Analysis Platform")
st.markdown("Upload multiple logs • Analyze • Switch between reports")

# ---------------- MODEL ----------------
model = IsolationForest(contamination=0.2)
model.fit([[1],[2],[3],[10],[20],[30]])

# ---------------- SESSION STORAGE ----------------
if "datasets" not in st.session_state:
    st.session_state.datasets = {}

if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = set()

# ---------------- PARSE LOG ----------------
def parse_logs(file):
    logs = []
    for line in file:
        line = line.decode("utf-8")
        ip_match = re.findall(r'\d+\.\d+\.\d+\.\d+', line)

        if ip_match:
            logs.append({
                "ip": ip_match[0],
                "attempts": np.random.randint(1,30),
                "latitude": np.random.uniform(10,30),
                "longitude": np.random.uniform(70,90)
            })
    return pd.DataFrame(logs)

# ---------------- DETECTION ----------------
def detect(df):
    results = []
    for _, row in df.iterrows():
        attempts = row["attempts"]
        pred = model.predict([[attempts]])[0]

        if attempts > 20:
            attack, severity = "Brute Force", "High"
        elif pred == -1:
            attack, severity = "Anomaly", "Medium"
        elif attempts > 10:
            attack, severity = "Suspicious", "Low"
        else:
            attack, severity = "Normal", "Safe"

        results.append((attack, severity))

    df["attack"], df["severity"] = zip(*results)
    return df

# ---------------- BLOCK FUNCTIONS ----------------
def auto_block(df):
    for _, r in df.iterrows():
        if r["severity"] == "High":
            st.session_state.blocked_ips.add(r["ip"])

def manual_block(ip):
    st.session_state.blocked_ips.add(ip)

def unblock(ip):
    if ip in st.session_state.blocked_ips:
        st.session_state.blocked_ips.remove(ip)

# ---------------- UPLOAD ----------------
uploaded = st.sidebar.file_uploader("📂 Upload Log File", type=["txt","log"])

if uploaded:
    filename = uploaded.name

    if st.sidebar.button("Analyze & Save"):
        df = parse_logs(uploaded)
        df = detect(df)

        # AUTO BLOCK HIGH THREATS
        auto_block(df)

        st.session_state.datasets[filename] = df
        st.success(f"{filename} analyzed & saved!")

# ---------------- SELECT DATASET ----------------
if st.session_state.datasets:
    selected_file = st.sidebar.selectbox(
        "📁 Select Log File",
        list(st.session_state.datasets.keys())
    )

    df = st.session_state.datasets[selected_file]

    # ADD BLOCK STATUS COLUMN
    df["blocked"] = df["ip"].apply(lambda x: "🚫 BLOCKED" if x in st.session_state.blocked_ips else "✅ ALLOWED")

    # ---------------- TABS ----------------
    tabs = st.tabs(["📊 Dashboard","📡 Logs","🌍 Map","🧩 Protection"])

    # ---------------- DASHBOARD ----------------
    with tabs[0]:
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("Logs", len(df))
        c2.metric("Blocked IPs", len(st.session_state.blocked_ips))
        c3.metric("High Threats", len(df[df["severity"]=="High"]))
        c4.metric("Safe", len(df[df["severity"]=="Safe"]))

        st.bar_chart(df["severity"].value_counts())

        st.subheader("🔥 Heatmap")
        pivot = df.pivot_table(values="attempts", index="severity", aggfunc="mean")
        fig, ax = plt.subplots()
        sns.heatmap(pivot, annot=True, cmap="Reds", ax=ax)
        st.pyplot(fig)

    # ---------------- LOGS ----------------
    with tabs[1]:
        st.subheader("📡 Logs with Actions")

        for i, row in df.iterrows():
            col1, col2, col3, col4, col5 = st.columns([2,1,1,1,1])

            col1.write(row["ip"])
            col2.write(row["attack"])
            col3.write(row["severity"])
            col4.write(row["blocked"])

            if row["ip"] not in st.session_state.blocked_ips:
                if col5.button("Block", key=f"block_{i}"):
                    manual_block(row["ip"])
                    st.rerun()
            else:
                if col5.button("Unblock", key=f"unblock_{i}"):
                    unblock(row["ip"])
                    st.rerun()

    # ---------------- MAP ----------------
    with tabs[2]:
        m = folium.Map(location=[20,78], zoom_start=4)

        for _, r in df.iterrows():
            color = "green"
            if r["ip"] in st.session_state.blocked_ips:
                color = "red"
            elif r["severity"]=="Medium":
                color="orange"

            folium.CircleMarker(
                location=[r["latitude"], r["longitude"]],
                radius=7,
                popup=f"{r['ip']} - {r['attack']}",
                color=color,
                fill=True
            ).add_to(m)

        st_folium(m, width=900, height=400)

    # ---------------- PROTECTION ----------------
    with tabs[3]:
        st.subheader("🧩 Blocked IP Manager")

        st.write("🚫 Blocked IPs:")
        st.write(list(st.session_state.blocked_ips))

        ip = st.text_input("Enter IP to unblock")

        if st.button("Unblock IP"):
            unblock(ip)
            st.success("IP Unblocked")

else:
    st.info("👆 Upload and analyze a log file to begin")