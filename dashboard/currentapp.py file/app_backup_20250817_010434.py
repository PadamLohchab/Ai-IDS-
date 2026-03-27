import streamlit as st
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
import altair as alt
import networkx as nx
import matplotlib.pyplot as plt
import time
import os

# ------------------- PROTOCOL MAPPING -------------------
PROTOCOL_MAP = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2,
    "HTTP": 3,
    "HTTPS": 4,
    "FTP": 5,
    "DNS": 6,
    "SSH": 7,
    "SMTP": 8,
    "SNMP": 9
}

# ------------------- MODEL LOADING -------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "../models/model.joblib")
model = joblib.load(model_path)

# ------------------- SESSION STATE -------------------
if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=[
        "time","src_ip","dest_ip","duration","bytes_in","bytes_out",
        "packets","protocol","result","probability","attack_type"
    ])
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'running' not in st.session_state:
    st.session_state.running = False

# ------------------- PAGE CONFIG -------------------
st.set_page_config(page_title="Futuristic AI-IDS", layout="wide")
st.title("🚀  AI-IDS Dashboard")

# ------------------- SIDEBAR -------------------
st.sidebar.title("Controls")
mode = st.sidebar.radio("Mode", ["Live Traffic", "CSV Upload", "Manual Entry", "Analytics", "Alert History"])
email_alert = st.sidebar.checkbox("Enable Email Alerts")
sms_alert = st.sidebar.checkbox("Enable SMS Alerts")
st.sidebar.markdown("---")

# ------------------- CLASSIFY FUNCTION -------------------
def classify_packet(packet):
    # Get protocol string
    if isinstance(packet, pd.Series):
        proto_str = packet["protocol"]
        duration = pd.to_numeric(packet.get("duration", 0), errors="coerce")
        bytes_in = pd.to_numeric(packet.get("bytes_in", 0), errors="coerce")
        bytes_out = pd.to_numeric(packet.get("bytes_out", 0), errors="coerce")
        packets_count = pd.to_numeric(packet.get("packets", 1), errors="coerce")
    else:
        proto_str = packet.get("protocol", "TCP")
        duration = packet.get("duration", 0)
        bytes_in = packet.get("bytes_in", 0)
        bytes_out = packet.get("bytes_out", 0)
        packets_count = packet.get("packets", 1)

    proto_num = PROTOCOL_MAP.get(proto_str, 0)

    features = pd.DataFrame([{
        "duration": duration,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "packets": packets_count,
        "protocol": proto_num
    }])

    prob = model.predict_proba(features)[0][1]
    result = int(prob > 0.5)

    attack_type = None
    if result == 1:
        if bytes_in > 1000:
            attack_type = "DoS"
        elif packets_count > 40:
            attack_type = "Port Scan"
        else:
            attack_type = "Unknown Attack"

    return result, round(prob, 2), attack_type

# ------------------- ALERT FUNCTION -------------------
def send_alert(pkt_info):
    st.session_state.alerts.append(pkt_info)
    if email_alert:
        pass  # implement email
    if sms_alert:
        pass  # implement SMS

# ------------------- LIVE TRAFFIC -------------------
if mode == "Live Traffic":
    st.subheader("📡 Real-Time Network Traffic Monitoring")
    interface = st.text_input("Network Interface (e.g., eth0, wlan0)", value="lo")
    col1, col2 = st.columns(2)
    start = col1.button("Start Monitoring")
    stop = col2.button("Stop Monitoring")
    live_table = st.empty()

    if start:
        st.session_state.running = True
    if stop:
        st.session_state.running = False

    if st.session_state.running:
        st.info("Monitoring started...")
        try:
            from scapy.all import sniff, IP
            def packet_callback(pkt):
                pkt_info = {
                    "time": datetime.now(),
                    "src_ip": pkt[IP].src if IP in pkt else "N/A",
                    "dest_ip": pkt[IP].dst if IP in pkt else "N/A",
                    "duration": np.random.rand(),
                    "bytes_in": len(pkt),
                    "bytes_out": 0,
                    "packets": 1,
                    "protocol": "TCP"  # placeholder
                }
                pkt_info["result"], pkt_info["probability"], pkt_info["attack_type"] = classify_packet(pkt_info)
                st.session_state.df = pd.concat([st.session_state.df, pd.DataFrame([pkt_info])], ignore_index=True)
                if pkt_info["result"] == 1:
                    send_alert(pkt_info)
                    st.warning(f"⚠️ Attack Detected {pkt_info['src_ip']} -> {pkt_info['dest_ip']} ({pkt_info['attack_type']}) Prob: {pkt_info['probability']}")
                live_table.dataframe(st.session_state.df.tail(10))
            sniff(iface=interface, prn=packet_callback, store=False)
        except ImportError:
            st.error("Scapy not installed. Live monitoring disabled.")
        except Exception as e:
            st.error(f"Error sniffing: {e}")

# ------------------- CSV UPLOAD -------------------
elif mode == "CSV Upload":
    st.subheader("📂 Upload CSV for Analysis")
    uploaded_file = st.file_uploader("Choose CSV", type=["csv"])
    if uploaded_file:
        df_csv = pd.read_csv(uploaded_file)

        # Convert numeric columns
        for col in ["duration","bytes_in","bytes_out","packets"]:
            df_csv[col] = pd.to_numeric(df_csv[col], errors="coerce").fillna(0)
        df_csv["protocol"] = df_csv["protocol"].astype(str)

        df_csv["result"], df_csv["probability"], df_csv["attack_type"] = zip(*df_csv.apply(classify_packet, axis=1))
        st.session_state.df = pd.concat([st.session_state.df, df_csv], ignore_index=True)
        st.dataframe(df_csv)

        for _, row in df_csv.iterrows():
            if row.result == 1:
                send_alert(row)
        st.download_button("Download Report", st.session_state.df.to_csv(index=False), "AI_IDS_Report.csv")

# ------------------- MANUAL ENTRY -------------------
elif mode == "Manual Entry":
    st.subheader("✍️ Manual Packet Input")
    with st.form("manual_form"):
        src_ip = st.text_input("Source IP")
        dest_ip = st.text_input("Destination IP")
        duration = st.number_input("Duration", min_value=0.0, step=0.01)
        bytes_in = st.number_input("Bytes In", min_value=0)
        bytes_out = st.number_input("Bytes Out", min_value=0)
        packets = st.number_input("Packets", min_value=1)
        protocol = st.selectbox("Protocol", list(PROTOCOL_MAP.keys()))
        submitted = st.form_submit_button("Add Packet")
    if submitted:
        pkt_info = {
            "time": datetime.now(),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "duration": duration,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "packets": packets,
            "protocol": protocol
        }
        pkt_info["result"], pkt_info["probability"], pkt_info["attack_type"] = classify_packet(pkt_info)
        st.session_state.df = pd.concat([st.session_state.df, pd.DataFrame([pkt_info])], ignore_index=True)
        st.dataframe(pd.DataFrame([pkt_info]))
        if pkt_info["result"] == 1:
            send_alert(pkt_info)
            st.warning(f"⚠️ Attack Detected! Type: {pkt_info['attack_type']} Prob: {pkt_info['probability']}")
        else:
            st.success("✅ Normal Packet Added.")

# ------------------- ALERT HISTORY -------------------
elif mode == "Alert History":
    st.subheader("📜 Alert History")
    if st.session_state.alerts:
        alert_df = pd.DataFrame(st.session_state.alerts)
        st.dataframe(alert_df)
        st.download_button("Download Alerts", alert_df.to_csv(index=False), "Alert_History.csv")
    else:
        st.info("No alerts yet.")

# ------------------- ANALYTICS -------------------
elif mode == "Analytics":
    st.subheader("📊 Traffic Analytics & Trends")
    df_analytics = st.session_state.df.copy()
    if df_analytics.empty:
        st.info("No data yet. Add packets or upload CSV first.")
    else:
        timeline = alt.Chart(df_analytics).mark_line(point=True).encode(
            x='time:T',
            y='result:Q',
            color='result:N',
            tooltip=['time','src_ip','dest_ip','attack_type','probability']
        )
        st.altair_chart(timeline, use_container_width=True)

        top_src = df_analytics[df_analytics['result']==1]['src_ip'].value_counts().reset_index()
        top_src.columns = ['src_ip','count']
        st.bar_chart(top_src.set_index('src_ip'))

        st.subheader("🌐 Network Visualization")
        G = nx.from_pandas_edgelist(df_analytics, 'src_ip', 'dest_ip', edge_attr=True, create_using=nx.DiGraph())
        plt.figure(figsize=(8,6))
        nx.draw_networkx(G, node_color='cyan', edge_color='red', with_labels=True, node_size=800, arrowsize=20)
        st.pyplot(plt)

        st.download_button("Download Full Analytics Report", df_analytics.to_csv(index=False), "Full_Analytics_Report.csv")
