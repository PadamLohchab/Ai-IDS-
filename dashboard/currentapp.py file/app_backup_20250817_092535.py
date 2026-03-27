import streamlit as st
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
import altair as alt
import networkx as nx
import matplotlib.pyplot as plt
import os
import socket

# ------------------- OPTIONAL LIBRARIES -------------------
# Nmap
try:
    import nmap
    nmap_available = True
except ImportError:
    nmap = None
    nmap_available = False

# Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    scapy_available = True
except ImportError:
    sniff = None
    IP = TCP = UDP = ICMP = None
    scapy_available = False
# ------------------- RISK SCORING -------------------
def compute_risk(port: int, service_name: str, state: str) -> int:
    """
    Simple risk scoring function:
    - Adds base score for open ports
    - Extra for common risky ports/services
    """
    base = 10
    if state.lower() == "open":
        base += 20
    # High-risk ports
    if port in (23, 445, 3389, 5900, 2375):
        base += 40
    # Common web ports
    if port in (80, 443, 8080, 8443):
        base += 15
    s = service_name.lower()
    if "telnet" in s:
        base += 40
    if "ssh" in s:
        base += 10
    if any(k in s for k in ("mysql", "mongodb", "postgres", "redis")):
        base += 25
    return min(100, base)

# ------------------- PORT INTELLIGENCE -------------------
PORT_INTEL = {
    20: ("FTP-Data", "FTP data channel"),
    21: ("FTP", "Legacy FTP — plaintext credentials"),
    22: ("SSH", "Secure shell"),
    23: ("Telnet", "Insecure — plaintext"),
    25: ("SMTP", "Mail transfer"),
    53: ("DNS", "Domain Name System"),
    67: ("DHCP", "DHCP server port"),
    80: ("HTTP", "Web server (unencrypted)"),
    110: ("POP3", "Mail retrieval"),
    123: ("NTP", "Time sync; amplification risk"),
    139: ("NetBIOS", "Windows file/print service"),
    143: ("IMAP", "Mail access"),
    161: ("SNMP", "Network mgmt; check community strings"),
    389: ("LDAP", "Directory service"),
    443: ("HTTPS", "Encrypted web"),
    445: ("SMB", "Windows file sharing; high risk if internet-exposed"),
    3306: ("MySQL", "Database server"),
    5432: ("Postgres", "Database server"),
    27017: ("MongoDB", "No-auth default historically"),
    6379: ("Redis", "Often unsecured if exposed"),
    3389: ("RDP", "Remote Desktop; brute-force risk"),
}

# Usage of PORT_INTEL should be inside a function like this:
def get_port_info(p):
    """Return service and intel info for a port."""
    intel = PORT_INTEL.get(p, ("unknown", "No quick intel"))
    return intel[0], intel[1]

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
if "df" not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=[
        "time", "src_ip", "dest_ip", "duration", "bytes_in", "bytes_out",
        "packets", "protocol", "result", "probability", "attack_type"
    ])
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "running" not in st.session_state:
    st.session_state.running = False

# ------------------- PAGE CONFIG -------------------
st.set_page_config(page_title="Futuristic AI-IDS", layout="wide")
st.title("🚀 Futuristic AI-IDS Dashboard")

# ------------------- SIDEBAR -------------------
st.sidebar.title("Controls")
mode = st.sidebar.radio("Mode", ["Live Traffic", "Active Scan", "CSV Upload", "Manual Entry", "Analytics", "Alert History"])
email_alert = st.sidebar.checkbox("Enable Email Alerts")
sms_alert = st.sidebar.checkbox("Enable SMS Alerts")
st.sidebar.markdown("---")

# ------------------- CLASSIFY FUNCTION -------------------
def classify_packet(packet):
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
        pass  # TODO: implement email alerts
    if sms_alert:
        pass  # TODO: implement SMS alerts

# ------------------- LIVE TRAFFIC -------------------
if mode == "Live Traffic":
    st.subheader("📡 Real-Time Network Traffic Monitoring")
    interface = st.text_input("Network Interface (e.g., eth0, wlan0)", value="eth0")
    col1, col2 = st.columns(2)
    start = col1.button("Start Monitoring")
    stop = col2.button("Stop Monitoring")
    live_table = st.empty()
    port_summary_table = st.empty()

    if start:
        st.session_state.running = True
    if stop:
        st.session_state.running = False

    if st.session_state.running:
        st.info("Monitoring started... Press Stop to end.")

        try:
            def packet_callback(pkt):
                proto = "OTHER"
                if TCP in pkt:
                    proto = "TCP"
                    port = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    port = pkt[UDP].dport
                elif ICMP in pkt:
                    proto = "ICMP"
                    port = 0
                else:
                    port = 0

                pkt_info = {
                    "time": datetime.now(),
                    "src_ip": pkt[IP].src if IP in pkt else "N/A",
                    "dest_ip": pkt[IP].dst if IP in pkt else "N/A",
                    "duration": 0,
                    "bytes_in": len(pkt),
                    "bytes_out": 0,
                    "packets": 1,
                    "protocol": proto,
                    "port": port
                }

                pkt_info["result"], pkt_info["probability"], pkt_info["attack_type"] = classify_packet(pkt_info)
                st.session_state.df = pd.concat([st.session_state.df, pd.DataFrame([pkt_info])], ignore_index=True)

                if pkt_info["result"] == 1:
                    send_alert(pkt_info)
                    st.warning(f"⚠️ Attack Detected {pkt_info['src_ip']} -> {pkt_info['dest_ip']} "
                               f"({pkt_info['attack_type']}) Prob: {pkt_info['probability']}")

                # Show last 10 packets
                live_table.dataframe(st.session_state.df.tail(10))

                # Show protocol/port summary table
                summary = st.session_state.df.groupby(["protocol", "port"])["result"].count().reset_index()
                summary.columns = ["Protocol", "Port", "Packet Count"]
                port_summary_table.dataframe(summary)

            sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda x: not st.session_state.running)

        except Exception as e:
            st.error(f"Error sniffing: {e}")

# ------------------- ACTIVE SCAN -------------------
elif mode == "Active Scan":
    st.subheader("🔍 Active Network Scan (Nmap-enhanced)")
    target = st.text_input("Enter target IP/domain", value="127.0.0.1")
    ports = st.text_input("Ports to scan (e.g., 20-100,80,443)", value="20-1024")
    scan_btn = st.button("Start Scan")

    if scan_btn:
        st.info("Starting scan... please wait ⏳")
        open_ports_info = []

        # Use nmap if available
        if nmap_available:
            import nmap
            nm = nmap.PortScanner()
            try:
                args = f"-sV -O -Pn -p {ports}"
                nm.scan(hosts=target, arguments=args)
                for host in nm.all_hosts():
                    host_info = nm[host]
                    hostnames = host_info.get('hostnames', [])
                    hostname = hostnames[0]['name'] if hostnames else ''
                    state = host_info.get('status', {}).get('state', '')
                    os_guess = host_info.get('osmatch', [{}])[0].get('name', '')

                    for proto in host_info.all_protocols():
                        for port, pdata in host_info[proto].items():
                            intel = PORT_INTEL.get(int(port), ("unknown","No quick intel"))
                            risk = compute_risk(int(port), pdata.get("name",""), state)
                            open_ports_info.append({
                                "Host": host,
                                "Hostname": hostname,
                                "State": state,
                                "Port": int(port),
                                "Protocol": proto.upper(),
                                "Service": pdata.get("name", ""),
                                "Product": pdata.get("product",""),
                                "Version": pdata.get("version",""),
                                "OS_Guess": os_guess,
                                "Risk": risk,
                                "Intel": intel[1]
                            })
            except Exception as e:
                st.error(f"Nmap scan failed: {e}. Falling back to socket scan.")

        # Fallback socket scan if nmap unavailable or failed
        if not open_ports_info:
            def port_is_open(ip, port):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect((ip, port))
                    s.close()
                    return True
                except:
                    return False

            port_list = []
            for part in ports.split(","):
                if "-" in part:
                    start, end = part.split("-")
                    port_list.extend(range(int(start), int(end)+1))
                else:
                    port_list.append(int(part))

            for p in port_list:
                if port_is_open(target, p):
                    # Minimal info for socket scan
                    banner = ""
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1)
                        s.connect((target, p))
                        try:
                            s.sendall(b"\r\n")
                            banner = s.recv(1024).decode(errors="ignore").strip()
                        except:
                            pass
                        s.close()
                    except:
                        pass
                    intel = PORT_INTEL.get(p, ("unknown","No quick intel"))
                    risk = compute_risk(p, "", "open")
                    open_ports_info.append({
                        "Host": target,
                        "Hostname": "",
                        "State": "open",
                        "Port": p,
                        "Protocol": "TCP",
                        "Service": intel[0],
                        "Product": "",
                        "Version": "",
                        "OS_Guess": "",
                        "Risk": risk,
                        "Intel": intel[1]
                    })

        if open_ports_info:
            df_open_ports = pd.DataFrame(open_ports_info)
            st.success(f"Scan completed. {len(df_open_ports)} open ports found ✅")
            st.dataframe(df_open_ports)
            st.download_button("Download Scan Report", df_open_ports.to_csv(index=False), "Active_Scan_Report.csv")
        else:
            st.info("No open ports found.")

# ------------------- CSV UPLOAD -------------------
elif mode == "CSV Upload":
    st.subheader("📂 Upload CSV for Analysis")
    uploaded_file = st.file_uploader("Choose CSV", type=["csv"])
    if uploaded_file:
        df_csv = pd.read_csv(uploaded_file)
        for col in ["duration", "bytes_in", "bytes_out", "packets"]:
            df_csv[col] = pd.to_numeric(df_csv[col], errors="coerce").fillna(0)
        df_csv["protocol"] = df_csv["protocol"].astype(str)

        df_csv["result"], df_csv["probability"], df_csv["attack_type"] = zip(*df_csv.apply(classify_packet, axis=1))
        st.session_state.df = pd.concat([st.session_state.df, df_csv], ignore_index=True)
        st.dataframe(df_csv)

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
            x="time:T",
            y="result:Q",
            color="result:N",
            tooltip=["time", "src_ip", "dest_ip", "attack_type", "probability"]
        )
        st.altair_chart(timeline, use_container_width=True)

        top_src = df_analytics[df_analytics["result"] == 1]["src_ip"].value_counts().reset_index()
        top_src.columns = ["src_ip", "count"]
        st.bar_chart(top_src.set_index("src_ip"))

        st.subheader("🌐 Network Visualization")
        G = nx.from_pandas_edgelist(df_analytics, "src_ip", "dest_ip", edge_attr=True, create_using=nx.DiGraph())
        plt.figure(figsize=(8, 6))
        nx.draw_networkx(G, node_color="cyan", edge_color="red", with_labels=True, node_size=800, arrowsize=20)
        st.pyplot(plt)
