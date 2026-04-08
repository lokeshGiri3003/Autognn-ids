import streamlit as st
import pandas as pd
import requests
import json
from pyvis.network import Network
import streamlit.components.v1 as components
from time import sleep

API_URL = "http://localhost:8000"

st.set_page_config(layout="wide", page_title="AutoGNN-IDS Dashboard", page_icon="🛡️")

# Top-level functions to fetch data
@st.cache_data(ttl=5)
def fetch_status():
    try:
        r = requests.get(f"{API_URL}/api/status", timeout=2)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"mode": "error", "message": f"API Unreachable: {e}"}

@st.cache_data(ttl=5)
def fetch_topology():
    try:
        r = requests.get(f"{API_URL}/api/topology", timeout=5)
        r.raise_for_status()
        return r.json()
    except:
        return {"nodes": [], "links": []}

@st.cache_data(ttl=5)
def fetch_alerts():
    try:
        r = requests.get(f"{API_URL}/api/alerts?limit=100", timeout=5)
        r.raise_for_status()
        return r.json()
    except:
        return []

# Fetch live status from backend
status = fetch_status()
mode = status.get("mode", "unknown").upper()

# Title and Global Layout
st.title("🛡️ AutoGNN-IDS Dashboard")

# Top status metric row
col1, col2, col3, col4 = st.columns(4)

# Mode styling
if mode == 'DETECTION':
    st.markdown(f"<style>.css-1wivap2 {{ color: #00ff00 !important; }}</style>", unsafe_allow_html=True)
elif mode == 'ERROR':
    st.markdown(f"<style>.css-1wivap2 {{ color: #ff0000 !important; }}</style>", unsafe_allow_html=True)

col1.metric("System Mode", mode)
col2.metric("Baselines Collected", status.get("baseline_count", 0))
col3.metric("Detection Cycles", status.get("detection_cycles", 0))
col4.metric("Total Alerts", status.get("total_alerts", 0))

st.markdown("---")

tab1, tab2, tab3 = st.tabs(["🌐 Network Graph", "🚨 Threat Alerts", "⚙️ System State"])

with tab1:
    st.subheader("Live Network Topology & Anomaly Scores")
    topology = fetch_topology()
    nodes = topology.get("nodes", [])
    edges = topology.get("links", [])
    
    if len(nodes) > 0:
        net = Network(height='600px', width='100%', bgcolor='#0E1117', font_color='white')
        net.force_atlas_2based()
        
        for n in nodes:
            score = n.get('anomaly_score', 0)
            # Normal: Green, Elevated: Orange, Critical: Red
            if score < 0.3:
                color = '#00cc66' 
            elif score < 0.7:
                color = '#ff9933'
            else:
                color = '#ff3333'
                
            label = f"{n.get('ip', n['device_id'])}"
            title_text = f"IP: {n.get('ip')}\nMAC: {n.get('mac')}\nScore: {score:.3f}\nVendor: {n.get('vendor', 'Unknown')}"
            net.add_node(n['device_id'], label=label, title=title_text, color=color)
            
        for e in edges:
            score = e.get('anomaly_score', 0)
            color = '#333333' if score < 0.5 else '#ff3333'
            title = f"Protocol: {e.get('protocol', 'Unknown')}\nBytes: {e.get('bytes', 0)}"
            net.add_edge(e['src_device'], e['dst_device'], title=title, color=color)
            
        net.save_graph('/tmp/network_graph.html')
        HtmlFile = open('/tmp/network_graph.html', 'r', encoding='utf-8')
        source_code = HtmlFile.read()
        components.html(source_code, height=650)
    else:
        if mode == 'ERROR':
            st.error("Cannot load topology. Is the FastAPI server running?")
        else:
            st.info("No active devices found in the network. If in detection mode, the backend might still be acquiring the layout.")

with tab2:
    st.subheader("Active & Past Alerts")
    alerts = fetch_alerts()
    if alerts:
        df = pd.DataFrame(alerts)
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp', ascending=False)
            
        st.dataframe(df, use_container_width=True)
    else:
        st.success("No alerts found in the database. Network is considered secure.")

with tab3:
    st.subheader("Raw System State")
    st.json(status)

# Background auto-refresh logic (every 10 seconds)
if mode != "ERROR":
    sleep(10)
    try:
        st.rerun()
    except AttributeError:
        st.experimental_rerun()
