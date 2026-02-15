import streamlit as st
import json
import os
import sys
import pandas as pd
import pydeck as pdk
import hashlib
import base64
from datetime import datetime, timedelta
from streamlit_agraph import agraph, Node, Edge, Config
import plotly.express as px
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from database import get_pending_tasks, update_task_status
from setup_opensearch import get_opensearch_client, upload_to_opensearch
from to_pdf import generate_pdf_report
from utils import get_ai_remediation
from audit_logger import AuditLogger
import requests

audit_logger = AuditLogger()
from audit_logger import AuditLogger

audit_logger = AuditLogger()

# 設定頁面
st.set_page_config(page_title="CTI & SOC Platform", layout="wide", page_icon="🛡️")

# ================= CSS 美化 =================
st.markdown("""
<style>
    .stApp { background-color: #F8F9FA; }
    div[data-testid="stMetric"] {
        background-color: #FFFFFF;
        border: 1px solid #E6E9EF;
        border-left: 6px solid #FF4B4B !important;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .report-card {
        padding: 15px; border-radius: 10px; background: white; margin-bottom: 10px; border: 1px solid #ddd;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ================= 登入驗證模組 =================
def check_password():
    """回傳 True 代表登入成功"""
    
    def password_entered():
        """檢查使用者輸入的帳密"""
        correct_user = os.getenv("UI_USERNAME", "admin")
        correct_pass = os.getenv("UI_PASSWORD", "admin")
        
        if st.session_state["username"] == correct_user and st.session_state["password"] == correct_pass:
            st.session_state["password_correct"] = True
            st.session_state["logged_in_user"] = st.session_state["username"]
            del st.session_state["password"]  
        else:
            st.session_state["password_correct"] = False

    if "password_correct" not in st.session_state:
        st.markdown("<h1 style='text-align: center;'>🛡️ CTI & SOC Platform</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center;'>Please Login</h3>", unsafe_allow_html=True)
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            st.text_input("Username", key="username")
            st.text_input("Password", type="password", on_change=password_entered, key="password")
        return False
        
    elif not st.session_state["password_correct"]:
        st.markdown("<h1 style='text-align: center;'>🛡️ CTI & SOC Platform</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center;'>Please Login</h3>", unsafe_allow_html=True)
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            st.text_input("Username", key="username")
            st.text_input("Password", type="password", on_change=password_entered, key="password")
            st.error(" 😔 User not known or password incorrect")
        return False
    else:
        return True

# ================= 輔助函式 =================

def get_all_reports():
    """從 OpenSearch 撈取所有歷史情資 (Knowledge Base)"""
    client = get_opensearch_client()
    query = {"size": 200, "sort": [{"timestamp": "desc"}], "query": {"match_all": {}}}
    try:
        response = client.search(index="cti-reports", body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
    except:
        return []

def get_graph_data():
    """將情資轉換為 Graph 節點與連線"""
    reports = get_all_reports()
    nodes = []
    edges = []
    node_ids = set()
    
    for r in reports:
        report_id = r.get('filename', 'Unknown')
        
        # 報告節點
        if report_id not in node_ids:
            nodes.append(Node(id=report_id, label=report_id[:15]+"...", size=20, shape="circularImage", image="https://img.icons8.com/color/48/file.png"))
            node_ids.add(report_id)
            
        # IOC 節點
        indicators = r.get('indicators', {})
        for ip in indicators.get('ipv4', []):
            if ip not in node_ids:
                nodes.append(Node(id=ip, label=ip, size=15, color="#FF4B4B"))
                node_ids.add(ip)
            edges.append(Edge(source=report_id, target=ip, label="mentions"))
            
        for domain in indicators.get('domains', []):
            if domain not in node_ids:
                nodes.append(Node(id=domain, label=domain, size=15, color="#FFA500"))
                node_ids.add(domain)
            edges.append(Edge(source=report_id, target=domain, label="mentions"))
            
        # TTPs 節點
        for ttp in r.get('ttps', []):
            t_id = ttp.get('mitre_technique_id') or ttp.get('id')
            if t_id and t_id not in node_ids:
                nodes.append(Node(id=t_id, label=t_id, size=18, color="#0083B8", shape="box"))
                node_ids.add(t_id)
                edges.append(Edge(source=report_id, target=t_id, label="uses"))

    return nodes, edges

def get_audit_logs():
    """Fetch recent audit logs from OpenSearch"""
    client = get_opensearch_client()
    query = {
        "size": 1000,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}}
    }
    try:
        if not client.indices.exists(index="soc-audit-logs"):
            return pd.DataFrame()
            
        response = client.search(index="soc-audit-logs", body=query)
        data = [hit["_source"] for hit in response["hits"]["hits"]]
        return pd.DataFrame(data)
    except Exception as e:
        # st.error(f"Failed to fetch audit logs: {e}")
        return pd.DataFrame()

def get_real_soc_data():
    """從 OpenSearch 撈取 SOC 告警 (包含 GeoIP 豐富化資料)"""
    client = get_opensearch_client()
    index_name = "security-logs-knn"
    query = {
        "size": 100, "sort": [{"timestamp": "desc"}],
        "query": { "bool": { "must": [{ "term": { "threat_matched": True }}] } }
    }
    try:
        response = client.search(index=index_name, body=query)
        data = []
        for hit in response['hits']['hits']:
            src = hit['_source']
            ip_val = src.get('source_ip') or src.get('indicators', {}).get('ipv4', [None])[0] or "Unknown"
            
            # 提取 GeoIP 資料
            # enrichment 結構通常是: { "8.8.8.8": { "geo": { "lat": 1.23, "lon": 4.56, "country": "US" } } }
            enrich = src.get('enrichment', {}).get(ip_val, {}).get('geo', {})
            
            if ip_val != "Unknown":
                data.append({
                    "id": hit['_id'],
                    "timestamp": src.get('timestamp'),
                    "source_ip": ip_val,
                    "attack_type": src.get('attack_type', 'Threat Match'),
                    "severity": src.get('severity', 'High'),
                    "related_report": src.get('filename', 'N/A'),
                    "Mitigation": src.get('mitigation_status', 'Pending ⏳'),
                    "lat": enrich.get('lat'),
                    "lon": enrich.get('lon'),
                    "country": enrich.get('country', 'Unknown'),
                    "vulnerabilities": src.get("vulnerabilities", []),
                    "summary": src.get("summary", ""),
                    "message": src.get("message", ""),
                    "file_path": src.get("filename", "")
                })
        return pd.DataFrame(data)
    except:
        return pd.DataFrame()
    
def get_related_reports(indicators):
    """
    動態查詢關聯報告
    """
    if not indicators:
        return []

    target_values = []
    if isinstance(indicators, dict):
        target_values.extend(indicators.get("ipv4", []))
        target_values.extend(indicators.get("domains", []))
    
    if not target_values:
        return []

    client = get_opensearch_client()
    try:
        query = {
            "size": 50,
            "query": {
                "terms": {
                    "value.keyword": target_values
                }
            },
            "_source": ["related_reports"]
        }
        resp = client.search(index="cti-indicators", body=query)
        related_files = set()
        for hit in resp["hits"]["hits"]:
            reports = hit["_source"].get("related_reports", [])
            for r in reports:
                related_files.add(r)
        return list(related_files)
    except Exception as e:
        return []

def get_enriched_alerts():
    """從 OpenSearch 撈取 CMDB 豐富化後的警報資料"""
    client = get_opensearch_client()
    index_name = "security-alerts"
    query = {
        "size": 100,
        "sort": [{"timestamp": "desc"}],
        "query": {"match_all": {}}
    }
    try:
        response = client.search(index=index_name, body=query)
        data = []
        for hit in response['hits']['hits']:
            item = hit['_source']
            item['alert_id'] = hit['_id'] # 儲存 ID 方便未來更新狀態
            data.append(item)
        return pd.DataFrame(data)
    except:
        return pd.DataFrame()

# ================= 主程式 =================

if not check_password():
    st.stop()

st.sidebar.title("🛡️ CTI & SOC Platform")
st.sidebar.success(f"Login as: {st.session_state.get('logged_in_user', 'Admin')}")

if st.sidebar.button("Logout"):
    st.session_state["password_correct"] = False
    st.rerun()

page = st.sidebar.radio("Navigation", ["🚨 Internal Threat Monitor (SOC)", "📈 Enriched Alerts Dashboard", "🔍 CTI Report Review", "🕸️ Threat Graph", "📚 Knowledge Base", "📜 Audit & Compliance Trail"])

## --- 1. SOC Dashboard ---
if page == "🚨 Internal Threat Monitor (SOC)":
    st.title("🚨 Security Operations Center")
    df = get_real_soc_data()
    
    if df.empty:
        st.info("No active threats detected. (System Clean)")
    else:
        # --- 頂部指標 ---
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Active Alerts", len(df))
        k2.metric("Attackers", df['source_ip'].nunique())
        
        # 計算不重複的攻擊來源國
        countries = df[df['country'] != 'Unknown']['country'].nunique()
        k3.metric("Attacking Countries", countries)
        
        k4.metric("Status", "DEFCON 3")
        
        st.divider()

        # --- 地圖區塊 ---
        st.subheader("🌍 Real-time Attack Map (GeoIP Enabled)")
        
        # Fallback Coordinates for common countries
        COUNTRY_COORDINATES = {
            "United States": {"lat": 37.0902, "lon": -95.7129},
            "China": {"lat": 35.8617, "lon": 104.1954},
            "Russia": {"lat": 61.5240, "lon": 105.3188},
            "Germany": {"lat": 51.1657, "lon": 10.4515},
            "France": {"lat": 46.2276, "lon": 2.2137},
            "Japan": {"lat": 36.2048, "lon": 138.2529},
            "Taiwan": {"lat": 23.6978, "lon": 120.9605}, # Source Taiwan
            "Internal / Private": {"lat": 23.5, "lon": 121.0}, # Map internal threats to Central Taiwan (Visible Arc)
            "Unknown": {"lat": 0, "lon": 0} # Null Island
        }

        # 準備地圖資料 (Grouped by IP for Denoising)
        map_points = {}
        
        for idx, row in df.iterrows():
            ip = row['source_ip']
            country = row.get('country', 'Unknown')
            
            # 1. Coordinate Fallback Logic
            lat = row.get('lat')
            lon = row.get('lon')
            
            if pd.isna(lat) or pd.isna(lon):
                # Try fallback
                fallback = COUNTRY_COORDINATES.get(country)
                # Fallback to "Unknown" if not found but prevent total loss
                if not fallback:
                     fallback = COUNTRY_COORDINATES.get("Unknown")
                
                if fallback:
                    lat = fallback["lat"]
                    lon = fallback["lon"]
            
            if lat is not None and lon is not None:
                if ip not in map_points:
                    map_points[ip] = {
                        "ip": ip, 
                        "lat": float(lat), 
                        "lon": float(lon),
                        "country": country,
                        "attack_count": 0
                    }
                map_points[ip]["attack_count"] += 1
        
        if map_points:
            # Convert dict back to list for PyDeck
            point_data = list(map_points.values())
            
            # 定義防禦目標 (預設：台灣)
            TARGET_COORDS = [121.5, 25.0] 
            
            # 準備連線資料
            arc_data = []
            for p in point_data:
                # Pre-calculate width to avoid "Function calls not allowed" error in JS
                width = min(10, 2 + (p["attack_count"] * 0.5))
                
                arc_data.append({
                    "source_ip": p["ip"],
                    "source_coords": [p["lon"], p["lat"]],
                    "target_coords": TARGET_COORDS,
                    "country": p["country"],
                    "attack_count": p["attack_count"],
                    "stroke_width": width
                })

            # 低弧度飛行路徑 (Dynamic Width by Pre-calculated field)
            arc_layer = pdk.Layer(
                "ArcLayer",
                data=arc_data,
                get_source_position="source_coords",
                get_target_position="target_coords",
                get_source_color=[255, 50, 50, 150], # 紅色半透明
                get_target_color=[0, 255, 100, 150], # 綠色半透明
                get_width="stroke_width", # Use pre-calculated field
                pickable=True,
                great_circle=False, # 2D 平面線條
                get_height=0.5,
            )

            # ScatterplotLayer (紅點, Aggregated)
            scatterplot_layer = pdk.Layer(
                "ScatterplotLayer",
                data=point_data,
                get_position=["lon", "lat"],
                get_color=[255, 50, 50, 200],
                get_radius=100000, # 半徑大小
                pickable=True,
            )

            # 渲染地圖
            st.pydeck_chart(pdk.Deck(
                map_style=None,
                initial_view_state=pdk.ViewState(
                    latitude=20, 
                    longitude=100, 
                    zoom=1.2, 
                    pitch=0,
                    bearing=0
                ),
                layers=[arc_layer, scatterplot_layer],
                tooltip={"text": "Attacker: {source_ip}\nOrigin: {country}\nAttacks: {attack_count}"}
            ))
        else:
            st.warning("Threats detected but no GeoIP data available.")

        # --- Intelligent Remediation Engine (AI-Driven) ---
        st.subheader("🛡️ Intelligent Remediation Engine")
        
        # 1. Grouping Logic
        unique_threats = {} # Key: Identifier (CVE or Attack Type) -> Value: Threat Info

        for _, row in df.iterrows():
            # Check for specific CVEs first (Higher Priority)
            vulns = row.get("vulnerabilities", [])
            if isinstance(vulns, list) and vulns:
                for v in vulns:
                    # Specific CVE found
                    vid = v.get("id")
                    if not vid: # Fallback for empty ID (Generic Remediation Case)
                        vid = row.get("attack_type", "Unknown Threat")
                        # USE AI PLAYBOOK for generic threats (Overwrite static JSON text)
                        remediation_text = get_ai_remediation(vid)
                    else:
                        # Use CVE specific remediation
                        remediation_text = v.get("remediation", "No remediation available.")
                    
                    if vid not in unique_threats:
                        unique_threats[vid] = {
                            "type": "CVE Exploit" if v.get("id") else "AI Anomaly",
                            "severity": v.get("severity", "High"),
                            "description": v.get("description", "No description available."),
                            "remediation": remediation_text,
                            "count": 1,
                            "source_ips": {row.get('source_ip')} if row.get('source_ip') else set(),
                        }
                    else:
                        unique_threats[vid]["count"] += 1
                        if row.get('source_ip'):
                             if "source_ips" not in unique_threats[vid]:
                                 unique_threats[vid]["source_ips"] = set()
                             unique_threats[vid]["source_ips"].add(row.get('source_ip'))
                        
                    # Collect Evidence (Unified)
                    if "evidence" not in unique_threats[vid]:
                        unique_threats[vid]["evidence"] = set()
                    
                    msg = row.get('summary') or row.get('message') or "No details"
                    fname = row.get('file_path') or row.get('related_report') or "Unknown Source"
                    evidence_str = f"{os.path.basename(fname)}: {msg[:100]}..."
                    unique_threats[vid]["evidence"].add(evidence_str)
            else:
                # No CVE? Use AI Attack Type Classification (e.g., DDoS, Brute Force)
                attack_type = row.get("attack_type", "Suspicious Activity")
                if attack_type not in unique_threats:
                    # Construct smart default remediation based on attack type (AI-Driven)
                    if row.get("Mitigation"):
                        default_remediation = row.get("Mitigation") # Use provided mitigation if available
                    else:
                        default_remediation = get_ai_remediation(attack_type) # Fallback to AI Playbook
                    
                    unique_threats[attack_type] = {
                        "type": "Behavioral Pattern",
                        "severity": row.get("severity", "Medium"),
                        "description": f"AI detected {attack_type} pattern from {row.get('source_ip', 'unknown source')}.",
                        "remediation": default_remediation,
                        "count": 1,
                        "source_ips": {row.get('source_ip')} if row.get('source_ip') else set(),
                    }
                else:
                    unique_threats[attack_type]["count"] += 1
                    ip = row.get('source_ip')
                    # ... (rest of logic)
                    if ip:
                        if "source_ips" not in unique_threats[attack_type]:
                            unique_threats[attack_type]["source_ips"] = set()
                        unique_threats[attack_type]["source_ips"].add(ip)
                        # Update description if multiple IPs are detected
                        if len(unique_threats[attack_type]["source_ips"]) > 1:
                             unique_threats[attack_type]["description"] = f"AI detected {attack_type} pattern from multiple sources ({len(unique_threats[attack_type]['source_ips'])} unique IPs)."
                    
                # Collect Evidence (Unified)
                if "evidence" not in unique_threats[attack_type]:
                    unique_threats[attack_type]["evidence"] = set()
                
                msg = row.get('summary') or row.get('message') or "No details"
                fname = row.get('file_path') or row.get('related_report') or "Unknown Source"
                evidence_str = f"{os.path.basename(fname)}: {msg[:100]}..."
                unique_threats[attack_type]["evidence"].add(evidence_str)

        # === ROLLBACK / UNBLOCK SECTION ===
        st.subheader("🛡️ Active Defense Actions (SOAR)")
        active_blocks = df[df['Mitigation'].str.contains('Blocked', na=False)]
        if not active_blocks.empty:
            for idx, row in active_blocks.iterrows():
                with st.expander(f"🔴 Blocked: {row['source_ip']} ({row['attack_type']})"):
                    c1, c2 = st.columns([3, 1])
                    c1.write(f"**Justification**: {row.get('summary', 'Threat Matched')}")
                    if c2.button("⏪ Rollback / Unblock", key=f"rb_{row['id']}"):
                        try:
                            # 1. Call Mock SOAR
                            requests.post("http://soar-server:5000/unblock", json={"ip": row['source_ip']})
                            
                            # 2. Audit Log
                            audit_logger.log_event(
                                actor=st.session_state.get("logged_in_user", "Admin"),
                                action="ROLLBACK_BLOCK",
                                target=row['source_ip'],
                                status="SUCCESS",
                                justification="Manual Rollback requested by Analyst"
                            )
                            
                            # 3. Update OpenSearch
                            client = get_opensearch_client()
                            client.update(
                                index="security-logs-knn", 
                                id=row['id'], 
                                body={"doc": {"mitigation_status": "Rolled Back ⏪"}},
                                refresh=True # Ensure immediate visibility
                            )
                            st.success(f"Successfully Unblocked {row['source_ip']}")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Rollback failed: {e}")
        else:
            st.caption("No active blocks to rollback.")

        if unique_threats:
            # 2. Full-Width Stacked Layout (No Columns)
            st.markdown("#### � Defense Playbooks (AI Generated)")
            
            for tid, info in unique_threats.items():
                # Dynamic color based on severity
                severity_color = "red" if info["severity"] == "High" else "orange"
                
                # Enhanced Title: 🚨 [High] Defense Playbook: SQL Injection (Behavioral Pattern)
                expander_title = f"🚨 [{info['severity']}] Defense Playbook: {tid} ({info['type']})"
                
                with st.expander(expander_title, expanded=False):
                    st.markdown(f"**Severity**: :{severity_color}[{info['severity']}]")
                    st.markdown(f"**Context**: {info['description']}")
                    
                    st.info(f"**Action Plan**:\n\n{info['remediation']}")
                    
                    # --- Evidence Section ---
                    st.markdown("---")
                    st.markdown("**Evidence / Associated Logs:**")
                    evidence_list = list(info.get("evidence", []))
                    
                    # Limit to 5 items
                    max_items = 5
                    display_items = evidence_list[:max_items]
                    
                    for item in display_items:
                        st.code(item, language="text")
                        
                    if len(evidence_list) > max_items:
                        st.caption(f"... and {len(evidence_list) - max_items} more logs.")
                    
                    if info["count"] > 1:
                        st.caption(f"👀 Affecting {info['count']} separate alerts.")
            
        else:
            st.info("No active threats requiring remediation. System Clean.")

# --- Enriched Alerts Dashboard (CMDB 面板) ---
elif page == "📈 Enriched Alerts Dashboard":
    st.title("📈 Enriched Security Alerts Dashboard")
    df_alerts = get_enriched_alerts()

    if df_alerts.empty:
        st.info("No enriched alerts found yet. Run the Detection Engine to generate some!")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Alerts", len(df_alerts))
        c2.metric("Critical Assets Hit", len(df_alerts[df_alerts['asset_criticality'] == 'CRITICAL']))
        c3.metric("Affected Depts", df_alerts['asset_department'].nunique())
        c4.metric("New Alerts", len(df_alerts[df_alerts['status'] == 'New']))
        st.divider()

        col_left, col_right = st.columns(2)
        with col_left:
            st.subheader("🏢 Alerts by Department")
            fig_dept = px.pie(df_alerts, names='asset_department', hole=0.4, color_discrete_sequence=px.colors.qualitative.Pastel)
            st.plotly_chart(fig_dept, use_container_width=True)
        with col_right:
            st.subheader("⚠️ Asset Risk Distribution")
            fig_risk = px.pie(df_alerts, names='asset_criticality', color='asset_criticality', color_discrete_map={'CRITICAL':'#FF4B4B', 'HIGH':'#FFA500', 'MEDIUM':'#F9D71C', 'LOW':'#28A745'})
            st.plotly_chart(fig_risk, use_container_width=True)

        st.subheader("📋 Enriched Alert List")
        display_df = df_alerts[['timestamp', 'rule_name', 'asset_hostname', 'asset_department', 'asset_criticality', 'asset_owner', 'status']].sort_values(by='timestamp', ascending=False)
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        with st.expander("🔍 Evidence Log Excerpt"):
            for idx, row in df_alerts.head(5).iterrows():
                st.markdown(f"**Alert:** {row['rule_name']} | **Target:** {row['asset_hostname']}")
                st.code(row['log_excerpt'], language='text')
                st.divider()


# --- CTI Review ---
elif page == "🔍 CTI Report Review":
    st.title("🔍 CTI Analysis Workbench (Pending)")
    tasks = get_pending_tasks()
    
    if not tasks:
        st.success("✅ No pending reports.")
    else:
        task_options = {f"{t['id']}: {t['filename']}": t for t in tasks}
        sel = st.sidebar.selectbox("Select Report:", list(task_options.keys()))
        task = task_options[sel]
        
        c1, c2 = st.columns(2)
        with c1:
            st.text_area("Raw Text", task['raw_content'], height=400, disabled=True)
        with c2:
            try:
                j_obj = json.loads(task['analysis_json']) if isinstance(task['analysis_json'], str) else task['analysis_json']
                j_str = json.dumps(j_obj, indent=4)
            except: j_str = "{}"
            
            edited_json = st.text_area("JSON Analysis", j_str, height=400, key=f"json_{task['id']}")
            
        if st.button("✅ Approve & Generate PDF", type="primary"):
            final_json = json.loads(edited_json)
            expiration_date = (datetime.now() + timedelta(days=30)).isoformat()

            update_task_status(task['id'], "APPROVED", final_json)
            
            pdf_filename = f"{os.path.splitext(task['filename'])[0]}.pdf"
            pdf_path = os.path.join("data/reports", pdf_filename)
            generate_pdf_report(final_json, pdf_path)
            
            from setup_opensearch import upsert_indicator
            indicators = final_json.get("indicators", {})
            report_info = {"filename": task['filename'], "confidence": final_json.get("confidence", 100)}

            for ip in indicators.get("ipv4", []):
                upsert_indicator(ip, "ipv4", report_info)
            for domain in indicators.get("domains", []):
                upsert_indicator(domain, "domain", report_info)

            doc = final_json.copy()
            doc.update({
                "filename": task['filename'], 
                "timestamp": datetime.now().isoformat(),
                "expiration_date": expiration_date,
                "pdf_path": pdf_path,
                "source_type": task['source_type'],
                "threat_matched": False
            })
            
            # 使用檔名當 ID 避免重複
            report_id = os.path.splitext(task['filename'])[0]
            upload_to_opensearch(doc, report_id, "cti-reports")
            
            # AUDIT LOG: APPROVE
            audit_logger.log_event(
                actor=st.session_state.get("logged_in_user", "Admin"),
                action="APPROVE_REPORT",
                target=task['filename'],
                status="SUCCESS",
                justification="Manual Approval by Analyst",
                details={"confidence": final_json.get("confidence")}
            )
            
            st.success(f"Approved! PDF generated at: {pdf_path}")
            st.rerun()

        rejection_reason = st.text_input("Rejection Reason (Optional - helps AI learn):", key=f"reason_{task['id']}")
        if st.button("🗑️ Reject"):
            update_task_status(task['id'], "REJECTED")
            
            # Optimization 5: Human Feedback Loop
            # 將誤判案例存入 ai-feedback index
            if rejection_reason:
                feedback_doc = {
                    "timestamp": datetime.now().isoformat(),
                    "filename": task['filename'],
                    "content": task['raw_content'],
                    "reason": rejection_reason,
                    "original_analysis": task['analysis_json']
                }
                try:
                    upload_to_opensearch(feedback_doc, f"feedback_{task['id']}", "ai-feedback")
                    st.success("Feedback saved! AI will learn from this mistake.")
                except Exception as e:
                    st.error(f"Failed to save feedback: {e}")
            
            # AUDIT LOG: REJECT
            audit_logger.log_event(
                actor=st.session_state.get("logged_in_user", "Admin"),
                action="REJECT_REPORT",
                target=task['filename'],
                status="SUCCESS",
                justification=rejection_reason or "No reason provided",
                details={"original_confidence": task.get("confidence")}
            )

            st.rerun()

# --- Threat Graph ---
elif page == "🕸️ Threat Graph":
    st.title("🕸️ Threat Intelligence Graph")
    nodes, edges = get_graph_data()
    
    if not nodes:
        st.info("No data to visualize.")
    else:
        config = Config(width=900, height=600, directed=True, nodeHighlightBehavior=True, highlightColor="#F7A7A6", collapsible=True)
        agraph(nodes=nodes, edges=edges, config=config)

# --- Knowledge Base (With Filters) ---
elif page == "📚 Knowledge Base":
    st.title("📚 Intelligence Knowledge Base")
    all_reports = get_all_reports()
    
    if not all_reports:
        st.info("No reports found.")
    else:
        st.caption(f"Loaded {len(all_reports)} reports from database.")
        # Filter 邏輯
        unique_sources = list(set([r.get('source_type', 'Unknown') for r in all_reports]))
        all_ttps = set()
        for r in all_reports:
            ttps = r.get('ttps', [])
            if isinstance(ttps, list):
                for t in ttps:
                    t_id = t.get('id') or t.get('mitre_technique_id')
                    if t_id: all_ttps.add(t_id)
            elif isinstance(ttps, dict):
                 all_ttps.update(ttps.keys())
        unique_ttps = sorted(list(all_ttps))

        with st.expander("🔍 Advanced Filters", expanded=True):
            c1, c2, c3 = st.columns([2, 1, 1])
            with c1: search_query = st.text_input("Search (Filename, IP, Domain)")
            with c2: selected_sources = st.multiselect("🏷️ Source Type", unique_sources, default=[])
            with c3: 
                st.write("")
                show_threats_only = st.toggle("🚨 High Threats Only")
            
            c4, c5 = st.columns([3, 1])
            with c4: selected_ttps = st.multiselect("🛡️ MITRE ATT&CK Techniques", unique_ttps, default=[])

        filtered_reports = []
        for r in all_reports:
            if selected_sources and r.get('source_type', 'Unknown') not in selected_sources: continue
            if show_threats_only and not r.get('threat_matched', False): continue
            
            if selected_ttps:
                report_ttps = []
                raw_ttps = r.get('ttps', [])
                if isinstance(raw_ttps, list):
                    report_ttps = [t.get('id') or t.get('mitre_technique_id') for t in raw_ttps]
                elif isinstance(raw_ttps, dict):
                    report_ttps = list(raw_ttps.keys())
                if not (set(selected_ttps) & set(filter(None, report_ttps))): continue

            if search_query:
                q = search_query.lower()
                match_file = q in r.get('filename', '').lower()
                match_ioc = q in json.dumps(r.get('indicators', {})).lower()
                if not (match_file or match_ioc): continue
            
            filtered_reports.append(r)
            
        filtered_reports.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        st.divider()

        if not filtered_reports:
            st.warning("No reports match your filters.")
        else:
            for i, r in enumerate(filtered_reports):
                exp_date = r.get("expiration_date", "N/A")
                is_expired = (exp_date != "N/A" and exp_date < datetime.now().isoformat())
                status_icon = "🔴 Expired" if is_expired else "🟢 Active"
                type_icon = "🚨" if r.get('threat_matched') else "📄"
                
                with st.expander(f"{type_icon} {r.get('timestamp', '')[:10]} - {r.get('filename')} ({status_icon})"):
                    c1, c2 = st.columns([2, 1])
                    with c1:
                        st.subheader("Indicators")
                        st.json(r.get('indicators', {}))
                        
                        vulns = r.get('vulnerabilities', [])
                        if vulns:
                            st.subheader("🛡️ Vulnerabilities & Remediation")
                            for v in vulns:
                                st.markdown(f"**{v.get('id')}** (Severity: {v.get('severity')})")
                                st.markdown(f"_{v.get('description')}_")
                                st.markdown(f"**Remediation:** {v.get('remediation')}")
                                st.divider()
                                
                        st.subheader("TTPs")
                        st.json(r.get('ttps', {}))
                    with c2:
                        st.write(f"**Source:** {r.get('source_type', 'Unknown')}")
                        st.metric("Confidence", f"{r.get('confidence', 0)}%")
                        st.write(f"**TTL:** {exp_date[:10]}")
                        
                        pdf_path = r.get("pdf_path")
                        if pdf_path and os.path.exists(pdf_path):
                            with open(pdf_path, "rb") as f:
                                st.download_button("📥 Download PDF", f, file_name=os.path.basename(pdf_path), mime="application/pdf", key=f"btn_{i}_{r.get('filename')}")
                        else:
                            st.caption("⚠️ PDF not available")

                    st.divider()
                    st.markdown("### 🔗 Related Intelligence")
                    related = get_related_reports(r.get('indicators', {}))
                    if r.get('filename') in related: related.remove(r.get('filename'))
                    
                    if related:
                        for rf in related: st.markdown(f"- 📄 `{rf}`")
                    else:
                        st.caption("No linked reports.")

# --- Audit Trail ---
elif page == "📜 Audit & Compliance Trail":
    st.title("📜 Audit & Compliance Trail (ISO 27001)")
    st.info("Immutable record of all AI and Analyst actions.")
    
    df_audit = get_audit_logs()
    
    if df_audit.empty:
        st.warning("No audit logs found.")
    else:
        # Filters
        c1, c2, c3 = st.columns(3)
        with c1: filter_actor = st.multiselect("Actor", df_audit['actor'].unique())
        with c2: filter_action = st.multiselect("Action", df_audit['action'].unique())
        with c3: filter_status = st.multiselect("Status", df_audit['status'].unique())
        
        if filter_actor: df_audit = df_audit[df_audit['actor'].isin(filter_actor)]
        if filter_action: df_audit = df_audit[df_audit['action'].isin(filter_action)]
        if filter_status: df_audit = df_audit[df_audit['status'].isin(filter_status)]
        
        st.dataframe(
            df_audit[['timestamp', 'actor', 'action', 'target', 'status', 'justification', 'event_id']], 
            use_container_width=True,
            hide_index=True
        )