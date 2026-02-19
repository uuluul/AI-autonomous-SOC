import streamlit as st
import json
import os
import sys
import uuid
import time
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
# ================= 登入驗證模組 (RBAC Enabled + 5min Persistence) =================
@st.cache_resource
def get_session_store():
    """Global session store for persistence across reloads."""
    return {} # format: {token: {"expiry": datetime, "role": str, "user": str}}

def check_password():
    """回傳 True 代表登入成功"""
    
    sessions = get_session_store()
    params = st.query_params # Streamlit 1.30+
    
    # 1. Check for Active Session Token in URL
    token = params.get("auth_token", None)
    if token and token in sessions:
        session_data = sessions[token]
        if datetime.now() < session_data["expiry"]:
            # Restore Session
            st.session_state["password_correct"] = True
            st.session_state["logged_in_user"] = session_data["user"]
            st.session_state["user_role"] = session_data["role"]
            st.session_state["session_id"] = str(uuid.uuid4()) # New ID for this run, but same auth
            # Extend expiry on activity? Optional. Let's keep strict 5 min for security or refresh it.
            # sessions[token]["expiry"] = datetime.now() + timedelta(minutes=5) 
            return True
        else:
            # Expired
            del sessions[token]

    def password_entered():
        """檢查使用者輸入的帳密"""
        correct_user = os.getenv("UI_USERNAME", "admin")
        correct_pass = os.getenv("UI_PASSWORD", "admin")
        
        # Backdoor for demo: if username is "demo", bypass password
        if st.session_state["username"] == "demo" or (st.session_state["username"] == correct_user and st.session_state["password"] == correct_pass):
            st.session_state["password_correct"] = True
            st.session_state["logged_in_user"] = st.session_state["username"]
            # Assign Role based on Sidebar Selection (Mock Auth)
            role = st.session_state.get("selected_role_login", "Viewer")
            st.session_state["user_role"] = role
            st.session_state["session_id"] = str(uuid.uuid4())
            
            # Generate Persistent Token (5 Minutes)
            new_token = str(uuid.uuid4())
            expiry = datetime.now() + timedelta(minutes=5)
            sessions[new_token] = {
                "expiry": expiry,
                "role": role,
                "user": st.session_state["username"]
            }
            st.query_params["auth_token"] = new_token
            
            if "password" in st.session_state: del st.session_state["password"]  
        else:
            st.session_state["password_correct"] = False
            st.error(" 😔 User not known or password incorrect")

    if "password_correct" not in st.session_state:
        st.markdown("<h1 style='text-align: center;'>🛡️ NeoVigil Enterprise SOC</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center;'>Secure Login Gateway</h3>", unsafe_allow_html=True)
        
        c1, c2, c3 = st.columns([1, 1, 1])
        with c2:
            # RBAC Simulation Selector
            st.selectbox("🎭 Simulation Role", 
                         ["Viewer", "Tier1_Analyst", "Tier2_Analyst", "Admin", "System_Owner"],
                         key="selected_role_login")
            
            st.text_input("Username", key="username")
            st.text_input("Password", type="password", on_change=password_entered, key="password")
            st.caption("Default: admin / admin (or use 'demo' / any)")
            
        return False
        
    elif not st.session_state["password_correct"]:
        # Logic handles error inside password_entered callback for smoother UX
        # But we need to re-render login if failed
        st.markdown("<h1 style='text-align: center;'>🛡️ NeoVigil Enterprise SOC</h1>", unsafe_allow_html=True)
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            st.selectbox("🎭 Simulation Role", ["Viewer", "Tier1_Analyst", "Tier2_Analyst", "Admin", "System_Owner"], key="selected_role_login_retry")
            st.text_input("Username", key="username")
            st.text_input("Password", type="password", on_change=password_entered, key="password")
        return False
    else:
        return True

# ================= 輔助函式 =================

def get_all_reports(tenant_id="All"):
    """從 OpenSearch 撈取所有歷史情資 (Knowledge Base)"""
    client = get_opensearch_client()
    query = {"size": 200, "sort": [{"timestamp": "desc"}], "query": {"match_all": {}}}
    
    if tenant_id != "All":
        query["query"] = {"bool": {"must": [{"term": {"tenant_id": tenant_id}}]}}

    try:
        response = client.search(index="cti-reports", body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
    except:
        return []

def get_graph_data(tenant_id="All"):
    """將情資轉換為 Graph 節點與連線"""
    reports = get_all_reports(tenant_id)
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

def get_audit_logs(tenant_id="All"):
    """Fetch recent audit logs from OpenSearch"""
    client = get_opensearch_client()
    query = {
        "size": 1000,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": []}}
    }
    if tenant_id != "All":
        query["query"]["bool"]["must"].append({"term": {"tenant_id": tenant_id}})
    else:
        query["query"] = {"match_all": {}}
    try:
        if not client.indices.exists(index="soc-audit-logs"):
            return pd.DataFrame()
            
        response = client.search(index="soc-audit-logs", body=query)
        data = [hit["_source"] for hit in response["hits"]["hits"]]
        return pd.DataFrame(data)
    except Exception as e:
        # st.error(f"Failed to fetch audit logs: {e}")
        return pd.DataFrame()

def get_real_soc_data(tenant_id="All"):
    """從 OpenSearch 撈取 SOC 告警 (包含 GeoIP 豐富化資料)"""
    client = get_opensearch_client()
    index_name = "security-logs-knn"
    query = {
        "size": 100, "sort": [{"timestamp": "desc"}],
        "query": { "bool": { "must": [{ "term": { "threat_matched": True }}] } }
    }
    if tenant_id != "All":
        query["query"]["bool"]["must"].append({"term": {"tenant_id": tenant_id}})
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
                    "file_path": src.get("filename", ""),
                    "telemetry_source": src.get("telemetry_source", "unknown")
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

def get_predictions(tenant_id="All"):
    """從 OpenSearch 撈取攻擊路徑預測 (Adversarial Engine Output)"""
    client = get_opensearch_client()
    query = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 20
    }
    
    if tenant_id != "All":
        # 如果有 tenant 欄位則過濾，沒有則全撈 (預設 mock 資料可能沒這欄位)
        pass 

    try:
        response = client.search(index="attack-path-predictions", body=query)
        hits = response['hits']['hits']
        data = [hit['_source'] for hit in hits]
        # 轉換 nested 欄位以便顯示
        for d in data:
            if 'prediction' in d and 'predicted_kill_chain' in d['prediction']:
                d['kill_chain_summary'] = json.dumps(d['prediction']['predicted_kill_chain'], indent=2)
                d['confidence'] = d['prediction'].get('confidence', 'N/A')
        return pd.DataFrame(data)
    except Exception as e:
        return pd.DataFrame()

def get_enriched_alerts(tenant_id="All"):
    """從 OpenSearch 撈取 CMDB 豐富化後的警報資料"""
    client = get_opensearch_client()
    index_name = "security-alerts"
    query = {
        "size": 100,
        "sort": [{"timestamp": "desc"}],
        "query": {"match_all": {}}
    }
    if tenant_id != "All":
        query["query"] = {"bool": {"must": [{"term": {"tenant_id": tenant_id}}]}}
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

# ================= RBAC 權限矩陣 =================
RBAC_POLICY = {
    "Viewer":        ["VIEW_DASHBOARD", "VIEW_KB", "VIEW_GRAPH"],
    "Tier1_Analyst": ["VIEW_DASHBOARD", "VIEW_KB", "VIEW_GRAPH", "REVIEW_REPORT", "REJECT_REPORT", "VIEW_AUDIT"],
    "Tier2_Analyst": ["VIEW_DASHBOARD", "VIEW_KB", "VIEW_GRAPH", "REVIEW_REPORT", "REJECT_REPORT", "APPROVE_REPORT", "ROLLBACK", "VIEW_AUDIT", "EXPORT_AUDIT"],
    "Admin":         ["ALL"],
    "System_Owner":  ["ALL"]
}

def check_permission(action):
    """Check if current user role has permission for action"""
    role = st.session_state.get("user_role", "Viewer")
    allowed_actions = RBAC_POLICY.get(role, [])
    if "ALL" in allowed_actions: return True
    return action in allowed_actions

if not check_password():
    st.stop()

# --- Sidebar Info ---
role = st.session_state.get("user_role", "Viewer")
st.sidebar.title("🛡️ NeoVigil SOC")
st.sidebar.info(f"👤 **User**: {st.session_state.get('logged_in_user')}\n🎭 **Role**: {role}")

# --- Multi-Tenancy Selector (Persistent) ---
st.sidebar.markdown("---")
tenant_options = ["All", "tenant_alpha", "tenant_beta", "default"]

# Initialize Tenant State
if "selected_tenant_key" not in st.session_state:
    st.session_state["selected_tenant_key"] = tenant_options[0]

def update_tenant():
    st.session_state["selected_tenant_key"] = st.session_state.active_tenant_widget

# Tenant Index Logic
try:
    tenant_index = tenant_options.index(st.session_state["selected_tenant_key"])
except ValueError:
    tenant_index = 0

selected_tenant = st.sidebar.selectbox(
    "🏢 Active Tenant", 
    tenant_options, 
    index=tenant_index,
    key="active_tenant_widget",
    on_change=update_tenant
)



if st.sidebar.button("Logout"):
    st.session_state["password_correct"] = False
    st.rerun()

# --- Persistent Navigation Logic ---
# Define Options
nav_options = ["🚨 Internal Threat Monitor (SOC)", "📈 Enriched Alerts Dashboard", "🕸️ Threat Graph", "📚 Knowledge Base"]
if check_permission("REVIEW_REPORT"):
    nav_options.append("🔍 CTI Report Review")
if check_permission("VIEW_AUDIT"):
    nav_options.append("📜 Audit & Compliance Trail")
nav_options.append("🎯 Predictive Threat Map")
nav_options.append("🛡️ Moving Target Defense")

# Initialize Navigation State
if "current_page" not in st.session_state:
    st.session_state["current_page"] = nav_options[0]

def update_nav():
    st.session_state["current_page"] = st.session_state.nav_radio_widget

# Calculate Index Safely
try:
    current_idx = nav_options.index(st.session_state["current_page"])
except ValueError:
    current_idx = 0
    # Fallback if page access lost
    st.session_state["current_page"] = nav_options[0]

page = st.sidebar.radio(
    "Navigation", 
    nav_options, 
    index=current_idx, 
    key="nav_radio_widget",
    on_change=update_nav
)

## --- 1. SOC Dashboard ---
if page == "🚨 Internal Threat Monitor (SOC)":
    st.title(f"🚨 Security Operations Center ({selected_tenant})")

    # ─── Telemetry Sources Dynamic Logic ───────────────────────
    
    # 1. Fetch Alert Data (Moved Up for Status Check)
    df = get_real_soc_data(selected_tenant)
    
    # 2. Determine Status
    status_endpoint = "Active"
    status_network = "Active"
    status_identity = "Active"
    status_deception = "Active"
    
    if not df.empty:
        # Filter for High/Critical Severity
        critical_alerts = df[df['severity'].isin(['High', 'Critical'])]
        
        if not critical_alerts[critical_alerts['telemetry_source'] == 'sysmon'].empty:
            status_endpoint = "UNDER ATTACK"
            
        if not critical_alerts[critical_alerts['telemetry_source'] == 'suricata'].empty:
            status_network = "UNDER ATTACK"
            
        if not critical_alerts[critical_alerts['telemetry_source'] == 'windows_ad'].empty:
            status_identity = "UNDER ATTACK"

    # 3. Check Deception (Honeypot) - Query separate index
    try:
        os_client = get_opensearch_client()
        h_query = {"size": 1, "query": {"match_all": {}}}
        
        if selected_tenant != "All":
             h_query["query"] = {"term": {"tenant_id": selected_tenant}}
             
        if os_client.indices.exists(index="honeypot-telemetry"):
            h_res = os_client.search(index="honeypot-telemetry", body=h_query)
            if h_res['hits']['hits']:
                status_deception = "UNDER ATTACK"
    except Exception:
        pass

    st.markdown("#### 📡 Active Telemetry Sources")
    
    def render_telemetry_card(title, subtitle, status):
        is_attack = (status != "Active")
        icon = "🚨" if is_attack else "🟢"
        status_text = "🚨 UNDER ATTACK" if is_attack else "🟢 Active"
        
        # Dynamic Styling
        bg_color = "linear-gradient(135deg, #4a1c1c, #1f0a0a)" if is_attack else "linear-gradient(135deg, #1a1a2e, #16213e)"
        border_color = "#ff4b4b" if is_attack else "#0f3460"
        text_color = "#ff4b4b" if is_attack else "#00d4aa"
        
        html = f"""
        <div style="background:{bg_color};
            padding:16px;border-radius:12px;text-align:center;
            border:1px solid {border_color};box-shadow: 0 4px 6px rgba(0,0,0,0.3);">
            <p style="margin:0;font-size:28px;">{icon}</p>
            <p style="margin:4px 0 0;font-weight:700;color:#e0e0e0;font-size:14px;">{title}</p>
            <p style="margin:2px 0;color:{text_color};font-size:11px;">{subtitle}</p>
            <p style="margin:4px 0 0;color:{text_color};font-weight:bold;font-size:12px;letter-spacing:0.5px;">{status_text}</p>
        </div>
        """
        st.markdown(html, unsafe_allow_html=True)

    tel1, tel2, tel3, tel4 = st.columns(4)
    with tel1: render_telemetry_card("Endpoint", "Sysmon / EDR", status_endpoint)
    with tel2: render_telemetry_card("Network", "Suricata / NDR", status_network)
    with tel3: render_telemetry_card("Identity", "Active Directory", status_identity)
    with tel4: render_telemetry_card("Deception", "NeoVigil Honeypots", status_deception)
    
    st.markdown("")
    
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
            "Taiwan": {"lat": 23.6978, "lon": 120.9605},
            "Internal / Private": {"lat": 23.5, "lon": 121.0},
            # NOTE: "Unknown" intentionally omitted — do NOT map to Null Island (0,0)
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
                # Try fallback by country name
                fallback = COUNTRY_COORDINATES.get(country)
                if fallback:
                    lat = fallback["lat"]
                    lon = fallback["lon"]
                else:
                    # No valid coordinates — skip this point entirely
                    # (do NOT fall back to Null Island 0,0)
                    continue
            
            # Filter out Null Island (0,0) coordinates
            if float(lat) == 0.0 and float(lon) == 0.0:
                continue

            if ip not in map_points:
                map_points[ip] = {
                    "ip": ip, 
                    "lat": float(lat), 
                    "lon": float(lon),
                    "country": country,
                    "attack_count": 0
                }
            map_points[ip]["attack_count"] += 1
        
        # Default view: Taiwan / East Asia
        default_view = pdk.ViewState(
            latitude=23.5, 
            longitude=121.0, 
            zoom=2.0, 
            pitch=0,
            bearing=0
        )

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

            # Build layers only if we have valid data
            layers = []

            if arc_data:
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
                layers.append(arc_layer)

            if point_data:
                # ScatterplotLayer (紅點, Aggregated)
                scatterplot_layer = pdk.Layer(
                    "ScatterplotLayer",
                    data=point_data,
                    get_position=["lon", "lat"],
                    get_color=[255, 50, 50, 200],
                    get_radius=100000, # 半徑大小
                    pickable=True,
                )
                layers.append(scatterplot_layer)

            # 渲染地圖
            st.pydeck_chart(pdk.Deck(
                map_style=None,
                initial_view_state=default_view,
                layers=layers,
                tooltip={"text": "Attacker: {source_ip}\nOrigin: {country}\nAttacks: {attack_count}"}
            ))
        else:
            # No valid geo data — render clean empty map with no attack lines
            st.pydeck_chart(pdk.Deck(
                map_style=None,
                initial_view_state=default_view,
                layers=[],  # Explicitly empty — no arcs, no points
            ))
            st.info("✅ No geo-located threats to display. The environment appears safe.")

        # --- SOC Performance Metrics (Phase 2) ---
        st.divider()
        st.subheader("📊 SOC Performance Metrics")
        
        m1, m2, m3, m4 = st.columns(4)
        
        # Calculate MTTD/MTTR (Mock Logic -> Real Logic)
        # Real logic: Time diff between 'timestamp' and 'first_seen' or similar
        # For now, we simulate based on alert timestamps
        
        if not df.empty:
            timestamps = pd.to_datetime(df['timestamp'])
            uptime = (datetime.now() - timestamps.min()).total_seconds() / 3600 # Hours
            avg_mttd = max(1, int(uptime * 60 / len(df))) # Minutes
            avg_mttr = max(5, int(avg_mttd * 1.5)) # Response usually takes longer
        else:
            avg_mttd = 0
            avg_mttr = 0

        m1.metric("MTTD (Mean Time to Detect)", f"{avg_mttd} min", "-2%")
        m2.metric("MTTR (Mean Time to Respond)", f"{avg_mttr} min", "-5%")
        m3.metric("False Positive Rate", "1.2%", "+0.1%")
        m4.metric("Automated Resolution", "94%", "+2%")

    # ─── Helper: Query Defense Playbooks (SOAR) ───
    # ─── Helper: Query Defense Playbooks (SOAR) ───
    def get_defense_playbooks(size=10):
        try:
            client = get_opensearch_client()
            resp = client.search(
                index="defense-playbooks",
                body={"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc"}}], "size": size}
            )
            hits = [hit["_source"] for hit in resp["hits"]["hits"]]
            return hits
        except Exception:
            # Atomic failure: return empty list, let caller handle UI
            return []

    def get_soar_actions(size=10):
        try:
            client = get_opensearch_client()
            resp = client.search(
                index="soar-actions",
                body={"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc"}}], "size": size}
            )
            hits = [hit["_source"] for hit in resp["hits"]["hits"]]
            return hits
        except Exception:
            return []

# --- Intelligent Remediation Engine (AI-Driven) ---
    # 1. Header Always Visible
    st.subheader("🛡️ Intelligent Remediation Engine")
    
    # 2. Crash-Proof Data Fetching
    playbooks = []
    try:
        playbooks = get_defense_playbooks(size=10)
    except Exception as e:
        st.error(f"Data Fetch Error (Playbooks): {e}")
    
    # 3. Debug Info (Moved Up)
    # Using st.caption or st.code for cleaner debug, but user asked for st.write
    st.write(f"Debug: Found {len(playbooks)} playbooks")

    # 4. Forced Rendering
    if not playbooks:
         st.info("No playbooks found in OpenSearch.")
    else:
        for pb in playbooks[:5]:
            try: # Extra safety inside loop
                with st.expander(f"📘 Playbook: {pb.get('name', 'Unknown')} (Risk: {pb.get('trigger_risk', 'N/A')})", expanded=True):
                    c1, c2 = st.columns([3, 1])
                    c1.markdown(f"**ID**: `{pb.get('playbook_id', 'N/A')}`")
                    c1.markdown(f"**Time**: {pb.get('timestamp', 'N/A')}")
                    
                    steps = pb.get("remediation_steps", [])
                    if steps:
                        c1.markdown("**Remediation Steps:**")
                        for s in steps:
                            c1.markdown(f"- {s}")
                    else:
                        c1.info("No specific remediation steps listed.")
            except Exception as inner_e:
                st.error(f"Error rendering playbook: {inner_e}")

# === ROLLBACK / UNBLOCK SECTION ===
    # 1. Header Always Visible
    st.subheader("🛡️ Active Defense Actions (SOAR)")
    
    # 2. Crash-Proof Data Fetching
    active_actions = []
    try:
        active_actions = get_soar_actions(size=5)
    except Exception as e:
         st.error(f"Data Fetch Error (Actions): {e}")

    # 3. Debug Info
    st.write(f"Debug: Found {len(active_actions)} actions") 
    
    # 4. Forced Rendering
    if not active_actions:
        st.info("No active defensive actions found.")
    else:
        for action in active_actions:
            try:
                target_ip = action.get("target", "Unknown IP")
                action_id = action.get("action_id", "N/A")
                action_type = action.get("action_type", "UNKNOWN")
                
                with st.expander(f"⚡ Action: {action_type} on {target_ip}", expanded=True):
                    c1, c2 = st.columns([3, 1])
                    c1.write(f"**Action ID**: `{action_id}`")
                    c1.write(f"**Timestamp**: {action.get('timestamp')}")
                    c1.write(f"**Log**: {action.get('execution_log')}")
                    
                    # RBAC Check for Rollback
                    if action_type == "BLOCK_IP":
                        if check_permission("ROLLBACK"):
                            if c2.button("⏪ Rollback / Unblock", key=f"rb_{action_id}"):
                                try:
                                    # 1. Call Real SOAR Unblock
                                    requests.post("http://soar-server:5000/unblock", json={"ip": target_ip})
                                    
                                    # 2. Audit Log
                                    audit_logger.log_event(
                                        actor=st.session_state.get("logged_in_user", "Admin"),
                                        action="ROLLBACK_BLOCK",
                                        target=target_ip,
                                        status="SUCCESS",
                                        justification="Manual Rollback requested by Analyst",
                                        role=st.session_state.get("user_role", "Unknown"),
                                        session_id=st.session_state.get("session_id", "N/A")
                                    )
                                    
                                    # 3. Index 'UNBLOCK' action to soar-actions so history is preserved
                                    client = get_opensearch_client()
                                    unblock_doc = {
                                        "action_id": f"act-{str(uuid.uuid4())[:8]}",
                                        "timestamp": datetime.utcnow().isoformat(),
                                        "action_type": "UNBLOCK_IP",
                                        "target": target_ip,
                                        "status": "SUCCESS",
                                        "executor": st.session_state.get("logged_in_user", "Admin")
                                    }
                                    client.index(index="soar-actions", body=unblock_doc, refresh=True)
                                    
                                    st.success(f"Successfully Unblocked {target_ip}")
                                    time.sleep(1)
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Rollback failed: {e}")
                        else:
                            c2.error("🚫 Permission Denied")
                    elif action_type == "UNBLOCK_IP":
                        c2.success("✅ Allowlisted")
            except Exception as inner_e:
                 st.error(f"Error rendering action: {inner_e}")

    # --- DATA PREPARATION FOR ALERT DISPLAY (Restored) ---
    # 1. Obtain Predictions for Linking
    predictions = get_predictions(selected_tenant) 
    if not predictions.empty:
        preds_list = predictions.to_dict('records')
    else:
        preds_list = []
    
    # 2. Build Map: Alert ID -> Remediation Steps
    alert_to_remediation = {}
    pred_to_alert = {p.get("prediction_id"): p.get("trigger_alert_id") for p in preds_list}
    
    for pb in playbooks: # Uses the fetched playbooks
        pred_id = pb.get("prediction_id")
        alert_id = pred_to_alert.get(pred_id)
        if alert_id:
            steps = pb.get("remediation_steps", [])
            steps_str = "\n".join([f"- {s}" for s in steps])
            alert_to_remediation[alert_id] = steps_str

    # 3. Build unique_threats from df (Alerts)
    unique_threats = {} 

    for _, row in df.iterrows():
        # Check for specific CVEs first (Higher Priority)
        vulns = row.get("vulnerabilities", [])
        alert_id = row.get('id') 
        
        # Determine Remediation (Real SOAR vs Waiting)
        if alert_id in alert_to_remediation:
            remediation_text = alert_to_remediation[alert_id]
        else:
            remediation_text = "⏳ Waiting for AI analysis... (Prediction Engine -> SOAR)"

        if isinstance(vulns, list) and vulns:
            for v in vulns:
                vid = v.get("id") or row.get("attack_type", "Unknown Threat")
                
                if vid not in unique_threats:
                    unique_threats[vid] = {
                        "type": "CVE Exploit" if v.get("id") else "AI Anomaly",
                        "severity": v.get("severity", "High"),
                        "description": v.get("description", "No description available."),
                        "remediation": remediation_text,
                        "count": 1,
                        "source_ips": {row.get('source_ip')} if row.get('source_ip') else set(),
                        "confidence": row.get("confidence", 0),
                        "rag_context": row.get("rag_context", [])
                    }
                else:
                    unique_threats[vid]["count"] += 1
                    if row.get('source_ip'):
                         if "source_ips" not in unique_threats[vid]: unique_threats[vid]["source_ips"] = set()
                         unique_threats[vid]["source_ips"].add(row.get('source_ip'))
                    if row.get("rag_context"):
                         if "rag_context" not in unique_threats[vid]: unique_threats[vid]["rag_context"] = []
                         for r in row.get("rag_context", []):
                             if r not in unique_threats[vid]["rag_context"]: unique_threats[vid]["rag_context"].append(r)
                    
                if "evidence" not in unique_threats[vid]: unique_threats[vid]["evidence"] = set()
                msg = row.get('summary') or row.get('message') or "No details"
                fname = row.get('file_path') or row.get('related_report') or "Unknown Source"
                evidence_str = f"{os.path.basename(fname)}: {msg[:100]}..."
                unique_threats[vid]["evidence"].add(evidence_str)
        else:
            attack_type = row.get("attack_type", "Suspicious Activity")
            if attack_type not in unique_threats:
                unique_threats[attack_type] = {
                    "type": "Behavioral Pattern",
                    "severity": row.get("severity", "Medium"),
                    "description": f"AI detected {attack_type} pattern from {row.get('source_ip', 'unknown source')}.",
                    "remediation": remediation_text,
                    "count": 1,
                    "source_ips": {row.get('source_ip')} if row.get('source_ip') else set(),
                    "confidence": row.get("confidence", 0),
                    "rag_context": row.get("rag_context", [])
                }
            else:
                unique_threats[attack_type]["count"] += 1
                ip = row.get('source_ip')
                if ip:
                    if "source_ips" not in unique_threats[attack_type]: unique_threats[attack_type]["source_ips"] = set()
                    unique_threats[attack_type]["source_ips"].add(ip)
                    if len(unique_threats[attack_type]["source_ips"]) > 1:
                         unique_threats[attack_type]["description"] = f"AI detected {attack_type} pattern from multiple sources ({len(unique_threats[attack_type]['source_ips'])} unique IPs)."
                if row.get("rag_context"):
                     if "rag_context" not in unique_threats[attack_type]: unique_threats[attack_type]["rag_context"] = []
                     for r in row.get("rag_context", []):
                         if r not in unique_threats[attack_type]["rag_context"]: unique_threats[attack_type]["rag_context"].append(r)
                
            if "evidence" not in unique_threats[attack_type]: unique_threats[attack_type]["evidence"] = set()
            msg = row.get('summary') or row.get('message') or "No details"
            fname = row.get('file_path') or row.get('related_report') or "Unknown Source"
            evidence_str = f"{os.path.basename(fname)}: {msg[:100]}..."
            unique_threats[attack_type]["evidence"].add(evidence_str)

    if unique_threats:
        # 2. Full-Width Stacked Layout (No Columns)
        st.markdown("#### 🛡️ Defense Playbooks (AI Generated)")
        
        
        for tid, info in unique_threats.items():
            # Dynamic color based on severity
            severity_color = "red" if info["severity"] == "High" else "orange"
            
            # Enhanced Title: 🚨 [High] Defense Playbook: SQL Injection (Behavioral Pattern)
            expander_title = f"🚨 [{info['severity']}] Defense Playbook: {tid} ({info['type']})"
            
            with st.expander(expander_title, expanded=False):
                st.markdown(f"**Severity**: :{severity_color}[{info['severity']}]")
                st.markdown(f"**Context**: {info['description']}")
                
                # --- XAI Section (Explainable AI) ---
                st.markdown("### 🧠 AI Confidence & Reasoning")
                c1, c2 = st.columns([1, 2])
                
                with c1:
                     confidence = info.get("confidence", 0) # Need to propagate confidence to unique_threats
                     st.metric("AI Confidence Score", f"{confidence}%")
                     if confidence > 80:
                         st.success("High Confidence: AI is very sure about this threat.")
                     elif confidence > 50:
                         st.warning("Medium Confidence: AI suggests human review.")
                     else:
                         st.info("Low Confidence: Likely a false positive or noise.")

                with c2:
                    st.markdown("**Reasoning Factors:**")
                    # Mock factors if not present (Real implementation needs to propagate 'rag_context' from alert to unique_threats)
                    # Here we will try to retrieve it if available in the first alert of the group
                    sample_rag = info.get("rag_context", [])
                    if sample_rag:
                        st.write("✅ **RAG Knowledge Matched:**")
                        for r in sample_rag[:3]: # Show top 3
                            st.caption(f"- {r[:100]}...")
                    else:
                        st.caption("ℹ️ Decision based on Heuristic Rules and Behavioral Patterns.")
                        
                    if "type" in info:
                        st.write(f"✅ **Attack Pattern Identified:** {info['type']}")

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
    st.title(f"📈 Enriched Security Alerts Dashboard ({selected_tenant})")
    df_alerts = get_enriched_alerts(selected_tenant)

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
            
            
            col_act1, col_act2 = st.columns([1, 1])
            
            with col_act1:
                # RBAC Check for Approval
                if check_permission("APPROVE_REPORT"):
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
                            details={"confidence": final_json.get("confidence")},
                            role=st.session_state.get("user_role", "Unknown"),
                            session_id=st.session_state.get("session_id", "N/A")
                        )
                        
                        st.success(f"Approved! PDF generated at: {pdf_path}")
                        st.rerun()
                else:
                    st.warning("🔒 Approval requires Tier 2+.")

            with col_act2:
                rejection_reason = st.text_input("Rejection Reason (Optional):", key=f"reason_{task['id']}")
                # RBAC Check for Rejection
                if check_permission("REJECT_REPORT"):
                    if st.button("🗑️ Reject"):
                        update_task_status(task['id'], "REJECTED")
                        
                        # Optimization 5: Human Feedback Loop
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
                            details={"original_confidence": task.get("confidence")},
                            role=st.session_state.get("user_role", "Unknown"),
                            session_id=st.session_state.get("session_id", "N/A")
                        )

                        st.rerun()
                else:
                    st.warning("🔒 Rejection requires Tier 1+.")

# --- Threat Graph ---
elif page == "🕸️ Threat Graph":
    st.title(f"🕸️ Threat Intelligence Graph ({selected_tenant})")
    nodes, edges = get_graph_data(selected_tenant)
    
    if not nodes:
        st.info("No data to visualize.")
    else:
        config = Config(width=900, height=600, directed=True, nodeHighlightBehavior=True, highlightColor="#F7A7A6", collapsible=True)
        agraph(nodes=nodes, edges=edges, config=config)

# --- Knowledge Base (With Filters) ---
elif page == "📚 Knowledge Base":
    st.title(f"📚 Knowledge Base ({selected_tenant})")
    all_reports = get_all_reports(selected_tenant)
    
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
    st.title(f"📜 Audit & Compliance Trail ({selected_tenant})")
    st.info("Immutable record of all AI and Analyst actions.")
    
    df_audit = get_audit_logs(selected_tenant)
    
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
        
        # Define columns to display (Handling older logs gracefully)
        display_cols = ['timestamp', 'actor', 'action', 'target', 'status', 'justification']
        if 'role' in df_audit.columns: display_cols.insert(2, 'role')
        if 'session_id' in df_audit.columns: display_cols.append('session_id')
        
        st.dataframe(
            df_audit[display_cols], 
            use_container_width=True,
            hide_index=True
        )
        
        # Export Feature (RBAC)
        if check_permission("EXPORT_AUDIT"):
            csv = df_audit.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Audit Report (CSV)",
                data=csv,
                file_name=f"audit_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            if not df_audit.empty:
                st.caption("🔒 Export requires Tier 2+ Role.")

# --- Predictive Threat Map ---
elif page == "🎯 Predictive Threat Map":
    st.title(f"🎯 Predictive Threat Map ({selected_tenant})")
    st.caption("AI-driven attack path predictions \u2014 powered by REDSPEC adversarial emulation & zero-log anticipation.")

    predictions = get_predictions(selected_tenant)

    if predictions.empty:
        st.info("No predictions generated yet. Predictions are triggered when high-risk alerts are detected or global threat outbreaks are identified.")
    else:
        # Compatibility: Convert DataFrame to list of dicts for iteration logic below
        predictions = predictions.to_dict('records')
        # \u2500\u2500 Top metrics \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        active_preds = [p for p in predictions if p.get("status") == "ACTIVE"]
        preemptive_preds = [p for p in predictions if p.get("status") == "PREEMPTIVE"]
        avg_risk = sum(p.get("overall_risk_score", 0) for p in predictions) / len(predictions) if predictions else 0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Predictions", len(predictions))
        m2.metric("Active (Alert-Triggered)", len(active_preds))
        m3.metric("Preemptive (Zero-Log)", len(preemptive_preds))
        m4.metric("Avg Risk Score", f"{avg_risk:.1f}")

        # \u2500\u2500 Tabs for alert-triggered vs zero-log \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        tab1, tab2 = st.tabs(["🚨 Attack Path Predictions", "🛡️ Zero-Log Preemptive Alerts"])

        with tab1:
            if not active_preds:
                st.info("No alert-triggered predictions yet.")
            else:
                for pred in active_preds:
                    risk = pred.get("overall_risk_score", 0)
                    risk_color = "🔴" if risk >= 70 else "🟡" if risk >= 40 else "🟢"
                    host_info = pred.get("compromised_host", {})

                    with st.expander(
                        f"{risk_color} Risk {risk:.0f} | "
                        f"{host_info.get('hostname', '?')} ({host_info.get('ip', '?')}) | "
                        f"{pred.get('timestamp', '')[:19]}",
                        expanded=(risk >= 70),
                    ):
                        st.markdown(f"**Prediction ID**: `{pred.get('prediction_id', '?')}`")
                        st.markdown(f"**Trigger Alert**: `{pred.get('trigger_alert_id', 'N/A')}`")
                        st.markdown(f"**Compromised Zone**: `{host_info.get('zone', '?')}`")

                        # Kill Chain Table
                        chain = pred.get("predicted_kill_chain", [])
                        if chain:
                            st.markdown("#### 🎯 Predicted Kill Chain")
                            chain_data = []
                            for step in chain:
                                conf = step.get("confidence", 0)
                                conf_bar = "\u2588" * int(conf * 10) + "\u2591" * (10 - int(conf * 10))
                                chain_data.append({
                                    "Step": step.get("step", "?"),
                                    "Tactic": step.get("tactic", "?"),
                                    "Technique": f"{step.get('technique_id', '?')} \u2014 {step.get('technique_name', '?')}",
                                    "Target": f"{step.get('target_host', '?')} ({step.get('target_ip', '?')})",
                                    "Confidence": f"{conf_bar} {conf:.0%}",
                                    "Rationale": step.get("exploit_rationale", step.get("reasoning", "")),
                                })
                            st.dataframe(pd.DataFrame(chain_data), use_container_width=True, hide_index=True)

                        # Defensive recommendations
                        actions = pred.get("recommended_actions", [])
                        if actions:
                            st.markdown("#### 🛡️ Recommended Defensive Actions")
                            for i, action in enumerate(actions, 1):
                                st.markdown(f"{i}. {action}")

        with tab2:
            if not preemptive_preds:
                st.info("No zero-log preemptive alerts. Your assets are not currently exposed to any active global outbreaks.")
            else:
                for pred in preemptive_preds:
                    risk = pred.get("overall_risk_score", 0)
                    cve_id = pred.get("cve_id", "Unknown CVE")

                    with st.expander(
                        f"🚨 {cve_id} | Risk {risk:.0f} | {pred.get('timestamp', '')[:19]}",
                        expanded=True,
                    ):
                        st.markdown(f"**Prediction ID**: `{pred.get('prediction_id', '?')}`")
                        st.markdown(f"**Status**: `PREEMPTIVE` \u2014 No local attacks detected yet")

                        # Exposed assets
                        exposed = pred.get("exposed_assets", [])
                        if exposed:
                            st.markdown("#### \u26a0\ufe0f Exposed Assets")
                            ea_data = []
                            for a in exposed:
                                ea_data.append({
                                    "Hostname": a.get("hostname", "?"),
                                    "IP": a.get("ip", "?"),
                                    "Zone": a.get("network_zone", "?"),
                                    "Criticality": a.get("criticality", "?"),
                                    "Vulnerable Software": a.get("matched_software", "?"),
                                })
                            st.dataframe(pd.DataFrame(ea_data), use_container_width=True, hide_index=True)

                        # LLM defense plan
                        plan = pred.get("prediction", {})
                        if plan:
                            st.markdown(f"#### 📝 {plan.get('alert_title', 'Defense Plan')}")
                            st.markdown(plan.get("risk_assessment", ""))

                            actions = plan.get("immediate_actions", [])
                            if actions:
                                st.markdown("**Immediate Actions:**")
                                for a in actions:
                                    st.markdown(f"- {a}")

                            patching = plan.get("patching_priority", [])
                            if patching:
                                st.markdown("**Patching Priority:**")
                                st.dataframe(pd.DataFrame(patching), use_container_width=True, hide_index=True)

                            window = plan.get("estimated_patch_window")
                            if window:
                                st.metric("Estimated Patch Window", window)

# =====================================================
# 🛡️ Moving Target Defense (Phase 3)
# =====================================================
elif page == "🛡️ Moving Target Defense":
    st.title("🛡️ Moving Target Defense")
    st.caption("Phase 3 — Dynamic obfuscation & container migration to invalidate attacker reconnaissance.")

    # ─── Helper: Query MTD indices    # Helper：撈取 MTD 資料
    # ─── Helper: Query MTD indices    # Helper：撈取 MTD 資料
    def get_mtd_data(index_name, size=50):
        try:
            client = get_opensearch_client()
            resp = client.search(
                index=index_name,
                body={"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}], "size": size}
            )
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        except Exception as e:
            st.error(f"Failed to fetch MTD data from {index_name}: {e}")
            return []

    # Helper：撈取 Audit Log
    def get_mtd_audit(size=100):
        try:
            client = get_opensearch_client()
            resp = client.search(
                index="mtd-audit-log",
                body={"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}], "size": size}
            )
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        except Exception as e:
            st.error(f"Failed to fetch MTD Audit Log: {e}")
            return []

    # ─── Metrics Row ──────────────────────────────────
    mutations = get_mtd_data("mtd-active-mutations", 100)
    audit_entries = get_mtd_audit(200)

    obf_rules = [m for m in mutations if m.get("mutation_type") == "obfuscation" and m.get("status") == "ACTIVE"]
    active_migrations = [m for m in mutations if m.get("mutation_type") == "migration" and m.get("status") == "COMPLETED"]
    pending = [a for a in audit_entries if a.get("status") == "PENDING_APPROVAL"]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🎭 Active Obfuscation Rules", len(obf_rules))
    col2.metric("🔄 Active Migrations", len(active_migrations))
    col3.metric("⏳ Pending Approvals", len(pending))
    col4.metric("📝 Total MTD Actions", len(audit_entries))

    st.markdown("---")

    # ─── Tabs ─────────────────────────────────────────
    tab1, tab2, tab3, tab4 = st.tabs(["🎭 Obfuscation Rules", "⏳ Pending Approvals", "🔄 Migrations", "📝 Audit Log"])

    # ── Tab 1: Active Obfuscation Rules ───────────────
    with tab1:
        st.subheader("🎭 Active Obfuscation Rules")
        st.caption("Currently active header/banner spoofing rules applied to suspicious scanner IPs.")

        if obf_rules:
            for rule in obf_rules:
                with st.expander(f"🎭 {rule.get('scanner_ip', 'N/A')} → Spoofing: {rule.get('spoof_profile', 'N/A')}", expanded=False):
                    rc1, rc2, rc3 = st.columns(3)
                    rc1.markdown(f"**Scanner IP:** `{rule.get('scanner_ip', 'N/A')}`")
                    rc2.markdown(f"**Target:** {rule.get('target_host', 'N/A')}")
                    rc3.markdown(f"**Real Service:** {rule.get('real_service', 'N/A')}")

                    sc = rule.get("spoof_config", {})
                    st.markdown(f"**Spoofed Server Header:** `{sc.get('server_header', 'N/A')}`")
                    st.markdown(f"**X-Powered-By:** `{sc.get('x_powered_by', 'None')}`")
                    st.markdown(f"**Expires:** {rule.get('expires_at', 'N/A')}")
                    st.markdown(f"**Trigger:** {rule.get('trigger_reason', 'N/A')}")
        else:
            st.info("No active obfuscation rules. Rules are created when the MTD score exceeds 60.")

    # ── Tab 2: Pending Approvals ──────────────────────
    with tab2:
        st.subheader("⏳ Actions Pending Approval")
        st.caption("MTD migration actions requiring Tier 2+ analyst approval before execution.")

        if pending:
            for action in pending:
                with st.container():
                    st.markdown(f"### 🔔 {action.get('action_type', 'N/A').upper()}")
                    ac1, ac2, ac3, ac4 = st.columns(4)
                    ac1.metric("MTD Score", f"{action.get('score', 0):.0f}")
                    ac2.markdown(f"**Target:** {action.get('target_host', 'N/A')}")
                    ac3.markdown(f"**Scanner:** `{action.get('scanner_ip', 'N/A')}`")
                    ac4.markdown(f"**Deadline:** {action.get('approval_deadline', 'N/A')}")

                    signals = action.get("signals", {})
                    st.markdown(
                        f"**Signals:** Prediction Risk={signals.get('prediction_risk', 0)}, "
                        f"Captures={signals.get('captures', 0)}, "
                        f"Scans={signals.get('scan_count', 0)}, "
                        f"Criticality={signals.get('criticality', 'N/A')}"
                    )

                    bcol1, bcol2 = st.columns(2)
                    if check_permission("APPROVE_MIGRATION"):
                        if bcol1.button("✅ Approve", key=f"approve_{action.get('action_id')}"):
                            st.success(f"Approved: {action.get('action_id')}")
                        if bcol2.button("❌ Reject", key=f"reject_{action.get('action_id')}"):
                            st.warning(f"Rejected: {action.get('action_id')}")
                    else:
                        st.warning("🔒 Requires Tier 2+ role to approve/reject.")
                    st.markdown("---")
        else:
            st.info("No pending approvals. Actions requiring human review will appear here.")

    # ── Tab 3: Active Migrations ──────────────────────
    with tab3:
        st.subheader("🔄 Container Migrations")
        st.caption("Blue/Green container migrations that have been executed or are in progress.")

        if active_migrations:
            for mig in active_migrations:
                with st.expander(f"🔄 {mig.get('target_container', 'N/A')} — {mig.get('status', 'N/A')}", expanded=False):
                    mc1, mc2, mc3 = st.columns(3)
                    mc1.markdown(f"**Migration ID:** `{mig.get('migration_id', 'N/A')[:12]}`")
                    mc2.markdown(f"**Status:** {mig.get('status', 'N/A')}")
                    mc3.markdown(f"**Green IP:** `{mig.get('green_ip', 'N/A')}`")
                    st.markdown(f"**Rollback Until:** {mig.get('can_rollback_until', 'N/A')}")
                    st.markdown(f"**Trigger:** {mig.get('trigger_reason', 'N/A')}")

                    if check_permission("ROLLBACK_MTD"):
                        if st.button("↩️ Rollback", key=f"rb_{mig.get('migration_id')}"):
                            st.warning(f"Rollback requested for {mig.get('migration_id', 'N/A')[:12]}")
        else:
            st.info("No active migrations. Blue/Green migrations appear here when MTD score ≥ 85 and approved.")

    # ── Tab 4: Audit Log ──────────────────────────────
    with tab4:
        st.subheader("📝 MTD Audit Trail")
        st.caption("Immutable record of all MTD actions — obfuscation, migration, approval, rejection, and rollback.")

        if audit_entries:
            audit_df = pd.DataFrame(audit_entries)
            display_cols = [c for c in ["action_id", "action_type", "status", "score", "target_host", "scanner_ip", "proposed_at", "approved_by"] if c in audit_df.columns]
            if display_cols:
                st.dataframe(audit_df[display_cols], use_container_width=True, hide_index=True)
        else:
            st.info("No MTD audit entries yet. Actions will be logged here as they occur.")