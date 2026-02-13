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
    query = {"size": 50, "sort": [{"timestamp": "desc"}], "query": {"match_all": {}}}
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

page = st.sidebar.radio("Navigation", ["🚨 Internal Threat Monitor (SOC)", "📈 Enriched Alerts Dashboard", "🔍 CTI Report Review", "🕸️ Threat Graph", "📚 Knowledge Base"])

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
        
        # 準備地圖資料
        map_points = []
        for idx, row in df.iterrows():
            lat = row.get('lat')
            lon = row.get('lon')
            if lat and lon and not (pd.isna(lat) or pd.isna(lon)):
                map_points.append({
                    "ip": row['source_ip'], 
                    "lat": float(lat), 
                    "lon": float(lon),
                    "country": row.get('country', 'Unknown')
                })
        
        if map_points:
            # 定義防禦目標 (預設：台灣)
            TARGET_COORDS = [121.5, 25.0] 
            
            # 準備連線資料
            arc_data = []
            for p in map_points:
                arc_data.append({
                    "source_ip": p["ip"],
                    "source_coords": [p["lon"], p["lat"]],
                    "target_coords": TARGET_COORDS,
                    "country": p["country"]
                })

            # 低弧度飛行路徑
            arc_layer = pdk.Layer(
                "ArcLayer",
                data=arc_data,
                get_source_position="source_coords",
                get_target_position="target_coords",
                get_source_color=[255, 50, 50, 150], # 紅色半透明
                get_target_color=[0, 255, 100, 150], # 綠色半透明
                get_width=2,
                pickable=True,
                great_circle=False, # 2D 平面線條
                get_height=0.5,   # 如果覺得線還是太低，可以註解這行來拉高它
            )

            # ScatterplotLayer (紅點)
            scatterplot_layer = pdk.Layer(
                "ScatterplotLayer",
                data=map_points,
                get_position=["lon", "lat"],
                get_color=[255, 50, 50, 200],
                get_radius=100000, # 半徑大小
                pickable=True,
            )

            # 渲染地圖
            st.pydeck_chart(pdk.Deck(
                map_style=None, # 或 "mapbox://styles/mapbox/dark-v10" (如果有 Token)
                initial_view_state=pdk.ViewState(
                    latitude=20, 
                    longitude=100, 
                    zoom=1.2, 
                    pitch=0,   # 預設為 0 確保是平面視角
                    bearing=0
                ),
                layers=[arc_layer, scatterplot_layer],
                tooltip={"text": "Attacker: {source_ip}\nOrigin: {country}"}
            ))
        else:
            st.warning("Threats detected but no GeoIP data available.")

        # --- 漏洞分析表格區塊 ---
        st.subheader("🛡️ Vulnerability & Remediation")
        
        all_vulns = []
        for _, row in df.iterrows():
            vulns = row.get("vulnerabilities", [])
            if isinstance(vulns, list):
                all_vulns.extend(vulns)

        if all_vulns:
            vuln_df = pd.DataFrame(all_vulns)
            
            if "id" in vuln_df.columns:
                vuln_df = vuln_df.drop_duplicates(subset=['id'])

            # 欄位改名
            vuln_df = vuln_df.rename(columns={
                "id": "ID",
                "severity": "Severity",
                "description": "Description",
                "remediation": "Remediation"
            })

            display_cols = ["ID", "Severity", "Description", "Remediation"]
            final_df = vuln_df[[c for c in display_cols if c in vuln_df.columns]]

            # --- CSS ---
            st.markdown("""
            <style>
            table {
                width: 100% !important;
                table-layout: fixed !important;
                border-collapse: collapse !important;
            }
            
            /* 1. 隱藏第一欄 (Index) - 包含標題與內容 */
            th:nth-child(1), td:nth-child(1) {
                display: none !important;
                width: 0px !important;
            }

            /* 2. ID (實際上的第2欄) - 單行 */
            th:nth-child(2), td:nth-child(2) {
                width: 15% !important;
                white-space: nowrap !important;
                overflow: hidden !important;
                text-overflow: ellipsis !important;
                vertical-align: top !important;
            }

            /* 3. Severity (實際上的第3欄) - 單行 */
            th:nth-child(3), td:nth-child(3) {
                width: 10% !important;
                white-space: nowrap !important;
                vertical-align: top !important;
            }

            /* 4. Description (實際上的第4欄) - 多行，37.5% */
            th:nth-child(4), td:nth-child(4) {
                width: 37.5% !important;
                white-space: normal !important; /* 允許換行 */
                word-wrap: break-word !important;
                vertical-align: top !important;
            }

            /* 5. Remediation (實際上的第5欄) - 多行，37.5% */
            th:nth-child(5), td:nth-child(5) {
                width: 37.5% !important;
                white-space: normal !important; /* 允許換行 */
                word-wrap: break-word !important;
                vertical-align: top !important;
            }
            </style>
            """, unsafe_allow_html=True)

            st.table(final_df)
            
        else:
            st.info("No known CVE vulnerability correlations detected in current incidents.")

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
            
            st.success(f"Approved! PDF generated at: {pdf_path}")
            st.rerun()

        if st.button("🗑️ Reject"):
            update_task_status(task['id'], "REJECTED")
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