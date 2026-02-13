# src/cmdb_mock.py

# 模擬公司內部資產資料庫
ASSET_DB = {
    "192.168.1.105": {
        "hostname": "Web-Prod-Server-01",
        "owner": "Manager",
        "department": "IT_Infrastructure",
        "criticality": "CRITICAL",
        "description": "Core public-facing web server"
    },
    "192.168.1.5": {
        "hostname": "Admin-Workstation-05",
        "owner": "Admin_Manager",
        "department": "Management",
        "criticality": "HIGH",
        "description": "Executive management workstation"
    },
    "192.168.1.200": {
        "hostname": "Dev-Test-Box",
        "owner": "Intern_Alice",
        "department": "R&D",
        "criticality": "LOW",
        "description": "Development testing sandbox"
    }
}

def get_asset_context(ip):
    """
    根據 IP 查詢內部資產詳細資訊
    """
    # 如果在資料庫中找不到，回傳預設的「未知/外部資產」資訊
    return ASSET_DB.get(ip, {
        "hostname": "Unknown_Host",
        "owner": "Unknown",
        "department": "External_Network",
        "criticality": "MEDIUM",
        "description": "External host or unmanaged asset"
    })