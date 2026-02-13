import os
import logging
import hashlib
from datetime import datetime, timedelta
from dotenv import load_dotenv
from opensearchpy import OpenSearch, RequestsHttpConnection


load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OpenSearch 連線設定
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch-node")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "Admin123!")

# 定義 Index 名稱
INDEX_LOGS_KNN = "security-logs-knn"
INDEX_CTI_REPORTS = "cti-reports"
INDEX_CTI_INDICATORS = "cti-indicators"
INDEX_ALERTS = "security-alerts"

def get_opensearch_client():
    host = os.getenv("OPENSEARCH_HOST", "opensearch-node")
    port = int(os.getenv("OPENSEARCH_PORT", 9200))
    user = os.getenv("OPENSEARCH_USER", "admin")
    password = os.getenv("OPENSEARCH_PASSWORD", "admin")

    connection_kwargs = {
        "hosts": [{'host': host, 'port': port}],
        "http_compress": True,
        "use_ssl": False,
        "verify_certs": False,
        "ssl_show_warn": False,
        "connection_class": RequestsHttpConnection
    }

    if user and password:
        connection_kwargs["http_auth"] = (user, password)

    return OpenSearch(**connection_kwargs)

def create_index():
    """主函式：建立所有需要的 Indexes"""
    client = get_opensearch_client()
    create_knn_index(client)
    create_reports_index(client)
    create_alerts_index(client)

def create_knn_index(client):
    """建立 Log 向量搜尋用的 Index"""
    index_body = {
        "settings": {
            "index": {
                "knn": True,
                "knn.algo_param.ef_search": 100
            }
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "log_text": {"type": "text"},
                "log_vector": {
                    "type": "knn_vector",
                    "dimension": 1536,
                    "method": {
                        "name": "hnsw",
                        "space_type": "cosinesimil",
                        "engine": "lucene",
                        "parameters": {"ef_construction": 128, "m": 24}
                    }
                },
                "log_source": {"type": "keyword"},
                "threat_matched": {"type": "boolean"},
                "confidence": {"type": "integer"},
                "source_type": {"type": "keyword"},
                "indicators": {"properties": {"ipv4": {"type": "keyword"}}}
            }
        }
    }
    _create_if_not_exists(client, INDEX_LOGS_KNN, index_body)

def create_reports_index(client):
    """建立存放 CTI 分析報告的 Index"""
    index_body = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "filename": {"type": "keyword"},
                "confidence": {"type": "integer"},
                "indicators": {"type": "object"},
                "ttps": {"type": "object"},
                "threat_matched": {"type": "boolean"},
                "source_type": {"type": "keyword"},
                "related_reports": {"type": "keyword"}
                
            }
        }
    }
    _create_if_not_exists(client, INDEX_CTI_REPORTS, index_body)

def create_alerts_index(client):
    """建立存放豐富化警報的 Index"""
    index_body = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "rule_name": {"type": "keyword"},
                "asset_hostname": {"type": "keyword"},
                "asset_department": {"type": "keyword"},
                "asset_criticality": {"type": "keyword"},
                "status": {"type": "keyword"},
                "log_excerpt": {"type": "text"}
            }
        }
    }
    _create_if_not_exists(client, INDEX_ALERTS, index_body)

def _create_if_not_exists(client, index_name, body):
    if not client.indices.exists(index=index_name):
        try:
            client.indices.create(index=index_name, body=body)
            logger.info(f"  Index '{index_name}' created successfully.")
        except Exception as e:
            logger.error(f"  Failed to create index '{index_name}' : {e}")
    else:
        logger.info(f"   Index '{index_name}' already exists. Skipping.")

def upload_to_opensearch(doc_body, doc_id=None, index_name=INDEX_CTI_REPORTS):
    """通用上傳函式"""
    client = get_opensearch_client()
    try:
        response = client.index(index=index_name, body=doc_body, id=doc_id, refresh=True)
        logger.info(f"  Upload success to {index_name} (ID: {response['_id']})")
        return True
    except Exception as e:
        logger.error(f"  Upload failed: {e}")
        return False

def upsert_indicator(indicator_value, indicator_type, report_data):
    """
    去重邏輯：使用 MD5 作為文件 ID。
    如果指標已存在，更新 last_seen 並延長過期時間；若不存在則新增。
    """
    client = get_opensearch_client()
    index_name = INDEX_CTI_INDICATORS
    
    # 產生唯一 ID (對值進行雜湊)
    doc_id = hashlib.md5(indicator_value.lower().encode()).hexdigest()
    
    # 計算新的過期時間 (從現在起算 30 天)
    new_expiry = (datetime.now() + timedelta(days=30)).isoformat()
    now_str = datetime.now().isoformat()
    
    # 定義更新腳本
    update_body = {
        "script": {
            "source": """
                ctx._source.last_seen = params.now;
                ctx._source.expiration_date = params.expiry;
                if (!ctx._source.related_reports.contains(params.report)) {
                    ctx._source.related_reports.add(params.report);
                }
            """,
            "params": {
                "now": now_str,
                "expiry": new_expiry,
                "report": report_data.get("filename", "Unknown")
            }
        },
        "upsert": {
            "value": indicator_value,
            "type": indicator_type,
            "first_seen": now_str,
            "last_seen": now_str,
            "expiration_date": new_expiry,
            "related_reports": [report_data.get("filename", "Unknown")],
            "confidence": report_data.get("confidence", 50)
        }
    }
    
    try:
        client.update(index=index_name, id=doc_id, body=update_body, refresh=True)
        logger.info(f"  Indicator upserted: {indicator_value}")
    except Exception as e:
        # 如果索引未建立，直接寫入第一筆資料
        try:
            client.index(index=index_name, id=doc_id, body=update_body["upsert"], refresh=True)
            logger.info(f"  Indicator created (Fallback): {indicator_value}")
        except Exception as create_err:
             logger.error(f"  Failed to upsert indicator: {create_err}")

if __name__ == "__main__":
    create_index()