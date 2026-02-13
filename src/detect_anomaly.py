# src/detect_anomaly.py
import os
import random
import numpy as np
from dotenv import load_dotenv
from opensearchpy import OpenSearch
from .llm_client import LLMClient

load_dotenv()
llm = LLMClient()
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False
)

index_name = "security-logs-knn"

# ---- kNN 參數 ----
K = 5                  # 可調整 資料多時可改 20
CALIB_SAMPLE_N = 200   # 校準 threshold 時抽樣數
QUANTILE = 0.95        # P95 資料多可改P99


def _build_knn_query(query_vector, k=K, size=K, filters=None, exclude_id=None):
    """
    建立 kNN 查詢 + 可選 filter + 可選排除某 doc（避免自比對）
    """
    knn_part = {
        "knn": {
            "log_vector": {
                "vector": query_vector,
                "k": k
            }
        }
    }

    # 排除自己那筆 baseline
    must_not = []
    if exclude_id:
        must_not.append({"ids": {"values": [exclude_id]}})

    if filters:
        return {
            "size": size,
            "query": {
                "bool": {
                    "filter": [{"term": {k: v}} for k, v in filters.items()],
                    "must": knn_part,
                    "must_not": must_not
                }
            }
        }

    if must_not:
        return {
            "size": size,
            "query": {
                "bool": {
                    "must": knn_part,
                    "must_not": must_not
                }
            }
        }

    return {"size": size, "query": knn_part}


def _anomaly_score_from_hits(hits, k=K, method="kth"):
    """
    計算異常分數
    method:
      - "kth": score = 1 - sim_k
      - "avg": score = 1 - avg_sim_topk
    """
    if not hits:
        return None

    sims = sorted([h["_score"] for h in hits], reverse=True)  # 越大越像
    
    if method == "avg":
        sim = float(np.mean(sims))
    elif method == "max":
        sim = float(sims[0])
    else:  # "kth" (Default)
        # 取第 k 個鄰居
        idx = min(k - 1, len(sims) - 1)
        sim = float(sims[idx])

    return 1.0 - sim  # 越大越異常


def calibrate_threshold(sample_n=CALIB_SAMPLE_N, k=K, quantile=QUANTILE,
                        filters=None, score_method="kth", seed=42):
    """
    從 baseline 抽樣 N 筆，計算建議的 threshold
    """
    random.seed(seed)
    print(f"\n   Starting automatic calibration...")

    #    抓取 baseline 文件的 ID 和向量
    try:
        random_query = {
            "size": sample_n,
            "query": {
                "function_score": {
                    "query": {"match_all": {}},
                    "random_score": {}
                }
            },
            "_source": ["log_vector"]
        }
        
        if filters:
            random_query["query"]["function_score"]["query"] = {
                "bool": {"filter": [{"term": {k: v}} for k, v in filters.items()]}
            }

        resp = client.search(index=index_name, body=random_query)
        hits = resp.get("hits", {}).get("hits", [])
    
    except Exception as e:
        print(f"   Calibration failed (unable to fetch samples): {e}")
        return None

    if len(hits) < max(5, k + 1):
        print(f"   Not enough documents ({len(hits)} < {k+1})，cannot calibrate.")
        return None

    scores = []

    # 對每個樣本做 kNN
    for doc in hits:
        doc_id = doc["_id"]
        vector = doc["_source"].get("log_vector")
        
        if not vector: continue

        knn_query = _build_knn_query(
            query_vector=vector,
            k=k,
            size=k,
            filters=filters,
            exclude_id=doc_id
        )

        try:
            nn = client.search(index=index_name, body=knn_query)
            neighbors = nn.get("hits", {}).get("hits", [])
            
            s = _anomaly_score_from_hits(neighbors, k=k, method=score_method)
            if s is not None:
                scores.append(s)
        except Exception:
            continue

    if not scores:
        return None

    #    計算分位數
    threshold = float(np.quantile(scores, quantile))
    
    print(f"  Calibration complete: Method={score_method}, K={k}, P{int(quantile*100)}={threshold:.4f}, Samples={len(scores)}")
    return threshold


def detect(log_text, threshold, k=K, filters=None, score_method="kth", print_top=5):
    print(f"\n  Analyzing log: '{log_text}'")

    # 這裡 call LLM，因為是新進來的未知 Log
    try:
        vector = llm.get_embedding(log_text)
    except Exception as e:
        print(f"  Embedding failed: {e}")
        return

    query = _build_knn_query(query_vector=vector, k=k, size=k, filters=filters)
    
    try:
        response = client.search(index=index_name, body=query)
    except Exception as e:
        print(f"  Search failed: {e}")
        return

    hits = response.get("hits", {}).get("hits", [])

    if not hits:
        print("      No comparable data found (index empty or filters returned no results).")
        return

    anomaly_score = _anomaly_score_from_hits(hits, k=k, method=score_method)
    
    print("   -> Top neighbors:")
    for i, h in enumerate(hits[:print_top], 1):
        txt = h["_source"].get("log_text", "")
        print(f"      {i}. sim={h['_score']:.4f} | {txt[:60]}...")

    print(f"   -> anomaly_score ({score_method}) = {anomaly_score:.4f}")
    print(f"   -> threshold (P{int(QUANTILE*100)}) = {threshold:.4f}")

    if anomaly_score > threshold:
        print(f"🔴 [ANOMALY DETECTED] Score {anomaly_score:.4f} > {threshold:.4f}")
    else:
        print(f"🟢 [BENIGN] Score {anomaly_score:.4f} <= {threshold:.4f}")


if __name__ == "__main__":
    # 自動校正
    threshold = calibrate_threshold(score_method="kth")
    if threshold is None:
        threshold = 0.35 
        print(f"   Using default threshold: {threshold}")

    # test case 1: 正常
    normal_test = "User admin logged in successfully from 192.168.1.5"
    detect(normal_test, threshold=threshold)

    # test case 2: 攻擊
    malicious_test = "Suspicious process mimikatz.exe dumping credentials from lsass.exe"
    detect(malicious_test, threshold=threshold)