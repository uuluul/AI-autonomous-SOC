import urllib.request
import concurrent.futures
import time
import random
import json
import sys

LLM_URL = "http://localhost:8000/v1/chat/completions"

def test_llm():
    # 模擬真實網路抖動 (Jitter)
    time.sleep(random.uniform(0.01, 0.1))
    req = urllib.request.Request(LLM_URL, method="POST")
    req.add_header("Content-Type", "application/json")
    data = json.dumps({
        "model": "mock",
        "messages": [{"role": "user", "content": "stress test"}]
    }).encode("utf-8")
    
    # 容錯重試機制
    for _ in range(2):
        try:
            with urllib.request.urlopen(req, data=data, timeout=10) as response:
                if response.status == 200:
                    return True
        except Exception as e:
            last_err = str(e)
            time.sleep(0.1)
    return last_err

def main():
    print("[LOAD_TEST] Starting API Stress Test: 50 concurrent requests...")
    
    success_count = 0
    errors = []
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(lambda _: test_llm(), range(50)))
        
    for r in results:
        if r is True:
            success_count += 1
        else:
            errors.append(r)
            
    elapsed = time.time() - start_time
    
    print("[RESULT] Results:")
    print(f"   - Mock LLM: {success_count}/50 success")
    print(f"   - Avg Latency: {elapsed/50:.3f}s")
    
    if errors:
        print(f"[ERROR] Errors Sample: {list(set(errors))[:3]}")
        
    if success_count == 50:
        print("[SUCCESS] PASS: API Load Resilience")
        sys.exit(0)
    else:
        print("[FAIL] FAIL: API Load Resilience")
        sys.exit(1)

if __name__ == "__main__":
    main()
