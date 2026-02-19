
import concurrent.futures
import requests
import time
import json
import random

# Configuration
CONCURRENT_REQUESTS = 50
LLM_URL = "http://localhost:8000/v1/chat/completions"
SOAR_URL = "http://localhost:5001/analyze"

def stress_llm(request_id):
    """Send a request to the Mock LLM"""
    time.sleep(random.uniform(0.01, 0.1))  # Jitter
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are an AI assistant."},
            {"role": "user", "content": f"Analyze this log: User admin failed login from 192.168.1.{request_id}"}
        ]
    }
    for attempt in range(2):
        try:
            start = time.time()
            response = requests.post(LLM_URL, json=payload, timeout=10)
            duration = time.time() - start
            
            if response.status_code == 200:
                return True, duration, "LLM"
            else:
                return False, duration, f"LLM status {response.status_code}"
        except Exception as e:
            if attempt == 0:
                time.sleep(0.5) # Retry backoff
                continue
            return False, 0, f"LLM Error: {str(e)}"

def stress_soar(request_id):
    """Send a request to the SOAR Server"""
    time.sleep(random.uniform(0.01, 0.1))  # Jitter
    payload = {
        "prediction_id": f"stress-test-{request_id}",
        "overall_risk_score": random.randint(50, 90),
        "scanner_ip": f"10.0.0.{request_id}"
    }
    for attempt in range(2):
        try:
            start = time.time()
            response = requests.post(SOAR_URL, json=payload, timeout=10)
            duration = time.time() - start
            
            if response.status_code == 200:
                return True, duration, "SOAR"
            else:
                return False, duration, f"SOAR status {response.status_code}"
        except Exception as e:
            if attempt == 0:
                time.sleep(0.5) # Retry backoff
                continue
            return False, 0, f"SOAR Error: {str(e)}"

def run_stress_test():
    print(f"[LOAD_TEST] Starting API Stress Test: {CONCURRENT_REQUESTS} concurrent requests per service...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_REQUESTS * 2) as executor:
        # Submit tasks
        llm_futures = [executor.submit(stress_llm, i) for i in range(CONCURRENT_REQUESTS)]
        soar_futures = [executor.submit(stress_soar, i) for i in range(CONCURRENT_REQUESTS)]
        
        futures = llm_futures + soar_futures
        
        # Collect results
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Analyze
    llm_success = sum(1 for s, _, t in results if s and t == "LLM")
    soar_success = sum(1 for s, _, t in results if s and t == "SOAR")
    failures = [msg for s, _, msg in results if not s]
    avg_duration = sum(d for _, d, _ in results) / len(results)

    print(f"[RESULT] Results:")
    print(f"   - Mock LLM: {llm_success}/{CONCURRENT_REQUESTS} success")
    print(f"   - SOAR Server: {soar_success}/{CONCURRENT_REQUESTS} success")
    print(f"   - Avg Latency: {avg_duration:.3f}s")

    if failures:
        print(f"[ERROR] Errors Sample: {failures[:5]}")
        return False
    
    if llm_success == CONCURRENT_REQUESTS and soar_success == CONCURRENT_REQUESTS:
        print("[PASS] All services handled load without crashing.")
        return True
    else:
        print("[FAIL] Some requests failed.")
        return False

if __name__ == "__main__":
    if run_stress_test():
        exit(0)
    else:
        exit(1)
