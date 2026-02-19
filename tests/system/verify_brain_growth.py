
import time
import subprocess
import sys
from opensearchpy import OpenSearch

# Configuration
OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
OPENSEARCH_AUTH = ("admin", "admin")
INDICES_TO_CHECK = ["cti-reports", "defense-playbooks", "security-alerts"]

def get_opensearch_client():
    return OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_compress=True,
        http_auth=OPENSEARCH_AUTH,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )

def count_docs(client, indices):
    counts = {}
    for index in indices:
        try:
            # Refresh to ensure latest counts
            client.indices.refresh(index=index)
            count = client.count(index=index)['count']
            counts[index] = count
        except Exception:
            counts[index] = 0 # Index might not exist yet
    return counts

def run_simulation():
    print("🚀 Triggering APT Killchain Simulation...")
    try:
        # Run the simulation script
        result = subprocess.run(
            [sys.executable, "src/simulate_apt_killchain.py"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            print(f"❌ Simulation failed: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"❌ Failed to run simulation script: {e}")
        return False

def verify_brain_growth():
    print("🧠 Starting AI Brain Growth Verification...")
    client = get_opensearch_client()

    # Step 1: Baseline Count
    initial_counts = count_docs(client, INDICES_TO_CHECK)
    print(f"📊 Initial Knowledge Base State: {initial_counts}")

    # Step 2: Trigger Simulation
    if not run_simulation():
        return False

    # Step 3: Wait for Pipeline Processing
    wait_seconds = 15
    print(f"⏳ Waiting {wait_seconds}s for ingestion and playbook generation...")
    time.sleep(wait_seconds)

    # Step 4: Final Count
    final_counts = count_docs(client, INDICES_TO_CHECK)
    print(f"📊 Final Knowledge Base State:   {final_counts}")

    # Step 5: Assert Growth
    growth_observed = False
    for index in INDICES_TO_CHECK:
        initial = initial_counts.get(index, 0)
        final = final_counts.get(index, 0)
        
        if final > initial:
            print(f"✅ Growth Confirmed in '{index}': {initial} -> {final} (+{final - initial})")
            growth_observed = True
        elif final == initial:
            print(f"⚠️ No growth in '{index}'. (This might be expected if simulation data was duplicate or pipeline stalled)")
        else:
            print(f"❌ Data LOSS in '{index}'! {initial} -> {final}")
            return False

    if growth_observed:
        print("✅ [PASS] The System is Learning! New data was successfully ingested and indexed.")
        return True
    else:
        print("❌ [FAIL] No data accumulation detected across checked indices.")
        return False

if __name__ == "__main__":
    if verify_brain_growth():
        exit(0)
    else:
        exit(1)
