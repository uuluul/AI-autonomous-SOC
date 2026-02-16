import random
import hashlib
import time

class MockThreatIntel:
    """
    Simulates external Threat Intelligence APIs (VirusTotal, AbuseIPDB, AlienVault).
    """
    
    def __init__(self):
        self.cache = {}

    def get_ip_reputation(self, ip_address: str) -> dict:
        """
        Simulate AbuseIPDB / VirusTotal IP check.
        Returns: {
            "score": int (0-100),
            "verdict": str (Malicious/Suspicious/Clean),
            "tags": list,
            "source": str
        }
        """
        if ip_address in self.cache:
            return self.cache[ip_address]
            
        # Deterministic simulation based on IP string hash
        # This ensures consistent results for the same IP during demos
        h = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
        
        # Reserved / Local IPs are always clean
        if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address == "127.0.0.1":
            result = {
                "score": 0,
                "verdict": "Clean",
                "tags": ["Whitelisted", "Internal"],
                "source": "Internal-Allowlist"
            }
        
        # High Risk Logic (Simulated)
        elif h % 10 < 3: # 30% chance of high risk
            tags = ["Botnet", "C2", "Brute-Force", "Scanner"]
            result = {
                "score": random.randint(80, 100),
                "verdict": "Malicious",
                "tags": random.sample(tags, 2),
                "source": "AbuseIPDB (Mock)"
            }
            
        # Medium Risk
        elif h % 10 < 6: # 30% chance of medium risk
            result = {
                "score": random.randint(40, 79),
                "verdict": "Suspicious",
                "tags": ["Low-Reputation", "Tor-Exit"],
                "source": "AlienVault OTX (Mock)"
            }
            
        # Clean
        else:
            result = {
                "score": random.randint(0, 10),
                "verdict": "Clean",
                "tags": [],
                "source": "VirusTotal (Mock)"
            }
            
        self.cache[ip_address] = result
        time.sleep(0.1) # Simulate API latency
        return result

    def get_file_reputation(self, file_hash: str) -> dict:
        """
        Simulate VirusTotal File Hash check.
        """
        # (Similar deterministic logic can be added here if needed)
        return {"score": 0, "verdict": "Unknown", "source": "VirusTotal"}

if __name__ == "__main__":
    # Quick Test
    ti = MockThreatIntel()
    print(ti.get_ip_reputation("1.1.1.1"))
    print(ti.get_ip_reputation("192.168.1.5"))
    print(ti.get_ip_reputation("185.220.101.5")) # Likely high risk in simulation
