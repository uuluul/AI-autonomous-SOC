import logging
import time
import random

logger = logging.getLogger(__name__)

class FirewallClient:
    def __init__(self, vendor="Fortinet"):
        self.vendor = vendor
        self.connected = False

    def connect(self):
        """模擬連線到防火牆"""
        logger.info(f"🔌 Connecting to {self.vendor} Firewall at 192.168.1.254...")
        time.sleep(0.5) # 演一下連線延遲
        self.connected = True
        logger.info(f"  Connected to {self.vendor} API.")

    def block_ip(self, ip_address):
        """模擬封鎖 IP"""
        if not self.connected:
            self.connect()
        
        logger.info(f"  [Firewall Action] Requesting block for IP: {ip_address}...")
        time.sleep(1)
        
        # 隨機模擬成功或失敗 (大部分成功)
        if random.random() > 0.05:
            logger.info(f"  [SUCCESS] Firewall Rule Created: DENY ANY -> {ip_address}")
            return True
        else:
            logger.error(f"  [FAIL] Firewall API Timeout for {ip_address}")
            return False

if __name__ == "__main__":
    fw = FirewallClient()
    fw.block_ip("103.15.22.88")