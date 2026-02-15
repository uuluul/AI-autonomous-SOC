import geoip2.database
import json
import os
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

class EnrichmentEngine:
    def __init__(self, geoip_path="data/GeoLite2-City.mmdb", assets_path="data/assets.json"):
        self.geoip_path = geoip_path
        self.assets_path = assets_path
        self.assets = self._load_assets()
        self.geo_reader = self._load_geoip()

    def _load_assets(self):
        """載入內部資產表 (CMDB)"""
        if os.path.exists(self.assets_path):
            try:
                with open(self.assets_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"  Failed to load assets.json: {e}")
                return {}
        else:
            logger.warning(f"  Assets CMDB NOT FOUND at: {os.path.abspath(self.assets_path)}")
            return{}

    def _load_geoip(self):
        """載入 GeoIP 資料庫"""
        if os.path.exists(self.geoip_path):
            try:
                reader = geoip2.database.Reader(self.geoip_path)
                logger.info(f"  GeoIP Database loaded from {self.geoip_path}")
                return reader
            except Exception as e:
                logger.error(f"  Error reading GeoIP DB: {e}")
                return None
        else:
            # 除錯用：印出絕對路徑，看容器到底在找哪裡
            logger.error(f"  GeoIP DB NOT FOUND at: {os.path.abspath(self.geoip_path)}")
            return None

    @lru_cache(maxsize=1024)
    def enrich_ip(self, ip_address):
        """
        輸入一個 IP，回傳它的地理位置和內部資產資訊
        """
        result = {
            "ip": ip_address,
            "geo": {"country": None, "city": None, "lat": None, "lon": None, "iso_code": None},
            "asset": {}
        }

        # 查詢 GeoIP (外部 IP)
        if self.geo_reader:
            try:
                response = self.geo_reader.city(ip_address)
                result["geo"] = {
                    "country": response.country.name,
                    "city": response.city.name,
                    "lat": response.location.latitude,
                    "lon": response.location.longitude,
                    "iso_code": response.country.iso_code
                }
                logger.info(f"📍 Geo lookup success for {ip_address}: {result['geo']['country']}")
            except geoip2.errors.AddressNotFoundError:
                result["geo"]["country"] = "Internal / Private"

        # 查詢 CMDB (內部 IP)
        if ip_address in self.assets:
            result["asset"] = self.assets[ip_address]

        return result

    def close(self):
        if self.geo_reader:
            self.geo_reader.close()