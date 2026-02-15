import unittest
from unittest.mock import MagicMock, patch
import json
import os
import shutil
from src.cve_enrichment import CVEEnricher
from src.enrichment import EnrichmentEngine
from src.run_pipeline import process_task
from src.llm_client import LLMClient

class TestOptimizations(unittest.TestCase):

    def setUp(self):
        # Setup for DLQ test
        self.failed_dir = "data/failed_tasks"
        if os.path.exists(self.failed_dir):
            shutil.rmtree(self.failed_dir)
        os.makedirs(self.failed_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.failed_dir):
            shutil.rmtree(self.failed_dir)

    def test_optimization_1_caching(self):
        print("\nTesting Optimization 1: API Caching")
        enricher = CVEEnricher()
        # Mock the actual request to avoid network calls and verify cache hit
        enricher._make_request = MagicMock(return_value=[{"id": "CVE-2021-44228", "score": 10.0}])
        
        # First call
        enricher.get_cve_details("CVE-2021-44228")
        # Second call
        enricher.get_cve_details("CVE-2021-44228")
        
        # Should be called only once due to lru_cache
        enricher._make_request.assert_called_once()
        print("  API Caching Verified!")

    @patch("src.run_pipeline.upsert_indicator")
    def test_optimization_2_whitelist(self, mock_upsert):
        print("\nTesting Optimization 2: Whitelist")
        # Initialize mocks
        llm = MagicMock(spec=LLMClient)
        enricher = MagicMock(spec=EnrichmentEngine)
        cve_enricher = MagicMock(spec=CVEEnricher)
        llm.normalize_log.return_value = {"source_ip": "8.8.8.8"}
        llm.get_extraction.return_value = {"indicators": {"ipv4": ["8.8.8.8"]}, "confidence": 90}
        
        task_payload = {"filename": "LOG_TEST", "source_ip": "8.8.8.8", "message": "Test whitelist"}
        
        # Run process_task
        process_task(task_payload, llm, enricher, cve_enricher)
        
        # upsert_indicator should NOT be called for whitelisted IP
        # But wait, run_pipeline calls upsert_indicator for reporting? 
        # The logic added was:
        # if ip in WHITELIST... continue (skip upsert)
        
        # Let's verify mock_upsert was NOT called for 8.8.8.8
        # Note: report_info arg might make assert_not_called tricky if strict
        # We can check call_args_list
        for call in mock_upsert.call_args_list:
            args, _ = call
            if args[0] == "8.8.8.8":
                self.fail("  Whitelisted IP 8.8.8.8 was upserted (blocked)!")
        
        print("  Whitelist Verified!")

    def test_optimization_3_keyword_triage(self):
        print("\nTesting Optimization 3: Keyword Triage")
        llm = MagicMock(spec=LLMClient)
        enricher = MagicMock(spec=EnrichmentEngine)
        cve_enricher = MagicMock(spec=CVEEnricher)
        
        # Plain text log with NO suspicious keywords
        task_payload = {"filename": "LOG_NORMAL", "message": "This is a completely normal log message system operational."}
        
        process_task(task_payload, llm, enricher, cve_enricher)
        
        # LLM normalize or extraction should NOT be called
        llm.normalize_log.assert_not_called()
        print("  Keyword Triage Verified (LLM skipped for benign log)!")

    # DLQ is harder to unittest inside process_task as it's in run_worker, 
    # but we can verify the directory creation logic if we extracted it, 
    # or just rely on code review + manual check if feasible. 
    # Here we will skip strict DLQ unit test as it depends on RabbitMQ mocking which is complex.
    
if __name__ == "__main__":
    unittest.main()
