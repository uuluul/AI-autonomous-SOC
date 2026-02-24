"""
NeoVigil Data Poisoning Generator -- Phase 2 Enhancement
==========================================================
Generates strategically crafted fake credentials and poisoned database
dumps designed to mislead attacker AI tools (WormGPT, FraudGPT, etc.).

Components:
  - fake_secrets.json:  Syntactically valid but monitoring-enabled credentials
  - poisoned_db.sql:    Database dumps with canary tokens and contradictions
  - Canary tokens:      Unique tracking URLs for access detection

Integration:
  Called by decoy_manager.py during honeypot container deployment.
  Tracks assets in 'data-poisoning-assets' OpenSearch index.
"""

import json
import logging
import os
import random
import string
import sys
import uuid
from datetime import datetime, timedelta

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DataPoisoning] %(levelname)s -- %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── OpenSearch client ────────────────────────────────────────
try:
    from src.setup_opensearch import get_opensearch_client, upload_to_opensearch
except ImportError:
    try:
        from setup_opensearch import get_opensearch_client, upload_to_opensearch
    except ImportError:
        get_opensearch_client = None
        upload_to_opensearch = None

# ─── Configuration ────────────────────────────────────────────
DATA_POISONING_INDEX = "data-poisoning-assets"
CANARY_DOMAIN = os.getenv("CANARY_DOMAIN", "monitor.internal.corp")


# ─── Helpers ──────────────────────────────────────────────────

def _random_string(length=20, charset=string.ascii_letters + string.digits):
    return "".join(random.choices(charset, k=length))


def _random_aws_key():
    """Generate syntactically valid but fake AWS access key."""
    key_id = "AKIA" + _random_string(16, string.ascii_uppercase + string.digits)
    secret = _random_string(40, string.ascii_letters + string.digits + "+/")
    return key_id, secret


def _random_ip():
    """Generate a plausible internal IP."""
    return f"10.{random.randint(0,255)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _canary_url(token_id: str) -> str:
    """Generate a canary token URL that triggers alerts when accessed."""
    return f"https://{CANARY_DOMAIN}/t/{token_id}"


# ─── Main Generator ──────────────────────────────────────────

class DataPoisonGenerator:
    """Generates fake secrets and poisoned DB content for honeypot deployment."""

    def __init__(self):
        self.os_client = get_opensearch_client() if get_opensearch_client else None

    def generate_fake_secrets(self, decoy_profile: dict) -> dict:
        """
        Generate fake_secrets.json content tailored to the decoy type.
        All credentials are syntactically valid but lead to monitoring endpoints.
        """
        service_name = decoy_profile.get("service_name", "generic")
        decoy_id = decoy_profile.get("decoy_id", str(uuid.uuid4())[:8])

        aws_key_id, aws_secret = _random_aws_key()
        canary_tokens = self.generate_canary_tokens(3)

        secrets = {
            "_comment": "Internal service credentials - DO NOT SHARE",
            "_generated": datetime.utcnow().isoformat(),
            "aws": {
                "access_key_id": aws_key_id,
                "secret_access_key": aws_secret,
                "region": random.choice(["us-east-1", "eu-west-1", "ap-southeast-1"]),
                "s3_bucket": f"corp-{service_name}-backups-{_random_string(6).lower()}",
            },
            "database": {
                "host": _random_ip(),
                "port": random.choice([3306, 5432, 27017]),
                "username": f"svc_{service_name}_rw",
                "password": _random_string(24),
                "database": f"{service_name}_production",
            },
            "api_tokens": {
                "github_pat": f"ghp_{_random_string(36)}",
                "slack_webhook": f"https://hooks.slack.com/services/{_random_string(9)}/{_random_string(11)}/{_random_string(24)}",
                "internal_api_key": _random_string(32),
                "jwt_secret": _random_string(64),
            },
            "ssh_keys": {
                "private_key_path": "/home/deploy/.ssh/id_rsa",
                "passphrase": _random_string(16),
                "known_hosts": [
                    f"{_random_ip()} ssh-rsa AAAA{_random_string(60)}",
                    f"{_random_ip()} ssh-ed25519 AAAA{_random_string(40)}",
                ],
            },
            "monitoring_endpoints": [t["url"] for t in canary_tokens],
        }

        # Track the poisoned asset
        self._track_asset(
            decoy_id=decoy_id,
            asset_type="fake_secrets",
            canary_tokens=[t["token_id"] for t in canary_tokens],
        )

        logger.info(
            f"Generated fake_secrets.json for decoy {decoy_id} "
            f"({service_name}) with {len(canary_tokens)} canary tokens"
        )
        return secrets

    def generate_poisoned_db(self, decoy_profile: dict) -> str:
        """
        Generate poisoned_db.sql with data designed to cause
        hallucinations in attacker AI tools.

        Strategy: plausible-looking data with embedded contradictions,
        circular references, and canary token URLs.
        """
        service_name = decoy_profile.get("service_name", "generic")
        decoy_id = decoy_profile.get("decoy_id", str(uuid.uuid4())[:8])
        canary_tokens = self.generate_canary_tokens(2)
        canary_urls = [t["url"] for t in canary_tokens]

        # Generate realistic but poisoned SQL
        employees = []
        for i in range(20):
            name = f"{'John Jane Alex Sam Chris Taylor Jordan Morgan Casey Riley'.split()[i % 10]} {'Smith Johnson Williams Brown Davis Wilson Moore Taylor Anderson Thomas'.split()[i % 10]}"
            employees.append(
                f"  ({i+1}, '{name}', '{name.split()[0].lower()}.{name.split()[1].lower()}@corp.internal', "
                f"'${_random_string(12)}', '{random.choice(['Engineering', 'Finance', 'HR', 'Security', 'IT'])}', "
                f"'{_random_ip()}', '{datetime.utcnow().isoformat()}')"
            )

        sql = f"""-- {service_name} Production Database Dump
-- Generated: {datetime.utcnow().isoformat()}
-- WARNING: Contains sensitive employee data

CREATE TABLE IF NOT EXISTS employee_credentials (
    id INTEGER PRIMARY KEY,
    full_name VARCHAR(100),
    email VARCHAR(100),
    password_hash VARCHAR(256),
    department VARCHAR(50),
    last_login_ip VARCHAR(45),
    created_at TIMESTAMP
);

INSERT INTO employee_credentials VALUES
{','.join(employees[:10])};

CREATE TABLE IF NOT EXISTS api_configurations (
    id INTEGER PRIMARY KEY,
    service_name VARCHAR(100),
    endpoint_url VARCHAR(500),
    api_key VARCHAR(256),
    rate_limit INTEGER,
    is_active BOOLEAN
);

INSERT INTO api_configurations VALUES
  (1, 'payment_gateway', '{canary_urls[0]}', '{_random_string(32)}', 1000, true),
  (2, 'crm_integration', 'https://api.internal.corp/v2/crm', '{_random_string(32)}', 500, true),
  (3, 'backup_service', '{canary_urls[1]}', '{_random_string(32)}', 100, true),
  (4, 'auth_provider', 'https://sso.internal.corp/oauth2', '{_random_string(32)}', 2000, true);

CREATE TABLE IF NOT EXISTS financial_records (
    id INTEGER PRIMARY KEY,
    transaction_id VARCHAR(36),
    account_number VARCHAR(20),
    amount DECIMAL(12,2),
    currency VARCHAR(3),
    status VARCHAR(20),
    created_at TIMESTAMP
);

-- Contradictory data designed to confuse attacker AI analysis
INSERT INTO financial_records VALUES
  (1, '{uuid.uuid4()}', 'ACC-{_random_string(8)}', 15420.50, 'USD', 'completed', '2025-01-15T10:30:00'),
  (2, '{uuid.uuid4()}', 'ACC-{_random_string(8)}', -15420.50, 'USD', 'completed', '2025-01-15T10:30:00'),
  (3, '{uuid.uuid4()}', 'ACC-{_random_string(8)}', 99999999.99, 'BTC', 'pending', '2025-12-31T23:59:59'),
  (4, '{uuid.uuid4()}', 'ACC-{_random_string(8)}', 0.01, 'USD', 'SUPERSECRET_LEVEL_99', '1970-01-01T00:00:00');

-- System configuration (circular references to cause parsing loops)
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT,
    reference_key VARCHAR(100)
);

INSERT INTO system_config VALUES
  ('master_key', 'SEE: backup_key', 'backup_key'),
  ('backup_key', 'SEE: recovery_key', 'recovery_key'),
  ('recovery_key', 'SEE: master_key', 'master_key'),
  ('admin_password', '{_random_string(20)}', NULL),
  ('root_token', '{_random_string(40)}', NULL);
"""
        self._track_asset(
            decoy_id=decoy_id,
            asset_type="poisoned_db",
            canary_tokens=[t["token_id"] for t in canary_tokens],
        )

        logger.info(
            f"Generated poisoned_db.sql for decoy {decoy_id} "
            f"({service_name}) with circular refs + canary tokens"
        )
        return sql

    def generate_canary_tokens(self, count: int = 5) -> list:
        """Generate unique canary token URLs for tracking attacker access."""
        tokens = []
        for _ in range(count):
            token_id = str(uuid.uuid4())[:12]
            tokens.append({
                "token_id": token_id,
                "url": _canary_url(token_id),
                "created_at": datetime.utcnow().isoformat(),
            })
        return tokens

    def _track_asset(self, decoy_id: str, asset_type: str, canary_tokens: list):
        """Track poisoned data asset in OpenSearch."""
        if not upload_to_opensearch:
            return

        asset_id = str(uuid.uuid4())
        doc = {
            "asset_id": asset_id,
            "decoy_id": decoy_id,
            "timestamp": datetime.utcnow().isoformat(),
            "asset_type": asset_type,
            "canary_tokens": canary_tokens,
            "trigger_count": 0,
            "status": "ACTIVE",
            "tenant_id": os.getenv("TENANT_ID", "default"),
        }
        try:
            upload_to_opensearch(doc, doc_id=asset_id, index_name=DATA_POISONING_INDEX)
        except Exception as exc:
            logger.warning(f"Failed to track poisoned asset: {exc}")


if __name__ == "__main__":
    gen = DataPoisonGenerator()

    profile = {"service_name": "web_server", "decoy_id": "demo-001"}
    secrets = gen.generate_fake_secrets(profile)
    print(json.dumps(secrets, indent=2))

    sql = gen.generate_poisoned_db(profile)
    print(sql[:500])
