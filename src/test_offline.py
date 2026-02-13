from __future__ import annotations
import json
from pathlib import Path

from to_stix import build_stix_bundle
from validate_stix import validate_stix_json
from utils import ensure_dir, write_text, write_json

def main() -> None:
    ensure_dir("out")
    extracted = json.loads(Path("data/extracted_mock.json").read_text(encoding="utf-8"))
    stix_str = build_stix_bundle(extracted)
    write_text("out/offline_bundle_stix21.json", stix_str)

    ok, payload = validate_stix_json(stix_str)
    write_json("out/offline_validator_report.json", payload)

    print("OFFLINE STIX VALID:", ok)
    print("Counts:", payload.get("counts"))

if __name__ == "__main__":
    main()
