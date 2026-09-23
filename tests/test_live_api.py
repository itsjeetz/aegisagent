"""
Live End-to-End API Verification Script.
Sends requests to http://127.0.0.1:8000/api/inspect and verifies that
all 9 attack vectors are detected and neutralized over HTTP.
"""

import os
import sys
import urllib.request
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aegis_firewall.benchmark import BENCHMARK_CASES

def main():
    attacks = [c for c in BENCHMARK_CASES if c["is_attack"]]
    print(f"Testing {len(attacks)} attack vectors through live API...")

    for a in attacks:
        data = json.dumps({"content": a["content"], "source": a["source"].value}).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/inspect",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        res_bytes = urllib.request.urlopen(req).read()
        res = json.loads(res_bytes.decode("utf-8"))

        assert not res["is_safe"], f"Failed detection on {a['id']} - {a['name']}"
        assert res["risk_score"] >= 35.0, f"Low risk score on {a['id']}: {res['risk_score']}"
        assert len(res["neutralized"]["safe_text"]) > 0, f"Neutralization empty on {a['id']}"
        print(f"  [PASS] {a['id']}: {a['name']:<42} -> Detected: {res['primary_attack']} (Risk: {res['risk_score']}%)")

    print("\nTesting Benign Scenarios (False Positive Check)...")
    benigns = [c for c in BENCHMARK_CASES if not c["is_attack"]]
    for b in benigns:
        data = json.dumps({"content": b["content"], "source": b["source"].value}).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/inspect",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        res = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
        assert res["is_safe"], f"False positive on benign {b['id']} - {b['name']}"
        print(f"  [PASS] {b['id']}: {b['name']:<42} -> Verified SAFE (Risk: {res['risk_score']}%)")

    print("\nALL 29 LIVE API TESTS PASSED WITH 100% RELIABILITY!")

if __name__ == "__main__":
    main()
