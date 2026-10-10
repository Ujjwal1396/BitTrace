"""
Unit & Cross-Language Test Suite for BidTrace OCDS 1.1 & RFC 8785 Canonical JCS Engine
======================================================================================
Verifies:
1. RFC 8785 (JCS) deterministic canonicalization rules.
2. Permuted dictionary keys produce identical byte-for-byte canonical output.
3. Whitespace, float representation, and UTF-8 string integrity.
4. OCDS 1.1 Tender Notice, Technical Evaluation, and Final Award releases.
5. Strict cross-language hash parity between Python and Node.js.
"""

import sys
import os
import json
import subprocess
import unittest

# Ensure bidtrace_py is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bidtrace_py.ocds import (
    canonicalize_jcs,
    canonical_json_str,
    hash_canonical_json,
    build_ocid,
    create_tender_notice_release,
    create_evaluation_release,
    create_award_release,
    validate_ocds_release
)

class TestOCDSAndJCS(unittest.TestCase):

    def test_jcs_key_permutation_invariance(self):
        """Objects with different key orders must produce the exact same canonical bytes and hash."""
        obj1 = {"z": 100, "a": "hello", "m": [3, 2, 1], "b": {"y": True, "x": None}}
        obj2 = {"a": "hello", "b": {"x": None, "y": True}, "m": [3, 2, 1], "z": 100}
        obj3 = {"m": [3, 2, 1], "z": 100, "b": {"y": True, "x": None}, "a": "hello"}

        canon1 = canonical_json_str(obj1)
        canon2 = canonical_json_str(obj2)
        canon3 = canonical_json_str(obj3)

        self.assertEqual(canon1, canon2)
        self.assertEqual(canon2, canon3)
        self.assertEqual(hash_canonical_json(obj1), hash_canonical_json(obj2))
        self.assertEqual(hash_canonical_json(obj2), hash_canonical_json(obj3))

        # Expected sorted keys: a, b (x, y), m, z
        expected = '{"a":"hello","b":{"x":null,"y":true},"m":[3,2,1],"z":100}'
        self.assertEqual(canon1, expected)

    def test_jcs_utf8_international_characters(self):
        """Unicode characters (Spanish, German, Korean, Japanese) must not be corrupted or escaped as ASCII."""
        intl_data = {
            "country": "España",
            "contractor": "Müller & Söhne Bau GmbH",
            "city": "São Paulo",
            "korean": "대한민국 조달청",
            "japanese": "東京都"
        }
        canon_str = canonical_json_str(intl_data)
        # Verify raw UTF-8 chars are preserved (not escaped into \u00fc or \u00e3)
        self.assertIn("España", canon_str)
        self.assertIn("Müller & Söhne", canon_str)
        self.assertIn("São Paulo", canon_str)
        self.assertIn("대한민국 조달청", canon_str)
        self.assertIn("東京都", canon_str)

    def test_ocid_builder(self):
        """Verifies clean OCID generation."""
        ocid = build_ocid("US NYC DOT", "TENDER 2026 BRIDGE 01")
        self.assertEqual(ocid, "ocds-us-nyc-dot-TENDER-2026-BRIDGE-01")

    def test_tender_notice_release_lifecycle(self):
        """Creates and validates an OCDS Tender Notice Release."""
        ocid = build_ocid("WORLD-BANK", "WB-7890-ROAD")
        tender_release = create_tender_notice_release(
            ocid=ocid,
            tender_id="WB-7890-ROAD",
            title="Pan-American Highway Rehabilitation Sector 4",
            description="Reconstruction of 120km asphalt highway and drainage systems",
            buyer_id="WB-DEPT-INFRA",
            buyer_name="World Bank Infrastructure Division",
            currency="USD",
            estimated_amount=45000000.0,
            submission_deadline_iso="2026-11-15T18:00:00Z",
            evaluation_type="QCBS",
            tech_weight=0.70,
            fin_weight=0.30,
            min_tech_score=75.0,
            bond_amount=900000.0,
            bond_mode="SuretyService",
            solana_tender_pda="4YHMPVM4xXywPGoFo5NREN33jmqkfDPy9Nf6n72MymWK",
            submission_deadline_slot=508900000
        )

        is_valid, errors = validate_ocds_release(tender_release)
        self.assertTrue(is_valid, f"Validation errors: {errors}")
        self.assertEqual(tender_release["tag"], ["tender"])
        self.assertEqual(tender_release["tender"]["awardCriteria"], "ratedCriteria")
        self.assertEqual(tender_release["bidtrace"]["evaluationType"], "QCBS")
        self.assertEqual(tender_release["bidtrace"]["techWeightBps"], 7000)
        self.assertEqual(tender_release["bidtrace"]["finWeightBps"], 3000)
        self.assertTrue(len(tender_release["bidtrace"]["canonicalHash"]) == 64)

    def test_evaluation_and_award_releases(self):
        """Builds multi-stage evaluation and final QCBS award releases and validates them."""
        ocid = build_ocid("US-NYC", "TENDER-NYC-009")
        tender_rel = create_tender_notice_release(
            ocid=ocid,
            tender_id="TENDER-NYC-009",
            title="Subway Line 7 Signal Modernization",
            description="Complete CBTC signaling installation",
            buyer_id="MTA-NYC",
            buyer_name="Metropolitan Transportation Authority",
            currency="USD",
            estimated_amount=15000000.0,
            submission_deadline_iso="2026-10-30T12:00:00Z"
        )

        eval_panel = [
            {"evaluatorId": "EV-01", "name": "Chief Signal Engineer A"},
            {"evaluatorId": "EV-02", "name": "Safety Systems Auditor B"},
            {"evaluatorId": "EV-03", "name": "Transit Operations Expert C"}
        ]

        bids_eval = [
            {
                "bidderId": "BIDDER-APEX",
                "technicalScoreBps": 8450,
                "isTechQualified": True,
                "subScores": [2600, 1800, 2100, 1150, 800],
                "outliersPruned": 0
            },
            {
                "bidderId": "BIDDER-BETA",
                "technicalScoreBps": 6800,
                "isTechQualified": False,
                "subScores": [1900, 1500, 1800, 1000, 600],
                "outliersPruned": 1
            }
        ]

        eval_rel = create_evaluation_release(
            parent_release=tender_rel,
            evaluator_panel=eval_panel,
            bids_evaluation=bids_eval,
            tech_lock_slot=508920100,
            lock_tx_signature="3gwC4CA8MMxRzJ4FcTWAPztrSCPSqskT3vapba3iwiYhFGkmmJCycqVRYgCABji4ApaLvd4y87JLFAWAQnkans6c"
        )

        self.assertEqual(eval_rel["tag"], ["evaluation"])
        self.assertEqual(len(eval_rel["bids"]["details"]), 2)
        self.assertTrue(eval_rel["bids"]["details"][0]["isTechQualified"])
        self.assertFalse(eval_rel["bids"]["details"][1]["isTechQualified"])
        self.assertEqual(len(eval_rel["bidtrace"]["canonicalHash"]), 64)

        award_rel = create_award_release(
            parent_release=eval_rel,
            winner_bidder_id="BIDDER-APEX",
            winner_name="Apex Transit Systems Ltd",
            awarded_amount=13800000.0,
            currency="USD",
            composite_score=87.65,
            lowest_revealed_price=13800000.0,
            award_slot=508925000,
            award_tx_signature="468t7S8kd89RTX1Con9MT5MsgktLLm7c1gGHjuEZRuvHZ5oZoq7r2rcMqNPREYRKnirWaGrw6RKnZizyH6PDi33i"
        )

        self.assertEqual(award_rel["tag"], ["award", "contract"])
        self.assertEqual(award_rel["awards"][0]["value"]["amount"], 13800000.0)
        self.assertEqual(award_rel["bidtrace"]["winningBidderId"], "BIDDER-APEX")
        self.assertEqual(len(award_rel["bidtrace"]["canonicalHash"]), 64)

    def test_cross_language_parity_with_node(self):
        """
        Executes Node.js with public/ocds.js on the exact same payload
        and asserts that Python and Node.js produce identical canonical strings and SHA-256 hashes.
        """
        sample_payload = {
            "zebra": 999,
            "alpha": "standard-test",
            "nested": {
                "tags": ["b", "a", "c"],
                "active": True,
                "amount": 4200000.5,
                "empty": None
            },
            "unicode": "García & Söhne España - 100% Verified"
        }

        # 1. Compute in Python
        py_canon_str = canonical_json_str(sample_payload)
        py_hash = hash_canonical_json(sample_payload)

        # 2. Compute in Node.js via UTF-8 stdin to avoid Windows command-line codepage mangling
        node_script = """
        const ocds = require('./public/ocds.js');
        const fs = require('fs');
        const stdinBuffer = fs.readFileSync(0); // read from stdin
        const data = JSON.parse(stdinBuffer.toString('utf8'));
        const canon = ocds.canonicalizeJcs(data);
        const hash = require('crypto').createHash('sha256').update(Buffer.from(canon, 'utf8')).digest('hex');
        process.stdout.write(JSON.stringify({ canon: canon, hash: hash }));
        """

        node_path = r"C:\Program Files\nodejs\node.exe"
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        
        proc = subprocess.run(
            [node_path, "-e", node_script],
            input=json.dumps(sample_payload, ensure_ascii=False).encode('utf-8'),
            cwd=repo_root,
            capture_output=True
        )

        self.assertEqual(proc.returncode, 0, f"Node.js script failed: {proc.stderr.decode('utf-8', errors='replace')}")
        node_result = json.loads(proc.stdout.decode('utf-8'))

        # Assert strict cross-language identity
        self.assertEqual(py_canon_str, node_result["canon"], "Canonical string mismatch between Python and Node.js!")
        self.assertEqual(py_hash, node_result["hash"], "SHA-256 hash mismatch between Python and Node.js!")
        print(f"\n[CROSS-LANG SUCCESS] Python & Node.js hash parity verified: {py_hash}")


if __name__ == "__main__":
    unittest.main()
