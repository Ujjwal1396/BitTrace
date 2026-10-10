"""
BidTrace 3.0 - Security Verification Suite: SEC-04
Arbitrary Winning Bidder Selection & Zero-Price Division Defense Test

Vulnerability Context (SEC-04):
In record_award_qcbs.rs (and ledger.py / relayer.py parity):
1. In QCBS mode, record_award_qcbs allowed the authority to designate an arbitrary
   winning_bid account without cryptographically asserting or verifying that no
   competing revealed bidder achieved a higher composite score.
2. Division-by-zero edge case on line 59 if winning_bid.revealed_price == 0
   ((tender.lowest_revealed_price * 10000) / winning_bid.revealed_price).
3. Missing validation against competing revealed qualified bids or remaining accounts.

Fix Verification:
1. Authority CANNOT award an inferior scoring bidder over a higher scoring bidder in QCBS mode.
2. Authority CANNOT award a non-lowest price bidder in Least-Cost mode.
3. Division by zero and zero price quotes are strictly guarded with ZeroPriceNotAllowed.
4. Programmatic QCBS composite scoring formula maintains strict mathematical correctness.
5. REST API endpoint /api/tender/award rejects corrupt authority attempting to award an inferior bidder.
"""

import unittest
import os
import json
import secrets
import hashlib
import threading
import time
import urllib.request
import urllib.error

from bidtrace_py.crypto import (
    generate_keypair,
    compute_tech_commitment,
    compute_fin_commitment,
    compute_grade_commitment
)
from bidtrace_py.ledger import BidTraceLedger, TenderStatus, EvaluationType
from bidtrace_py.relayer import BidTraceRelayerGateway


class TestSEC04QcbsAwardSecurity(unittest.TestCase):
    def setUp(self):
        self.ledger = BidTraceLedger()
        self.ledger.current_slot = 1000
        self.authority = generate_keypair()
        self.evaluators = [generate_keypair()["public_key"] for _ in range(5)]

    def test_01_division_by_zero_guarded_in_reveal(self):
        """
        Verify that reveal_financial_envelope strictly rejects price <= 0 with ZeroPriceNotAllowed.
        """
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC04-ZERO-PRICE-REVEAL",
            submission_deadline_slot=1020,
            admin_review_deadline_slot=1030,
            tech_eval_deadline_slot=1040,
            fin_reveal_deadline_slot=1060
        )
        tender_pda = tender["pda"]

        bidder = generate_keypair()
        salt_fin = secrets.token_hex(32)
        boq_hash = hashlib.sha256(b"BOQ_ZERO").hexdigest()
        zero_comm_fin = compute_fin_commitment(tender_pda, bidder["public_key"], salt_fin, 0, boq_hash).hex()

        self.ledger.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder["public_key"],
            admin_dossier_hash="00" * 32,
            tech_commitment_hash="11" * 32,
            fin_commitment_hash=zero_comm_fin
        )

        # Advance to FinancialEvaluation
        self.ledger.current_slot = 1045
        self.ledger.tenders[tender_pda]["status"] = TenderStatus.FinancialEvaluation
        bid_pda = self.ledger.derive_bid_pda(tender_pda, bidder["public_key"])
        self.ledger.commitments[bid_pda]["is_tech_qualified"] = True
        self.ledger.tenders[tender_pda]["total_tech_qualified"] = 1

        # Attempt to reveal with price = 0
        with self.assertRaises(ValueError) as ctx:
            self.ledger.reveal_financial_envelope(
                tender_pda=tender_pda,
                bidder_pubkey=bidder["public_key"],
                salt_fin=salt_fin,
                price=0,
                boq_hash=boq_hash
            )
        self.assertIn("ZeroPriceNotAllowed", str(ctx.exception))

    def test_02_division_by_zero_guarded_in_award(self):
        """
        Verify that record_award_qcbs rejects winning bid or lowest price <= 0 with ZeroPriceNotAllowed.
        """
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC04-ZERO-PRICE-AWARD",
            submission_deadline_slot=1020,
            admin_review_deadline_slot=1030,
            tech_eval_deadline_slot=1040,
            fin_reveal_deadline_slot=1060
        )
        tender_pda = tender["pda"]
        self.ledger.tenders[tender_pda]["status"] = TenderStatus.FinancialEvaluation

        bidder = generate_keypair()
        bid_pda = self.ledger.derive_bid_pda(tender_pda, bidder["public_key"])
        self.ledger.commitments[bid_pda] = {
            "tender_pda": tender_pda,
            "bidder": bidder["public_key"],
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "revealed_price": 0,  # Corrupt zero price
            "technical_score_bps": 8500
        }
        self.ledger.tenders[tender_pda]["total_tech_qualified"] = 1
        self.ledger.tenders[tender_pda]["total_fin_revealed"] = 1
        self.ledger.tenders[tender_pda]["lowest_revealed_price"] = 0

        self.ledger.current_slot = 1070  # Past reveal deadline

        with self.assertRaises(ValueError) as ctx:
            self.ledger.record_award_qcbs(
                tender_pda=tender_pda,
                authority_pubkey=self.authority["public_key"],
                winning_bidder_pubkey=bidder["public_key"]
            )
        self.assertIn("ZeroPriceNotAllowed", str(ctx.exception))

    def test_03_authority_cannot_award_inferior_scoring_bidder_qcbs(self):
        """
        Critical Attack Scenario (SEC-04):
        Authority attempts to award an inferior scoring bidder (Rank 2) over the rightful
        highest composite score bidder (Rank 1). Contract MUST reject with WinnerNotHighestCompositeScore.
        """
        # Create QCBS tender: Tech Weight = 70%, Fin Weight = 30%
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC04-CORRUPT-AWARD-001",
            submission_deadline_slot=1020,
            admin_review_deadline_slot=1030,
            tech_eval_deadline_slot=1040,
            fin_reveal_deadline_slot=1060,
            evaluation_type=EvaluationType.QCBS,
            tech_weight_bps=7000,
            fin_weight_bps=3000
        )
        tender_pda = tender["pda"]

        # Bidder 1 (High Quality Honest Contractor):
        # Technical score = 90.00% (9000 bps)
        # Price = $3,800,000
        b1 = generate_keypair()
        b1_pk = b1["public_key"]

        # Bidder 2 (Colluding Substandard Contractor):
        # Technical score = 76.00% (7600 bps, passed cutoff of 75.00%)
        # Price = $3,500,000 (cheaper, lowest revealed price)
        b2 = generate_keypair()
        b2_pk = b2["public_key"]

        # Set up state directly in FinancialEvaluation
        self.ledger.tenders[tender_pda]["status"] = TenderStatus.FinancialEvaluation
        self.ledger.tenders[tender_pda]["total_tech_qualified"] = 2
        self.ledger.tenders[tender_pda]["total_fin_revealed"] = 2
        self.ledger.tenders[tender_pda]["lowest_revealed_price"] = 3500000

        b1_pda = self.ledger.derive_bid_pda(tender_pda, b1_pk)
        self.ledger.commitments[b1_pda] = {
            "tender_pda": tender_pda,
            "bidder": b1_pk,
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "technical_score_bps": 9000,
            "revealed_price": 3800000
        }

        b2_pda = self.ledger.derive_bid_pda(tender_pda, b2_pk)
        self.ledger.commitments[b2_pda] = {
            "tender_pda": tender_pda,
            "bidder": b2_pk,
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "technical_score_bps": 7600,
            "revealed_price": 3500000
        }

        # Expected Math:
        # Lowest price = 3,500,000
        # Bidder 1:
        #   Tech part = (9000 * 7000) // 10000 = 6300 bps
        #   Fin ratio = (3500000 * 10000) // 3800000 = 9210
        #   Fin part = (9210 * 3000) // 10000 = 2763 bps
        #   Composite Score = 6300 + 2763 = 9063 bps
        #
        # Bidder 2:
        #   Tech part = (7600 * 7000) // 10000 = 5320 bps
        #   Fin ratio = (3500000 * 10000) // 3500000 = 10000
        #   Fin part = (10000 * 3000) // 10000 = 3000 bps
        #   Composite Score = 5320 + 3000 = 8320 bps
        #
        # Rightful Winner: Bidder 1 (9063 > 8320)

        self.ledger.current_slot = 1070

        # ATTACK: Corrupt authority attempts to award inferior scoring Bidder 2
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record_award_qcbs(
                tender_pda=tender_pda,
                authority_pubkey=self.authority["public_key"],
                winning_bidder_pubkey=b2_pk
            )
        self.assertIn("WinnerNotHighestCompositeScore", str(ctx.exception))
        # Tender must remain in FinancialEvaluation status
        self.assertEqual(self.ledger.tenders[tender_pda]["status"], TenderStatus.FinancialEvaluation)

        # HONEST AWARD: Authority records award for rightful winner Bidder 1
        awarded_tender = self.ledger.record_award_qcbs(
            tender_pda=tender_pda,
            authority_pubkey=self.authority["public_key"],
            winning_bidder_pubkey=b1_pk
        )
        self.assertEqual(awarded_tender["status"], TenderStatus.Awarded)
        self.assertEqual(awarded_tender["winning_bidder"], b1_pk)
        self.assertEqual(awarded_tender["highest_composite_score"], 9063)
        self.assertEqual(self.ledger.commitments[b1_pda]["composite_score"], 9063)
        self.assertEqual(self.ledger.commitments[b2_pda]["composite_score"], 8320)

    def test_04_least_cost_mode_winner_must_be_lowest_price(self):
        """
        Verify that in LeastCost mode, authority cannot select a higher priced bidder.
        """
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC04-LEAST-COST-001",
            submission_deadline_slot=1020,
            admin_review_deadline_slot=1030,
            tech_eval_deadline_slot=1040,
            fin_reveal_deadline_slot=1060,
            evaluation_type=EvaluationType.LeastCost
        )
        tender_pda = tender["pda"]

        b1 = generate_keypair()["public_key"]
        b2 = generate_keypair()["public_key"]

        self.ledger.tenders[tender_pda]["status"] = TenderStatus.FinancialEvaluation
        self.ledger.tenders[tender_pda]["total_tech_qualified"] = 2
        self.ledger.tenders[tender_pda]["total_fin_revealed"] = 2
        self.ledger.tenders[tender_pda]["lowest_revealed_price"] = 3500000

        self.ledger.commitments[self.ledger.derive_bid_pda(tender_pda, b1)] = {
            "tender_pda": tender_pda,
            "bidder": b1,
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "technical_score_bps": 8500,
            "revealed_price": 4000000  # Higher price
        }
        self.ledger.commitments[self.ledger.derive_bid_pda(tender_pda, b2)] = {
            "tender_pda": tender_pda,
            "bidder": b2,
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "technical_score_bps": 8500,
            "revealed_price": 3500000  # Lowest price
        }

        self.ledger.current_slot = 1070

        # Attempt to award higher priced bidder b1 -> rejected
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record_award_qcbs(
                tender_pda=tender_pda,
                authority_pubkey=self.authority["public_key"],
                winning_bidder_pubkey=b1
            )
        self.assertIn("WinnerNotLowestPrice", str(ctx.exception))

        # Award lowest priced bidder b2 -> succeeds
        awarded = self.ledger.record_award_qcbs(
            tender_pda=tender_pda,
            authority_pubkey=self.authority["public_key"],
            winning_bidder_pubkey=b2
        )
        self.assertEqual(awarded["winning_bidder"], b2)
        self.assertEqual(awarded["status"], TenderStatus.Awarded)

    def test_05_programmatic_qcbs_mathematical_correctness(self):
        """
        Verify exact integer precision of QCBS composite scoring formula.
        S_composite = (S_tech * W_tech / 10000) + ((P_lowest * 10000 / P_bidder) * W_fin / 10000)
        """
        tech_score = 8850       # 88.50%
        tech_weight = 7000      # 70.00%
        fin_weight = 3000       # 30.00%
        lowest_price = 3200000  # $3.20M
        bidder_price = 3600000  # $3.60M

        # Pure mathematical calculation
        expected_tech_part = (tech_score * tech_weight) // 10000 # (8850 * 7000) // 10000 = 6195
        expected_fin_ratio = (lowest_price * 10000) // bidder_price # (32000000000) // 3600000 = 8888
        expected_fin_part = (expected_fin_ratio * fin_weight) // 10000 # (8888 * 3000) // 10000 = 2666
        expected_composite = expected_tech_part + expected_fin_part # 6195 + 2666 = 8861 bps (88.61%)

        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC04-MATH-PRECISION",
            submission_deadline_slot=1020,
            admin_review_deadline_slot=1030,
            tech_eval_deadline_slot=1040,
            fin_reveal_deadline_slot=1060,
            evaluation_type=EvaluationType.QCBS,
            tech_weight_bps=tech_weight,
            fin_weight_bps=fin_weight
        )
        tender_pda = tender["pda"]
        self.ledger.tenders[tender_pda]["status"] = TenderStatus.FinancialEvaluation
        self.ledger.tenders[tender_pda]["total_tech_qualified"] = 1
        self.ledger.tenders[tender_pda]["total_fin_revealed"] = 1
        self.ledger.tenders[tender_pda]["lowest_revealed_price"] = lowest_price

        bidder = generate_keypair()["public_key"]
        bid_pda = self.ledger.derive_bid_pda(tender_pda, bidder)
        self.ledger.commitments[bid_pda] = {
            "tender_pda": tender_pda,
            "bidder": bidder,
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "technical_score_bps": tech_score,
            "revealed_price": bidder_price
        }

        self.ledger.current_slot = 1070
        res = self.ledger.record_award_qcbs(tender_pda, self.authority["public_key"], bidder)
        self.assertEqual(res["highest_composite_score"], expected_composite)
        self.assertEqual(expected_composite, 8861)


class TestSEC04RestApiAwardSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import HTTPServer
        from server import BidTraceHandler, state

        cls.server_port = 8778
        cls.server_address = f"http://127.0.0.1:{cls.server_port}"
        cls.httpd = HTTPServer(("127.0.0.1", cls.server_port), BidTraceHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            f"{self.server_address}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_rest_api_rejects_inferior_bidder_award(self):
        """
        Verify that /api/tender/award rejects corrupt authority trying to award Rank 2 bidder.
        """
        from server import state
        self._post("/api/reset", {})

        # 1. Create QCBS tender
        self._post("/api/tender/create", {
            "tender_id": "TENDER-SEC04-API-001",
            "title": "SEC-04 Award Security API Test",
            "evaluation_type": "QCBS",
            "tech_weight": 0.70,
            "fin_weight": 0.30
        })

        # 2. Add two qualified bidders directly to state for financial reveal
        b1_kp = generate_keypair()
        b2_kp = generate_keypair()

        state.ledger.advance_slot(100)
        state.ledger.tenders[state.tender_pda]["status"] = TenderStatus.FinancialEvaluation
        state.ledger.tenders[state.tender_pda]["total_tech_qualified"] = 2
        state.ledger.tenders[state.tender_pda]["total_fin_revealed"] = 2
        state.ledger.tenders[state.tender_pda]["lowest_revealed_price"] = 3500000
        state.ledger.tenders[state.tender_pda]["fin_reveal_deadline_slot"] = state.ledger.current_slot - 10

        b1_pda = state.ledger.derive_bid_pda(state.tender_pda, b1_kp["public_key"])
        state.ledger.commitments[b1_pda] = {
            "tender_pda": state.tender_pda,
            "bidder": b1_kp["public_key"],
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "technical_score_bps": 9200,  # Rank 1: composite ~9203
            "revealed_price": 3800000
        }

        b2_pda = state.ledger.derive_bid_pda(state.tender_pda, b2_kp["public_key"])
        state.ledger.commitments[b2_pda] = {
            "tender_pda": state.tender_pda,
            "bidder": b2_kp["public_key"],
            "is_tech_qualified": True,
            "is_fin_revealed": True,
            "technical_score_bps": 7700,  # Rank 2: composite ~8390
            "revealed_price": 3500000
        }

        # Attempt to award inferior Bidder 2 via REST API
        req = urllib.request.Request(
            f"{self.server_address}/api/tender/award",
            data=json.dumps({
                "winning_bidder_pubkey": b2_kp["public_key"],
                "winner_name": "Inferior Contractor"
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.fail("Expected HTTP 400 for awarding inferior scoring bidder")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 400)
            err_data = json.loads(err.read().decode("utf-8"))
            self.assertIn("WinnerNotHighestCompositeScore", err_data.get("message", ""))

        # Honest award to rightful winner Bidder 1 via REST API succeeds
        honest_award = self._post("/api/tender/award", {
            "winning_bidder_pubkey": b1_kp["public_key"],
            "winner_name": "Optimal Contractor"
        })
        self.assertEqual(honest_award["status"], "ok")
        self.assertEqual(honest_award["winning_bid"]["bidder"], b1_kp["public_key"])


if __name__ == "__main__":
    unittest.main()
