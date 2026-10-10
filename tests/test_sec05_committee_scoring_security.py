"""
BidTrace 3.0 - Security Verification Suite: SEC-05
Committee Grading Inclusivity & Outlier Math Edge Cases Defense Test

Vulnerability Context (SEC-05):
In finalize_technical_scores.rs (and ledger.py / verifier.py parity):
1. Evaluator Cherry-Picking: finalize_technical_scores allowed remaining.len() >= 3,
   enabling a corrupt authority to cherry-pick favorable evaluators and omit unfavorable
   evaluators from a 5-member committee. Enforced full committee roster completeness:
   remaining.len() == committee.evaluators.len() with IncompleteCommitteeGrades.
2. Zero-Median Variance Panic: When median == 0, (median * max_variance_bps) / 10000
   evaluated to 0. A minimum variance threshold floor of 100 bps (1.00%) guards against
   zero-median division / panic and false outlier flagging.
3. Empty Trimmed Pool Revert: If severe variance drops all evaluator scores in the trimmed pool,
   the protocol must cleanly revert with EmptyTrimmedScorePool instead of silently falling back.
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
from http.server import HTTPServer

from bidtrace_py.crypto import (
    generate_keypair,
    compute_tech_commitment,
    compute_fin_commitment,
    compute_grade_commitment
)
from bidtrace_py.ledger import BidTraceLedger, TenderStatus, EvaluationType
from bidtrace_py.relayer import BidTraceRelayerGateway
from bidtrace_py.verifier import AirGappedTribunalVerifier
from server import BidTraceHandler, state


class TestSEC05CommitteeScoringSecurity(unittest.TestCase):
    def setUp(self):
        self.ledger = BidTraceLedger()
        self.ledger.current_slot = 1000
        self.authority = generate_keypair()
        self.evaluators = [generate_keypair()["public_key"] for _ in range(5)]

    def _setup_tender_in_tech_eval(self, evaluator_count=5, max_variance_bps=2000):
        evaluators = [generate_keypair()["public_key"] for _ in range(evaluator_count)]
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id=f"TENDER-SEC05-{secrets.token_hex(4)}",
            submission_deadline_slot=1020,
            admin_review_deadline_slot=1030,
            tech_eval_deadline_slot=1050,
            fin_reveal_deadline_slot=1070
        )
        tender_pda = tender["pda"]

        # Initialize committee
        self.ledger.initialize_committee(
            tender_pda=tender_pda,
            authority_pubkey=self.authority["public_key"],
            evaluators=evaluators,
            max_variance_bps=max_variance_bps
        )

        # Register bidder
        bidder = generate_keypair()
        tech_comm = compute_tech_commitment(tender_pda, bidder["public_key"], "00"*32, "PROP_HASH").hex()
        fin_comm = compute_fin_commitment(tender_pda, bidder["public_key"], "11"*32, 5000000, "BOQ_HASH").hex()

        self.ledger.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder["public_key"],
            admin_dossier_hash="00"*32,
            tech_commitment_hash=tech_comm,
            fin_commitment_hash=fin_comm
        )

        # Advance to TechnicalEvaluation
        self.ledger.current_slot = 1035
        self.ledger.tenders[tender_pda]["status"] = TenderStatus.TechnicalEvaluation

        # Reveal technical bid
        self.ledger.reveal_technical_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder["public_key"],
            salt_tech="00"*32,
            proposal_hash="PROP_HASH"
        )

        return tender_pda, evaluators, bidder

    def test_01_incomplete_committee_grades_rejected_evaluator_cherry_picking(self):
        """
        Verify that an authority CANNOT omit evaluators (cherry-picking attack):
        submitting only 3 or 4 grades when committee has 5 members raises IncompleteCommitteeGrades.
        """
        tender_pda, evaluators, bidder = self._setup_tender_in_tech_eval(evaluator_count=5)

        # Evaluators 0, 1, 2 submit and reveal grades (3 out of 5)
        for i in range(3):
            ev = evaluators[i]
            comm = compute_grade_commitment(tender_pda, bidder["public_key"], ev, "00"*32, [1600]*5, "00"*32).hex()
            self.ledger.commit_evaluator_grade(tender_pda, ev, bidder["public_key"], comm)
            self.ledger.reveal_evaluator_grade(tender_pda, ev, bidder["public_key"], [1600]*5, "00"*32, "00"*32)

        # Authority attempts to finalize scores with only 3 of 5 grades
        with self.assertRaises(ValueError) as ctx:
            self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertIn("IncompleteCommitteeGrades", str(ctx.exception))

        # Evaluator 3 submits and reveals grade (4 out of 5)
        ev3 = evaluators[3]
        comm3 = compute_grade_commitment(tender_pda, bidder["public_key"], ev3, "00"*32, [1600]*5, "00"*32).hex()
        self.ledger.commit_evaluator_grade(tender_pda, ev3, bidder["public_key"], comm3)
        self.ledger.reveal_evaluator_grade(tender_pda, ev3, bidder["public_key"], [1600]*5, "00"*32, "00"*32)

        # Still 4 out of 5: must fail
        with self.assertRaises(ValueError) as ctx:
            self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertIn("IncompleteCommitteeGrades", str(ctx.exception))

        # Evaluator 4 submits and reveals grade (5 out of 5)
        ev4 = evaluators[4]
        comm4 = compute_grade_commitment(tender_pda, bidder["public_key"], ev4, "00"*32, [1600]*5, "00"*32).hex()
        self.ledger.commit_evaluator_grade(tender_pda, ev4, bidder["public_key"], comm4)
        self.ledger.reveal_evaluator_grade(tender_pda, ev4, bidder["public_key"], [1600]*5, "00"*32, "00"*32)

        # Full roster 5/5 submitted: finalize succeeds
        res = self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertEqual(res["final_score_bps"], 8000)
        self.assertTrue(res["is_tech_qualified"])

    def test_02_substituted_or_unauthorized_evaluator_rejected(self):
        """
        Verify that passing grades where one is from an unaccredited evaluator
        fails either at commit time with EvaluatorNotAuthorized or at finalization
        with IncompleteCommitteeGrades if roster completeness is not met.
        """
        tender_pda, evaluators, bidder = self._setup_tender_in_tech_eval(evaluator_count=5)
        fake_evaluator = generate_keypair()["public_key"]

        # Attempt to commit grade with unaccredited evaluator
        comm = compute_grade_commitment(tender_pda, bidder["public_key"], fake_evaluator, "00"*32, [1600]*5, "00"*32).hex()
        with self.assertRaises(ValueError) as ctx:
            self.ledger.commit_evaluator_grade(tender_pda, fake_evaluator, bidder["public_key"], comm)
        self.assertIn("EvaluatorNotAuthorized", str(ctx.exception))

        # Directly inject a fake grade into evaluator_grades to simulate forged storage
        fake_pda = f"grade_{fake_evaluator}"
        self.ledger.evaluator_grades[fake_pda] = {
            "tender": tender_pda,
            "bidder": bidder["public_key"],
            "evaluator": fake_evaluator,
            "commitment_hash": comm,
            "is_revealed": True,
            "sub_scores": [1600]*5,
            "total_score_bps": 8000,
            "justification_hash": "00"*32,
            "is_outlier_flagged": False
        }

        # 4 legitimate evaluators reveal
        for ev in evaluators[:4]:
            comm_legit = compute_grade_commitment(tender_pda, bidder["public_key"], ev, "00"*32, [1600]*5, "00"*32).hex()
            self.ledger.commit_evaluator_grade(tender_pda, ev, bidder["public_key"], comm_legit)
            self.ledger.reveal_evaluator_grade(tender_pda, ev, bidder["public_key"], [1600]*5, "00"*32, "00"*32)

        # Finalize technical scores must reject because the committee roster of 5 accredited evaluators is not satisfied
        with self.assertRaises(ValueError) as ctx2:
            self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertIn("IncompleteCommitteeGrades", str(ctx2.exception))

    def test_03_zero_median_variance_floor_prevents_false_outliers(self):
        """
        Verify that when median == 0, the minimum variance floor of 100 bps (1.00%)
        prevents zero-division / panic and false outlier pruning.
        """
        tender_pda, evaluators, bidder = self._setup_tender_in_tech_eval(evaluator_count=5)

        # All 5 evaluators submit score of 0
        for ev in evaluators:
            comm = compute_grade_commitment(tender_pda, bidder["public_key"], ev, "00"*32, [0]*5, "00"*32).hex()
            self.ledger.commit_evaluator_grade(tender_pda, ev, bidder["public_key"], comm)
            self.ledger.reveal_evaluator_grade(tender_pda, ev, bidder["public_key"], [0]*5, "00"*32, "00"*32)

        res = self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertEqual(res["median_score_bps"], 0)
        self.assertEqual(res["final_score_bps"], 0)
        self.assertEqual(res["outliers_pruned"], 0)
        self.assertFalse(res["is_tech_qualified"])

    def test_04_zero_median_within_floor_scores_accepted(self):
        """
        Verify that when median == 0, minor non-zero scores <= 100 bps (e.g. 50, 80)
        are NOT flagged as outliers because they fall within the 100 bps floor.
        """
        tender_pda, evaluators, bidder = self._setup_tender_in_tech_eval(evaluator_count=5)

        # Scores: [0, 0, 0, 50, 80]
        sub_scores_list = [
            [0]*5,
            [0]*5,
            [0]*5,
            [10, 10, 10, 10, 10],   # 50 bps
            [16, 16, 16, 16, 16]    # 80 bps
        ]

        for ev, subs in zip(evaluators, sub_scores_list):
            comm = compute_grade_commitment(tender_pda, bidder["public_key"], ev, "00"*32, subs, "00"*32).hex()
            self.ledger.commit_evaluator_grade(tender_pda, ev, bidder["public_key"], comm)
            self.ledger.reveal_evaluator_grade(tender_pda, ev, bidder["public_key"], subs, "00"*32, "00"*32)

        res = self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertEqual(res["median_score_bps"], 0)
        # 50 and 80 are within 100 bps floor of median 0 -> 0 outliers pruned
        self.assertEqual(res["outliers_pruned"], 0)
        # Dropping min (0) and max (80) leaves [0, 0, 50], average = 50 // 3 = 16 bps
        self.assertEqual(res["final_score_bps"], 16)

    def test_05_zero_median_large_variation_correctly_flagged_as_outlier(self):
        """
        Verify that when median == 0, a rogue score of 5000 bps (> 100 bps floor)
        is correctly identified and flagged as an outlier.
        """
        tender_pda, evaluators, bidder = self._setup_tender_in_tech_eval(evaluator_count=5)

        # Scores: [0, 0, 0, 0, 5000]
        sub_scores_list = [
            [0]*5,
            [0]*5,
            [0]*5,
            [0]*5,
            [1000, 1000, 1000, 1000, 1000] # 5000 bps
        ]

        for ev, subs in zip(evaluators, sub_scores_list):
            comm = compute_grade_commitment(tender_pda, bidder["public_key"], ev, "00"*32, subs, "00"*32).hex()
            self.ledger.commit_evaluator_grade(tender_pda, ev, bidder["public_key"], comm)
            self.ledger.reveal_evaluator_grade(tender_pda, ev, bidder["public_key"], subs, "00"*32, "00"*32)

        res = self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertEqual(res["median_score_bps"], 0)
        self.assertEqual(res["outliers_pruned"], 1)
        self.assertEqual(res["final_score_bps"], 0)

    def test_06_empty_trimmed_pool_reverts_on_severe_variance(self):
        """
        Verify that when severe variance drops all middle scores in the trimmed pool,
        the contract / ledger cleanly reverts with EmptyTrimmedScorePool instead of
        silently falling back to median.
        """
        # Committee of 4 evaluators, max_variance_bps = 2000 (20%)
        tender_pda, evaluators, bidder = self._setup_tender_in_tech_eval(evaluator_count=4, max_variance_bps=2000)

        # Polarized scores: [1000, 1000, 9000, 9000]
        # Min 1000 dropped, Max 9000 dropped.
        # Middle elements: [1000, 9000]
        # Median = (1000 + 9000) // 2 = 5000
        # max_delta = (5000 * 2000) // 10000 = 1000
        # Delta for 1000 is 4000 > 1000 -> pruned
        # Delta for 9000 is 4000 > 1000 -> pruned
        # Accepted pool is EMPTY!
        sub_scores_list = [
            [200]*5,    # 1000
            [200]*5,    # 1000
            [1800]*5,   # 9000
            [1800]*5    # 9000
        ]

        for ev, subs in zip(evaluators, sub_scores_list):
            comm = compute_grade_commitment(tender_pda, bidder["public_key"], ev, "00"*32, subs, "00"*32).hex()
            self.ledger.commit_evaluator_grade(tender_pda, ev, bidder["public_key"], comm)
            self.ledger.reveal_evaluator_grade(tender_pda, ev, bidder["public_key"], subs, "00"*32, "00"*32)

        with self.assertRaises(ValueError) as ctx:
            self.ledger.finalize_technical_scores(tender_pda, self.authority["public_key"], bidder["public_key"])
        self.assertIn("EmptyTrimmedScorePool", str(ctx.exception))


class TestSEC05RestApiAndVerifierParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_port = 8105
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

    def test_rest_api_rejects_incomplete_committee_evaluation(self):
        """
        Verify that /api/tender/finalize_technical returns 400 if committee roster is incomplete.
        """
        self._post("/api/reset", {})
        self._post("/api/tender/create", {
            "tender_id": "TENDER-SEC05-API-001",
            "title": "SEC-05 REST Inclusivity Test",
            "evaluation_type": "QCBS"
        })

        b1_kp = generate_keypair()
        comm_pda = state.ledger.derive_committee_pda(state.tender_pda)
        evaluators = state.ledger.committees[comm_pda]["evaluators"] # 5 default evaluators

        # Setup bidder in technical evaluation
        state.ledger.advance_slot(100)
        state.ledger.tenders[state.tender_pda]["status"] = TenderStatus.TechnicalEvaluation
        b1_pda = state.ledger.derive_bid_pda(state.tender_pda, b1_kp["public_key"])
        state.ledger.commitments[b1_pda] = {
            "tender_pda": state.tender_pda,
            "bidder": b1_kp["public_key"],
            "is_tech_revealed": True,
            "is_tech_qualified": False,
            "is_fin_revealed": False,
            "technical_score_bps": 0,
            "revealed_price": 0
        }

        # Only 3 of 5 evaluators commit and reveal
        for ev in evaluators[:3]:
            comm = compute_grade_commitment(
                state.tender_pda, b1_kp["public_key"], ev, "00"*32, [1600]*5, "00"*32
            ).hex()
            state.ledger.commit_evaluator_grade(
                state.tender_pda, ev, b1_kp["public_key"], comm
            )
            state.ledger.reveal_evaluator_grade(
                state.tender_pda, ev, b1_kp["public_key"], [1600]*5, "00"*32, "00"*32
            )

        # Call finalize via API
        req = urllib.request.Request(
            f"{self.server_address}/api/tender/finalize_technical",
            data=json.dumps({"bidder_pubkeys": [b1_kp["public_key"]]}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.fail("Expected HTTP 400 for incomplete committee roster")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 400)
            err_data = json.loads(err.read().decode("utf-8"))
            self.assertIn("IncompleteCommitteeGrades", err_data.get("message", ""))

    def test_verifier_detects_incomplete_committee_evaluation(self):
        """
        Verify that AirGappedTribunalVerifier flags incomplete committee evaluation.
        """
        evaluators = [f"EV_{i}" for i in range(5)]
        dossier = {
            "ledger/solana_state_proofs.json": {
                "tender": {
                    "tender_id": "TENDER-VERIFY-001",
                    "min_tech_score_bps": 7500
                },
                "committee": {
                    "evaluators": evaluators,
                    "max_variance_bps": 2000
                },
                "commitments": {
                    "b1": {"bidder": "BIDDER_1", "technical_score_bps": 8000, "is_tech_qualified": True}
                },
                "evaluator_grades": {
                    f"g_{i}": {
                        "tender": "TENDER_PDA",
                        "bidder": "BIDDER_1",
                        "evaluator": evaluators[i],
                        "is_revealed": True,
                        "sub_scores": [1600]*5,
                        "total_score_bps": 8000,
                        "is_outlier_flagged": False
                    } for i in range(3) # Only 3 of 5
                }
            }
        }

        verifier = AirGappedTribunalVerifier(dossier)
        res = verifier.verify_phase4_committee_and_trimmed_mean()
        self.assertFalse(res["valid"])
        self.assertTrue(any("Incomplete committee evaluation" in err for err in res["errors"]))


if __name__ == "__main__":
    unittest.main()
