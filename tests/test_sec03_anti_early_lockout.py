"""
BidTrace 3.0 - Security Verification Suite: SEC-03
Authority Early-Lockout Denial-of-Service Bypass Defense Test

Vulnerability Context (SEC-03):
In advance_tender_phase.rs, the original condition allowed the tender authority
to bypass consensus slot deadlines (clock.slot > deadline || caller == tender.authority).
A corrupt authority could prematurely advance phases:
1. Locking out honest bidders before submission_deadline_slot (denial-of-service).
2. Locking out accredited evaluators before tech_eval_deadline_slot.

Fix Verification:
1. Authority CANNOT prematurely advance tender phase before consensus deadlines elapse.
2. Honest contractors can submit dual-envelope bids right up to the deadline.
3. Advance succeeds strictly after clock.slot > deadline.
4. Evaluators are guaranteed their scoring window without authority truncation.
5. REST API rejects premature phase advance when consensus slot has not reached deadline.
"""

import unittest
import os
import sys
import json
import secrets
import hashlib
import threading
import time
import urllib.request
import urllib.error
from typing import Dict, Any

from bidtrace_py.crypto import generate_keypair, compute_tech_commitment, compute_fin_commitment, compute_grade_commitment
from bidtrace_py.ledger import BidTraceLedger, TenderStatus
from bidtrace_py.relayer import BidTraceRelayerGateway
from bidtrace_py.bonds import BondMode


class TestSEC03AntiEarlyLockout(unittest.TestCase):
    def setUp(self):
        self.ledger = BidTraceLedger()
        self.ledger.current_slot = 1000
        self.authority = generate_keypair()
        self.evaluators = [generate_keypair()["public_key"] for _ in range(5)]

    def test_authority_cannot_prematurely_close_submissions_window(self):
        """
        Verify that a corrupt authority calling advance_tender_phase before
        submission_deadline_slot is strictly rejected with SubmissionDeadlineNotReached.
        """
        sub_deadline = 1050
        admin_deadline = 1070
        tech_deadline = 1090

        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC03-ANTILOCKOUT-001",
            submission_deadline_slot=sub_deadline,
            admin_review_deadline_slot=admin_deadline,
            tech_eval_deadline_slot=tech_deadline
        )
        tender_pda = tender["pda"]

        # Current slot is 1000, deadline is 1050.
        self.assertEqual(self.ledger.current_slot, 1000)
        self.assertEqual(tender["status"], TenderStatus.SubmissionsOpen)

        # 1. Authority attempts premature phase advancement (Early Lockout Attack)
        with self.assertRaises(ValueError) as ctx:
            self.ledger.advance_tender_phase(
                tender_pda=tender_pda,
                caller_pubkey=self.authority["public_key"]
            )
        self.assertIn("SubmissionDeadlineNotReached", str(ctx.exception))
        self.assertEqual(self.ledger.tenders[tender_pda]["status"], TenderStatus.SubmissionsOpen)

        # 2. Third-party caller also attempts premature advance -> rejected
        random_caller = generate_keypair()["public_key"]
        with self.assertRaises(ValueError) as ctx:
            self.ledger.advance_tender_phase(
                tender_pda=tender_pda,
                caller_pubkey=random_caller
            )
        self.assertIn("SubmissionDeadlineNotReached", str(ctx.exception))

        # 3. Honest bidder submits bid at slot 1025 during open window
        self.ledger.current_slot = 1025
        bidder = generate_keypair()
        bid = self.ledger.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder["public_key"],
            admin_dossier_hash="11" * 32,
            tech_commitment_hash="22" * 32,
            fin_commitment_hash="33" * 32
        )
        self.assertEqual(self.ledger.tenders[tender_pda]["total_committed"], 1)

        # 4. Authority attempts premature advance at slot 1049 -> STILL strictly rejected
        self.ledger.current_slot = 1049
        with self.assertRaises(ValueError) as ctx:
            self.ledger.advance_tender_phase(
                tender_pda=tender_pda,
                caller_pubkey=self.authority["public_key"]
            )
        self.assertIn("SubmissionDeadlineNotReached", str(ctx.exception))

        # 5. At slot 1050 (exact deadline), still not strictly greater than deadline
        self.ledger.current_slot = 1050
        with self.assertRaises(ValueError) as ctx:
            self.ledger.advance_tender_phase(
                tender_pda=tender_pda,
                caller_pubkey=self.authority["public_key"]
            )
        self.assertIn("SubmissionDeadlineNotReached", str(ctx.exception))

        # 6. Consensus slot passes deadline (slot 1051 > 1050)
        self.ledger.current_slot = 1051
        advanced_tender = self.ledger.advance_tender_phase(
            tender_pda=tender_pda,
            caller_pubkey=self.authority["public_key"]
        )
        self.assertEqual(advanced_tender["status"], TenderStatus.AdministrativeReview)

    def test_administrative_and_technical_anti_lockout_progression(self):
        """
        Verify that early lockout defense protects administrative review and
        technical evaluation deadlines from being prematurely terminated.
        """
        sub_deadline = 1050
        admin_deadline = 1070
        tech_deadline = 1090

        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC03-ANTILOCKOUT-002",
            submission_deadline_slot=sub_deadline,
            admin_review_deadline_slot=admin_deadline,
            tech_eval_deadline_slot=tech_deadline
        )
        tender_pda = tender["pda"]
        self.ledger.initialize_committee(tender_pda, self.authority["public_key"], self.evaluators)

        # Contractor commits dual bid during open submission window (slot 1020)
        self.ledger.current_slot = 1020
        bidder = generate_keypair()
        salt_tech = "aa" * 32
        prop_hash = "bb" * 32
        tech_comm = compute_tech_commitment(tender_pda, bidder["public_key"], salt_tech, prop_hash).hex()
        self.ledger.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder["public_key"],
            admin_dossier_hash="00" * 32,
            tech_commitment_hash=tech_comm,
            fin_commitment_hash="22" * 32
        )

        # Advance past submission deadline to AdministrativeReview
        self.ledger.current_slot = 1051
        self.ledger.advance_tender_phase(tender_pda, caller_pubkey=self.authority["public_key"])
        self.assertEqual(self.ledger.tenders[tender_pda]["status"], TenderStatus.AdministrativeReview)

        # 1. Authority attempts to prematurely terminate AdministrativeReview at slot 1060
        self.ledger.current_slot = 1060
        with self.assertRaises(ValueError) as ctx:
            self.ledger.advance_tender_phase(
                tender_pda=tender_pda,
                caller_pubkey=self.authority["public_key"]
            )
        self.assertIn("AdminReviewDeadlineNotReached", str(ctx.exception))

        # 2. Once slot passes admin deadline (1071 > 1070), advance to TechnicalEvaluation succeeds
        self.ledger.current_slot = 1071
        self.ledger.advance_tender_phase(tender_pda, caller_pubkey=self.authority["public_key"])
        self.assertEqual(self.ledger.tenders[tender_pda]["status"], TenderStatus.TechnicalEvaluation)

        # 3. Unseal technical bid
        self.ledger.reveal_technical_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder["public_key"],
            salt_tech=salt_tech,
            proposal_hash=prop_hash
        )

        # 4. Evaluators grade within technical evaluation window (slot 1080 <= 1090)
        self.ledger.current_slot = 1080
        comm_grade = compute_grade_commitment(
            tender_pda, bidder["public_key"], self.evaluators[0], "00"*32, [1800]*5, "00"*32
        ).hex()
        grade = self.ledger.commit_evaluator_grade(
            tender_pda=tender_pda,
            evaluator_pubkey=self.evaluators[0],
            bidder_pubkey=bidder["public_key"],
            commitment_hash=comm_grade,
            enforce_deadline=True
        )
        self.assertIsNotNone(grade)

        # 5. Authority attempts to prematurely close TechnicalEvaluation at slot 1085
        self.ledger.current_slot = 1085
        with self.assertRaises(ValueError) as ctx:
            self.ledger.advance_tender_phase(
                tender_pda=tender_pda,
                caller_pubkey=self.authority["public_key"]
            )
        self.assertIn("TechEvalDeadlineNotReached", str(ctx.exception))

        # 6. Once slot passes tech deadline (1091 > 1090), advance to FinancialEvaluation succeeds
        self.ledger.current_slot = 1091
        self.ledger.advance_tender_phase(tender_pda, caller_pubkey=self.authority["public_key"])
        self.assertEqual(self.ledger.tenders[tender_pda]["status"], TenderStatus.FinancialEvaluation)

        # 7. Late evaluator grade after deadline is rejected
        with self.assertRaises(ValueError) as ctx:
            self.ledger.commit_evaluator_grade(
                tender_pda=tender_pda,
                evaluator_pubkey=self.evaluators[1],
                bidder_pubkey=bidder["public_key"],
                commitment_hash=comm_grade,
                enforce_deadline=True
            )
        self.assertIn("TechEvalDeadlineExceeded", str(ctx.exception))

    def test_permissionless_advance_once_deadline_elapses(self):
        """
        Verify that ANY caller (permissionless keeper / bot) can advance the phase
        once the consensus deadline has passed.
        """
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC03-PERMISSIONLESS-003",
            submission_deadline_slot=1050,
            admin_review_deadline_slot=1050 # direct jump to TechEvaluation
        )
        tender_pda = tender["pda"]

        # Slot passes deadline
        self.ledger.current_slot = 1055
        unrelated_keeper = generate_keypair()["public_key"]

        # Unrelated keeper advances phase permissionlessly
        res = self.ledger.advance_tender_phase(
            tender_pda=tender_pda,
            caller_pubkey=unrelated_keeper
        )
        self.assertEqual(res["status"], TenderStatus.TechnicalEvaluation)


class TestSEC03RestApiAntiLockout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import HTTPServer
        from server import BidTraceHandler, state

        cls.server_port = 8769
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

    def test_rest_api_early_lockout_rejection(self):
        """
        Verify that /api/tender/advance_phase strictly rejects premature phase advance
        when advance_slot is disabled and consensus deadline has not elapsed.
        """
        # 1. Reset state & initialize tender
        self._post("/api/reset", {})
        init_res = self._post("/api/tender/create", {
            "tender_id": "TENDER-SEC03-API-001",
            "title": "Anti-Lockout API Verification",
            "estimated_amount": 1000000.0
        })
        self.assertEqual(init_res["status"], "ok")

        # 2. Attempt premature advance with advance_slot=False
        req = urllib.request.Request(
            f"{self.server_address}/api/tender/advance_phase",
            data=json.dumps({"advance_slot": False}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                self.fail("Expected 400 error for premature advance")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 400)
            err_data = json.loads(err.read().decode("utf-8"))
            self.assertIn("SubmissionDeadlineNotReached", err_data.get("message", ""))

        # 3. Standard advance with advance_slot=True (simulating consensus slot progression) succeeds
        adv_res = self._post("/api/tender/advance_phase", {"advance_slot": True})
        self.assertEqual(adv_res["status"], "ok")


if __name__ == "__main__":
    unittest.main()
