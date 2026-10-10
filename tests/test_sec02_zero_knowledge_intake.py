"""
Test Suite: SEC-02 Relayer Gateway Zero-Knowledge Blind Intake & Commercial Secrecy
===================================================================================
Verifies:
1. Zero-Knowledge Blind Intake: Relayer gateway ingests precomputed commitment hashes
   (tech_commitment_hash, fin_commitment_hash) without requiring plaintext price or salt.
2. Invariant: Server memory (relayer.bidder_receipts, state.bidders_receipts) strictly
   seals Envelope B ("SEALED_COMMERCIAL_SECRECY_PRESERVED", price=0) during intake.
3. Commercial Secrecy Guarantee: Disqualified contractors ($S_tech < 75.00%$) NEVER have
   Envelope B preimages stored, logged, or exposed in server memory or tribunal dossiers.
4. Qualified Contractors Deferred Reveal: Envelope B is unsealed on-chain exclusively for
   candidates passing the technical cutoff.
5. Full lifecycle Tribunal Dossier verification passes all 5 phases with Commercial Secrecy.
"""

import os
import json
import secrets
import hashlib
import tempfile
import shutil
import threading
import socketserver
import urllib.request
import unittest

from bidtrace_py.crypto import (
    generate_keypair,
    compute_tech_commitment,
    compute_fin_commitment,
    compute_grade_commitment
)
from bidtrace_py.ledger import (
    BidTraceLedger,
    TenderStatus,
    TenderMode,
    EvaluationType,
    BondMode
)
from bidtrace_py.relayer import BidTraceRelayerGateway
from bidtrace_py.verifier import (
    export_tribunal_dossier,
    AirGappedTribunalVerifier
)
from server import BidTraceHandler, state as server_state


class TestSec02ZeroKnowledgeIntake(unittest.TestCase):
    """Unit and integration tests for SEC-02 resolution."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.relayer = BidTraceRelayerGateway()
        self.authority = generate_keypair()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_blind_intake_precomputed_hashes(self):
        """
        Verify that commit_dual_bid accepts blind precomputed hashes without
        any plaintext price or financial salt, and stores a sealed server receipt.
        """
        tender_res = self.relayer.create_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC02-BLIND-001",
            title="Zero-Knowledge Intake Tender",
            description="Tender testing blind commitment hash intake",
            buyer_name="Public Works Ministry",
            currency="USD",
            estimated_amount=5000000.0,
            evaluation_type="QCBS",
            tech_weight=0.70,
            fin_weight=0.30,
            min_tech_score=75.0,
            bond_amount=190000.0,
            bond_mode_str="SuretyService"
        )
        t_pda = tender_res["tender"]["pda"]

        # Contractor generates hashes locally (air-gapped)
        contractor = generate_keypair()
        local_salt_tech = secrets.token_hex(32)
        local_proposal_hash = hashlib.sha256(b"CONFIDENTIAL_PROPOSAL_BLUEPRINTS").hexdigest()
        local_salt_fin = secrets.token_hex(32)
        local_price = 3750000
        local_boq_hash = hashlib.sha256(b"CONFIDENTIAL_BOQ_SCHEDULE").hexdigest()

        blind_comm_tech = compute_tech_commitment(t_pda, contractor["public_key"], local_salt_tech, local_proposal_hash).hex()
        blind_comm_fin = compute_fin_commitment(t_pda, contractor["public_key"], local_salt_fin, local_price, local_boq_hash).hex()

        # Submit ONLY hashes to relayer (NO plaintext price, NO salt_fin)
        res = self.relayer.commit_dual_bid(
            tender_pda=t_pda,
            bidder_pubkey=contractor["public_key"],
            bidder_name="Confidential Construction AG",
            admin_dossier_hash="aa" * 32,
            tech_commitment_hash=blind_comm_tech,
            fin_commitment_hash=blind_comm_fin,
            bond_mode=int(BondMode.SuretyService),
            bond_amount=190000
        )

        # 1. On-chain commitment holds the hashes
        bid_pda = self.relayer.ledger.derive_bid_pda(t_pda, contractor["public_key"])
        bid_acc = self.relayer.ledger.commitments[bid_pda]
        self.assertEqual(bid_acc["tech_commitment_hash"], blind_comm_tech)
        self.assertEqual(bid_acc["fin_commitment_hash"], blind_comm_fin)

        # 2. Server-side stored receipt strictly seals Envelope B
        server_receipt = self.relayer.bidder_receipts[contractor["public_key"]]
        p_img = server_receipt["unsealingPreimages"]
        self.assertEqual(p_img["saltFin"], "SEALED_COMMERCIAL_SECRECY_PRESERVED")
        self.assertEqual(p_img["price"], 0)
        self.assertEqual(p_img["boqHash"], "SEALED_COMMERCIAL_SECRECY_PRESERVED")
        self.assertIn("secrecyNotice", p_img)

    def test_commercial_secrecy_memory_isolation_and_disqualification(self):
        """
        Verify that disqualified contractors' financial trade secrets are NEVER
        stored in server memory, and that legitimate qualification unseals Envelope B.
        """
        evaluators = [generate_keypair()["public_key"] for _ in range(5)]
        tender_res = self.relayer.create_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC02-ISOLATION",
            title="Commercial Secrecy Isolation Tender",
            description="Testing memory isolation",
            buyer_name="Dept of Highways",
            currency="USD",
            estimated_amount=4000000.0,
            evaluation_type="QCBS",
            tech_weight=0.70,
            fin_weight=0.30,
            min_tech_score=75.0,
            bond_amount=150000.0,
            bond_mode_str="SuretyService",
            evaluators=evaluators
        )
        t_pda = tender_res["tender"]["pda"]

        # Bidder 1: Qualified Contractor
        b1_kp = generate_keypair()
        b1_salt_tech = secrets.token_hex(32)
        b1_prop_h = hashlib.sha256(b"TECH_PROPOSAL_1").hexdigest()
        b1_salt_fin = secrets.token_hex(32)
        b1_price = 3800000
        b1_boq_h = hashlib.sha256(b"BOQ_1").hexdigest()

        commit1 = self.relayer.commit_dual_bid(
            tender_pda=t_pda,
            bidder_pubkey=b1_kp["public_key"],
            bidder_name="Qualified Builder Co",
            admin_dossier_hash="11" * 32,
            salt_tech=b1_salt_tech,
            proposal_hash=b1_prop_h,
            salt_fin=b1_salt_fin,
            price=b1_price,
            boq_hash=b1_boq_h,
            bond_mode=int(BondMode.SuretyService),
            bond_amount=150000
        )

        # Bidder 2: Substandard / Disqualified Contractor
        b2_kp = generate_keypair()
        b2_salt_tech = secrets.token_hex(32)
        b2_prop_h = hashlib.sha256(b"TECH_PROPOSAL_2_FLAWED").hexdigest()
        b2_salt_fin = secrets.token_hex(32)
        b2_price = 2800000  # Low price secret
        b2_boq_h = hashlib.sha256(b"BOQ_2").hexdigest()

        commit2 = self.relayer.commit_dual_bid(
            tender_pda=t_pda,
            bidder_pubkey=b2_kp["public_key"],
            bidder_name="Disqualified Contractor Ltd",
            admin_dossier_hash="22" * 32,
            salt_tech=b2_salt_tech,
            proposal_hash=b2_prop_h,
            salt_fin=b2_salt_fin,
            price=b2_price,
            boq_hash=b2_boq_h,
            bond_mode=int(BondMode.SuretyService),
            bond_amount=150000
        )

        # CHECK 1: Before technical evaluation, BOTH bidder receipts in server memory are SEALED
        r1_server = self.relayer.bidder_receipts[b1_kp["public_key"]]
        r2_server = self.relayer.bidder_receipts[b2_kp["public_key"]]
        self.assertEqual(r1_server["unsealingPreimages"]["saltFin"], "SEALED_COMMERCIAL_SECRECY_PRESERVED")
        self.assertEqual(r1_server["unsealingPreimages"]["price"], 0)
        self.assertEqual(r2_server["unsealingPreimages"]["saltFin"], "SEALED_COMMERCIAL_SECRECY_PRESERVED")
        self.assertEqual(r2_server["unsealingPreimages"]["price"], 0)

        # But returning client receipts contain their air-gapped preimages for their own wallet
        self.assertEqual(commit1["receipt"]["unsealingPreimages"]["price"], b1_price)
        self.assertEqual(commit2["receipt"]["unsealingPreimages"]["price"], b2_price)

        # Advance to Tech Eval
        self.relayer.ledger.advance_tender_phase(t_pda) # SubmissionsOpen -> AdministrativeReview
        self.relayer.ledger.advance_tender_phase(t_pda) # AdministrativeReview -> TechnicalEvaluation
        self.relayer.ledger.reveal_technical_bid(t_pda, b1_kp["public_key"], b1_salt_tech, b1_prop_h)
        self.relayer.ledger.reveal_technical_bid(t_pda, b2_kp["public_key"], b2_salt_tech, b2_prop_h)

        # Evaluator Scoring:
        # B1 gets 8200 bps (> 7500 bps -> Qualified)
        # B2 gets 6200 bps (< 7500 bps -> Disqualified)
        for ev in evaluators:
            # Score B1
            s1 = [1640] * 5
            c1 = compute_grade_commitment(t_pda, b1_kp["public_key"], ev, "00"*32, s1, "00"*32).hex()
            self.relayer.ledger.commit_evaluator_grade(t_pda, ev, b1_kp["public_key"], c1)
            self.relayer.ledger.reveal_evaluator_grade(t_pda, ev, b1_kp["public_key"], s1, "00"*32, "00"*32)
            # Score B2
            s2 = [1240] * 5
            c2 = compute_grade_commitment(t_pda, b2_kp["public_key"], ev, "00"*32, s2, "00"*32).hex()
            self.relayer.ledger.commit_evaluator_grade(t_pda, ev, b2_kp["public_key"], c2)
            self.relayer.ledger.reveal_evaluator_grade(t_pda, ev, b2_kp["public_key"], s2, "00"*32, "00"*32)

        eval_res = self.relayer.finalize_technical_evaluation(
            tender_pda=t_pda,
            authority_pubkey=self.authority["public_key"],
            bidder_pubkeys=[b1_kp["public_key"], b2_kp["public_key"]]
        )
        self.assertEqual(eval_res["total_qualified"], 1)

        # Advance to Financial Evaluation
        self.relayer.ledger.advance_slot(30)
        self.relayer.ledger.advance_tender_phase(t_pda)
        self.assertEqual(self.relayer.ledger.tenders[t_pda]["status"], TenderStatus.FinancialEvaluation)

        # CHECK 2: Adversary attempts to unseal Disqualified B2's Envelope B -> MUST FAIL
        with self.assertRaises(ValueError) as ctx:
            self.relayer.ledger.reveal_financial_envelope(
                tender_pda=t_pda,
                bidder_pubkey=b2_kp["public_key"],
                salt_fin=b2_salt_fin,
                price=b2_price,
                boq_hash=b2_boq_h
            )
        self.assertIn("BidderTechnicallyDisqualified", str(ctx.exception))

        # Check B2's receipt in relayer memory remains permanently sealed
        r2_server_after = self.relayer.bidder_receipts[b2_kp["public_key"]]
        self.assertEqual(r2_server_after["unsealingPreimages"]["saltFin"], "SEALED_COMMERCIAL_SECRECY_PRESERVED")
        self.assertEqual(r2_server_after["unsealingPreimages"]["price"], 0)

        # CHECK 3: Qualified B1 unseals Envelope B -> SUCCEEDS
        unseal_b1 = self.relayer.ledger.reveal_financial_envelope(
            tender_pda=t_pda,
            bidder_pubkey=b1_kp["public_key"],
            salt_fin=b1_salt_fin,
            price=b1_price,
            boq_hash=b1_boq_h
        )
        self.assertTrue(unseal_b1["is_fin_revealed"])
        self.assertEqual(unseal_b1["revealed_price"], b1_price)

        # Relayer memory for B1 is now updated for public tribunal verification
        r1_server_after = self.relayer.bidder_receipts[b1_kp["public_key"]]
        self.assertEqual(r1_server_after["unsealingPreimages"]["saltFin"], b1_salt_fin)
        self.assertEqual(r1_server_after["unsealingPreimages"]["price"], b1_price)

        # Record Award
        self.relayer.record_award(
            tender_pda=t_pda,
            authority_pubkey=self.authority["public_key"],
            winning_bidder_pubkey=b1_kp["public_key"],
            winner_name="Qualified Builder Co"
        )

        # CHECK 4: Export Tribunal Dossier and Verify All 5 Phases
        zip_path = os.path.join(self.tmpdir, "tribunal_dossier.zip")
        export_res = export_tribunal_dossier(self.relayer, output_path=zip_path, tender_pda=t_pda)
        self.assertTrue(os.path.exists(zip_path))

        verifier = AirGappedTribunalVerifier(zip_path)
        audit_report = verifier.verify_all()
        self.assertTrue(audit_report["valid"], f"Audit failed: {audit_report.get('findings')}")
        self.assertTrue(audit_report["critical_invariants_verified"]["commercial_secrecy_invariant"])
        self.assertTrue(audit_report["phases"]["phase5_financial_and_qcbs_award"]["commercial_secrecy_preserved"])


class TestSec02RestApiHttpIntegration(unittest.TestCase):
    """End-to-end HTTP integration tests for Zero-Knowledge Blind Intake & Secrecy."""

    @classmethod
    def setUpClass(cls):
        cls.server_state = server_state
        cls.server_state.reset()
        cls.port = 8892

        socketserver.TCPServer.allow_reuse_address = True
        cls.httpd = socketserver.TCPServer(("127.0.0.1", cls.port), BidTraceHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _post(self, path: str, payload: dict) -> dict:
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode('utf-8'))

    def test_http_blind_intake_and_client_reveals_flow(self):
        # 1. Reset
        r_reset = self._post("/api/reset", {})
        self.assertEqual(r_reset["status"], "ok")

        # 2. Init Tender
        r_tender = self._post("/api/tender/create", {
            "tender_id": "TENDER-HTTP-SEC02",
            "title": "HTTP Blind Intake Test",
            "min_tech_score": 75.0,
            "bond_amount": 190000.0
        })
        self.assertEqual(r_tender["status"], "ok")
        tender_pda = r_tender["tender"]["pda"]

        # 3. Bidder Alpha commits using precomputed blind commitment hashes
        kp_alpha = generate_keypair()
        s_tech = secrets.token_hex(32)
        p_hash = hashlib.sha256(b"PROPOSAL_ALPHA").hexdigest()
        s_fin = secrets.token_hex(32)
        price_alpha = 3600000
        boq_h = hashlib.sha256(b"BOQ_ALPHA").hexdigest()

        tech_comm = compute_tech_commitment(tender_pda, kp_alpha["public_key"], s_tech, p_hash).hex()
        fin_comm = compute_fin_commitment(tender_pda, kp_alpha["public_key"], s_fin, price_alpha, boq_h).hex()

        # Submit ONLY hashes to API
        r_commit = self._post("/api/bid/commit_dual", {
            "bidder_pubkey": kp_alpha["public_key"],
            "bidder_name": "Alpha Blind Bidder",
            "tech_commitment_hash": tech_comm,
            "fin_commitment_hash": fin_comm,
            "bond_mode": 1,
            "bond_amount": 190000
        })
        self.assertEqual(r_commit["status"], "ok")
        self.assertIn("server_receipt", r_commit)
        # Server receipt strictly sealed
        self.assertEqual(r_commit["server_receipt"]["unsealingPreimages"]["saltFin"], "SEALED_COMMERCIAL_SECRECY_PRESERVED")
        self.assertEqual(r_commit["server_receipt"]["unsealingPreimages"]["price"], 0)

        # 4. Advance phase to TechnicalEvaluation
        self._post("/api/tender/advance_phase", {}) # SubmissionsOpen -> AdministrativeReview
        self._post("/api/tender/advance_phase", {}) # AdministrativeReview -> TechnicalEvaluation

        # Reveal tech
        self._post("/api/bid/reveal_technical", {
            "bidder_pubkey": kp_alpha["public_key"],
            "salt_tech": s_tech,
            "proposal_hash": p_hash
        })

        # Submit evaluator grades
        comm_pda = self.server_state.ledger.derive_committee_pda(tender_pda)
        evaluators = self.server_state.ledger.committees[comm_pda]["evaluators"]
        for ev in evaluators:
            sub = [1800] * 5 # 90.00%
            s_ev = secrets.token_hex(32)
            c_ev = compute_grade_commitment(tender_pda, kp_alpha["public_key"], ev, s_ev, sub, "00"*32).hex()
            self._post("/api/evaluator/commit_grade", {
                "evaluator_pubkey": ev,
                "bidder_pubkey": kp_alpha["public_key"],
                "commitment_hash": c_ev
            })
            self._post("/api/evaluator/reveal_grade", {
                "evaluator_pubkey": ev,
                "bidder_pubkey": kp_alpha["public_key"],
                "sub_scores": sub,
                "salt": s_ev,
                "justification_hash": "00"*32
            })

        # Finalize tech scores
        self._post("/api/tender/finalize_technical", {})

        # Advance to Financial Evaluation
        self._post("/api/tender/advance_phase", {})

        # 5. Reveal Financial using batch reveals array provided by client
        r_reveal = self._post("/api/bid/reveal_financial", {
            "reveals": [{
                "bidder_pubkey": kp_alpha["public_key"],
                "salt_fin": s_fin,
                "price": price_alpha,
                "boq_hash": boq_h
            }]
        })
        self.assertEqual(r_reveal["status"], "ok")
        self.assertEqual(len(r_reveal["revealed"]), 1)
        self.assertEqual(r_reveal["revealed"][0]["revealed_price"], price_alpha)

        # 6. Verify empty / missing reveals is rejected with Commercial Secrecy explanation
        r_empty = self._post("/api/bid/reveal_financial", {})
        self.assertEqual(r_empty["status"], "error")
        self.assertIn("Commercial Secrecy Invariant", r_empty["message"])


if __name__ == "__main__":
    unittest.main()
