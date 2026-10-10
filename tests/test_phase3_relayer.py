"""
BidTrace 3.0 Phase 3 Automated Test Suite
=========================================
Tests:
1. Model A Pre-Qualified Merkle Whitelist generation & Anchor-compatible verification.
2. Multi-Jurisdiction Hybrid Bonds (Surety-as-a-Service, MT760, BSD, Escrow).
3. Two-Envelope state machine & gas-sponsored Relayer Gateway.
4. Evaluator blinded rubrics & Olympic Trimmed Mean rogue score outlier detection.
5. Commercial Secrecy Invariant (disqualified bidder permanently blocked from opening Envelope B).
6. Programmatic QCBS composite scoring and OCDS 1.1 full audit trail generation.
7. HTTP REST API endpoints live integration test.
"""

import unittest
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
    compute_grade_commitment,
    b58encode,
    b58decode,
    to_32bytes
)
from bidtrace_py.merkle import MerkleTree, verify_merkle_proof, compute_leaf
from bidtrace_py.bonds import (
    BondMode,
    issue_surety_policy,
    issue_bank_guarantee_attestation,
    sign_bid_securing_declaration,
    create_solana_escrow_record,
    list_all_bonds
)
from bidtrace_py.ledger import BidTraceLedger, TenderStatus, TenderMode, EvaluationType, BondMode as LedgerBondMode
from bidtrace_py.relayer import BidTraceRelayerGateway
from bidtrace_py.ocds import canonicalize_jcs, hash_canonical_json


class TestPhase3MerkleWhitelist(unittest.TestCase):
    """Tests Model A Pre-Qualified Merkle Whitelist Engine."""

    def test_merkle_tree_construction_and_proof_verification(self):
        bidders = [
            generate_keypair()["public_key"] for _ in range(5)
        ]
        tree = MerkleTree(bidders)
        root = tree.root

        self.assertEqual(len(root), 32)
        self.assertEqual(len(tree.leaves), 5)

        # Valid proofs for all approved members
        for bidder in bidders:
            proof = tree.get_proof(bidder)
            self.assertTrue(verify_merkle_proof(bidder, proof, root))
            
            proof_hex = tree.get_proof_hex(bidder)
            self.assertTrue(verify_merkle_proof(bidder, proof_hex, tree.root_hex))

        # Rejection of uninvited bidder
        rogue_bidder = generate_keypair()["public_key"]
        proof_for_bidder_0 = tree.get_proof(bidders[0])
        self.assertFalse(verify_merkle_proof(rogue_bidder, proof_for_bidder_0, root))


class TestPhase3HybridBondEngine(unittest.TestCase):
    """Tests Multi-Jurisdiction Hybrid Bond Engine."""

    def test_surety_as_a_service_issuance(self):
        policy = issue_surety_policy(
            bidder_id="BIDDER-ACME-01",
            bidder_name="ACME Infrastructure Corp",
            tender_id="TENDER-QCBS-2026-001",
            penal_sum_usd=190000.0,
            officer_name="Jane Doe, Chief Executive Officer",
            flat_fee_fiat=250.0
        )
        self.assertTrue(policy["policyId"].startswith("SURETY-POL-2026-"))
        self.assertEqual(policy["bondMode"], int(BondMode.SURETY_SERVICE))
        self.assertEqual(policy["fiatPremiumUsd"], 250.0)
        self.assertEqual(len(policy["giaCanonicalHash"]), 64)
        self.assertEqual(len(policy["canonicalHash"]), 64)
        self.assertIn("corporateOfficer", policy["giaDocument"]["indemnitor"])

    def test_digital_bank_guarantee_mt760(self):
        guarantee = issue_bank_guarantee_attestation(
            bidder_id="BIDDER-BUILDCO-02",
            bidder_name="BuildCo Global Ltd",
            tender_id="TENDER-QCBS-2026-001",
            bank_name="JPMorgan Chase Bank, N.A.",
            swift_bic="CHASUS33",
            guarantee_ref="BG-MT760-994821",
            amount_usd=190000.0,
            beneficiary_entity="Ministry of Public Works",
            expiry_date_iso="2026-12-31T23:59:59Z"
        )
        self.assertTrue(guarantee["attestationId"].startswith("BG-ATT-"))
        self.assertEqual(guarantee["bondMode"], int(BondMode.BANK_GUARANTEE))
        self.assertEqual(len(guarantee["mt760Hash"]), 64)
        self.assertEqual(guarantee["mt760Payload"]["swiftMessageType"], "MT760")

    def test_world_bank_bid_securing_declaration(self):
        bsd = sign_bid_securing_declaration(
            bidder_id="BIDDER-DEVCONSORT-03",
            bidder_name="Developing World Construction Consortium",
            tender_id="TENDER-QCBS-2026-001",
            procuring_entity="World Bank Project Implementation Unit",
            signatory_name="Dr. Kwame Mensah",
            signatory_title="Managing Director",
            sanction_period_months=36
        )
        self.assertTrue(bsd["declarationId"].startswith("BSD-DECL-"))
        self.assertEqual(bsd["bondMode"], int(BondMode.BID_SECURING_DECLARATION))
        self.assertEqual(bsd["sanctionPeriodMonths"], 36)
        self.assertIn("36 months", bsd["legalDeclarationText"])
        self.assertEqual(len(bsd["canonicalHash"]), 64)


class TestPhase3RelayerProtocolLifecycle(unittest.TestCase):
    """Tests full Two-Envelope procurement lifecycle via Relayer Gateway."""

    def setUp(self):
        self.relayer = BidTraceRelayerGateway()
        self.authority = generate_keypair()
        self.evaluators = [generate_keypair()["public_key"] for _ in range(5)]

    def test_full_two_envelope_qcbs_lifecycle(self):
        tender_id = "TENDER-AUTO-2026-001"
        
        # 1. Initialize Tender
        created = self.relayer.create_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id=tender_id,
            title="Express Highway Bypass",
            description="High priority corridor",
            buyer_name="National Highway Agency",
            evaluators=self.evaluators,
            min_tech_score=75.0,
            tech_weight=0.70,
            fin_weight=0.30
        )
        tender_pda = created["tender"]["pda"]
        self.assertEqual(created["tender"]["status"], TenderStatus.SubmissionsOpen)
        self.assertIn("REL-TENDER-AUTO-2026-001-01-TENDER-NOTICE", self.relayer.ocds_releases)

        # 2. Contractor A (High Quality, Compliant Price: $3.80M) commits
        bidderA = generate_keypair()
        saltTechA = secrets.token_hex(32)
        propA = hashlib.sha256(b"BLUEPRINTS_A_REINFORCED").hexdigest()
        saltFinA = secrets.token_hex(32)
        priceA = 3800000
        boqA = hashlib.sha256(b"BOQ_A_USD").hexdigest()

        suretyA = issue_surety_policy(
            bidder_id=bidderA["public_key"],
            bidder_name="Apex Highway Constructors",
            tender_id=tender_id,
            penal_sum_usd=190000.0,
            officer_name="Alice Vance, VP Operations"
        )

        commitA = self.relayer.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidderA["public_key"],
            bidder_name="Apex Highway Constructors",
            admin_dossier_hash="aa" * 32,
            salt_tech=saltTechA,
            proposal_hash=propA,
            salt_fin=saltFinA,
            price=priceA,
            boq_hash=boqA,
            bond_mode=int(BondMode.SURETY_SERVICE),
            bond_amount=190000,
            bond_record=suretyA
        )
        self.assertEqual(commitA["receipt"]["bidderPubkey"], bidderA["public_key"])

        # 3. Contractor B (Substandard Quality: $3.50M) commits
        bidderB = generate_keypair()
        saltTechB = secrets.token_hex(32)
        propB = hashlib.sha256(b"BLUEPRINTS_B_STANDARD").hexdigest()
        saltFinB = secrets.token_hex(32)
        priceB = 3500000
        boqB = hashlib.sha256(b"BOQ_B_USD").hexdigest()

        bsdB = sign_bid_securing_declaration(
            bidder_id=bidderB["public_key"],
            bidder_name="Budget Paving Ltd",
            tender_id=tender_id,
            procuring_entity="National Highway Agency",
            signatory_name="Bob Miller",
            signatory_title="Managing Director"
        )

        commitB = self.relayer.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidderB["public_key"],
            bidder_name="Budget Paving Ltd",
            admin_dossier_hash="bb" * 32,
            salt_tech=saltTechB,
            proposal_hash=propB,
            salt_fin=saltFinB,
            price=priceB,
            boq_hash=boqB,
            bond_mode=int(BondMode.BID_SECURING_DECLARATION),
            bond_amount=190000,
            bond_record=bsdB
        )
        self.assertEqual(self.relayer.ledger.tenders[tender_pda]["total_committed"], 2)

        # 4. Advance phase: SubmissionsOpen -> AdministrativeReview -> TechnicalEvaluation
        self.relayer.ledger.advance_tender_phase(tender_pda) # to AdministrativeReview
        self.relayer.ledger.advance_tender_phase(tender_pda) # to TechnicalEvaluation
        self.assertEqual(self.relayer.ledger.tenders[tender_pda]["status"], TenderStatus.TechnicalEvaluation)

        # 5. Unseal Envelope A for both bidders
        bidA = self.relayer.ledger.reveal_technical_bid(tender_pda, bidderA["public_key"], saltTechA, propA)
        bidB = self.relayer.ledger.reveal_technical_bid(tender_pda, bidderB["public_key"], saltTechB, propB)
        self.assertTrue(bidA["is_tech_revealed"])
        self.assertTrue(bidB["is_tech_revealed"])

        # 6. Evaluators commit & reveal blinded rubrics
        # Scores for Bidder A: [8200, 8100, 8300, 8000, 8250] (consistently qualified)
        # Scores for Bidder B: [6400, 6300, 6500, 6200, 9800] (honest fail ~63.5%, rogue evaluator 5 injects 9800)
        scoresA = [
            [2000, 1500, 2200, 1300, 1200], # 8200
            [1950, 1500, 2150, 1300, 1200], # 8100
            [2050, 1500, 2250, 1300, 1200], # 8300
            [1900, 1500, 2100, 1300, 1200], # 8000
            [2000, 1500, 2200, 1350, 1200], # 8250
        ]
        scoresB = [
            [1500, 1200, 1600, 1100, 1000], # 6400
            [1450, 1200, 1550, 1100, 1000], # 6300
            [1550, 1200, 1650, 1100, 1000], # 6500
            [1400, 1200, 1500, 1100, 1000], # 6200
            [2500, 2000, 2500, 1500, 1300], # 9800 (Rogue Outlier)
        ]

        for i, ev in enumerate(self.evaluators):
            # Bidder A
            saltA = secrets.token_hex(32)
            justA = hashlib.sha256(f"Justification A {i}".encode('utf-8')).hexdigest()
            commA = compute_grade_commitment(tender_pda, bidderA["public_key"], ev, saltA, scoresA[i], justA).hex()
            self.relayer.ledger.commit_evaluator_grade(tender_pda, ev, bidderA["public_key"], commA)
            self.relayer.ledger.reveal_evaluator_grade(tender_pda, ev, bidderA["public_key"], scoresA[i], saltA, justA)

            # Bidder B
            saltB = secrets.token_hex(32)
            justB = hashlib.sha256(f"Justification B {i}".encode('utf-8')).hexdigest()
            commB = compute_grade_commitment(tender_pda, bidderB["public_key"], ev, saltB, scoresB[i], justB).hex()
            self.relayer.ledger.commit_evaluator_grade(tender_pda, ev, bidderB["public_key"], commB)
            self.relayer.ledger.reveal_evaluator_grade(tender_pda, ev, bidderB["public_key"], scoresB[i], saltB, justB)

        # 7. Finalize Technical Evaluation (Olympic Trimmed Mean)
        eval_res = self.relayer.finalize_technical_evaluation(
            tender_pda=tender_pda,
            authority_pubkey=self.authority["public_key"],
            bidder_pubkeys=[bidderA["public_key"], bidderB["public_key"]]
        )
        self.assertEqual(eval_res["total_qualified"], 1)

        # Check Bidder A qualified, Bidder B disqualified
        bidA_acc = self.relayer.ledger.commitments[self.relayer.ledger.derive_bid_pda(tender_pda, bidderA["public_key"])]
        bidB_acc = self.relayer.ledger.commitments[self.relayer.ledger.derive_bid_pda(tender_pda, bidderB["public_key"])]
        self.assertTrue(bidA_acc["is_tech_qualified"])
        self.assertFalse(bidB_acc["is_tech_qualified"])
        self.assertLess(bidB_acc["technicalScoreBps"] if "technicalScoreBps" in bidB_acc else bidB_acc["technical_score_bps"], 7500)

        # Verify Rogue Evaluator was flagged
        rogue_pda = self.relayer.ledger.derive_grade_pda(tender_pda, self.evaluators[4], bidderB["public_key"])
        self.assertTrue(self.relayer.ledger.evaluator_grades[rogue_pda]["is_outlier_flagged"])

        # Check OCDS Evaluation Release generated
        self.assertIn("REL-TENDER-AUTO-2026-001-02-TECH-EVALUATION", self.relayer.ocds_releases)

        # 8. Advance to Financial Evaluation
        self.relayer.ledger.advance_tender_phase(tender_pda)
        self.assertEqual(self.relayer.ledger.tenders[tender_pda]["status"], TenderStatus.FinancialEvaluation)

        # 9. COMMERCIAL SECRECY GUARANTEE TEST:
        # Disqualified Bidder B MUST NOT be able to open Envelope B!
        with self.assertRaises(ValueError) as ctx:
            self.relayer.ledger.reveal_financial_envelope(
                tender_pda=tender_pda,
                bidder_pubkey=bidderB["public_key"],
                salt_fin=saltFinB,
                price=priceB,
                boq_hash=boqB
            )
        self.assertIn("BidderTechnicallyDisqualified", str(ctx.exception))
        self.assertFalse(bidB_acc["is_fin_revealed"])

        # 10. Qualified Bidder A unseals Envelope B
        revealedA = self.relayer.ledger.reveal_financial_envelope(
            tender_pda=tender_pda,
            bidder_pubkey=bidderA["public_key"],
            salt_fin=saltFinA,
            price=priceA,
            boq_hash=boqA
        )
        self.assertTrue(revealedA["is_fin_revealed"])
        self.assertEqual(revealedA["revealed_price"], 3800000)

        # 11. Record Programmatic QCBS Award
        award_res = self.relayer.record_award(
            tender_pda=tender_pda,
            authority_pubkey=self.authority["public_key"],
            winning_bidder_pubkey=bidderA["public_key"],
            winner_name="Apex Highway Constructors"
        )
        self.assertEqual(award_res["tender"]["winning_bidder"], bidderA["public_key"])
        self.assertEqual(award_res["tender"]["status"], TenderStatus.Awarded)
        self.assertGreater(award_res["winning_bid"]["composite_score"], 8000)

        # Check OCDS Final Award Release generated
        self.assertIn("REL-TENDER-AUTO-2026-001-03-FINAL-AWARD", self.relayer.ocds_releases)
        self.assertEqual(len(self.relayer.ocds_releases), 3)


class TestPhase3HttpEndpoints(unittest.TestCase):
    """Integration test testing HTTP REST API endpoints against server.py."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        from server import BidTraceHandler, state as server_state

        cls.server_state = server_state
        cls.server_state.reset()
        cls.port = 8899

        socketserver.TCPServer.allow_reuse_address = True
        cls.httpd = socketserver.TCPServer(("127.0.0.1", cls.port), BidTraceHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _post(self, path: str, payload: dict) -> dict:
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def _get(self, path: str) -> dict:
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def test_http_api_flow(self):
        # 1. Reset
        r_reset = self._post("/api/reset", {})
        self.assertEqual(r_reset["status"], "ok")

        # 2. Merkle Whitelist
        bidders = ["bidderA_key", "bidderB_key", "bidderC_key"]
        r_tree = self._post("/api/merkle/tree", {"bidders": bidders})
        self.assertEqual(r_tree["status"], "ok")
        root = r_tree["root_hex"]
        self.assertEqual(len(root), 64)

        r_proof = self._post("/api/merkle/proof", {"bidders": bidders, "bidder": "bidderB_key"})
        self.assertTrue(r_proof["is_valid"])

        # 3. Hybrid Bonds
        r_surety = self._post("/api/surety/issue_policy", {
            "bidder_id": "BIDDER_1",
            "bidder_name": "Mega Builders Inc",
            "penal_sum_usd": 150000.0
        })
        self.assertEqual(r_surety["status"], "ok")
        self.assertTrue(r_surety["policyId"].startswith("SURETY-POL-"))

        r_bsd = self._post("/api/bond/bsd_sign", {
            "bidder_id": "BIDDER_2",
            "bidder_name": "Eco Roads Ltd"
        })
        self.assertEqual(r_bsd["status"], "ok")
        self.assertTrue(r_bsd["declarationId"].startswith("BSD-DECL-"))

        # 4. Create Tender (OCDS notice release)
        r_tender = self._post("/api/tender/create", {
            "tender_id": "TENDER-HTTP-001",
            "title": "Metropolitan Bridge Project",
            "estimated_amount": 5000000.0,
            "min_tech_score": 75.0
        })
        self.assertEqual(r_tender["status"], "ok")
        pda = r_tender["tender"]["pda"]
        self.assertIsNotNone(pda)

        # 5. Commit Dual Bid
        r_bid = self._post("/api/bid/commit_dual", {
            "name": "Mega Builders Inc",
            "price": 4800000,
            "specs": "High quality cable suspension",
            "bond_mode": int(BondMode.SURETY_SERVICE),
            "bond_amount": 150000
        })
        self.assertEqual(r_bid["status"], "ok")
        self.assertIn("receiptId", r_bid["receipt"])

        # 6. Status GET
        r_status = self._get("/api/status")
        self.assertEqual(r_status["status"], "ok")
        self.assertEqual(r_status["bids_count"], 1)

        # 7. OCDS Releases GET
        r_releases = self._get("/api/ocds/releases")
        self.assertEqual(r_releases["status"], "ok")
        self.assertGreaterEqual(r_releases["count"], 1)


if __name__ == "__main__":
    unittest.main()
