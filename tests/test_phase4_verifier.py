"""
BidTrace 3.0 Phase 4 Automated Test Suite: Air-Gapped OCDS Verifier CLI
=======================================================================
Validates:
1. Tribunal Dossier packaging (releases, preimages, bonds, ledger proofs, manifest).
2. Standalone air-gapped verification across all 5 procurement lifecycle phases.
3. Strict enforcement of the Commercial Secrecy Invariant (disqualified bidder Envelope B forever sealed).
4. Detection of adversarial attacks:
   - Tampered OCDS Notice Canonical Hash
   - Model A Merkle Whitelist Fraud
   - Tampered Hybrid Bond Attestation
   - Late Bid Temporal Slot Violation
   - Rogue Evaluator Bribery & Outlier Flagging
   - Commercial Secrecy Envelope B Leak Breach
   - Tampered Financial Quotation
   - Arbitrary / Corrupt Contract Awardee Selection
5. REST API endpoints:
   - POST /api/tribunal/export_dossier
   - GET /api/tribunal/download_dossier
   - POST /api/tribunal/verify
6. CLI tool invocations:
   - python -m bidtrace.verifier --dossier <path>
   - python verifier/verify_ocds.py --dossier <path>
"""

import unittest
import os
import sys
import json
from typing import Dict, Any, List, Optional
import zipfile
import secrets
import hashlib
import tempfile
import shutil
import subprocess
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
from bidtrace_py.merkle import MerkleTree
from bidtrace_py.bonds import (
    BondMode,
    issue_surety_policy,
    issue_bank_guarantee_attestation,
    sign_bid_securing_declaration,
    create_solana_escrow_record
)
from bidtrace_py.ledger import BidTraceLedger, TenderStatus
from bidtrace_py.relayer import BidTraceRelayerGateway
from bidtrace_py.verifier import (
    AirGappedTribunalVerifier,
    export_tribunal_dossier,
    verify_proof_bundle
)
from server import BidTraceHandler, state


def setup_full_lifecycle_tender(model_a: bool = True) -> Dict[str, Any]:
    """Helper to set up a complete 5-phase procurement lifecycle."""
    relayer = BidTraceRelayerGateway()
    authority = generate_keypair()
    
    # Generate 3 bidders: Bidder 1 (Winner), Bidder 2 (Qualified), Bidder 3 (Disqualified)
    bidders = [
        {"kp": generate_keypair(), "name": "ACME Infrastructure Corp", "price": 3800000},
        {"kp": generate_keypair(), "name": "Apex Civil Engineering", "price": 4100000},
        {"kp": generate_keypair(), "name": "Rogue Non-Compliant Builder", "price": 2900000}
    ]
    bidder_pks = [b["kp"]["public_key"] for b in bidders]

    tree = None
    auth_root = None
    if model_a:
        tree = MerkleTree(bidder_pks)
        auth_root = tree.root_hex

    # Evaluators committee (5 evaluators)
    evaluators = [generate_keypair()["public_key"] for _ in range(5)]

    # 1. Create tender
    tender_res = relayer.create_tender(
        authority_pubkey=authority["public_key"],
        tender_id="TENDER-QCBS-GLOBAL-001",
        title="Global Trans-Continental Corridor Project",
        description="Two-Envelope QCBS Procurement standard compliant with OCDS 1.1",
        buyer_name="International Infrastructure Commission",
        currency="USD",
        estimated_amount=4000000.0,
        submission_deadline_iso="2026-11-15T23:59:59Z",
        evaluation_type="QCBS",
        tech_weight=0.70,
        fin_weight=0.30,
        min_tech_score=75.0,
        bond_amount=190000.0,
        bond_mode_str="SuretyService",
        authorized_bidders_root=auth_root,
        evaluators=evaluators
    )
    tender_pda = relayer.active_tender_pda

    # 2. Issue bonds & commit dual bids
    # Bidder 1: Surety Policy
    surety_pol = issue_surety_policy(
        bidder_id=bidders[0]["kp"]["public_key"],
        bidder_name=bidders[0]["name"],
        tender_id="TENDER-QCBS-GLOBAL-001",
        penal_sum_usd=190000.0,
        officer_name="Chief Executive Officer"
    )
    proof_0 = tree.get_proof_hex(bidders[0]["kp"]["public_key"]) if tree else None
    salt_tech_0 = secrets.token_hex(32)
    prop_hash_0 = hashlib.sha256(b"BLUEPRINT_ACME_V1").hexdigest()
    salt_fin_0 = secrets.token_hex(32)
    boq_hash_0 = hashlib.sha256(b"BOQ_ACME_3800000").hexdigest()

    relayer.commit_dual_bid(
        tender_pda=tender_pda,
        bidder_pubkey=bidders[0]["kp"]["public_key"],
        bidder_name=bidders[0]["name"],
        admin_dossier_hash=hashlib.sha256(b"ADMIN_DOSSIER_ACME").hexdigest(),
        salt_tech=salt_tech_0,
        proposal_hash=prop_hash_0,
        salt_fin=salt_fin_0,
        price=bidders[0]["price"],
        boq_hash=boq_hash_0,
        bond_mode=int(BondMode.SURETY_SERVICE),
        bond_amount=190000,
        bond_record=surety_pol,
        whitelist_proof=proof_0
    )

    # Bidder 2: Bank Guarantee MT760
    bg = issue_bank_guarantee_attestation(
        bidder_id=bidders[1]["kp"]["public_key"],
        bidder_name=bidders[1]["name"],
        tender_id="TENDER-QCBS-GLOBAL-001",
        bank_name="Barclays Bank PLC",
        swift_bic="BARCGB22",
        guarantee_ref="BG-MT760-2026-992",
        amount_usd=190000.0
    )
    proof_1 = tree.get_proof_hex(bidders[1]["kp"]["public_key"]) if tree else None
    salt_tech_1 = secrets.token_hex(32)
    prop_hash_1 = hashlib.sha256(b"BLUEPRINT_APEX_V1").hexdigest()
    salt_fin_1 = secrets.token_hex(32)
    boq_hash_1 = hashlib.sha256(b"BOQ_APEX_4100000").hexdigest()

    relayer.commit_dual_bid(
        tender_pda=tender_pda,
        bidder_pubkey=bidders[1]["kp"]["public_key"],
        bidder_name=bidders[1]["name"],
        admin_dossier_hash=hashlib.sha256(b"ADMIN_DOSSIER_APEX").hexdigest(),
        salt_tech=salt_tech_1,
        proposal_hash=prop_hash_1,
        salt_fin=salt_fin_1,
        price=bidders[1]["price"],
        boq_hash=boq_hash_1,
        bond_mode=int(BondMode.BANK_GUARANTEE),
        bond_amount=190000,
        bond_record=bg,
        whitelist_proof=proof_1
    )

    # Bidder 3: World Bank BSD (will score < 75% and be disqualified)
    bsd = sign_bid_securing_declaration(
        bidder_id=bidders[2]["kp"]["public_key"],
        bidder_name=bidders[2]["name"],
        tender_id="TENDER-QCBS-GLOBAL-001"
    )
    proof_2 = tree.get_proof_hex(bidders[2]["kp"]["public_key"]) if tree else None
    salt_tech_2 = secrets.token_hex(32)
    prop_hash_2 = hashlib.sha256(b"BLUEPRINT_ROGUE_V1").hexdigest()
    salt_fin_2 = secrets.token_hex(32)
    boq_hash_2 = hashlib.sha256(b"BOQ_ROGUE_2900000").hexdigest()

    relayer.commit_dual_bid(
        tender_pda=tender_pda,
        bidder_pubkey=bidders[2]["kp"]["public_key"],
        bidder_name=bidders[2]["name"],
        admin_dossier_hash=hashlib.sha256(b"ADMIN_DOSSIER_ROGUE").hexdigest(),
        salt_tech=salt_tech_2,
        proposal_hash=prop_hash_2,
        salt_fin=salt_fin_2,
        price=bidders[2]["price"],
        boq_hash=boq_hash_2,
        bond_mode=int(BondMode.BID_SECURING_DECLARATION),
        bond_amount=190000,
        bond_record=bsd,
        whitelist_proof=proof_2
    )

    # 3. Advance to Technical Evaluation & reveal Envelope A
    relayer.ledger.advance_slot(60)
    relayer.ledger.advance_tender_phase(tender_pda) # to AdministrativeReview
    relayer.ledger.advance_tender_phase(tender_pda) # to TechnicalEvaluation

    relayer.ledger.reveal_technical_bid(tender_pda, bidders[0]["kp"]["public_key"], salt_tech_0, prop_hash_0)
    relayer.ledger.reveal_technical_bid(tender_pda, bidders[1]["kp"]["public_key"], salt_tech_1, prop_hash_1)
    relayer.ledger.reveal_technical_bid(tender_pda, bidders[2]["kp"]["public_key"], salt_tech_2, prop_hash_2)

    # 4. Committee Blinded Rubric Scoring
    # Scores for Bidder 1 (ACME): 88%, 90%, 89%, 91%, and a rogue score 99% (outlier) -> final ~90%
    b1_scores = [
        [1760, 1760, 1760, 1760, 1760],  # 8800
        [1800, 1800, 1800, 1800, 1800],  # 9000
        [1780, 1780, 1780, 1780, 1780],  # 8900
        [1820, 1820, 1820, 1820, 1820],  # 9100
        [1980, 1980, 1980, 1980, 1980]   # 9900 (rogue max)
    ]
    # Scores for Bidder 2 (Apex): 82%, 84%, 83%, 85%, 83% -> final ~83%
    b2_scores = [
        [1640, 1640, 1640, 1640, 1640],  # 8200
        [1680, 1680, 1680, 1680, 1680],  # 8400
        [1660, 1660, 1660, 1660, 1660],  # 8300
        [1700, 1700, 1700, 1700, 1700],  # 8500
        [1660, 1660, 1660, 1660, 1660]   # 8300
    ]
    # Scores for Bidder 3 (Rogue): honest fail ~61%, rogue evaluator 5 injects 9800 (outlier)
    b3_scores = [
        [1200, 1200, 1200, 1200, 1200],  # 6000
        [1240, 1240, 1240, 1240, 1240],  # 6200
        [1160, 1160, 1160, 1160, 1160],  # 5800
        [1280, 1280, 1280, 1280, 1280],  # 6400
        [1960, 1960, 1960, 1960, 1960]   # 9800 (Rogue Bribery Outlier: > 20% variance)
    ]

    for ev_idx, ev in enumerate(evaluators):
        for b_idx, (b_pk, sc_matrix) in enumerate([(bidders[0]["kp"]["public_key"], b1_scores),
                                                   (bidders[1]["kp"]["public_key"], b2_scores),
                                                   (bidders[2]["kp"]["public_key"], b3_scores)]):
            sub_sc = sc_matrix[ev_idx]
            salt_ev = secrets.token_hex(32)
            just_h = hashlib.sha256(f"REPORT_{ev_idx}_{b_idx}".encode()).hexdigest()
            comm_h = compute_grade_commitment(tender_pda, b_pk, ev, salt_ev, sub_sc, just_h).hex()
            relayer.ledger.commit_evaluator_grade(tender_pda, ev, b_pk, comm_h)
            relayer.ledger.reveal_evaluator_grade(tender_pda, ev, b_pk, sub_sc, salt_ev, just_h)

    # 5. Finalize Technical Evaluation (Olympic Trimmed Mean & OCDS 1.1 Evaluation Release)
    eval_res = relayer.finalize_technical_evaluation(
        tender_pda=tender_pda,
        authority_pubkey=authority["public_key"],
        bidder_pubkeys=bidder_pks
    )

    # 6. Advance to Financial Evaluation
    relayer.ledger.advance_slot(30)
    relayer.ledger.advance_tender_phase(tender_pda)

    # Reveal Envelope B for Qualified Bidders (ACME & Apex)
    relayer.ledger.reveal_financial_envelope(tender_pda, bidders[0]["kp"]["public_key"], salt_fin_0, bidders[0]["price"], boq_hash_0)
    relayer.ledger.reveal_financial_envelope(tender_pda, bidders[1]["kp"]["public_key"], salt_fin_1, bidders[1]["price"], boq_hash_1)

    # 7. Record Award (QCBS Formula: ACME Wins)
    award_res = relayer.record_award(
        tender_pda=tender_pda,
        authority_pubkey=authority["public_key"],
        winning_bidder_pubkey=bidders[0]["kp"]["public_key"],
        winner_name=bidders[0]["name"]
    )

    return {
        "relayer": relayer,
        "authority": authority,
        "tender_pda": tender_pda,
        "bidders": bidders,
        "evaluators": evaluators,
        "tree": tree
    }


class TestPhase4DossierPackaging(unittest.TestCase):
    """Tests packaging of the complete Tribunal Audit Dossier into a ZIP file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.zip_path = os.path.join(self.tmpdir, "tribunal_dossier.zip")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export_tribunal_dossier_contents(self):
        env = setup_full_lifecycle_tender(model_a=True)
        res = export_tribunal_dossier(env["relayer"], output_path=self.zip_path)

        self.assertEqual(res["status"], "ok")
        self.assertTrue(os.path.exists(self.zip_path))
        self.assertGreater(res["size_bytes"], 1000)

        # Inspect ZIP structure
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            namelist = [n.replace("\\", "/") for n in zf.namelist()]
            self.assertIn("manifest.json", namelist)
            self.assertIn("releases/ocds_01_tender.json", namelist)
            self.assertIn("releases/ocds_02_evaluation.json", namelist)
            self.assertIn("releases/ocds_03_award.json", namelist)
            self.assertIn("bids/bidder_receipts.json", namelist)
            self.assertIn("committee/evaluations.json", namelist)
            self.assertIn("bonds/bond_attestations.json", namelist)
            self.assertIn("ledger/solana_state_proofs.json", namelist)

            # Check Manifest integrity mapping
            manifest = json.loads(zf.read("manifest.json").decode('utf-8'))
            self.assertEqual(manifest["protocol"], "BidTrace Global Standard")
            self.assertEqual(manifest["version"], "3.0.0")
            self.assertEqual(manifest["tenderId"], "TENDER-QCBS-GLOBAL-001")
            self.assertEqual(len(manifest["files"]), len(namelist) - 1)

            # Check Commercial Secrecy Invariant preservation in exported receipts
            receipts = json.loads(zf.read("bids/bidder_receipts.json").decode('utf-8'))
            disqualified_receipt = next((r for r in receipts if r["bidderName"] == "Rogue Non-Compliant Builder"), None)
            self.assertIsNotNone(disqualified_receipt)
            p_img = disqualified_receipt["unsealingPreimages"]
            self.assertEqual(p_img["saltFin"], "SEALED_COMMERCIAL_SECRECY_PRESERVED")
            self.assertEqual(p_img["price"], 0)


class TestPhase4AirGappedVerifier(unittest.TestCase):
    """Tests standalone air-gapped auditor verification across all 5 procurement phases."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.zip_path = os.path.join(self.tmpdir, "tribunal_dossier.zip")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_clean_procurement_lifecycle_verifies_100_percent(self):
        env = setup_full_lifecycle_tender(model_a=True)
        export_tribunal_dossier(env["relayer"], output_path=self.zip_path)

        verifier = AirGappedTribunalVerifier(self.zip_path)
        report = verifier.verify_all()

        self.assertTrue(report["valid"])
        self.assertEqual(report["overall_status"], "[PASS] 100% CRYPTOGRAPHICALLY VERIFIED ACROSS 5 LIFECYCLE PHASES")

        # Verify each of the 5 phases
        phases = report["phases"]
        self.assertTrue(phases["phase1_tender_notice"]["valid"])
        self.assertTrue(phases["phase2_due_diligence_and_bonds"]["valid"])
        self.assertTrue(phases["phase3_slot_adherence_and_tech_commitments"]["valid"])
        self.assertTrue(phases["phase4_committee_and_trimmed_mean"]["valid"])
        self.assertTrue(phases["phase5_financial_and_qcbs_award"]["valid"])

        # Check invariant checks
        invariants = report["critical_invariants_verified"]
        self.assertTrue(invariants["ocds_canonical_hash_anchor"])
        self.assertTrue(invariants["merkle_whitelist_inclusion"])
        self.assertTrue(invariants["temporal_slot_boundaries"])
        self.assertTrue(invariants["evaluator_blinded_commitments"])
        self.assertTrue(invariants["olympic_trimmed_mean_outlier_rejection"])
        self.assertTrue(invariants["commercial_secrecy_invariant"])
        self.assertTrue(invariants["programmatic_qcbs_award_math"])

        # Check CLI formatted text output
        cli_output = verifier.format_cli_report(report)
        self.assertIn("100% CRYPTOGRAPHICALLY VERIFIED ACROSS 5 LIFECYCLE PHASES", cli_output)
        self.assertIn("PHASE 1: OCDS 1.1 Tender Notice RFC 8785 Canonical Anchor", cli_output)
        self.assertIn("PHASE 4: Multi-Evaluator Rubrics & Olympic Trimmed Mean Filter", cli_output)
        self.assertIn("PHASE 5: Envelope B Integrity, Commercial Secrecy & QCBS Award", cli_output)
        self.assertIn("AWARDED WINNER:", cli_output)


class TestPhase4AdversarialAttacks(unittest.TestCase):
    """Tests adversary tampering detection across all 5 verification phases."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.env = setup_full_lifecycle_tender(model_a=True)
        self.clean_zip = os.path.join(self.tmpdir, "clean_dossier.zip")
        export_tribunal_dossier(self.env["relayer"], output_path=self.clean_zip)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _tamper_zip_file(self, file_to_tamper: str, tamper_fn) -> str:
        """Helper to create a tampered dossier zip."""
        tampered_zip = os.path.join(self.tmpdir, f"tampered_{secrets.token_hex(4)}.zip")
        with zipfile.ZipFile(self.clean_zip, 'r') as zin, zipfile.ZipFile(tampered_zip, 'w') as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                norm_fn = item.filename.replace("\\", "/")
                if norm_fn == file_to_tamper:
                    parsed = json.loads(data.decode('utf-8'))
                    tampered_parsed = tamper_fn(parsed)
                    data = json.dumps(tampered_parsed, indent=2).encode('utf-8')
                zout.writestr(item, data)
        return tampered_zip

    def test_attack_1_tampered_ocds_tender_notice_canonical_hash(self):
        # Corrupt title in OCDS notice release
        def tamper(notice_rel):
            notice_rel["tender"]["title"] = "CORRUPT MODIFIED TITLE BY ADVERSARY"
            return notice_rel

        tampered_path = self._tamper_zip_file("releases/ocds_01_tender.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase1_tender_notice"]["valid"])
        self.assertTrue(any("Canonical RFC 8785 hash mismatch" in err for err in report["findings"]))

    def test_attack_2_merkle_whitelist_proof_fraud(self):
        # Alter a bidder's whitelist proof
        def tamper(receipts):
            receipts[0]["whitelistProof"] = ["11" * 32, "22" * 32]
            return receipts

        tampered_path = self._tamper_zip_file("bids/bidder_receipts.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase2_due_diligence_and_bonds"]["valid"])
        self.assertTrue(any("Merkle whitelist proof verification failed" in err for err in report["findings"]))

    def test_attack_3_tampered_hybrid_surety_bond_gia(self):
        # Corrupt General Indemnity Agreement covenants in bond attestations
        def tamper(bonds):
            for b in bonds:
                if "giaDocument" in b:
                    b["giaDocument"]["covenants"] = ["Fraudulent modified indemnity covenants"]
            return bonds

        tampered_path = self._tamper_zip_file("bonds/bond_attestations.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase2_due_diligence_and_bonds"]["valid"])
        self.assertTrue(any("Surety GIA canonical hash mismatch" in err for err in report["findings"]))

    def test_attack_4_late_bid_submission_temporal_violation(self):
        # Alter a commitment's slot to be after the submission deadline
        def tamper(ledger):
            first_comm = next(iter(ledger["commitments"].values()))
            first_comm["committed_at_slot"] = ledger["tender"]["submission_deadline_slot"] + 50
            return ledger

        tampered_path = self._tamper_zip_file("ledger/solana_state_proofs.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase3_slot_adherence_and_tech_commitments"]["valid"])
        self.assertTrue(any("CRITICAL TEMPORAL BREACH" in err for err in report["findings"]))

    def test_attack_5_rogue_evaluator_outlier_suppression(self):
        # Unflag an outlier grade in the committee snapshot
        def tamper(ledger):
            for g in ledger["evaluator_grades"].values():
                if g.get("is_outlier_flagged"):
                    g["is_outlier_flagged"] = False  # Suppress outlier detection
            return ledger

        tampered_path = self._tamper_zip_file("ledger/solana_state_proofs.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase4_committee_and_trimmed_mean"]["valid"])
        self.assertTrue(any("Outlier flag mismatch" in err for err in report["findings"]))

    def test_attack_6_commercial_secrecy_breach_disqualified_pricing_leak(self):
        # ADVERSARY LEAKS DISQUALIFIED BIDDER'S ENVELOPE B PREIMAGES
        def tamper(receipts):
            disqualified = next(r for r in receipts if r["bidderName"] == "Rogue Non-Compliant Builder")
            # Leak the proprietary financial pricing quotation
            disqualified["unsealingPreimages"]["saltFin"] = secrets.token_hex(32)
            disqualified["unsealingPreimages"]["price"] = 2900000
            return receipts

        tampered_path = self._tamper_zip_file("bids/bidder_receipts.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase5_financial_and_qcbs_award"]["valid"])
        self.assertFalse(report["critical_invariants_verified"]["commercial_secrecy_invariant"])
        self.assertTrue(any("CRITICAL COMMERCIAL SECRECY VIOLATION" in err for err in report["findings"]))

    def test_attack_7_tampered_financial_quotation_hash_mismatch(self):
        # Alter pricing for qualified winner
        def tamper(receipts):
            winner = receipts[0]
            winner["unsealingPreimages"]["price"] = winner["unsealingPreimages"]["price"] - 500000
            return receipts

        tampered_path = self._tamper_zip_file("bids/bidder_receipts.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase5_financial_and_qcbs_award"]["valid"])
        self.assertTrue(any("Envelope B financial commitment mismatch" in err for err in report["findings"]))

    def test_attack_8_arbitrary_corrupt_contract_awardee_selection(self):
        # Authority awards contract to Rank 2 instead of Rank 1 winner
        def tamper(ledger):
            # Swap winning bidder to second bidder
            bidders = list(ledger["commitments"].values())
            ledger["tender"]["winning_bidder"] = bidders[1]["bidder"]
            return ledger

        tampered_path = self._tamper_zip_file("ledger/solana_state_proofs.json", tamper)
        verifier = AirGappedTribunalVerifier(tampered_path)
        report = verifier.verify_all()

        self.assertFalse(report["valid"])
        self.assertFalse(report["phases"]["phase5_financial_and_qcbs_award"]["valid"])
        self.assertTrue(any("Awarded winner mismatch" in err for err in report["findings"]))


class TestPhase4RestApiAndCli(unittest.TestCase):
    """Tests Phase 4 REST API endpoints and CLI entrypoint executions."""

    @classmethod
    def setUpClass(cls):
        # Start server in background thread for REST tests
        import socketserver
        cls.port = 8994
        socketserver.TCPServer.allow_reuse_address = True
        cls.httpd = socketserver.TCPServer(("127.0.0.1", cls.port), BidTraceHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _post(self, path: str, payload: dict) -> dict:
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def _get(self, path: str) -> bytes:
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read()

    def test_rest_api_export_and_verify_pipeline(self):
        self._post("/api/reset", {})
        
        # 1. Create tender
        t_res = self._post("/api/tender/create", {
            "tender_id": "TENDER-API-PHASE4-01",
            "title": "Corridor Modernization API Test",
            "bond_amount": 190000.0
        })
        self.assertEqual(t_res["status"], "ok")

        # 2. Commit 2 bids
        b1_kp = generate_keypair()
        b2_kp = generate_keypair()
        self._post("/api/bid/commit_dual", {
            "bidder_pubkey": b1_kp["public_key"],
            "bidder_name": "Contractor Alpha",
            "price": 3800000,
            "bond_amount": 190000
        })
        self._post("/api/bid/commit_dual", {
            "bidder_pubkey": b2_kp["public_key"],
            "bidder_name": "Contractor Beta",
            "price": 4000000,
            "bond_amount": 190000
        })

        # 3. Advance to Tech Eval (SubmissionsOpen -> AdministrativeReview -> TechnicalEvaluation)
        self._post("/api/tender/advance_phase", {}) # to AdministrativeReview
        self._post("/api/tender/advance_phase", {}) # to TechnicalEvaluation

        # Reveal Envelope A
        r1 = state.bidders_receipts[0]
        r2 = state.bidders_receipts[1]
        self._post("/api/bid/reveal_technical", {
            "bidder_pubkey": b1_kp["public_key"],
            "salt_tech": r1["unsealingPreimages"]["saltTech"],
            "proposal_hash": r1["unsealingPreimages"]["proposalHash"]
        })
        self._post("/api/bid/reveal_technical", {
            "bidder_pubkey": b2_kp["public_key"],
            "salt_tech": r2["unsealingPreimages"]["saltTech"],
            "proposal_hash": r2["unsealingPreimages"]["proposalHash"]
        })

        # Score committee
        comm_pda = state.ledger.derive_committee_pda(state.tender_pda)
        evaluators = state.ledger.committees[comm_pda]["evaluators"]
        for ev in evaluators:
            for b_pk in [b1_kp["public_key"], b2_kp["public_key"]]:
                sub_sc = [1800, 1800, 1800, 1800, 1800]
                salt = secrets.token_hex(32)
                just = "00" * 32
                comm_h = compute_grade_commitment(state.tender_pda, b_pk, ev, salt, sub_sc, just).hex()
                self._post("/api/evaluator/commit_grade", {
                    "evaluator_pubkey": ev,
                    "bidder_pubkey": b_pk,
                    "commitment_hash": comm_h
                })
                self._post("/api/evaluator/reveal_grade", {
                    "evaluator_pubkey": ev,
                    "bidder_pubkey": b_pk,
                    "sub_scores": sub_sc,
                    "salt": salt,
                    "justification_hash": just
                })

        # Finalize tech scores
        self._post("/api/tender/finalize_technical", {})

        # Advance to Financial Evaluation
        self._post("/api/tender/advance_phase", {})

        # Reveal Envelope B
        self._post("/api/bid/reveal_financial", {
            "bidder_pubkey": b1_kp["public_key"],
            "salt_fin": r1["unsealingPreimages"]["saltFin"],
            "price": 3800000,
            "boq_hash": r1["unsealingPreimages"]["boqHash"]
        })
        self._post("/api/bid/reveal_financial", {
            "bidder_pubkey": b2_kp["public_key"],
            "salt_fin": r2["unsealingPreimages"]["saltFin"],
            "price": 4000000,
            "boq_hash": r2["unsealingPreimages"]["boqHash"]
        })

        # Award
        self._post("/api/tender/award", {
            "winning_bidder_pubkey": b1_kp["public_key"],
            "winner_name": "Contractor Alpha"
        })

        # 4. Export Dossier via REST API
        export_res = self._post("/api/tribunal/export_dossier", {})
        self.assertEqual(export_res["status"], "ok")
        self.assertEqual(export_res["filename"], "tribunal_dossier.zip")
        self.assertIn("download_url", export_res)

        # 5. Download Dossier binary via GET
        raw_zip = self._get("/api/tribunal/download_dossier")
        self.assertGreater(len(raw_zip), 1000)

        # 6. Verify Dossier via REST API
        verify_res = self._post("/api/tribunal/verify", {})
        self.assertEqual(verify_res["status"], "ok")
        report = verify_res["audit_report"]
        self.assertTrue(report["valid"])
        self.assertIn("100% CRYPTOGRAPHICALLY VERIFIED", report["overall_status"])

    def test_cli_verifier_execution(self):
        # Run CLI entrypoint scripts via subprocess on a generated dossier
        env = setup_full_lifecycle_tender(model_a=True)
        zip_path = os.path.join(tempfile.gettempdir(), f"cli_test_dossier_{secrets.token_hex(4)}.zip")
        export_tribunal_dossier(env["relayer"], output_path=zip_path)

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 1. Test python -m bidtrace.verifier --dossier <path>
        cmd1 = [sys.executable, "-m", "bidtrace.verifier", "--dossier", zip_path]
        proc1 = subprocess.run(cmd1, cwd=repo_root, capture_output=True, text=True)
        self.assertEqual(proc1.returncode, 0, f"CLI bidtrace.verifier failed: {proc1.stderr}")
        self.assertIn("[PASS] 100% CRYPTOGRAPHICALLY VERIFIED ACROSS 5 LIFECYCLE PHASES", proc1.stdout)

        # 2. Test python verifier/verify_ocds.py --dossier <path>
        cmd2 = [sys.executable, "verifier/verify_ocds.py", "--dossier", zip_path]
        proc2 = subprocess.run(cmd2, cwd=repo_root, capture_output=True, text=True)
        self.assertEqual(proc2.returncode, 0, f"CLI verifier/verify_ocds.py failed: {proc2.stderr}")
        self.assertIn("[PASS] 100% CRYPTOGRAPHICALLY VERIFIED ACROSS 5 LIFECYCLE PHASES", proc2.stdout)

        # Clean up
        if os.path.exists(zip_path):
            os.remove(zip_path)


if __name__ == "__main__":
    unittest.main()
