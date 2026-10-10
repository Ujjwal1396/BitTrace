import unittest
import secrets
from bidtrace_py.crypto import generate_keypair, compute_tech_commitment, compute_fin_commitment, compute_grade_commitment
from bidtrace_py.ledger import BidTraceLedger, TenderStatus, TenderMode, EvaluationType, BondMode
from bidtrace_py.relayer import BidTraceRelayerGateway

class TestSEC01DisqualifiedBondRefund(unittest.TestCase):
    """
    Verifies that SEC-01 (The Bond-Secrecy Trap / Permanent Capital Lockup) is completely resolved:
    1. Technically disqualified bidders are barred from revealing Envelope B (Commercial Secrecy Invariant).
    2. Technically disqualified bidders CAN safely refund their escrowed SOL bond without unsealing Envelope B.
    3. Technically qualified bidders CANNOT claim disqualified refund (they must reveal Envelope B to settle).
    4. Double-refund attempts are rejected with BondAlreadySettled.
    5. Attempted refund before FinancialEvaluation status is rejected.
    """

    def setUp(self):
        self.ledger = BidTraceLedger()
        self.authority = generate_keypair()
        self.bidder_a = generate_keypair() # Qualified
        self.bidder_b = generate_keypair() # Disqualified

        # 1. Initialize tender
        self.tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-SEC01-TEST",
            tender_mode=TenderMode.PostQualifiedOpen,
            evaluation_type=EvaluationType.QCBS,
            authorized_bidders_root="00" * 32,
            min_tech_score_bps=7500,
            tech_weight_bps=7000,
            fin_weight_bps=3000,
            deadline_slots=200
        )
        self.tender_pda = self.tender["pda"]

        # Committee of 5 evaluators
        self.evaluators = [generate_keypair()["public_key"] for _ in range(5)]
        self.committee = self.ledger.initialize_committee(
            tender_pda=self.tender_pda,
            authority_pubkey=self.authority["public_key"],
            evaluators=self.evaluators,
            max_variance_bps=2000
        )

        # 2. Both commit dual bids with SolanaEscrow bond of 5000 lamports
        self.salt_tech_a = secrets.token_hex(32)
        self.salt_fin_a = secrets.token_hex(32)
        self.comm_tech_a = compute_tech_commitment(self.tender_pda, self.bidder_a["public_key"], self.salt_tech_a, "SPEC_A").hex()
        self.comm_fin_a = compute_fin_commitment(self.tender_pda, self.bidder_a["public_key"], self.salt_fin_a, 4000000, "BOQ_A").hex()

        self.salt_tech_b = secrets.token_hex(32)
        self.salt_fin_b = secrets.token_hex(32)
        self.comm_tech_b = compute_tech_commitment(self.tender_pda, self.bidder_b["public_key"], self.salt_tech_b, "SPEC_B").hex()
        self.comm_fin_b = compute_fin_commitment(self.tender_pda, self.bidder_b["public_key"], self.salt_fin_b, 3500000, "BOQ_B").hex()

        self.ledger.commit_dual_bid(
            tender_pda=self.tender_pda,
            bidder_pubkey=self.bidder_a["public_key"],
            admin_dossier_hash="00" * 32,
            tech_commitment_hash=self.comm_tech_a,
            fin_commitment_hash=self.comm_fin_a,
            bond_mode=BondMode.SolanaEscrow,
            bond_amount=5000
        )

        self.ledger.commit_dual_bid(
            tender_pda=self.tender_pda,
            bidder_pubkey=self.bidder_b["public_key"],
            admin_dossier_hash="00" * 32,
            tech_commitment_hash=self.comm_tech_b,
            fin_commitment_hash=self.comm_fin_b,
            bond_mode=BondMode.SolanaEscrow,
            bond_amount=5000
        )

    def test_disqualified_bidder_bond_refund_and_commercial_secrecy(self):
        # 3. Advance to TechnicalEvaluation
        self.ledger.advance_slot(60)
        self.ledger.advance_tender_phase(self.tender_pda) # SubmissionsOpen -> AdministrativeReview
        self.ledger.advance_slot(60)
        self.ledger.advance_tender_phase(self.tender_pda) # AdministrativeReview -> TechnicalEvaluation
        self.assertEqual(self.ledger.tenders[self.tender_pda]["status"], TenderStatus.TechnicalEvaluation)

        # Cannot refund while in TechnicalEvaluation phase
        with self.assertRaises(ValueError) as ctx:
            self.ledger.refund_disqualified_bond(self.tender_pda, self.bidder_b["public_key"])
        self.assertIn("TenderNotFinancialEvaluation", str(ctx.exception))

        # Unseal tech proposals
        self.ledger.reveal_technical_bid(self.tender_pda, self.bidder_a["public_key"], self.salt_tech_a, "SPEC_A")
        self.ledger.reveal_technical_bid(self.tender_pda, self.bidder_b["public_key"], self.salt_tech_b, "SPEC_B")

        # Evaluator scores: Bidder A gets 8000 (qualified), Bidder B gets 6000 (disqualified)
        for ev in self.evaluators:
            # Bidder A: [1600, 1600, 1600, 1600, 1600] = 8000
            comm_a = compute_grade_commitment(self.tender_pda, self.bidder_a["public_key"], ev, "00"*32, [1600]*5, "00"*32).hex()
            self.ledger.commit_evaluator_grade(self.tender_pda, ev, self.bidder_a["public_key"], comm_a)
            self.ledger.reveal_evaluator_grade(self.tender_pda, ev, self.bidder_a["public_key"], [1600]*5, "00"*32, "00"*32)

            # Bidder B: [1200, 1200, 1200, 1200, 1200] = 6000
            comm_b = compute_grade_commitment(self.tender_pda, self.bidder_b["public_key"], ev, "00"*32, [1200]*5, "00"*32).hex()
            self.ledger.commit_evaluator_grade(self.tender_pda, ev, self.bidder_b["public_key"], comm_b)
            self.ledger.reveal_evaluator_grade(self.tender_pda, ev, self.bidder_b["public_key"], [1200]*5, "00"*32, "00"*32)

        # Finalize technical scores
        self.ledger.finalize_technical_scores(self.tender_pda, self.authority["public_key"], self.bidder_a["public_key"])
        self.ledger.finalize_technical_scores(self.tender_pda, self.authority["public_key"], self.bidder_b["public_key"])

        bid_a_pda = self.ledger.derive_bid_pda(self.tender_pda, self.bidder_a["public_key"])
        bid_b_pda = self.ledger.derive_bid_pda(self.tender_pda, self.bidder_b["public_key"])

        self.assertTrue(self.ledger.commitments[bid_a_pda]["is_tech_qualified"])
        self.assertFalse(self.ledger.commitments[bid_b_pda]["is_tech_qualified"])

        # 4. Advance to FinancialEvaluation
        self.ledger.advance_slot(60)
        self.ledger.advance_tender_phase(self.tender_pda)
        self.assertEqual(self.ledger.tenders[self.tender_pda]["status"], TenderStatus.FinancialEvaluation)

        # Disqualified Bidder B attempts to reveal financial envelope -> MUST FAIL with Commercial Secrecy
        with self.assertRaises(ValueError) as ctx:
            self.ledger.reveal_financial_envelope(self.tender_pda, self.bidder_b["public_key"], self.salt_fin_b, 3500000, "BOQ_B")
        self.assertIn("BidderTechnicallyDisqualified", str(ctx.exception))
        self.assertFalse(self.ledger.commitments[bid_b_pda]["is_fin_revealed"])

        # Qualified Bidder A attempts to call refund_disqualified_bond -> MUST FAIL (must reveal to settle)
        with self.assertRaises(ValueError) as ctx:
            self.ledger.refund_disqualified_bond(self.tender_pda, self.bidder_a["public_key"])
        self.assertIn("BidderIsTechQualified", str(ctx.exception))

        # Disqualified Bidder B calls refund_disqualified_bond -> SUCCESS!
        bid_b_record = self.ledger.refund_disqualified_bond(self.tender_pda, self.bidder_b["public_key"])
        self.assertTrue(bid_b_record["is_bond_settled"])
        self.assertEqual(bid_b_record["escrowed_deposit"], 0)

        # CRITICAL VERIFICATION: Commercial secrecy is 100% preserved!
        self.assertFalse(bid_b_record["is_fin_revealed"])
        self.assertEqual(bid_b_record.get("revealed_price", 0), 0)

        # Attempted second refund fails with BondAlreadySettled
        with self.assertRaises(ValueError) as ctx:
            self.ledger.refund_disqualified_bond(self.tender_pda, self.bidder_b["public_key"])
        self.assertIn("BondAlreadySettled", str(ctx.exception))

        # Qualified Bidder A reveals legitimately and wins
        revealed_a = self.ledger.reveal_financial_envelope(self.tender_pda, self.bidder_a["public_key"], self.salt_fin_a, 4000000, "BOQ_A")
        self.assertTrue(revealed_a["is_fin_revealed"])

        # Award
        awarded = self.ledger.record_award_qcbs(self.tender_pda, self.authority["public_key"], self.bidder_a["public_key"])
        self.assertEqual(awarded["winning_bidder"], self.bidder_a["public_key"])

    def test_relayer_gateway_refund_disqualified_bond(self):
        relayer = BidTraceRelayerGateway()
        authority = generate_keypair()
        tender_res = relayer.create_tender(
            authority_pubkey=authority["public_key"],
            tender_id="TENDER-RELAYER-SEC01",
            title="Relayer Bond Test",
            description="Testing relayer bond refund",
            buyer_name="Audit Bureau",
            currency="USD",
            estimated_amount=1000000.0,
            submission_deadline_iso="2026-12-01T00:00:00Z",
            evaluation_type="QCBS",
            tech_weight=0.7,
            fin_weight=0.3,
            min_tech_score=75.0,
            bond_amount=3000,
            bond_mode_str="SolanaEscrow"
        )
        t_pda = tender_res["tender"]["pda"]
        evals = [generate_keypair()["public_key"] for _ in range(5)]
        relayer.ledger.initialize_committee(t_pda, authority["public_key"], evals, 2000)

        # Bidder commits
        b_kp = generate_keypair()
        relayer.commit_dual_bid(
            tender_pda=t_pda,
            bidder_pubkey=b_kp["public_key"],
            bidder_name="Disqualified Contractor",
            admin_dossier_hash="00"*32,
            salt_tech="aa"*32,
            proposal_hash="bb"*32,
            salt_fin="cc"*32,
            price=900000,
            boq_hash="dd"*32,
            bond_mode=BondMode.SolanaEscrow,
            bond_amount=3000
        )

        # Advance to tech
        relayer.ledger.advance_slot(60)
        relayer.ledger.advance_tender_phase(t_pda) # SubmissionsOpen -> AdministrativeReview
        relayer.ledger.advance_slot(60)
        relayer.ledger.advance_tender_phase(t_pda) # AdministrativeReview -> TechnicalEvaluation
        relayer.ledger.reveal_technical_bid(t_pda, b_kp["public_key"], "aa"*32, "bb"*32)

        # Low scores (5000 bps < 7500 bps)
        for ev in evals:
            comm = compute_grade_commitment(t_pda, b_kp["public_key"], ev, "00"*32, [1000]*5, "00"*32).hex()
            relayer.ledger.commit_evaluator_grade(t_pda, ev, b_kp["public_key"], comm)
            relayer.ledger.reveal_evaluator_grade(t_pda, ev, b_kp["public_key"], [1000]*5, "00"*32, "00"*32)

        relayer.ledger.finalize_technical_scores(t_pda, authority["public_key"], b_kp["public_key"])

        # Advance to financial
        relayer.ledger.advance_slot(60)
        relayer.ledger.advance_tender_phase(t_pda)

        # Relayer sponsors disqualified bond refund
        res = relayer.refund_disqualified_bond(t_pda, b_kp["public_key"])
        self.assertTrue(res["bid"]["is_bond_settled"])
        self.assertFalse(res["bid"]["is_fin_revealed"])
        self.assertIn("tx_refund_", res["tx_signature"])

if __name__ == "__main__":
    unittest.main()
