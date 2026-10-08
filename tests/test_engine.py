import unittest
import os
import secrets
from bidtrace_py.crypto import generate_keypair, encrypt_payload, compute_commitment_hash
from bidtrace_py.ledger import BidTraceLedger, TenderStatus
from bidtrace_py.verifier import verify_proof_bundle

class TestBidTraceProtocol(unittest.TestCase):
    def setUp(self):
        self.ledger = BidTraceLedger()
        self.authority = generate_keypair()
        self.bidder_a = generate_keypair()
        self.bidder_b = generate_keypair()
        self.bidder_c = generate_keypair()
        self.bidder_d = generate_keypair()

    def test_01_happy_path(self):
        """Story 1 & 2: Complete tender lifecycle with 3 bidders."""
        # 1. Authority initializes tender with deadline at slot 1050
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-2026-HIGHWAY",
            deadline_slot=1050
        )
        tender_pda = tender["pda"]
        self.assertEqual(tender["status"], TenderStatus.ACTIVE)

        # 2. Bidder A commits
        salt_a = secrets.token_hex(32)
        payload_a = encrypt_payload({"bidder": "ACME Corp", "amount": 4200000, "specs": "Concrete A"})
        comm_a = compute_commitment_hash(tender_pda, self.bidder_a["public_key"], salt_a, payload_a["ciphertext_hash_hex"], 4200000)
        bid_a = self.ledger.commit_bid(tender_pda, self.bidder_a["public_key"], comm_a)
        self.assertEqual(bid_a["committed_at_slot"], 1000)

        # 3. Bidder B commits
        salt_b = secrets.token_hex(32)
        payload_b = encrypt_payload({"bidder": "BuildCo", "amount": 3950000, "specs": "Steel Spec"})
        comm_b = compute_commitment_hash(tender_pda, self.bidder_b["public_key"], salt_b, payload_b["ciphertext_hash_hex"], 3950000)
        self.ledger.commit_bid(tender_pda, self.bidder_b["public_key"], comm_b)

        # 4. Advance time past deadline
        self.ledger.advance_slot(60) # slot is now 1060 (> 1050)

        # 5. Lock tender
        locked_tender = self.ledger.lock_tender(tender_pda)
        self.assertEqual(locked_tender["status"], TenderStatus.LOCKED)
        self.assertEqual(locked_tender["total_committed"], 2)

        # 6. Reveal Bidder A
        rev_a = self.ledger.reveal_bid(tender_pda, self.bidder_a["public_key"], salt_a, payload_a["ciphertext_hash_hex"], 4200000)
        self.assertTrue(rev_a["is_revealed"])
        self.assertEqual(rev_a["revealed_amount"], 4200000)

        # 7. Reveal Bidder B
        rev_b = self.ledger.reveal_bid(tender_pda, self.bidder_b["public_key"], salt_b, payload_b["ciphertext_hash_hex"], 3950000)
        self.assertTrue(rev_b["is_revealed"])
        self.assertEqual(rev_b["revealed_amount"], 3950000)

        # 8. Award to lowest compliant bidder (BuildCo / Bidder B)
        awarded = self.ledger.record_award(tender_pda, self.authority["public_key"], self.bidder_b["public_key"])
        self.assertEqual(awarded["status"], TenderStatus.AWARDED)
        self.assertEqual(awarded["winning_bidder"], self.bidder_b["public_key"])

    def test_02_attack_late_bid_injection_fails(self):
        """Story 3 (Attack A): Malicious admin attempts late bid submission after deadline."""
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-LATE-ATTACK",
            deadline_slot=1020
        )
        tender_pda = tender["pda"]

        # Advance slot past deadline
        self.ledger.advance_slot(25) # Slot 1025 > 1020

        # Attempt to insert late bid D
        salt_d = secrets.token_hex(32)
        payload_d = encrypt_payload({"bidder": "Corrupt Co", "amount": 1000000, "specs": "Late"})
        comm_d = compute_commitment_hash(tender_pda, self.bidder_d["public_key"], salt_d, payload_d["ciphertext_hash_hex"], 1000000)

        with self.assertRaises(ValueError) as ctx:
            self.ledger.commit_bid(tender_pda, self.bidder_d["public_key"], comm_d)
        self.assertIn("DeadlineExceeded", str(ctx.exception))

    def test_03_attack_bid_tampering_fails(self):
        """Story 3 (Attack B): Malicious admin attempts to alter bid amount during reveal."""
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-TAMPER-ATTACK",
            deadline_slot=1050
        )
        tender_pda = tender["pda"]

        # Legitimate commitment of $4,200,000
        salt = secrets.token_hex(32)
        payload = encrypt_payload({"bidder": "Legit Corp", "amount": 4200000, "specs": "Legit"})
        comm = compute_commitment_hash(tender_pda, self.bidder_a["public_key"], salt, payload["ciphertext_hash_hex"], 4200000)
        self.ledger.commit_bid(tender_pda, self.bidder_a["public_key"], comm)

        # Advance past deadline & lock
        self.ledger.advance_slot(60)
        self.ledger.lock_tender(tender_pda)

        # Corrupt admin tries to reveal with forged price of $3,800,000 to win
        with self.assertRaises(ValueError) as ctx:
            self.ledger.reveal_bid(tender_pda, self.bidder_a["public_key"], salt, payload["ciphertext_hash_hex"], 3800000)
        self.assertIn("InvalidRevealHash", str(ctx.exception))

    def test_04_flaw_a_censorship_resistance(self):
        """Proof that Flaw A is resolved: Direct PDA intake ensures non-custodial inclusion."""
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-CENSORSHIP-PROOF",
            deadline_slot=1050
        )
        tender_pda = tender["pda"]

        # Three bidders commit directly
        for bidder in [self.bidder_a, self.bidder_b, self.bidder_c]:
            salt = secrets.token_hex(32)
            payload = encrypt_payload({"bidder": bidder["public_key"][:8], "amount": 5000000, "specs": "X"})
            comm = compute_commitment_hash(tender_pda, bidder["public_key"], salt, payload["ciphertext_hash_hex"], 5000000)
            self.ledger.commit_bid(tender_pda, bidder["public_key"], comm)

        # All 3 are recorded in independent PDAs
        self.assertEqual(self.ledger.tenders[tender_pda]["total_committed"], 3)
        pda_c = self.ledger.derive_bid_pda(tender_pda, self.bidder_c["public_key"])
        self.assertIn(pda_c, self.ledger.commitments)

    def test_05_flaw_b_partial_reveal_resilience(self):
        """Proof that Flaw B is resolved: Bidder C defaults, but tender still succeeds for honest bidders."""
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-PARTIAL-REVEAL",
            deadline_slot=1050
        )
        tender_pda = tender["pda"]

        # Bidder A commits
        salt_a = secrets.token_hex(32)
        payload_a = encrypt_payload({"bidder": "Honest A", "amount": 4000000, "specs": "A"})
        comm_a = compute_commitment_hash(tender_pda, self.bidder_a["public_key"], salt_a, payload_a["ciphertext_hash_hex"], 4000000)
        self.ledger.commit_bid(tender_pda, self.bidder_a["public_key"], comm_a)

        # Bidder C commits
        salt_c = secrets.token_hex(32)
        payload_c = encrypt_payload({"bidder": "Flaky C", "amount": 3500000, "specs": "C"})
        comm_c = compute_commitment_hash(tender_pda, self.bidder_c["public_key"], salt_c, payload_c["ciphertext_hash_hex"], 3500000)
        self.ledger.commit_bid(tender_pda, self.bidder_c["public_key"], comm_c)

        self.ledger.advance_slot(60)
        self.ledger.lock_tender(tender_pda)

        # Only Bidder A reveals. Bidder C vanishes/defaults.
        rev_a = self.ledger.reveal_bid(tender_pda, self.bidder_a["public_key"], salt_a, payload_a["ciphertext_hash_hex"], 4000000)
        self.assertTrue(rev_a["is_revealed"])

        # Early award while reveal window is active is blocked:
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record_award(tender_pda, self.authority["public_key"], self.bidder_a["public_key"])
        self.assertIn("RevealWindowActive", str(ctx.exception))

        # Advance past reveal deadline: slot 1060 + 50 = 1110 (> 1100)
        self.ledger.advance_slot(50)

        # Tender does not deadlock! Once reveal window expires, authority awards to lowest revealed Bidder A
        awarded = self.ledger.record_award(tender_pda, self.authority["public_key"], self.bidder_a["public_key"])
        self.assertEqual(awarded["winning_bidder"], self.bidder_a["public_key"])
        self.assertEqual(self.ledger.tenders[tender_pda]["total_revealed"], 1)

    def test_06_offline_verifier(self):
        """Story 4: Zero-backend standalone offline verification."""
        tender = self.ledger.initialize_tender(
            authority_pubkey=self.authority["public_key"],
            tender_id="TENDER-VERIFIER-TEST",
            deadline_slot=1050
        )
        tender_pda = tender["pda"]

        salt = secrets.token_hex(32)
        payload = encrypt_payload({"bidder": "ACME", "amount": 5500000, "specs": "Grade 50 Concrete"})
        comm = compute_commitment_hash(tender_pda, self.bidder_a["public_key"], salt, payload["ciphertext_hash_hex"], 5500000)
        self.ledger.commit_bid(tender_pda, self.bidder_a["public_key"], comm)

        self.ledger.advance_slot(60)
        self.ledger.lock_tender(tender_pda)

        proof_bundle = {
            "tender_pda": tender_pda,
            "bidder_pubkey": self.bidder_a["public_key"],
            "salt_hex": salt,
            "bid_amount": 5500000,
            "ciphertext_b64": payload["ciphertext_b64"],
            "key_hex": payload["key_hex"],
            "ciphertext_hash_hex": payload["ciphertext_hash_hex"]
        }

        raw_state = {
            "current_slot": self.ledger.current_slot,
            "tenders": self.ledger.tenders,
            "commitments": self.ledger.commitments
        }

        result = verify_proof_bundle(proof_bundle, raw_state)
        self.assertTrue(result["valid"])
        self.assertEqual(result["bid_amount"], 5500000)
        self.assertEqual(result["committed_slot"], 1000)

if __name__ == "__main__":
    unittest.main()
