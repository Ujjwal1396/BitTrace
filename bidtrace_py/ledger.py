import hashlib
import json
import os
from typing import Dict, Optional
from .crypto import compute_commitment_hash

class TenderStatus:
    ACTIVE = "Active"
    LOCKED = "Locked"
    AWARDED = "Awarded"
    CANCELLED = "Cancelled"

class BidTraceLedger:
    """
    Simulates the Solana Ledger and BidTrace Anchor Program state machine.
    Enforces identical rules, PDA derivation, slot deadlines, and error conditions.
    """
    def __init__(self, state_file: Optional[str] = None):
        self.state_file = state_file
        self.current_slot: int = 1000
        self.tenders: Dict[str, dict] = {}
        self.commitments: Dict[str, dict] = {} # Keyed by pda_address
        self.load_state()

    def load_state(self):
        if self.state_file and os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.current_slot = data.get("current_slot", 1000)
                    self.tenders = data.get("tenders", {})
                    self.commitments = data.get("commitments", {})
            except Exception:
                pass

    def save_state(self):
        if self.state_file:
            data = {
                "current_slot": self.current_slot,
                "tenders": self.tenders,
                "commitments": self.commitments
            }
            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)

    def advance_slot(self, slots: int = 1):
        self.current_slot += slots
        self.save_state()
        return self.current_slot

    def derive_tender_pda(self, authority_pubkey: str, tender_id: str) -> str:
        raw = f"tender:{authority_pubkey}:{tender_id}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:44]

    def derive_bid_pda(self, tender_pda: str, bidder_pubkey: str) -> str:
        raw = f"bid:{tender_pda}:{bidder_pubkey}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:44]

    def initialize_tender(self, authority_pubkey: str, tender_id: str, deadline_slot: int, authorized_bidders_root: str = "00"*32) -> dict:
        if deadline_slot <= self.current_slot:
            raise ValueError(f"InvalidDeadlineSlot: deadline_slot ({deadline_slot}) must be > current_slot ({self.current_slot})")
        
        tender_pda = self.derive_tender_pda(authority_pubkey, tender_id)
        if tender_pda in self.tenders:
            raise ValueError("TenderAlreadyExists")

        tender = {
            "pda": tender_pda,
            "authority": authority_pubkey,
            "tender_id": tender_id,
            "deadline_slot": deadline_slot,
            "authorized_bidders_root": authorized_bidders_root,
            "total_committed": 0,
            "total_revealed": 0,
            "status": TenderStatus.ACTIVE,
            "winning_bidder": None,
            "initialized_at_slot": self.current_slot
        }
        self.tenders[tender_pda] = tender
        self.save_state()
        return tender

    def commit_bid(self, tender_pda: str, bidder_pubkey: str, commitment_hash: str) -> dict:
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        
        tender = self.tenders[tender_pda]
        if tender["status"] != TenderStatus.ACTIVE:
            raise ValueError("TenderAlreadyLocked: Submissions are closed")

        if self.current_slot > tender["deadline_slot"]:
            raise ValueError(
                f"DeadlineExceeded: Current slot {self.current_slot} > deadline slot {tender['deadline_slot']}"
            )

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda in self.commitments:
            raise ValueError("BidAlreadyCommitted: Bidder already submitted a commitment")

        bid_record = {
            "pda": bid_pda,
            "tender_pda": tender_pda,
            "bidder": bidder_pubkey,
            "commitment_hash": commitment_hash,
            "committed_at_slot": self.current_slot,
            "is_revealed": False,
            "revealed_at_slot": 0,
            "revealed_amount": 0
        }

        self.commitments[bid_pda] = bid_record
        tender["total_committed"] += 1
        self.save_state()
        return bid_record

    def lock_tender(self, tender_pda: str) -> dict:
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        
        tender = self.tenders[tender_pda]
        if tender["status"] != TenderStatus.ACTIVE:
            raise ValueError("TenderAlreadyLocked")

        if self.current_slot <= tender["deadline_slot"]:
            raise ValueError(
                f"DeadlineNotReached: Current slot {self.current_slot} <= deadline slot {tender['deadline_slot']}"
            )

        tender["status"] = TenderStatus.LOCKED
        self.save_state()
        return tender

    def reveal_bid(self, tender_pda: str, bidder_pubkey: str, salt_hex: str, ciphertext_hash_hex: str, bid_amount: int) -> dict:
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["status"] != TenderStatus.LOCKED:
            raise ValueError("TenderNotLocked: Tender must be locked before reveals can take place")

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda not in self.commitments:
            raise ValueError("BidNotFound")

        bid = self.commitments[bid_pda]
        if bid["is_revealed"]:
            raise ValueError("BidAlreadyRevealed")

        # Cryptographic check
        expected_hash = compute_commitment_hash(
            tender_pubkey_hex=tender_pda,
            bidder_pubkey_hex=bidder_pubkey,
            salt_hex=salt_hex,
            ciphertext_hash_hex=ciphertext_hash_hex,
            bid_amount=bid_amount
        )

        if expected_hash != bid["commitment_hash"]:
            raise ValueError(
                f"InvalidRevealHash: Recomputed hash ({expected_hash}) != on-chain commitment ({bid['commitment_hash']})"
            )

        bid["is_revealed"] = True
        bid["revealed_at_slot"] = self.current_slot
        bid["revealed_amount"] = bid_amount
        tender["total_revealed"] += 1
        self.save_state()
        return bid

    def record_award(self, tender_pda: str, authority_pubkey: str, winning_bidder_pubkey: str) -> dict:
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["authority"] != authority_pubkey:
            raise ValueError("Unauthorized: Only authority can record award")

        if tender["status"] != TenderStatus.LOCKED:
            raise ValueError("TenderNotLocked: Must be in Locked state to award")

        winner_bid_pda = self.derive_bid_pda(tender_pda, winning_bidder_pubkey)
        if winner_bid_pda not in self.commitments:
            raise ValueError("WinningBidNotFound")

        winning_bid = self.commitments[winner_bid_pda]
        if not winning_bid["is_revealed"]:
            raise ValueError("WinnerNotRevealed: Cannot award to an unrevealed bid")

        tender["winning_bidder"] = winning_bidder_pubkey
        tender["status"] = TenderStatus.AWARDED
        self.save_state()
        return tender
