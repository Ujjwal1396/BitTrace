"""
BidTrace 3.0 Ledger & Anchor State Machine Simulator
===================================================
Simulates the upgraded Solana Anchor smart contract (programs/bidtrace).
Enforces:
1. Two-Envelope cryptographic state machine (Technical + Financial separation).
2. Model A (Pre-Qualified Merkle Whitelist) and Model B (Post-Qualified Open).
3. Multi-evaluator blinded scoring protocol with Olympic Trimmed Mean and rogue outlier detection.
4. The Commercial Secrecy Guarantee: Disqualified bidders strictly cannot unseal Envelope B.
5. Programmatic QCBS composite scoring and deterministic award.
"""

import hashlib
import json
import os
from typing import Dict, Any, List, Optional, Union
from .crypto import (
    to_32bytes,
    b58encode,
    b58decode,
    compute_tech_commitment,
    compute_fin_commitment,
    compute_grade_commitment,
    compute_commitment_hash
)
from .merkle import verify_merkle_proof


class TenderStatus:
    ACTIVE = "Active"
    LOCKED = "Locked"
    AWARDED = "Awarded"
    CANCELLED = "Cancelled"

    SubmissionsOpen = "Active"
    AdministrativeReview = "AdministrativeReview"
    TechnicalEvaluation = "Locked"
    FinancialEvaluation = "FinancialEvaluation"
    Awarded = "Awarded"
    Cancelled = "Cancelled"


class TenderMode:
    PreQualifiedWhitelist = 0  # Model A
    PostQualifiedOpen = 1      # Model B


class EvaluationType:
    LeastCost = 0
    QCBS = 1


class AdminStatus:
    Pending = 0
    Passed = 1
    Failed = 2


class BondMode:
    SolanaEscrow = 0
    SuretyService = 1
    BankGuaranteeAttestation = 2
    BidSecuringDeclaration = 3


class BidTraceLedger:
    """
    Solana Anchor Program State Machine Simulator for BidTrace 3.0.
    """
    def __init__(self, state_file: Optional[str] = None):
        self.state_file = state_file
        self.current_slot: int = 1000
        self.tenders: Dict[str, dict] = {}
        self.committees: Dict[str, dict] = {}
        self.commitments: Dict[str, dict] = {}
        self.evaluator_grades: Dict[str, dict] = {}
        self.load_state()

    def load_state(self):
        if self.state_file and os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.current_slot = data.get("current_slot", 1000)
                    self.tenders = data.get("tenders", {})
                    self.committees = data.get("committees", {})
                    self.commitments = data.get("commitments", {})
                    self.evaluator_grades = data.get("evaluator_grades", {})
            except Exception:
                pass

    def save_state(self):
        if self.state_file:
            data = {
                "current_slot": self.current_slot,
                "tenders": self.tenders,
                "committees": self.committees,
                "commitments": self.commitments,
                "evaluator_grades": self.evaluator_grades
            }
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

    def advance_slot(self, slots: int = 1) -> int:
        self.current_slot += slots
        self.save_state()
        return self.current_slot

    def derive_tender_pda(self, authority_pubkey: str, tender_id: str) -> str:
        raw = f"tender:{authority_pubkey}:{tender_id}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:44]

    def derive_committee_pda(self, tender_pda: str) -> str:
        raw = f"committee:{tender_pda}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:44]

    def derive_bid_pda(self, tender_pda: str, bidder_pubkey: str) -> str:
        raw = f"bid:{tender_pda}:{bidder_pubkey}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:44]

    def derive_grade_pda(self, tender_pda: str, evaluator_pubkey: str, bidder_pubkey: str) -> str:
        raw = f"grade:{tender_pda}:{evaluator_pubkey}:{bidder_pubkey}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:44]

    def initialize_tender(
        self,
        authority_pubkey: str,
        tender_id: str,
        ocds_notice_hash: str = "00" * 32,
        tender_mode: int = TenderMode.PostQualifiedOpen,
        evaluation_type: int = EvaluationType.QCBS,
        submission_deadline_slot: Optional[int] = None,
        admin_review_deadline_slot: Optional[int] = None,
        tech_eval_deadline_slot: Optional[int] = None,
        fin_reveal_deadline_slot: Optional[int] = None,
        authorized_bidders_root: str = "00" * 32,
        min_tech_score_bps: int = 7500,
        tech_weight_bps: int = 7000,
        fin_weight_bps: int = 3000,
        bid_deposit: int = 0,
        deadline_slots: int = 50,
        deadline_slot: Optional[int] = None,
        reveal_deadline_slot: Optional[int] = None
    ) -> dict:
        """
        Initializes Tender PDA matching Anchor initialize_tender instruction.
        """
        if submission_deadline_slot is None:
            if deadline_slot is not None:
                submission_deadline_slot = deadline_slot
            else:
                submission_deadline_slot = self.current_slot + deadline_slots

        if admin_review_deadline_slot is None:
            admin_review_deadline_slot = submission_deadline_slot + 20
        if tech_eval_deadline_slot is None:
            tech_eval_deadline_slot = submission_deadline_slot + 40

        if fin_reveal_deadline_slot is None:
            if reveal_deadline_slot is not None:
                fin_reveal_deadline_slot = reveal_deadline_slot
            else:
                fin_reveal_deadline_slot = submission_deadline_slot + 50

        if submission_deadline_slot <= self.current_slot:
            raise ValueError(f"Submission deadline {submission_deadline_slot} must be > current slot {self.current_slot}")

        tender_pda = self.derive_tender_pda(authority_pubkey, tender_id)
        
        tender = {
            "pda": tender_pda,
            "authority": authority_pubkey,
            "tender_id": tender_id,
            "ocds_notice_hash": ocds_notice_hash,
            "tender_mode": tender_mode,
            "evaluation_type": evaluation_type,
            "status": TenderStatus.SubmissionsOpen,
            
            # Deadlines
            "submission_deadline_slot": submission_deadline_slot,
            "admin_review_deadline_slot": admin_review_deadline_slot,
            "tech_eval_deadline_slot": tech_eval_deadline_slot,
            "fin_reveal_deadline_slot": fin_reveal_deadline_slot,
            "deadline_slot": submission_deadline_slot, # backwards compat
            "reveal_deadline_slot": fin_reveal_deadline_slot, # backwards compat

            # Merkle whitelist
            "authorized_bidders_root": authorized_bidders_root,

            # Scoring weights (bps: 10,000 = 100%)
            "min_tech_score_bps": min_tech_score_bps,
            "tech_weight_bps": tech_weight_bps,
            "fin_weight_bps": fin_weight_bps,

            # Progress counters
            "total_committed": 0,
            "total_admin_passed": 0,
            "total_tech_qualified": 0,
            "total_fin_revealed": 0,
            "total_revealed": 0, # backwards compat

            # Pricing & Award
            "lowest_revealed_price": 0,
            "highest_composite_score": 0,
            "winning_bidder": None,
            "bid_deposit": bid_deposit,
            "initialized_at_slot": self.current_slot
        }

        self.tenders[tender_pda] = tender
        self.save_state()
        return tender

    def initialize_committee(
        self,
        tender_pda: str,
        authority_pubkey: str,
        evaluators: List[str],
        max_variance_bps: int = 2000
    ) -> dict:
        """Initializes TenderCommittee PDA with certified evaluators."""
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]
        if tender["authority"] != authority_pubkey:
            raise ValueError("Unauthorized: Only tender authority can initialize committee")
        if len(evaluators) < 3:
            raise ValueError("Committee must have at least 3 evaluators")

        comm_pda = self.derive_committee_pda(tender_pda)
        committee = {
            "pda": comm_pda,
            "tender": tender_pda,
            "evaluators": list(evaluators),
            "max_variance_bps": max_variance_bps,
            "is_locked": True
        }
        self.committees[comm_pda] = committee
        self.save_state()
        return committee

    def commit_dual_bid(
        self,
        tender_pda: str,
        bidder_pubkey: str,
        admin_dossier_hash: str,
        tech_commitment_hash: str,
        fin_commitment_hash: str,
        bond_mode: int = BondMode.SuretyService,
        bond_amount: int = 0,
        whitelist_proof: Optional[List[str]] = None
    ) -> dict:
        """
        Commits DualBidCommitment PDA.
        Enforces Model A Merkle proof verification if PreQualifiedWhitelist.
        """
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["status"] != TenderStatus.SubmissionsOpen:
            raise ValueError(f"TenderNotSubmissionsOpen: Status is {tender['status']}")

        if self.current_slot > tender["submission_deadline_slot"]:
            raise ValueError(f"SubmissionDeadlineExceeded: Slot {self.current_slot} > {tender['submission_deadline_slot']}")

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda in self.commitments:
            raise ValueError("BidAlreadyCommitted: Bidder already committed")

        # Model A: Merkle Proof Verification
        admin_status = AdminStatus.Pending
        if tender["tender_mode"] == TenderMode.PreQualifiedWhitelist:
            if not whitelist_proof:
                raise ValueError("UnauthorizedBidder: Missing Model A Merkle whitelist proof")
            root = tender["authorized_bidders_root"]
            if not verify_merkle_proof(bidder_pubkey, whitelist_proof, root):
                raise ValueError("InvalidMerkleProof: Bidder not in pre-authorized whitelist")
            admin_status = AdminStatus.Passed
            tender["total_admin_passed"] += 1

        bid_record = {
            "pda": bid_pda,
            "tender": tender_pda,
            "tender_pda": tender_pda,
            "bidder": bidder_pubkey,
            "committed_at_slot": self.current_slot,
            "admin_dossier_hash": admin_dossier_hash,
            "tech_commitment_hash": tech_commitment_hash,
            "fin_commitment_hash": fin_commitment_hash,
            "commitment_hash": tech_commitment_hash, # compat
            "admin_status": admin_status,
            "admin_rejection_code": 0,
            
            # Phase 2 Technical
            "is_tech_revealed": False,
            "is_revealed": False, # compat
            "technical_score_bps": 0,
            "is_tech_qualified": False,

            # Phase 3 Financial
            "is_fin_revealed": False,
            "revealed_price": 0,
            "composite_score": 0,

            # Bond
            "bond_mode": bond_mode,
            "bond_amount": bond_amount,
            "is_bond_settled": False,
            "escrowed_deposit": tender.get("bid_deposit", 0),
            "revealed_amount": 0,
            "whitelist_proof": whitelist_proof or []
        }

        self.commitments[bid_pda] = bid_record
        tender["total_committed"] += 1
        self.save_state()
        return bid_record

    def advance_tender_phase(
        self,
        tender_pda: str,
        caller_pubkey: Optional[str] = None,
        enforce_deadlines: bool = False
    ) -> dict:
        """
        Advances the state machine:
        SubmissionsOpen -> AdministrativeReview -> TechnicalEvaluation -> FinancialEvaluation -> Awarded
        
        SEC-03 Anti-Early-Lockout Defense:
        When caller_pubkey is provided or enforce_deadlines is True, consensus slot deadlines
        are strictly enforced. The tender authority CANNOT bypass deadlines to lock out honest
        bidders or committee evaluators early.
        """
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        should_enforce = enforce_deadlines or (caller_pubkey is not None)
        curr = tender["status"]

        if curr == TenderStatus.SubmissionsOpen:
            if should_enforce and self.current_slot <= tender["submission_deadline_slot"]:
                raise ValueError("SubmissionDeadlineNotReached: Submissions window is still open")
            if tender.get("admin_review_deadline_slot") == tender["submission_deadline_slot"]:
                tender["status"] = TenderStatus.TechnicalEvaluation
            else:
                tender["status"] = TenderStatus.AdministrativeReview
        elif curr == TenderStatus.AdministrativeReview:
            if should_enforce and self.current_slot <= tender.get("admin_review_deadline_slot", tender["submission_deadline_slot"]):
                raise ValueError("AdminReviewDeadlineNotReached: Administrative review deadline has not elapsed")
            tender["status"] = TenderStatus.TechnicalEvaluation
        elif curr == TenderStatus.TechnicalEvaluation:
            if should_enforce and self.current_slot <= tender["tech_eval_deadline_slot"]:
                raise ValueError("TechEvalDeadlineNotReached: Technical evaluation deadline has not elapsed")
            tender["status"] = TenderStatus.FinancialEvaluation
        elif curr == TenderStatus.FinancialEvaluation:
            tender["status"] = TenderStatus.Awarded
        else:
            raise ValueError(f"Cannot advance tender from status '{curr}'")

        self.save_state()
        return tender

    def reveal_technical_bid(
        self,
        tender_pda: str,
        bidder_pubkey: str,
        salt_tech: str,
        proposal_hash: str
    ) -> dict:
        """
        Unseals Envelope A (Technical proposal).
        Verifies domain-separated BIDTRACE_TECH_V1 commitment.
        """
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["status"] != TenderStatus.TechnicalEvaluation:
            raise ValueError(f"TenderNotTechnicalEvaluation: Tender status is {tender['status']}")

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda not in self.commitments:
            raise ValueError("BidNotFound")
        bid = self.commitments[bid_pda]

        if bid["is_tech_revealed"]:
            raise ValueError("TechAlreadyRevealed")

        expected = compute_tech_commitment(tender_pda, bidder_pubkey, salt_tech, proposal_hash).hex()
        actual = bid["tech_commitment_hash"]
        if expected.lower() != actual.lower():
            raise ValueError(f"InvalidRevealHash: Computed {expected} != on-chain {actual}")

        bid["is_tech_revealed"] = True
        bid["is_revealed"] = True
        self.save_state()
        return bid

    def commit_evaluator_grade(
        self,
        tender_pda: str,
        evaluator_pubkey: str,
        bidder_pubkey: str,
        commitment_hash: str,
        enforce_deadline: bool = False
    ) -> dict:
        """Commits blinded grade for an evaluator."""
        comm_pda = self.derive_committee_pda(tender_pda)
        if comm_pda not in self.committees:
            raise ValueError("CommitteeNotFound")
        comm = self.committees[comm_pda]
        if evaluator_pubkey not in comm["evaluators"]:
            raise ValueError("EvaluatorNotAuthorized")

        if enforce_deadline and tender_pda in self.tenders:
            tender = self.tenders[tender_pda]
            if self.current_slot > tender.get("tech_eval_deadline_slot", float("inf")):
                raise ValueError("TechEvalDeadlineExceeded: Technical evaluation deadline has passed")

        grade_pda = self.derive_grade_pda(tender_pda, evaluator_pubkey, bidder_pubkey)
        grade_record = {
            "pda": grade_pda,
            "tender": tender_pda,
            "evaluator": evaluator_pubkey,
            "bidder": bidder_pubkey,
            "commitment_hash": commitment_hash,
            "committed_at_slot": self.current_slot,
            "is_revealed": False,
            "sub_scores": [0, 0, 0, 0, 0],
            "total_score_bps": 0,
            "justification_hash": "00" * 32,
            "is_outlier_flagged": False
        }
        self.evaluator_grades[grade_pda] = grade_record
        self.save_state()
        return grade_record

    def reveal_evaluator_grade(
        self,
        tender_pda: str,
        evaluator_pubkey: str,
        bidder_pubkey: str,
        sub_scores: List[int],
        salt: str,
        justification_hash: str
    ) -> dict:
        """Reveals blinded evaluator rubric scores."""
        grade_pda = self.derive_grade_pda(tender_pda, evaluator_pubkey, bidder_pubkey)
        if grade_pda not in self.evaluator_grades:
            raise ValueError("GradeCommitmentNotFound")
        grade = self.evaluator_grades[grade_pda]

        if grade["is_revealed"]:
            raise ValueError("GradeAlreadyRevealed")

        expected = compute_grade_commitment(tender_pda, bidder_pubkey, evaluator_pubkey, salt, sub_scores, justification_hash).hex()
        actual = grade["commitment_hash"]
        if expected.lower() != actual.lower():
            raise ValueError(f"InvalidRevealHash: Computed grade hash {expected} != {actual}")

        grade["is_revealed"] = True
        grade["sub_scores"] = list(sub_scores)
        grade["total_score_bps"] = sum(sub_scores)
        grade["justification_hash"] = justification_hash
        self.save_state()
        return grade

    def finalize_technical_scores(
        self,
        tender_pda: str,
        authority_pubkey: str,
        bidder_pubkey: str
    ) -> dict:
        """
        Executes Olympic Trimmed Mean across evaluator grades:
        1. Checks min 3 grades.
        2. Computes median.
        3. Flags outliers (> 20% variance from median).
        4. Drops highest and lowest (if N >= 4) + flagged outliers.
        5. Calculates final technical_score_bps and qualification against cutoff.
        """
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]
        comm_pda = self.derive_committee_pda(tender_pda)
        comm = self.committees.get(comm_pda)

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda not in self.commitments:
            raise ValueError("BidNotFound")
        bid = self.commitments[bid_pda]

        # Gather grades for this bidder
        grades: List[dict] = []
        for g in self.evaluator_grades.values():
            if g["tender"] == tender_pda and g["bidder"] == bidder_pubkey and g["is_revealed"]:
                grades.append(g)

        if len(grades) < 3:
            raise ValueError(f"InsufficientEvaluatorGrades: Required >= 3, found {len(grades)}")

        n = len(grades)
        scores = sorted([g["total_score_bps"] for g in grades])

        median = scores[n // 2] if n % 2 == 1 else (scores[n // 2 - 1] + scores[n // 2]) // 2
        max_delta = (median * (comm["max_variance_bps"] if comm else 2000)) // 10000

        # Mark outliers
        outlier_count = 0
        for g in grades:
            delta = abs(g["total_score_bps"] - median)
            if delta > max_delta:
                g["is_outlier_flagged"] = True
                outlier_count += 1
            else:
                g["is_outlier_flagged"] = False

        # Olympic trimmed mean: drop min and max if n >= 4
        if n >= 4:
            # scores[1..n-1]
            accepted = [s for s in scores[1:-1] if abs(s - median) <= max_delta]
            final_score = sum(accepted) // len(accepted) if accepted else median
        else:
            accepted = [s for s in scores if abs(s - median) <= max_delta]
            final_score = sum(accepted) // len(accepted) if accepted else median

        bid["technical_score_bps"] = final_score
        is_qualified = (final_score >= tender["min_tech_score_bps"])
        bid["is_tech_qualified"] = is_qualified
        if is_qualified:
            tender["total_tech_qualified"] += 1

        self.save_state()
        return {
            "bidder": bidder_pubkey,
            "final_score_bps": final_score,
            "median_score_bps": median,
            "outliers_pruned": outlier_count,
            "is_tech_qualified": is_qualified,
            "cutoff_bps": tender["min_tech_score_bps"]
        }

    def reveal_financial_envelope(
        self,
        tender_pda: str,
        bidder_pubkey: str,
        salt_fin: str,
        price: int,
        boq_hash: str
    ) -> dict:
        """
        Unseals Envelope B (Financial envelope).
        STRICTLY BLOCKS disqualified bidders (The Commercial Secrecy Guarantee).
        """
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["status"] != TenderStatus.FinancialEvaluation:
            raise ValueError(f"TenderNotFinancialEvaluation: Status is {tender['status']}")

        if self.current_slot > tender["fin_reveal_deadline_slot"]:
            raise ValueError(f"FinancialRevealDeadlineExceeded: Slot {self.current_slot} > {tender['fin_reveal_deadline_slot']}")

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda not in self.commitments:
            raise ValueError("BidNotFound")
        bid = self.commitments[bid_pda]

        if bid["is_fin_revealed"]:
            raise ValueError("FinAlreadyRevealed")

        # THE COMMERCIAL SECRECY GUARANTEE
        if not bid["is_tech_qualified"]:
            raise ValueError("BidderTechnicallyDisqualified: Contractor failed technical cutoff; financial envelope is permanently sealed")

        expected = compute_fin_commitment(tender_pda, bidder_pubkey, salt_fin, price, boq_hash).hex()
        actual = bid["fin_commitment_hash"]
        if expected.lower() != actual.lower():
            raise ValueError(f"InvalidRevealHash: Computed fin hash {expected} != {actual}")

        if price <= 0:
            raise ValueError("ZeroPriceNotAllowed: Revealed price must be greater than zero")

        bid["is_fin_revealed"] = True
        bid["revealed_price"] = price

        tender["total_fin_revealed"] += 1
        tender["total_revealed"] += 1
        if tender["lowest_revealed_price"] == 0 or price < tender["lowest_revealed_price"]:
            tender["lowest_revealed_price"] = price

        self.save_state()

        if hasattr(self, "on_fin_reveal") and callable(self.on_fin_reveal):
            self.on_fin_reveal(tender_pda, bidder_pubkey, salt_fin, price, boq_hash)

        return bid

    def refund_disqualified_bond(
        self,
        tender_pda: str,
        bidder_pubkey: str
    ) -> dict:
        """
        Refunds the escrowed bond deposit for a technically disqualified bidder,
        without unsealing Envelope B (Commercial Secrecy Invariant preserved).
        """
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        # Must be in FinancialEvaluation or Awarded status
        if tender["status"] not in [TenderStatus.FinancialEvaluation, TenderStatus.AWARDED, "FinancialEvaluation", "Awarded"]:
            raise ValueError(f"TenderNotFinancialEvaluation: Status is {tender['status']}")

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda not in self.commitments:
            raise ValueError("BidNotFound")
        bid = self.commitments[bid_pda]

        # ONLY technically disqualified bidders can use this instruction!
        if bid.get("is_tech_qualified", False):
            raise ValueError("BidderIsTechQualified: Bidder is qualified; Envelope B must be unsealed to settle bond")

        if bid.get("is_bond_settled", False):
            raise ValueError("BondAlreadySettled: Bond has already been settled")

        if bid.get("bond_mode", BondMode.SolanaEscrow) != BondMode.SolanaEscrow:
            raise ValueError("InvalidBondMode: Bond mode is not SolanaEscrow")

        refund_amount = bid.get("bond_amount", bid.get("escrowed_deposit", 0))
        if refund_amount <= 0:
            raise ValueError("InsufficientDeposit: No escrowed deposit to refund")

        bid["is_bond_settled"] = True
        bid["escrowed_deposit"] = 0

        self.save_state()
        return bid

    def record_award_qcbs(
        self,
        tender_pda: str,
        authority_pubkey: str,
        winning_bidder_pubkey: str,
        rationale_hash: str = "00" * 32
    ) -> dict:
        """
        Executes programmatic award calculation.
        """
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["authority"] != authority_pubkey:
            raise ValueError("Unauthorized: Only authority can record award")

        if tender["status"] != TenderStatus.FinancialEvaluation:
            raise ValueError(f"TenderNotFinancialEvaluation: Status is {tender['status']}")

        # Anti-lockout gate
        if not (self.current_slot > tender["fin_reveal_deadline_slot"] or tender["total_fin_revealed"] == tender["total_tech_qualified"]):
            raise ValueError(
                f"FinancialRevealWindowActive: Window still open ({self.current_slot} <= {tender['fin_reveal_deadline_slot']}) "
                f"and unrevealed qualified bids remain ({tender['total_fin_revealed']}/{tender['total_tech_qualified']})"
            )

        winner_bid_pda = self.derive_bid_pda(tender_pda, winning_bidder_pubkey)
        if winner_bid_pda not in self.commitments:
            raise ValueError("WinningBidNotFound")
        winning_bid = self.commitments[winner_bid_pda]

        if not winning_bid["is_tech_qualified"]:
            raise ValueError("WinnerNotQualified")
        if not winning_bid["is_fin_revealed"]:
            raise ValueError("WinnerNotRevealed")

        if winning_bid.get("revealed_price", 0) <= 0:
            raise ValueError("ZeroPriceNotAllowed: Revealed price cannot be zero")
        if tender.get("lowest_revealed_price", 0) <= 0:
            raise ValueError("ZeroPriceNotAllowed: Lowest revealed price cannot be zero")

        # Programmatic score calculation across all qualified and revealed bidders
        highest_score = 0
        for b_acc in self.commitments.values():
            if (
                b_acc.get("tender_pda") == tender_pda
                and b_acc.get("is_tech_qualified")
                and b_acc.get("is_fin_revealed")
            ):
                price = b_acc.get("revealed_price", 0)
                if price <= 0:
                    raise ValueError("ZeroPriceNotAllowed: Revealed price cannot be zero")

                if tender["evaluation_type"] == EvaluationType.LeastCost:
                    score = 10000 if price == tender["lowest_revealed_price"] else 0
                else:
                    tech_part = (b_acc["technical_score_bps"] * tender["tech_weight_bps"]) // 10000
                    fin_ratio = (tender["lowest_revealed_price"] * 10000) // price
                    fin_part = (fin_ratio * tender["fin_weight_bps"]) // 10000
                    score = tech_part + fin_part

                b_acc["composite_score"] = score
                if score > highest_score:
                    highest_score = score

        if tender["evaluation_type"] == EvaluationType.LeastCost:
            if winning_bid["revealed_price"] != tender["lowest_revealed_price"]:
                raise ValueError("WinnerNotLowestPrice: Selected winner does not have the lowest price in Least-Cost mode")
        else:
            if winning_bid["composite_score"] < highest_score:
                raise ValueError(
                    f"WinnerNotHighestCompositeScore: Selected winner score ({winning_bid['composite_score']}) "
                    f"is less than highest score ({highest_score})"
                )

        composite_score = winning_bid["composite_score"]
        tender["highest_composite_score"] = composite_score
        tender["winning_bidder"] = winning_bidder_pubkey
        tender["status"] = TenderStatus.Awarded

        self.save_state()
        return tender

    # Backwards compatibility wrappers
    def commit_bid(self, tender_pda: str, bidder_pubkey: str, commitment_hash: str) -> dict:
        return self.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder_pubkey,
            admin_dossier_hash="00" * 32,
            tech_commitment_hash=commitment_hash,
            fin_commitment_hash=commitment_hash
        )

    def lock_tender(self, tender_pda: str) -> dict:
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]
        if tender["status"] != TenderStatus.ACTIVE and tender["status"] != TenderStatus.SubmissionsOpen:
            raise ValueError("TenderAlreadyLocked")
        if self.current_slot <= tender["submission_deadline_slot"]:
            raise ValueError(
                f"SubmissionDeadlineNotReached: Current slot {self.current_slot} <= submission deadline slot {tender['submission_deadline_slot']}"
            )
        tender["status"] = TenderStatus.LOCKED
        self.save_state()
        return tender

    def reveal_bid(self, tender_pda: str, bidder_pubkey: str, salt_hex: str, ciphertext_hash_hex: str, bid_amount: int) -> dict:
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["status"] not in [TenderStatus.LOCKED, "Locked", "TechnicalEvaluation", "FinancialEvaluation"]:
            raise ValueError("TenderNotLocked: Tender must be locked before reveals can take place")

        if self.current_slot > tender["fin_reveal_deadline_slot"]:
            raise ValueError(
                f"RevealWindowExpired: Current slot {self.current_slot} > reveal deadline slot {tender['fin_reveal_deadline_slot']}"
            )

        bid_pda = self.derive_bid_pda(tender_pda, bidder_pubkey)
        if bid_pda not in self.commitments:
            raise ValueError("BidNotFound")

        bid = self.commitments[bid_pda]
        if bid["is_revealed"]:
            raise ValueError("BidAlreadyRevealed")

        expected_hash = compute_commitment_hash(
            tender_pubkey_hex=tender_pda,
            bidder_pubkey_hex=bidder_pubkey,
            salt_hex=salt_hex,
            ciphertext_hash_hex=ciphertext_hash_hex,
            bid_amount=bid_amount
        )

        if expected_hash != bid.get("commitment_hash") and expected_hash != bid.get("tech_commitment_hash"):
            raise ValueError(
                f"InvalidRevealHash: Recomputed hash ({expected_hash}) != on-chain commitment ({bid.get('commitment_hash')})"
            )

        bid["is_revealed"] = True
        bid["is_tech_revealed"] = True
        bid["is_fin_revealed"] = True
        bid["is_tech_qualified"] = True
        bid["revealed_at_slot"] = self.current_slot
        bid["revealed_amount"] = bid_amount
        bid["revealed_price"] = bid_amount
        bid["escrowed_deposit"] = 0

        tender["total_revealed"] += 1
        tender["total_fin_revealed"] += 1
        tender["total_tech_qualified"] += 1

        if tender.get("lowest_bidder") is None or bid_amount < tender.get("lowest_revealed_amount", float('inf')):
            tender["lowest_revealed_amount"] = bid_amount
            tender["lowest_revealed_price"] = bid_amount
            tender["lowest_bidder"] = bidder_pubkey

        self.save_state()
        return bid

    def record_award(self, tender_pda: str, authority_pubkey: str, winning_bidder_pubkey: str) -> dict:
        if tender_pda not in self.tenders:
            raise ValueError("TenderNotFound")
        tender = self.tenders[tender_pda]

        if tender["authority"] != authority_pubkey:
            raise ValueError("Unauthorized: Only authority can record award")

        if tender["status"] not in [TenderStatus.LOCKED, "Locked", "TechnicalEvaluation", "FinancialEvaluation"]:
            raise ValueError("TenderNotLocked: Must be in Locked state to award")

        # Anti-Lockout Gate:
        if not (self.current_slot > tender["fin_reveal_deadline_slot"] or tender["total_revealed"] == tender["total_committed"]):
            raise ValueError(
                f"RevealWindowActive: Reveal window is still open (slot {self.current_slot} <= {tender['fin_reveal_deadline_slot']}) "
                f"and unrevealed bids remain ({tender['total_revealed']}/{tender['total_committed']}). Early award is prohibited."
            )

        winner_bid_pda = self.derive_bid_pda(tender_pda, winning_bidder_pubkey)
        if winner_bid_pda not in self.commitments:
            raise ValueError("WinningBidNotFound")

        winning_bid = self.commitments[winner_bid_pda]
        if not winning_bid["is_revealed"]:
            raise ValueError("WinnerNotRevealed: Cannot award to an unrevealed bid")

        if tender.get("lowest_bidder") and winning_bidder_pubkey != tender["lowest_bidder"]:
            raise ValueError(
                f"WinnerNotLowestBid: Selected winner ({winning_bidder_pubkey}) is not the lowest compliant revealed bidder ({tender['lowest_bidder']})"
            )

        tender["winning_bidder"] = winning_bidder_pubkey
        tender["status"] = TenderStatus.AWARDED
        self.save_state()
        return tender
