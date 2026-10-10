"""
BidTrace B2B/B2G Gas Sponsorship Relayer Gateway
================================================
Coordinates gas-sponsored Solana transactions, Two-Envelope cryptosystems,
hybrid bond attachments, and OCDS 1.1 audit releases.
"""

import os
import json
import secrets
from typing import Dict, Any, List, Optional
from .crypto import (
    generate_keypair,
    to_32bytes,
    b58encode,
    compute_tech_commitment,
    compute_fin_commitment,
    compute_grade_commitment
)
from .ledger import BidTraceLedger, TenderStatus, TenderMode, EvaluationType, BondMode
from .bonds import issue_surety_policy, issue_bank_guarantee_attestation, sign_bid_securing_declaration
from .ocds import (
    build_ocid,
    create_tender_notice_release,
    create_evaluation_release,
    create_award_release,
    hash_canonical_json,
    get_iso_now
)


class BidTraceRelayerGateway:
    """
    Central protocol relayer serving the Web Portals and Enterprise APIs.
    """
    def __init__(self, state_file: Optional[str] = None):
        self.ledger = BidTraceLedger(state_file)
        self.fee_payer_wallet = "GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU"
        self.program_id = "x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ"
        self.active_tender_pda: Optional[str] = None
        self.active_ocid: Optional[str] = None
        
        # OCDS 1.1 releases store for auditor verification
        self.ocds_releases: Dict[str, Dict[str, Any]] = {}
        # Bidder receipts store
        self.bidder_receipts: Dict[str, Dict[str, Any]] = {}

    def create_tender(
        self,
        authority_pubkey: str,
        tender_id: str,
        title: str,
        description: str,
        buyer_name: str,
        currency: str = "USD",
        estimated_amount: float = 3800000.0,
        submission_deadline_iso: Optional[str] = None,
        evaluation_type: str = "QCBS",
        tech_weight: float = 0.70,
        fin_weight: float = 0.30,
        min_tech_score: float = 75.0,
        bond_amount: float = 190000.0,
        bond_mode_str: str = "SuretyService",
        authorized_bidders_root: Optional[str] = None,
        evaluators: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Creates tender:
        1. Compiles OCDS 1.1 Tender Notice Release.
        2. Computes RFC 8785 canonical hash.
        3. Initializes Tender PDA on Solana state machine.
        4. Initializes Committee PDA with certified evaluators.
        """
        if not submission_deadline_iso:
            submission_deadline_iso = "2026-11-15T23:59:59Z"

        ocid = build_ocid("bidtrace-intl", tender_id)
        self.active_ocid = ocid
        tender_pda = self.ledger.derive_tender_pda(authority_pubkey, tender_id)
        self.active_tender_pda = tender_pda

        # 1. Compile OCDS 1.1 Tender Notice Release
        notice_release = create_tender_notice_release(
            ocid=ocid,
            tender_id=tender_id,
            title=title,
            description=description,
            buyer_id=authority_pubkey,
            buyer_name=buyer_name,
            currency=currency,
            estimated_amount=estimated_amount,
            submission_deadline_iso=submission_deadline_iso,
            evaluation_type=evaluation_type,
            tech_weight=tech_weight,
            fin_weight=fin_weight,
            min_tech_score=min_tech_score,
            bond_amount=bond_amount,
            bond_mode=bond_mode_str,
            authorized_bidders_root=authorized_bidders_root,
            solana_program_id=self.program_id,
            solana_tender_pda=tender_pda,
            submission_deadline_slot=self.ledger.current_slot + 50,
            init_tx_signature=f"tx_init_{secrets.token_hex(16)}"
        )
        ocds_notice_hash = notice_release["bidtrace"]["canonicalHash"]
        self.ocds_releases[notice_release["id"]] = notice_release

        # 2. Initialize Tender on Anchor Ledger
        tender_mode_val = (
            TenderMode.PreQualifiedWhitelist if authorized_bidders_root and authorized_bidders_root != "00" * 32
            else TenderMode.PostQualifiedOpen
        )
        eval_type_val = EvaluationType.QCBS if evaluation_type == "QCBS" else EvaluationType.LeastCost

        tender_acc = self.ledger.initialize_tender(
            authority_pubkey=authority_pubkey,
            tender_id=tender_id,
            ocds_notice_hash=ocds_notice_hash,
            tender_mode=tender_mode_val,
            evaluation_type=eval_type_val,
            authorized_bidders_root=authorized_bidders_root or ("00" * 32),
            min_tech_score_bps=int(min_tech_score * 100),
            tech_weight_bps=int(tech_weight * 10000),
            fin_weight_bps=int(fin_weight * 10000),
            deadline_slots=50
        )

        # 3. Setup default certified evaluators committee if provided
        committee_acc = None
        if evaluators:
            committee_acc = self.ledger.initialize_committee(
                tender_pda=tender_pda,
                authority_pubkey=authority_pubkey,
                evaluators=evaluators,
                max_variance_bps=2000
            )

        return {
            "tender": tender_acc,
            "committee": committee_acc,
            "ocds_release": notice_release,
            "ocds_notice_hash": ocds_notice_hash,
            "fee_payer": self.fee_payer_wallet
        }

    def commit_dual_bid(
        self,
        tender_pda: str,
        bidder_pubkey: str,
        bidder_name: str,
        admin_dossier_hash: str,
        salt_tech: str,
        proposal_hash: str,
        salt_fin: str,
        price: int,
        boq_hash: str,
        bond_mode: int,
        bond_amount: int,
        bond_record: Optional[Dict[str, Any]] = None,
        whitelist_proof: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Calculates domain-separated commitments, commits onto Anchor ledger,
        and generates a portable, air-gapped bidder_receipt.json.
        """
        comm_tech = compute_tech_commitment(tender_pda, bidder_pubkey, salt_tech, proposal_hash).hex()
        comm_fin = compute_fin_commitment(tender_pda, bidder_pubkey, salt_fin, price, boq_hash).hex()

        bid_acc = self.ledger.commit_dual_bid(
            tender_pda=tender_pda,
            bidder_pubkey=bidder_pubkey,
            admin_dossier_hash=admin_dossier_hash,
            tech_commitment_hash=comm_tech,
            fin_commitment_hash=comm_fin,
            bond_mode=bond_mode,
            bond_amount=bond_amount,
            whitelist_proof=whitelist_proof
        )

        # Generate Portable Air-Gapped Receipt
        receipt = {
            "version": "3.0.0",
            "receiptId": f"RECEIPT-{secrets.token_hex(6).upper()}",
            "tenderPda": tender_pda,
            "bidderPubkey": bidder_pubkey,
            "bidderName": bidder_name,
            "committedSlot": bid_acc["committed_at_slot"],
            "feePayerSponsor": self.fee_payer_wallet,
            "txSignature": f"tx_commit_{secrets.token_hex(16)}",
            "dualCommitments": {
                "adminDossierHash": admin_dossier_hash,
                "techCommitmentHash": comm_tech,
                "finCommitmentHash": comm_fin
            },
            "unsealingPreimages": {
                "saltTech": salt_tech,
                "proposalHash": proposal_hash,
                "saltFin": salt_fin,
                "price": price,
                "boqHash": boq_hash
            },
            "bond": bond_record or {
                "mode": bond_mode,
                "amount": bond_amount,
                "status": "ATTACHED"
            },
            "whitelistProof": whitelist_proof or [],
            "issuedAt": get_iso_now()
        }

        self.bidder_receipts[bidder_pubkey] = receipt
        return {
            "bid": bid_acc,
            "receipt": receipt
        }

    def finalize_technical_evaluation(
        self,
        tender_pda: str,
        authority_pubkey: str,
        bidder_pubkeys: List[str]
    ) -> Dict[str, Any]:
        """
        Finalizes technical scores across all bidders, applies Olympic trimmed mean,
        prunes rogue outliers, and compiles OCDS 1.1 Technical Evaluation Release.
        """
        tender = self.ledger.tenders[tender_pda]
        comm_pda = self.ledger.derive_committee_pda(tender_pda)
        comm = self.ledger.committees.get(comm_pda, {"evaluators": []})

        bids_eval_summary = []
        for bp in bidder_pubkeys:
            res = self.ledger.finalize_technical_scores(tender_pda, authority_pubkey, bp)
            bids_eval_summary.append({
                "bidderId": bp,
                "isTechQualified": res["is_tech_qualified"],
                "technicalScoreBps": res["final_score_bps"],
                "outliersPruned": res["outliers_pruned"]
            })

        # Compile OCDS 1.1 Evaluation Release
        notice_rel = next((r for r in self.ocds_releases.values() if "tender" in r.get("tag", [])), None)
        if notice_rel:
            eval_panel = [{"evaluatorId": ev, "name": f"Certified Evaluator {ev[:8]}"} for ev in comm.get("evaluators", [])]
            eval_release = create_evaluation_release(
                parent_release=notice_rel,
                evaluator_panel=eval_panel,
                bids_evaluation=bids_eval_summary,
                tech_lock_slot=self.ledger.current_slot,
                lock_tx_signature=f"tx_lock_{secrets.token_hex(16)}"
            )
            self.ocds_releases[eval_release["id"]] = eval_release
        else:
            eval_release = None

        return {
            "evaluations": bids_eval_summary,
            "ocds_release": eval_release,
            "total_qualified": tender["total_tech_qualified"]
        }

    def record_award(
        self,
        tender_pda: str,
        authority_pubkey: str,
        winning_bidder_pubkey: str,
        winner_name: str
    ) -> Dict[str, Any]:
        """
        Executes programmatic award calculation and compiles OCDS 1.1 Award Release.
        """
        tender = self.ledger.record_award_qcbs(
            tender_pda=tender_pda,
            authority_pubkey=authority_pubkey,
            winning_bidder_pubkey=winning_bidder_pubkey
        )
        winning_bid = self.ledger.commitments[self.ledger.derive_bid_pda(tender_pda, winning_bidder_pubkey)]

        # Compile OCDS 1.1 Award Release
        notice_rel = next((r for r in self.ocds_releases.values() if "tender" in r.get("tag", [])), None)
        award_release = None
        if notice_rel:
            award_release = create_award_release(
                parent_release=notice_rel,
                winner_bidder_id=winning_bidder_pubkey,
                winner_name=winner_name,
                awarded_amount=float(winning_bid["revealed_price"]),
                currency=notice_rel["tender"]["value"]["currency"],
                composite_score=float(winning_bid["composite_score"]) / 100.0,
                lowest_revealed_price=float(tender["lowest_revealed_price"]),
                award_slot=self.ledger.current_slot,
                award_tx_signature=f"tx_award_{secrets.token_hex(16)}"
            )
            self.ocds_releases[award_release["id"]] = award_release

        return {
            "tender": tender,
            "winning_bid": winning_bid,
            "ocds_release": award_release
        }

    def refund_disqualified_bond(
        self,
        tender_pda: str,
        bidder_pubkey: str
    ) -> Dict[str, Any]:
        """
        Sponsors transaction to refund escrowed bond to a technically disqualified bidder,
        strictly maintaining Commercial Secrecy (Envelope B remains sealed forever).
        """
        bid = self.ledger.refund_disqualified_bond(tender_pda, bidder_pubkey)
        return {
            "bid": bid,
            "tx_signature": f"tx_refund_{secrets.token_hex(16)}",
            "fee_payer": self.fee_payer_wallet
        }

