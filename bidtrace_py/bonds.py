"""
BidTrace Multi-Jurisdiction Hybrid Bond Engine
==============================================
Provides institutional bond issuance, verification, and canonical hashing for:
1. Solana Escrow (native lamports)
2. TradFi Surety-as-a-Service (MGA Model with General Indemnity Agreement)
3. Digital Bank Guarantee / SWIFT MT760 Attestation
4. World Bank / UN Standard Bid-Securing Declaration (BSD)
"""

import os
import uuid
import secrets
from enum import IntEnum
from typing import Dict, Any, Optional, List
from .ocds import get_iso_now, hash_canonical_json


class BondMode(IntEnum):
    SOLANA_ESCROW = 0
    SURETY_SERVICE = 1
    BANK_GUARANTEE = 2
    BID_SECURING_DECLARATION = 3


# In-memory registry of issued bonds and attestations
_BOND_REGISTRY: Dict[str, Dict[str, Any]] = {}


def issue_surety_policy(
    bidder_id: str,
    bidder_name: str,
    tender_id: str,
    penal_sum_usd: float,
    officer_name: str,
    surety_mga_name: str = "BidTrace MGA Global Surety Syndicate (Munich Re / Travelers Partner)",
    flat_fee_fiat: float = 250.00
) -> Dict[str, Any]:
    """
    Issues a digital Surety-as-a-Service Bid Bond Policy (Mode 1).
    Contractor pays a flat fiat fee (e.g. $250 via card/invoice) and executes
    a binding General Indemnity Agreement (GIA).
    """
    policy_id = f"SURETY-POL-2026-{secrets.token_hex(4).upper()}"
    gia_id = f"GIA-DOC-{secrets.token_hex(4).upper()}"
    
    # 1. Compile General Indemnity Agreement (GIA)
    gia_document = {
        "giaId": gia_id,
        "tenderId": tender_id,
        "indemnitor": {
            "bidderId": bidder_id,
            "companyName": bidder_name,
            "corporateOfficer": officer_name
        },
        "surety": surety_mga_name,
        "penalSumUsd": float(penal_sum_usd),
        "covenants": [
            "Indemnitor unconditionally agrees to hold harmless and indemnify the Surety against 100% of losses, damages, expenses, and legal fees incurred under this bond.",
            "Indemnitor warrants that withdrawal of bid or refusal to execute final procurement contract constitutes immediate breach.",
            "Surety reserves the right to pursue full corporate and personal asset recovery in the event of default payout."
        ],
        "executedAt": get_iso_now()
    }
    gia_hash = hash_canonical_json(gia_document)

    # 2. Compile Official Digital Surety Policy
    policy = {
        "policyId": policy_id,
        "bondMode": int(BondMode.SURETY_SERVICE),
        "modeName": "SuretyService",
        "tenderId": tender_id,
        "bidderId": bidder_id,
        "bidderName": bidder_name,
        "suretyIssuer": surety_mga_name,
        "penalSumUsd": float(penal_sum_usd),
        "fiatPremiumUsd": float(flat_fee_fiat),
        "paymentStatus": "SETTLED_FIAT_INVOICE",
        "status": "ISSUED_ACTIVE",
        "giaId": gia_id,
        "giaCanonicalHash": gia_hash,
        "giaDocument": gia_document,
        "issuedAt": get_iso_now(),
        "canonicalHash": ""
    }

    # 3. Canonical hash of the complete policy
    policy_copy = dict(policy)
    policy_copy["canonicalHash"] = ""
    policy_hash = hash_canonical_json(policy_copy)
    policy["canonicalHash"] = policy_hash

    # Save in registry
    _BOND_REGISTRY[policy_id] = policy
    return policy


def issue_bank_guarantee_attestation(
    bidder_id: str,
    bidder_name: str,
    tender_id: str,
    bank_name: str = "JPMorgan Chase Bank, N.A.",
    swift_bic: str = "CHASUS33",
    guarantee_ref: Optional[str] = None,
    amount_usd: float = 190000.0,
    beneficiary_entity: str = "Procuring Entity",
    expiry_date_iso: str = "2026-12-31T23:59:59Z"
) -> Dict[str, Any]:
    """
    Issues a Digital Bank Guarantee / SWIFT MT760 Attestation (Mode 2).
    """
    attestation_id = f"BG-ATT-{secrets.token_hex(4).upper()}"
    if not guarantee_ref:
        guarantee_ref = f"BG-MT760-2026-{secrets.token_hex(4).upper()}"
    
    mt760_payload = {
        "swiftMessageType": "MT760",
        "attestationId": attestation_id,
        "guaranteeReference": guarantee_ref,
        "issuingBank": bank_name,
        "swiftBic": swift_bic,
        "applicant": {
            "bidderId": bidder_id,
            "companyName": bidder_name
        },
        "beneficiary": beneficiary_entity,
        "tenderId": tender_id,
        "guaranteeAmountUsd": float(amount_usd),
        "expiryDate": expiry_date_iso,
        "applicableRules": "URDG 758 (Uniform Rules for Demand Guarantees)",
        "issuedAt": get_iso_now()
    }
    mt760_hash = hash_canonical_json(mt760_payload)

    guarantee = {
        "attestationId": attestation_id,
        "bondMode": int(BondMode.BANK_GUARANTEE),
        "modeName": "BankGuaranteeAttestation",
        "tenderId": tender_id,
        "bidderId": bidder_id,
        "bidderName": bidder_name,
        "bankName": bank_name,
        "swiftBic": swift_bic,
        "guaranteeRef": guarantee_ref,
        "amountUsd": float(amount_usd),
        "status": "ATTESTED_ACTIVE",
        "mt760Hash": mt760_hash,
        "mt760Payload": mt760_payload,
        "issuedAt": get_iso_now(),
        "canonicalHash": ""
    }

    g_copy = dict(guarantee)
    g_copy["canonicalHash"] = ""
    guarantee["canonicalHash"] = hash_canonical_json(g_copy)

    _BOND_REGISTRY[attestation_id] = guarantee
    return guarantee


def sign_bid_securing_declaration(
    bidder_id: str,
    bidder_name: str,
    tender_id: str,
    procuring_entity: str = "Procuring Entity",
    signatory_name: str = "Authorized Corporate Officer",
    signatory_title: str = "Managing Director",
    sanction_period_months: int = 36
) -> Dict[str, Any]:
    """
    Signs a World Bank / UN Standard Bid-Securing Declaration (Mode 3).
    Bidder legally commits to immediate global 3-year procurement suspension
    if they default or withdraw their bid.
    """
    bsd_id = f"BSD-DECL-{secrets.token_hex(4).upper()}"

    declaration_text = (
        f"We, the undersigned {bidder_name}, hereby irrevocably declare to {procuring_entity} that "
        f"in consideration of submitting our bid for {tender_id}, if we withdraw or modify our bid "
        f"during the period of validity, or if awarded the contract fail to execute the formal contract "
        f"or furnish the required performance security, we will automatically be disqualified and "
        f"suspended from participating in all public procurement for a period of {sanction_period_months} months."
    )

    bsd_document = {
        "declarationId": bsd_id,
        "bondMode": int(BondMode.BID_SECURING_DECLARATION),
        "modeName": "BidSecuringDeclaration",
        "tenderId": tender_id,
        "procuringEntity": procuring_entity,
        "bidderId": bidder_id,
        "bidderName": bidder_name,
        "signatory": {
            "name": signatory_name,
            "title": signatory_title
        },
        "sanctionPeriodMonths": sanction_period_months,
        "legalDeclarationText": declaration_text,
        "governingStandard": "World Bank / UNCITRAL Standard Procurement Regulations",
        "status": "EXECUTED_ACTIVE",
        "executedAt": get_iso_now(),
        "canonicalHash": ""
    }

    b_copy = dict(bsd_document)
    b_copy["canonicalHash"] = ""
    bsd_hash = hash_canonical_json(b_copy)
    bsd_document["canonicalHash"] = bsd_hash

    _BOND_REGISTRY[bsd_id] = bsd_document
    return bsd_document


def create_solana_escrow_record(
    bidder_id: str,
    tender_id: str,
    lamports: int
) -> Dict[str, Any]:
    """
    Creates record for Solana Escrow bond (Mode 0).
    """
    escrow_id = f"ESCROW-{secrets.token_hex(4).upper()}"
    escrow = {
        "escrowId": escrow_id,
        "bondMode": int(BondMode.SOLANA_ESCROW),
        "modeName": "SolanaEscrow",
        "tenderId": tender_id,
        "bidderId": bidder_id,
        "lamports": lamports,
        "status": "ESCROWED",
        "issuedAt": get_iso_now()
    }
    _BOND_REGISTRY[escrow_id] = escrow
    return escrow


def get_bond_record(bond_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an issued bond record from registry."""
    return _BOND_REGISTRY.get(bond_id)


def list_all_bonds() -> List[Dict[str, Any]]:
    """Returns all registered bonds."""
    return list(_BOND_REGISTRY.values())
