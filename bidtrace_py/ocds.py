"""
BidTrace OCDS 1.1 & RFC 8785 Canonical Hashing Engine
======================================================
Provides standard Open Contracting Data Standard (OCDS 1.1) release builders,
canonical JSON serialization according to RFC 8785 (JSON Canonicalization Scheme - JCS),
and deterministic SHA-256 cryptographic hash anchors for the Solana Anchor runtime.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

# ==============================================================================
# RFC 8785: JSON CANONICALIZATION SCHEME (JCS)
# ==============================================================================

def _utf16_sort_key(s: str) -> bytes:
    """
    Computes the sorting key according to RFC 8785 Section 3.2.3:
    Keys MUST be sorted by their UTF-16 code units (lexicographical byte order
    of their big-endian UTF-16 representation).
    """
    return s.encode('utf-16-be')


def canonicalize_jcs(data: Any) -> bytes:
    """
    Canonicalizes arbitrary JSON-serializable Python data structures into
    deterministic UTF-8 bytes strictly adhering to RFC 8785 (JCS).
    
    Rules enforced:
    1. Object keys sorted lexicographically by UTF-16 code units.
    2. No whitespace between tokens (no spaces after ',' or ':').
    3. Proper string escaping (control characters U+0000 - U+001F, quotes, backslashes).
    4. IEEE 754 number representation with no redundant exponents or trailing zeroes.
    5. Pure UTF-8 output without unescaped ASCII wrappers.
    """
    if data is None:
        return b"null"
    elif isinstance(data, bool):
        return b"true" if data else b"false"
    elif isinstance(data, (int, float)):
        if isinstance(data, float):
            if data != data or data == float('inf') or data == float('-inf'):
                raise ValueError("RFC 8785 does not permit NaN or Infinity")
            # Format float cleanly matching ECMAScript standard
            if data.is_integer():
                return str(int(data)).encode('utf-8')
            s = f"{data:.16g}"
            return s.encode('utf-8')
        return str(data).encode('utf-8')
    elif isinstance(data, str):
        # Escape control characters, quotes, and backslashes
        # json.dumps without ascii escaping formats unicode properly
        escaped = json.dumps(data, ensure_ascii=False)
        return escaped.encode('utf-8')
    elif isinstance(data, list):
        items = [canonicalize_jcs(item) for item in data]
        return b"[" + b",".join(items) + b"]"
    elif isinstance(data, dict):
        # Sort keys according to UTF-16 code unit ordering
        sorted_keys = sorted(data.keys(), key=_utf16_sort_key)
        items = []
        for k in sorted_keys:
            key_bytes = json.dumps(k, ensure_ascii=False).encode('utf-8')
            val_bytes = canonicalize_jcs(data[k])
            items.append(key_bytes + b":" + val_bytes)
        return b"{" + b",".join(items) + b"}"
    else:
        raise TypeError(f"Type {type(data)} is not JSON serializable according to RFC 8785")


def canonical_json_str(data: Any) -> str:
    """Returns canonical JSON as a UTF-8 string."""
    return canonicalize_jcs(data).decode('utf-8')


def hash_canonical_json(data: Any) -> str:
    """
    Computes the canonical SHA-256 hash (hex string) of an OCDS document
    using RFC 8785 canonical serialization.
    """
    canonical_bytes = canonicalize_jcs(data)
    return hashlib.sha256(canonical_bytes).hexdigest()


# ==============================================================================
# OCDS 1.1 RELEASE BUILDERS
# ==============================================================================

def get_iso_now() -> str:
    """Returns current UTC timestamp formatted as ISO 8601 with Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_ocid(publisher_prefix: str, tender_id: str) -> str:
    """Generates a globally unique Open Contracting Identifier (OCID)."""
    clean_prefix = publisher_prefix.strip().lower().replace(" ", "-")
    clean_tender = tender_id.strip().upper().replace(" ", "-")
    return f"ocds-{clean_prefix}-{clean_tender}"


def create_tender_notice_release(
    ocid: str,
    tender_id: str,
    title: str,
    description: str,
    buyer_id: str,
    buyer_name: str,
    currency: str,
    estimated_amount: float,
    submission_deadline_iso: str,
    evaluation_type: str = "QCBS",
    tech_weight: float = 0.70,
    fin_weight: float = 0.30,
    min_tech_score: float = 75.0,
    bond_amount: float = 0.0,
    bond_mode: str = "SuretyService",
    authorized_bidders_root: Optional[str] = None,
    solana_program_id: Optional[str] = None,
    solana_tender_pda: Optional[str] = None,
    submission_deadline_slot: Optional[int] = None,
    init_tx_signature: Optional[str] = None
) -> Dict[str, Any]:
    """
    Builds an official OCDS 1.1 Tender Notice Release (tag: ["tender"])
    complete with the BidTrace cryptographic extension.
    """
    release_id = f"REL-{tender_id}-01-TENDER-NOTICE"
    
    release: Dict[str, Any] = {
        "uri": f"https://api.bidtrace.io/ocds/releases/{release_id}",
        "version": "1.1",
        "tag": ["tender"],
        "ocid": ocid,
        "id": release_id,
        "date": get_iso_now(),
        "initiationType": "tender",
        "parties": [
            {
                "id": buyer_id,
                "name": buyer_name,
                "roles": ["buyer", "procuringEntity"]
            }
        ],
        "buyer": {
            "id": buyer_id,
            "name": buyer_name
        },
        "tender": {
            "id": tender_id,
            "title": title,
            "description": description,
            "status": "active",
            "procurementMethod": "selective" if authorized_bidders_root else "open",
            "awardCriteria": "ratedCriteria" if evaluation_type == "QCBS" else "lowestCost",
            "value": {
                "amount": float(estimated_amount),
                "currency": currency.upper()
            },
            "tenderPeriod": {
                "startDate": get_iso_now(),
                "endDate": submission_deadline_iso
            },
            "submissionMethod": ["electronicSubmission"],
            "criteria": [
                {
                    "id": "CRIT-TECH",
                    "title": "Technical Evaluation Weight",
                    "relatesTo": "tenderer",
                    "weight": tech_weight,
                    "minimumScore": min_tech_score
                },
                {
                    "id": "CRIT-FIN",
                    "title": "Financial Price Evaluation Weight",
                    "relatesTo": "tenderer",
                    "weight": fin_weight
                }
            ]
        },
        "bidtrace": {
            "version": "3.0.0",
            "solanaNetwork": "solana-devnet",
            "programId": solana_program_id or "x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ",
            "tenderPda": solana_tender_pda or "",
            "submissionDeadlineSlot": submission_deadline_slot or 0,
            "evaluationType": evaluation_type,
            "techWeightBps": int(tech_weight * 10000),
            "finWeightBps": int(fin_weight * 10000),
            "minTechScoreBps": int(min_tech_score * 100),
            "bondMode": bond_mode,
            "bondAmount": int(bond_amount),
            "authorizedBiddersRoot": authorized_bidders_root or "0000000000000000000000000000000000000000000000000000000000000000",
            "initTxSignature": init_tx_signature or "",
            "canonicalHash": ""
        }
    }
    
    # Calculate canonical hash of the release (excluding the hash field itself)
    payload_copy = dict(release)
    payload_copy["bidtrace"] = dict(release["bidtrace"])
    payload_copy["bidtrace"]["canonicalHash"] = ""
    canonical_hash = hash_canonical_json(payload_copy)
    release["bidtrace"]["canonicalHash"] = canonical_hash
    
    return release


def create_evaluation_release(
    parent_release: Dict[str, Any],
    evaluator_panel: List[Dict[str, str]],
    bids_evaluation: List[Dict[str, Any]],
    tech_lock_slot: int,
    lock_tx_signature: Optional[str] = None
) -> Dict[str, Any]:
    """
    Builds an OCDS 1.1 Technical Evaluation Release (tag: ["evaluation"]).
    Documents anonymized proposal scores, sub-criteria rubrics, and the on-chain trimmed mean.
    """
    tender_id = parent_release["tender"]["id"]
    ocid = parent_release["ocid"]
    release_id = f"REL-{tender_id}-02-TECH-EVALUATION"
    
    parties = list(parent_release.get("parties", []))
    for ev in evaluator_panel:
        parties.append({
            "id": ev["evaluatorId"],
            "name": ev.get("name", f"Certified Evaluator {ev['evaluatorId'][:8]}"),
            "roles": ["evaluator"]
        })

    release: Dict[str, Any] = {
        "uri": f"https://api.bidtrace.io/ocds/releases/{release_id}",
        "version": "1.1",
        "tag": ["evaluation"],
        "ocid": ocid,
        "id": release_id,
        "date": get_iso_now(),
        "initiationType": "tender",
        "parties": parties,
        "buyer": parent_release["buyer"],
        "tender": {
            "id": tender_id,
            "status": "active",
            "numberOfTenderers": len(bids_evaluation)
        },
        "bids": {
            "details": [
                {
                    "id": b["bidderId"],
                    "status": "qualified" if b["isTechQualified"] else "disqualified",
                    "technicalScore": b["technicalScoreBps"] / 100.0,
                    "isTechQualified": b["isTechQualified"],
                    "subScores": b.get("subScores", []),
                    "evaluatorGrades": b.get("evaluatorGrades", []),
                    "outliersPruned": b.get("outliersPruned", 0)
                }
                for b in bids_evaluation
            ]
        },
        "bidtrace": {
            "version": "3.0.0",
            "parentReleaseId": parent_release["id"],
            "techLockSlot": tech_lock_slot,
            "lockTxSignature": lock_tx_signature or "",
            "evaluationStatus": "TECHNICAL_SCORES_LOCKED",
            "canonicalHash": ""
        }
    }
    
    payload_copy = dict(release)
    payload_copy["bidtrace"] = dict(release["bidtrace"])
    payload_copy["bidtrace"]["canonicalHash"] = ""
    release["bidtrace"]["canonicalHash"] = hash_canonical_json(payload_copy)
    
    return release


def create_award_release(
    parent_release: Dict[str, Any],
    winner_bidder_id: str,
    winner_name: str,
    awarded_amount: float,
    currency: str,
    composite_score: float,
    lowest_revealed_price: float,
    award_slot: int,
    award_tx_signature: str
) -> Dict[str, Any]:
    """
    Builds the final OCDS 1.1 Award Release (tag: ["award", "contract"]).
    Records winning contractor, financial unsealing, QCBS final composite score,
    and the Solana transaction signature.
    """
    tender_id = parent_release["tender"]["id"]
    ocid = parent_release["ocid"]
    release_id = f"REL-{tender_id}-03-FINAL-AWARD"
    
    parties = list(parent_release.get("parties", []))
    parties.append({
        "id": winner_bidder_id,
        "name": winner_name,
        "roles": ["tenderer", "supplier"]
    })

    release: Dict[str, Any] = {
        "uri": f"https://api.bidtrace.io/ocds/releases/{release_id}",
        "version": "1.1",
        "tag": ["award", "contract"],
        "ocid": ocid,
        "id": release_id,
        "date": get_iso_now(),
        "initiationType": "tender",
        "parties": parties,
        "buyer": parent_release["buyer"],
        "tender": {
            "id": tender_id,
            "status": "complete"
        },
        "awards": [
            {
                "id": f"AWARD-{tender_id}-01",
                "title": f"Contract Awarded for {tender_id}",
                "status": "active",
                "date": get_iso_now(),
                "value": {
                    "amount": float(awarded_amount),
                    "currency": currency.upper()
                },
                "suppliers": [
                    {
                        "id": winner_bidder_id,
                        "name": winner_name
                    }
                ]
            }
        ],
        "bidtrace": {
            "version": "3.0.0",
            "parentReleaseId": parent_release["id"],
            "winningBidderId": winner_bidder_id,
            "winningBidderPubkey": winner_bidder_id,
            "winningAmount": awarded_amount,
            "lowestRevealedPrice": lowest_revealed_price,
            "compositeScore": composite_score,
            "awardSlot": award_slot,
            "awardTxSignature": award_tx_signature,
            "verificationStatus": "CRYPTOGRAPHICALLY_FINALIZED",
            "canonicalHash": ""
        }
    }
    
    payload_copy = dict(release)
    payload_copy["bidtrace"] = dict(release["bidtrace"])
    payload_copy["bidtrace"]["canonicalHash"] = ""
    release["bidtrace"]["canonicalHash"] = hash_canonical_json(payload_copy)
    
    return release


# ==============================================================================
# OCDS VALIDATION HELPER
# ==============================================================================

def validate_ocds_release(release: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates an OCDS 1.1 release structure against mandatory core requirements.
    Returns (is_valid, list_of_errors).
    """
    errors: List[str] = []
    
    required_top_level = ["uri", "version", "tag", "ocid", "id", "date", "initiationType", "parties", "buyer", "tender"]
    for field in required_top_level:
        if field not in release:
            errors.append(f"Missing mandatory top-level field: '{field}'")
            
    if release.get("version") != "1.1":
        errors.append(f"Invalid OCDS version: expected '1.1', got '{release.get('version')}'")
        
    if not isinstance(release.get("tag"), list) or len(release.get("tag", [])) == 0:
        errors.append("Mandatory field 'tag' must be a non-empty list of tags")
        
    if "bidtrace" not in release:
        errors.append("Missing mandatory 'bidtrace' cryptographic extension object")
    else:
        bt = release["bidtrace"]
        if not bt.get("canonicalHash"):
            errors.append("Missing 'bidtrace.canonicalHash' cryptographic anchor")
            
    return (len(errors) == 0, errors)
