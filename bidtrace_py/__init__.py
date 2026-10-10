"""
BidTrace 3.0: The Incorruptible Cryptographic Global Standard for Public & Enterprise Procurement
"""
__version__ = "3.0.0"

from .crypto import (
    b58encode,
    b58decode,
    to_32bytes,
    generate_keypair,
    encrypt_payload,
    decrypt_payload,
    compute_tech_commitment,
    compute_fin_commitment,
    compute_grade_commitment
)
from .ocds import (
    canonicalize_jcs,
    hash_canonical_json,
    build_ocid,
    create_tender_notice_release,
    create_evaluation_release,
    create_award_release
)
from .merkle import MerkleTree, verify_merkle_proof, compute_leaf
from .bonds import (
    BondMode,
    issue_surety_policy,
    issue_bank_guarantee_attestation,
    sign_bid_securing_declaration,
    create_solana_escrow_record,
    get_bond_record,
    list_all_bonds
)
from .ledger import (
    BidTraceLedger,
    TenderStatus,
    TenderMode,
    EvaluationType,
    AdminStatus
)
from .relayer import BidTraceRelayerGateway
from .verifier import (
    AirGappedTribunalVerifier,
    export_tribunal_dossier,
    verify_proof_bundle
)

