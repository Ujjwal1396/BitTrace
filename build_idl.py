import json
import hashlib
import os

def discriminator(prefix: str, name: str) -> list:
    h = hashlib.sha256(f"{prefix}:{name}".encode("utf-8")).digest()[:8]
    return list(h)

def generate_idl():
    program_id = "x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ"

    idl = {
        "address": program_id,
        "metadata": {
            "name": "bidtrace",
            "version": "3.0.0",
            "spec": "0.1.0",
            "description": "BidTrace 3.0 - Incorruptible Cryptographic Global Standard for Procurement"
        },
        "instructions": [
            {
                "name": "initialize_tender",
                "discriminator": discriminator("global", "initialize_tender"),
                "accounts": [
                    {
                        "name": "tender",
                        "writable": True,
                        "pda": {
                            "seeds": [
                                {"kind": "const", "value": list(b"tender")},
                                {"kind": "account", "path": "authority"},
                                {"kind": "arg", "path": "tender_id"}
                            ]
                        }
                    },
                    {"name": "authority", "writable": True, "signer": True},
                    {"name": "system_program", "address": "11111111111111111111111111111111"}
                ],
                "args": [
                    {"name": "tender_id", "type": "string"},
                    {"name": "ocds_notice_hash", "type": {"array": ["u8", 32]}},
                    {"name": "tender_mode", "type": {"defined": {"name": "TenderMode"}}},
                    {"name": "evaluation_type", "type": {"defined": {"name": "EvaluationType"}}},
                    {"name": "submission_deadline_slot", "type": "u64"},
                    {"name": "admin_review_deadline_slot", "type": "u64"},
                    {"name": "tech_eval_deadline_slot", "type": "u64"},
                    {"name": "fin_reveal_deadline_slot", "type": "u64"},
                    {"name": "authorized_bidders_root", "type": {"array": ["u8", 32]}},
                    {"name": "min_tech_score_bps", "type": "u16"},
                    {"name": "tech_weight_bps", "type": "u16"},
                    {"name": "fin_weight_bps", "type": "u16"}
                ]
            },
            {
                "name": "initialize_committee",
                "discriminator": discriminator("global", "initialize_committee"),
                "accounts": [
                    {"name": "tender"},
                    {
                        "name": "committee",
                        "writable": True,
                        "pda": {
                            "seeds": [
                                {"kind": "const", "value": list(b"committee")},
                                {"kind": "account", "path": "tender"}
                            ]
                        }
                    },
                    {"name": "authority", "writable": True, "signer": True},
                    {"name": "system_program", "address": "11111111111111111111111111111111"}
                ],
                "args": [
                    {"name": "evaluators", "type": {"vec": "pubkey"}},
                    {"name": "max_variance_bps", "type": "u16"}
                ]
            },
            {
                "name": "commit_dual_bid",
                "discriminator": discriminator("global", "commit_dual_bid"),
                "accounts": [
                    {"name": "tender", "writable": True},
                    {
                        "name": "bid_commitment",
                        "writable": True,
                        "pda": {
                            "seeds": [
                                {"kind": "const", "value": list(b"bid")},
                                {"kind": "account", "path": "tender"},
                                {"kind": "account", "path": "bidder"}
                            ]
                        }
                    },
                    {"name": "bidder", "signer": True},
                    {"name": "fee_payer", "writable": True, "signer": True},
                    {"name": "system_program", "address": "11111111111111111111111111111111"}
                ],
                "args": [
                    {"name": "admin_dossier_hash", "type": {"array": ["u8", 32]}},
                    {"name": "tech_commitment_hash", "type": {"array": ["u8", 32]}},
                    {"name": "fin_commitment_hash", "type": {"array": ["u8", 32]}},
                    {"name": "bond_mode", "type": {"defined": {"name": "BondMode"}}},
                    {"name": "bond_amount", "type": "u64"},
                    {"name": "whitelist_proof", "type": {"option": {"vec": {"array": ["u8", 32]}}}}
                ]
            },
            {
                "name": "advance_tender_phase",
                "discriminator": discriminator("global", "advance_tender_phase"),
                "accounts": [
                    {"name": "tender", "writable": True},
                    {"name": "caller", "signer": True}
                ],
                "args": []
            },
            {
                "name": "reveal_technical_bid",
                "discriminator": discriminator("global", "reveal_technical_bid"),
                "accounts": [
                    {"name": "tender", "writable": True},
                    {"name": "bid_commitment", "writable": True},
                    {"name": "revealer", "signer": True}
                ],
                "args": [
                    {"name": "salt_tech", "type": {"array": ["u8", 32]}},
                    {"name": "proposal_hash", "type": {"array": ["u8", 32]}}
                ]
            },
            {
                "name": "commit_evaluator_grade",
                "discriminator": discriminator("global", "commit_evaluator_grade"),
                "accounts": [
                    {"name": "tender"},
                    {"name": "committee"},
                    {"name": "bid_commitment"},
                    {
                        "name": "evaluator_grade",
                        "writable": True,
                        "pda": {
                            "seeds": [
                                {"kind": "const", "value": list(b"grade")},
                                {"kind": "account", "path": "tender"},
                                {"kind": "account", "path": "evaluator"},
                                {"kind": "account", "path": "bidder"}
                            ]
                        }
                    },
                    {"name": "evaluator", "writable": True, "signer": True},
                    {"name": "bidder"},
                    {"name": "system_program", "address": "11111111111111111111111111111111"}
                ],
                "args": [
                    {"name": "commitment_hash", "type": {"array": ["u8", 32]}}
                ]
            },
            {
                "name": "reveal_evaluator_grade",
                "discriminator": discriminator("global", "reveal_evaluator_grade"),
                "accounts": [
                    {"name": "tender"},
                    {"name": "committee"},
                    {"name": "evaluator_grade", "writable": True},
                    {"name": "evaluator", "signer": True},
                    {"name": "bidder"}
                ],
                "args": [
                    {"name": "sub_scores", "type": {"array": ["u16", 5]}},
                    {"name": "salt", "type": {"array": ["u8", 32]}},
                    {"name": "justification_hash", "type": {"array": ["u8", 32]}}
                ]
            },
            {
                "name": "finalize_technical_scores",
                "discriminator": discriminator("global", "finalize_technical_scores"),
                "accounts": [
                    {"name": "tender", "writable": True},
                    {"name": "committee"},
                    {"name": "bid_commitment", "writable": True},
                    {"name": "authority", "signer": True}
                ],
                "args": []
            },
            {
                "name": "reveal_financial_envelope",
                "discriminator": discriminator("global", "reveal_financial_envelope"),
                "accounts": [
                    {"name": "tender", "writable": True},
                    {"name": "bid_commitment", "writable": True},
                    {"name": "revealer", "signer": True},
                    {"name": "bidder_recipient", "writable": True}
                ],
                "args": [
                    {"name": "salt_fin", "type": {"array": ["u8", 32]}},
                    {"name": "price", "type": "u64"},
                    {"name": "boq_hash", "type": {"array": ["u8", 32]}}
                ]
            },
            {
                "name": "record_award_qcbs",
                "discriminator": discriminator("global", "record_award_qcbs"),
                "accounts": [
                    {"name": "tender", "writable": True},
                    {"name": "winning_bid", "writable": True},
                    {"name": "authority", "signer": True}
                ],
                "args": [
                    {"name": "rationale_hash", "type": {"array": ["u8", 32]}}
                ]
            },
            {
                "name": "refund_disqualified_bond",
                "discriminator": discriminator("global", "refund_disqualified_bond"),
                "accounts": [
                    {"name": "tender"},
                    {"name": "bid_commitment", "writable": True},
                    {"name": "bidder_recipient", "writable": True},
                    {"name": "caller", "signer": True}
                ],
                "args": []
            }
        ],
        "accounts": [
            {
                "name": "Tender",
                "discriminator": discriminator("account", "Tender")
            },
            {
                "name": "DualBidCommitment",
                "discriminator": discriminator("account", "DualBidCommitment")
            },
            {
                "name": "TenderCommittee",
                "discriminator": discriminator("account", "TenderCommittee")
            },
            {
                "name": "EvaluatorGrade",
                "discriminator": discriminator("account", "EvaluatorGrade")
            }
        ],
        "types": [
            {
                "name": "Tender",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "authority", "type": "pubkey"},
                        {"name": "tender_id", "type": "string"},
                        {"name": "ocds_notice_hash", "type": {"array": ["u8", 32]}},
                        {"name": "tender_mode", "type": {"defined": {"name": "TenderMode"}}},
                        {"name": "evaluation_type", "type": {"defined": {"name": "EvaluationType"}}},
                        {"name": "status", "type": {"defined": {"name": "TenderStatus"}}},
                        {"name": "submission_deadline_slot", "type": "u64"},
                        {"name": "admin_review_deadline_slot", "type": "u64"},
                        {"name": "tech_eval_deadline_slot", "type": "u64"},
                        {"name": "fin_reveal_deadline_slot", "type": "u64"},
                        {"name": "authorized_bidders_root", "type": {"array": ["u8", 32]}},
                        {"name": "min_tech_score_bps", "type": "u16"},
                        {"name": "tech_weight_bps", "type": "u16"},
                        {"name": "fin_weight_bps", "type": "u16"},
                        {"name": "total_committed", "type": "u32"},
                        {"name": "total_admin_passed", "type": "u32"},
                        {"name": "total_tech_qualified", "type": "u32"},
                        {"name": "total_fin_revealed", "type": "u32"},
                        {"name": "lowest_revealed_price", "type": "u64"},
                        {"name": "highest_composite_score", "type": "u64"},
                        {"name": "winning_bidder", "type": {"option": "pubkey"}},
                        {"name": "bump", "type": "u8"}
                    ]
                }
            },
            {
                "name": "DualBidCommitment",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "tender", "type": "pubkey"},
                        {"name": "bidder", "type": "pubkey"},
                        {"name": "committed_at_slot", "type": "u64"},
                        {"name": "admin_dossier_hash", "type": {"array": ["u8", 32]}},
                        {"name": "tech_commitment_hash", "type": {"array": ["u8", 32]}},
                        {"name": "fin_commitment_hash", "type": {"array": ["u8", 32]}},
                        {"name": "admin_status", "type": {"defined": {"name": "AdminStatus"}}},
                        {"name": "admin_rejection_code", "type": "u16"},
                        {"name": "is_tech_revealed", "type": "bool"},
                        {"name": "technical_score_bps", "type": "u16"},
                        {"name": "is_tech_qualified", "type": "bool"},
                        {"name": "is_fin_revealed", "type": "bool"},
                        {"name": "revealed_price", "type": "u64"},
                        {"name": "composite_score", "type": "u64"},
                        {"name": "bond_mode", "type": {"defined": {"name": "BondMode"}}},
                        {"name": "bond_amount", "type": "u64"},
                        {"name": "is_bond_settled", "type": "bool"},
                        {"name": "bump", "type": "u8"}
                    ]
                }
            },
            {
                "name": "TenderCommittee",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "tender", "type": "pubkey"},
                        {"name": "evaluators", "type": {"vec": "pubkey"}},
                        {"name": "max_variance_bps", "type": "u16"},
                        {"name": "is_locked", "type": "bool"},
                        {"name": "bump", "type": "u8"}
                    ]
                }
            },
            {
                "name": "EvaluatorGrade",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "tender", "type": "pubkey"},
                        {"name": "evaluator", "type": "pubkey"},
                        {"name": "bidder", "type": "pubkey"},
                        {"name": "commitment_hash", "type": {"array": ["u8", 32]}},
                        {"name": "committed_at_slot", "type": "u64"},
                        {"name": "is_revealed", "type": "bool"},
                        {"name": "sub_scores", "type": {"array": ["u16", 5]}},
                        {"name": "total_score_bps", "type": "u16"},
                        {"name": "justification_hash", "type": {"array": ["u8", 32]}},
                        {"name": "is_outlier_flagged", "type": "bool"},
                        {"name": "bump", "type": "u8"}
                    ]
                }
            },
            {
                "name": "TenderStatus",
                "type": {
                    "kind": "enum",
                    "variants": [
                        {"name": "SubmissionsOpen"},
                        {"name": "AdministrativeReview"},
                        {"name": "TechnicalEvaluation"},
                        {"name": "FinancialEvaluation"},
                        {"name": "Awarded"},
                        {"name": "Cancelled"}
                    ]
                }
            },
            {
                "name": "TenderMode",
                "type": {
                    "kind": "enum",
                    "variants": [
                        {"name": "PreQualifiedWhitelist"},
                        {"name": "PostQualifiedOpen"}
                    ]
                }
            },
            {
                "name": "EvaluationType",
                "type": {
                    "kind": "enum",
                    "variants": [
                        {"name": "LeastCost"},
                        {"name": "QCBS"}
                    ]
                }
            },
            {
                "name": "AdminStatus",
                "type": {
                    "kind": "enum",
                    "variants": [
                        {"name": "Pending"},
                        {"name": "Passed"},
                        {"name": "Failed"}
                    ]
                }
            },
            {
                "name": "BondMode",
                "type": {
                    "kind": "enum",
                    "variants": [
                        {"name": "SolanaEscrow"},
                        {"name": "SuretyService"},
                        {"name": "BankGuaranteeAttestation"},
                        {"name": "BidSecuringDeclaration"}
                    ]
                }
            }
        ],
        "errors": [
            {"code": 6000, "name": "InvalidSubmissionDeadline", "msg": "Submission deadline slot must be in the future."},
            {"code": 6001, "name": "InvalidDeadlineSequence", "msg": "Deadline slots must be strictly sequential (submission <= admin <= tech <= fin)."},
            {"code": 6002, "name": "SubmissionDeadlineExceeded", "msg": "Submission deadline has passed. Commitments are frozen."},
            {"code": 6003, "name": "SubmissionDeadlineNotReached", "msg": "Submission deadline has not been reached yet."},
            {"code": 6004, "name": "AdminReviewDeadlineExceeded", "msg": "Admin review deadline has passed."},
            {"code": 6005, "name": "TechEvalDeadlineExceeded", "msg": "Technical evaluation deadline has passed."},
            {"code": 6006, "name": "FinancialRevealDeadlineExceeded", "msg": "Financial reveal deadline has passed. Reveals are closed."},
            {"code": 6007, "name": "TenderNotSubmissionsOpen", "msg": "Tender is not in SubmissionsOpen status."},
            {"code": 6008, "name": "TenderNotAdminReview", "msg": "Tender is not in AdministrativeReview status."},
            {"code": 6009, "name": "TenderNotTechnicalEvaluation", "msg": "Tender is not in TechnicalEvaluation status."},
            {"code": 6010, "name": "TenderNotFinancialEvaluation", "msg": "Tender is not in FinancialEvaluation status."},
            {"code": 6011, "name": "TenderAlreadyAwarded", "msg": "Tender has already been awarded."},
            {"code": 6012, "name": "UnauthorizedBidder", "msg": "Bidder is not in the authorized whitelist."},
            {"code": 6013, "name": "InvalidMerkleProof", "msg": "Merkle proof verification failed."},
            {"code": 6014, "name": "InvalidRevealHash", "msg": "Provided reveal preimage does not match the committed cryptographic hash."},
            {"code": 6015, "name": "TechAlreadyRevealed", "msg": "Technical bid has already been revealed."},
            {"code": 6016, "name": "TechNotRevealed", "msg": "Technical proposal has not been revealed yet."},
            {"code": 6017, "name": "FinAlreadyRevealed", "msg": "Financial envelope has already been revealed."},
            {"code": 6018, "name": "BidderTechnicallyDisqualified", "msg": "Commercial Secrecy Invariant: Bidder is technically disqualified. Financial envelope is permanently sealed."},
            {"code": 6019, "name": "BidderNotAdminPassed", "msg": "Bidder has not passed administrative due diligence."},
            {"code": 6020, "name": "WinnerNotQualified", "msg": "Winning bidder is not technically qualified."},
            {"code": 6021, "name": "WinnerNotRevealed", "msg": "Winning bidder has not unsealed their financial envelope."},
            {"code": 6022, "name": "WinnerNotLowestPrice", "msg": "Selected winner does not have the lowest price in Least-Cost mode."},
            {"code": 6023, "name": "WinnerNotHighestCompositeScore", "msg": "Selected winner does not have the highest composite score in QCBS mode."},
            {"code": 6024, "name": "FinancialRevealWindowActive", "msg": "Anti-Lockout Gate: Financial reveal window is active and qualified bids remain unrevealed."},
            {"code": 6025, "name": "TenderIdTooLong", "msg": "Tender ID exceeds maximum allowed length of 32 characters."},
            {"code": 6026, "name": "InsufficientDeposit", "msg": "Insufficient deposit attached for bid commitment bond."},
            {"code": 6027, "name": "EvaluatorNotAuthorized", "msg": "Signer is not an accredited member of the Tender Committee."},
            {"code": 6028, "name": "CommitteeAlreadyLocked", "msg": "Tender committee roster is already locked."},
            {"code": 6029, "name": "GradeAlreadyRevealed", "msg": "Evaluator grade has already been revealed."},
            {"code": 6030, "name": "GradeNotRevealed", "msg": "Evaluator grade has not been revealed yet."},
            {"code": 6031, "name": "InsufficientEvaluatorGrades", "msg": "At least 3 revealed committee evaluations required for trimmed mean scoring."},
            {"code": 6032, "name": "InvalidSubScores", "msg": "Sub-scores do not match the claimed total score."},
            {"code": 6033, "name": "SubScoresOutOfRange", "msg": "Sub-scores exceed maximum allowed value (10,000 bps total)."},
            {"code": 6034, "name": "InvalidWeights", "msg": "Technical and financial weights must sum exactly to 10,000 basis points (100%)."},
            {"code": 6035, "name": "BondAlreadySettled", "msg": "Bond deposit has already been refunded or settled."},
            {"code": 6036, "name": "BidderIsTechQualified", "msg": "Bidder is technically qualified. Financial envelope must be unsealed to settle bond."},
            {"code": 6037, "name": "InvalidBondMode", "msg": "Bond mode is not SolanaEscrow."}
        ]
    }

    os.makedirs("target/idl", exist_ok=True)
    with open("target/idl/bidtrace.json", "w") as f:
        json.dump(idl, f, indent=2)

    os.makedirs("target/types", exist_ok=True)
    ts_content = f"""/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 * _DO NOT EDIT THIS FILE DIRECTLY_
 */
export type Bidtrace = {json.dumps(idl, indent=2)};
"""
    with open("target/types/bidtrace.ts", "w") as f:
        f.write(ts_content)

    print("[SUCCESS] target/idl/bidtrace.json and target/types/bidtrace.ts generated successfully!")

if __name__ == "__main__":
    generate_idl()
