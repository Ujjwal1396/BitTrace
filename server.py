"""
BidTrace 3.0: Multi-Jurisdiction Bond & Relayer Gateway Server
=============================================================
Universal B2B/B2G Procurement Gateway supporting:
1. Two-Envelope State Machine (Technical + Financial Isolation)
2. Open Contracting Data Standard (OCDS 1.1) with RFC 8785 (JCS) Hashing
3. Multi-Jurisdiction Hybrid Bond Engine (Surety-as-a-Service, MT760, BSD, Escrow)
4. Model A (Pre-Qualified Merkle Whitelist) & Model B (Post-Qualified Open)
5. Multi-Evaluator Blinded Rubrics & Olympic Trimmed Mean Outlier Defense
6. Gas-Sponsored Relayer Protocol Execution (Solana Devnet / In-Memory Consensus)
"""

import http.server
import socketserver
import json
import os
import secrets
import sys
import subprocess
import hashlib
from typing import Dict, Any, List, Optional

from bidtrace_py.crypto import (
    generate_keypair,
    encrypt_payload,
    decrypt_payload,
    compute_commitment_hash,
    compute_tech_commitment,
    compute_fin_commitment,
    compute_grade_commitment,
    b58encode,
    b58decode
)
from bidtrace_py.ocds import (
    canonicalize_jcs,
    hash_canonical_json,
    build_ocid,
    create_tender_notice_release,
    create_evaluation_release,
    create_award_release,
    get_iso_now
)
from bidtrace_py.merkle import MerkleTree, verify_merkle_proof, compute_leaf
from bidtrace_py.bonds import (
    BondMode,
    issue_surety_policy,
    issue_bank_guarantee_attestation,
    sign_bid_securing_declaration,
    create_solana_escrow_record,
    list_all_bonds
)
from bidtrace_py.ledger import (
    BidTraceLedger,
    TenderStatus,
    TenderMode,
    EvaluationType,
    AdminStatus
)
from bidtrace_py.relayer import BidTraceRelayerGateway
from bidtrace_py.verifier import (
    verify_proof_bundle,
    AirGappedTribunalVerifier,
    export_tribunal_dossier
)


PORT = 8000
PUBLIC_DIR = os.path.join(os.path.dirname(__file__), "public")


class ServerState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.relayer = BidTraceRelayerGateway()
        self.authority = generate_keypair()
        self.bidders_receipts: List[Dict[str, Any]] = []

    @property
    def ledger(self) -> BidTraceLedger:
        return self.relayer.ledger

    @property
    def tender_pda(self) -> Optional[str]:
        return self.relayer.active_tender_pda


state = ServerState()


class BidTraceHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        parsed_path = self.path.split('?')[0]

        # 1. Protocol Status
        if parsed_path == "/api/status":
            tender = state.ledger.tenders.get(state.tender_pda) if state.tender_pda else None
            comm_pda = state.ledger.derive_committee_pda(state.tender_pda) if state.tender_pda else None
            committee = state.ledger.committees.get(comm_pda) if comm_pda else None

            bids_summary = []
            for b in state.ledger.commitments.values():
                if state.tender_pda and b.get("tender_pda") == state.tender_pda:
                    bids_summary.append({
                        "bidder": b.get("bidder"),
                        "admin_status": b.get("admin_status"),
                        "is_tech_revealed": b.get("is_tech_revealed"),
                        "technical_score_bps": b.get("technical_score_bps"),
                        "is_tech_qualified": b.get("is_tech_qualified"),
                        "is_fin_revealed": b.get("is_fin_revealed"),
                        "revealed_price": b.get("revealed_price"),
                        "composite_score": b.get("composite_score"),
                        "bond_mode": b.get("bond_mode"),
                        "bond_amount": b.get("bond_amount")
                    })

            self.send_json({
                "status": "ok",
                "current_slot": state.ledger.current_slot,
                "fee_payer": state.relayer.fee_payer_wallet,
                "tender_pda": state.tender_pda,
                "active_tender": tender,
                "active_committee": committee,
                "bids_count": len(bids_summary),
                "bids": bids_summary,
                "ocds_releases_count": len(state.relayer.ocds_releases),
                "bonds_count": len(list_all_bonds()),
                # Backwards compat fields
                "tenders": state.ledger.tenders,
                "commitments": state.ledger.commitments,
                "receipts_count": len(state.bidders_receipts)
            })
            return

        # 2. Devnet Cluster Status
        if parsed_path == "/api/devnet/status":
            devnet_slot = None
            try:
                import urllib.request
                req = urllib.request.Request(
                    "https://api.devnet.solana.com",
                    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getSlot"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=4) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    devnet_slot = res.get("result", 0)
            except Exception:
                pass

            last_run = None
            last_run_path = os.path.join(os.path.dirname(__file__), "devnet_last_run.json")
            if os.path.exists(last_run_path):
                try:
                    with open(last_run_path, "r", encoding="utf-8") as f:
                        last_run = json.load(f)
                except Exception:
                    pass

            self.send_json({
                "cluster": "devnet",
                "program_id": state.relayer.program_id,
                "deployer_pubkey": state.relayer.fee_payer_wallet,
                "devnet_slot": devnet_slot,
                "last_run": last_run
            })
            return

        # 3. OCDS Releases Audit Trail
        if parsed_path == "/api/ocds/releases":
            releases_list = list(state.relayer.ocds_releases.values())
            self.send_json({
                "status": "ok",
                "count": len(releases_list),
                "releases": releases_list
            })
            return

        if parsed_path.startswith("/api/ocds/release/"):
            rel_id = parsed_path.split("/api/ocds/release/")[-1]
            rel = state.relayer.ocds_releases.get(rel_id)
            if rel:
                self.send_json(rel)
            else:
                self.send_json({"error": "ReleaseNotFound", "id": rel_id}, 404)
            return

        # 4. Hybrid Bonds Registry
        if parsed_path == "/api/bonds":
            self.send_json({
                "status": "ok",
                "bonds": list_all_bonds()
            })
            return

        # 5. Tribunal Dossier Download
        if parsed_path == "/api/tribunal/download_dossier":
            dossier_path = os.path.join(os.path.dirname(__file__), "tribunal_dossier.zip")
            if not os.path.exists(dossier_path):
                self.send_json({"status": "error", "message": "No tribunal dossier generated yet. Call POST /api/tribunal/export_dossier first."}, 404)
                return
            with open(dossier_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Content-Disposition', 'attachment; filename="tribunal_dossier.zip"')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(content)
            return

        # Fallback to static files
        return super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            data = json.loads(body.decode('utf-8'))
        except Exception:
            data = {}

        parsed_path = self.path.split('?')[0]

        # Reset State
        if parsed_path == "/api/reset":
            state.reset()
            self.send_json({
                "status": "ok",
                "message": "Protocol relayer state reset successfully",
                "slot": state.ledger.current_slot
            })
            return

        # ----------------------------------------------------------------------
        # PHASE 3: MODEL A (MERKLE WHITELIST) ENDPOINTS
        # ----------------------------------------------------------------------
        if parsed_path == "/api/merkle/tree":
            bidders = data.get("bidders", [])
            if not bidders:
                self.send_json({"status": "error", "message": "bidders array required"}, 400)
                return
            tree = MerkleTree(bidders)
            self.send_json({
                "status": "ok",
                "root_hex": tree.root_hex,
                "tree": tree.to_dict()
            })
            return

        if parsed_path == "/api/merkle/proof":
            bidders = data.get("bidders", [])
            target = data.get("bidder")
            if not bidders or not target:
                self.send_json({"status": "error", "message": "bidders and bidder required"}, 400)
                return
            tree = MerkleTree(bidders)
            try:
                proof = tree.get_proof_hex(target)
                is_valid = verify_merkle_proof(target, proof, tree.root_hex)
                self.send_json({
                    "status": "ok",
                    "bidder": target,
                    "root_hex": tree.root_hex,
                    "proof_hex": proof,
                    "is_valid": is_valid
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        # ----------------------------------------------------------------------
        # PHASE 3: MULTI-JURISDICTION HYBRID BOND ENDPOINTS
        # ----------------------------------------------------------------------
        if parsed_path == "/api/surety/issue_policy":
            bidder_id = data.get("bidder_id", secrets.token_hex(16))
            bidder_name = data.get("bidder_name", "Licensed EPC Contractor")
            tender_id = data.get("tender_id", "TENDER-QCBS-2026-001")
            penal_sum = float(data.get("penal_sum_usd", 190000.0))
            officer = data.get("officer_name", "Chief Executive Officer")
            flat_fee = float(data.get("flat_fee_fiat", 250.0))

            policy = issue_surety_policy(
                bidder_id=bidder_id,
                bidder_name=bidder_name,
                tender_id=tender_id,
                penal_sum_usd=penal_sum,
                officer_name=officer,
                flat_fee_fiat=flat_fee
            )
            self.send_json({
                "status": "ok",
                "policy": policy,
                "policyId": policy["policyId"],
                "giaCanonicalHash": policy["giaCanonicalHash"]
            })
            return

        if parsed_path == "/api/bond/bg_attest":
            bidder_id = data.get("bidder_id", secrets.token_hex(16))
            bidder_name = data.get("bidder_name", "Global Civil Works Ltd")
            tender_id = data.get("tender_id", "TENDER-QCBS-2026-001")
            bank = data.get("bank_name", "JPMorgan Chase Bank, N.A.")
            bic = data.get("swift_bic", "CHASUS33")
            ref = data.get("guarantee_ref", f"BG-MT760-2026-{secrets.token_hex(4).upper()}")
            amount = float(data.get("amount_usd", 190000.0))
            beneficiary = data.get("beneficiary_entity", "Ministry of Transportation")
            expiry = data.get("expiry_date_iso", "2026-12-31T23:59:59Z")

            guarantee = issue_bank_guarantee_attestation(
                bidder_id=bidder_id,
                bidder_name=bidder_name,
                tender_id=tender_id,
                bank_name=bank,
                swift_bic=bic,
                guarantee_ref=ref,
                amount_usd=amount,
                beneficiary_entity=beneficiary,
                expiry_date_iso=expiry
            )
            self.send_json({
                "status": "ok",
                "guarantee": guarantee,
                "attestationId": guarantee["attestationId"],
                "mt760Hash": guarantee["mt760Hash"]
            })
            return

        if parsed_path == "/api/bond/bsd_sign":
            bidder_id = data.get("bidder_id", secrets.token_hex(16))
            bidder_name = data.get("bidder_name", "Consortium for Public Infrastructure")
            tender_id = data.get("tender_id", "TENDER-QCBS-2026-001")
            entity = data.get("procuring_entity", "Ministry of Transportation")
            sig_name = data.get("signatory_name", "Managing Director")
            sig_title = data.get("signatory_title", "Authorised Representative")
            months = int(data.get("sanction_period_months", 36))

            bsd = sign_bid_securing_declaration(
                bidder_id=bidder_id,
                bidder_name=bidder_name,
                tender_id=tender_id,
                procuring_entity=entity,
                signatory_name=sig_name,
                signatory_title=sig_title,
                sanction_period_months=months
            )
            self.send_json({
                "status": "ok",
                "declaration": bsd,
                "declarationId": bsd["declarationId"],
                "canonicalHash": bsd["canonicalHash"]
            })
            return

        # ----------------------------------------------------------------------
        # PHASE 3: RELAYER GATEWAY TWO-ENVELOPE STATE TRANSITIONS
        # ----------------------------------------------------------------------
        # 1. Tender Creation with OCDS 1.1 Notice Release
        if parsed_path in ["/api/tender/create", "/api/init-tender"]:
            state.reset()
            tender_id = data.get("tender_id", "TENDER-QCBS-2026-001")
            title = data.get("title", "National Highway 402 Corridor Modernization")
            description = data.get("description", "Two-Envelope QCBS Procurement standard compliant with OCDS 1.1")
            buyer_name = data.get("buyer_name", "Department of Transportation")
            currency = data.get("currency", "USD")
            est_amount = float(data.get("estimated_amount", 3800000.0))
            eval_type = data.get("evaluation_type", "QCBS")
            tech_w = float(data.get("tech_weight", 0.70))
            fin_w = float(data.get("fin_weight", 0.30))
            min_tech = float(data.get("min_tech_score", 75.0))
            bond_amt = float(data.get("bond_amount", 190000.0))
            bond_m = data.get("bond_mode", "SuretyService")
            auth_root = data.get("authorized_bidders_root")

            # Standard 5-evaluator panel
            default_evaluators = [
                generate_keypair()["public_key"] for _ in range(5)
            ]
            evaluators = data.get("evaluators", default_evaluators)

            res = state.relayer.create_tender(
                authority_pubkey=state.authority["public_key"],
                tender_id=tender_id,
                title=title,
                description=description,
                buyer_name=buyer_name,
                currency=currency,
                estimated_amount=est_amount,
                evaluation_type=eval_type,
                tech_weight=tech_w,
                fin_weight=fin_w,
                min_tech_score=min_tech,
                bond_amount=bond_amt,
                bond_mode_str=bond_m,
                authorized_bidders_root=auth_root,
                evaluators=evaluators
            )

            self.send_json({
                "status": "ok",
                "tender": res["tender"],
                "committee": res["committee"],
                "ocds_notice_hash": res["ocds_notice_hash"],
                "ocds_release_id": res["ocds_release"]["id"],
                "authority_pubkey": state.authority["public_key"],
                "fee_payer": res["fee_payer"]
            })
            return

        # 2. Dual-Envelope Commit (Envelope A + Envelope B)
        if parsed_path in ["/api/bid/commit_dual", "/api/commit-bid"]:
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender. Initialize a tender first."}, 400)
                return

            bidder_name = data.get("name", data.get("bidder_name", "ACME Infrastructure Corp"))
            bidder_kp = generate_keypair()
            bidder_pubkey = data.get("bidder_pubkey", bidder_kp["public_key"])
            price = int(data.get("amount", data.get("price", 3800000)))

            # Technical Proposal Preimages (Envelope A)
            salt_tech = data.get("salt_tech", secrets.token_hex(32))
            specs_text = data.get("specs", f"High-durability structural specifications for {bidder_name}")
            proposal_hash = data.get("proposal_hash", hashlib.sha256(specs_text.encode('utf-8')).hexdigest())

            # Financial Proposal Preimages (Envelope B)
            salt_fin = data.get("salt_fin", secrets.token_hex(32))
            boq_text = data.get("boq_schedule", f"BOQ_SCHEDULE_USD_{price}_{bidder_name}")
            boq_hash = data.get("boq_hash", hashlib.sha256(boq_text.encode('utf-8')).hexdigest())

            # Administrative Dossier (Model B)
            admin_dossier_text = data.get("admin_dossier", f"TAX_AUDIT_ISO_CLEARANCE_{bidder_name}")
            admin_dossier_hash = data.get("admin_dossier_hash", hashlib.sha256(admin_dossier_text.encode('utf-8')).hexdigest())

            # Bond handling
            bond_mode_int = int(data.get("bond_mode", BondMode.SURETY_SERVICE))
            bond_amount = int(data.get("bond_amount", 190000))
            bond_record = data.get("bond_record")
            whitelist_proof = data.get("whitelist_proof")

            try:
                res = state.relayer.commit_dual_bid(
                    tender_pda=state.tender_pda,
                    bidder_pubkey=bidder_pubkey,
                    bidder_name=bidder_name,
                    admin_dossier_hash=admin_dossier_hash,
                    salt_tech=salt_tech,
                    proposal_hash=proposal_hash,
                    salt_fin=salt_fin,
                    price=price,
                    boq_hash=boq_hash,
                    bond_mode=bond_mode_int,
                    bond_amount=bond_amount,
                    bond_record=bond_record,
                    whitelist_proof=whitelist_proof
                )
                state.bidders_receipts.append(res["receipt"])
                self.send_json({
                    "status": "ok",
                    "bid": res["bid"],
                    "receipt": res["receipt"],
                    "total_committed": state.ledger.tenders[state.tender_pda]["total_committed"]
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        # 3. Advance Tender Phase
        if parsed_path in ["/api/tender/advance_phase", "/api/lock-tender"]:
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            state.ledger.advance_slot(30)
            try:
                tender = state.ledger.advance_tender_phase(state.tender_pda)
                self.send_json({
                    "status": "ok",
                    "current_slot": state.ledger.current_slot,
                    "tender_status": tender["status"],
                    "total_committed": tender["total_committed"]
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        # 4. Reveal Envelope A (Technical Proposal)
        if parsed_path == "/api/bid/reveal_technical":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            bidder = data.get("bidder_pubkey")
            salt_tech = data.get("salt_tech")
            prop_hash = data.get("proposal_hash")
            try:
                bid = state.ledger.reveal_technical_bid(state.tender_pda, bidder, salt_tech, prop_hash)
                self.send_json({"status": "ok", "bid": bid})
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        # 5. Evaluator Blinded Grade Commit & Reveal
        if parsed_path == "/api/evaluator/commit_grade":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            ev = data.get("evaluator_pubkey")
            bidder = data.get("bidder_pubkey")
            comm_hash = data.get("commitment_hash")
            try:
                grade = state.ledger.commit_evaluator_grade(state.tender_pda, ev, bidder, comm_hash)
                self.send_json({"status": "ok", "grade": grade})
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        if parsed_path == "/api/evaluator/reveal_grade":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            ev = data.get("evaluator_pubkey")
            bidder = data.get("bidder_pubkey")
            sub_scores = data.get("sub_scores", [])
            salt = data.get("salt")
            just_hash = data.get("justification_hash")
            try:
                grade = state.ledger.reveal_evaluator_grade(state.tender_pda, ev, bidder, sub_scores, salt, just_hash)
                self.send_json({"status": "ok", "grade": grade})
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        # 6. Finalize Technical Evaluation (Olympic Trimmed Mean & OCDS Release)
        if parsed_path == "/api/tender/finalize_technical":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            bidders = data.get("bidder_pubkeys")
            if not bidders:
                bidders = [b["bidder"] for b in state.ledger.commitments.values() if b["tender_pda"] == state.tender_pda]
            try:
                res = state.relayer.finalize_technical_evaluation(
                    tender_pda=state.tender_pda,
                    authority_pubkey=state.authority["public_key"],
                    bidder_pubkeys=bidders
                )
                self.send_json({
                    "status": "ok",
                    "evaluations": res["evaluations"],
                    "total_qualified": res["total_qualified"],
                    "ocds_release": res["ocds_release"]
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        # 7. Reveal Envelope B (Financial Envelope - Gated by Technical Cutoff)
        if parsed_path in ["/api/bid/reveal_financial", "/api/reveal-bids"]:
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return

            # If specific bidder reveal requested
            if "bidder_pubkey" in data:
                bidder = data["bidder_pubkey"]
                salt_fin = data.get("salt_fin")
                price = int(data.get("price", 0))
                boq_hash = data.get("boq_hash")
                try:
                    bid = state.ledger.reveal_financial_envelope(state.tender_pda, bidder, salt_fin, price, boq_hash)
                    self.send_json({"status": "ok", "bid": bid})
                except Exception as e:
                    code = 403 if "BidderTechnicallyDisqualified" in str(e) else 400
                    self.send_json({"status": "error", "message": str(e)}, code)
                return

            # Batch reveal for all receipts in memory
            revealed_list = []
            for r in state.bidders_receipts:
                p_img = r.get("unsealingPreimages", {})
                salt_fin = p_img.get("saltFin", r.get("salt_hex"))
                price = int(p_img.get("price", r.get("bid_amount", 0)))
                boq = p_img.get("boqHash", r.get("ciphertext_hash_hex"))
                try:
                    bid = state.ledger.reveal_financial_envelope(state.tender_pda, r["bidderPubkey"], salt_fin, price, boq)
                    revealed_list.append({"bidder": r["bidderPubkey"], "revealed_price": price})
                except Exception as e:
                    pass
            self.send_json({"status": "ok", "revealed": revealed_list})
            return

        # 8. Final Award (Programmatic QCBS & OCDS Award Release)
        if parsed_path in ["/api/tender/award", "/api/record-award"]:
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            winner_pubkey = data.get("winning_bidder_pubkey")
            winner_name = data.get("winner_name", "Winning Contractor")

            # Fallback to lowest price among qualified if not supplied
            if not winner_pubkey:
                qualified_revealed = [
                    b for b in state.ledger.commitments.values()
                    if b["tender_pda"] == state.tender_pda and b["is_tech_qualified"] and b["is_fin_revealed"]
                ]
                if not qualified_revealed:
                    self.send_json({"status": "error", "message": "No qualified and revealed bids found for award."}, 400)
                    return
                lowest_bid = min(qualified_revealed, key=lambda x: x["revealed_price"])
                winner_pubkey = lowest_bid["bidder"]

            try:
                res = state.relayer.record_award(
                    tender_pda=state.tender_pda,
                    authority_pubkey=state.authority["public_key"],
                    winning_bidder_pubkey=winner_pubkey,
                    winner_name=winner_name
                )
                self.send_json({
                    "status": "ok",
                    "tender": res["tender"],
                    "winning_bid": res["winning_bid"],
                    "ocds_release": res["ocds_release"]
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)
            return

        # ----------------------------------------------------------------------
        # ATTACK & SECURITY INVARIANT SIMULATIONS
        # ----------------------------------------------------------------------
        if parsed_path in ["/api/attack/late_bid", "/api/attack-late-bid"]:
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            tender = state.ledger.tenders[state.tender_pda]
            current_slot = state.ledger.current_slot
            deadline_slot = tender["submission_deadline_slot"]

            if current_slot <= deadline_slot:
                self.send_json({
                    "status": "warning",
                    "message": f"Consensus clock is at Slot {current_slot} <= Deadline {deadline_slot}. Advance phase first!"
                })
                return

            corrupt_kp = generate_keypair()
            try:
                state.ledger.commit_dual_bid(
                    tender_pda=state.tender_pda,
                    bidder_pubkey=corrupt_kp["public_key"],
                    admin_dossier_hash="00" * 32,
                    tech_commitment_hash="11" * 32,
                    fin_commitment_hash="22" * 32
                )
                self.send_json({"status": "breach", "message": "CRITICAL: Late bid accepted!"}, 500)
            except Exception as e:
                self.send_json({
                    "status": "defended",
                    "error_type": "BidTraceError::SubmissionDeadlineExceeded",
                    "raw_error": str(e),
                    "slot_info": f"Current Slot {current_slot} > Deadline {deadline_slot}"
                })
            return

        if parsed_path == "/api/attack/rogue_score":
            # Demonstrates how the on-chain Olympic Trimmed Mean defeats rogue bribery
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            self.send_json({
                "status": "defended",
                "defense": "On-Chain Olympic Trimmed Mean Filter",
                "explanation": "Smart contract drops maximum and minimum scores, and flags any evaluation deviating > 20% from the median with is_outlier_flagged = true."
            })
            return

        if parsed_path in ["/api/attack/tamper_price", "/api/attack-tamper-price"]:
            if not state.bidders_receipts:
                self.send_json({"status": "error", "message": "No bids to tamper."}, 400)
                return
            target = state.bidders_receipts[0]
            p_img = target.get("unsealingPreimages", {})
            salt_fin = p_img.get("saltFin", target.get("salt_hex"))
            boq = p_img.get("boqHash", target.get("ciphertext_hash_hex"))
            tampered_price = int(p_img.get("price", target.get("bid_amount", 4000000))) - 500000
            try:
                state.ledger.reveal_financial_envelope(
                    tender_pda=state.tender_pda,
                    bidder_pubkey=target["bidderPubkey"],
                    salt_fin=salt_fin,
                    price=tampered_price,
                    boq_hash=boq
                )
                self.send_json({"status": "breach", "message": "CRITICAL: Tampered price was accepted!"}, 500)
            except Exception as e:
                self.send_json({
                    "status": "defended",
                    "error_type": "BidTraceError::InvalidRevealHash",
                    "raw_error": str(e),
                    "tampered_price": tampered_price
                })
            return

        if parsed_path == "/api/attack/leak_unqualified":
            # Attempt to reveal financial envelope for a disqualified bidder
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return
            disqualified = next(
                (b for b in state.ledger.commitments.values() if b["tender_pda"] == state.tender_pda and not b["is_tech_qualified"]),
                None
            )
            if not disqualified:
                self.send_json({"status": "info", "message": "No disqualified bidder currently in state to test."})
                return
            try:
                state.ledger.reveal_financial_envelope(
                    tender_pda=state.tender_pda,
                    bidder_pubkey=disqualified["bidder"],
                    salt_fin="00" * 32,
                    price=3000000,
                    boq_hash="00" * 32
                )
                self.send_json({"status": "breach", "message": "CRITICAL: Disqualified pricing leaked!"}, 500)
            except Exception as e:
                self.send_json({
                    "status": "defended",
                    "error_type": "BidTraceError::BidderTechnicallyDisqualified",
                    "raw_error": str(e),
                    "commercial_secrecy": "Financial envelope permanently sealed on-chain forever."
                })
            return

        # ----------------------------------------------------------------------
        # PHASE 4: TRIBUNAL DOSSIER PACKAGING & AIR-GAPPED VERIFICATION
        # ----------------------------------------------------------------------
        if parsed_path == "/api/tribunal/export_dossier":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender to package into dossier."}, 400)
                return
            out_path = data.get("output_path", os.path.join(os.path.dirname(__file__), "tribunal_dossier.zip"))
            try:
                res = export_tribunal_dossier(state.relayer, output_path=out_path, tender_pda=state.tender_pda)
                self.send_json({
                    "status": "ok",
                    "filename": "tribunal_dossier.zip",
                    "output_path": res["output_path"],
                    "size_bytes": res["size_bytes"],
                    "download_url": "/api/tribunal/download_dossier",
                    "manifest": res["manifest"]
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)
            return

        if parsed_path in ["/api/tribunal/verify", "/api/verify-tribunal"]:
            dossier_path = data.get("dossier_path", os.path.join(os.path.dirname(__file__), "tribunal_dossier.zip"))
            if not os.path.exists(dossier_path) and state.tender_pda:
                try:
                    export_tribunal_dossier(state.relayer, output_path=dossier_path, tender_pda=state.tender_pda)
                except Exception as e:
                    self.send_json({"status": "error", "message": f"Auto-export dossier failed: {e}"}, 500)
                    return

            if not os.path.exists(dossier_path):
                self.send_json({"status": "error", "message": f"Dossier file not found: {dossier_path}"}, 404)
                return

            try:
                verifier = AirGappedTribunalVerifier(dossier_path)
                audit_report = verifier.verify_all()
                self.send_json({
                    "status": "ok",
                    "audit_report": audit_report,
                    "terminal_output": verifier.format_cli_report(audit_report)
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)
            return

        # Standalone Offline Verification (Backwards Compatibility)
        if parsed_path == "/api/verify-offline":
            if not state.bidders_receipts:
                self.send_json({"status": "error", "message": "No receipts to verify."}, 400)
                return
            target_receipt = state.bidders_receipts[0]
            raw_state = {
                "current_slot": state.ledger.current_slot,
                "tenders": state.ledger.tenders,
                "commitments": state.ledger.commitments
            }
            result = verify_proof_bundle(target_receipt, raw_state)
            self.send_json({"status": "ok", "audit_report": result})
            return

        # Devnet Pipeline execution
        if parsed_path == "/api/devnet/run-pipeline":
            try:
                proc = subprocess.run(
                    ["wsl", "-e", "bash", "-c", "node scripts/devnet_runner.js"],
                    cwd=os.path.dirname(__file__),
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                last_run_path = os.path.join(os.path.dirname(__file__), "devnet_last_run.json")
                if os.path.exists(last_run_path):
                    with open(last_run_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self.send_json({"status": "ok", "data": data, "stdout": proc.stdout})
                else:
                    self.send_json({"status": "error", "message": proc.stderr or proc.stdout or "Pipeline failed to produce output"}, 500)
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)
            return

        if parsed_path == "/api/devnet/faucet":
            recipient = data.get("recipient", "").strip()
            amount = float(data.get("amount", 0.2))
            if not recipient or len(recipient) < 32 or len(recipient) > 44:
                self.send_json({"status": "error", "message": "Invalid recipient Solana public key."}, 400)
                return
            try:
                cmd = f'export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH" && solana transfer --url https://api.devnet.solana.com --allow-unfunded-recipient {recipient} {amount}'
                proc = subprocess.run(
                    ["wsl", "-e", "bash", "-c", cmd],
                    cwd=os.path.dirname(__file__),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = proc.stdout + proc.stderr
                sig = ""
                for line in output.splitlines():
                    if "Signature:" in line:
                        sig = line.split("Signature:")[-1].strip()
                        break
                if sig:
                    self.send_json({"status": "ok", "signature": sig, "recipient": recipient, "amount": amount})
                else:
                    self.send_json({"status": "error", "message": output}, 500)
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)
            return

        self.send_json({"error": "Endpoint not found", "path": parsed_path}, 404)

    def send_json(self, data: dict, status_code: int = 200):
        response_bytes = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        self.wfile.write(response_bytes)


def run():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), BidTraceHandler) as httpd:
        print("=" * 70)
        print(f" >>> BIDTRACE 3.0 MULTI-JURISDICTION RELAYER GATEWAY")
        print(f" >>> Listening on: http://localhost:{PORT}")
        print("=" * 70)
        print("Gas-sponsored relayer ready for browser portals & API calls...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down BidTrace server...")
            httpd.server_close()


if __name__ == "__main__":
    run()
