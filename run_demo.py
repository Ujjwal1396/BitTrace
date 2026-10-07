#!/usr/bin/env python3
"""
BidTrace: 3-Minute Hackathon Live Demonstration Script
Demonstrates the full lifecycle, adversarial attack defenses, and air-gapped verification.
"""

import os
import sys
import json
import time
import secrets

from bidtrace_py.crypto import generate_keypair, encrypt_payload, compute_commitment_hash
from bidtrace_py.ledger import BidTraceLedger, TenderStatus
from bidtrace_py.verifier import verify_proof_bundle

def print_banner(text):
    print("\n" + "=" * 70)
    print(f" >>> {text}")
    print("=" * 70)

def main():
    print_banner("BIDTRACE: INCORRUPTIBLE DEADLINE-LOCK FOR PROCUREMENT")
    print("Initializing simulated Solana ledger & Anchor Program runtime...")
    ledger = BidTraceLedger()
    
    # ---------------------------------------------------------
    # STEP 1: Tender Authority Initializes Tender
    # ---------------------------------------------------------
    print_banner("STEP 1: TENDER CREATION (Solana Anchor Instruction: initialize_tender)")
    authority = generate_keypair()
    start_slot = ledger.current_slot
    deadline_slot = start_slot + 50
    tender_id = "TENDER-2026-HIGHWAY-402"
    
    tender = ledger.initialize_tender(
        authority_pubkey=authority["public_key"],
        tender_id=tender_id,
        deadline_slot=deadline_slot
    )
    tender_pda = tender["pda"]
    print(f"[OK] Tender Created: {tender_id}")
    print(f"     Authority Pubkey: {authority['public_key'][:16]}...")
    print(f"     Tender PDA:       {tender_pda}")
    print(f"     Current Slot:     {start_slot}")
    print(f"     Deadline Slot:    {deadline_slot} (Strict consensus enforcement)")

    # ---------------------------------------------------------
    # STEP 2: Bidders Submit Encrypted Commitments Pre-Deadline
    # ---------------------------------------------------------
    print_banner("STEP 2: PRE-DEADLINE COMMITMENTS (Flaw A Resolution: Direct PDA Intake)")
    print("Bidders encrypt payloads locally and write directly to individual PDAs:")

    bidders = [
        {"name": "ACME Corp", "amount": 4200000, "specs": "Grade 50 Reinforced Concrete"},
        {"name": "BuildCo Ltd", "amount": 3950000, "specs": "Structural Steel & Concrete"},
        {"name": "InfraPlus", "amount": 4100000, "specs": "Composite Concrete & Drainage"}
    ]

    receipts = []
    for b in bidders:
        kp = generate_keypair()
        salt = secrets.token_hex(32)
        encrypted = encrypt_payload({"bidder": b["name"], "amount": b["amount"], "specs": b["specs"]})
        
        # Domain-separated commitment calculation
        comm_hash = compute_commitment_hash(
            tender_pubkey_hex=tender_pda,
            bidder_pubkey_hex=kp["public_key"],
            salt_hex=salt,
            ciphertext_hash_hex=encrypted["ciphertext_hash_hex"],
            bid_amount=b["amount"]
        )

        # On-chain commitment directly to PDA derived from [b"bid", tender_pda, bidder_pubkey]
        bid_record = ledger.commit_bid(tender_pda, kp["public_key"], comm_hash)
        
        receipt = {
            "bidder_name": b["name"],
            "bidder_pubkey": kp["public_key"],
            "tender_pda": tender_pda,
            "salt_hex": salt,
            "bid_amount": b["amount"],
            "ciphertext_b64": encrypted["ciphertext_b64"],
            "key_hex": encrypted["key_hex"],
            "ciphertext_hash_hex": encrypted["ciphertext_hash_hex"],
            "commitment_hash": comm_hash,
            "committed_slot": bid_record["committed_at_slot"]
        }
        receipts.append(receipt)
        print(f"  [+] {b['name']:14} committed at Slot {bid_record['committed_at_slot']} | PDA: {bid_record['pda'][:16]}... | Hash: {comm_hash[:16]}...")

    print(f"\nTotal commitments locked in tender state: {ledger.tenders[tender_pda]['total_committed']}")

    # ---------------------------------------------------------
    # STEP 3: Deadline Elapsed & Tender Freeze
    # ---------------------------------------------------------
    print_banner("STEP 3: DEADLINE FREEZE (Solana Anchor Instruction: lock_tender)")
    print(f"Consensus clock advances past deadline slot {deadline_slot}...")
    ledger.advance_slot(60) # Current slot is now start_slot + 60 (> deadline_slot)
    print(f"Current Slot is now: {ledger.current_slot}")

    locked_tender = ledger.lock_tender(tender_pda)
    print(f"[OK] Tender Status flipped to: {locked_tender['status']} (Commitments permanently frozen)")

    # ---------------------------------------------------------
    # STEP 4: Adversarial Attack Demonstrations
    # ---------------------------------------------------------
    print_banner("STEP 4: LIVE ADVERSARIAL ATTACK SIMULATIONS")
    
    # Attack 1: Malicious Admin tries to insert Bidder D after the deadline
    print(">>> ATTACK 1: Malicious Admin attempts to inject late bid (Bidder D) post-deadline...")
    corrupt_bidder = generate_keypair()
    corrupt_salt = secrets.token_hex(32)
    corrupt_payload = encrypt_payload({"bidder": "Shadow Contractor", "amount": 3800000, "specs": "Late Collusive Bid"})
    corrupt_comm = compute_commitment_hash(
        tender_pda, corrupt_bidder["public_key"], corrupt_salt, corrupt_payload["ciphertext_hash_hex"], 3800000
    )
    try:
        ledger.commit_bid(tender_pda, corrupt_bidder["public_key"], corrupt_comm)
        print("  [CRITICAL FAILURE] Malicious late bid was accepted!")
    except Exception as e:
        print(f"  [DEFENSE SUCCESS] Transaction REVERTED on-chain: {e}")
        print("  -> Proof: Consensus rules prevent any post-deadline submission regardless of admin privileges.")

    # Attack 2: Corrupt Admin modifies database record for ACME Corp to alter price
    print("\n>>> ATTACK 2: Admin modifies off-chain DB record for ACME Corp ($4.2M -> $3.7M to steal award)...")
    acme_receipt = receipts[0]
    try:
        # Corrupt admin tries to call reveal_bid with forged price of 3,700,000
        ledger.reveal_bid(
            tender_pda=tender_pda,
            bidder_pubkey=acme_receipt["bidder_pubkey"],
            salt_hex=acme_receipt["salt_hex"],
            ciphertext_hash_hex=acme_receipt["ciphertext_hash_hex"],
            bid_amount=3700000 # TAMPERED AMOUNT
        )
        print("  [CRITICAL FAILURE] Tampered bid was accepted!")
    except Exception as e:
        print(f"  [DEFENSE SUCCESS] Transaction REVERTED on-chain: {e}")
        print("  -> Proof: Recomputed hash does not match immutable on-chain commitment!")

    # ---------------------------------------------------------
    # STEP 5: Legitimate Reveal & Award Recording
    # ---------------------------------------------------------
    print_banner("STEP 5: LEGITIMATE REVEALS & CONTRACT AWARD")
    for r in receipts:
        rev = ledger.reveal_bid(
            tender_pda=tender_pda,
            bidder_pubkey=r["bidder_pubkey"],
            salt_hex=r["salt_hex"],
            ciphertext_hash_hex=r["ciphertext_hash_hex"],
            bid_amount=r["bid_amount"]
        )
        print(f"  [REVEALED] {r['bidder_name']:14} | Verified Price: ${r['bid_amount']:,} | Hash Match: VALID")

    # Tender Authority records winning award to BuildCo Ltd (lowest price: $3,950,000)
    winner_receipt = receipts[1] # BuildCo Ltd
    award = ledger.record_award(tender_pda, authority["public_key"], winner_receipt["bidder_pubkey"])
    print(f"\n[AWARD RECORDED] Winner: {winner_receipt['bidder_name']}")
    print(f"                 Winning Amount: ${winner_receipt['bid_amount']:,}")
    print(f"                 Tender Status:  {award['status']}")

    # ---------------------------------------------------------
    # STEP 6: Independent Air-Gapped Offline Verification
    # ---------------------------------------------------------
    print_banner("STEP 6: AIR-GAPPED OFFLINE VERIFIER (Story 4)")
    print("Simulating procurement server SHUT DOWN...")
    print("Auditor receives standalone 'proof_bundle.json' and verifies against raw public ledger accounts:")

    proof_bundle = {
        "tender_pda": tender_pda,
        "bidder_pubkey": winner_receipt["bidder_pubkey"],
        "salt_hex": winner_receipt["salt_hex"],
        "bid_amount": winner_receipt["bid_amount"],
        "ciphertext_b64": winner_receipt["ciphertext_b64"],
        "key_hex": winner_receipt["key_hex"],
        "ciphertext_hash_hex": winner_receipt["ciphertext_hash_hex"]
    }

    raw_state = {
        "current_slot": ledger.current_slot,
        "tenders": ledger.tenders,
        "commitments": ledger.commitments
    }

    result = verify_proof_bundle(proof_bundle, raw_state)
    if result["valid"]:
        print("\n  ========================================================")
        print("   VERIFIER AUDIT REPORT: [CRYPTOGRAPHICALLY VERIFIED]")
        print("  ========================================================")
        print(f"   Tender Reference:    {result['tender_id']}")
        print(f"   Committed Slot:      {result['committed_slot']} <= Deadline {result['deadline_slot']} [PASS]")
        print(f"   Ciphertext Tag:      AES-256-GCM Authentic [PASS]")
        print(f"   Preimage Commitment: {result['on_chain_hash'][:32]}... [MATCH]")
        print(f"   Winning Price:       ${result['bid_amount']:,}")
        print(f"   Tender Final State:  {result['tender_status']} [PASS]")
        print("  ========================================================")
        print("\n[CONCLUSION] Complete BidTrace protocol executed successfully with zero trusted intermediaries.")

if __name__ == "__main__":
    main()
