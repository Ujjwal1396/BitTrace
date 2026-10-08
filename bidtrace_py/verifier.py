import json
import os
import sys
from .crypto import decrypt_payload, compute_commitment_hash

def verify_proof_bundle(proof_bundle: dict, ledger_state: dict) -> dict:
    """
    Performs standalone, air-gapped cryptographic verification of a proof bundle
    against raw public ledger records.
    """
    tender_pda = proof_bundle["tender_pda"]
    bidder_pubkey = proof_bundle["bidder_pubkey"]
    salt_hex = proof_bundle["salt_hex"]
    bid_amount = proof_bundle["bid_amount"]
    ciphertext_b64 = proof_bundle["ciphertext_b64"]
    key_hex = proof_bundle["key_hex"]
    ciphertext_hash_hex = proof_bundle["ciphertext_hash_hex"]

    # 1. Look up Tender account from raw ledger state
    tenders = ledger_state.get("tenders", {})
    if tender_pda not in tenders:
        return {"valid": False, "step": "Tender Lookup", "error": f"Tender {tender_pda} not found in public ledger"}
    tender = tenders[tender_pda]

    # 2. Look up Bid PDA from raw ledger state
    commitments = ledger_state.get("commitments", {})
    bid_pda = None
    for pda, record in commitments.items():
        if record.get("tender_pda") == tender_pda and record.get("bidder") == bidder_pubkey:
            bid_pda = pda
            break

    if not bid_pda:
        return {"valid": False, "step": "Commitment Lookup", "error": f"No on-chain commitment found for bidder {bidder_pubkey}"}
    bid_record = commitments[bid_pda]

    # 3. Check Slot Adherence (Deadline Proof)
    committed_slot = bid_record["committed_at_slot"]
    deadline_slot = tender.get("submission_deadline_slot", tender.get("deadline_slot"))
    if committed_slot > deadline_slot:
        return {
            "valid": False,
            "step": "Slot Deadline Check",
            "error": f"Bid committed at slot {committed_slot}, after submission deadline {deadline_slot}"
        }

    # 4. Decrypt and check plaintext integrity
    try:
        decrypted = decrypt_payload(key_hex, ciphertext_b64)
    except Exception as e:
        return {"valid": False, "step": "Decryption Integrity", "error": f"AES-GCM decryption failed: {e}"}

    if decrypted.get("amount") != bid_amount:
        return {
            "valid": False,
            "step": "Amount Mismatch",
            "error": f"Decrypted amount {decrypted.get('amount')} != claimed amount {bid_amount}"
        }

    # 5. Recompute Domain-Separated Cryptographic Commitment
    recomputed_hash = compute_commitment_hash(
        tender_pubkey_hex=tender_pda,
        bidder_pubkey_hex=bidder_pubkey,
        salt_hex=salt_hex,
        ciphertext_hash_hex=ciphertext_hash_hex,
        bid_amount=bid_amount
    )

    on_chain_hash = bid_record["commitment_hash"]
    if recomputed_hash != on_chain_hash:
        return {
            "valid": False,
            "step": "Commitment Match",
            "error": f"Recomputed hash ({recomputed_hash}) does not match on-chain commitment ({on_chain_hash})"
        }

    # 6. Check Tender Lifecycle Status
    if tender["status"] not in ["Locked", "Awarded"]:
        return {
            "valid": False,
            "step": "Tender Status",
            "error": f"Tender is in '{tender['status']}' state, expected Locked or Awarded"
        }

    return {
        "valid": True,
        "tender_id": tender["tender_id"],
        "tender_pda": tender_pda,
        "bidder_pubkey": bidder_pubkey,
        "committed_slot": committed_slot,
        "deadline_slot": deadline_slot,
        "bid_amount": bid_amount,
        "decrypted_specs": decrypted.get("specs", ""),
        "on_chain_hash": on_chain_hash,
        "tender_status": tender["status"]
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: python -m bidtrace_py.verifier <proof_bundle.json> <ledger_state.json>")
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        bundle = json.load(f)

    with open(sys.argv[2], 'r') as f:
        state = json.load(f)

    result = verify_proof_bundle(bundle, state)
    print("=" * 60)
    print("      BIDTRACE AIR-GAPPED INDEPENDENT VERIFIER")
    print("=" * 60)
    if result["valid"]:
        print("RESULT: [SUCCESS] Cryptographically Verified!")
        print(f"  Tender:         {result['tender_id']} ({result['tender_pda']})")
        print(f"  Bidder:         {result['bidder_pubkey']}")
        print(f"  Committed Slot: {result['committed_slot']} <= Deadline {result['deadline_slot']} [PASS]")
        print(f"  Verified Price: ${result['bid_amount']:,}")
        print(f"  On-Chain Hash:  {result['on_chain_hash']}")
        print(f"  Tender State:   {result['tender_status']}")
    else:
        print(f"RESULT: [FAILED] at step: {result['step']}")
        print(f"  Error: {result['error']}")
    print("=" * 60)

if __name__ == "__main__":
    main()
