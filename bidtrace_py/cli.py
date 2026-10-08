import argparse
import json
import os
import secrets
import sys
from .crypto import generate_keypair, encrypt_payload, compute_commitment_hash
from .ledger import BidTraceLedger, TenderStatus

STATE_FILE = "ledger_state.json"

def get_ledger():
    return BidTraceLedger(STATE_FILE)

def main():
    parser = argparse.ArgumentParser(description="BidTrace CLI - Cryptographic Deadline-Lock for Procurement")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Authority: Init Tender
    init_parser = subparsers.add_parser("init-tender", help="Initialize a new tender")
    init_parser.add_argument("--id", required=True, help="Tender ID (e.g. T-2026-001)")
    init_parser.add_argument("--submission-deadline-slots", type=int, default=50, help="Number of slots until submission deadline")
    init_parser.add_argument("--reveal-deadline-slots", type=int, default=100, help="Number of slots until reveal deadline")
    init_parser.add_argument("--bid-deposit", type=int, default=0, help="Deposit bond per bid in lamports/units")
    init_parser.add_argument("--deadline-slots", type=int, default=None, help="Deprecated: alias for submission-deadline-slots")

    # 2. Bidder: Submit Bid
    submit_parser = subparsers.add_parser("submit", help="Submit an encrypted bid before deadline")
    submit_parser.add_argument("--tender", required=True, help="Tender PDA")
    submit_parser.add_argument("--bidder-name", required=True, help="Bidder Company Name")
    submit_parser.add_argument("--amount", type=int, required=True, help="Bid Amount in USD")
    submit_parser.add_argument("--specs", default="Standard Compliant Specs", help="Specification summary")
    submit_parser.add_argument("--out-receipt", default="bidder_receipt.json", help="Path to save portable receipt")

    # 3. Advance Slot (Simulator helper)
    adv_parser = subparsers.add_parser("advance-slots", help="Advance blockchain slot clock")
    adv_parser.add_argument("--slots", type=int, default=60, help="Number of slots to advance")

    # 4. Anyone: Lock Tender
    lock_parser = subparsers.add_parser("lock-tender", help="Freeze tender after deadline slot has passed")
    lock_parser.add_argument("--tender", required=True, help="Tender PDA")

    # 5. Bidder: Reveal Bid
    reveal_parser = subparsers.add_parser("reveal", help="Reveal bid post-deadline using receipt")
    reveal_parser.add_argument("--receipt", required=True, help="Path to bidder_receipt.json")

    # 6. Authority: Record Award
    award_parser = subparsers.add_parser("record-award", help="Record tender award")
    award_parser.add_argument("--tender", required=True, help="Tender PDA")
    award_parser.add_argument("--authority-key", required=True, help="Authority Public Key")
    award_parser.add_argument("--winner", required=True, help="Winning Bidder Public Key")

    # 7. Status
    status_parser = subparsers.add_parser("status", help="Inspect tender state")
    status_parser.add_argument("--tender", required=True, help="Tender PDA")

    args = parser.parse_args()
    ledger = get_ledger()

    if args.command == "init-tender":
        auth = generate_keypair()
        sub_slots = args.deadline_slots if args.deadline_slots is not None else args.submission_deadline_slots
        sub_deadline = ledger.current_slot + sub_slots
        rev_deadline = ledger.current_slot + args.reveal_deadline_slots
        tender = ledger.initialize_tender(
            authority_pubkey=auth["public_key"],
            tender_id=args.id,
            submission_deadline_slot=sub_deadline,
            reveal_deadline_slot=rev_deadline,
            bid_deposit=args.bid_deposit
        )
        print(f"[SUCCESS] Tender Initialized:")
        print(f"  Tender ID:            {tender['tender_id']}")
        print(f"  Tender PDA:           {tender['pda']}")
        print(f"  Authority:            {tender['authority']}")
        print(f"  Current Slot:         {ledger.current_slot}")
        print(f"  Submission Deadline:  Slot {tender['submission_deadline_slot']}")
        print(f"  Reveal Deadline:      Slot {tender['reveal_deadline_slot']}")
        print(f"  Bid Bond Deposit:     {tender['bid_deposit']} lamports")
        print(f"  Status:               {tender['status']}")

    elif args.command == "submit":
        bidder = generate_keypair()
        salt = secrets.token_hex(32)
        payload = encrypt_payload({
            "bidder": args.bidder_name,
            "amount": args.amount,
            "specs": args.specs
        })
        comm_hash = compute_commitment_hash(
            tender_pubkey_hex=args.tender,
            bidder_pubkey_hex=bidder["public_key"],
            salt_hex=salt,
            ciphertext_hash_hex=payload["ciphertext_hash_hex"],
            bid_amount=args.amount
        )

        try:
            bid = ledger.commit_bid(args.tender, bidder["public_key"], comm_hash)
            receipt = {
                "tender_pda": args.tender,
                "bidder_pubkey": bidder["public_key"],
                "bidder_name": args.bidder_name,
                "salt_hex": salt,
                "bid_amount": args.amount,
                "ciphertext_b64": payload["ciphertext_b64"],
                "key_hex": payload["key_hex"],
                "ciphertext_hash_hex": payload["ciphertext_hash_hex"],
                "commitment_hash": comm_hash,
                "committed_slot": bid["committed_at_slot"]
            }
            with open(args.out_receipt, 'w') as f:
                json.dump(receipt, f, indent=2)

            print(f"[SUCCESS] Bid Committed before deadline:")
            print(f"  Bidder Pubkey:  {bidder['public_key']}")
            print(f"  Bid PDA:        {bid['pda']}")
            print(f"  Committed Slot: {bid['committed_at_slot']}")
            print(f"  Commitment:     {comm_hash}")
            print(f"  Receipt saved:  {args.out_receipt}")
        except Exception as e:
            print(f"[ERROR] Commit failed: {e}")
            sys.exit(1)

    elif args.command == "advance-slots":
        new_slot = ledger.advance_slot(args.slots)
        print(f"[CLOCK ADVANCED] Current Slot is now: {new_slot}")

    elif args.command == "lock-tender":
        try:
            tender = ledger.lock_tender(args.tender)
            print(f"[SUCCESS] Tender Locked at Slot {ledger.current_slot}:")
            print(f"  Status:           {tender['status']}")
            print(f"  Total Committed:  {tender['total_committed']}")
        except Exception as e:
            print(f"[ERROR] Lock failed: {e}")
            sys.exit(1)

    elif args.command == "reveal":
        with open(args.receipt, 'r') as f:
            rec = json.load(f)
        try:
            bid = ledger.reveal_bid(
                tender_pda=rec["tender_pda"],
                bidder_pubkey=rec["bidder_pubkey"],
                salt_hex=rec["salt_hex"],
                ciphertext_hash_hex=rec["ciphertext_hash_hex"],
                bid_amount=rec["bid_amount"]
            )
            print(f"[SUCCESS] Bid Revealed and Verified on-chain:")
            print(f"  Bidder:          {rec['bidder_name']} ({rec['bidder_pubkey']})")
            print(f"  Revealed Price:  ${rec['bid_amount']:,}")
            print(f"  Revealed Slot:   {bid['revealed_at_slot']}")
            print(f"  Hash Matched:    YES (Preimage validated)")
        except Exception as e:
            print(f"[ERROR] Reveal failed: {e}")
            sys.exit(1)

    elif args.command == "record-award":
        try:
            tender = ledger.record_award(args.tender, args.authority_key, args.winner)
            print(f"[SUCCESS] Tender Award Recorded:")
            print(f"  Winning Bidder: {tender['winning_bidder']}")
            print(f"  Status:         {tender['status']}")
        except Exception as e:
            print(f"[ERROR] Award failed: {e}")
            sys.exit(1)

    elif args.command == "status":
        tenders = ledger.tenders
        if args.tender not in tenders:
            print(f"[ERROR] Tender {args.tender} not found.")
            sys.exit(1)
        t = tenders[args.tender]
        print(json.dumps(t, indent=2))

if __name__ == "__main__":
    main()
