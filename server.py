import http.server
import socketserver
import json
import os
import secrets
import sys

from bidtrace_py.crypto import generate_keypair, encrypt_payload, compute_commitment_hash
from bidtrace_py.ledger import BidTraceLedger, TenderStatus
from bidtrace_py.verifier import verify_proof_bundle

PORT = 8000
PUBLIC_DIR = os.path.join(os.path.dirname(__file__), "public")

# In-memory session state connected to the real protocol ledger
class AppState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.ledger = BidTraceLedger()
        self.authority = generate_keypair()
        self.tender_pda = None
        self.tender_id = None
        self.bidders_receipts = []

state = AppState()

class BidTraceHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def do_GET(self):
        if self.path == "/api/status":
            self.send_json({
                "current_slot": state.ledger.current_slot,
                "tenders": state.ledger.tenders,
                "commitments": state.ledger.commitments,
                "tender_pda": state.tender_pda,
                "receipts_count": len(state.bidders_receipts)
            })
            return

        if self.path == "/api/devnet/status":
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
                "program_id": "x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ",
                "deployer_pubkey": "GFRRqHMPekLkEUPDzwLXnBoETUU1EFrfFoZxiCWUwSzU",
                "devnet_slot": devnet_slot,
                "last_run": last_run
            })
            return
        # Default static file serving (index.html, etc.)
        return super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            data = json.loads(body.decode('utf-8'))
        except Exception:
            data = {}

        if self.path == "/api/reset":
            state.reset()
            self.send_json({"status": "ok", "message": "State reset successfully", "slot": state.ledger.current_slot})

        elif self.path == "/api/init-tender":
            state.reset()
            tender_id = data.get("tender_id", "TENDER-2026-HIGHWAY-402")
            deadline_slots = data.get("deadline_slots", 50)
            submission_deadline_slot = state.ledger.current_slot + deadline_slots
            reveal_deadline_slot = submission_deadline_slot + 50
            bid_deposit = data.get("bid_deposit", 0)
            
            tender = state.ledger.initialize_tender(
                authority_pubkey=state.authority["public_key"],
                tender_id=tender_id,
                submission_deadline_slot=submission_deadline_slot,
                reveal_deadline_slot=reveal_deadline_slot,
                bid_deposit=bid_deposit
            )
            state.tender_pda = tender["pda"]
            state.tender_id = tender_id
            self.send_json({
                "status": "ok",
                "tender": tender,
                "authority_pubkey": state.authority["public_key"]
            })

        elif self.path == "/api/commit-bid":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender. Initialize a tender first."}, 400)
                return

            bidder_name = data.get("name", "Contractor")
            amount = int(data.get("amount", 4000000))
            specs = data.get("specs", "Standard Specs")

            # 1. Real cryptographic keypair generation
            kp = generate_keypair()
            salt = secrets.token_hex(32)

            # 2. Real AES-256-GCM payload encryption
            encrypted = encrypt_payload({"bidder": bidder_name, "amount": amount, "specs": specs})

            # 3. Real domain-separated SHA-256 commitment hash
            comm_hash = compute_commitment_hash(
                tender_pubkey_hex=state.tender_pda,
                bidder_pubkey_hex=kp["public_key"],
                salt_hex=salt,
                ciphertext_hash_hex=encrypted["ciphertext_hash_hex"],
                bid_amount=amount
            )

            # 4. Direct PDA commitment onto simulated Solana Anchor ledger
            try:
                bid_record = state.ledger.commit_bid(state.tender_pda, kp["public_key"], comm_hash)
                receipt = {
                    "bidder_name": bidder_name,
                    "bidder_pubkey": kp["public_key"],
                    "tender_pda": state.tender_pda,
                    "salt_hex": salt,
                    "bid_amount": amount,
                    "ciphertext_b64": encrypted["ciphertext_b64"],
                    "key_hex": encrypted["key_hex"],
                    "ciphertext_hash_hex": encrypted["ciphertext_hash_hex"],
                    "commitment_hash": comm_hash,
                    "committed_slot": bid_record["committed_at_slot"],
                    "pda": bid_record["pda"]
                }
                state.bidders_receipts.append(receipt)
                self.send_json({"status": "ok", "receipt": receipt, "total_committed": state.ledger.tenders[state.tender_pda]["total_committed"]})
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)

        elif self.path == "/api/lock-tender":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return

            # Advance clock past deadline
            state.ledger.advance_slot(60)
            try:
                tender = state.ledger.lock_tender(state.tender_pda)
                self.send_json({
                    "status": "ok",
                    "current_slot": state.ledger.current_slot,
                    "tender_status": tender["status"],
                    "total_committed": tender["total_committed"]
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)

        elif self.path == "/api/reveal-bids":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender."}, 400)
                return

            revealed_list = []
            for r in state.bidders_receipts:
                try:
                    rev = state.ledger.reveal_bid(
                        tender_pda=state.tender_pda,
                        bidder_pubkey=r["bidder_pubkey"],
                        salt_hex=r["salt_hex"],
                        ciphertext_hash_hex=r["ciphertext_hash_hex"],
                        bid_amount=r["bid_amount"]
                    )
                    revealed_list.append({
                        "bidder_name": r["bidder_name"],
                        "bidder_pubkey": r["bidder_pubkey"],
                        "amount": r["bid_amount"],
                        "is_revealed": True
                    })
                except Exception as e:
                    self.send_json({"status": "error", "message": str(e)}, 400)
                    return

            self.send_json({"status": "ok", "revealed": revealed_list})

        elif self.path == "/api/record-award":
            if not state.tender_pda or not state.bidders_receipts:
                self.send_json({"status": "error", "message": "No bids available to award."}, 400)
                return

            # Find the lowest bid among revealed bids
            lowest = min(state.bidders_receipts, key=lambda x: x["bid_amount"])
            try:
                award = state.ledger.record_award(state.tender_pda, state.authority["public_key"], lowest["bidder_pubkey"])
                self.send_json({
                    "status": "ok",
                    "winner_name": lowest["bidder_name"],
                    "winner_pubkey": lowest["bidder_pubkey"],
                    "winning_amount": lowest["bid_amount"],
                    "tender_status": award["status"]
                })
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 400)

        elif self.path == "/api/attack-late-bid":
            if not state.tender_pda:
                self.send_json({"status": "error", "message": "No active tender. Initialize a tender first."}, 400)
                return

            tender = state.ledger.tenders[state.tender_pda]
            current_slot = state.ledger.current_slot
            deadline_slot = tender["deadline_slot"]

            if current_slot <= deadline_slot:
                self.send_json({
                    "status": "warning",
                    "title": "BID ACCEPTED (NOT AN ATTACK YET)",
                    "message": f"Consensus clock is at Slot {current_slot} (Deadline is {deadline_slot}). Because the deadline has not passed yet, Bidder D's bid was legally accepted! Click '3. Advance Slot & Lock Tender' first to test what happens after the deadline."
                })
                return

            # Actually attempt late commit after deadline
            corrupt_kp = generate_keypair()
            corrupt_salt = secrets.token_hex(32)
            corrupt_payload = encrypt_payload({"bidder": "Shadow Contractor", "amount": 3800000, "specs": "Late Collusive Bid"})
            corrupt_comm = compute_commitment_hash(
                state.tender_pda, corrupt_kp["public_key"], corrupt_salt, corrupt_payload["ciphertext_hash_hex"], 3800000
            )
            try:
                state.ledger.commit_bid(state.tender_pda, corrupt_kp["public_key"], corrupt_comm)
                self.send_json({"status": "breach", "message": "CRITICAL: Malicious late bid was accepted!"}, 500)
            except Exception as e:
                self.send_json({
                    "status": "defended",
                    "error_type": "BidTraceError::DeadlineExceeded",
                    "raw_error": str(e),
                    "slot_info": f"Current Slot {current_slot} > Deadline {deadline_slot}"
                })

        elif self.path == "/api/attack-tamper-price":
            if not state.bidders_receipts:
                self.send_json({"status": "error", "message": "No bids to tamper."}, 400)
                return

            tender = state.ledger.tenders[state.tender_pda]
            if tender["status"] != TenderStatus.LOCKED:
                self.send_json({
                    "status": "defended",
                    "error_type": "BidTraceError::TenderNotLocked",
                    "raw_error": f"TenderNotLocked: Tender status is still '{tender['status']}'. Nobody is allowed to open or reveal bids before the deadline closes!",
                })
                return

            target = state.bidders_receipts[0] # ACME Corp
            tampered_price = target["bid_amount"] - 500000 # Tampered down to undercut
            try:
                state.ledger.reveal_bid(
                    tender_pda=state.tender_pda,
                    bidder_pubkey=target["bidder_pubkey"],
                    salt_hex=target["salt_hex"],
                    ciphertext_hash_hex=target["ciphertext_hash_hex"],
                    bid_amount=tampered_price
                )
                self.send_json({"status": "breach", "message": "CRITICAL: Tampered price was accepted!"}, 500)
            except Exception as e:
                self.send_json({
                    "status": "defended",
                    "error_type": "BidTraceError::InvalidRevealHash",
                    "raw_error": str(e),
                    "tampered_price": tampered_price,
                    "original_price": target["bid_amount"]
                })

        elif self.path == "/api/verify-offline":
            if not state.bidders_receipts:
                self.send_json({"status": "error", "message": "No receipts to verify."}, 400)
                return

            # Verify the lowest/winner receipt using zero-backend standalone verifier
            target_receipt = min(state.bidders_receipts, key=lambda x: x["bid_amount"])
            raw_state = {
                "current_slot": state.ledger.current_slot,
                "tenders": state.ledger.tenders,
                "commitments": state.ledger.commitments
            }
            result = verify_proof_bundle(target_receipt, raw_state)
            self.send_json({"status": "ok", "audit_report": result})

        elif self.path == "/api/devnet/run-pipeline":
            import subprocess
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
                    self.send_json({
                        "status": "ok",
                        "data": data,
                        "stdout": proc.stdout
                    })
                else:
                    self.send_json({
                        "status": "error",
                        "message": proc.stderr or proc.stdout or "Pipeline failed to produce output"
                    }, 500)
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)

        elif self.path == "/api/devnet/faucet":
            import subprocess
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
                    self.send_json({
                        "status": "ok",
                        "signature": sig,
                        "recipient": recipient,
                        "amount": amount
                    })
                else:
                    self.send_json({"status": "error", "message": output}, 500)
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)

        else:
            self.send_json({"error": "Endpoint not found"}, 404)

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
    # Allow port reuse to avoid 'Address already in use' errors on quick restarts
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), BidTraceHandler) as httpd:
        print("=" * 65)
        print(f" >>> BIDTRACE LIVE PROTOCOL SERVER RUNNING ON PORT {PORT}")
        print(f" >>> Open your browser at: http://localhost:{PORT}")
        print("=" * 65)
        print("Waiting for browser connections & protocol requests...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down BidTrace server...")
            httpd.server_close()

if __name__ == "__main__":
    run()
