import * as crypto from "crypto";
import * as fs from "fs";

interface ProofBundle {
  tender_pda: string;
  bidder_pubkey: string;
  salt_hex: string;
  bid_amount: number;
  ciphertext_b64: string;
  key_hex: string;
  ciphertext_hash_hex: string;
}

interface RawLedgerState {
  current_slot: number;
  tenders: Record<string, any>;
  commitments: Record<string, any>;
}

export function verifyProofBundle(bundle: ProofBundle, rawState: RawLedgerState) {
  console.log("=== BIDTRACE STANDALONE TYPESCRIPT OFFLINE VERIFIER ===");

  const tender = rawState.tenders[bundle.tender_pda];
  if (!tender) {
    return { valid: false, error: `Tender ${bundle.tender_pda} not found in public ledger` };
  }

  // Find bidder commitment
  let bidRecord = null;
  for (const pda of Object.keys(rawState.commitments)) {
    const item = rawState.commitments[pda];
    if (item.tender_pda === bundle.tender_pda && item.bidder === bundle.bidder_pubkey) {
      bidRecord = item;
      break;
    }
  }

  if (!bidRecord) {
    return { valid: false, error: `No commitment found for bidder ${bundle.bidder_pubkey}` };
  }

  // 1. Check Slot
  if (bidRecord.committed_at_slot > tender.deadline_slot) {
    return { valid: false, error: `Committed slot ${bidRecord.committed_at_slot} exceeds deadline ${tender.deadline_slot}` };
  }

  // 2. Recompute Domain-Separated Hash
  const hasher = crypto.createHash("sha256");
  hasher.update(Buffer.from("BIDTRACE_V1"));
  hasher.update(Buffer.from(bundle.tender_pda, "hex"));
  hasher.update(Buffer.from(bundle.bidder_pubkey, "hex"));
  hasher.update(Buffer.from(bundle.salt_hex, "hex"));
  hasher.update(Buffer.from(bundle.ciphertext_hash_hex, "hex"));
  
  const bufAmount = Buffer.alloc(8);
  bufAmount.writeBigUInt64LE(BigInt(bundle.bid_amount));
  hasher.update(bufAmount);

  const recomputed = hasher.digest("hex");
  if (recomputed !== bidRecord.commitment_hash) {
    return { valid: false, error: `Recomputed hash (${recomputed}) != on-chain commitment (${bidRecord.commitment_hash})` };
  }

  return {
    valid: true,
    tender_id: tender.tender_id,
    committed_slot: bidRecord.committed_at_slot,
    deadline_slot: tender.deadline_slot,
    bid_amount: bundle.bid_amount,
    on_chain_hash: bidRecord.commitment_hash
  };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.log("Usage: node verifier/verify.js <proof_bundle.json> <ledger_state.json>");
    process.exit(1);
  }
  const bundle = JSON.parse(fs.readFileSync(args[0], "utf-8"));
  const state = JSON.parse(fs.readFileSync(args[1], "utf-8"));
  const res = verifyProofBundle(bundle, state);
  console.log(res);
}
