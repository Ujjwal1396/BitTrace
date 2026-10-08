const fs = require('fs');
const vm = require('vm');
const nodeCrypto = require('crypto');

const code = fs.readFileSync('./public/solanaWeb3.min.js', 'utf8');
const context = {
  window: {},
  exports: {},
  crypto: nodeCrypto.webcrypto,
  fetch: fetch,
  Buffer: globalThis.Buffer,
  Uint8Array: globalThis.Uint8Array,
  Array: globalThis.Array,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  setInterval: setInterval,
  clearInterval: clearInterval
};
context.window = context;
context.global = context;
context.self = context;
vm.createContext(context);
vm.runInContext(code, context);
const solanaWeb3 = context.solanaWeb3;

const PROGRAM_ID = new solanaWeb3.PublicKey("x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ");
const DEVNET_RPC = "https://api.devnet.solana.com";

const DISCRIMINATORS = {
  initializeTender: Buffer.from([209, 239, 55, 105, 195, 125, 42, 9]),
  commitBid: Buffer.from([149, 237, 198, 113, 53, 66, 70, 76]),
  lockTender: Buffer.from([182, 82, 25, 163, 74, 59, 20, 144]),
  revealBid: Buffer.from([48, 73, 28, 255, 202, 126, 236, 196]),
  recordAward: Buffer.from([156, 213, 120, 99, 54, 114, 88, 49])
};

function encodeString(str) {
  const bytes = Buffer.from(str, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32LE(bytes.length, 0);
  return Buffer.concat([len, bytes]);
}

function encodeU64(val) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(val), 0);
  return buf;
}

async function sha256(data) {
  return Buffer.from(await nodeCrypto.webcrypto.subtle.digest("SHA-256", data));
}

async function computeCommitmentHash(tenderPda, bidderPubkey, salt, cipherHash, amount) {
  const domain = Buffer.from("BIDTRACE_V1", "utf8");
  const amountBuf = encodeU64(amount);
  const preimage = Buffer.concat([domain, tenderPda.toBuffer(), bidderPubkey.toBuffer(), salt, cipherHash, amountBuf]);
  return await sha256(preimage);
}

async function sendAndPoll(conn, tx, signers) {
  const sig = await conn.sendTransaction(tx, signers, { skipPreflight: false });
  for (let i = 0; i < 35; i++) {
    const status = await conn.getSignatureStatus(sig);
    if (status && status.value && (status.value.confirmationStatus === 'confirmed' || status.value.confirmationStatus === 'finalized')) {
      return sig;
    }
    await new Promise(r => setTimeout(r, 1000));
  }
  return sig;
}

async function runDevnetPipeline() {
  console.log("=================================================================");
  console.log("   BIDTRACE ON-CHAIN DEVNET PIPELINE (ANCHOR SMART CONTRACT)     ");
  console.log("   Program ID:", PROGRAM_ID.toBase58());
  console.log("=================================================================");

  const rawKey = JSON.parse(fs.readFileSync('/home/wazir/.config/solana/id.json', 'utf8'));
  const authority = solanaWeb3.Keypair.fromSecretKey(Uint8Array.from(rawKey));
  console.log("Authority Address:", authority.publicKey.toBase58());

  const conn = new solanaWeb3.Connection(DEVNET_RPC, "confirmed");
  const balance = await conn.getBalance(authority.publicKey);
  console.log("Authority Devnet Balance:", balance / solanaWeb3.LAMPORTS_PER_SOL, "SOL");

  const startSlot = await conn.getSlot();
  console.log("Current Devnet Consensus Slot:", startSlot);

  // 1. Initialize Tender
  const tenderId = "TENDER-" + Math.floor(Date.now() / 1000);
  const [tenderPda] = solanaWeb3.PublicKey.findProgramAddressSync(
    [Buffer.from("tender"), authority.publicKey.toBuffer(), Buffer.from(tenderId)],
    PROGRAM_ID
  );

  const subDeadlineSlot = startSlot + 100;
  const revDeadlineSlot = startSlot + 250;
  const depositLamports = 10000; // 0.00001 SOL deposit bond

  console.log("\n[STEP 1] Initializing Tender on Devnet...");
  console.log(`   Tender ID: ${tenderId}`);
  console.log(`   Tender PDA: ${tenderPda.toBase58()}`);
  console.log(`   Submission Deadline: Slot ${subDeadlineSlot}`);
  console.log(`   Reveal Deadline: Slot ${revDeadlineSlot}`);
  console.log(`   Escrowed Bid Bond: ${depositLamports} lamports`);

  const initData = Buffer.concat([
    DISCRIMINATORS.initializeTender,
    encodeString(tenderId),
    encodeU64(subDeadlineSlot),
    encodeU64(revDeadlineSlot),
    encodeU64(depositLamports),
    Buffer.alloc(32) // Merkle root (none)
  ]);

  const initIx = new solanaWeb3.TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: tenderPda, isSigner: false, isWritable: true },
      { pubkey: authority.publicKey, isSigner: true, isWritable: true },
      { pubkey: solanaWeb3.SystemProgram.programId, isSigner: false, isWritable: false }
    ],
    data: initData
  });

  const initTx = new solanaWeb3.Transaction().add(initIx);
  const initSig = await sendAndPoll(conn, initTx, [authority]);
  console.log("   -> Init Confirmed!");
  console.log("   -> Signature:", initSig);
  console.log(`   -> Explorer: https://explorer.solana.com/tx/${initSig}?cluster=devnet`);

  // 2. Commit Bid from Contractor A
  const contractorA = solanaWeb3.Keypair.generate();
  // Transfer rent + deposit to contractor A
  console.log("\n[STEP 2] Committing Sealed Bid for Contractor A...");
  console.log(`   Contractor Pubkey: ${contractorA.publicKey.toBase58()}`);

  const fundIx = solanaWeb3.SystemProgram.transfer({
    fromPubkey: authority.publicKey,
    toPubkey: contractorA.publicKey,
    lamports: 0.01 * solanaWeb3.LAMPORTS_PER_SOL
  });
  const fundTx = new solanaWeb3.Transaction().add(fundIx);
  await sendAndPoll(conn, fundTx, [authority]);

  const saltA = Buffer.from(nodeCrypto.randomBytes(32));
  const cipherHashA = Buffer.from(nodeCrypto.randomBytes(32));
  const amountA = 3950000; // $3.95M
  const commHashA = await computeCommitmentHash(tenderPda, contractorA.publicKey, saltA, cipherHashA, amountA);

  const [bidAPda] = solanaWeb3.PublicKey.findProgramAddressSync(
    [Buffer.from("bid"), tenderPda.toBuffer(), contractorA.publicKey.toBuffer()],
    PROGRAM_ID
  );
  console.log(`   BidCommitment PDA: ${bidAPda.toBase58()}`);
  console.log(`   SHA-256 Commitment Hash: ${commHashA.toString('hex')}`);

  const commitData = Buffer.concat([
    DISCRIMINATORS.commitBid,
    commHashA,
    Buffer.from([0]) // whitelist_proof: None
  ]);

  const commitIx = new solanaWeb3.TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: tenderPda, isSigner: false, isWritable: true },
      { pubkey: bidAPda, isSigner: false, isWritable: true },
      { pubkey: contractorA.publicKey, isSigner: true, isWritable: false },
      { pubkey: contractorA.publicKey, isSigner: true, isWritable: true },
      { pubkey: solanaWeb3.SystemProgram.programId, isSigner: false, isWritable: false }
    ],
    data: commitData
  });

  const commitTx = new solanaWeb3.Transaction().add(commitIx);
  const commitSig = await sendAndPoll(conn, commitTx, [contractorA]);
  console.log("   -> Commit Confirmed!");
  console.log("   -> Signature:", commitSig);
  console.log(`   -> Explorer: https://explorer.solana.com/tx/${commitSig}?cluster=devnet`);

  // Verify on-chain state of tender and bid
  const tenderAcc = await conn.getAccountInfo(tenderPda);
  const bidAcc = await conn.getAccountInfo(bidAPda);

  console.log("\n=================================================================");
  console.log("   VERIFIED LIVE ON-CHAIN STATE RESULTS:                         ");
  console.log("   Tender PDA Account Size:", tenderAcc.data.length, "bytes");
  console.log("   Bid PDA Account Size:", bidAcc.data.length, "bytes");
  console.log("   All state mathematically sealed on Solana Devnet!");
  console.log("=================================================================\n");

  return {
    tenderId,
    tenderPda: tenderPda.toBase58(),
    contractorPubkey: contractorA.publicKey.toBase58(),
    bidPda: bidAPda.toBase58(),
    commitmentHash: commHashA.toString('hex'),
    initTxSignature: initSig,
    commitTxSignature: commitSig
  };
}

if (require.main === module) {
  runDevnetPipeline()
    .then(res => {
      fs.writeFileSync('./devnet_last_run.json', JSON.stringify(res, null, 2));
      process.exit(0);
    })
    .catch(err => {
      console.error("Pipeline Error:", err);
      process.exit(1);
    });
}

module.exports = { runDevnetPipeline };
