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

const BIDTRACE_PROGRAM_ID = new solanaWeb3.PublicKey("x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ");
const DEVNET_RPC = "https://api.devnet.solana.com";
const devnetConnection = new solanaWeb3.Connection(DEVNET_RPC, "confirmed");

const userPubkey = new solanaWeb3.PublicKey("9DdVGb1TE2gMcsuBU32GL3yAxXnPUoETjqNqFAjDTa6d");

const DISCRIMINATORS = {
  initializeTender: new Uint8Array([209, 239, 55, 105, 195, 125, 42, 9]),
  commitBid: new Uint8Array([149, 237, 198, 113, 53, 66, 70, 76]),
  lockTender: new Uint8Array([182, 82, 25, 163, 74, 59, 20, 144]),
  revealBid: new Uint8Array([48, 73, 28, 255, 202, 126, 236, 196]),
  recordAward: new Uint8Array([156, 213, 120, 99, 54, 114, 88, 49])
};

function encodeString(str) {
  const bytes = Buffer.from(str, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32LE(bytes.length, 0);
  return Buffer.concat([len, bytes]);
}

function encodeU64(num) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(num), 0);
  return buf;
}

function concatBytes(...arrays) {
  return Buffer.concat(arrays.map(a => Buffer.from(a)));
}

async function testSimulate() {
  console.log("Checking User Balance on Devnet...");
  const balance = await devnetConnection.getBalance(userPubkey);
  console.log("User Pubkey:", userPubkey.toBase58());
  console.log("User Devnet Balance:", balance / solanaWeb3.LAMPORTS_PER_SOL, "SOL");

  const currentSlot = await devnetConnection.getSlot();
  console.log("Current Slot:", currentSlot);

  const tenderId = "TENDER-TEST-" + Math.floor(Date.now() / 1000);
  const [tenderPda] = solanaWeb3.PublicKey.findProgramAddressSync(
    [
      Buffer.from("tender"),
      userPubkey.toBuffer(),
      Buffer.from(tenderId)
    ],
    BIDTRACE_PROGRAM_ID
  );
  console.log("Tender PDA:", tenderPda.toBase58());

  const subSlot = currentSlot + 100;
  const revSlot = subSlot + 150;
  const bond = 1000;

  const data = concatBytes(
    DISCRIMINATORS.initializeTender,
    encodeString(tenderId),
    encodeU64(subSlot),
    encodeU64(revSlot),
    encodeU64(bond),
    new Uint8Array(32)
  );

  const keys = [
    { pubkey: tenderPda, isSigner: false, isWritable: true },
    { pubkey: userPubkey, isSigner: true, isWritable: true },
    { pubkey: solanaWeb3.SystemProgram.programId, isSigner: false, isWritable: false }
  ];

  const instruction = new solanaWeb3.TransactionInstruction({
    programId: BIDTRACE_PROGRAM_ID,
    keys,
    data
  });

  const tx = new solanaWeb3.Transaction().add(instruction);
  const { blockhash } = await devnetConnection.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey;

  console.log("\nSimulating Transaction on Devnet...");
  const sim = await devnetConnection.simulateTransaction(tx);
  console.log("Simulation Result:", JSON.stringify(sim, null, 2));
}

testSimulate().catch(console.error);
