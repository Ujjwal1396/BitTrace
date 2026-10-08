/**
 * BidTrace Web3 & Phantom Wallet Integration
 * Connects browser frontend directly to Solana Devnet and deployed Anchor Program.
 * Program ID: x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ
 */

const BIDTRACE_PROGRAM_ID = new solanaWeb3.PublicKey("x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ");
const DEVNET_RPC_URL = "https://api.devnet.solana.com";
const devnetConnection = new solanaWeb3.Connection(DEVNET_RPC_URL, "confirmed");

// Anchor Instruction 8-Byte Discriminators (sha256("global:<name>")[..8])
const DISCRIMINATORS = {
  initializeTender: new Uint8Array([209, 239, 55, 105, 195, 125, 42, 9]),
  commitBid: new Uint8Array([149, 237, 198, 113, 53, 66, 70, 76]),
  lockTender: new Uint8Array([182, 82, 25, 163, 74, 59, 20, 144]),
  revealBid: new Uint8Array([48, 73, 28, 255, 202, 126, 236, 196]),
  recordAward: new Uint8Array([156, 213, 120, 99, 54, 114, 88, 49])
};

// Binary / Borsh Encoding Helpers
function encodeString(str) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, bytes.length, true);
  const out = new Uint8Array(4 + bytes.length);
  out.set(lenBuf, 0);
  out.set(bytes, 4);
  return out;
}

function encodeU64(num) {
  const buf = new Uint8Array(8);
  const bi = typeof num === "bigint" ? num : BigInt(Math.floor(num));
  new DataView(buf.buffer).setBigUint64(0, bi, true);
  return buf;
}

function concatBytes(...arrays) {
  const totalLen = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

// Client-side Cryptographic Commitments (SHA-256 + AES-256)
async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

function getRandomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Domain-separated commitment hash matching Rust Anchor & Python verifier:
 * H("BIDTRACE_V1" || tender_pda || bidder_pubkey || salt || ciphertext_hash || bid_amount_le64)
 */
async function computeBidCommitmentHash(tenderPda, bidderPubkey, saltBytes, ciphertextHashBytes, amount) {
  const domain = new TextEncoder().encode("BIDTRACE_V1");
  const tenderBytes = tenderPda.toBytes();
  const bidderBytes = bidderPubkey.toBytes();
  const amountBytes = encodeU64(amount);

  const preimage = concatBytes(
    domain,
    tenderBytes,
    bidderBytes,
    saltBytes,
    ciphertextHashBytes,
    amountBytes
  );

  return await sha256(preimage);
}

// PDA Derivation
function findTenderPDA(authorityPubkey, tenderId) {
  return solanaWeb3.PublicKey.findProgramAddressSync(
    [
      new TextEncoder().encode("tender"),
      authorityPubkey.toBuffer(),
      new TextEncoder().encode(tenderId)
    ],
    BIDTRACE_PROGRAM_ID
  );
}

function findBidCommitmentPDA(tenderPda, bidderPubkey) {
  return solanaWeb3.PublicKey.findProgramAddressSync(
    [
      new TextEncoder().encode("bid"),
      tenderPda.toBuffer(),
      bidderPubkey.toBuffer()
    ],
    BIDTRACE_PROGRAM_ID
  );
}

// Instruction Builders
function createInitializeTenderInstruction({
  authority,
  tenderId,
  submissionDeadlineSlot,
  revealDeadlineSlot,
  bidDeposit = 0,
  authorizedBiddersRoot = new Uint8Array(32)
}) {
  const [tenderPda] = findTenderPDA(authority, tenderId);

  const data = concatBytes(
    DISCRIMINATORS.initializeTender,
    encodeString(tenderId),
    encodeU64(submissionDeadlineSlot),
    encodeU64(revealDeadlineSlot),
    encodeU64(bidDeposit),
    authorizedBiddersRoot
  );

  const keys = [
    { pubkey: tenderPda, isSigner: false, isWritable: true },
    { pubkey: authority, isSigner: true, isWritable: true },
    { pubkey: solanaWeb3.SystemProgram.programId, isSigner: false, isWritable: false }
  ];

  return {
    instruction: new solanaWeb3.TransactionInstruction({
      programId: BIDTRACE_PROGRAM_ID,
      keys,
      data
    }),
    tenderPda
  };
}

function createCommitBidInstruction({
  tenderPda,
  bidder,
  feePayer,
  commitmentHash
}) {
  const [bidCommitmentPda] = findBidCommitmentPDA(tenderPda, bidder);

  // Whitelist proof: None (1 byte 0x00)
  const optionNone = new Uint8Array([0]);

  const data = concatBytes(
    DISCRIMINATORS.commitBid,
    commitmentHash,
    optionNone
  );

  const keys = [
    { pubkey: tenderPda, isSigner: false, isWritable: true },
    { pubkey: bidCommitmentPda, isSigner: false, isWritable: true },
    { pubkey: bidder, isSigner: true, isWritable: false },
    { pubkey: feePayer, isSigner: true, isWritable: true },
    { pubkey: solanaWeb3.SystemProgram.programId, isSigner: false, isWritable: false }
  ];

  return {
    instruction: new solanaWeb3.TransactionInstruction({
      programId: BIDTRACE_PROGRAM_ID,
      keys,
      data
    }),
    bidCommitmentPda
  };
}

function createLockTenderInstruction({
  tenderPda,
  caller
}) {
  const data = DISCRIMINATORS.lockTender;
  const keys = [
    { pubkey: tenderPda, isSigner: false, isWritable: true },
    { pubkey: caller, isSigner: true, isWritable: false }
  ];

  return new solanaWeb3.TransactionInstruction({
    programId: BIDTRACE_PROGRAM_ID,
    keys,
    data
  });
}

function createRevealBidInstruction({
  tenderPda,
  bidCommitmentPda,
  revealer,
  bidderRecipient,
  salt,
  ciphertextHash,
  bidAmount
}) {
  const data = concatBytes(
    DISCRIMINATORS.revealBid,
    salt,
    ciphertextHash,
    encodeU64(bidAmount)
  );

  const keys = [
    { pubkey: tenderPda, isSigner: false, isWritable: true },
    { pubkey: bidCommitmentPda, isSigner: false, isWritable: true },
    { pubkey: revealer, isSigner: true, isWritable: true },
    { pubkey: bidderRecipient, isSigner: false, isWritable: true }
  ];

  return new solanaWeb3.TransactionInstruction({
    programId: BIDTRACE_PROGRAM_ID,
    keys,
    data
  });
}

function createRecordAwardInstruction({
  tenderPda,
  winningBidPda,
  authority,
  rationaleHash = new Uint8Array(32)
}) {
  const data = concatBytes(
    DISCRIMINATORS.recordAward,
    rationaleHash
  );

  const keys = [
    { pubkey: tenderPda, isSigner: false, isWritable: true },
    { pubkey: winningBidPda, isSigner: false, isWritable: true },
    { pubkey: authority, isSigner: true, isWritable: false }
  ];

  return new solanaWeb3.TransactionInstruction({
    programId: BIDTRACE_PROGRAM_ID,
    keys,
    data
  });
}

// Phantom & Solana Wallet Management
class BidTraceWalletManager {
  constructor() {
    this.provider = null;
    this.publicKey = null;
    this.isConnected = false;
    this.onStateChangeCallbacks = [];
  }

  getWalletProvider() {
    if ("phantom" in window && window.phantom?.solana?.isPhantom) {
      return window.phantom.solana;
    }
    if ("solana" in window && window.solana?.isPhantom) {
      return window.solana;
    }
    if ("solana" in window) {
      return window.solana;
    }
    return null;
  }

  isPhantomInstalled() {
    return !!this.getWalletProvider();
  }

  async connect() {
    const provider = this.getWalletProvider();
    if (!provider) {
      throw new Error("No Solana wallet extension detected. Please install Phantom (https://phantom.app/) or use the Automated Devnet Relayer.");
    }
    this.provider = provider;
    const resp = await this.provider.connect();
    this.publicKey = resp.publicKey;
    this.isConnected = true;
    this.notifyState();

    // Setup listener
    this.provider.on("disconnect", () => {
      this.publicKey = null;
      this.isConnected = false;
      this.notifyState();
    });
    this.provider.on("accountChanged", (pk) => {
      if (pk) {
        this.publicKey = pk;
        this.isConnected = true;
      } else {
        this.publicKey = null;
        this.isConnected = false;
      }
      this.notifyState();
    });

    return this.publicKey;
  }

  async disconnect() {
    if (this.provider) {
      await this.provider.disconnect();
    }
    this.publicKey = null;
    this.isConnected = false;
    this.notifyState();
  }

  onStateChange(cb) {
    this.onStateChangeCallbacks.push(cb);
  }

  notifyState() {
    for (const cb of this.onStateChangeCallbacks) {
      cb({
        isConnected: this.isConnected,
        publicKey: this.publicKey ? this.publicKey.toBase58() : null
      });
    }
  }

  async getBalance() {
    if (!this.publicKey) return 0;
    const lamports = await devnetConnection.getBalance(this.publicKey);
    return lamports / solanaWeb3.LAMPORTS_PER_SOL;
  }

  async signAndSendTransaction(transaction) {
    if (!this.provider || !this.publicKey) {
      throw new Error("Wallet not connected");
    }

    const { blockhash, lastValidBlockHeight } = await devnetConnection.getLatestBlockhash("confirmed");
    transaction.recentBlockhash = blockhash;
    transaction.feePayer = this.publicKey;

    // Use Phantom's signAndSendTransaction
    const { signature } = await this.provider.signAndSendTransaction(transaction);
    await devnetConnection.confirmTransaction({
      signature,
      blockhash,
      lastValidBlockHeight
    }, "confirmed");

    return signature;
  }
}

window.BidTraceWeb3 = {
  PROGRAM_ID: BIDTRACE_PROGRAM_ID,
  DEVNET_RPC_URL,
  devnetConnection,
  walletManager: new BidTraceWalletManager(),
  findTenderPDA,
  findBidCommitmentPDA,
  createInitializeTenderInstruction,
  createCommitBidInstruction,
  createLockTenderInstruction,
  createRevealBidInstruction,
  createRecordAwardInstruction,
  computeBidCommitmentHash,
  getRandomBytes,
  bytesToHex,
  hexToBytes
};
