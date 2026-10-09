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
  const tender = new solanaWeb3.PublicKey(tenderPda.toString ? tenderPda.toString() : tenderPda);
  const bidder = new solanaWeb3.PublicKey(bidderPubkey.toString ? bidderPubkey.toString() : bidderPubkey);
  const tenderBytes = tender.toBytes();
  const bidderBytes = bidder.toBytes();
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
  const auth = new solanaWeb3.PublicKey(authorityPubkey.toString ? authorityPubkey.toString() : authorityPubkey);
  return solanaWeb3.PublicKey.findProgramAddressSync(
    [
      new TextEncoder().encode("tender"),
      auth.toBytes(),
      new TextEncoder().encode(tenderId)
    ],
    BIDTRACE_PROGRAM_ID
  );
}

function findBidCommitmentPDA(tenderPda, bidderPubkey) {
  const tender = new solanaWeb3.PublicKey(tenderPda.toString ? tenderPda.toString() : tenderPda);
  const bidder = new solanaWeb3.PublicKey(bidderPubkey.toString ? bidderPubkey.toString() : bidderPubkey);
  return solanaWeb3.PublicKey.findProgramAddressSync(
    [
      new TextEncoder().encode("bid"),
      tender.toBytes(),
      bidder.toBytes()
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
    this.keypair = null;
    this.isInternal = false;
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
      throw new Error("No Solana wallet extension detected. You can either install Phantom (https://phantom.app/) or click 'Use In-Browser Wallet' to generate an instant zero-install Devnet keypair directly in your browser.");
    }
    this.provider = provider;
    this.keypair = null;
    this.isInternal = false;
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

  async createInBrowserWallet() {
    let secret = localStorage.getItem("bidtrace_devnet_secret");
    let kp;
    if (secret) {
      try {
        kp = solanaWeb3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(secret)));
      } catch (e) {
        kp = solanaWeb3.Keypair.generate();
        localStorage.setItem("bidtrace_devnet_secret", JSON.stringify(Array.from(kp.secretKey)));
      }
    } else {
      kp = solanaWeb3.Keypair.generate();
      localStorage.setItem("bidtrace_devnet_secret", JSON.stringify(Array.from(kp.secretKey)));
    }
    this.keypair = kp;
    this.publicKey = kp.publicKey;
    this.isInternal = true;
    this.isConnected = true;
    this.provider = null;
    this.notifyState();
    return this.publicKey;
  }

  async disconnect() {
    if (this.provider) {
      try { await this.provider.disconnect(); } catch (e) {}
    }
    this.provider = null;
    this.keypair = null;
    this.isInternal = false;
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
        isInternal: this.isInternal,
        publicKey: this.publicKey ? this.publicKey.toBase58() : null
      });
    }
  }

  async getBalance() {
    if (!this.publicKey) return 0;
    try {
      const lamports = await devnetConnection.getBalance(this.publicKey);
      return lamports / solanaWeb3.LAMPORTS_PER_SOL;
    } catch (e) {
      return 0;
    }
  }

  async signAndSendTransaction(transaction, additionalSigners = []) {
    if (!this.isConnected || !this.publicKey) {
      throw new Error("Wallet not connected");
    }

    const { blockhash, lastValidBlockHeight } = await devnetConnection.getLatestBlockhash("confirmed");
    transaction.recentBlockhash = blockhash;
    transaction.feePayer = this.publicKey;

    // Pre-flight simulation check directly against Devnet RPC
    try {
      const sim = await devnetConnection.simulateTransaction(transaction);
      if (sim.value && sim.value.err) {
        const logs = sim.value.logs || [];
        const logsStr = logs.join(" ");
        if (logsStr.includes("already in use") || logsStr.includes("Allocate: account")) {
          if (logsStr.includes("CommitBid")) {
            throw new Error("This wallet has already committed a sealed bid to this tender! Each wallet is restricted to 1 sealed bid per tender to prevent sybil attacks. To submit a competing bid, switch to another account in Phantom.");
          } else {
            throw new Error("Tender account already exists on-chain! Please click '⚡ New ID' to generate a fresh unique tender ID.");
          }
        } else if (logsStr.includes("SubmissionDeadlineExceeded") || logsStr.includes("6002")) {
          throw new Error("The submission window for this Tender has expired! Commitments are frozen.");
        } else if (logsStr.includes("SubmissionDeadlineNotReached") || logsStr.includes("6003")) {
          throw new Error("Consensus slot has not reached the submission deadline yet. Please wait for the deadline to pass before locking the tender.");
        } else if (logsStr.includes("TenderAlreadyLocked") || logsStr.includes("6004")) {
          throw new Error("This Tender has already been locked on-chain.");
        } else if (logsStr.includes("TenderNotLocked") || logsStr.includes("6005")) {
          throw new Error("Tender must be locked before revealing bids. Please execute Step 3 (Lock Tender) first!");
        } else if (logsStr.includes("RevealWindowExpired") || logsStr.includes("6006")) {
          throw new Error("The reveal deadline has expired for this Tender! Reveals are closed.");
        } else if (logsStr.includes("InvalidRevealHash") || logsStr.includes("6007")) {
          throw new Error("Cryptographic verification failed: Domain-separated SHA-256 hash does not match your committed on-chain hash! The smart contract prevented tampered data.");
        } else if (logsStr.includes("BidAlreadyRevealed") || logsStr.includes("6008")) {
          throw new Error("This bid has already been revealed and verified on Devnet.");
        } else if (logsStr.includes("RevealWindowActive") || logsStr.includes("6010")) {
          throw new Error("Cannot award yet! Either all bids must be revealed or the reveal deadline must pass before recording award.");
        } else if (logsStr.includes("WinnerNotRevealed") || logsStr.includes("6011")) {
          throw new Error("Winning bid must be revealed before recording award.");
        } else if (logsStr.includes("WinnerNotLowestBid") || logsStr.includes("6012")) {
          throw new Error("Security rejected! The selected winning bid does not match the lowest revealed bid.");
        } else if (logsStr.includes("insufficient funds") || logsStr.includes("0x1")) {
          throw new Error("Insufficient Devnet SOL to pay for transaction rent. Please click '+ Airdrop' to fund your wallet.");
        } else {
          throw new Error(`Simulation failed: ${JSON.stringify(sim.value.err)}. ${logs.slice(-2).join(" | ")}`);
        }
      }
    } catch (simErr) {
      // Re-throw our explicit helpful simulation errors
      if (simErr.message && (
        simErr.message.includes("already exists") || 
        simErr.message.includes("already committed") || 
        simErr.message.includes("expired") || 
        simErr.message.includes("locked") || 
        simErr.message.includes("Verification") || 
        simErr.message.includes("revealed") || 
        simErr.message.includes("lowest revealed") || 
        simErr.message.includes("Insufficient") || 
        simErr.message.includes("Simulation failed")
      )) {
        throw simErr;
      }
      console.warn("Devnet pre-simulation warning:", simErr);
    }

    if (this.isInternal && this.keypair) {
      transaction.sign(this.keypair, ...additionalSigners);
      const rawTx = transaction.serialize();
      const signature = await devnetConnection.sendRawTransaction(rawTx, { skipPreflight: false });
      
      // Poll confirmation
      for (let i = 0; i < 35; i++) {
        const st = await devnetConnection.getSignatureStatus(signature);
        if (st && st.value && (st.value.confirmationStatus === 'confirmed' || st.value.confirmationStatus === 'finalized')) {
          return signature;
        }
        await new Promise(r => setTimeout(r, 1000));
      }
      return signature;
    } else if (this.provider) {
      let signature;
      if (typeof this.provider.signAndSendTransaction === 'function') {
        const res = await this.provider.signAndSendTransaction(transaction);
        signature = res.signature;
      } else if (typeof this.provider.signTransaction === 'function') {
        const signedTx = await this.provider.signTransaction(transaction);
        signature = await devnetConnection.sendRawTransaction(signedTx.serialize(), { skipPreflight: false });
      } else {
        throw new Error("No compatible signing method on wallet provider");
      }

      for (let i = 0; i < 35; i++) {
        const st = await devnetConnection.getSignatureStatus(signature);
        if (st && st.value && (st.value.confirmationStatus === 'confirmed' || st.value.confirmationStatus === 'finalized')) {
          return signature;
        }
        await new Promise(r => setTimeout(r, 1000));
      }
      return signature;
    } else {
      throw new Error("No signer provider available");
    }
  }
}

async function fetchTenderState(tenderPda) {
  try {
    const pk = new solanaWeb3.PublicKey(tenderPda.toString ? tenderPda.toString() : tenderPda);
    const acc = await devnetConnection.getAccountInfo(pk);
    if (!acc || !acc.data || acc.data.length < 50) return { exists: false };
    const data = acc.data;
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    
    // Authority Pubkey (bytes 8..40)
    const authority = new solanaWeb3.PublicKey(data.subarray(8, 40)).toBase58();
    
    // Tender ID (length prefix at 40..44)
    const idLen = dv.getUint32(40, true);
    const id = new TextDecoder().decode(data.subarray(44, 44 + idLen));
    const offset = 44 + idLen;
    
    // Deadlines & config
    const subDeadline = Number(dv.getBigUint64(offset, true));
    const revDeadline = Number(dv.getBigUint64(offset + 8, true));
    const bond = Number(dv.getBigUint64(offset + 16, true));
    
    // Total counters
    const totalCommitted = dv.getUint32(offset + 56, true);
    const totalRevealed = dv.getUint32(offset + 60, true);
    const lowestRevealedAmount = Number(dv.getBigUint64(offset + 64, true));
    
    // Option<Pubkey> lowest_bidder
    let cur = offset + 72;
    const lowestBidderOpt = data[cur++];
    let lowestBidder = null;
    if (lowestBidderOpt === 1) {
      lowestBidder = new solanaWeb3.PublicKey(data.subarray(cur, cur + 32)).toBase58();
      cur += 32;
    }
    
    // Lifecycle status enum: 0 = Active, 1 = Locked, 2 = Awarded, 3 = Cancelled
    const status = data[cur++];
    
    // Option<Pubkey> winning_bidder
    const winningBidderOpt = data[cur++];
    let winningBidder = null;
    if (winningBidderOpt === 1) {
      winningBidder = new solanaWeb3.PublicKey(data.subarray(cur, cur + 32)).toBase58();
      cur += 32;
    }

    const currentSlot = await devnetConnection.getSlot();
    const isExpired = currentSlot > subDeadline;
    const isRevealExpired = currentSlot > revDeadline;
    const slotsRemaining = Math.max(0, subDeadline - currentSlot);
    const revealSlotsRemaining = Math.max(0, revDeadline - currentSlot);

    return {
      exists: true,
      authority,
      id,
      subDeadline,
      revDeadline,
      bond,
      totalCommitted,
      totalRevealed,
      lowestRevealedAmount,
      lowestBidder,
      status,
      winningBidder,
      currentSlot,
      isExpired,
      isRevealExpired,
      slotsRemaining,
      revealSlotsRemaining
    };
  } catch (e) {
    console.warn("fetchTenderState error:", e);
    return { exists: false };
  }
}

async function fetchBidState(bidPda) {
  try {
    const pk = new solanaWeb3.PublicKey(bidPda.toString ? bidPda.toString() : bidPda);
    const acc = await devnetConnection.getAccountInfo(pk);
    if (!acc || !acc.data || acc.data.length < 130) return { exists: false };
    const data = acc.data;
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const tender = new solanaWeb3.PublicKey(data.subarray(8, 40)).toBase58();
    const bidder = new solanaWeb3.PublicKey(data.subarray(40, 72)).toBase58();
    const commitmentHash = bytesToHex(data.subarray(72, 104));
    const committedAtSlot = Number(dv.getBigUint64(104, true));
    const escrowedDeposit = Number(dv.getBigUint64(112, true));
    const isRevealed = data[120] === 1;
    const revealedAtSlot = Number(dv.getBigUint64(121, true));
    const revealedAmount = Number(dv.getBigUint64(129, true));
    return {
      exists: true,
      tender,
      bidder,
      commitmentHash,
      committedAtSlot,
      escrowedDeposit,
      isRevealed,
      revealedAtSlot,
      revealedAmount
    };
  } catch (e) {
    console.warn("fetchBidState error:", e);
    return { exists: false };
  }
}

window.BidTraceWeb3 = {
  PROGRAM_ID: BIDTRACE_PROGRAM_ID,
  DEVNET_RPC_URL,
  devnetConnection,
  walletManager: new BidTraceWalletManager(),
  findTenderPDA,
  findBidCommitmentPDA,
  fetchTenderState,
  fetchBidState,
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
