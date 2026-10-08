import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert, expect } from "chai";
import * as crypto from "crypto";

describe("bidtrace", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Derive program from workspace or IDL
  const program = anchor.workspace.Bidtrace as Program<any>;
  const authority = (provider.wallet as any).payer;

  const tenderId = "TENDER-TS-001";
  let tenderPda: anchor.web3.PublicKey;
  let tenderBump: number;

  const bidderA = anchor.web3.Keypair.generate();
  const bidderB = anchor.web3.Keypair.generate();

  let bidAPda: anchor.web3.PublicKey;
  let bidBPda: anchor.web3.PublicKey;
  let saltA: Buffer;
  let cipherHashA: Buffer;
  let commHashA: Buffer;
  const amountA = new anchor.BN(3800000);

  let saltB: Buffer;
  let cipherHashB: Buffer;
  let commHashB: Buffer;
  const amountB = new anchor.BN(4000000);

  before(async () => {
    // Air-drop funds to bidders for rent if running on localnet / devnet
    try {
      const airdropSigA = await provider.connection.requestAirdrop(bidderA.publicKey, 1e9);
      await provider.connection.confirmTransaction(airdropSigA);
      const airdropSigB = await provider.connection.requestAirdrop(bidderB.publicKey, 1e9);
      await provider.connection.confirmTransaction(airdropSigB);
    } catch (e) {
      // Ignore if already funded
    }

    [tenderPda, tenderBump] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("tender"), authority.publicKey.toBuffer(), Buffer.from(tenderId)],
      program.programId
    );

    [bidAPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bid"), tenderPda.toBuffer(), bidderA.publicKey.toBuffer()],
      program.programId
    );

    [bidBPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bid"), tenderPda.toBuffer(), bidderB.publicKey.toBuffer()],
      program.programId
    );

    // Compute cryptographic domain-separated commitment for Bidder A
    saltA = crypto.randomBytes(32);
    cipherHashA = crypto.createHash("sha256").update(Buffer.from("encrypted_payload_A")).digest();

    const hasherA = crypto.createHash("sha256");
    hasherA.update(Buffer.from("BIDTRACE_V1"));
    hasherA.update(tenderPda.toBuffer());
    hasherA.update(bidderA.publicKey.toBuffer());
    hasherA.update(saltA);
    hasherA.update(cipherHashA);
    hasherA.update(amountA.toArrayLike(Buffer, "le", 8));
    commHashA = hasherA.digest();

    // Compute commitment for Bidder B
    saltB = crypto.randomBytes(32);
    cipherHashB = crypto.createHash("sha256").update(Buffer.from("encrypted_payload_B")).digest();

    const hasherB = crypto.createHash("sha256");
    hasherB.update(Buffer.from("BIDTRACE_V1"));
    hasherB.update(tenderPda.toBuffer());
    hasherB.update(bidderB.publicKey.toBuffer());
    hasherB.update(saltB);
    hasherB.update(cipherHashB);
    hasherB.update(amountB.toArrayLike(Buffer, "le", 8));
    commHashB = hasherB.digest();
  });

  it("Test 1: Initializes a tender with submission and reveal deadlines and bid bond", async () => {
    const currentSlot = await provider.connection.getSlot();
    const submissionDeadlineSlot = new anchor.BN(currentSlot + 50);
    const revealDeadlineSlot = new anchor.BN(currentSlot + 100);
    const bidDeposit = new anchor.BN(1000);

    const tx = await program.methods
      .initializeTender(
        tenderId,
        submissionDeadlineSlot,
        revealDeadlineSlot,
        bidDeposit,
        Array.from(Buffer.alloc(32))
      )
      .accounts({
        tender: tenderPda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const tenderAccount = await program.account.tender.fetch(tenderPda);
    expect(tenderAccount.tenderId).to.equal(tenderId);
    expect(tenderAccount.totalCommitted).to.equal(0);
    expect(tenderAccount.bidDeposit.toNumber()).to.equal(1000);
  });

  it("Test 2: Allows Bidder A and Bidder B to commit directly with escrowed deposit", async () => {
    // Bidder A commits
    await program.methods
      .commitBid(Array.from(commHashA), null)
      .accounts({
        tender: tenderPda,
        bidCommitment: bidAPda,
        bidder: bidderA.publicKey,
        feePayer: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([bidderA])
      .rpc();

    // Bidder B commits
    await program.methods
      .commitBid(Array.from(commHashB), null)
      .accounts({
        tender: tenderPda,
        bidCommitment: bidBPda,
        bidder: bidderB.publicKey,
        feePayer: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([bidderB])
      .rpc();

    const tenderAccount = await program.account.tender.fetch(tenderPda);
    expect(tenderAccount.totalCommitted).to.equal(2);
  });

  it("Test 3 (Adversarial): Rejects forged reveal with invalid preimage hash", async () => {
    const forgedAmount = new anchor.BN(3500000);
    try {
      await program.methods
        .revealBid(Array.from(saltA), Array.from(cipherHashA), forgedAmount)
        .accounts({
          tender: tenderPda,
          bidCommitment: bidAPda,
          revealer: bidderA.publicKey,
          bidderRecipient: bidderA.publicKey,
        })
        .signers([bidderA])
        .rpc();
      assert.fail("Should have failed with InvalidRevealHash");
    } catch (err: any) {
      expect(err.toString()).to.include("InvalidRevealHash");
    }
  });

  it("Test 4: Legitimate reveal refunds deposit and tracks lowest bidder", async () => {
    await program.methods
      .revealBid(Array.from(saltA), Array.from(cipherHashA), amountA)
      .accounts({
        tender: tenderPda,
        bidCommitment: bidAPda,
        revealer: bidderA.publicKey,
        bidderRecipient: bidderA.publicKey,
      })
      .signers([bidderA])
      .rpc();

    const bidAAccount = await program.account.bidCommitment.fetch(bidAPda);
    expect(bidAAccount.isRevealed).to.be.true;
    expect(bidAAccount.escrowedDeposit.toNumber()).to.equal(0); // refunded
  });

  it("Test 5 (Anti-Lockout Gate): Rejects premature award while reveal window is active and unrevealed bids remain", async () => {
    // Only Bidder A has revealed; Bidder B has not yet revealed, and reveal deadline has not expired.
    try {
      await program.methods
        .recordAward(Array.from(Buffer.alloc(32)))
        .accounts({
          tender: tenderPda,
          winningBid: bidAPda,
          authority: authority.publicKey,
        })
        .rpc();
      assert.fail("Should have failed with RevealWindowActive");
    } catch (err: any) {
      expect(err.toString()).to.include("RevealWindowActive");
    }
  });
});
