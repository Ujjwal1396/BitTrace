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
  const bidderD = anchor.web3.Keypair.generate();

  let bidAPda: anchor.web3.PublicKey;
  let saltA: Buffer;
  let cipherHashA: Buffer;
  let commHashA: Buffer;
  const amountA = new anchor.BN(4200000);

  before(async () => {
    // Air-drop funds to bidders for rent if running on localnet
    try {
      const airdropSigA = await provider.connection.requestAirdrop(bidderA.publicKey, 1e9);
      await provider.connection.confirmTransaction(airdropSigA);
      const airdropSigB = await provider.connection.requestAirdrop(bidderB.publicKey, 1e9);
      await provider.connection.confirmTransaction(airdropSigB);
    } catch (e) {
      // Ignore if on mock or already funded
    }

    [tenderPda, tenderBump] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("tender"), authority.publicKey.toBuffer(), Buffer.from(tenderId)],
      program.programId
    );

    [bidAPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bid"), tenderPda.toBuffer(), bidderA.publicKey.toBuffer()],
      program.programId
    );

    // Compute cryptographic domain-separated commitment for Bidder A
    saltA = crypto.randomBytes(32);
    cipherHashA = crypto.createHash("sha256").update(Buffer.from("encrypted_payload_A")).digest();

    const hasher = crypto.createHash("sha256");
    hasher.update(Buffer.from("BIDTRACE_V1"));
    hasher.update(tenderPda.toBuffer());
    hasher.update(bidderA.publicKey.toBuffer());
    hasher.update(saltA);
    hasher.update(cipherHashA);
    hasher.update(amountA.toArrayLike(Buffer, "le", 8));
    commHashA = hasher.digest();
  });

  it("Test 1: Initializes a tender with deadline slot", async () => {
    const currentSlot = await provider.connection.getSlot();
    const deadlineSlot = new anchor.BN(currentSlot + 50);

    const tx = await program.methods
      .initializeTender(tenderId, deadlineSlot, Array.from(Buffer.alloc(32)))
      .accounts({
        tender: tenderPda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const tenderAccount = await program.account.tender.fetch(tenderPda);
    expect(tenderAccount.tenderId).to.equal(tenderId);
    expect(tenderAccount.totalCommitted).to.equal(0);
  });

  it("Test 2: Allows Bidder A to commit directly to PDA pre-deadline (Flaw A resolution)", async () => {
    const tx = await program.methods
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

    const bidAccount = await program.account.bidCommitment.fetch(bidAPda);
    expect(bidAccount.bidder.toBase58()).to.equal(bidderA.publicKey.toBase58());
    expect(bidAccount.isRevealed).to.be.false;

    const tenderAccount = await program.account.tender.fetch(tenderPda);
    expect(tenderAccount.totalCommitted).to.equal(1);
  });

  it("Test 3 (Adversarial): Rejects forged reveal with invalid hash", async () => {
    // Note: Assuming tender is locked in real flow.
    // When attempting to reveal with wrong amount (e.g. 3,800,000 instead of 4,200,000):
    const forgedAmount = new anchor.BN(3800000);
    try {
      await program.methods
        .revealBid(Array.from(saltA), Array.from(cipherHashA), forgedAmount)
        .accounts({
          tender: tenderPda,
          bidCommitment: bidAPda,
          revealer: bidderA.publicKey,
        })
        .signers([bidderA])
        .rpc();
      assert.fail("Should have failed with InvalidRevealHash");
    } catch (err: any) {
      expect(err.toString()).to.include("InvalidRevealHash");
    }
  });
});
