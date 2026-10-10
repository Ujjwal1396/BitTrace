import * as anchor from "@coral-xyz/anchor";
import * as assert from "assert";
import * as crypto from "crypto";

describe("BidTrace 3.0: Incorruptible Two-Envelope & Blinded Scoring Protocol", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Bidtrace as any;
  const authority = (provider.wallet as any).payer;

  const tenderId = "TENDER-QCBS-2026-001";
  let tenderPda: anchor.web3.PublicKey;
  let committeePda: anchor.web3.PublicKey;

  // Bidders
  const bidderA = anchor.web3.Keypair.generate(); // High tech, compliant price
  const bidderB = anchor.web3.Keypair.generate(); // Low tech, rogue score target
  let bidAPda: anchor.web3.PublicKey;
  let bidBPda: anchor.web3.PublicKey;

  // Evaluators Panel (5 certified evaluators)
  const evaluators = [
    anchor.web3.Keypair.generate(),
    anchor.web3.Keypair.generate(),
    anchor.web3.Keypair.generate(),
    anchor.web3.Keypair.generate(),
    anchor.web3.Keypair.generate(), // Evaluator 5 (potential rogue)
  ];

  // Cryptographic Preimages for Bidder A
  const saltTechA = crypto.randomBytes(32);
  const proposalHashA = crypto.createHash("sha256").update(Buffer.from("BLUEPRINTS_SPEC_A_2026")).digest();
  const saltFinA = crypto.randomBytes(32);
  const boqHashA = crypto.createHash("sha256").update(Buffer.from("BOQ_SCHEDULE_A_USD")).digest();
  const priceA = new anchor.BN(3800000); // $3.80M

  // Cryptographic Preimages for Bidder B
  const saltTechB = crypto.randomBytes(32);
  const proposalHashB = crypto.createHash("sha256").update(Buffer.from("BLUEPRINTS_SPEC_B_2026")).digest();
  const saltFinB = crypto.randomBytes(32);
  const boqHashB = crypto.createHash("sha256").update(Buffer.from("BOQ_SCHEDULE_B_USD")).digest();
  const priceB = new anchor.BN(3500000); // $3.50M (cheaper, but sub-standard quality)

  let commTechA: Buffer;
  let commFinA: Buffer;
  let commTechB: Buffer;
  let commFinB: Buffer;

  // Helpers for domain-separated hashing
  function computeTechCommitment(tender: anchor.web3.PublicKey, bidder: anchor.web3.PublicKey, salt: Buffer, proposal: Buffer): Buffer {
    const h = crypto.createHash("sha256");
    h.update(Buffer.from("BIDTRACE_TECH_V1"));
    h.update(tender.toBuffer());
    h.update(bidder.toBuffer());
    h.update(salt);
    h.update(proposal);
    return h.digest();
  }

  function computeFinCommitment(tender: anchor.web3.PublicKey, bidder: anchor.web3.PublicKey, salt: Buffer, price: anchor.BN, boq: Buffer): Buffer {
    const h = crypto.createHash("sha256");
    h.update(Buffer.from("BIDTRACE_FIN_V1"));
    h.update(tender.toBuffer());
    h.update(bidder.toBuffer());
    h.update(salt);
    h.update(price.toArrayLike(Buffer, "le", 8));
    h.update(boq);
    return h.digest();
  }

  function computeGradeCommitment(tender: anchor.web3.PublicKey, bidder: anchor.web3.PublicKey, evaluator: anchor.web3.PublicKey, salt: Buffer, subScores: number[], justHash: Buffer): Buffer {
    const h = crypto.createHash("sha256");
    h.update(Buffer.from("BIDTRACE_GRADE_V1"));
    h.update(tender.toBuffer());
    h.update(bidder.toBuffer());
    h.update(evaluator.toBuffer());
    h.update(salt);
    for (const score of subScores) {
      const b = Buffer.alloc(2);
      b.writeUInt16LE(score, 0);
      h.update(b);
    }
    h.update(justHash);
    return h.digest();
  }

  before(async () => {
    // Fund test participants
    const accountsToFund = [bidderA.publicKey, bidderB.publicKey, ...evaluators.map(e => e.publicKey)];
    for (const pubkey of accountsToFund) {
      try {
        const sig = await provider.connection.requestAirdrop(pubkey, 2e9);
        await provider.connection.confirmTransaction(sig);
      } catch (err) {
        // Fallback / ignore if already funded in test-validator
      }
    }

    [tenderPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("tender"), authority.publicKey.toBuffer(), Buffer.from(tenderId)],
      program.programId
    );

    [committeePda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("committee"), tenderPda.toBuffer()],
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

    commTechA = computeTechCommitment(tenderPda, bidderA.publicKey, saltTechA, proposalHashA);
    commFinA = computeFinCommitment(tenderPda, bidderA.publicKey, saltFinA, priceA, boqHashA);

    commTechB = computeTechCommitment(tenderPda, bidderB.publicKey, saltTechB, proposalHashB);
    commFinB = computeFinCommitment(tenderPda, bidderB.publicKey, saltTechB, priceB, boqHashB);
  });

  it("Test 1: Authority initializes Two-Envelope QCBS Tender with OCDS Hash and Deadlines", async () => {
    const currentSlot = await provider.connection.getSlot();
    const subSlot = new anchor.BN(currentSlot + 50);
    const adminSlot = new anchor.BN(currentSlot + 50);
    const techSlot = new anchor.BN(currentSlot + 100);
    const finSlot = new anchor.BN(currentSlot + 150);

    const ocdsNoticeHash = crypto.createHash("sha256").update(Buffer.from("OCDS_1_1_TENDER_NOTICE_RFC8785")).digest();

    await program.methods
      .initializeTender(
        tenderId,
        Array.from(ocdsNoticeHash),
        { postQualifiedOpen: {} }, // Model B: Open tender with bond escrow
        { qcbs: {} },              // QCBS 70/30
        subSlot,
        adminSlot,
        techSlot,
        finSlot,
        Array.from(Buffer.alloc(32)), // authorized_bidders_root
        7500, // min_tech_score_bps: 75.00% cutoff threshold
        7000, // tech_weight_bps: 70.00%
        3000  // fin_weight_bps: 30.00%
      )
      .accounts({
        tender: tenderPda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const tender = await program.account.tender.fetch(tenderPda);
    assert.strictEqual(tender.tenderId, tenderId);
    assert.strictEqual(tender.minTechScoreBps, 7500);
    assert.strictEqual(tender.techWeightBps, 7000);
    assert.strictEqual(tender.finWeightBps, 3000);
  });

  it("Test 2: Authority initializes Tender Committee with 5 accredited evaluators", async () => {
    await program.methods
      .initializeCommittee(
        evaluators.map(e => e.publicKey),
        2000 // 20.00% max variance tolerance
      )
      .accounts({
        tender: tenderPda,
        committee: committeePda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const committee = await program.account.tenderCommittee.fetch(committeePda);
    assert.strictEqual(committee.evaluators.length, 5);
    assert.strictEqual(committee.maxVarianceBps, 2000);
    assert.strictEqual(committee.isLocked, true);
  });

  it("Test 3: Contractors submit confidential Dual-Envelope Bids (A & B)", async () => {
    const adminDossierA = crypto.createHash("sha256").update(Buffer.from("TAX_ISO_AUDIT_ACME")).digest();
    const adminDossierB = crypto.createHash("sha256").update(Buffer.from("TAX_ISO_AUDIT_BUILDCO")).digest();

    // Bidder A commits
    await program.methods
      .commitDualBid(
        Array.from(adminDossierA),
        Array.from(commTechA),
        Array.from(commFinA),
        { solanaEscrow: {} },
        new anchor.BN(1000),
        null
      )
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
      .commitDualBid(
        Array.from(adminDossierB),
        Array.from(commTechB),
        Array.from(commFinB),
        { solanaEscrow: {} },
        new anchor.BN(1000),
        null
      )
      .accounts({
        tender: tenderPda,
        bidCommitment: bidBPda,
        bidder: bidderB.publicKey,
        feePayer: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([bidderB])
      .rpc();

    const tender = await program.account.tender.fetch(tenderPda);
    assert.strictEqual(tender.totalCommitted, 2);
  });

  it("Test 4: Tender advances to Technical Evaluation and unseals Envelope A", async () => {
    // Advance phase
    await program.methods
      .advanceTenderPhase()
      .accounts({
        tender: tenderPda,
        caller: authority.publicKey,
      })
      .rpc();

    // Bidder A reveals Envelope A
    await program.methods
      .revealTechnicalBid(Array.from(saltTechA), Array.from(proposalHashA))
      .accounts({
        tender: tenderPda,
        bidCommitment: bidAPda,
        revealer: bidderA.publicKey,
      })
      .signers([bidderA])
      .rpc();

    // Bidder B reveals Envelope A
    await program.methods
      .revealTechnicalBid(Array.from(saltTechB), Array.from(proposalHashB))
      .accounts({
        tender: tenderPda,
        bidCommitment: bidBPda,
        revealer: bidderB.publicKey,
      })
      .signers([bidderB])
      .rpc();

    const bidA = await program.account.dualBidCommitment.fetch(bidAPda);
    const bidB = await program.account.dualBidCommitment.fetch(bidBPda);
    assert.strictEqual(bidA.isTechRevealed, true);
    assert.strictEqual(bidB.isTechRevealed, true);
  });

  // Storage for grade salts and preimages
  const gradesA: { salt: Buffer; subScores: [number, number, number, number, number]; justHash: Buffer; pda: anchor.web3.PublicKey }[] = [];
  const gradesB: { salt: Buffer; subScores: [number, number, number, number, number]; justHash: Buffer; pda: anchor.web3.PublicKey }[] = [];

  it("Test 5: Evaluators submit and unseal blinded grades (including adversarial outlier)", async () => {
    // Scoring setup for Bidder A: Consistently high marks (around 82.00%)
    // Sub-scores: [2000, 1500, 2200, 1300, 1200] = 8200
    const scoresA: [number, number, number, number, number][] = [
      [2000, 1500, 2200, 1300, 1200], // 8200
      [1950, 1500, 2150, 1300, 1200], // 8100
      [2050, 1500, 2250, 1300, 1200], // 8300
      [1900, 1500, 2100, 1300, 1200], // 8000
      [2000, 1500, 2200, 1350, 1200], // 8250
    ];

    // Scoring setup for Bidder B: Honest evaluators give sub-cutoff marks (~64.00%),
    // Rogue Evaluator 5 gives inflated 98.00% to attempt illegal favoritism.
    const scoresB: [number, number, number, number, number][] = [
      [1500, 1200, 1600, 1100, 1000], // 6400
      [1450, 1200, 1550, 1100, 1000], // 6300
      [1550, 1200, 1650, 1100, 1000], // 6500
      [1400, 1200, 1500, 1100, 1000], // 6200
      [2500, 2000, 2500, 1500, 1300], // 9800 (Rogue Outlier!)
    ];

    // Commit and Reveal for Bidder A across all 5 evaluators
    for (let i = 0; i < 5; i++) {
      const ev = evaluators[i];
      const salt = crypto.randomBytes(32);
      const justHash = crypto.createHash("sha256").update(Buffer.from(`JUSTIFICATION_A_EV_${i}`)).digest();
      const subScores = scoresA[i];
      const commHash = computeGradeCommitment(tenderPda, bidderA.publicKey, ev.publicKey, salt, subScores, justHash);

      const [gradePda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("grade"), tenderPda.toBuffer(), ev.publicKey.toBuffer(), bidderA.publicKey.toBuffer()],
        program.programId
      );
      gradesA.push({ salt, subScores, justHash, pda: gradePda });

      // Commit
      await program.methods
        .commitEvaluatorGrade(Array.from(commHash))
        .accounts({
          tender: tenderPda,
          committee: committeePda,
          bidCommitment: bidAPda,
          evaluatorGrade: gradePda,
          evaluator: ev.publicKey,
          bidder: bidderA.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([ev])
        .rpc();

      // Reveal
      await program.methods
        .revealEvaluatorGrade(subScores, Array.from(salt), Array.from(justHash))
        .accounts({
          tender: tenderPda,
          committee: committeePda,
          evaluatorGrade: gradePda,
          evaluator: ev.publicKey,
          bidder: bidderA.publicKey,
        })
        .signers([ev])
        .rpc();
    }

    // Commit and Reveal for Bidder B across all 5 evaluators
    for (let i = 0; i < 5; i++) {
      const ev = evaluators[i];
      const salt = crypto.randomBytes(32);
      const justHash = crypto.createHash("sha256").update(Buffer.from(`JUSTIFICATION_B_EV_${i}`)).digest();
      const subScores = scoresB[i];
      const commHash = computeGradeCommitment(tenderPda, bidderB.publicKey, ev.publicKey, salt, subScores, justHash);

      const [gradePda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("grade"), tenderPda.toBuffer(), ev.publicKey.toBuffer(), bidderB.publicKey.toBuffer()],
        program.programId
      );
      gradesB.push({ salt, subScores, justHash, pda: gradePda });

      // Commit
      await program.methods
        .commitEvaluatorGrade(Array.from(commHash))
        .accounts({
          tender: tenderPda,
          committee: committeePda,
          bidCommitment: bidBPda,
          evaluatorGrade: gradePda,
          evaluator: ev.publicKey,
          bidder: bidderB.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([ev])
        .rpc();

      // Reveal
      await program.methods
        .revealEvaluatorGrade(subScores, Array.from(salt), Array.from(justHash))
        .accounts({
          tender: tenderPda,
          committee: committeePda,
          evaluatorGrade: gradePda,
          evaluator: ev.publicKey,
          bidder: bidderB.publicKey,
        })
        .signers([ev])
        .rpc();
    }
  });

  it("Test 6: On-chain Olympic Trimmed Mean flags Rogue Evaluator & Qualifies Bidder A while Disqualifying Bidder B", async () => {
    // 1. Finalize Bidder B scores
    await program.methods
      .finalizeTechnicalScores()
      .accounts({
        tender: tenderPda,
        committee: committeePda,
        bidCommitment: bidBPda,
        authority: authority.publicKey,
      })
      .remainingAccounts(gradesB.map(g => ({
        pubkey: g.pda,
        isWritable: true,
        isSigner: false,
      })))
      .rpc();

    const bidB = await program.account.dualBidCommitment.fetch(bidBPda);
    // Trimmed mean drops min (6200) and max (9800), leaving [6300, 6400, 6500] -> avg = 6400 bps (< 7500)
    assert.strictEqual(bidB.isTechQualified, false);
    assert.ok(bidB.technicalScoreBps < 7500);

    // Verify Rogue Evaluator was permanently flagged in account state
    const rogueGrade = await program.account.evaluatorGrade.fetch(gradesB[4].pda);
    assert.strictEqual(rogueGrade.isOutlierFlagged, true);

    // 2. Finalize Bidder A scores
    await program.methods
      .finalizeTechnicalScores()
      .accounts({
        tender: tenderPda,
        committee: committeePda,
        bidCommitment: bidAPda,
        authority: authority.publicKey,
      })
      .remainingAccounts(gradesA.map(g => ({
        pubkey: g.pda,
        isWritable: true,
        isSigner: false,
      })))
      .rpc();

    const bidA = await program.account.dualBidCommitment.fetch(bidAPda);
    assert.strictEqual(bidA.isTechQualified, true);
    assert.ok(bidA.technicalScoreBps >= 7500);
  });

  it("Test 7 (Commercial Secrecy Invariant): Disqualified Bidder B is strictly prevented from unsealing Financial Envelope", async () => {
    // Advance to Financial Evaluation phase
    await program.methods
      .advanceTenderPhase()
      .accounts({
        tender: tenderPda,
        caller: authority.publicKey,
      })
      .rpc();

    try {
      await program.methods
        .revealFinancialEnvelope(Array.from(saltFinB), priceB, Array.from(boqHashB))
        .accounts({
          tender: tenderPda,
          bidCommitment: bidBPda,
          revealer: bidderB.publicKey,
          bidderRecipient: bidderB.publicKey,
        })
        .signers([bidderB])
        .rpc();
      assert.fail("Disqualified bidder should never be allowed to reveal financial envelope!");
    } catch (err: any) {
      assert.ok(err.toString().includes("BidderTechnicallyDisqualified"));
    }

    // Confirm Bidder B financial envelope remains sealed
    const bidB = await program.account.dualBidCommitment.fetch(bidBPda);
    assert.strictEqual(bidB.isFinRevealed, false);
    assert.strictEqual(bidB.revealedPrice.toNumber(), 0);
  });

  it("Test 7b (SEC-01 Fix): Disqualified Bidder B reclaims escrowed bond without leaking Envelope B", async () => {
    // Check initial state of Bidder B
    const bidBBefore = await program.account.dualBidCommitment.fetch(bidBPda);
    assert.strictEqual(bidBBefore.isBondSettled, false);
    assert.strictEqual(bidBBefore.isTechQualified, false);
    assert.strictEqual(bidBBefore.isFinRevealed, false);
    assert.strictEqual(bidBBefore.bondAmount.toNumber(), 1000);

    // Qualified Bidder A attempts to call refundDisqualifiedBond -> must fail with BidderIsTechQualified!
    try {
      await program.methods
        .refundDisqualifiedBond()
        .accounts({
          tender: tenderPda,
          bidCommitment: bidAPda,
          bidderRecipient: bidderA.publicKey,
          caller: bidderA.publicKey,
        })
        .signers([bidderA])
        .rpc();
      assert.fail("Qualified bidder should NOT be allowed to call refundDisqualifiedBond!");
    } catch (err: any) {
      assert.ok(err.toString().includes("BidderIsTechQualified"));
    }

    // Balance before refund
    const balBefore = await provider.connection.getBalance(bidderB.publicKey);

    // Bidder B (or sponsored relayer) successfully executes refundDisqualifiedBond
    await program.methods
      .refundDisqualifiedBond()
      .accounts({
        tender: tenderPda,
        bidCommitment: bidBPda,
        bidderRecipient: bidderB.publicKey,
        caller: authority.publicKey, // authority or sponsored relayer signs as caller
      })
      .rpc();

    // Verify bond is settled
    const bidBAfter = await program.account.dualBidCommitment.fetch(bidBPda);
    assert.strictEqual(bidBAfter.isBondSettled, true);
    // CRITICAL: Commercial Secrecy still 100% intact!
    assert.strictEqual(bidBAfter.isFinRevealed, false);
    assert.strictEqual(bidBAfter.revealedPrice.toNumber(), 0);

    // Verify balance increased by bondAmount (1000 lamports)
    const balAfter = await provider.connection.getBalance(bidderB.publicKey);
    assert.strictEqual(balAfter - balBefore, 1000);

    // Attempting double refund must fail with BondAlreadySettled!
    try {
      await program.methods
        .refundDisqualifiedBond()
        .accounts({
          tender: tenderPda,
          bidCommitment: bidBPda,
          bidderRecipient: bidderB.publicKey,
          caller: authority.publicKey,
        })
        .rpc();
      assert.fail("Double refund must fail!");
    } catch (err: any) {
      assert.ok(err.toString().includes("BondAlreadySettled"));
    }
  });

  it("Test 8: Qualified Bidder A unseals Financial Envelope and wins QCBS Award", async () => {
    // 1. Bidder A legitimately reveals financial envelope
    await program.methods
      .revealFinancialEnvelope(Array.from(saltFinA), priceA, Array.from(boqHashA))
      .accounts({
        tender: tenderPda,
        bidCommitment: bidAPda,
        revealer: bidderA.publicKey,
        bidderRecipient: bidderA.publicKey,
      })
      .signers([bidderA])
      .rpc();

    const bidA = await program.account.dualBidCommitment.fetch(bidAPda);
    assert.strictEqual(bidA.isFinRevealed, true);
    assert.strictEqual(bidA.revealedPrice.toNumber(), 3800000);

    // 2. Authority records QCBS Award
    const rationaleHash = crypto.createHash("sha256").update(Buffer.from("FINAL_AWARD_DETERMINATION_MEMO")).digest();

    await program.methods
      .recordAwardQcbs(Array.from(rationaleHash))
      .accounts({
        tender: tenderPda,
        winningBid: bidAPda,
        authority: authority.publicKey,
      })
      .rpc();

    const finalTender = await program.account.tender.fetch(tenderPda);
    assert.strictEqual(finalTender.winningBidder.toBase58(), bidderA.publicKey.toBase58());
    assert.deepStrictEqual(finalTender.status, { awarded: {} });
    assert.ok(finalTender.highestCompositeScore.toNumber() > 8000);
  });
});
