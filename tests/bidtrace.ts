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
  let subSlot: anchor.BN;
  let adminSlot: anchor.BN;
  let techSlot: anchor.BN;
  let finSlot: anchor.BN;

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
    subSlot = new anchor.BN(currentSlot + 6);
    adminSlot = new anchor.BN(currentSlot + 6);
    techSlot = new anchor.BN(currentSlot + 45);
    finSlot = new anchor.BN(currentSlot + 150);

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
    // SEC-03: Authority Early-Lockout Denial-of-Service Defense Test
    // Verify that premature advance before submission deadline is strictly rejected even by authority
    const slotBefore = await provider.connection.getSlot();
    if (slotBefore <= subSlot.toNumber()) {
      try {
        await program.methods
          .advanceTenderPhase()
          .accounts({
            tender: tenderPda,
            caller: authority.publicKey,
          })
          .rpc();
        assert.fail("Should have failed with SubmissionDeadlineNotReached");
      } catch (err: any) {
        assert.ok(
          err.toString().includes("SubmissionDeadlineNotReached") || err.toString().includes("6003"),
          `Expected SubmissionDeadlineNotReached, got: ${err}`
        );
      }
    }

    // Wait until consensus slot advances past submission deadline
    while ((await provider.connection.getSlot()) <= subSlot.toNumber()) {
      await new Promise(r => setTimeout(r, 200));
    }

    // Advance phase legitimately once deadline has passed
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
    // SEC-05: Evaluator Cherry-Picking Rejection (3 of 5 and 4 of 5 grades submitted)
    try {
      await program.methods
        .finalizeTechnicalScores()
        .accounts({
          tender: tenderPda,
          committee: committeePda,
          bidCommitment: bidBPda,
          authority: authority.publicKey,
        })
        .remainingAccounts(gradesB.slice(0, 3).map(g => ({
          pubkey: g.pda,
          isWritable: true,
          isSigner: false,
        })))
        .rpc();
      assert.fail("Should have failed with IncompleteCommitteeGrades (3 of 5)");
    } catch (err: any) {
      assert.ok(
        err.toString().includes("IncompleteCommitteeGrades") || err.toString().includes("6043"),
        `Expected IncompleteCommitteeGrades, got: ${err}`
      );
    }

    try {
      await program.methods
        .finalizeTechnicalScores()
        .accounts({
          tender: tenderPda,
          committee: committeePda,
          bidCommitment: bidBPda,
          authority: authority.publicKey,
        })
        .remainingAccounts(gradesB.slice(0, 4).map(g => ({
          pubkey: g.pda,
          isWritable: true,
          isSigner: false,
        })))
        .rpc();
      assert.fail("Should have failed with IncompleteCommitteeGrades (4 of 5)");
    } catch (err: any) {
      assert.ok(
        err.toString().includes("IncompleteCommitteeGrades") || err.toString().includes("6043"),
        `Expected IncompleteCommitteeGrades, got: ${err}`
      );
    }

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
    // SEC-03: Verify that premature advance to Financial Evaluation before tech deadline is strictly rejected even by authority
    const slotBeforeTech = await provider.connection.getSlot();
    if (slotBeforeTech <= techSlot.toNumber()) {
      try {
        await program.methods
          .advanceTenderPhase()
          .accounts({
            tender: tenderPda,
            caller: authority.publicKey,
          })
          .rpc();
        assert.fail("Should have failed with TechEvalDeadlineNotReached");
      } catch (err: any) {
        assert.ok(
          err.toString().includes("TechEvalDeadlineNotReached") || err.toString().includes("6039"),
          `Expected TechEvalDeadlineNotReached, got: ${err}`
        );
      }
    }

    // Wait until consensus slot advances past tech evaluation deadline
    while ((await provider.connection.getSlot()) <= techSlot.toNumber()) {
      await new Promise(r => setTimeout(r, 200));
    }

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

  it("Test 8b (SEC-04 Fix): Anti-Arbitrary Winner Verification & Zero-Price Guard in QCBS Mode", async () => {
    // 1. Initialize a second tender specifically to test multi-bidder QCBS competitive award
    const sec04TenderId = "TENDER-QCBS-SEC04-001";
    const [tenderSec04Pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("tender"), authority.publicKey.toBuffer(), Buffer.from(sec04TenderId)],
      program.programId
    );
    const [commSec04Pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("committee"), tenderSec04Pda.toBuffer()],
      program.programId
    );

    const b1Keypair = anchor.web3.Keypair.generate();
    const b2Keypair = anchor.web3.Keypair.generate();

    // Fund b1 and b2
    const fundTx1 = new anchor.web3.Transaction().add(
      anchor.web3.SystemProgram.transfer({
        fromPubkey: authority.publicKey,
        toPubkey: b1Keypair.publicKey,
        lamports: 5e8,
      }),
      anchor.web3.SystemProgram.transfer({
        fromPubkey: authority.publicKey,
        toPubkey: b2Keypair.publicKey,
        lamports: 5e8,
      })
    );
    await provider.sendAndConfirm(fundTx1);

    const [b1Pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bid"), tenderSec04Pda.toBuffer(), b1Keypair.publicKey.toBuffer()],
      program.programId
    );
    const [b2Pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bid"), tenderSec04Pda.toBuffer(), b2Keypair.publicKey.toBuffer()],
      program.programId
    );

    const curSlot = await provider.connection.getSlot();
    const sec04SubSlot = new anchor.BN(curSlot + 4);
    const sec04AdminSlot = sec04SubSlot; // Direct progression to TechnicalEvaluation
    const sec04TechSlot = new anchor.BN(curSlot + 25);
    const sec04FinSlot = new anchor.BN(curSlot + 150);

    const noticeHash = crypto.createHash("sha256").update(Buffer.from("NOTICE_SEC04")).digest();

    await program.methods
      .initializeTender(
        sec04TenderId,
        Array.from(noticeHash),
        { postQualifiedOpen: {} },
        { qcbs: {} },
        sec04SubSlot,
        sec04AdminSlot,
        sec04TechSlot,
        sec04FinSlot,
        Array.from(Buffer.alloc(32)),
        7500, // 75.00% cutoff
        7000, // 70.00% tech weight
        3000  // 30.00% fin weight
      )
      .accounts({
        tender: tenderSec04Pda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // Committee of 3 evaluators
    await program.methods
      .initializeCommittee(
        evaluators.slice(0, 3).map(e => e.publicKey),
        2000
      )
      .accounts({
        tender: tenderSec04Pda,
        committee: commSec04Pda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // Commit dual bids
    const sTech1 = crypto.randomBytes(32);
    const pHash1 = crypto.createHash("sha256").update(Buffer.from("PROP_1")).digest();
    const sFin1 = crypto.randomBytes(32);
    const bHash1 = crypto.createHash("sha256").update(Buffer.from("BOQ_1")).digest();
    const price1 = new anchor.BN(3800000); // $3.80M

    const sTech2 = crypto.randomBytes(32);
    const pHash2 = crypto.createHash("sha256").update(Buffer.from("PROP_2")).digest();
    const sFin2 = crypto.randomBytes(32);
    const bHash2 = crypto.createHash("sha256").update(Buffer.from("BOQ_2")).digest();
    const price2 = new anchor.BN(3500000); // $3.50M (lowest price)

    const cTech1 = computeTechCommitment(tenderSec04Pda, b1Keypair.publicKey, sTech1, pHash1);
    const cFin1 = computeFinCommitment(tenderSec04Pda, b1Keypair.publicKey, sFin1, price1, bHash1);
    const cTech2 = computeTechCommitment(tenderSec04Pda, b2Keypair.publicKey, sTech2, pHash2);
    const cFin2 = computeFinCommitment(tenderSec04Pda, b2Keypair.publicKey, sFin2, price2, bHash2);

    await program.methods
      .commitDualBid(Array.from(Buffer.alloc(32)), Array.from(cTech1), Array.from(cFin1), { solanaEscrow: {} }, new anchor.BN(100), null)
      .accounts({
        tender: tenderSec04Pda,
        bidCommitment: b1Pda,
        bidder: b1Keypair.publicKey,
        feePayer: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([b1Keypair])
      .rpc();

    await program.methods
      .commitDualBid(Array.from(Buffer.alloc(32)), Array.from(cTech2), Array.from(cFin2), { solanaEscrow: {} }, new anchor.BN(100), null)
      .accounts({
        tender: tenderSec04Pda,
        bidCommitment: b2Pda,
        bidder: b2Keypair.publicKey,
        feePayer: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([b2Keypair])
      .rpc();

    // Wait past submission deadline
    while ((await provider.connection.getSlot()) <= sec04SubSlot.toNumber()) {
      await new Promise(r => setTimeout(r, 200));
    }

    // Advance to TechnicalEvaluation
    await program.methods
      .advanceTenderPhase()
      .accounts({
        tender: tenderSec04Pda,
        caller: authority.publicKey,
      })
      .rpc();

    // Reveal Technical
    await program.methods
      .revealTechnicalBid(Array.from(sTech1), Array.from(pHash1))
      .accounts({ tender: tenderSec04Pda, bidCommitment: b1Pda, revealer: b1Keypair.publicKey })
      .signers([b1Keypair])
      .rpc();

    await program.methods
      .revealTechnicalBid(Array.from(sTech2), Array.from(pHash2))
      .accounts({ tender: tenderSec04Pda, bidCommitment: b2Pda, revealer: b2Keypair.publicKey })
      .signers([b2Keypair])
      .rpc();

    // Grade both bidders with 3 evaluators
    // Bidder 1: high marks (90.00% = 9000 bps)
    // Bidder 2: passing marks (78.00% = 7800 bps)
    const grades1: { pda: anchor.web3.PublicKey }[] = [];
    const grades2: { pda: anchor.web3.PublicKey }[] = [];

    for (let i = 0; i < 3; i++) {
      const ev = evaluators[i];
      const saltG1 = crypto.randomBytes(32);
      const justG1 = crypto.createHash("sha256").update(Buffer.from(`JUST_1_${i}`)).digest();
      const subG1: [number, number, number, number, number] = [1800, 1800, 1800, 1800, 1800]; // 9000 bps
      const commG1 = computeGradeCommitment(tenderSec04Pda, b1Keypair.publicKey, ev.publicKey, saltG1, subG1, justG1);
      const [g1Pda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("grade"), tenderSec04Pda.toBuffer(), ev.publicKey.toBuffer(), b1Keypair.publicKey.toBuffer()],
        program.programId
      );
      grades1.push({ pda: g1Pda });

      await program.methods
        .commitEvaluatorGrade(Array.from(commG1))
        .accounts({
          tender: tenderSec04Pda,
          committee: commSec04Pda,
          bidCommitment: b1Pda,
          evaluatorGrade: g1Pda,
          evaluator: ev.publicKey,
          bidder: b1Keypair.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([ev])
        .rpc();

      await program.methods
        .revealEvaluatorGrade(subG1, Array.from(saltG1), Array.from(justG1))
        .accounts({
          tender: tenderSec04Pda,
          committee: commSec04Pda,
          evaluatorGrade: g1Pda,
          evaluator: ev.publicKey,
          bidder: b1Keypair.publicKey,
        })
        .signers([ev])
        .rpc();

      const saltG2 = crypto.randomBytes(32);
      const justG2 = crypto.createHash("sha256").update(Buffer.from(`JUST_2_${i}`)).digest();
      const subG2: [number, number, number, number, number] = [1560, 1560, 1560, 1560, 1560]; // 7800 bps
      const commG2 = computeGradeCommitment(tenderSec04Pda, b2Keypair.publicKey, ev.publicKey, saltG2, subG2, justG2);
      const [g2Pda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("grade"), tenderSec04Pda.toBuffer(), ev.publicKey.toBuffer(), b2Keypair.publicKey.toBuffer()],
        program.programId
      );
      grades2.push({ pda: g2Pda });

      await program.methods
        .commitEvaluatorGrade(Array.from(commG2))
        .accounts({
          tender: tenderSec04Pda,
          committee: commSec04Pda,
          bidCommitment: b2Pda,
          evaluatorGrade: g2Pda,
          evaluator: ev.publicKey,
          bidder: b2Keypair.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([ev])
        .rpc();

      await program.methods
        .revealEvaluatorGrade(subG2, Array.from(saltG2), Array.from(justG2))
        .accounts({
          tender: tenderSec04Pda,
          committee: commSec04Pda,
          evaluatorGrade: g2Pda,
          evaluator: ev.publicKey,
          bidder: b2Keypair.publicKey,
        })
        .signers([ev])
        .rpc();
    }

    // Finalize technical scores
    await program.methods
      .finalizeTechnicalScores()
      .accounts({ tender: tenderSec04Pda, committee: commSec04Pda, bidCommitment: b1Pda, authority: authority.publicKey })
      .remainingAccounts(grades1.map(g => ({ pubkey: g.pda, isWritable: true, isSigner: false })))
      .rpc();

    await program.methods
      .finalizeTechnicalScores()
      .accounts({ tender: tenderSec04Pda, committee: commSec04Pda, bidCommitment: b2Pda, authority: authority.publicKey })
      .remainingAccounts(grades2.map(g => ({ pubkey: g.pda, isWritable: true, isSigner: false })))
      .rpc();

    const fetchB1 = await program.account.dualBidCommitment.fetch(b1Pda);
    const fetchB2 = await program.account.dualBidCommitment.fetch(b2Pda);
    assert.strictEqual(fetchB1.isTechQualified, true);
    assert.strictEqual(fetchB2.isTechQualified, true);
    assert.strictEqual(fetchB1.technicalScoreBps, 9000);
    assert.strictEqual(fetchB2.technicalScoreBps, 7800);

    // Wait past tech deadline
    while ((await provider.connection.getSlot()) <= sec04TechSlot.toNumber()) {
      await new Promise(r => setTimeout(r, 200));
    }

    // Advance to FinancialEvaluation
    await program.methods
      .advanceTenderPhase()
      .accounts({ tender: tenderSec04Pda, caller: authority.publicKey })
      .rpc();

    // Zero-Price Reveal Guard: Attempt reveal with price = 0
    try {
      await program.methods
        .revealFinancialEnvelope(Array.from(sFin1), new anchor.BN(0), Array.from(bHash1))
        .accounts({
          tender: tenderSec04Pda,
          bidCommitment: b1Pda,
          revealer: b1Keypair.publicKey,
          bidderRecipient: b1Keypair.publicKey,
        })
        .signers([b1Keypair])
        .rpc();
      assert.fail("Should have rejected zero price");
    } catch (err: any) {
      assert.ok(err.toString().includes("ZeroPriceNotAllowed") || err.toString().includes("6040"), `Expected ZeroPriceNotAllowed, got: ${err}`);
    }

    // Both legitimate unsealings
    await program.methods
      .revealFinancialEnvelope(Array.from(sFin1), price1, Array.from(bHash1))
      .accounts({ tender: tenderSec04Pda, bidCommitment: b1Pda, revealer: b1Keypair.publicKey, bidderRecipient: b1Keypair.publicKey })
      .signers([b1Keypair])
      .rpc();

    await program.methods
      .revealFinancialEnvelope(Array.from(sFin2), price2, Array.from(bHash2))
      .accounts({ tender: tenderSec04Pda, bidCommitment: b2Pda, revealer: b2Keypair.publicKey, bidderRecipient: b2Keypair.publicKey })
      .signers([b2Keypair])
      .rpc();

    const tenderAfterReveal = await program.account.tender.fetch(tenderSec04Pda);
    assert.strictEqual(tenderAfterReveal.totalFinRevealed, 2);
    assert.strictEqual(tenderAfterReveal.lowestRevealedPrice.toNumber(), 3500000);

    const awardRationale = crypto.createHash("sha256").update(Buffer.from("SEC04_MEMO")).digest();

    // Attack 1: Authority attempts to award inferior Bidder 2 omitting competing Bidder 1
    try {
      await program.methods
        .recordAwardQcbs(Array.from(awardRationale))
        .accounts({
          tender: tenderSec04Pda,
          winningBid: b2Pda,
          authority: authority.publicKey,
        })
        .rpc();
      assert.fail("Should have failed with MissingCompetingBids");
    } catch (err: any) {
      assert.ok(err.toString().includes("MissingCompetingBids") || err.toString().includes("6041"), `Expected MissingCompetingBids, got: ${err}`);
    }

    // Attack 2: Authority attempts to award inferior Bidder 2 while providing Bidder 1 in remainingAccounts
    try {
      await program.methods
        .recordAwardQcbs(Array.from(awardRationale))
        .accounts({
          tender: tenderSec04Pda,
          winningBid: b2Pda,
          authority: authority.publicKey,
        })
        .remainingAccounts([
          { pubkey: b1Pda, isWritable: true, isSigner: false },
        ])
        .rpc();
      assert.fail("Should have failed with WinnerNotHighestCompositeScore");
    } catch (err: any) {
      assert.ok(err.toString().includes("WinnerNotHighestCompositeScore") || err.toString().includes("6023"), `Expected WinnerNotHighestCompositeScore, got: ${err}`);
    }

    // Legitimate Award: Authority awards rightful winner Bidder 1 with Bidder 2 in remainingAccounts
    await program.methods
      .recordAwardQcbs(Array.from(awardRationale))
      .accounts({
        tender: tenderSec04Pda,
        winningBid: b1Pda,
        authority: authority.publicKey,
      })
      .remainingAccounts([
        { pubkey: b2Pda, isWritable: true, isSigner: false },
      ])
      .rpc();

    const awardedTender = await program.account.tender.fetch(tenderSec04Pda);
    assert.strictEqual(awardedTender.winningBidder.toBase58(), b1Keypair.publicKey.toBase58());
    assert.deepStrictEqual(awardedTender.status, { awarded: {} });
    assert.strictEqual(awardedTender.highestCompositeScore.toNumber(), 9063);

    const winningBidAccount = await program.account.dualBidCommitment.fetch(b1Pda);
    assert.strictEqual(winningBidAccount.compositeScore.toNumber(), 9063);

    const competingBidAccount = await program.account.dualBidCommitment.fetch(b2Pda);
    assert.strictEqual(competingBidAccount.compositeScore.toNumber(), 8460);
  });

  it("Test 8c (SEC-05 Fix): Committee Inclusivity, Zero-Median Variance Floor & Empty Trimmed Pool Revert", async () => {
    const sec05TenderId = `TENDER-SEC05-${Math.floor(Math.random() * 100000)}`;
    const [tenderSec05Pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("tender"), authority.publicKey.toBuffer(), Buffer.from(sec05TenderId)],
      program.programId
    );
    const [commSec05Pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("committee"), tenderSec05Pda.toBuffer()],
      program.programId
    );

    const bPolarKeypair = anchor.web3.Keypair.generate();
    const bZeroKeypair = anchor.web3.Keypair.generate();

    const [bPolarPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bid"), tenderSec05Pda.toBuffer(), bPolarKeypair.publicKey.toBuffer()],
      program.programId
    );
    const [bZeroPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bid"), tenderSec05Pda.toBuffer(), bZeroKeypair.publicKey.toBuffer()],
      program.programId
    );

    // Fund bidders
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(bPolarKeypair.publicKey, 1000000000),
      "confirmed"
    );
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(bZeroKeypair.publicKey, 1000000000),
      "confirmed"
    );

    const curSlot = await provider.connection.getSlot();
    const sec05SubSlot = new anchor.BN(curSlot + 6);
    const sec05AdminSlot = sec05SubSlot;
    const sec05TechSlot = new anchor.BN(curSlot + 25);
    const sec05FinSlot = new anchor.BN(curSlot + 100);

    const noticeHash = crypto.createHash("sha256").update(Buffer.from("NOTICE_SEC05")).digest();

    await program.methods
      .initializeTender(
        sec05TenderId,
        Array.from(noticeHash),
        { postQualifiedOpen: {} },
        { qcbs: {} },
        sec05SubSlot,
        sec05AdminSlot,
        sec05TechSlot,
        sec05FinSlot,
        Array.from(Buffer.alloc(32)),
        7500,
        7000,
        3000
      )
      .accounts({
        tender: tenderSec05Pda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // 4 evaluators, max_variance_bps = 2000 (20%)
    const ev4 = evaluators.slice(0, 4);
    await program.methods
      .initializeCommittee(
        ev4.map(e => e.publicKey),
        2000
      )
      .accounts({
        tender: tenderSec05Pda,
        committee: commSec05Pda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    // Commit bids
    const sTechP = crypto.randomBytes(32);
    const pHashP = crypto.createHash("sha256").update(Buffer.from("PROP_POLAR")).digest();
    const cTechP = computeTechCommitment(tenderSec05Pda, bPolarKeypair.publicKey, sTechP, pHashP);
    const cFinP = computeFinCommitment(tenderSec05Pda, bPolarKeypair.publicKey, crypto.randomBytes(32), new anchor.BN(4000000), crypto.randomBytes(32));

    const sTechZ = crypto.randomBytes(32);
    const pHashZ = crypto.createHash("sha256").update(Buffer.from("PROP_ZERO")).digest();
    const cTechZ = computeTechCommitment(tenderSec05Pda, bZeroKeypair.publicKey, sTechZ, pHashZ);
    const cFinZ = computeFinCommitment(tenderSec05Pda, bZeroKeypair.publicKey, crypto.randomBytes(32), new anchor.BN(4000000), crypto.randomBytes(32));

    await program.methods
      .commitDualBid(Array.from(Buffer.alloc(32)), Array.from(cTechP), Array.from(cFinP), { solanaEscrow: {} }, new anchor.BN(100), null)
      .accounts({
        tender: tenderSec05Pda,
        bidCommitment: bPolarPda,
        bidder: bPolarKeypair.publicKey,
        feePayer: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([bPolarKeypair])
      .rpc();

    await program.methods
      .commitDualBid(Array.from(Buffer.alloc(32)), Array.from(cTechZ), Array.from(cFinZ), { solanaEscrow: {} }, new anchor.BN(100), null)
      .accounts({
        tender: tenderSec05Pda,
        bidCommitment: bZeroPda,
        bidder: bZeroKeypair.publicKey,
        feePayer: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([bZeroKeypair])
      .rpc();

    // Wait past submission deadline
    while ((await provider.connection.getSlot()) <= sec05SubSlot.toNumber()) {
      await new Promise(r => setTimeout(r, 200));
    }

    // Advance to TechnicalEvaluation
    await program.methods
      .advanceTenderPhase()
      .accounts({ tender: tenderSec05Pda, caller: authority.publicKey })
      .rpc();

    // Reveal Technical
    await program.methods
      .revealTechnicalBid(Array.from(sTechP), Array.from(pHashP))
      .accounts({ tender: tenderSec05Pda, bidCommitment: bPolarPda, revealer: bPolarKeypair.publicKey })
      .signers([bPolarKeypair])
      .rpc();

    await program.methods
      .revealTechnicalBid(Array.from(sTechZ), Array.from(pHashZ))
      .accounts({ tender: tenderSec05Pda, bidCommitment: bZeroPda, revealer: bZeroKeypair.publicKey })
      .signers([bZeroKeypair])
      .rpc();

    // Evaluators grade bPolar with polarized scores: 1000, 1000, 9000, 9000
    // Evaluators grade bZero with zero scores: 0, 0, 0, 0
    const polarGrades: { pda: anchor.web3.PublicKey }[] = [];
    const zeroGrades: { pda: anchor.web3.PublicKey }[] = [];

    const polarSubs: [number, number, number, number, number][] = [
      [200, 200, 200, 200, 200],   // 1000
      [200, 200, 200, 200, 200],   // 1000
      [1800, 1800, 1800, 1800, 1800], // 9000
      [1800, 1800, 1800, 1800, 1800], // 9000
    ];

    for (let i = 0; i < 4; i++) {
      const ev = ev4[i];
      const s1 = crypto.randomBytes(32);
      const j1 = crypto.createHash("sha256").update(Buffer.from(`JP_${i}`)).digest();
      const comm1 = computeGradeCommitment(tenderSec05Pda, bPolarKeypair.publicKey, ev.publicKey, s1, polarSubs[i], j1);
      const [g1Pda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("grade"), tenderSec05Pda.toBuffer(), ev.publicKey.toBuffer(), bPolarKeypair.publicKey.toBuffer()],
        program.programId
      );
      polarGrades.push({ pda: g1Pda });

      await program.methods
        .commitEvaluatorGrade(Array.from(comm1))
        .accounts({
          tender: tenderSec05Pda,
          committee: commSec05Pda,
          bidCommitment: bPolarPda,
          evaluatorGrade: g1Pda,
          evaluator: ev.publicKey,
          bidder: bPolarKeypair.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([ev])
        .rpc();

      await program.methods
        .revealEvaluatorGrade(polarSubs[i], Array.from(s1), Array.from(j1))
        .accounts({
          tender: tenderSec05Pda,
          committee: commSec05Pda,
          evaluatorGrade: g1Pda,
          evaluator: ev.publicKey,
          bidder: bPolarKeypair.publicKey,
        })
        .signers([ev])
        .rpc();

      // Zero grades
      const s0 = crypto.randomBytes(32);
      const j0 = crypto.createHash("sha256").update(Buffer.from(`JZ_${i}`)).digest();
      const zeroSub: [number, number, number, number, number] = [0, 0, 0, 0, 0];
      const comm0 = computeGradeCommitment(tenderSec05Pda, bZeroKeypair.publicKey, ev.publicKey, s0, zeroSub, j0);
      const [g0Pda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("grade"), tenderSec05Pda.toBuffer(), ev.publicKey.toBuffer(), bZeroKeypair.publicKey.toBuffer()],
        program.programId
      );
      zeroGrades.push({ pda: g0Pda });

      await program.methods
        .commitEvaluatorGrade(Array.from(comm0))
        .accounts({
          tender: tenderSec05Pda,
          committee: commSec05Pda,
          bidCommitment: bZeroPda,
          evaluatorGrade: g0Pda,
          evaluator: ev.publicKey,
          bidder: bZeroKeypair.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([ev])
        .rpc();

      await program.methods
        .revealEvaluatorGrade(zeroSub, Array.from(s0), Array.from(j0))
        .accounts({
          tender: tenderSec05Pda,
          committee: commSec05Pda,
          evaluatorGrade: g0Pda,
          evaluator: ev.publicKey,
          bidder: bZeroKeypair.publicKey,
        })
        .signers([ev])
        .rpc();
    }

    // 1. Cherry-Picking test: Omitting 1 evaluator (submitting 3 of 4) must fail with IncompleteCommitteeGrades
    try {
      await program.methods
        .finalizeTechnicalScores()
        .accounts({ tender: tenderSec05Pda, committee: commSec05Pda, bidCommitment: bPolarPda, authority: authority.publicKey })
        .remainingAccounts(polarGrades.slice(0, 3).map(g => ({ pubkey: g.pda, isWritable: true, isSigner: false })))
        .rpc();
      assert.fail("Should have failed with IncompleteCommitteeGrades");
    } catch (err: any) {
      assert.ok(
        err.toString().includes("IncompleteCommitteeGrades") || err.toString().includes("6043"),
        `Expected IncompleteCommitteeGrades, got: ${err}`
      );
    }

    // 2. Empty Trimmed Pool Revert: Polarized grades drop both middle elements -> EmptyTrimmedScorePool
    try {
      await program.methods
        .finalizeTechnicalScores()
        .accounts({ tender: tenderSec05Pda, committee: commSec05Pda, bidCommitment: bPolarPda, authority: authority.publicKey })
        .remainingAccounts(polarGrades.map(g => ({ pubkey: g.pda, isWritable: true, isSigner: false })))
        .rpc();
      assert.fail("Should have failed with EmptyTrimmedScorePool");
    } catch (err: any) {
      assert.ok(
        err.toString().includes("EmptyTrimmedScorePool") || err.toString().includes("6044"),
        `Expected EmptyTrimmedScorePool, got: ${err}`
      );
    }

    // 3. Zero-Median Variance Floor: All 0 grades evaluated with 100 bps floor -> no panic, trimmed mean = 0
    await program.methods
      .finalizeTechnicalScores()
      .accounts({ tender: tenderSec05Pda, committee: commSec05Pda, bidCommitment: bZeroPda, authority: authority.publicKey })
      .remainingAccounts(zeroGrades.map(g => ({ pubkey: g.pda, isWritable: true, isSigner: false })))
      .rpc();

    const fetchBZero = await program.account.dualBidCommitment.fetch(bZeroPda);
    assert.strictEqual(fetchBZero.technicalScoreBps, 0);
    assert.strictEqual(fetchBZero.isTechQualified, false);
  });
});

