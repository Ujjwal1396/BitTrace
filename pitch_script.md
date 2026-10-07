# BidTrace: 3-Minute Hackathon Video Pitch Script

**Duration:** Exactly 3 Minutes  
**Visuals:** Start on Pitch Slide $\rightarrow$ Transition to Live Interactive Dashboard (`public/index.html`) $\rightarrow$ Terminal / Explorer $\rightarrow$ Conclusion Slide.

---

### 0:00 – 0:45 | The Hook & The Critical Procurement Attack
* **Visual:** Slide showing government tender headline: *"After bids close, can anyone prove the winning bid wasn't inserted late?"*
* **Speaker:**
  > "Every year, trillions of dollars are spent on public and enterprise procurement. But there is a fatal blind spot in modern e-procurement platforms: **the window between the submission deadline and bid opening.**
  >
  > A corrupt administrator or database operator with root access can inspect competing bids after the 12:00 deadline, secretly insert a 4th favored bid, or tamper with an existing price before bids are opened. When honest bidders lose, the operator simply claims: *'That's what was in the database.'*
  >
  > We built **BidTrace**: an incorruptible cryptographic deadline-lock protocol for competitive procurement on Solana."

---

### 0:45 – 1:30 | How It Works (Direct PDAs & Consensus Clock)
* **Visual:** Switch screen to the **BidTrace Web Dashboard** (`public/index.html`). Show Tender `TENDER-2026-HIGHWAY-402` and the 3 bidder cards.
* **Speaker:**
  > "BidTrace does not put confidential bids on-chain or try to replace the entire legal system. Instead, it proves one mathematically irrefutable claim: **bid-set completeness at the deadline.**
  >
  > Here is Tender 402 closing at Slot 1050. Bidders encrypt their proposals locally using AES-256-GCM and write a 32-byte domain-separated cryptographic commitment **directly to a non-custodial Solana PDA**.
  >
  > Because bidders commit directly to the chain, the operator cannot selectively censor or exclude any bidder. And because Solana's consensus clock enforces `slot <= deadline_slot`, the submission window is permanently sealed the moment slot 1050 passes."

---

### 1:30 – 2:20 | The Live Attacks & Defenses (The "Climax")
* **Visual:** Click **"Advance Slot to 1060 & Lock Tender"**. Watch the status turn to **Locked**.
* **Speaker:**
  > "Now, let's watch what happens when a corrupt operator attacks the system."
* **Visual:** Click **"Attack 1: Inject Late Bidder D"**. Show red error alert in console: `BidTraceError::DeadlineExceeded`.
* **Speaker:**
  > "Attack 1: The operator receives a bribe and tries to insert Bidder D five minutes after the deadline. Solana Anchor rejects the transaction on-chain: `DeadlineExceeded`. The consensus slot has passed; no admin key can rewrite history."
* **Visual:** Click **"Attack 2: Tamper ACME Price"**. Show red error alert: `BidTraceError::InvalidRevealHash`.
* **Speaker:**
  > "Attack 2: The operator tries to alter ACME's price from \$4.2M to \$3.7M in the database. When reveal occurs, Anchor recomputes the preimage hash, detects the tamper, and halts: `InvalidRevealHash`."

---

### 2:20 – 2:50 | Legitimate Opening & Air-Gapped Verification
* **Visual:** Click **"Reveal Legitimate Bids"** $\rightarrow$ Click **"Record Award (BuildCo)"** $\rightarrow$ Click **"Run Air-Gapped Audit Check"**. Green badge appears.
* **Speaker:**
  > "Legitimate bids reveal cleanly. And unlike naive root schemes that break if one bidder defaults, BidTrace evaluates each leaf independently so honest bidders are never deadlocked.
  >
  > Finally, what if the ministry shuts down its website? An auditor or losing contractor can take their standalone `proof_bundle.json` and run our zero-dependency verifier offline. It queries public Solana state directly and proves within milliseconds that the bid was committed before slot 1050 and is 100% tamper-free."

---

### 2:50 – 3:00 | Conclusion & Impact
* **Visual:** Final slide showing GitHub repo, Solana Devnet Program ID, and team contact.
* **Speaker:**
  > "BidTrace turns procurement corruption from *'your word against the database administrator'* into mathematical certainty. Built with Anchor on Solana. Thank you."
