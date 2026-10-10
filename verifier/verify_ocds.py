#!/usr/bin/env python3
"""
BidTrace 3.0: Standalone Air-Gapped OCDS & Solana Cryptographic Verifier CLI
============================================================================
Audits the complete procurement lifecycle without trusting the BidTrace server.
Verifies all 5 phases:
- Phase 1: OCDS 1.1 Tender Notice Canonical Hash Anchor
- Phase 2: Administrative Whitelist (Merkle Proof) & Hybrid Bond Attestations
- Phase 3: Two-Envelope Temporal Slot Adherence & Envelope A Integrity
- Phase 4: Multi-Evaluator Rubrics & Olympic Trimmed Mean Rogue Defense
- Phase 5: Envelope B Integrity, Commercial Secrecy Invariant & QCBS Award Math
"""

import sys
import os

# Add parent directory to path so bidtrace_py is importable
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from bidtrace_py.verifier import main

if __name__ == "__main__":
    main()
