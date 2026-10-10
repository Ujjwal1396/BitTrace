"""
BidTrace 3.0 CLI Verifier Entrypoint
"""
import sys
import os

current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from bidtrace_py.verifier import (
    AirGappedTribunalVerifier,
    export_tribunal_dossier,
    verify_proof_bundle,
    main
)

if __name__ == "__main__":
    main()
