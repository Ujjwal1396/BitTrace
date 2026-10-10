"""
BidTrace Model A: Pre-Qualified Merkle Whitelist Engine
======================================================
Constructs deterministic sorted-pair Merkle Trees over approved bidder public keys
and generates inclusion proofs verifiable by Anchor smart contracts on Solana.
"""

import hashlib
from typing import List, Dict, Any, Optional, Union
from .crypto import to_32bytes, b58encode, b58decode


def compute_leaf(bidder_key: Any) -> bytes:
    """
    Computes leaf hash for a bidder: SHA-256(bidder_pubkey_32bytes).
    Matches Anchor handle_commit_dual_bid instruction.
    """
    raw_key = to_32bytes(bidder_key)
    return hashlib.sha256(raw_key).digest()


def hash_pair(a: bytes, b: bytes) -> bytes:
    """
    Computes sorted-pair SHA-256 hash:
    if a <= b: SHA256(a || b) else SHA256(b || a).
    """
    hasher = hashlib.sha256()
    if a <= b:
        hasher.update(a)
        hasher.update(b)
    else:
        hasher.update(b)
        hasher.update(a)
    return hasher.digest()


def verify_merkle_proof(bidder_key: Any, proof: List[Union[bytes, str]], root: Union[bytes, str]) -> bool:
    """
    Verifies that a bidder belongs to the Merkle tree with the given root.
    Proof elements and root can be either 32-byte bytes or hex strings.
    """
    root_bytes = to_32bytes(root)
    current = compute_leaf(bidder_key)
    
    for sib in proof:
        sib_bytes = to_32bytes(sib)
        current = hash_pair(current, sib_bytes)
        
    return current == root_bytes


class MerkleTree:
    """
    A sorted-pair Merkle Tree for Model A Pre-Qualified Whitelisting.
    """
    def __init__(self, bidders: List[Any]):
        if not bidders:
            raise ValueError("Cannot construct Merkle tree with empty bidder list")
        
        self.raw_bidders = list(bidders)
        self.leaves: List[bytes] = [compute_leaf(b) for b in self.raw_bidders]
        self.levels: List[List[bytes]] = [self.leaves]
        self._build_tree()

    def _build_tree(self):
        current_level = self.leaves
        while len(current_level) > 1:
            next_level: List[bytes] = []
            n = len(current_level)
            for i in range(0, n, 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < n else left
                next_level.append(hash_pair(left, right))
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> bytes:
        return self.levels[-1][0] if self.levels else b"\x00" * 32

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def get_proof(self, bidder_key: Any) -> List[bytes]:
        """
        Returns list of 32-byte sibling hashes forming the inclusion proof.
        """
        target_leaf = compute_leaf(bidder_key)
        try:
            index = self.leaves.index(target_leaf)
        except ValueError:
            raise ValueError(f"Bidder key not found in Merkle tree leaves: {bidder_key}")

        proof: List[bytes] = []
        for level in self.levels[:-1]:
            is_right_child = (index % 2 == 1)
            sibling_index = index - 1 if is_right_child else index + 1
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            else:
                # Odd length; paired with itself
                proof.append(level[index])
            index = index // 2

        return proof

    def get_proof_hex(self, bidder_key: Any) -> List[str]:
        """Returns proof as list of hex strings."""
        return [p.hex() for p in self.get_proof(bidder_key)]

    def to_dict(self) -> Dict[str, Any]:
        """Exports tree metadata for API responses and OCDS attachments."""
        return {
            "root_hex": self.root_hex,
            "bidders_count": len(self.raw_bidders),
            "bidders": [
                {
                    "bidder": b if isinstance(b, str) else b.hex(),
                    "leaf_hex": compute_leaf(b).hex(),
                    "proof_hex": self.get_proof_hex(b)
                }
                for b in self.raw_bidders
            ]
        }
