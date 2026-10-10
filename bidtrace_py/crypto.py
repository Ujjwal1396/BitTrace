import os
import hashlib
import json
import base64
from typing import Any, List, Optional, Union, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519

DOMAIN_TAG = b"BIDTRACE_V1"

def generate_keypair():
    """Generates an Ed25519 keypair for an actor (authority or bidder)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = pub.public_bytes_raw()
    return {
        "private_key": priv_bytes.hex(),
        "public_key": pub_bytes.hex(),
        "_priv_obj": priv,
        "_pub_obj": pub
    }

def sign_message(private_key_hex: str, message: bytes) -> str:
    """Signs a message using the Ed25519 private key."""
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    sig = priv.sign(message)
    return sig.hex()

def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verifies an Ed25519 signature."""
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), message)
        return True
    except Exception:
        return False

def encrypt_payload(plaintext_dict: dict):
    """Encrypts a plaintext bid dictionary using AES-256-GCM."""
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext_bytes = json.dumps(plaintext_dict, sort_keys=True).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    # Pack nonce + ciphertext
    full_ciphertext = nonce + ciphertext
    ciphertext_hash = hashlib.sha256(full_ciphertext).digest()
    
    return {
        "key_hex": key.hex(),
        "ciphertext_b64": base64.b64encode(full_ciphertext).decode('utf-8'),
        "ciphertext_hash_hex": ciphertext_hash.hex(),
        "ciphertext_bytes": full_ciphertext
    }

def decrypt_payload(key_hex: str, ciphertext_b64: str) -> dict:
    """Decrypts ciphertext using AES-256-GCM and returns the parsed dict."""
    key = bytes.fromhex(key_hex)
    full_ciphertext = base64.b64decode(ciphertext_b64)
    nonce = full_ciphertext[:12]
    ciphertext = full_ciphertext[12:]
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext_bytes.decode('utf-8'))

# ==============================================================================
# BASE58 CODEC (Solana Public Key Standard)
# ==============================================================================

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(raw: bytes) -> str:
    """Encodes arbitrary bytes into Base58 string."""
    n = int.from_bytes(raw, 'big')
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(B58_ALPHABET[r])
    pad = 0
    for byte in raw:
        if byte == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[0] * pad) + "".join(reversed(chars)) if chars or pad else "1"

def b58decode(s: str) -> bytes:
    """Decodes a Base58 string into raw bytes."""
    n = 0
    for char in s:
        idx = B58_ALPHABET.find(char)
        if idx == -1:
            raise ValueError(f"Invalid Base58 character: {char}")
        n = n * 58 + idx
    res = []
    while n > 0:
        n, r = divmod(n, 256)
        res.append(r)
    res = bytes(reversed(res))
    pad = 0
    for char in s:
        if char == B58_ALPHABET[0]:
            pad += 1
        else:
            break
    return (b"\x00" * pad) + res

def to_32bytes(val: Any) -> bytes:
    """Normalizes a base58 string, hex string, bytes, or int into a 32-byte array."""
    if isinstance(val, bytes):
        if len(val) == 32:
            return val
        elif len(val) < 32:
            return val.rjust(32, b'\x00')
        return val[:32]
    if isinstance(val, str):
        # Check if 64-char hex
        if len(val) == 64:
            try:
                return bytes.fromhex(val)
            except ValueError:
                pass
        # Try base58 decode
        try:
            decoded = b58decode(val)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        # Fallback SHA256 of string
        return hashlib.sha256(val.encode('utf-8')).digest()
    if isinstance(val, int):
        return val.to_bytes(32, byteorder='big')
    raise TypeError(f"Cannot convert {type(val)} to 32 bytes")

# ==============================================================================
# BIDTRACE 3.0 TWO-ENVELOPE DOMAIN-SEPARATED COMMITMENTS
# ==============================================================================

def compute_tech_commitment(
    tender_key: Any,
    bidder_key: Any,
    salt_tech: Any,
    proposal_hash: Any
) -> bytes:
    """
    Computes Anchor Envelope A (Technical) domain-separated commitment:
    SHA256("BIDTRACE_TECH_V1" || tender_pubkey || bidder_pubkey || salt_tech || proposal_hash)
    """
    hasher = hashlib.sha256()
    hasher.update(b"BIDTRACE_TECH_V1")
    hasher.update(to_32bytes(tender_key))
    hasher.update(to_32bytes(bidder_key))
    hasher.update(to_32bytes(salt_tech))
    hasher.update(to_32bytes(proposal_hash))
    return hasher.digest()

def compute_fin_commitment(
    tender_key: Any,
    bidder_key: Any,
    salt_fin: Any,
    price: int,
    boq_hash: Any
) -> bytes:
    """
    Computes Anchor Envelope B (Financial) domain-separated commitment:
    SHA256("BIDTRACE_FIN_V1" || tender_pubkey || bidder_pubkey || salt_fin || price_u64_le || boq_hash)
    """
    hasher = hashlib.sha256()
    hasher.update(b"BIDTRACE_FIN_V1")
    hasher.update(to_32bytes(tender_key))
    hasher.update(to_32bytes(bidder_key))
    hasher.update(to_32bytes(salt_fin))
    hasher.update(price.to_bytes(8, byteorder='little'))
    hasher.update(to_32bytes(boq_hash))
    return hasher.digest()

def compute_grade_commitment(
    tender_key: Any,
    bidder_key: Any,
    evaluator_key: Any,
    salt: Any,
    sub_scores: list,
    justification_hash: Any
) -> bytes:
    """
    Computes Anchor Evaluator Grade domain-separated commitment:
    SHA256("BIDTRACE_GRADE_V1" || tender || bidder || evaluator || salt || 5x sub_scores_u16_le || just_hash)
    """
    hasher = hashlib.sha256()
    hasher.update(b"BIDTRACE_GRADE_V1")
    hasher.update(to_32bytes(tender_key))
    hasher.update(to_32bytes(bidder_key))
    hasher.update(to_32bytes(evaluator_key))
    hasher.update(to_32bytes(salt))
    for s in sub_scores:
        hasher.update(int(s).to_bytes(2, byteorder='little'))
    hasher.update(to_32bytes(justification_hash))
    return hasher.digest()

def compute_commitment_hash(
    tender_pubkey_hex: str,
    bidder_pubkey_hex: str,
    salt_hex: str,
    ciphertext_hash_hex: str,
    bid_amount: int
) -> str:
    """
    Legacy commitment hash for backwards compatibility.
    """
    hasher = hashlib.sha256()
    hasher.update(DOMAIN_TAG)
    hasher.update(bytes.fromhex(tender_pubkey_hex))
    hasher.update(bytes.fromhex(bidder_pubkey_hex))
    hasher.update(bytes.fromhex(salt_hex))
    hasher.update(bytes.fromhex(ciphertext_hash_hex))
    hasher.update(bid_amount.to_bytes(8, byteorder='little'))
    return hasher.hexdigest()

