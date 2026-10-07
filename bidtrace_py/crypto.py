import os
import hashlib
import json
import base64
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

def compute_commitment_hash(
    tender_pubkey_hex: str,
    bidder_pubkey_hex: str,
    salt_hex: str,
    ciphertext_hash_hex: str,
    bid_amount: int
) -> str:
    """
    Computes the domain-separated SHA-256 commitment hash:
    SHA256(DOMAIN_TAG || tender_pubkey || bidder_pubkey || salt || ciphertext_hash || bid_amount_le)
    """
    hasher = hashlib.sha256()
    hasher.update(DOMAIN_TAG)
    hasher.update(bytes.fromhex(tender_pubkey_hex))
    hasher.update(bytes.fromhex(bidder_pubkey_hex))
    hasher.update(bytes.fromhex(salt_hex))
    hasher.update(bytes.fromhex(ciphertext_hash_hex))
    hasher.update(bid_amount.to_bytes(8, byteorder='little'))
    return hasher.hexdigest()
