"""
Hybrid Digital Signature Mechanism (Hybrid Sign)
Combines Classical Ed25519 with NIST-standardized Lattice-Based PQC (ML-DSA-65 / Dilithium).
"""

import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import oqs

class HybridSign:
    def __init__(self, pqc_algorithm: str = "ML-DSA-65"):
        """
        Initializes the hybrid signing keypair consisting of:
        1. Classical Ed25519 private/public keypair.
        2. Post-Quantum signature keypair using liboqs (ML-DSA-65).
        """
        self.pqc_algorithm = pqc_algorithm
        
        # 1. Generate Classical Ed25519 Keypair
        self.classical_private_key = ed25519.Ed25519PrivateKey.generate()
        self.classical_public_key = self.classical_private_key.public_key()
        
        # 2. Generate Real Lattice PQC Signature Keypair via liboqs
        self.pqc_sig = oqs.Signature(self.pqc_algorithm)
        pqc_pub_bytes = self.pqc_sig.generate_keypair()
        
        self.pqc_keypair = {
            "public_key": pqc_pub_bytes,
            "private_key": self.pqc_sig.export_secret_key()
        }

    def sign(self, message: bytes) -> dict:
        """
        Signs a message using both classical and PQC private keys.
        """
        # 1. Classical signature
        classical_sig = self.classical_private_key.sign(message)
        
        # 2. PQC signature
        pqc_sig = self.pqc_sig.sign(message)
        
        return {
            "classical_signature": classical_sig,
            "pqc_signature": pqc_sig
        }

    @staticmethod
    def verify(message: bytes, signature_payload: dict, peer_classical_pub: ed25519.Ed25519PublicKey, peer_pqc_pub: bytes, pqc_algorithm: str = "ML-DSA-65") -> bool:
        """
        Verifies a hybrid signature payload against both sender public keys.
        Returns True only if BOTH classical and PQC signatures are valid.
        """
        try:
            # 1. Verify classical signature
            peer_classical_pub.verify(
                signature_payload["classical_signature"],
                message
            )
            
            # 2. Verify PQC signature using a temporary verifier instance
            verifier = oqs.Signature(pqc_algorithm)
            pqc_valid = verifier.verify(
                message,
                signature_payload["pqc_signature"],
                peer_pqc_pub
            )
            
            return pqc_valid
        except Exception:
            # Any cryptographic validation failure or tampering throws an exception
            return False

    # --- Serialization Helpers ---

    def serialize_public_keys(self) -> dict:
        """Serializes public keys into Base64 strings for network/API transmission."""
        classical_bytes = self.classical_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return {
            "classical_pub_b64": base64.b64encode(classical_bytes).decode("utf-8"),
            "pqc_pub_b64": base64.b64encode(self.pqc_keypair["public_key"]).decode("utf-8")
        }

    @staticmethod
    def deserialize_classical_pub(b64_string: str) -> ed25519.Ed25519PublicKey:
        """Reconstructs an Ed25519 public key object from a Base64 string."""
        raw_bytes = base64.b64decode(b64_string)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)

    @staticmethod
    def serialize_signature(sig_payload: dict) -> dict:
        """Serializes signature outputs into Base64 strings for JSON transmission."""
        return {
            "classical_signature_b64": base64.b64encode(sig_payload["classical_signature"]).decode("utf-8"),
            "pqc_signature_b64": base64.b64encode(sig_payload["pqc_signature"]).decode("utf-8")
        }

    @staticmethod
    def deserialize_signature(net_sig_payload: dict) -> dict:
        """Reconstructs raw signature bytes from Base64 network payloads."""
        return {
            "classical_signature": base64.b64decode(net_sig_payload["classical_signature_b64"]),
            "pqc_signature": base64.b64decode(net_sig_payload["pqc_signature_b64"])
        }