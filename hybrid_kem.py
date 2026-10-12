import os
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs

class HybridKEM:
    def __init__(self, pqc_algorithm: str = "ML-KEM-768"):
        self.pqc_algorithm = pqc_algorithm
        self.classical_private_key = x25519.X25519PrivateKey.generate()
        self.classical_public_key = self.classical_private_key.public_key()
        
        self.pqc_kem = oqs.KeyEncapsulation(self.pqc_algorithm)
        pqc_pub_bytes = self.pqc_kem.generate_keypair()
        self.pqc_keypair = {
            "public_key": pqc_pub_bytes,
            "private_key": self.pqc_kem.export_secret_key()
        }

    def encapsulate(self, peer_classical_pub: x25519.X25519PublicKey, peer_pqc_pub: bytes) -> dict:
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        classical_shared_secret = ephemeral_private.exchange(peer_classical_pub)
        
        sender_kem = oqs.KeyEncapsulation(self.pqc_algorithm)
        pqc_ciphertext, pqc_shared_secret = sender_kem.encapsulate(peer_pqc_pub)
        
        combined_entropy = classical_shared_secret + pqc_shared_secret
        final_symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"nexusbio-hybrid-kem-salt-v1",
            info=b"hybrid-pqc-banking-encryption",
        ).derive(combined_entropy)
        
        return {
            "ephemeral_classical_pub": ephemeral_public,
            "pqc_ciphertext": pqc_ciphertext,
            "shared_key": final_symmetric_key
        }

    def decapsulate(self, ephemeral_classical_pub: x25519.X25519PublicKey, pqc_ciphertext: bytes) -> bytes:
        classical_shared_secret = self.classical_private_key.exchange(ephemeral_classical_pub)
        
        receiver_kem = oqs.KeyEncapsulation(self.pqc_algorithm, secret_key=self.pqc_keypair["private_key"])
        pqc_shared_secret = receiver_kem.decapsulate(pqc_ciphertext)
        
        combined_entropy = classical_shared_secret + pqc_shared_secret
        final_symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"nexusbio-hybrid-kem-salt-v1",
            info=b"hybrid-pqc-banking-encryption",
        ).derive(combined_entropy)
        
        return final_symmetric_key

    # --- Serialization Helpers as Class Methods ---
    
    def serialize_public_keys(self) -> dict:
        """Serializes this instance's public keys into Base64 strings for JSON transmission."""
        classical_bytes = self.classical_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return {
            "classical_pub_b64": base64.b64encode(classical_bytes).decode("utf-8"),
            "pqc_pub_b64": base64.b64encode(self.pqc_keypair["public_key"]).decode("utf-8")
        }

    @staticmethod
    def deserialize_classical_pub(b64_string: str) -> x25519.X25519PublicKey:
        """Reconstructs an X25519 public key object from a Base64 string."""
        raw_bytes = base64.b64decode(b64_string)
        return x25519.X25519PublicKey.from_public_bytes(raw_bytes)

    @staticmethod
    def serialize_encap_result(encap_result: dict) -> dict:
        """Serializes the output of encapsulate() for network transmission."""
        classical_ephemeral_bytes = encap_result["ephemeral_classical_pub"].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return {
            "ephemeral_classical_pub_b64": base64.b64encode(classical_ephemeral_bytes).decode("utf-8"),
            "pqc_ciphertext_b64": base64.b64encode(encap_result["pqc_ciphertext"]).decode("utf-8")
        }
