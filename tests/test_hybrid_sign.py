import base64
import pytest
import oqs
from hybrid_crypto.hybrid_sign import HybridSign

def test_liboqs_signature_availability():
    """Verify that liboqs supports ML-DSA-65 signatures."""
    supported_sigs = oqs.get_enabled_sig_mechanisms()
    assert "ML-DSA-65" in supported_sigs, f"ML-DSA-65 not found in enabled signature mechanisms: {supported_sigs}"

    signer = HybridSign(pqc_algorithm="ML-DSA-65")
    assert signer.pqc_algorithm == "ML-DSA-65"
    assert len(signer.pqc_keypair["public_key"]) > 0
    assert len(signer.pqc_keypair["private_key"]) > 0

def test_hybrid_sign_and_verify_loop():
    """Test standard hybrid signing and verification between a sender and verifier."""
    sender = HybridSign()
    message = b"Authorize transaction ID: TX-987654321 for amount $50,000.00"

    # 1. Sign message
    sig_payload = sender.sign(message)
    assert "classical_signature" in sig_payload
    assert "pqc_signature" in sig_payload

    # 2. Verify with correct keys
    is_valid = HybridSign.verify(
        message=message,
        signature_payload=sig_payload,
        peer_classical_pub=sender.classical_public_key,
        peer_pqc_pub=sender.pqc_keypair["public_key"]
    )
    assert is_valid is True

def test_hybrid_sign_tamper_detection():
    """Test that tampering with the message or signatures causes verification to fail."""
    sender = HybridSign()
    message = b"Secure payload data"
    sig_payload = sender.sign(message)

    # Tamper with message
    tampered_message = b"Secure payload data (TAMPERED)"
    assert HybridSign.verify(
        message=tampered_message,
        signature_payload=sig_payload,
        peer_classical_pub=sender.classical_public_key,
        peer_pqc_pub=sender.pqc_keypair["public_key"]
    ) is False

    # Tamper with signature bytes
    corrupted_sig_payload = {
        "classical_signature": b"\x00" * len(sig_payload["classical_signature"]),
        "pqc_signature": sig_payload["pqc_signature"]
    }
    assert HybridSign.verify(
        message=message,
        signature_payload=corrupted_sig_payload,
        peer_classical_pub=sender.classical_public_key,
        peer_pqc_pub=sender.pqc_keypair["public_key"]
    ) is False

def test_hybrid_sign_serialization_and_network_flow():
    """Test full Base64 serialization and deserialization workflow over mock network payloads."""
    sender = HybridSign()
    message = b"Financial audit report approval."

    # 1. Serialize public keys (Sender -> Server/Client registry)
    pub_keys_dict = sender.serialize_public_keys()
    assert isinstance(pub_keys_dict["classical_pub_b64"], str)
    assert isinstance(pub_keys_dict["pqc_pub_b64"], str)

    # 2. Sign message and serialize signature packet
    sig_payload = sender.sign(message)
    net_sig_packet = HybridSign.serialize_signature(sig_payload)
    assert isinstance(net_sig_packet["classical_signature_b64"], str)
    assert isinstance(net_sig_packet["pqc_signature_b64"], str)

    # 3. Receiver side reconstructs public keys and signatures from JSON strings
    peer_classical_pub = HybridSign.deserialize_classical_pub(pub_keys_dict["classical_pub_b64"])
    peer_pqc_pub = base64.b64decode(pub_keys_dict["pqc_pub_b64"])
    reconstructed_sig_payload = HybridSign.deserialize_signature(net_sig_packet)

    # 4. Verify successfully
    is_valid = HybridSign.verify(
        message=message,
        signature_payload=reconstructed_sig_payload,
        peer_classical_pub=peer_classical_pub,
        peer_pqc_pub=peer_pqc_pub
    )
    assert is_valid is True
