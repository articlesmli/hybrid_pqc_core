import base64
import pytest
import oqs
from hybrid_crypto.hybrid_kem import HybridKEM

def test_liboqs_availability_and_algorithm():
    """Verify that liboqs is installed and ML-KEM-768 is supported."""
    supported_algorithms = oqs.get_enabled_kem_mechanisms()
    assert "ML-KEM-768" in supported_algorithms, f"ML-KEM-768 not found in enabled algorithms: {supported_algorithms}"

    kem_instance = HybridKEM(pqc_algorithm="ML-KEM-768")
    assert kem_instance.pqc_algorithm == "ML-KEM-768"
    assert len(kem_instance.pqc_keypair["public_key"]) > 0
    assert len(kem_instance.pqc_keypair["private_key"]) > 0

def test_hybrid_kem_key_generation():
    """Test that HybridKEM initializes classical and PQC keypairs correctly."""
    kem = HybridKEM()
    
    # Verify classical keypair exists
    assert kem.classical_private_key is not None
    assert kem.classical_public_key is not None
    
    # Verify PQC keypair exists and contains bytes
    assert "public_key" in kem.pqc_keypair
    assert "private_key" in kem.pqc_keypair
    assert isinstance(kem.pqc_keypair["public_key"], bytes)
    assert isinstance(kem.pqc_keypair["private_key"], bytes)

def test_hybrid_kem_encapsulation_decapsulation():
    """Test the full hybrid key exchange loop between a receiver and a sender."""
    # 1. Receiver initializes their identity
    receiver = HybridKEM()

    # 2. Sender prepares communication
    sender = HybridKEM()

    # 3. Sender encapsulates a shared secret using the receiver's public keys
    encap_result = sender.encapsulate(
        peer_classical_pub=receiver.classical_public_key,
        peer_pqc_pub=receiver.pqc_keypair["public_key"]
    )

    # Assert encapsulation output schema
    assert "ephemeral_classical_pub" in encap_result
    assert "pqc_ciphertext" in encap_result
    assert "shared_key" in encap_result

    # 4. Receiver decapsulates the package using their private keys
    receiver_shared_key = receiver.decapsulate(
        ephemeral_classical_pub=encap_result["ephemeral_classical_pub"],
        pqc_ciphertext=encap_result["pqc_ciphertext"]
    )

    # 5. Verify that both keys match securely and conform to 256-bit standards
    assert encap_result["shared_key"] == receiver_shared_key
    assert len(receiver_shared_key) == 32  # 256-bit shared key

def test_hybrid_kem_serialization_and_network_flow():
    """Test that public keys and network packets can be serialized to Base64/JSON and decapsulated successfully."""
    # 1. Receiver sets up their KEM and serializes public keys (simulating a JSON payload)
    receiver = HybridKEM()
    pub_keys_dict = receiver.serialize_public_keys()
    
    # Verify keys are strings ready for JSON transmission
    assert isinstance(pub_keys_dict["classical_pub_b64"], str)
    assert isinstance(pub_keys_dict["pqc_pub_b64"], str)
    
    # 2. Sender receives JSON payload, deserializes classical pub key, and decodes PQC bytes
    peer_classical_pub = HybridKEM.deserialize_classical_pub(pub_keys_dict["classical_pub_b64"])
    peer_pqc_pub = base64.b64decode(pub_keys_dict["pqc_pub_b64"])
    
    sender = HybridKEM()
    encap_result = sender.encapsulate(peer_classical_pub, peer_pqc_pub)
    
    # 3. Sender serializes encapsulation result for transmission back
    network_packet = HybridKEM.serialize_encap_result(encap_result)
    
    # 4. Receiver decodes network packet and decapsulates
    ephemeral_pub = HybridKEM.deserialize_classical_pub(network_packet["ephemeral_classical_pub_b64"])
    ciphertext = base64.b64decode(network_packet["pqc_ciphertext_b64"])
    
    receiver_shared_key = receiver.decapsulate(ephemeral_pub, ciphertext)
    
    # 5. Verify shared keys match
    assert encap_result["shared_key"] == receiver_shared_key
    assert len(receiver_shared_key) == 32