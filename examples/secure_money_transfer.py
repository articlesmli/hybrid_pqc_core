"""
Secure Money Transfer Example
Demonstrates end-to-end hybrid post-quantum encryption (ML-KEM-768 + X25519) 
and authentication (ML-DSA-65 + Ed25519) for a banking transfer.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hybrid_crypto.hybrid_kem import HybridKEM
from hybrid_crypto.hybrid_sign import HybridSign

def run_secure_money_transfer():
    print("=== PQC Hybrid Secure Money Transfer Simulation ===\n")

    # 1. Setup Identities
    # Bank (Receiver) and Customer (Sender) both have hybrid identity and KEM keys
    print("[*] Generating Bank and Customer Hybrid Keypairs...")
    bank_kem = HybridKEM()
    bank_sign = HybridSign()
    
    customer_kem = HybridKEM()
    customer_sign = HybridSign()

    # 2. Transaction Details
    transaction_payload = b"TRANSFER_TO: ACC-998877 | AMOUNT: $250,000.00 | CURRENCY: USD"
    print(f"[*] Original Transaction Payload: {transaction_payload.decode()}")

    # 3. Key Encapsulation (KEM) Phase - Establishing a Shared Symmetric Key
    # Customer encapsulates a shared secret using the Bank's public keys
    print("[*] Customer encapsulates shared secret using Bank's public keys (X25519 + ML-KEM-768)...")
    encap_result = customer_kem.encapsulate(
        peer_classical_pub=bank_kem.classical_public_key,
        peer_pqc_pub=bank_kem.pqc_keypair["public_key"]
    )
    shared_symmetric_key = encap_result["shared_key"]

    # 4. Symmetric Encryption Phase (AES-GCM using the Hybrid Shared Key)
    aesgcm = AESGCM(shared_symmetric_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, transaction_payload, None)
    print(f"[*] Transaction Encrypted (AES-256-GCM): {base64.b64encode(ciphertext).decode()[:40]}...")

    # 5. Hybrid Signature Phase (Authentication & Non-Repudiation)
    # Customer signs the encrypted ciphertext to prove authenticity
    print("[*] Customer signs the transfer packet using Hybrid Signatures (Ed25519 + ML-DSA-65)...")
    signature_payload = customer_sign.sign(ciphertext)

    # --- TRANSMISSION OVER NETWORK / API ---
    # The network packet includes: nonce, encrypted ciphertext, signature payload, and KEM exchange data
    network_packet = {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "ephemeral_classical_pub": encap_result["ephemeral_classical_pub"],
        "pqc_ciphertext": encap_result["pqc_ciphertext"],
        "signature_payload": signature_payload,
        "sender_classical_pub": customer_sign.classical_public_key,
        "sender_pqc_pub": customer_sign.pqc_keypair["public_key"]
    }
    print("[*] Network packet transmitted securely to Bank server...\n")

    # --- BANK RECEPTION & PROCESSING ---
    print("[*] Bank processing incoming transfer packet...")

    # Step A: Verify the Customer's Signature FIRST (Quantum-Resistant Authentication)
    is_authenticated = HybridSign.verify(
        message=network_packet["ciphertext"],
        signature_payload=network_packet["signature_payload"],
        peer_classical_pub=network_packet["sender_classical_pub"],
        peer_pqc_pub=network_packet["sender_pqc_pub"]
    )
    
    if not is_authenticated:
        print("[ERROR] Signature verification FAILED! Packet rejected.")
        return

    print("[SUCCESS] Hybrid Signature Verified! Sender identity and integrity confirmed.")

    # Step B: Decapsulate the Shared Secret
    bank_derived_key = bank_kem.decapsulate(
        ephemeral_classical_pub=network_packet["ephemeral_classical_pub"],
        pqc_ciphertext=network_packet["pqc_ciphertext"]
    )

    # Step C: Decrypt the Transaction Payload
    bank_aesgcm = AESGCM(bank_derived_key)
    decrypted_payload = bank_aesgcm.decrypt(
        network_packet["nonce"], 
        network_packet["ciphertext"], 
        None
    )

    print(f"[SUCCESS] Transaction Decrypted Successfully!")
    print(f"[*] Final Processed Data: {decrypted_payload.decode()}")
    print("\n=== Secure Money Transfer Complete ===")

if __name__ == "__main__":
    run_secure_money_transfer()
