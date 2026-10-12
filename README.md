# Hybrid Post-Quantum Cryptography (PQC) Core

A robust, production-ready Python library implementing **Hybrid Post-Quantum Cryptography (PQC)**. It combines classical cryptographic primitives with NIST-standardised quantum-resistant algorithms to secure data transmission against both classical and quantum computing threats.

---

## Architecture & Primitives

This library implements a dual-layer hybrid approach:
1. **Key Encapsulation Mechanism (HybridKEM)**: Combines **X25519** (ECDH) with **ML-KEM-768** (formerly CRYSTALS-Kyber) via HKDF-SHA256.
2. **Digital Signatures (HybridSign)**: Combines **Ed25519** with **ML-DSA-65** (formerly CRYSTALS-Dilithium) for quantum-resistant authentication and non-repudiation.

---

## Project Structure

```text
hybrid-pqc-core/
├── hybrid_crypto/
│   ├── __init__.py
│   ├── hybrid_kem.py             # Combines Classical (X25519) + NIST ML-KEM-768
│   └── hybrid_sign.py            # Combines Classical (Ed25519) + NIST ML-DSA-65
├── examples/
│   └── secure_money_transfer.py  # End-to-end encrypted & signed banking transaction
├── tests/
│   ├── test_hybrid_kem.py
│   └── test_hybrid_sign.py
├── README.md
└── requirements.txt

```

---

## Installation & Environment Setup

This library relies on `liboqs-python` for underlying NIST PQC primitives. It is recommended to run inside a dedicated Conda environment.

1. **Clone the repository:**
```bash
git clone [https://github.com/articlesmli/hybrid-pqc-core.git](https://github.com/your-username/hybrid-pqc-core.git)
cd hybrid-pqc-core

```


2. **Install dependencies:**
Ensure you have `liboqs` C binaries installed, then install Python requirements:
```bash
pip install -r requirements.txt

```



---

## Running Tests

To execute the test suite with `pytest`:

```bash
PYTHONPATH=. python -m pytest -v

```

---

## Quick Start Example: Secure Money Transfer

You can run the included financial transfer simulation to see hybrid encryption and signing in action:

```bash
PYTHONPATH=. python examples/secure_money_transfer.py

```

### Code Snippet:

```python
from hybrid_crypto.hybrid_kem import HybridKEM
from hybrid_crypto.hybrid_sign import HybridSign

# Initialize keypairs
alice_kem = HybridKEM()
bob_kem = HybridKEM()

# Encapsulate shared secret from Alice to Bob
encap_result = alice_kem.encapsulate(
    peer_classical_pub=bob_kem.classical_public_key,
    peer_pqc_pub=bob_kem.pqc_keypair["public_key"]
)
shared_key = encap_result["shared_key"] # 256-bit symmetric key for AES

```

---

## License

Distributed under the MIT License. See `LICENSE` for more information.


