hybrid-pqc-core/
├── hybrid_crypto/
│   ├── __init__.py
│   ├── hybrid_kem.py      # Combines Classical (ECDH) + NIST ML-KEM (Kyber)
│   └── hybrid_sign.py     # Combines Classical (ECDSA/Ed25519) + NIST ML-Dilithium
├── examples/
│   └── secure_fraud_alert.py # Demonstrates securing a fraud detection payload
├── tests/
│   ├── test_hybrid_kem.py
│   └── test_hybrid_sign.py
├── README.md
└── requirements.txt

hybrid-pqc-core is an open-source reference implementation for hybrid classical and lattice-based post-quantum cryptography.

Note: The architectural patterns and cryptographic wrappers found in this repository serve as the open-source security backbone deployed in high-security proprietary environments, including real-time transaction monitoring and fraud-detection pipelines requiring long-term quantum resistance.
