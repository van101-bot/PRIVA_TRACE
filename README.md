# SIH26237 — Cryptographic Attribution and Immutable Decryption Provenance

## Smart India Hackathon 2026

Problem Statement:

> Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution.

---

## Project Overview

This project develops a secure multi-recipient encrypted document distribution system with:

- Post-Quantum Cryptography (PQC)
- ML-KEM / Kyber for key encapsulation
- ML-DSA / Dilithium for digital signatures
- AES-256-GCM for document encryption
- Quantum Key Distribution (QKD) integration abstraction
- Hybrid QKD + PQC key establishment
- Zero-Knowledge Proofs (ZKP) for privacy-preserving attribution
- Hardware Security Module (HSM) integration
- Cryptographically signed decryption records
- Immutable provenance ledger integration

---

## Architecture

```text
                    Document Sender
                           |
                           v
                  +------------------+
                  | Document Encrypt |
                  +------------------+
                           |
                           v
                    AES-256-GCM
                           |
              +------------+------------+
              |                         |
              v                         v
        QKD Key Source             ML-KEM
              |                         |
              +------------+------------+
                           |
                           v
                    Hybrid Key
                           |
                           v
                  Encrypted Document
                           |
             +-------------+-------------+
             |                           |
             v                           v
        Recipient 1                Recipient N
             |                           |
             +-------------+-------------+
                           |
                           v
                    Decryption Event
                           |
                           v
                    ML-DSA Signature
                           |
                           v
                         HSM
                           |
                           v
                  Provenance Ledger
                           |
                           v
                         ZKP
                           |
                           v
              Privacy-Preserving Attribution