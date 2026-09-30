# System Architecture

## High-Level Components

The system consists of the following cryptographic components:

1. Document Encryption
2. Post-Quantum Key Encapsulation
3. Digital Signatures
4. QKD Key Source
5. Hybrid Key Derivation
6. Key Management
7. HSM
8. Zero-Knowledge Attribution
9. Provenance Ledger

---

## Cryptographic Flow

### Encryption

```text
Document
   |
   v
Generate random AES-256-GCM key
   |
   v
Encrypt document
   |
   v
Establish recipient key material
   |
   +---- QKD
   |
   +---- ML-KEM
   |
   v
Derive/wrap encryption key
   |
   v
Store encrypted document + metadata