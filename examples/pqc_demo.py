from src.pqc.kem import MLKEM
from src.pqc.signature import MLDSA


def main() -> None:
    print("=== SIH26237 PQC Demo ===")

    # ---------------------------------------------------------
    # ML-KEM
    # ---------------------------------------------------------

    print("\n[1] ML-KEM")

    kem = MLKEM("ML-KEM-768")

    recipient = kem.generate_keypair()

    encapsulation = kem.encapsulate(
        recipient.public_key
    )

    recovered_secret = kem.decapsulate(
        encapsulation.ciphertext,
        recipient.private_key,
    )

    print(
        "Shared secrets match:",
        encapsulation.shared_secret == recovered_secret,
    )

    # ---------------------------------------------------------
    # ML-DSA
    # ---------------------------------------------------------

    print("\n[2] ML-DSA")

    dsa = MLDSA("ML-DSA-65")

    signer = dsa.generate_keypair()

    message = b"SIH26237 provenance record"

    signature = dsa.sign(
        message,
        signer.private_key,
    )

    valid = dsa.verify(
        message,
        signature,
        signer.public_key,
    )

    print("Signature valid:", valid)


if __name__ == "__main__":
    main()