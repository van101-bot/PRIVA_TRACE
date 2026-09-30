import oqs


def main() -> None:
    print("=" * 60)
    print("SIH26237 PQC Environment")
    print("=" * 60)

    print(f"liboqs version: {oqs.oqs_version()}")
    print(f"liboqs-python version: {oqs.oqs_python_version()}")

    print("\nEnabled KEM algorithms:")

    for algorithm in oqs.get_enabled_kem_mechanisms():
        print(f"  {algorithm}")

    print("\nEnabled signature algorithms:")

    for algorithm in oqs.get_enabled_sig_mechanisms():
        print(f"  {algorithm}")


if __name__ == "__main__":
    main()