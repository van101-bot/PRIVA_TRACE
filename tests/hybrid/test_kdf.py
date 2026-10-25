from src.hybrid.kdf import HybridKDF


def test_hybrid_kdf_produces_32_byte_key():
    qkd_secret = b"qkd-secret-material"
    mlkem_secret = b"mlkem-secret-material"

    key = HybridKDF.derive_key(
        qkd_secret,
        mlkem_secret,
    )

    assert isinstance(key, bytes)
    assert len(key) == 32


def test_same_inputs_produce_same_key():
    qkd_secret = b"qkd-secret"
    mlkem_secret = b"mlkem-secret"

    key_a = HybridKDF.derive_key(
        qkd_secret,
        mlkem_secret,
    )

    key_b = HybridKDF.derive_key(
        qkd_secret,
        mlkem_secret,
    )

    assert key_a == key_b


def test_changing_qkd_secret_changes_key():
    key_a = HybridKDF.derive_key(
        b"qkd-a",
        b"mlkem",
    )

    key_b = HybridKDF.derive_key(
        b"qkd-b",
        b"mlkem",
    )

    assert key_a != key_b


def test_changing_mlkem_secret_changes_key():
    key_a = HybridKDF.derive_key(
        b"qkd",
        b"mlkem-a",
    )

    key_b = HybridKDF.derive_key(
        b"qkd",
        b"mlkem-b",
    )

    assert key_a != key_b


def test_missing_qkd_secret_rejected():
    try:
        HybridKDF.derive_key(
            b"",
            b"mlkem",
        )
        assert False
    except ValueError:
        assert True


def test_missing_mlkem_secret_rejected():
    try:
        HybridKDF.derive_key(
            b"qkd",
            b"",
        )
        assert False
    except ValueError:
        assert True