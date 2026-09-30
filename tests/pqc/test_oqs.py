import oqs


def test_oqs_import():
    """Verify that liboqs-python can be imported."""
    assert oqs is not None


def test_oqs_version():
    """Verify that liboqs reports a version."""
    version = oqs.oqs_version()

    assert isinstance(version, str)
    assert len(version) > 0


def test_kem_available():
    """Verify that at least one KEM is available."""
    kems = oqs.get_enabled_kem_mechanisms()

    assert len(kems) > 0


def test_signature_available():
    """Verify that at least one signature algorithm is available."""
    signatures = oqs.get_enabled_sig_mechanisms()

    assert len(signatures) > 0