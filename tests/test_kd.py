import pytest

from pyemv import kd


def test_derive_common_sk_exception():
    # ISS MK < 16 bytes
    with pytest.raises(
        ValueError, match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAA"),
            r=bytes.fromhex("FFFFFFFFFFFFFFFF"),
        )

    # ISS MK > 16 bytes
    with pytest.raises(
        ValueError, match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            r=bytes.fromhex("FFFFFFFFFFFFFFFF"),
        )

    # R < 8 bytes
    with pytest.raises(
        ValueError, match="Diversification value must be 8 bytes long",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            r=bytes.fromhex("FFFFFFFFFFFFFF"),
        )

    # R > 8 bytes
    with pytest.raises(
        ValueError, match="Diversification value must be 8 bytes long",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            r=bytes.fromhex("FFFFFFFFFFFFFFFFFF"),
        )


def test_derive_visa_sm_sk_exception():
    # ISS MK < 16 bytes
    with pytest.raises(
        ValueError, match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAA"), atc=bytes.fromhex("FFFF")
        )

    # ISS MK > 16 bytes
    with pytest.raises(
        ValueError, match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            atc=bytes.fromhex("FFFF"),
        )

    # ATC < 2 bytes
    with pytest.raises(
        ValueError, match="ATC value must be 2 bytes long",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FF"),
        )

    # ATC > 2 bytes
    with pytest.raises(
        ValueError, match="ATC value must be 2 bytes long",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FFFFFF"),
        )
