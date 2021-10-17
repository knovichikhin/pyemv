import pytest

from pyemv import kd


def test_derive_common_sk_exception() -> None:
    # ISS MK < 16 bytes
    with pytest.raises(
        ValueError,
        match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAA"),
            r=bytes.fromhex("FFFFFFFFFFFFFFFF"),
        )

    # ISS MK > 16 bytes
    with pytest.raises(
        ValueError,
        match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            r=bytes.fromhex("FFFFFFFFFFFFFFFF"),
        )

    # R < 8 bytes
    with pytest.raises(
        ValueError,
        match="Diversification value must be 8 bytes long",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            r=bytes.fromhex("FFFFFFFFFFFFFF"),
        )

    # R > 8 bytes
    with pytest.raises(
        ValueError,
        match="Diversification value must be 8 bytes long",
    ):
        kd.derive_common_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            r=bytes.fromhex("FFFFFFFFFFFFFFFFFF"),
        )


def test_derive_visa_sm_sk_exception() -> None:
    # ISS MK < 16 bytes
    with pytest.raises(
        ValueError,
        match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAA"), atc=bytes.fromhex("FFFF")
        )

    # ISS MK > 16 bytes
    with pytest.raises(
        ValueError,
        match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            atc=bytes.fromhex("FFFF"),
        )

    # ATC < 2 bytes
    with pytest.raises(
        ValueError,
        match="ATC value must be 2 bytes long",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FF"),
        )

    # ATC > 2 bytes
    with pytest.raises(
        ValueError,
        match="ATC value must be 2 bytes long",
    ):
        kd.derive_visa_sm_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FFFFFF"),
        )


def test_derive_emv2000_tree_sk_exception() -> None:
    # ISS MK < 16 bytes
    with pytest.raises(
        ValueError,
        match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_emv2000_tree_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAA"), atc=bytes.fromhex("FFFF")
        )

    # ISS MK > 16 bytes
    with pytest.raises(
        ValueError,
        match="ICC Master Key must be a double length DES key",
    ):
        kd.derive_emv2000_tree_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            atc=bytes.fromhex("FFFF"),
        )

    # ATC < 2 bytes
    with pytest.raises(
        ValueError,
        match="ATC value must be 2 bytes long",
    ):
        kd.derive_emv2000_tree_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FF"),
        )

    # ATC > 2 bytes
    with pytest.raises(
        ValueError,
        match="ATC value must be 2 bytes long",
    ):
        kd.derive_emv2000_tree_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FFFFFF"),
        )

    # IV < 16 bytes
    with pytest.raises(
        ValueError,
        match="Initialization vector value must be 16 bytes long",
    ):
        kd.derive_emv2000_tree_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FFFF"),
            iv=bytes.fromhex("000000000000000000000000000000"),
        )

    # IV > 16 bytes
    with pytest.raises(
        ValueError,
        match="Initialization vector value must be 16 bytes long",
    ):
        kd.derive_emv2000_tree_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FFFF"),
            iv=bytes.fromhex("0000000000000000000000000000000000"),
        )

    # Branch factor and tree height must be able to generate enough session
    # keys to cover every possible ATC value
    with pytest.raises(
        ValueError,
        match="Number of possible session keys must exceed maximum ATC value",
    ):
        kd.derive_emv2000_tree_sk(
            icc_mk=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            atc=bytes.fromhex("FFFF"),
            branch_factor=1,
            height=1,
        )
