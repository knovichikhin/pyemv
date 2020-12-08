import pytest
from pyemv import cvv


def test_generate_ac_exception() -> None:
    # icc cvc3 != 16 bytes
    with pytest.raises(
        ValueError,
        match="ICC CVC3 key must be a double length DES key",
    ):
        cvv.generate_cvc3(
            bytes.fromhex("AAAAAAAAAAAAAAAA"),
            bytes.fromhex("5123456789012345D35121010000000000000F"),
            bytes.fromhex("005E"),
            bytes.fromhex("00000899"),
        )

    # ATC != 2 bytes
    with pytest.raises(
        ValueError,
        match="ATC value must be 2 bytes long",
    ):
        cvv.generate_cvc3(
            bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            bytes.fromhex("5123456789012345D35121010000000000000F"),
            bytes.fromhex("5E"),
            bytes.fromhex("00000899"),
        )

    # UN != 4 bytes
    with pytest.raises(
        ValueError,
        match="Unpredictable number must be 4 bytes long",
    ):
        cvv.generate_cvc3(
            bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            bytes.fromhex("5123456789012345D35121010000000000000F"),
            bytes.fromhex("005E"),
            bytes.fromhex("000899"),
        )
