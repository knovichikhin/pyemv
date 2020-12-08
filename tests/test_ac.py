import pytest

from pyemv import ac


def test_generate_ac_exception() -> None:
    # SK < 16 bytes
    with pytest.raises(
        ValueError,
        match="Session Key must be a double length DES key",
    ):
        ac.generate_ac(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAA"),
            data=bytes.fromhex("12345678901214"),
        )

    # SK > 16 bytes
    with pytest.raises(
        ValueError,
        match="Session Key must be a double length DES key",
    ):
        ac.generate_ac(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            data=bytes.fromhex("12345678901214"),
        )

    # Invalid padding type
    with pytest.raises(
        TypeError,
        match="Padding type must be PaddingType Enum, not dict",
    ):
        ac.generate_ac(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            data=bytes.fromhex("12345678901214"),
            padding_type={},  # type: ignore
        )


def test_generate_arpc_1_exception() -> None:
    # SK < 16 bytes
    with pytest.raises(
        ValueError,
        match="Session Key must be a double length DES key",
    ):
        ac.generate_arpc_1(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAA"),
            arqc=bytes.fromhex("12345678"),
            arpc_rc=bytes.fromhex("0000"),
        )

    # SK > 16 bytes
    with pytest.raises(
        ValueError,
        match="Session Key must be a double length DES key",
    ):
        ac.generate_arpc_1(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            arqc=bytes.fromhex("12345678"),
            arpc_rc=bytes.fromhex("0000"),
        )

    # ARQC < 8 bytes
    with pytest.raises(
        ValueError,
        match="ARQC must be 8 bytes long",
    ):
        ac.generate_arpc_1(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("12345678"),
            arpc_rc=bytes.fromhex("0000"),
        )

    # ARQC > 16 bytes
    with pytest.raises(
        ValueError,
        match="ARQC must be 8 bytes long",
    ):
        ac.generate_arpc_1(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("1234567890ABCDEF12"),
            arpc_rc=bytes.fromhex("0000"),
        )

    # ARPC-RC < 2 bytes
    with pytest.raises(
        ValueError,
        match="ARPC-RC must be 2 bytes long",
    ):
        ac.generate_arpc_1(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("1234567890123456"),
            arpc_rc=bytes.fromhex("00"),
        )

    # ARPC-RC > 2 bytes
    with pytest.raises(
        ValueError,
        match="ARPC-RC must be 2 bytes long",
    ):
        ac.generate_arpc_1(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("1234567890123456"),
            arpc_rc=bytes.fromhex("001122"),
        )


def test_generate_arpc_2_exception() -> None:
    # SK < 16 bytes
    with pytest.raises(
        ValueError,
        match="Session Key must be a double length DES key",
    ):
        ac.generate_arpc_2(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAA"),
            arqc=bytes.fromhex("12345678901214"),
            csu=bytes.fromhex("12345678"),
            prop_auth_data=bytes.fromhex("1234567890123456"),
        )

    # SK > 16 bytes
    with pytest.raises(
        ValueError,
        match="Session Key must be a double length DES key",
    ):
        ac.generate_arpc_2(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
            arqc=bytes.fromhex("12345678901214"),
            csu=bytes.fromhex("12345678"),
            prop_auth_data=bytes.fromhex("1234567890123456"),
        )

    # ARQC < 8 bytes
    with pytest.raises(
        ValueError,
        match="ARQC must be 8 bytes long",
    ):
        ac.generate_arpc_2(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("12345678901214"),
            csu=bytes.fromhex("12345678"),
            prop_auth_data=bytes.fromhex("1234567890123456"),
        )

    # ARQC > 16 bytes
    with pytest.raises(
        ValueError,
        match="ARQC must be 8 bytes long",
    ):
        ac.generate_arpc_2(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("1234567890ABCDEF12"),
            csu=bytes.fromhex("12345678"),
            prop_auth_data=bytes.fromhex("1234567890123456"),
        )

    # CSU < 4 bytes
    with pytest.raises(
        ValueError,
        match="CSU must be 4 bytes long",
    ):
        ac.generate_arpc_2(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("1234567890121456"),
            csu=bytes.fromhex("123456"),
            prop_auth_data=bytes.fromhex("1234567890123456"),
        )

    # CSU > 4 bytes
    with pytest.raises(
        ValueError,
        match="CSU must be 4 bytes long",
    ):
        ac.generate_arpc_2(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("1234567890121456"),
            csu=bytes.fromhex("1234567890"),
            prop_auth_data=bytes.fromhex("1234567890123456"),
        )

    # PAD > 8 bytes
    with pytest.raises(
        ValueError,
        match="Proprietary Authentication Data must be 0-8 bytes long",
    ):
        ac.generate_arpc_2(
            sk_ac=bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"),
            arqc=bytes.fromhex("1234567890121456"),
            csu=bytes.fromhex("12345678"),
            prop_auth_data=bytes.fromhex("123456789012345678"),
        )
