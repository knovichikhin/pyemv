import pytest

from pyemv import mac


def test_mac_iso9797_3():
    # SK < 16 bytes
    with pytest.raises(
        ValueError,
        match="pecify valid padding method: 1, 2 or 3.",
    ):
        mac.mac_iso9797_3(
            bytes.fromhex("AAAAAAAAAAAAAAAA"),
            bytes.fromhex("BBBBBBBBBBBBBBBB"),
            b"hello world",
            4,
        )

    _mac = (
        mac.mac_iso9797_3(
            bytes.fromhex("AAAAAAAAAAAAAAAA"),
            bytes.fromhex("BBBBBBBBBBBBBBBB"),
            b"hello world",
            1,
        )
        .hex()
        .upper()
    )
    assert _mac == "78DA3D3DEB48FD4D"

    _mac = (
        mac.mac_iso9797_3(
            bytes.fromhex("AAAAAAAAAAAAAAAA"),
            bytes.fromhex("BBBBBBBBBBBBBBBB"),
            b"hello world",
            2,
        )
        .hex()
        .upper()
    )
    assert _mac == "2BC2D9EDE0CF31F6"

    _mac = (
        mac.mac_iso9797_3(
            bytes.fromhex("AAAAAAAAAAAAAAAA"),
            bytes.fromhex("BBBBBBBBBBBBBBBB"),
            b"hello world",
            3,
        )
        .hex()
        .upper()
    )
    assert _mac == "1789FED38FC05D1B"


def test_pad_iso9797_1():
    _mac = mac.pad_iso9797_1(b"")
    assert _mac == b"\x00" * 8

    for i in range(0, 9):
        _mac = mac.pad_iso9797_1(b"F" * i, 8)
        assert _mac == (b"F" * i) + (b"\x00" * (8 - i))

    for i in range(0, 17):
        _mac = mac.pad_iso9797_1(b"F" * i, 16)
        assert _mac == (b"F" * i) + (b"\x00" * (16 - i))


def test_pad_iso9797_2():
    _mac = mac.pad_iso9797_2(b"")
    assert _mac == b"\x80" + b"\x00" * 7

    for i in range(0, 8):
        _mac = mac.pad_iso9797_2(b"F" * i, 8)
        assert _mac == (b"F" * i) + b"\x80" + (b"\x00" * (7 - i))
    _mac = mac.pad_iso9797_2(b"F" * 8, 8)
    assert _mac == (b"F" * 8) + b"\x80" + (b"\x00" * 7)

    for i in range(0, 16):
        _mac = mac.pad_iso9797_2(b"F" * i, 16)
        assert _mac == (b"F" * i) + b"\x80" + (b"\x00" * (15 - i))
    _mac = mac.pad_iso9797_2(b"F" * 16, 16)
    assert _mac == (b"F" * 16) + b"\x80" + (b"\x00" * 15)


def test_pad_iso9797_3():
    _mac = mac.pad_iso9797_3(b"")
    assert _mac == b"\x00" * 8 + b"\x00" * 8
    _mac = mac.pad_iso9797_3(b"", 16)
    assert _mac == b"\x00" * 16 + b"\x00" * 16

    _mac = mac.pad_iso9797_3(b"F" * 1, 8)
    assert _mac == b"\x00" * 7 + b"\x08" + (b"F" * 1) + (b"\x00" * (8 - 1))
    _mac = mac.pad_iso9797_3(b"F" * 2, 8)
    assert _mac == b"\x00" * 7 + b"\x10" + (b"F" * 2) + (b"\x00" * (8 - 2))
    _mac = mac.pad_iso9797_3(b"F" * 3, 8)
    assert _mac == b"\x00" * 7 + b"\x18" + (b"F" * 3) + (b"\x00" * (8 - 3))
    _mac = mac.pad_iso9797_3(b"F" * 4, 8)
    assert _mac == b"\x00" * 7 + b"\x20" + (b"F" * 4) + (b"\x00" * (8 - 4))
    _mac = mac.pad_iso9797_3(b"F" * 5, 8)
    assert _mac == b"\x00" * 7 + b"\x28" + (b"F" * 5) + (b"\x00" * (8 - 5))
    _mac = mac.pad_iso9797_3(b"F" * 6, 8)
    assert _mac == b"\x00" * 7 + b"\x30" + (b"F" * 6) + (b"\x00" * (8 - 6))
    _mac = mac.pad_iso9797_3(b"F" * 7, 8)
    assert _mac == b"\x00" * 7 + b"\x38" + (b"F" * 7) + (b"\x00" * (8 - 7))
    _mac = mac.pad_iso9797_3(b"F" * 8, 8)
    assert _mac == b"\x00" * 7 + b"\x40" + (b"F" * 8) + (b"\x00" * (8 - 8))

    _mac = mac.pad_iso9797_3(b"F" * 1, 16)
    assert _mac == b"\x00" * 15 + b"\x08" + (b"F" * 1) + (b"\x00" * (16 - 1))
    _mac = mac.pad_iso9797_3(b"F" * 2, 16)
    assert _mac == b"\x00" * 15 + b"\x10" + (b"F" * 2) + (b"\x00" * (16 - 2))
    _mac = mac.pad_iso9797_3(b"F" * 3, 16)
    assert _mac == b"\x00" * 15 + b"\x18" + (b"F" * 3) + (b"\x00" * (16 - 3))
    _mac = mac.pad_iso9797_3(b"F" * 4, 16)
    assert _mac == b"\x00" * 15 + b"\x20" + (b"F" * 4) + (b"\x00" * (16 - 4))
    _mac = mac.pad_iso9797_3(b"F" * 5, 16)
    assert _mac == b"\x00" * 15 + b"\x28" + (b"F" * 5) + (b"\x00" * (16 - 5))
    _mac = mac.pad_iso9797_3(b"F" * 6, 16)
    assert _mac == b"\x00" * 15 + b"\x30" + (b"F" * 6) + (b"\x00" * (16 - 6))
    _mac = mac.pad_iso9797_3(b"F" * 7, 16)
    assert _mac == b"\x00" * 15 + b"\x38" + (b"F" * 7) + (b"\x00" * (16 - 7))
    _mac = mac.pad_iso9797_3(b"F" * 8, 16)
    assert _mac == b"\x00" * 15 + b"\x40" + (b"F" * 8) + (b"\x00" * (16 - 8))
    _mac = mac.pad_iso9797_3(b"F" * 9, 16)
    assert _mac == b"\x00" * 15 + b"\x48" + (b"F" * 9) + (b"\x00" * (16 - 9))
    _mac = mac.pad_iso9797_3(b"F" * 10, 16)
    assert _mac == b"\x00" * 15 + b"\x50" + (b"F" * 10) + (b"\x00" * (16 - 10))
    _mac = mac.pad_iso9797_3(b"F" * 11, 16)
    assert _mac == b"\x00" * 15 + b"\x58" + (b"F" * 11) + (b"\x00" * (16 - 11))
    _mac = mac.pad_iso9797_3(b"F" * 12, 16)
    assert _mac == b"\x00" * 15 + b"\x60" + (b"F" * 12) + (b"\x00" * (16 - 12))
    _mac = mac.pad_iso9797_3(b"F" * 13, 16)
    assert _mac == b"\x00" * 15 + b"\x68" + (b"F" * 13) + (b"\x00" * (16 - 13))
    _mac = mac.pad_iso9797_3(b"F" * 14, 16)
    assert _mac == b"\x00" * 15 + b"\x70" + (b"F" * 14) + (b"\x00" * (16 - 14))
    _mac = mac.pad_iso9797_3(b"F" * 15, 16)
    assert _mac == b"\x00" * 15 + b"\x78" + (b"F" * 15) + (b"\x00" * (16 - 15))
    _mac = mac.pad_iso9797_3(b"F" * 16, 16)
    assert _mac == b"\x00" * 15 + b"\x80" + (b"F" * 16) + (b"\x00" * (16 - 16))
