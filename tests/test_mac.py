import pytest

from pyemv import mac


def test_mac_iso9797_3() -> None:
    # SK < 16 bytes
    with pytest.raises(
        ValueError,
        match="pecify valid padding method: 1 or 2.",
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


def test_pad_iso9797_1() -> None:
    _mac = mac.pad_iso9797_1(b"")
    assert _mac == b"\x00" * 8

    for i in range(0, 9):
        _mac = mac.pad_iso9797_1(b"F" * i, 8)
        assert _mac == (b"F" * i) + (b"\x00" * (8 - i))

    for i in range(0, 17):
        _mac = mac.pad_iso9797_1(b"F" * i, 16)
        assert _mac == (b"F" * i) + (b"\x00" * (16 - i))


def test_pad_iso9797_2() -> None:
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
