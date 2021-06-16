from typing import Any, Optional

import pytest
from pyemv import tlv


# fmt: off
@pytest.mark.parametrize(
    ["tags", "value"],
    [
        ("", {}),
        # Single byte length length
        ("9C00",       {"9C":     b""}),
        ("9C01FF",     {"9C":     b"\xFF"}),
        ("9C8101FF",   {"9C":     b"\xFF"}),
        ("9F0200",     {"9F02":   b""}),
        ("9F0201FF",   {"9F02":   b"\xFF"}),
        ("9F820100",   {"9F8201": b""}),
        ("9F820101FF", {"9F8201": b"\xFF"}),
        # Extended length
        ("9C80",           {"9C": b""}),
        ("9C8100",         {"9C": b""}),
        ("9C820000",       {"9C": b""}),
        ("9C83000000",     {"9C": b""}),
        ("9C8400000000",   {"9C": b""}),
        ("9C8101FF",       {"9C": b"\xFF"}),
        ("9C820001FF",     {"9C": b"\xFF"}),
        ("9C83000001FF",   {"9C": b"\xFF"}),
        ("9C8400000001FF", {"9C": b"\xFF"}),
    ],
)
# fmt: on
def test_decode_tag(tags: str, value: Any) -> None:
    r = tlv.decode(bytes.fromhex(tags))
    assert r == value


# fmt: off
@pytest.mark.parametrize(
    ["tags", "value"],
    [
        ("", {}),
        # Single byte length length
        ("9C00",       {"9C":     ""}),
        ("9C01FF",     {"9C":     "FF"}),
        ("9C8101FF",   {"9C":     "FF"}),
        ("9F0200",     {"9F02":   ""}),
        ("9F0201FF",   {"9F02":   "FF"}),
        ("9F820100",   {"9F8201": ""}),
        ("9F820101FF", {"9F8201": "FF"}),
        # Extended length
        ("9C80",           {"9C": ""}),
        ("9C8100",         {"9C": ""}),
        ("9C820000",       {"9C": ""}),
        ("9C83000000",     {"9C": ""}),
        ("9C8400000000",   {"9C": ""}),
        ("9C8101FF",       {"9C": "FF"}),
        ("9C820001FF",     {"9C": "FF"}),
        ("9C83000001FF",   {"9C": "FF"}),
        ("9C8400000001FF", {"9C": "FF"}),
    ],
)
# fmt: on
def test_decode_tag_coerce(tags: str, value: Any) -> None:
    r = tlv.decode(
        bytes.fromhex(tags), convert=lambda t, v: v.hex().upper(), flatten=True
    )
    assert r == value


def test_decode_nested() -> None:
    r = tlv.decode(b"\x9f\x02\x01\xff\xe0\x03\x9f\x03\x00\x9f\x04\x00")
    assert r == {"9F02": b"\xff", "E0": {"9F03": b""}, "9F04": b""}


def test_decode_nested_flat() -> None:
    r = tlv.decode(b"\x9f\x02\x01\xff\xe0\x03\x9f\x03\x00\x9f\x04\x00", flatten=True)
    assert r == {"9F02": b"\xff", "9F03": b"", "9F04": b""}

    r = tlv.decode(
        b"\x9f\x02\x01\xff\xe0\x04\x9f\x02\x01\xaa\x9f\x04\x00", flatten=True
    )
    assert r == {"9F02": b"\xaa", "9F04": b""}


def test_decode_simple() -> None:
    r = tlv.decode(b"\x9f\x02\xff" + b"\xee" * 255 + b"\x9f\x03\x00", simple=True)
    assert r == {"9F02": b"\xee" * 255, "9F03": b""}


# fmt: off
@pytest.mark.parametrize(
    ["tags", "tag", "offset", "value", "error"],
    [
        # Malformed simple tags (before recursion)
        # Missing tag
        ("9F",   "9F",   0, {}, "Tag malformed, expecting more data: tag '9F', offset 0."),
        ("9FF0", "9FF0", 0, {}, "Tag malformed, expecting more data: tag '9FF0', offset 0."),
        # Missing length
        ("9C",     "9C", 1, {}, "Tag length malformed, expecting 1 byte(s): tag '9C', offset 1."),
        ("9C81",   "9C", 2, {}, "Tag length malformed, expecting 1 byte(s): tag '9C', offset 2."),
        ("9C8200", "9C", 2, {}, "Tag length malformed, expecting 2 byte(s): tag '9C', offset 2."),
        # Missing data
        ("9C01",   "9C", 2, {}, "Tag value malformed, expecting 1 byte(s): tag '9C', offset 2."),
        ("9C0200", "9C", 2, {}, "Tag value malformed, expecting 2 byte(s): tag '9C', offset 2."),
        ("E001",   "E0", 2, {}, "Tag value malformed, expecting 1 byte(s): tag 'E0', offset 2."),

        # Malformed constructed tags
        # Data must be preset after constructed tag to make things more complex.
        # Reported error must be  accurate.
        # Missing tag
        ("E0019F0001FF",       "9F", 2, {'E0': {}}, "Tag malformed, expecting more data: tag '9F', offset 2."),
        # Missing length
        ("E0019C01FF",         "9C", 3, {'E0': {}}, "Tag length malformed, expecting 1 byte(s): tag '9C', offset 3."),
        ("E0029C8101FF",       "9C", 4, {'E0': {}}, "Tag length malformed, expecting 1 byte(s): tag '9C', offset 4."),
        ("E0039C8201FF",       "9C", 4, {'E0': {}}, "Tag length malformed, expecting 2 byte(s): tag '9C', offset 4."),
        # Missing data
        ("E0039C8101C001FF",   "9C", 5, {'E0': {}}, "Tag value malformed, expecting 1 byte(s): tag '9C', offset 5."),
        ("E0049C810200C001FF", "9C", 5, {'E0': {}}, "Tag value malformed, expecting 2 byte(s): tag '9C', offset 5."),

        # Make sure exception contains correct TLV data
        ("9C01FFAA",     "AA", 4, {"9C": b"\xFF"},         "Tag length malformed, expecting 1 byte(s): tag 'AA', offset 4."),
        ("E0039C01FFAA", "AA", 6, {"E0": {"9C": b"\xFF"}}, "Tag length malformed, expecting 1 byte(s): tag 'AA', offset 6."),
    ],
)
# fmt: on
def test_decode_exception(
    tags: str, tag: str, offset: int, value: Any, error: str
) -> None:
    tags_b = bytes.fromhex(tags)
    with pytest.raises(tlv.DecodeError) as e:
        _ = tlv.decode(tags_b)
    assert e.value.args[0] == error
    assert e.value.tag == tag
    assert e.value.offset == offset
    assert e.value.tlv == value


# fmt: off
@pytest.mark.parametrize(
    ["tags", "value"],
    [
        ({}, ""),
        # Single byte length length
        ({"9C": b""},         "9C00"),
        ({"9C": b"\xFF"},     "9C01FF"),
        ({"9F00": b"\xFF"},   "9F0001FF"),
        ({"9F8001": b"\xFF"}, "9F800101FF"),
        # Extended length
        ({"9C": b"\xFF"*128}, "9C8180"+"FF"*128),
        ({"9C": b"\xFF"*511}, "9C8201FF"+"FF"*511),
        # Constructed
        ({"E0": {}},                "E000"),
        ({"E0": {"9C": b""}},       "E0029C00"),
        ({"E0": {"9C": b"\xFF"}},   "E0039C01FF"),
        ({"E0": {"9F00": b"\xFF"}}, "E0049F0001FF"),
        ({"E0": {"9F00": b"\xFF"}, "9C": b"\xFF"}, "E0049F0001FF9C01FF"),
    ],
)
# fmt: on
def test_encode(tags: Any, value: str) -> None:
    r = tlv.encode(tags)
    assert r == bytes.fromhex(value)


# fmt: off
@pytest.mark.parametrize(
    ["tags", "value"],
    [
        ({}, ""),
        # Single byte length length
        ({"9C": ""},       "9C00"),
        ({"9C": "FF"},     "9C01FF"),
        ({"9F00": "FF"},   "9F0001FF"),
        ({"9F8001": "FF"}, "9F800101FF"),
        # Extended length
        ({"9C": "FF"*128}, "9C8180"+"FF"*128),
        ({"9C": "FF"*511}, "9C8201FF"+"FF"*511),
        # Constructed
        ({"E0": {}},                "E000"),
        ({"E0": {"9C": ""}},       "E0029C00"),
        ({"E0": {"9C": "FF"}},   "E0039C01FF"),
        ({"E0": {"9F00": "FF"}}, "E0049F0001FF"),
        ({"E0": {"9F00": "FF"}, "9C": "FF"}, "E0049F0001FF9C01FF"),
    ],
)
# fmt: on
def test_encode_str(tags: Any, value: str) -> None:
    r = tlv.encode(tags)
    assert r == bytes.fromhex(value)


# fmt: off
@pytest.mark.parametrize(
    ["tags", "value"],
    [
        ({}, ""),
        # Single byte length length
        ({"9C": b""},         "9C00"),
        ({"9C": b"\xFF"},     "9C01FF"),
        ({"9F00": b"\xFF"},   "9F0001FF"),
        ({"9F8001": b"\xFF"}, "9F800101FF"),
        # Extended length
        ({"9C": b"\xFF"*128}, "9C80"+"FF"*128),
        ({"9C": b"\xFF"*255}, "9CFF"+"FF"*255),
        # Constructed
        ({"E0": {}},                "E000"),
        ({"E0": {"9C": b""}},       "E0029C00"),
        ({"E0": {"9C": b"\xFF"}},   "E0039C01FF"),
        ({"E0": {"9F00": b"\xFF"}}, "E0049F0001FF"),
        ({"E0": {"9F00": b"\xFF"}, "9C": b"\xFF"}, "E0049F0001FF9C01FF"),
    ],
)
# fmt: on
def test_encode_simple(tags: Any, value: str) -> None:
    r = tlv.encode(tags, simple=True)
    assert r == bytes.fromhex(value)


# fmt: off
@pytest.mark.parametrize(
    ["tags", "tag", "error"],
    [
        # Tag
        ({"XX": b""},     "XX",     "Invalid tag format, expecting hexchar string: tag 'XX'."),
        ({"00X": b""},    "00X",    "Invalid tag format, expecting hexchar string: tag '00X'."),
        ({"0": b""},      "0",      "Invalid tag format, expecting hexchar string: tag '0'."),
        ({"9F": b""},     "9F",     "Invalid tag format, expecting more data: tag '9F'."),
        ({"9F0001": b""}, "9F0001", "Invalid tag format, extra data: tag '9F0001'."),
        # Value
        ({"EC": []},   "EC",  "Invalid value type (list) for a constructed tag, expecting a dict: tag 'EC'."),
        ({"EC": ()},   "EC",  "Invalid value type (tuple) for a constructed tag, expecting a dict: tag 'EC'."),
        ({"9C": []},   "9C",  "Invalid value type (list) for a primitive tag, expecting bytes or str: tag '9C'."),
        ({"9C": ()},   "9C",  "Invalid value type (tuple) for a primitive tag, expecting bytes or str: tag '9C'."),
        ({"9C": "0"},  "9C", "Invalid value format, expecting hexchar string: tag '9C'."),
        ({"9C": "X"},  "9C", "Invalid value format, expecting hexchar string: tag '9C'."),
    ],
)
# fmt: on
def test_encode_exception(tags: Any, tag: str, error: str) -> None:
    with pytest.raises(tlv.EncodeError) as e:
        _ = tlv.encode(tags)
    assert e.value.args[0] == error
    assert e.value.tag == tag


# fmt: off
@pytest.mark.parametrize(
    ["tags", "tag", "error"],
    [
        ({"9C": b"\xFF" * 256}, "9C", "Value length (256) cannot exceed 255 bytes when 'simple' is enabled: tag '9C'."),
        ({"9C": "FF" * 256},    "9C", "Value length (256) cannot exceed 255 bytes when 'simple' is enabled: tag '9C'."),
    ],
)
# fmt: on
def test_encode_simple_exception(tags: Any, tag: str, error: str) -> None:
    with pytest.raises(tlv.EncodeError) as e:
        _ = tlv.encode(tags, simple=True)
    assert e.value.args[0] == error
    assert e.value.tag == tag
