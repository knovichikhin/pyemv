import typing as _typing

__all__ = ["decode", "DecodeError", "encode", "EncodeError"]

DecodedTLV = _typing.Dict[str, _typing.Any]
DecodedTLVFlat = _typing.Dict[str, bytes]


class DecodeError(ValueError):
    r"""Subclass of ValueError that describes TLV decoding error.

    Attributes
    ----------
    msg : str
        The unformatted error message
    tag : str
        Tag where parsing stopped
    offset : int
        Offset in the input data where parsing stopped
    tlv : dict
        Dictionary with partially decoded data
    """

    def __init__(
        self,
        msg: str,
        tag: str,
        offset: int,
        tlv: DecodedTLV,
    ):
        errmsg = f"{msg}: tag '{tag}', offset {offset}."
        ValueError.__init__(self, errmsg)
        self.msg = msg
        self.tag = tag
        self.offset = offset
        self.tlv = tlv


class EncodeError(ValueError):
    def __init__(
        self,
        msg: str,
        tag: str,
    ):
        errmsg = f"{msg}: tag '{tag}'."
        ValueError.__init__(self, errmsg)
        self.msg = msg
        self.tag = tag


# fmt: off
@_typing.overload
def decode(data: bytes) -> DecodedTLV: ...
@_typing.overload
def decode(data: bytes, *, simple: _typing.Optional[bool]) -> DecodedTLV: ...
@_typing.overload
def decode(data: bytes, *, flatten: _typing.Optional[bool] = True) -> DecodedTLVFlat: ...
@_typing.overload
def decode(data: bytes, *, flatten: _typing.Optional[bool] = True, simple: _typing.Optional[bool]) -> DecodedTLVFlat: ...
# fmt: on


def decode(
    data: bytes,
    *,
    flatten: _typing.Optional[bool] = None,
    simple: _typing.Optional[bool] = None,
) -> DecodedTLV:
    r"""Decode TLV data.

    Parameters
    ----------
    data : bytes
        Encoded TLV data
    flatten : bool, optional
        Flatten constructed tags and return one flat dictionary
        with all tags together. Defaults to False.
    simple : bool, optional
        Some specification stipulate that TLV length is always
        1 byte long with a maximum length of 255.
        To enable this option set simple to True. Defaults to False.

    Returns
    -------
    tlv : dict
        Dictionary with partially decoded data

    Raises
    ------
    DecodeError

    Examples
    --------
    >>> from pyemv import tlv
    >>> tlv.decode(bytes.fromhex("9C0101E0055F2A0202089F0200"))
    {'9C': b'\x01', 'E0': {'5F2A': b'\x02\x08'}, '9F02': b''}
    >>> tlv.decode(bytes.fromhex("9C0101E0055F2A0202089F0200"), flatten=True)
    {'9C': b'\x01', '5F2A': b'\x02\x08', '9F02': b''}
    """
    if flatten is None:
        flatten = False

    if simple is None:
        simple = False

    dec: DecodedTLV = {}
    try:
        _decode(data, 0, len(data), dec, flatten, simple)
    except DecodeError as e:
        # Catch the error here to provide reference
        # to a partically decoded data.
        e.tlv = dec
        raise
    return dec


def _decode(
    data: bytes,
    ofst: int,
    ofst_limit: int,
    dec: _typing.Dict[str, _typing.Any],
    flatten: bool,
    simple: bool,
) -> int:
    while ofst < ofst_limit:
        # Determine tag name length.
        tag_name_len = 1
        try:
            # If b0-4 are on then a 2nd byte follows.
            constructed = bool(data[ofst] & 0b00100000)
            if (data[ofst] & 0b00011111) == 0b00011111:
                # If b7 is on then another byte follows
                while data[ofst + tag_name_len] & 0b10000000:
                    tag_name_len += 1
                tag_name_len += 1
        except IndexError:
            raise DecodeError(
                f"Tag malformed, expecting more data",
                data[ofst : ofst + tag_name_len].hex().upper(),
                ofst,
                dec,
            ) from None

        # Check that tag name falls within parent tag
        if ofst + tag_name_len > ofst_limit:
            raise DecodeError(
                f"Tag malformed, expecting more data",
                data[ofst : min(ofst + tag_name_len, ofst_limit)].hex().upper(),
                ofst,
                dec,
            )

        # Save tag name and move farther
        tag = data[ofst : ofst + tag_name_len].hex().upper()
        ofst += tag_name_len

        # Determine tag length
        tag_len_len = 1

        # Check that tag length falls within parent tag
        if ofst + tag_len_len > ofst_limit:
            raise DecodeError(
                f"Tag length malformed, expecting {str(tag_len_len)} byte(s)",
                tag,
                ofst,
                dec,
            )

        if data[ofst] & 0b10000000 and not simple:
            tag_len_len = data[ofst] & 0b01111111
            ofst += 1
            # Data does not have enough bytes to contain full
            # length as indicated by the previous byte.
            if ofst + tag_len_len > ofst_limit:
                raise DecodeError(
                    f"Tag length malformed, expecting {str(tag_len_len)} byte(s)",
                    tag,
                    ofst,
                    dec,
                )
            tag_len = int.from_bytes(data[ofst : ofst + tag_len_len], "big")
            ofst += tag_len_len
        else:
            tag_len = data[ofst]
            ofst += tag_len_len

        # Check that tag data falls within parent tag
        if ofst + tag_len > ofst_limit:
            raise DecodeError(
                f"Tag value malformed, expecting {str(tag_len)} byte(s)",
                tag,
                ofst,
                dec,
            )

        # Constructed data type (b5=on)
        if constructed:
            if flatten:
                ofst = _decode(data, ofst, ofst + tag_len, dec, flatten, simple)
            else:
                dec[tag] = {}
                ofst = _decode(data, ofst, ofst + tag_len, dec[tag], flatten, simple)
        # Primitive data type
        else:
            dec[tag] = data[ofst : ofst + tag_len]
            ofst += tag_len

    return ofst


def encode(tlv: _typing.Mapping[str, _typing.Any]) -> bytes:
    data = _encode(tlv)
    return bytes(data)


def _encode(tlv: _typing.Mapping[str, _typing.Any]) -> bytearray:
    data = bytearray()
    for tag_s, value in tlv.items():
        # Tag
        try:
            tag = bytes.fromhex(tag_s)
            data += tag
        except ValueError:
            raise EncodeError("Invalid tag format, expecting hexchar string", tag_s)

        # Check tag format
        try:
            # If b0-4 are on then a 2nd byte follows.
            tag_name_len = 1
            if (tag[0] & 0b00011111) == 0b00011111:
                # If b7 is on then another byte follows
                while tag[tag_name_len] & 0b10000000:
                    tag_name_len += 1
                tag_name_len += 1
        except IndexError:
            raise EncodeError(
                f"Invalid tag format, expecting more data", tag_s
            ) from None

        if len(tag) != tag_name_len:
            raise EncodeError(f"Invalid tag format, extra data", tag_s)

        # Value
        # Constructed
        if bool(tag[0] & 0b00100000):
            if not isinstance(value, _typing.Mapping):
                raise EncodeError(
                    f"Invalid value type ({value.__class__.__name__}) "
                    "for constructed tag, expecting a dict",
                    tag_s,
                )
            value = _encode(value)
        # Primitive
        elif not isinstance(value, (bytes, bytearray)):
            raise EncodeError(
                f"Invalid value type ({value.__class__.__name__}) "
                "for primitive tag, expecting bytes",
                tag_s,
            )

        # Length
        tag_len_len = 1
        if len(value) > 127:
            # Multi-byte length required
            while len(value) > 2 ** (8 * tag_len_len) - 1:
                tag_len_len += 1
            data += int.to_bytes(tag_len_len | 0b10000000, 1, "big")

        data += int.to_bytes(len(value), tag_len_len, "big") + value

    return data
