r"""Use TLV decoder and encoder to disassemble and assemble tag-length-value EMV data.

By default TLV data is broken down into bytes:

    >>> import pyemv
    >>> tlv_data = bytes.fromhex("9C0101E0055F2A0202089F0200")
    >>> pyemv.tlv.decode(tlv_data)
    {'9C': b'\x01', 'E0': {'5F2A': b'\x02\x08'}, '9F02': b''}
    >>> pyemv.tlv.encode({'9C': b'\x01', 'E0': {'5F2A': b'\x02\x08'}, '9F02': b''}).hex().upper()
    '9C0101E0055F2A0202089F0200'

It can also be converted to strings (among other things):

    >>> import pyemv
    >>> tlv_data = bytes.fromhex("9C0101E0055F2A0202089F0200")
    >>> pyemv.tlv.decode(tlv_data, convert=lambda t, v: v.hex().upper())
    {'9C': '01', 'E0': {'5F2A': '0208'}, '9F02': ''}
    >>> pyemv.tlv.encode({'9C': '01', 'E0': {'5F2A': '0208'}, '9F02': ''}).hex().upper()
    '9C0101E0055F2A0202089F0200'
"""

import typing as _t

__all__ = ["decode", "DecodeError", "encode", "EncodeError"]


class DecodeError(ValueError):
    r"""Subclass of ValueError that describes TLV decoding error.

    Attributes
    ----------
    msg : str
        The unformatted error message
    tag : str
        Tag where decoding stopped
    offset : int
        Offset in the input data where decoding stopped
    tlv : dict
        Dictionary with partially decoded data
    """

    def __init__(
        self,
        msg: str,
        tag: str,
        offset: int,
        tlv: _t.Dict[str, _t.Any],
    ):
        errmsg = f"{msg}: tag '{tag}', offset {offset}."
        ValueError.__init__(self, errmsg)
        self.msg = msg
        self.tag = tag
        self.offset = offset
        self.tlv = tlv


class EncodeError(ValueError):
    r"""Subclass of ValueError that describes TLV encoding error.

    Attributes
    ----------
    msg : str
        The unformatted error message
    tag : str
        Tag where decoding stopped
    """

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
_S = _t.TypeVar("_S")
@_t.overload
def decode(data: bytes) -> _t.Dict[str, _t.Any]: ...
@_t.overload
def decode(data: bytes, *, simple: _t.Optional[bool]) -> _t.Dict[str, _t.Any]: ...
@_t.overload
def decode(data: bytes, *, convert: _t.Optional[_t.Callable[[str, _t.Union[bytes, bytearray]], _t.Any]]) -> _t.Dict[str, _t.Any]: ...
@_t.overload
def decode(data: bytes, *, simple: _t.Optional[bool], convert: _t.Optional[_t.Callable[[str, _t.Union[bytes, bytearray]], _t.Any]]) -> _t.Dict[str, _t.Any]: ...
@_t.overload
def decode(data: bytes, *, flatten: _t.Optional[bool] = True) -> _t.Dict[str, bytes]: ...
@_t.overload
def decode(data: bytes, *, flatten: _t.Optional[bool] = True, convert: _t.Optional[_t.Callable[[str, _t.Union[bytes, bytearray]], _S]]) -> _t.Dict[str, _S]: ...
@_t.overload
def decode(data: bytes, *, flatten: _t.Optional[bool] = True, simple: _t.Optional[bool]) -> _t.Dict[str, bytes]: ...
@_t.overload
def decode(data: bytes, *, flatten: _t.Optional[bool] = True, simple: _t.Optional[bool], convert: _t.Optional[_t.Callable[[str, _t.Union[bytes, bytearray]], _S]]) -> _t.Dict[str, _S]: ...
# fmt: on


def decode(
    data: _t.Union[bytes, bytearray],
    *,
    flatten: _t.Optional[bool] = None,
    simple: _t.Optional[bool] = None,
    convert: _t.Optional[_t.Callable[[str, _t.Union[bytes, bytearray]], _t.Any]] = None,
) -> _t.Dict[str, _t.Any]:
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
    convert : callable, optional
        Apply this function to every primitive tag value and
        return tag value in desired format.
        Function must accept tag name as a first argument and
        tag value as a second argument.
        Defauls to 'lambda t, v: bytes(v)' to return bytes objects.

    Returns
    -------
    tlv : dict
        Dictionary with decoded data

    Raises
    ------
    DecodeError

    Notes
    -----
    This decoder adheres to Rules for BER-TLV Data Objects in Annex B or
    EMV 4.3 Book 3 Application Specification.

    Examples
    --------
    >>> from pyemv import tlv
    >>> tlv.decode(bytes.fromhex("9C0101E0055F2A0202089F0200"))
    {'9C': b'\x01', 'E0': {'5F2A': b'\x02\x08'}, '9F02': b''}
    >>> tlv.decode(bytes.fromhex("9C0101E0055F2A0202089F0200"), flatten=True)
    {'9C': b'\x01', '5F2A': b'\x02\x08', '9F02': b''}
    >>> tlv.decode(bytes.fromhex("9C0101E0055F2A0202089F0200"), convert=lambda t, v: v.hex().upper())
    {'9C': '01', 'E0': {'5F2A': '0208'}, '9F02': ''}
    >>> tlv.decode(bytes.fromhex("9C0101E0055F2A0202089F0200"), flatten=True, convert=lambda t, v: v.hex().upper())
    {'9C': '01', '5F2A': '0208', '9F02': ''}
    """

    if flatten is None:
        flatten = False

    if simple is None:
        simple = False

    if convert is None:
        convert = lambda t, v: bytes(v)

    dec: _t.Dict[str, _t.Any] = {}

    try:
        _decode(data, 0, len(data), dec, flatten, simple, convert)
    except DecodeError as e:
        # Catch the error here to provide reference
        # to a partically decoded data.
        e.tlv = dec
        raise
    return dec


def _decode(
    data: _t.Union[bytes, bytearray],
    ofst: int,
    ofst_limit: int,
    dec: _t.Dict[str, _t.Any],
    flatten: bool,
    simple: bool,
    convert: _t.Callable[[str, _t.Union[bytes, bytearray]], _S],
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
                "Tag malformed, expecting more data",
                data[ofst : ofst + tag_name_len].hex().upper(),
                ofst,
                dec,
            ) from None

        # Check that tag name falls within parent tag
        if ofst + tag_name_len > ofst_limit:
            raise DecodeError(
                "Tag malformed, expecting more data",
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
                ofst = _decode(
                    data, ofst, ofst + tag_len, dec, flatten, simple, convert
                )
            else:
                dec[tag] = {}
                ofst = _decode(
                    data, ofst, ofst + tag_len, dec[tag], flatten, simple, convert
                )
        # Primitive data type
        else:
            dec[tag] = convert(tag, data[ofst : ofst + tag_len])
            ofst += tag_len

    return ofst


def encode(
    tlv: _t.Mapping[str, _t.Any],
    *,
    simple: _t.Optional[bool] = None,
) -> bytes:
    r"""Encode TLV data.

    Parameters
    ----------
    data : bytes
        Encoded TLV data
    simple : bool, optional
        Some specification stipulate that TLV length is always
        1 byte long with a maximum length of 255.
        To enable this option set simple to True. Defaults to False.

    Returns
    -------
    tlv : bytes
        Encoded TLV data

    Raises
    ------
    EncodeError

    Notes
    -----
    This encoder adheres to Rules for BER-TLV Data Objects in Annex B or
    EMV 4.3 Book 3 Application Specification.

    Examples
    --------
    >>> from pyemv import tlv
    >>> tlv_data = {'9C': b'\x01', 'E0': {'5F2A': b'\x02\x08'}, '9F02': b''}
    >>> tlv.encode(tlv_data).hex().upper()
    '9C0101E0055F2A0202089F0200'
    >>> tlv_data = {'9C': '01', 'E0': {'5F2A': '0208'}, '9F02': ''}
    >>> tlv.encode(tlv_data).hex().upper()
    '9C0101E0055F2A0202089F0200'
    """

    if simple is None:
        simple = False

    return bytes(_encode(tlv, simple))


def _encode(tlv: _t.Mapping[str, _t.Any], simple: bool) -> bytearray:
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
                "Invalid tag format, expecting more data", tag_s
            ) from None

        if len(tag) != tag_name_len:
            raise EncodeError("Invalid tag format, extra data", tag_s)

        # Value
        # Constructed
        if bool(tag[0] & 0b00100000):
            if not isinstance(value, _t.Mapping):
                raise EncodeError(
                    f"Invalid value type ({value.__class__.__name__}) "
                    "for a constructed tag, expecting a dict",
                    tag_s,
                )
            value = _encode(value, simple)
        # Primitive
        elif isinstance(value, str):
            try:
                value = bytes.fromhex(value)
            except ValueError:
                raise EncodeError(
                    "Invalid value format, expecting hexchar string", tag_s
                )
        elif not isinstance(value, (bytes, bytearray)):
            raise EncodeError(
                f"Invalid value type ({value.__class__.__name__}) "
                "for a primitive tag, expecting bytes or str",
                tag_s,
            )

        # Length
        tag_len_len = 1

        if len(value) > 255 and simple:
            raise EncodeError(
                f"Value length ({str(len(value))}) "
                "cannot exceed 255 bytes when 'simple' is enabled",
                tag_s,
            )

        # Multi-byte length required
        if len(value) > 127 and not simple:
            while len(value) > 2 ** (8 * tag_len_len) - 1:
                tag_len_len += 1
            data += int.to_bytes(tag_len_len | 0b10000000, 1, "big")

        data += int.to_bytes(len(value), tag_len_len, "big") + value

    return data
