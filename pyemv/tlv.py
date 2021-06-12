import typing as _typing

DecodedTLV = _typing.Dict[str, _typing.Union[bytes, _typing.Any]]


def decode(data: bytes) -> DecodedTLV:
    dec: DecodedTLV = {}
    i = _decode(data, len(data), 0, dec)
    return dec


def _decode(data: bytes, l: int, i: int, dec: _typing.Any) -> int:
    while i < len(data):
        # Determine tag name length. If b0-4 are on then a 2nd byte follows.
        tag_len = 1
        if data[i] & 0b00011111:
            # If b7 is on then another byte follows
            while data[i + tag_len] & 0b10000000:
                tag_len += 1
            tag_len += 1

        constructed = bool(data[i] & 0b00100000)

        # Save tag name and move farther
        tag = data[i : i + tag_len].hex().upper()
        i += tag_len

        # Determine tag length
        if data[i] & 0b10000000:
            tag_len_len = data[i] & 0b01111111
            i += 1
            tag_len = int.from_bytes(data[i : i + tag_len_len], "big")
            i += tag_len_len
        else:
            tag_len = data[i]
            i += 1

        # Constructed data type (b5=on)
        if constructed:
            dec[tag] = {}
            i = _decode(data, tag_len, i, dec[tag])
        else:
            # Primitive data type
            dec[tag] = data[i : i + tag_len]
            i += tag_len
    return i


#print(decode(b"\x9f\x02\x81\x01\xff\x9f\x03\x00"))
#print(decode(b"\x9f\x02\x81\x01\xff\xe0\x03\x9f\x03\x00"))
#print(decode(b"\x9f\x02\x81\x01\xff"))
