import typing as _typing

from cryptography.hazmat.backends import default_backend as _default_backend
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
from cryptography.hazmat.primitives.ciphers import modes as _modes

__all__ = [
    "mac_iso9797_3",
    "pad_iso9797_1",
    "pad_iso9797_2",
]


def mac_iso9797_3(
    key1: bytes,
    key2: bytes,
    data: bytes,
    padding: int,
    length: _typing.Optional[int] = None,
) -> bytes:
    r"""ISO/IEC 9797-1 MAC algorithm 3. Requires two independent keys.
    Only the last data block is processed using TDES,
    all previous blocks are processed using single DES.

    Parameters
    ----------
    key1 : bytes
        Binary MAC key used in initial transformation.
        Has to be a valid DES key.
    key2 : bytes
        Binary MAC key used  in output transformation.
        Has to be a valid DES key.
    data : bytes
        Data to be MAC'd.
    padding : int
        Padding method of `data`.

            - 1 = ISO/IEC 9797-1 method 1.
            - 2 = ISO/IEC 9797-1 method 2.

    length : int, optional
        Desired length of AC [4 <= N <= 8] (default 8 bytes).

    Returns
    -------
    mac : bytes
        Returns a binary MAC of requested length

    Raises
    ------
    ValueError
        Invalid padding method specified

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    See Also
    --------
    pyemv.mac.pad_iso9797_1 : ISO/IEC 9791-1 padding method 1
    pyemv.mac.pad_iso9797_2 : ISO/IEC 9791-1 padding method 2
    pyemv.mac.pad_iso9797_3 : ISO/IEC 9791-1 padding method 3

    Examples
    --------
    >>> from pyemv.mac import mac_iso9797_3
    >>> key1 = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> key2 = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
    >>> data = bytes.fromhex("1234567890ABCDEF")
    >>> mac_iso9797_3(key1, key2, data, padding=2).hex().upper()
    '644AA5C915DBDAF8'
    """
    if length is None:
        length = 8

    if padding == 1:
        data = pad_iso9797_1(data, 8)
    elif padding == 2:
        data = pad_iso9797_2(data, 8)
    else:
        raise ValueError("Specify valid padding method: 1 or 2.")

    # Encrypt first block with key1 then
    # encrypt the rest of the data in CBC mode
    cipher1 = _Cipher(
        _algorithms.TripleDES(key1),
        _modes.CBC(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        backend=_default_backend(),
    )
    encryptor1 = cipher1.encryptor()
    data = encryptor1.update(data)[-8:]

    # Decrypt the last block with key2 and then encrypt it with key1
    cipher2 = _Cipher(
        _algorithms.TripleDES(key2), _modes.CBC(data), backend=_default_backend()
    )
    decryptor2 = cipher2.decryptor()
    return encryptor1.update(decryptor2.update(data))[:length]


def pad_iso9797_1(data: bytes, block_size: _typing.Optional[int] = None) -> bytes:
    r"""ISO/IEC 9797-1 padding method 1.
    Add the smallest number of "0x00" bytes to the right
    such that the length of resulting message is a multiple of
    `block_size` bytes. If the data is already multiple of
    `block_size` bytes then no bytes added

    Parameters
    ----------
    data : bytes
        Data to be padded
    block_size : int, optional
        Padded data will be multiple of specified block size (default 8).

    Returns
    -------
    bytes
        Padded data

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    Examples
    --------
    >>> from pyemv.mac import pad_iso9797_1
    >>> pad_iso9797_1(bytes.fromhex("1234")).hex().upper()
    '1234000000000000'
    """
    if block_size is None:
        block_size = 8

    remainder = len(data) % block_size
    if remainder > 0:
        return data + (b"\x00" * (block_size - remainder))

    if len(data) == 0:
        return b"\x00" * block_size

    return data


def pad_iso9797_2(data: bytes, block_size: _typing.Optional[int] = None) -> bytes:
    r"""ISO/IEC 9797-1 padding method 2 (equivalent to ISO/IEC 7816-4).
    Add a mandatory "0x80" byte to the right of data,
    and then add the smallest number of "0x00" bytes to the right
    such that the length of resulting message is a multiple of
    `block_size` bytes.

    Parameters
    ----------
    data : bytes
        Data to be padded
    block_size : int, optional
        Padded data will be multiple of specified block size (default 8).

    Returns
    -------
    bytes
        Padded data

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    Examples
    --------
    >>> from pyemv.mac import pad_iso9797_2
    >>> pad_iso9797_2(bytes.fromhex("1234")).hex().upper()
    '1234800000000000'
    """
    if block_size is None:
        block_size = 8

    return pad_iso9797_1(data + b"\x80", block_size)
