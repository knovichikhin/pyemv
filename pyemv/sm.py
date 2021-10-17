r"""The objectives of secure messaging are to ensure data confidentiality, data
integrity, and authentication of the sender. Data integrity and issuer
authentication are achieved using a MAC. Data confidentiality is achieved
using encipherment of the data field.

Secure Messaging Integrity (MAC):

    >>> import pyemv
    >>> mac = pyemv.sm.generate_command_mac(
    ...     sk_smi=bytes.fromhex('0123456789ABCDEFFEDCBA9876543210'),
    ...     command=bytes.fromhex('8424000008'))
    >>> mac.hex().upper()
    '0BFFF5DF3FAA24E1'

Secure Messaging Confidentiality:

    >>> import pyemv
    >>> pin_block=pyemv.sm.format_iso9564_2_pin_block('9999')
    >>> encrypted_pin = pyemv.sm.encrypt_command_data(
    ...     sk_smc=bytes.fromhex('0123456789ABCDEFFEDCBA9876543210'),
    ...     command_data=pin_block,
    ...     encryption_type=pyemv.sm.EncryptionType.EMV)
    >>> encrypted_pin.hex().upper()
    '5A862D1381CCB94822CFDD706A376178'
"""

import binascii as _binascii
import sys as _sys
import typing as _typing
from enum import Enum as _Enum

from pyemv import mac as _mac
from pyemv import tools as _tools

__all__ = [
    "generate_command_mac",
    "EncryptionType",
    "encrypt_command_data",
    "format_vis_pin_block",
    "format_iso9564_2_pin_block",
]


def generate_command_mac(
    sk_smi: bytes, command: bytes, length: _typing.Optional[int] = None
) -> bytes:
    r"""Message Authentication Code (MAC) for Issuer Script Integrity.

    Parameters
    ----------
    sk_smi : bytes
        Binary ICC Session Key for script integrity (MAC).
    command : bytes
        Binary command to be MACed; may or may not include command data, e.g:

            Command Header || { Command Data if present }

        Some issuers choose to append transaction data, such as ATC and ARQC,
        to the command between header and data. The transaction data is present
        for the MAC calculation but not transmitted.

            Command Header || ATC || ARQC || { Command Data if present }

    length : int, optional
        Desired length of AC [4 <= `length` <= 8] (default 8 bytes).

    Returns
    -------
    mac : bytes
        Binary command MAC.

    Raises
    ------
    ValueError
        Session Key must be a double length DES key

    Notes
    -----
    During a transaction the host may send an Issuer Script. These
    Issuer Scripts allow the issuer to block or unblock an application,
    or unblock or change PIN on the card among other things. These issuer
    scripts are extracted from the host response and sent to the card as
    individual commands. These commands contain a MAC value that the card
    authenticates prior to actioning the script. The MAC can be 4-8 bytes
    in length.

    For further details see also:
        - EMV 4.3 Book 2 Section 9.2 Secure Messaging for Integrity and
          Authentication
        - EMV 4.3 Book 2 Section 9.2.1.2 Format 2
        - EMV 4.3 Book 2 Section 9.2.3 MAC Computation
        - EMV 4.3 Book 2 Annex A 1.2

    Examples
    --------
    >>> from pyemv import sm
    >>> sk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> command = bytes.fromhex("8424000008")
    >>> atc = bytes.fromhex("FFFF")
    >>> arqc = bytes.fromhex("1234567890123456")
    >>> mac = sm.generate_command_mac(sk_smi, command + atc + arqc)
    >>> mac.hex().upper()
    'E07B8DF1B4184282'
    """
    if len(sk_smi) != 16:
        raise ValueError("Session Key must be a double length DES key")

    return _mac.mac_iso9797_3(sk_smi[:8], sk_smi[-8:], command, 2, length)


class EncryptionType(_Enum):
    VISA = 1
    MASTERCARD = 2
    EMV = 3


def encrypt_command_data(
    sk_smc: bytes, command_data: bytes, encryption_type: EncryptionType
) -> bytes:
    r"""Command Data Encryption for Issuer Script Confidentiality.

    Parameters
    ----------
    sk_smc : bytes
        Binary ICC Session Key for script confidentiality.
    command_data : bytes
        Binary command data, e.g. PUT DATA or PIN block.
    encryption_type : EncryptionType
        Defines triple DES mode and padding method of `command_data`:

            - VISA = Prepend the command data with one byte containing the
              length of the command data. Then pad data according to
              ISO/IEC 9797-1 method 2.
            - MASTERCARD = If the command data is not multiple of 8 bytes then
              pad data according to ISO/IEC 9797-1 method 2.
            - EMV = Pad data according to ISO/IEC 9797-1 method 2.

    Returns
    -------
    encrypted_command_data : bytes
        Binary encrypted command data. Then the resulting command is:

            Header || Encrypted Data || MAC


    Raises
    ------
    ValueError
        Session Key must be a double length DES key
    TypeError
        Encryption type must be EncryptionType Enum

    Notes
    -----
    The Issuer Script sent by the host may contain command data, i.e.
    PUT DATA command on card data or the PIN Change issuer script.
    The issuer may decide to encrypt the command data

    For further details see also:
        - EMV 4.3 Book 2 Section 9.3 Secure Messaging for Confidentiality
        - EMV 4.3 Book 2 Section 9.3.1.2 Format 2
        - EMV 4.3 Book 2 Annex A 1.1

    See Also
    --------
    pyemv.mac.pad_iso9797_2 : ISO/IEC 9797-1 padding method 2

    Examples
    --------
    >>> from pyemv import sm
    >>> sk_smc = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> pin_block = bytes.fromhex("241234FFFFFFFFFF")
    >>> command_data = sm.encrypt_command_data(
    ...     sk_smc, pin_block, sm.EncryptionType.MASTERCARD)
    >>> command_data.hex().upper()
    '9859240AE52820C3'
    """
    if len(sk_smc) != 16:
        raise ValueError("Session Key must be a double length DES key")

    # Prepend data length as a single byte then
    # pad according to ISO/IEC 9797-1 method 2
    if encryption_type == EncryptionType.VISA:
        return _tools.encrypt_tdes_ecb(
            sk_smc,
            _mac.pad_iso9797_2(
                len(command_data).to_bytes(1, _sys.byteorder) + command_data, 8
            ),
        )

    # If the data is not multiple of 8 bytes then
    # pad according to ISO/IEC 9797-1 method 2
    if encryption_type == EncryptionType.MASTERCARD:
        if len(command_data) % 8 > 0:
            return _tools.encrypt_tdes_cbc(
                sk_smc,
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
                _mac.pad_iso9797_2(command_data, 8),
            )
        return _tools.encrypt_tdes_cbc(
            sk_smc, b"\x00\x00\x00\x00\x00\x00\x00\x00", command_data
        )

    # Always pad according to ISO/IEC 9797-1 method 2
    if encryption_type == EncryptionType.EMV:
        return _tools.encrypt_tdes_cbc(
            sk_smc,
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            _mac.pad_iso9797_2(command_data, 8),
        )

    raise TypeError(
        "Encryption type must be EncryptionType Enum, "
        f"not {encryption_type.__class__.__name__}"
    )


def format_vis_pin_block(
    icc_mk_ac: bytes,
    pin: _typing.Union[bytes, str],
    current_pin: _typing.Optional[_typing.Union[bytes, str]] = None,
) -> bytes:
    r"""Format VIS PIN block with or without the current PIN.

    Parameters
    ----------
    icc_mk_ac : bytes
        Binary 16-byte ICC Master Key for Application Cryptogram
        Has to be a valid DES key.
    pin : bytes or str
        New ASCII Personal Identification Number.
    current_pin : bytes or str, optional
        Current ASCII Personal Identification Number (optional). If present
        VIS PIN block is generated using current PIN.

    Returns
    -------
    pin_block : bytes
        Binary 16-byte VIS PIN block

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long
    ValueError
        Current PIN must be between 4 and 12 digits long
    ValueError
        ICC Master Key for AC must be a double length DES key

    Examples
    --------
    >>> from pyemv import sm
    >>> icc_mk_ac = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> sm.format_vis_pin_block(icc_mk_ac, "1234").hex().upper()
    '041234FF76543210'
    """
    if len(pin) < 4 or len(pin) > 12:
        raise ValueError("PIN must be between 4 and 12 digits long")

    if len(icc_mk_ac) != 16:
        raise ValueError("ICC Master Key for AC must be a double length DES key")

    if isinstance(pin, bytes):
        pin = pin.decode("ascii")

    if isinstance(current_pin, bytes):
        current_pin = current_pin.decode("ascii")

    # 4 right-most bytes of ICC MK AC Key A padded with 0x00 to form an 8-byte block
    block_a = b"\x00" * 4 + icc_mk_ac[4:8]

    # PIN length as 1 byte concatenated with PIN then F-padded to form an 8 byte block
    block_b = len(pin).to_bytes(1, _sys.byteorder) + _binascii.a2b_hex(
        pin + "F" * (14 - len(pin))
    )

    pin_block = _tools.xor(block_a, block_b)

    # Generate VIS PIN block using current PIN
    if current_pin is not None:
        if len(current_pin) < 4 or len(current_pin) > 12:
            raise ValueError("Current PIN must be between 4 and 12 digits long")

        pin_block = _tools.xor(
            pin_block, _binascii.a2b_hex(current_pin + "0" * (16 - len(current_pin)))
        )

    return pin_block


def format_iso9564_2_pin_block(pin: _typing.Union[bytes, str]) -> bytes:
    r"""Format ISO 9564-1 PIN block format 2.

    Parameters
    ----------
    pin : bytes or str
        New ASCII Personal Identification Number.

    Returns
    -------
    pin_block : bytes
        Binary 8-byte PIN block

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long

    Examples
    --------
    >>> from pyemv import sm
    >>> sm.format_iso9564_2_pin_block("123456789012").hex().upper()
    '2C123456789012FF'
    """
    if len(pin) < 4 or len(pin) > 12:
        raise ValueError("PIN must be between 4 and 12 digits long")

    if isinstance(pin, bytes):
        pin = pin.decode("ascii")

    return (len(pin) + 32).to_bytes(1, _sys.byteorder) + _binascii.a2b_hex(
        pin + "F" * (14 - len(pin))
    )
