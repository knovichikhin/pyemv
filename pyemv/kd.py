r"""Cryptographic key derivation functions for the
ICC Master Keys and ICC Session Keys.
"""

import binascii as _binascii
import hashlib as _hashlib
from typing import Union

from pyemv.tools import adjust_key_parity as _adjust_key_parity
from pyemv.tools import encrypt_tdes_ecb as _encrypt_tdes_ecb
from pyemv.tools import xor as _xor

__all__ = [
    "derive_icc_mk_a",
    "derive_icc_mk_b",
    "derive_common_sk",
    "derive_visa_sm_sk",
]


def derive_icc_mk_a(iss_mk: bytes, pan: bytes, psn: bytes = None) -> bytes:
    r"""ICC Master Key Derivation. EMV Option A.
    Uses PAN, PAN Sequence Number, MK ISS, Triple DES.

    Parameters
    ----------
    iss_mk : bytes
        Binary Issuer Master Key to derive ICC Master Key from.
        Has to be a valid DES key.
    pan : bytes
        ASCII Application Primary Account Number.
    psn : bytes, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Returns
    -------
    icc_mk : bytes
        Binary 16-byte ICC Master Key.

    Notes
    -----
    Derived from Issuer Master Key (iss_mk).
    Uses EMV Option A - Master Key Derivation method which uses
    the PAN and PAN sequence number, as defined in EMV Book 2, Annex A.

    When a card is personalised the issuer will take the 3 iss_mk keys
    and calculate the 3 icc_mk keys to be stored on the card.
        - icc_mk_ac - used for the transaction cryptograms (ARQC, TC or AAC)
        - icc_mk_smi - used for Issuer Script Integrity
        - icc_mk_smc - used for Issuer Script Confidentiality

    For further details see also:
        - EMV 4.3 Book 2 Annex A 1.4 Master Key Derivation
        - EMV 4.3 Book 2 Annex A 1.4.1 Option A

    Examples
    --------
    >>> from pyemv import kd
    >>> iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> icc_mk = kd.derive_icc_mk_a(iss_mk, pan=b"12345678901234567", psn=b"01")
    >>> icc_mk.hex().upper()
    '73AD54688CEF2934B0979857E3C719F1'
    """
    if psn is None:
        psn = b"00"

    # Data A must be at most 16 digits, right-justified,
    # zero-padded from the left.
    data_a = _binascii.a2b_hex((pan + psn)[-16:].zfill(16))

    # Data B is inverted data A
    data_b = _xor(data_a, b"\xFF" * len(data_a))

    icc_mk = _encrypt_tdes_ecb(iss_mk, data_a + data_b)

    return _adjust_key_parity(icc_mk)


def derive_icc_mk_b(iss_mk: bytes, pan: bytes, psn: bytes = None) -> bytes:
    r"""ICC Master Key Derivation. EMV Option B.
    Uses PAN, PAN Sequence Number, MK ISS, Triple DES, SHA-1 and
    decimalisation of hex digits.

    Parameters
    ----------
    iss_mk : bytes
        Binary Issuer Master Key to derive ICC Master Key from.
        Has to be a valid DES key.
    pan : bytes
        ASCII Application Primary Account Number.
    psn : bytes, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Returns
    -------
    icc_mk : bytes
        Binary 16-byte ICC Master Key

    Notes
    -----
    Derived from Issuer Master Key (iss_mk).
    Uses EMV Option B - Master Key Derivation method which uses
    the PAN and PAN sequence number, as defined in EMV Book 2, Annex A.

    When a card is personalised the issuer will take the 3 iss_mk keys
    and calculate the 3 icc_mk keys to be stored on the card.
        - icc_mk_ac - used for the transaction cryptograms (ARQC, TC or AAC)
        - icc_mk_smi - used for Issuer Script Integrity
        - icc_mk_smc - used for Issuer Script Confidentiality

    For further details see also:
        - EMV 4.3 Book 2 Annex A 1.4 Master Key Derivation
        - EMV 4.3 Book 2 Annex A 1.4.2 Option B

    Examples
    --------
    >>> from pyemv import kd
    >>> iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> icc_mk = kd.derive_icc_mk_b(iss_mk, pan=b"12345678901234567", psn=b"01")
    >>> icc_mk.hex().upper()
    'AD406D7F6D7570916D75E5DCAB8CF737'
    """
    # For PANs with length of 16 or less method B works as method A
    if len(pan) <= 16:
        return derive_icc_mk_a(iss_mk, pan, psn)

    if psn is None:
        psn = b"00"

    # Data A must be an even number of digits,
    # right-justified, zero-padded from the left.
    if len(pan) % 2:
        pan_psn = _binascii.a2b_hex(b"0" + pan + psn)
    else:
        pan_psn = _binascii.a2b_hex(pan + psn)

    # Hash PAN || PAN sequence
    digest = _hashlib.sha1(pan_psn).hexdigest()

    # Get first 16 digits out the hash value.
    result = "".join(filter(str.isdigit, digest))[:16]

    # If there are not enough digits, substitute
    # letters using the following decimalization table:
    # Input a b c d e f
    # Table 0 1 2 3 4 5
    if len(result) < 16:
        digest = "".join(filter((lambda x: x in ("abcdef")), digest))
        digest = digest.replace("a", "0")
        digest = digest.replace("b", "1")
        digest = digest.replace("c", "2")
        digest = digest.replace("d", "3")
        digest = digest.replace("e", "4")
        digest = digest.replace("f", "5")
        result = result + digest[: 16 - len(result)]

    data_a = _binascii.a2b_hex(result)

    # Data B is inverted data A
    data_b = _xor(data_a, b"\xFF" * len(data_a))

    icc_mk = _encrypt_tdes_ecb(iss_mk, data_a + data_b)

    return _adjust_key_parity(icc_mk)


def derive_common_sk(icc_mk: bytes, r: Union[bytes, bytearray]) -> bytes:
    r"""EMV Common Session Key Derivation

    Parameters
    ----------
    icc_mk : bytes
        Binary ICC Master Key to derive session key from.
        Has to be a valid DES key.
    r : bytes, bytearray
        Binary diversification value. Examples of diversification value:

            = R = ATC || 00 || 00 || 00 || 00 || 00 || 00 (AC Session Keys)
            - R = ARQC (Secure Messaging for Integrity and Confidentiality
              Session Keys)
            - R = ATC || 00 || 00 || UN (AC Session Keys)
            - Any other proprietary value

    Returns
    -------
    sk : bytes
        Binary 16-byte Session Key.

    Raises
    ------
    ValueError
        ICC Master Key must be a double length DES key
        Diversification value must be 8 bytes long

    Notes
    -----
    For more information see:
        - EMV 4.3 Book 2 Annex A 1.3 Session Key Derivation
        - EMV 4.3 Book 2 Annex A 1.3.1 Common Session Key Derivation Option

    Examples
    --------
    >>> from pyemv import kd
    >>> mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> r = bytes.fromhex("001C000000000000")
    >>> sk = kd.derive_common_sk(mk, r)
    >>> sk.hex().upper()
    'E9FB384AF807B940FEDCEA613461B0C4'
    """
    if len(icc_mk) != 16:
        raise ValueError("ICC Master Key must be a double length DES key")

    if len(r) != 8:
        raise ValueError("Diversification value must be 8 bytes long")

    # SK Key A (i.e. first 8 bytes) = TDES(icc_mk)[r]
    r_a = bytearray(r)
    r_a[2] = 0xF0

    # SK Key B (i.e. second 8 bytes) = TDES(icc_mk)[r]
    r_b = bytearray(r)
    r_b[2] = 0x0F

    sk = _encrypt_tdes_ecb(icc_mk, r_a + r_b)

    return _adjust_key_parity(sk)


def derive_visa_sm_sk(icc_mk: bytes, atc: bytes) -> bytes:
    r"""Visa Secure Messaging Session Key Derivation

    Parameters
    ----------
    icc_mk : bytes
        Binary ICC Master Key to derive session key from.
        Has to be a valid DES key.
    atc : bytes
        Binary data from tag 9F36 (Application Transaction Counter).

    Returns
    -------
    sk : bytes
        Binary 16-byte Session Key.

    Raises
    ------
    ValueError
        ICC Master Key must be a double length DES key
        ATC value must be 2 bytes long

    Examples
    --------
    >>> from pyemv import kd
    >>> mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> atc = bytes.fromhex("001C")
    >>> sk = kd.derive_visa_sm_sk(mk, atc)
    >>> sk.hex().upper()
    '0123456789ABCDF2FEDCBA987654CDF2'
    """
    if len(icc_mk) != 16:
        raise ValueError("ICC Master Key must be a double length DES key")

    if len(atc) != 2:
        raise ValueError("ATC value must be 2 bytes long")

    # SK Key A (i.e. first 8 bytes) = r _xor MK Key A
    r = b"\x00" * 6 + atc
    sk_a = _xor(r, icc_mk[:8])

    # SK Key B (i.e. second 8 bytes) = r _xor MK Key B
    r = b"\x00" * 6 + _xor(atc, b"\xff\xff")
    sk_b = _xor(r, icc_mk[8:])

    return _adjust_key_parity(sk_a + sk_b)
