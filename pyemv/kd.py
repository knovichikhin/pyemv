r"""Cryptographic key derivation functions for the ICC Master Keys and ICC Session Keys.

ICC Master Key derivation method A:

    >>> import pyemv
    >>> iss_mk = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    >>> pan = '99012345678901234'
    >>> psn = '45'
    >>> icc_mk = pyemv.kd.derive_icc_mk_a(iss_mk, pan, psn)
    >>> icc_mk.hex().upper()
    '67F8292358083E5EA7AB7FDA58D53B6B'
"""

import binascii as _binascii
import hashlib as _hashlib
import typing as _typing

from pyemv import tools as _tools

__all__ = [
    "derive_icc_mk_a",
    "derive_icc_mk_b",
    "derive_common_sk",
    "derive_visa_sm_sk",
    "derive_emv2000_tree_sk",
]


def derive_icc_mk_a(
    iss_mk: bytes,
    pan: _typing.Union[bytes, str],
    psn: _typing.Optional[_typing.Union[bytes, str]] = None,
) -> bytes:
    r"""ICC Master Key Derivation. EMV Option A.
    Uses PAN, PAN Sequence Number, MK ISS, Triple DES.

    Parameters
    ----------
    iss_mk : bytes
        Binary Issuer Master Key to derive ICC Master Key from.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
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
    >>> icc_mk = kd.derive_icc_mk_a(iss_mk, pan="12345678901234567", psn="01")
    >>> icc_mk.hex().upper()
    '73AD54688CEF2934B0979857E3C719F1'
    """
    if psn is None:
        psn = "00"

    if isinstance(psn, bytes):
        psn = psn.decode("ascii")

    if isinstance(pan, bytes):
        pan = pan.decode("ascii")

    # Data A must be at most 16 digits, right-justified,
    # zero-padded from the left.
    data_a = _binascii.a2b_hex((pan + psn)[-16:].zfill(16))

    # Data B is inverted data A
    data_b = _tools.xor(data_a, b"\xFF" * len(data_a))

    icc_mk = _tools.encrypt_tdes_ecb(iss_mk, data_a + data_b)

    return _tools.adjust_key_parity(icc_mk)


def derive_icc_mk_b(
    iss_mk: bytes,
    pan: _typing.Union[bytes, str],
    psn: _typing.Optional[_typing.Union[bytes, str]] = None,
) -> bytes:
    r"""ICC Master Key Derivation. EMV Option B.
    Uses PAN, PAN Sequence Number, MK ISS, Triple DES, SHA-1 and
    decimalisation of hex digits.

    Parameters
    ----------
    iss_mk : bytes
        Binary Issuer Master Key to derive ICC Master Key from.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
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
    >>> icc_mk = kd.derive_icc_mk_b(iss_mk, pan="12345678901234567", psn="01")
    >>> icc_mk.hex().upper()
    'AD406D7F6D7570916D75E5DCAB8CF737'
    """
    # For PANs with length of 16 or less method B works as method A
    if len(pan) <= 16:
        return derive_icc_mk_a(iss_mk, pan, psn)

    if psn is None:
        psn = "00"

    if isinstance(psn, bytes):
        psn = psn.decode("ascii")

    if isinstance(pan, bytes):
        pan = pan.decode("ascii")

    # Data A must be an even number of digits,
    # right-justified, zero-padded from the left.
    if len(pan) % 2:
        pan_psn = _binascii.a2b_hex("0" + pan + psn)
    else:
        pan_psn = _binascii.a2b_hex(pan + psn)

    # Hash PAN || PAN sequence
    digest = _hashlib.sha1(pan_psn).hexdigest()

    # Get first 16 digits out the hash value.
    result = "".join(
        [d for d in digest if d in {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}][
            :16
        ]
    )

    # If there are not enough digits, substitute
    # letters using the following decimalization table:
    # Input a b c d e f
    # Table 0 1 2 3 4 5
    if len(result) < 16:
        digest = "".join(
            [d for d in digest if d in {"a", "b", "c", "d", "e", "f"}][
                : 16 - len(result)
            ]
        )
        digest = digest.translate({97: 48, 98: 49, 99: 50, 100: 51, 101: 52, 102: 53})
        result = result + digest

    data_a = _binascii.a2b_hex(result)

    # Data B is inverted data A
    data_b = _tools.xor(data_a, b"\xFF" * len(data_a))

    icc_mk = _tools.encrypt_tdes_ecb(iss_mk, data_a + data_b)

    return _tools.adjust_key_parity(icc_mk)


def derive_common_sk(icc_mk: bytes, r: _typing.Union[bytes, bytearray]) -> bytes:
    r"""EMV Common Session Key Derivation.

    Parameters
    ----------
    icc_mk : bytes
        Binary ICC Master Key to derive session key from.
        Has to be a valid DES key.
    r : bytes, bytearray
        Binary diversification value. Examples of diversification value:

            - R = ATC || 00 || 00 || 00 || 00 || 00 || 00 (AC Session Keys)
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
    ValueError
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

    sk = _tools.encrypt_tdes_ecb(icc_mk, r_a + r_b)

    return _tools.adjust_key_parity(sk)


def derive_visa_sm_sk(icc_mk: bytes, atc: bytes) -> bytes:
    r"""Visa Secure Messaging Session Key Derivation.

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
    ValueError
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

    # SK Key A (i.e. first 8 bytes) = r xor MK Key A
    r = b"\x00" * 6 + atc
    sk_a = _tools.xor(r, icc_mk[:8])

    # SK Key B (i.e. second 8 bytes) = r xor MK Key B
    r = b"\x00" * 6 + _tools.xor(atc, b"\xff\xff")
    sk_b = _tools.xor(r, icc_mk[8:])

    return _tools.adjust_key_parity(sk_a + sk_b)


def derive_emv2000_tree_sk(
    icc_mk: bytes,
    atc: bytes,
    height: int = 8,
    branch_factor: int = 4,
    iv: bytes = b"\x00" * 16,
) -> bytes:
    r"""EMV2000-Tree Session Key Derivation.

    Parameters
    ----------
    icc_mk : bytes
        Binary ICC Master Key to derive session key from.
        Has to be a valid DES key.
    atc : bytes
        Binary data from tag 9F36 (Application Transaction Counter).
    height : int
        Height value used for EMV-Tree derivation. Height controls
        the number of levels of intermediate keys in the tree
        excluding the base level. Set to either 8 or 16.
        The specification recommends value 8. Defaults to 8.
    branch_factor : int
        Branch factor value used for EMV-Tree derivation. Branch factor
        controls number of "child" keys a "parent" key derives.
        The specification recommends value 4. Defaults to 4.
    iv : bytes
        16-byte binary initialization vector used for EMV-Tree derivation.
        The specification recommends IV value of zeros. Defaults to 0s.

    Returns
    -------
    sk : bytes
        Binary 16-byte Session Key.

    Raises
    ------
    ValueError
        ICC Master Key must be a double length DES key
    ValueError
        ATC value must be 2 bytes long
    ValueError
        Initialization vector value must be 16 bytes long
    ValueError
        Number of possible session keys must exceed maximum ATC value

    Notes
    -----
    For more information see:
        - EMV 4.1 Book 2 Annex A 1.3 Session Key Derivation
        - EMV 4.1 Book 2 Annex A 1.3.1 Description
        - EMV 4.1 Book 2 Annex A 1.3.2 Implementation

    This method was replaced by common session key derivation in 2005
    and should not be used for new development.
    See EMVCo specification update bulletin 46 (SU-46).

    Recommended branch factor and tree height combinations are as follow.
    Both combinations produce enough session keys for every possible ATC value.
        - Branch factor 2 and tree height 16
        - Branch factor 4 and tree height 8

    Examples
    --------
    >>> from pyemv import kd
    >>> mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> atc = bytes.fromhex("001C")
    >>> sk = kd.derive_emv2000_tree_sk(mk, atc, 8, 4)
    >>> sk.hex().upper()
    'E5BF6D1067F194B0A89B7F5D83BC64A2'
    """
    if len(icc_mk) != 16:
        raise ValueError("ICC Master Key must be a double length DES key")

    if len(atc) != 2:
        raise ValueError("ATC value must be 2 bytes long")

    if len(iv) != 16:
        raise ValueError("Initialization vector value must be 16 bytes long")

    # The number of possible session keys (branch_factor ** height)
    # must exceed the maximum value of the ATC which is 2 ** 16 - 1.
    if branch_factor**height < 65535:
        raise ValueError(
            "Number of possible session keys must exceed maximum ATC value"
        )

    # F(X,Y,j) := (DES3(X)[YL XOR (j mod b)] || DES3(X)[YR XOR (j mod b) XOR 'F0'])
    def derive(x: bytes, y: bytes, j: int) -> bytes:
        """Map two 16-byte numbers X and Y and an integer j onto a 16-byte number."""
        j_mod_b = int.to_bytes(j % branch_factor, 8, "big")

        # (DES3(X)[YL XOR (j mod b)]
        l_data = _tools.xor(y[:8], j_mod_b)
        l_data = _tools.encrypt_tdes_ecb(x, l_data)

        # DES3(X)[YR XOR (j mod b) XOR 'F0']
        r_data = _tools.xor(y[8:], j_mod_b)
        r_data = _tools.xor(r_data, b"\x00" * 7 + b"\xF0")
        r_data = _tools.encrypt_tdes_ecb(x, r_data)
        return l_data + r_data

    # GP = Grandparent Key
    # IK = Intermediate Key
    # P  = Parent Key
    # H  = Height of the tree
    def walk(j: int, h: int) -> _typing.Tuple[bytes, bytes]:
        """Returns P and GP"""
        # Base case: P = ICC MK, GP = IV
        if h == 0:
            return icc_mk, iv
        p, gp = walk(j // branch_factor, h - 1)
        # Derives an IK from P and GP
        # IK becomes the new parent and current P becomes the new GP
        return derive(p, gp, j), p

    atc_num = int.from_bytes(atc, "big")

    # Derive IKs from the bottom of the tree to the second to last level
    # because GP from that level is required for SK.
    p, gp = walk(atc_num // branch_factor, height - 1)

    # Derive SK from a new IK at the tree height XOR'd by GP.
    sk = _tools.xor(derive(p, gp, atc_num), gp)
    return _tools.adjust_key_parity(sk)
