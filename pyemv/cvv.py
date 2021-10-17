r"""Provide functions to generate Dynamic Card Verification Values.
Dynamic Card Verification is used in EMV transactions to
generate a new CVV for each transaction.
"""


from pyemv import mac as _mac
from pyemv import tools as _tools

__all__ = ["generate_cvc3"]


def generate_cvc3(icc_cvc3: bytes, track_template: bytes, atc: bytes, un: bytes) -> str:
    r"""Generate MasterCard Dynamic Card Verification Code (CVC3).

    Parameters
    ----------
    icc_cvc3 : bytes
        Binary 16-byte ICC CVC3 key encoded on the card.
        This key is derived from Issuer Master CVC3 key using
        either `kd.derive_icc_mk_a` or `kd.derive_icc_mk_b`.
        Has to be a valid Triple DES key.
    track_template : bytes
        Binary track template data.
        Track2 template consists of:

            PAN || "D" || EXPIRY DATE || SERVICE CODE || DD || "F"?

        DD is Discretionary Data up to 13 digits. DD must have
        value before it's encoded with ATC, UN and CVC3.
        If the resulting track2 template is odd length then it must
        be padded with an "F".

        Track1 template consists of:

            "B" || PAN || ^LAST/FIRST^ || EXPIRY DATE || SERVICE CODE || DD

        Track1 template must be encoded as an ASCII byte string, where, for example,
        character "B" is encoded as "\x42".

    atc : bytes
        Binary data from tag 9F36 (Application Transaction Counter).
    un : bytes
        Binary data from tag 9F37 (Unpredictable Number).

    Returns
    -------
    cvc3 : str
        5-digit Dynamic Card Verification Code.
        Compare generated CVC3 against number of available
        least significant digits of CVC3 received on track1/2.

    Raises
    ------
    ValueError
        ICC CVC3 key must be a double length DES key
    ValueError
        ATC value must be 2 bytes long
    ValueError
        Unpredictable number must be 4 bytes long

    Examples
    --------
    >>> from pyemv.cvv import generate_cvc3
    >>> from pyemv.kd import derive_icc_mk_a
    >>> iss_cvc3 = bytes.fromhex("01234567899876543210012345678998")
    >>> pan = "5123456789012345"
    >>> psn = "00"
    >>> icc_cvc3 = derive_icc_mk_a(iss_cvc3, pan, psn)
    >>> track2 = bytes.fromhex("5123456789012345D35121010000000000000F")
    >>> atc = bytes.fromhex("005E")
    >>> un = bytes.fromhex("00000899")
    >>> generate_cvc3(icc_cvc3, track2, atc, un)
    '29488'
    """
    if len(icc_cvc3) != 16:
        raise ValueError("ICC CVC3 key must be a double length DES key")

    if len(atc) != 2:
        raise ValueError("ATC value must be 2 bytes long")

    if len(un) != 4:
        raise ValueError("Unpredictable number must be 4 bytes long")

    # IV CVC3 is formed from 2 least significant bytes of CBC-MAC
    # computed over track template
    iv_cvc3 = _mac.mac_iso9797_3(icc_cvc3[:8], icc_cvc3[-8:], track_template, 2)[-2:]

    # CVC3 is formed from 2 least significant bytes of TDES encrypted
    # ciphertext block
    block = iv_cvc3 + un + atc
    cvc3 = _tools.encrypt_tdes_ecb(icc_cvc3, block)[-2:]

    return str(int(cvc3.hex(), 16))
