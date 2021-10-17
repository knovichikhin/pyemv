r"""PyEMV package provides methods to generate

    - Application Cryptograms (TC, ARQC, or AAC) used to verify ICC
    - Authorization Response Cryptogram (ARPC) used to verify card issuer
    - Secure Messaging Integrity and Confidentiality used by the issuer to update values on the ICC
    - Dynamic Card Verification Values

PyEMV consists of the following modules:

    - kd - Key Derivation support for ICC master keys and session keys.
    - ac - Application Cryptogram support for ARQC, AAC, TC, and ARPC.
    - sm - Secure Messaging support for script command integrity and confidentiality.
    - cvn - Putting it all together for various Cryptogram Version Numbers.
    - cvv - Support for dynamic card verification, such as CVC3.
    - tlv - TLV encoder and decoder.

For example, ICC Master Key derivation method A:

    >>> import pyemv
    >>> icc_mk = pyemv.kd.derive_icc_mk_a(
    ...     iss_mk=bytes.fromhex('0123456789ABCDEFFEDCBA9876543210'),
    ...     pan='99012345678901234',
    ...     psn='45')
    >>> icc_mk.hex().upper()
    '67F8292358083E5EA7AB7FDA58D53B6B'
"""

__version__ = "1.5.0"
__author__ = "Konstantin Novichikhin <konstantin.novichikhin@gmail.com>"

from pyemv import ac, cvn, cvv, kd, mac, sm, tlv, tools
