1.5.0 - 2021-10-16
------------------
- Added support for Visa CVN 22 in ``pyemv.cvn`` module.
- Added support for EMV2000-Tree session key derivation in ``pyemv.kd`` module.

1.4.0 - 2021-06-17
------------------
- Added TLV encoder/decoder. See ``pyemv.tlv`` module.
- Dropped Python 3.5 support.

1.3.0 - 2020-12-07
------------------
- Added MasterCard CVC3 support
- Updated all functions and classes that have PIN, PAN or PSN parameters to accept bytes and str.

1.2.0 - 2020-08-27
------------------
- Added CVN support for MasterCard CVN 16, 17, 20 and 21.
- Addressed remaining type hint issues.
- Included inline type information into the distribution according to `PEP 561 <https://www.python.org/dev/peps/pep-0561/>`_.

1.1.0 - 2020-05-01
------------------
Added ``pyemv.cvn`` module.
This module supports

    - Visa CVN 10
    - Visa CVN 18
    - Interac CVN 133

1.0.0 - 2020-01-27
------------------
- Added ``pyemv.ac`` module - Application Cryptogram functions
- Added ``pyemv.kd`` module - Key Derivation functions
- Added ``pyemv.sm`` module - Secure Messaging functions and associated PIN block formats
- Added ``pyemv.mac`` module - MAC helpers
- Added ``pyemv.tools`` module - various tools, TDES helpers
