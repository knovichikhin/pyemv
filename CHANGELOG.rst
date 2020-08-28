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
