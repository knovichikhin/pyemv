PyEMV
=====

|pypi| |coverage|

``PyEMV`` package provides methods to generate

- Application Cryptograms (TC, ARQC, or AAC) that's used to verify ICC.
- Authorization Response Cryptogram (ARPC) that's used to verify card issuer.
- Secure Messaging Integrity and Confidentiality that's used by the issuer to update values on the ICC.
- Dynamic Card Verification Values.

Installation
------------

``PyEMV`` is published on `PyPI`__ and can be installed from there:

.. code-block::

    pip install pyemv

__ https://pypi.org/project/pyemv/

Modules
-------

- kd - Key Derivation support for ICC master keys and session keys.
- ac - Application Cryptogram support for ARQC, AAC, TC, and ARPC.
- sm - Secure Messaging support for script command integrity and confidentiality.
- cvn - Putting it all together for various Cryptogram Version Numbers.
- cvv - Support for dynamic card verification, such as CVC3.
- tlv - TLV encoder and decoder.

.. |pypi| image:: https://img.shields.io/pypi/v/pyemv.svg
    :alt: PyPI
    :target:  https://pypi.org/project/pyemv/

.. |coverage| image:: https://codecov.io/gh/knovichikhin/pyemv/branch/master/graph/badge.svg
    :alt: Test coverage
    :target: https://codecov.io/gh/knovichikhin/pyemv
