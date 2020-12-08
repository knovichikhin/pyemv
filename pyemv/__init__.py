r"""PyEMV package provides methods to generate

    - Application Cryptograms (TC, ARQC, or AAC) used to verify ICC
    - Authorization Response Cryptogram (ARPC) used to verify card issuer
    - Secure Messaging Integrity and Confidentiality used by the issuer to update values on the ICC
    - Dynamic Card Verification Values

PyEMV consists of the following modules:

    - kd - Key Derivation support for ICC master keys and session keys
    - ac - Application Cryptogram support for ARQC, AAC, TC, and ARPC
    - sm - Secure Messaging support for script command integrity
      and confidentiality. It also provides support for PIN blocks.
    - cvn - Putting it all together for various Cryptogram Version Numbers

Key Derivation
~~~~~~~~~~~~~~

ICC Master Key derivation method A and B:

    >>> from pyemv import kd
    >>> iss_mk = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    >>> pan = '99012345678901234'
    >>> psn = '45'
    >>> icc_mk_a = kd.derive_icc_mk_a(iss_mk, pan, psn)
    >>> icc_mk_a.hex().upper()
    '67F8292358083E5EA7AB7FDA58D53B6B'
    >>> icc_mk_b = kd.derive_icc_mk_b(iss_mk, pan, psn)
    >>> icc_mk_b.hex().upper()
    '985EC4FD3EDF6162E31AF1C7D0543416'

Common Session Key derivation:

    >>> r = bytes.fromhex('1234567890123456')
    >>> sk = kd.derive_common_sk(icc_mk_a, r)
    >>> sk.hex().upper()
    '29B33180E567CE38EA4CBC9D753B0E61'

Cryptogram Generation
~~~~~~~~~~~~~~~~~~~~~

Application Request Cryptogram generation:

    >>> from pyemv import ac
    >>> ac_data = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF')
    >>> arqc = ac.generate_ac(sk, ac_data)
    >>> arqc.hex().upper()
    'FA624250B008B59A'

Application Response Cryptogram generation method 1 and 2:

    >>> arpc_rc = bytes.fromhex('0000')
    >>> arpc = ac.generate_arpc_1(sk, arqc, arpc_rc)
    >>> arpc.hex().upper()
    '45D4255EEF10C920'
    >>> csu = bytes.fromhex('00000000')
    >>> arpc = ac.generate_arpc_2(sk, arqc, csu)
    >>> arpc.hex().upper()
    'CB56FA40'

Secure Messaging
~~~~~~~~~~~~~~~~

Secure Messaging Integrity (MAC):

    >>> from pyemv import sm
    >>> sk_smi = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    >>> command = bytes.fromhex('8424000008')
    >>> mac = sm.generate_command_mac(sk_smi, command)
    >>> mac.hex().upper()
    '0BFFF5DF3FAA24E1'

Secure Messaging Confidentiality:

    >>> pin_block = sm.format_iso9564_2_pin_block('9999')
    >>> pin_block.hex().upper()
    '249999FFFFFFFFFF'
    >>> sk_smc = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    >>> enc_data = sm.encrypt_command_data(sk_smc, pin_block,
    ...                                    sm.EncryptionType.EMV)
    >>> enc_data.hex().upper()
    '5A862D1381CCB94822CFDD706A376178'

Cryptogram Version Number
~~~~~~~~~~~~~~~~~~~~~~~~~~
Cryptogram Version Number (CVN) module demonstrates how
application cryptogram generation, key derivation and secure messaging
come together.

    >>> from pyemv import cvn
    >>> cvn18 = cvn.VisaCVN18(
    ...     iss_mk_ac=bytes.fromhex('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    ...     iss_mk_smi=bytes.fromhex('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'),
    ...     iss_mk_smc=bytes.fromhex('CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'),
    ...     pan='1234567890123456',
    ...     psn='00')
    >>> atc = bytes.fromhex('0FFF')
    >>> arqc = cvn18.generate_ac(
    ...     tag_9f02=bytes.fromhex('000000009999'),
    ...     tag_9f03=bytes.fromhex('000000000000'),
    ...     tag_9f1a=bytes.fromhex('0840'),
    ...     tag_95=bytes.fromhex('8000048000'),
    ...     tag_5f2a=bytes.fromhex('0840'),
    ...     tag_9a=bytes.fromhex('991231'),
    ...     tag_9c=bytes.fromhex('01'),
    ...     tag_9f37=bytes.fromhex('52BF4585'),
    ...     tag_82=bytes.fromhex('1800'),
    ...     tag_9f36=atc,
    ...     tag_9f10=bytes.fromhex('06011203A0B800'))
    >>> arqc.hex().upper()
    '769577B5ABE9FE62'
    >>> arpc = cvn18.generate_arpc(
    ...     tag_9f26=arqc,
    ...     tag_9f36=atc,
    ...     csu=bytes.fromhex('00000000'))
    >>> arpc.hex().upper()
    '76503F48'
    >>> command_mac = cvn18.generate_command_mac(
    ...         command_header=bytes.fromhex('8418000008'),
    ...         tag_9f26=arqc,
    ...         tag_9f36=atc)
    >>> command_mac.hex().upper()
    'B5CB29759F9C3919'
    >>> pin_command = cvn18.generate_pin_change_command(
    ...         pin='9999',
    ...         tag_9f26=arqc,
    ...         tag_9f36=atc)
    >>> pin_command.hex().upper()
    '84240002182DC7A061323BA62472BC5308BD291B5F665B3A927E60661E'

Dynamic Card Verification
~~~~~~~~~~~~~~~~~~~~~~~~~

Dynamic card verification, unlike traditional CVV/CVC,
generates a new CVV for each transaction.

    >>> from pyemv.cvv import generate_cvc3
    >>> from pyemv.kd import derive_icc_mk_a
    >>> iss_cvc3 = bytes.fromhex('01234567899876543210012345678998')
    >>> pan = '5123456789012345'
    >>> psn = '00'
    >>> icc_cvc3 = derive_icc_mk_a(iss_cvc3, pan, psn)
    >>> track2 = bytes.fromhex('5123456789012345D35121010000000000000F')
    >>> atc = bytes.fromhex('005E')
    >>> un = bytes.fromhex('00000899')
    >>> generate_cvc3(icc_cvc3, track2, atc, un)
    '29488'
"""

__version__ = "1.2.0"
__author__ = "Konstantin Novichikhin <konstantin.novichikhin@gmail.com>"

from pyemv import ac, cvn, cvv, kd, mac, sm, tools
