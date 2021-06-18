"""Cryptogram Version Number (CVN) defines the following:

    - ICC Master Key derivation method
    - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method
    - Application Cryptogram (ARQC, TC, ACC) calculation method
    - Authorisation Response Cryptogram Session Key derivation method
    - Authorisation Response Cryptogram calculation method
    - Secure Messaging Session Key derivation method
    - Secure Messaging Integrity (MAC) data format and padding
    - Secure Messaging Confidentiality encryption method and padding

CVN module combines application cryptogram generation, key derivation and
secure messaging in one class per CVN.

    >>> import pyemv
    >>> cvn18 = pyemv.cvn.VisaCVN18(
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
"""


import typing as _typing

from pyemv import ac as _ac
from pyemv import kd as _kd
from pyemv import sm as _sm

__all__ = [
    "VisaCVN10",
    "VisaCVN18",
    "InteracCVN133",
    "MasterCardCVN16",
    "MasterCardCVN17",
    "MasterCardCVN20",
    "MasterCardCVN21",
]


class VisaCVN10(object):
    """Cryptogram Version Number (CVN) defines Card Authentication Method (CAM).
    Visa Cryptogram Version Number (CVN) 10 defines the following:

        - ICC Master Key derivation method = Option A
        - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method = None
        - Application Cryptogram (ARQC, TC, ACC) calculation method = Visa
        - Authorisation Response Cryptogram Session Key derivation method = None
        - Authorisation Response Cryptogram calculation method = 1
        - Secure Messaging Session Key derivation method = Visa
        - Secure Messaging Integrity (MAC) data format and padding = Format 2,
          padded with transaction data
        - Secure Messaging Confidentiality encryption method and padding = Visa

    Parameters
    ----------
    iss_mk_ac : bytes
        16-byte binary Issuer Master Key for Application Cryptography.
        Has to be a valid DES key.
    iss_mk_smi : bytes
        16-byte binary Issuer Master Key for Issuer Script Integrity.
        Has to be a valid DES key.
    iss_mk_smc : bytes
        16-byte binary Issuer Master Key for Issuer Script Confidentiality.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Attributes
    ----------
    icc_mk_ac : bytes
        16-byte binary ICC Master Key for Application Cryptography.
    icc_mk_smi : bytes
        16-byte binary ICC Master Key for Issuer Script Integrity.
    icc_mk_smc : bytes
        16-byte binary ICC Master Key for Issuer Script Confidentiality.
    """

    def __init__(
        self,
        iss_mk_ac: bytes,
        iss_mk_smi: bytes,
        iss_mk_smc: bytes,
        pan: _typing.Union[bytes, str],
        psn: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> None:
        # Derive AC, SMI, and SMC ICC Master Keys for a new card
        # using option A.
        psn = psn or "00"
        self.icc_mk_ac = _kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = _kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = _kd.derive_icc_mk_a(iss_mk_smc, pan, psn)

    def _derive_sk_ac_none(self) -> bytes:
        """Derive Application Cryptogram Session Key.
        Use ICC Master Key, since Session Key is not applicable.

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return self.icc_mk_ac

    def generate_ac(
        self,
        tag_9f02: bytes,
        tag_9f03: bytes,
        tag_9f1a: bytes,
        tag_95: bytes,
        tag_5f2a: bytes,
        tag_9a: bytes,
        tag_9c: bytes,
        tag_9f37: bytes,
        tag_82: bytes,
        tag_9f36: bytes,
        cvr: bytes,
    ) -> bytes:
        """Generate Application Cryptogram. Same process for
            - Authorisation Request Cryptogram (ARQC)
            - Transaction Cryptogram (TC)
            - Application Authentication Cryptogram (AAC)

        Parameters
        ----------
        tag_9f02 : bytes
            Binary data from tag 9F02 (Amount, Authorized).
        tag_9f03 : bytes
            Binary data from tag 9F03 (Amount, Other).
        tag_9f1a : bytes
            Binary data from tag 9F1A (Terminal Country Code).
        tag_95 : bytes
            Binary data from tag 95 (Terminal Verification Results).
        tag_5f2a : bytes
            Binary data from tag 5F2A (Transaction Currency Code).
        tag_9a : bytes
            Binary data from tag 9A (Transaction Date).
        tag_9c : bytes
            Binary Data from tag 9C (Transaction Type).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_82 : bytes
            Binary data from tag 82 (Application Interchange Profile).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        cvr : bytes
            4 bytes of binary Card Verification Results extracted from
            9F10 (Issuer Application Data).

        Returns
        -------
        ac : bytes
            Returns binary 8-byte cryptogram (ARQC, TC, AAC).
        """
        return _ac.generate_ac(
            self._derive_sk_ac_none(),
            tag_9f02
            + tag_9f03
            + tag_9f1a
            + tag_95
            + tag_5f2a
            + tag_9a
            + tag_9c
            + tag_9f37
            + tag_82
            + tag_9f36
            + cvr,
            _ac.PaddingType.VISA,
            8,
        )

    def generate_arpc(self, tag_9f26: bytes, arpc_rc: bytes) -> bytes:
        """Generate Authorisation Response Cryptogram (ARPC) using method 1.
        Method for the generation of a 8-byte ARPC consists of applying
        ISO/IEC 9797-1 MAC algorithm 3 to:

            - 8-byte binary ARQC
            - 2-byte binary ARPC response code

        Parameters
        ----------
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        arpc_rc : bytes
            Binary 2-byte ARPC response code.

        Returns
        -------
        arpc : bytes
            Returns binary 8-byte Authorisation Response Cryptogram (ARPC).
            The resulting issuer authentication data (tag 91) is:

                91 || Len || ARPC || ARPC-RC
        """
        return _ac.generate_arpc_1(self._derive_sk_ac_none(), tag_9f26, arpc_rc)

    def _derive_sk_sm_visa(self, icc_mk_sm: bytes, tag_9f36: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Visa method.

        Parameters
        ----------
        icc_mk_sm : bytes
            16-byte binary ICC Master Key for Secure Messaging.
            Has to be a valid DES key.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        sk_sm : bytes
            16-byte binary Session Key for Secure Messaging.
            Has to be a valid DES key.
        """
        return _kd.derive_visa_sm_sk(icc_mk_sm, tag_9f36)

    def generate_command_mac(
        self,
        command_header: bytes,
        tag_9f26: bytes,
        tag_9f36: bytes,
        command_data: bytes = b"",
    ) -> bytes:
        r"""Message Authentication Code (MAC) for Secure Messaging Integrity.

        Parameters
        ----------
        command_header : bytes
            Binary command header, such as \x84\x24\x00\x00\x08 for PIN unblock.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        command_data : bytes, optional
            Binary command data, e.g. PUT DATA or PIN block.

        Returns
        -------
        mac : bytes
            Binary 8-byte command MAC.
        """
        return _sm.generate_command_mac(
            self._derive_sk_sm_visa(self.icc_mk_smi, tag_9f36),
            command_header + tag_9f36 + tag_9f26 + command_data,
            8,
        )

    def encrypt_command_data(self, command_data: bytes, tag_9f36: bytes) -> bytes:
        """Command Data Encryption for Secure Messaging Confidentiality.

        Parameters
        ----------
        command_data : bytes
            Binary command data, e.g. PUT DATA or PIN block.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        encrypted_command_data : bytes
            Binary encrypted command command data. Then the resulting command is:

                Header || Encrypted Data || MAC
        """
        return _sm.encrypt_command_data(
            self._derive_sk_sm_visa(self.icc_mk_smc, tag_9f36),
            command_data,
            _sm.EncryptionType.VISA,
        )

    def generate_pin_change_command(
        self,
        pin: _typing.Union[bytes, str],
        tag_9f26: bytes,
        tag_9f36: bytes,
        current_pin: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> bytes:
        """Generate a PIN change command with encrypted PIN block and MAC.

        Parameters
        ----------
        pin : bytes or str
            New ASCII Personal Identification Number.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        current_pin : bytes or str, optional
            Current ASCII Personal Identification Number (optional). If present
            VIS PIN block is generated using current PIN.

        Returns
        -------
        pin_change_command : bytes
            Binary PIN change command with encrypted PIN block and MAC.
        """
        enc_pin_block = self.encrypt_command_data(
            _sm.format_vis_pin_block(self.icc_mk_ac, pin, current_pin), tag_9f36
        )

        if current_pin is None:
            command_header = b"\x84\x24\x00\x02\x18"
        else:
            command_header = b"\x84\x24\x00\x01\x18"

        return (
            command_header
            + enc_pin_block
            + self.generate_command_mac(
                command_header, tag_9f26, tag_9f36, enc_pin_block
            )
        )


class VisaCVN18(object):
    """Cryptogram Version Number (CVN) defines Card Authentication Method (CAM).
    Visa Cryptogram Version Number (CVN) 18 defines the following:

        - ICC Master Key derivation method = Option B
        - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method = Common
        - Application Cryptogram (ARQC, TC, ACC) calculation method = EMV
        - Authorisation Response Cryptogram Session Key derivation method = Common
        - Authorisation Response Cryptogram calculation method = 2
        - Secure Messaging Session Key derivation method = Visa
        - Secure Messaging Integrity (MAC) data format and padding = Format 2,
          padded with transaction data
        - Secure Messaging Confidentiality encryption method and padding = Visa

    Parameters
    ----------
    iss_mk_ac : bytes
        16-byte binary Issuer Master Key for Application Cryptography.
        Has to be a valid DES key.
    iss_mk_smi : bytes
        16-byte binary Issuer Master Key for Issuer Script Integrity.
        Has to be a valid DES key.
    iss_mk_smc : bytes
        16-byte binary Issuer Master Key for Issuer Script Confidentiality.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Attributes
    ----------
    icc_mk_ac : bytes
        16-byte binary ICC Master Key for Application Cryptography.
    icc_mk_smi : bytes
        16-byte binary ICC Master Key for Issuer Script Integrity.
    icc_mk_smc : bytes
        16-byte binary ICC Master Key for Issuer Script Confidentiality.
    """

    def __init__(
        self,
        iss_mk_ac: bytes,
        iss_mk_smi: bytes,
        iss_mk_smc: bytes,
        pan: _typing.Union[bytes, str],
        psn: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> None:
        # Derive AC, SMI, and SMC ICC Master Keys for a new card
        # using option B.
        psn = psn or "00"
        self.icc_mk_ac = _kd.derive_icc_mk_b(iss_mk_ac, pan, psn)
        self.icc_mk_smi = _kd.derive_icc_mk_b(iss_mk_smi, pan, psn)
        self.icc_mk_smc = _kd.derive_icc_mk_b(iss_mk_smc, pan, psn)

    def _derive_sk_ac_common(self, tag_9f36: bytes) -> bytes:
        """Derive Application Cryptogram Session Key using EMV Common method.

        Parameters
        ----------
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(self.icc_mk_ac, tag_9f36 + b"\x00" * 6)

    def generate_ac(
        self,
        tag_9f02: bytes,
        tag_9f03: bytes,
        tag_9f1a: bytes,
        tag_95: bytes,
        tag_5f2a: bytes,
        tag_9a: bytes,
        tag_9c: bytes,
        tag_9f37: bytes,
        tag_82: bytes,
        tag_9f36: bytes,
        tag_9f10: bytes,
    ) -> bytes:
        """Generate Application Cryptogram. Same process for
            - Authorisation Request Cryptogram (ARQC)
            - Transaction Cryptogram (TC)
            - Application Authentication Cryptogram (AAC)

        Parameters
        ----------
        tag_9f02 : bytes
            Binary data from tag 9F02 (Amount, Authorized).
        tag_9f03 : bytes
            Binary data from tag 9F03 (Amount, Other).
        tag_9f1a : bytes
            Binary data from tag 9F1A (Terminal Country Code).
        tag_95 : bytes
            Binary data from tag 95 (Terminal Verification Results).
        tag_5f2a : bytes
            Binary data from tag 5F2A (Transaction Currency Code).
        tag_9a : bytes
            Binary data from tag 9A (Transaction Date).
        tag_9c : bytes
            Binary Data from tag 9C (Transaction Type).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_82 : bytes
            Binary data from tag 82 (Application Interchange Profile).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        tag_9f10 : bytes
            Binary data from tag 9F10 (Issuer Application Data).

        Returns
        -------
        ac : bytes
            Returns binary 8-byte cryptogram (ARQC, TC, AAC).
        """
        return _ac.generate_ac(
            self._derive_sk_ac_common(tag_9f36),
            tag_9f02
            + tag_9f03
            + tag_9f1a
            + tag_95
            + tag_5f2a
            + tag_9a
            + tag_9c
            + tag_9f37
            + tag_82
            + tag_9f36
            + tag_9f10,
            _ac.PaddingType.EMV,
            8,
        )

    def generate_arpc(
        self,
        tag_9f26: bytes,
        tag_9f36: bytes,
        csu: bytes,
        proprietary_auth_data: _typing.Optional[bytes] = None,
    ) -> bytes:
        """Generate Authorisation Response Cryptogram (ARPC) using method 2.
        Method for the generation of a 4-byte ARPC consists of applying
        ISO/IEC 9797-1 MAC algorithm 3 to:

            - 8-byte binary ARQC
            - 4-byte binary Card Status Update (CSU)
            - 0-8 byte binary Proprietary Authentication Data

        Parameters
        ----------
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        csu : bytes
            Binary 4-byte Card Status Update (CSU).
        prop_auth_data : bytes, optional
            Binary 0-8 byte Proprietary Authentication Data.

        Returns
        -------
        arpc : bytes
            Returns binary 4-byte Authorisation Response Cryptogram (ARPC).
            The resulting issuer authentication data (tag 91) is:

                91 || Len || ARPC || CSU || { Proprietary Authentication Data }
        """
        return _ac.generate_arpc_2(
            self._derive_sk_ac_common(tag_9f36),
            tag_9f26,
            csu,
            proprietary_auth_data,
        )

    def _derive_sk_sm_visa(self, icc_mk_sm: bytes, tag_9f36: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Visa method.

        Parameters
        ----------
        icc_mk_sm : bytes
            16-byte binary ICC Master Key for Secure Messaging.
            Has to be a valid DES key.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        sk_sm : bytes
            16-byte binary Session Key for Secure Messaging.
            Has to be a valid DES key.
        """
        return _kd.derive_visa_sm_sk(icc_mk_sm, tag_9f36)

    def generate_command_mac(
        self,
        command_header: bytes,
        tag_9f26: bytes,
        tag_9f36: bytes,
        command_data: bytes = b"",
    ) -> bytes:
        r"""Message Authentication Code (MAC) for Secure Messaging Integrity.

        Parameters
        ----------
        command_header : bytes
            Binary command header, such as \x84\x24\x00\x00\x08 for PIN unblock.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        command_data : bytes, optional
            Binary command data, e.g. PUT DATA or PIN block.

        Returns
        -------
        mac : bytes
            Binary 8-byte command MAC.

        """
        return _sm.generate_command_mac(
            self._derive_sk_sm_visa(self.icc_mk_smi, tag_9f36),
            command_header + tag_9f36 + tag_9f26 + command_data,
            8,
        )

    def encrypt_command_data(self, command_data: bytes, tag_9f36: bytes) -> bytes:
        """Command Data Encryption for Secure Messaging Confidentiality.

        Parameters
        ----------
        command_data : bytes
            Binary command data, e.g. PUT DATA or PIN block.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        encrypted_command_data : bytes
            Binary encrypted command command data. Then the resulting command is:

                Header || Encrypted Data || MAC
        """
        return _sm.encrypt_command_data(
            self._derive_sk_sm_visa(self.icc_mk_smc, tag_9f36),
            command_data,
            _sm.EncryptionType.VISA,
        )

    def generate_pin_change_command(
        self,
        pin: _typing.Union[bytes, str],
        tag_9f26: bytes,
        tag_9f36: bytes,
        current_pin: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> bytes:
        """Generate a PIN change command with encrypted PIN block and MAC.

        Parameters
        ----------
        pin : bytes or str
            New ASCII Personal Identification Number.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        current_pin : bytes or str, optional
            Current ASCII Personal Identification Number (optional). If present
            VIS PIN block is generated using current PIN.

        Returns
        -------
        pin_change_command : bytes
            Binary PIN change command with encrypted PIN block and MAC.

        """
        enc_pin_block = self.encrypt_command_data(
            _sm.format_vis_pin_block(self.icc_mk_ac, pin, current_pin), tag_9f36
        )

        if current_pin is None:
            command_header = b"\x84\x24\x00\x02\x18"
        else:
            command_header = b"\x84\x24\x00\x01\x18"

        return (
            command_header
            + enc_pin_block
            + self.generate_command_mac(
                command_header, tag_9f26, tag_9f36, enc_pin_block
            )
        )


class InteracCVN133(object):
    """Cryptogram Version Number (CVN) defines Card Authentication Method (CAM).
    Interac Cryptogram Version Number (CVN) 133 defines the following:

        - ICC Master Key derivation method = Option A
        - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method = MasterCard
        - Application Cryptogram (ARQC, TC, ACC) calculation method = EMV
        - Authorisation Response Cryptogram Session Key derivation method = MasterCard
        - Authorisation Response Cryptogram calculation method = 1
        - Secure Messaging Session Key derivation method = MasterCard
        - Secure Messaging Integrity (MAC) data format and padding = Format 2,
          not padded with transaction data
        - Secure Messaging Confidentiality encryption method and padding = MasterCard

    Parameters
    ----------
    iss_mk_ac : bytes
        16-byte binary Issuer Master Key for Application Cryptography.
        Has to be a valid DES key.
    iss_mk_smi : bytes
        16-byte binary Issuer Master Key for Issuer Script Integrity.
        Has to be a valid DES key.
    iss_mk_smc : bytes
        16-byte binary Issuer Master Key for Issuer Script Confidentiality.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Attributes
    ----------
    icc_mk_ac : bytes
        16-byte binary ICC Master Key for Application Cryptography.
    icc_mk_smi : bytes
        16-byte binary ICC Master Key for Issuer Script Integrity.
    icc_mk_smc : bytes
        16-byte binary ICC Master Key for Issuer Script Confidentiality.
    """

    def __init__(
        self,
        iss_mk_ac: bytes,
        iss_mk_smi: bytes,
        iss_mk_smc: bytes,
        pan: _typing.Union[bytes, str],
        psn: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> None:
        # Derive AC, SMI, and SMC ICC Master Keys for a new card
        # using option A.
        psn = psn or "00"
        self.icc_mk_ac = _kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = _kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = _kd.derive_icc_mk_a(iss_mk_smc, pan, psn)

    def _derive_sk_ac_mastercard(self, tag_9f36: bytes, tag_9f37: bytes) -> bytes:
        """Derive Application Cryptogram Session Key using MasterCard method.

        Parameters
        ----------
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(self.icc_mk_ac, tag_9f36 + b"\x00" * 2 + tag_9f37)

    def generate_ac(
        self,
        tag_9f02: bytes,
        tag_9f03: bytes,
        tag_9f1a: bytes,
        tag_95: bytes,
        tag_5f2a: bytes,
        tag_9a: bytes,
        tag_9c: bytes,
        tag_9f37: bytes,
        tag_82: bytes,
        tag_9f36: bytes,
        tag_9f10: bytes,
    ) -> bytes:
        """Generate Application Cryptogram. Same process for
            - Authorisation Request Cryptogram (ARQC)
            - Transaction Cryptogram (TC)
            - Application Authentication Cryptogram (AAC)

        Parameters
        ----------
        tag_9f02 : bytes
            Binary data from tag 9F02 (Amount, Authorized).
        tag_9f03 : bytes
            Binary data from tag 9F03 (Amount, Other).
        tag_9f1a : bytes
            Binary data from tag 9F1A (Terminal Country Code).
        tag_95 : bytes
            Binary data from tag 95 (Terminal Verification Results).
        tag_5f2a : bytes
            Binary data from tag 5F2A (Transaction Currency Code).
        tag_9a : bytes
            Binary data from tag 9A (Transaction Date).
        tag_9c : bytes
            Binary Data from tag 9C (Transaction Type).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_82 : bytes
            Binary data from tag 82 (Application Interchange Profile).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        tag_9f10 : bytes
            Binary data from tag 9F10 (Issuer Application Data).

        Returns
        -------
        ac : bytes
            Returns binary 8-byte cryptogram (ARQC, TC, AAC).
        """
        return _ac.generate_ac(
            self._derive_sk_ac_mastercard(tag_9f36, tag_9f37),
            tag_9f02
            + tag_9f03
            + tag_9f1a
            + tag_95
            + tag_5f2a
            + tag_9a
            + tag_9c
            + tag_9f37
            + tag_82
            + tag_9f36
            + tag_9f10,
            _ac.PaddingType.EMV,
            8,
        )

    def generate_arpc(
        self,
        tag_9f26: bytes,
        tag_9f37: bytes,
        tag_9f36: bytes,
        arpc_rc: bytes,
    ) -> bytes:
        """Generate Authorisation Response Cryptogram (ARPC) using method 1.
        Method for the generation of a 8-byte ARPC consists of applying
        ISO/IEC 9797-1 MAC algorithm 3 to:

            - 8-byte binary ARQC
            - 2-byte binary ARPC response code

        Parameters
        ----------
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        arpc_rc : bytes
            Binary 2-byte ARPC response code.

        Returns
        -------
        arpc : bytes
            Returns binary 8-byte Authorisation Response Cryptogram (ARPC).
            The resulting issuer authentication data (tag 91) is:

                91 || Len || ARPC || ARPC-RC
        """
        return _ac.generate_arpc_1(
            self._derive_sk_ac_mastercard(tag_9f36, tag_9f37),
            tag_9f26,
            arpc_rc,
        )

    def _derive_sk_sm_common(self, icc_mk_sm: bytes, tag_9f26: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method.

        Parameters
        ----------
        icc_mk_sm : bytes
            16-byte binary ICC Master Key for Secure Messaging.
            Has to be a valid DES key.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).

        Returns
        -------
        sk_sm : bytes
            16-byte binary Session Key for Secure Messaging.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(icc_mk_sm, tag_9f26)

    def generate_command_mac(
        self,
        command_header: bytes,
        tag_9f26: bytes,
        command_data: bytes = b"",
    ) -> bytes:
        r"""Message Authentication Code (MAC) for Secure Messaging Integrity.

        Parameters
        ----------
        command_header : bytes
            Binary command header, such as \x84\x24\x00\x00\x08 for PIN unblock.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        command_data : bytes, optional
            Binary command data, e.g. PUT DATA or PIN block.

        Returns
        -------
        mac : bytes
            Binary 8-byte command MAC.

        """
        return _sm.generate_command_mac(
            self._derive_sk_sm_common(self.icc_mk_smi, tag_9f26),
            command_header + command_data,
            8,
        )

    def encrypt_command_data(self, command_data: bytes, tag_9f26: bytes) -> bytes:
        """Command Data Encryption for Secure Messaging Confidentiality.

        Parameters
        ----------
        command_data : bytes
            Binary command data, e.g. PUT DATA or PIN block.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).

        Returns
        -------
        encrypted_command_data : bytes
            Binary encrypted command command data. Then the resulting command is:

                Header || Encrypted Data || MAC
        """
        return _sm.encrypt_command_data(
            self._derive_sk_sm_common(self.icc_mk_smc, tag_9f26),
            command_data,
            _sm.EncryptionType.MASTERCARD,
        )

    def generate_pin_change_command(
        self, pin: _typing.Union[bytes, str], tag_9f26: bytes
    ) -> bytes:
        """Generate a PIN change command with encrypted PIN block and MAC.

        Parameters
        ----------
        pin : bytes or str
            New ASCII Personal Identification Number.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).

        Returns
        -------
        pin_change_command : bytes
            Binary PIN change command with encrypted PIN block and MAC.

        """
        enc_pin_block = self.encrypt_command_data(
            _sm.format_iso9564_2_pin_block(pin), tag_9f26
        )

        command_header = b"\x84\x24\x00\x02\x10"

        return (
            command_header
            + enc_pin_block
            + self.generate_command_mac(command_header, tag_9f26, enc_pin_block)
        )


class MasterCardCVN16(object):
    """Cryptogram Version Number (CVN) defines Card Authentication Method (CAM).
    MasterCard Cryptogram Version Number (CVN) 16 defines the following:

        - ICC Master Key derivation method = Option A
        - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method = MasterCard
        - Application Cryptogram (ARQC, TC, ACC) calculation method = EMV
        - Authorisation Response Cryptogram Session Key derivation method = None
        - Authorisation Response Cryptogram calculation method = 1
        - Secure Messaging Session Key derivation method = Common
        - Secure Messaging Integrity (MAC) data format and padding = Format 2,
          padded with transaction data
        - Secure Messaging Confidentiality encryption method and padding = MasterCard

    MasterCard CVN 16 (binary 0001 0 00 0):

        - Bit 2-3 = 00: Uses Mastercard Proprietary SKD session key
        - Bit 1 = 0:    Does not include counters in AC generation

    Parameters
    ----------
    iss_mk_ac : bytes
        16-byte binary Issuer Master Key for Application Cryptography.
        Has to be a valid DES key.
    iss_mk_smi : bytes
        16-byte binary Issuer Master Key for Issuer Script Integrity.
        Has to be a valid DES key.
    iss_mk_smc : bytes
        16-byte binary Issuer Master Key for Issuer Script Confidentiality.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Attributes
    ----------
    icc_mk_ac : bytes
        16-byte binary ICC Master Key for Application Cryptography.
    icc_mk_smi : bytes
        16-byte binary ICC Master Key for Issuer Script Integrity.
    icc_mk_smc : bytes
        16-byte binary ICC Master Key for Issuer Script Confidentiality.
    """

    def __init__(
        self,
        iss_mk_ac: bytes,
        iss_mk_smi: bytes,
        iss_mk_smc: bytes,
        pan: _typing.Union[bytes, str],
        psn: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> None:
        # Derive AC, SMI, and SMC ICC Master Keys for a new card
        # using option A.
        psn = psn or "00"
        self.icc_mk_ac = _kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = _kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = _kd.derive_icc_mk_a(iss_mk_smc, pan, psn)

    def _derive_sk_ac_mastercard(self, tag_9f36: bytes, tag_9f37: bytes) -> bytes:
        """Derive Application Cryptogram Session Key using MasterCard method.

        Parameters
        ----------
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(self.icc_mk_ac, tag_9f36 + b"\x00" * 2 + tag_9f37)

    def generate_ac(
        self,
        tag_9f02: bytes,
        tag_9f03: bytes,
        tag_9f1a: bytes,
        tag_95: bytes,
        tag_5f2a: bytes,
        tag_9a: bytes,
        tag_9c: bytes,
        tag_9f37: bytes,
        tag_82: bytes,
        tag_9f36: bytes,
        cvr: bytes,
    ) -> bytes:
        r"""Generate Application Cryptogram. Same process for
            - Authorisation Request Cryptogram (ARQC)
            - Transaction Cryptogram (TC)
            - Application Authentication Cryptogram (AAC)

        Parameters
        ----------
        tag_9f02 : bytes
            Binary data from tag 9F02 (Amount, Authorized).
        tag_9f03 : bytes
            Binary data from tag 9F03 (Amount, Other).
        tag_9f1a : bytes
            Binary data from tag 9F1A (Terminal Country Code).
        tag_95 : bytes
            Binary data from tag 95 (Terminal Verification Results).
        tag_5f2a : bytes
            Binary data from tag 5F2A (Transaction Currency Code).
        tag_9a : bytes
            Binary data from tag 9A (Transaction Date).
        tag_9c : bytes
            Binary Data from tag 9C (Transaction Type).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_82 : bytes
            Binary data from tag 82 (Application Interchange Profile).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        cvr : bytes
            6 bytes of binary Card Verification Results extracted from
            9F10 (Issuer Application Data).

        Returns
        -------
        ac : bytes
            Returns binary 8-byte cryptogram (ARQC, TC, AAC).
        """
        return _ac.generate_ac(
            self._derive_sk_ac_mastercard(tag_9f36, tag_9f37),
            tag_9f02
            + tag_9f03
            + tag_9f1a
            + tag_95
            + tag_5f2a
            + tag_9a
            + tag_9c
            + tag_9f37
            + tag_82
            + tag_9f36
            + cvr,
            _ac.PaddingType.EMV,
            8,
        )

    def _derive_sk_arpc_none(self) -> bytes:
        """Derive Application Cryptogram Session Key.
        Use ICC Master Key, since Session Key is not applicable.

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return self.icc_mk_ac

    def generate_arpc(self, tag_9f26: bytes, arpc_rc: bytes) -> bytes:
        """Generate Authorisation Response Cryptogram (ARPC) using method 1.
        Method for the generation of a 8-byte ARPC consists of applying
        ISO/IEC 9797-1 MAC algorithm 3 to:

            - 8-byte binary ARQC
            - 2-byte binary ARPC response code

        Parameters
        ----------
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        arpc_rc : bytes
            Binary 2-byte ARPC response code.

        Returns
        -------
        arpc : bytes
            Returns binary 8-byte Authorisation Response Cryptogram (ARPC).
            The resulting issuer authentication data (tag 91) is:

                91 || Len || ARPC || ARPC-RC
        """
        return _ac.generate_arpc_1(self._derive_sk_arpc_none(), tag_9f26, arpc_rc)

    def _derive_sk_sm_common(self, icc_mk_sm: bytes, tag_9f26: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method.

        Parameters
        ----------
        icc_mk_sm : bytes
            16-byte binary ICC Master Key for Secure Messaging.
            Has to be a valid DES key.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).

        Returns
        -------
        sk_sm : bytes
            16-byte binary Session Key for Secure Messaging.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(icc_mk_sm, tag_9f26)

    def generate_command_mac(
        self,
        command_header: bytes,
        tag_9f26: bytes,
        tag_9f36: bytes,
        command_data: bytes = b"",
    ) -> bytes:
        r"""Message Authentication Code (MAC) for Secure Messaging Integrity.

        Parameters
        ----------
        command_header : bytes
            Binary command header, such as \x84\x24\x00\x00\x08 for PIN unblock.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        command_data : bytes, optional
            Binary command data, e.g. PUT DATA or PIN block.

        Returns
        -------
        mac : bytes
            Binary 8-byte command MAC.

        """
        return _sm.generate_command_mac(
            self._derive_sk_sm_common(self.icc_mk_smi, tag_9f26),
            command_header + tag_9f36 + tag_9f26 + command_data,
            8,
        )

    def encrypt_command_data(self, command_data: bytes, tag_9f26: bytes) -> bytes:
        r"""Command Data Encryption for Secure Messaging Confidentiality.

        Parameters
        ----------
        command_data : bytes
            Binary command data, e.g. PUT DATA or PIN block.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.

        Returns
        -------
        encrypted_command_data : bytes
            Binary encrypted command command data. Then the resulting command is:

                Header || Encrypted Data || MAC
        """
        return _sm.encrypt_command_data(
            self._derive_sk_sm_common(self.icc_mk_smc, tag_9f26),
            command_data,
            _sm.EncryptionType.MASTERCARD,
        )

    def generate_pin_change_command(
        self,
        pin: _typing.Union[bytes, str],
        tag_9f26: bytes,
        tag_9f36: bytes,
    ) -> bytes:
        r"""Generate a PIN change command with encrypted PIN block and MAC.

        Parameters
        ----------
        pin : bytes or str
            New ASCII Personal Identification Number.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        pin_change_command : bytes
            Binary PIN change command with encrypted PIN block and MAC.

        """
        enc_pin_block = self.encrypt_command_data(
            _sm.format_iso9564_2_pin_block(pin), tag_9f26
        )

        command_header = b"\x84\x24\x00\x02\x10"

        return (
            command_header
            + enc_pin_block
            + self.generate_command_mac(
                command_header, tag_9f26, tag_9f36, enc_pin_block
            )
        )


class MasterCardCVN17(object):
    """Cryptogram Version Number (CVN) defines Card Authentication Method (CAM).
    MasterCard Cryptogram Version Number (CVN) 17 defines the following:

        - ICC Master Key derivation method = Option A
        - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method = MasterCard
        - Application Cryptogram (ARQC, TC, ACC) calculation method = EMV
        - Authorisation Response Cryptogram Session Key derivation method = None
        - Authorisation Response Cryptogram calculation method = 1
        - Secure Messaging Session Key derivation method = Common
        - Secure Messaging Integrity (MAC) data format and padding = Format 2,
          padded with transaction data
        - Secure Messaging Confidentiality encryption method and padding = MasterCard

    MasterCard CVN 17 (binary 0001 0 00 1):

        - Bit 2-3 = 00: Uses Mastercard Proprietary SKD session key
        - Bit 1 = 1:    Includes counters in AC generation

    Parameters
    ----------
    iss_mk_ac : bytes
        16-byte binary Issuer Master Key for Application Cryptography.
        Has to be a valid DES key.
    iss_mk_smi : bytes
        16-byte binary Issuer Master Key for Issuer Script Integrity.
        Has to be a valid DES key.
    iss_mk_smc : bytes
        16-byte binary Issuer Master Key for Issuer Script Confidentiality.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Attributes
    ----------
    icc_mk_ac : bytes
        16-byte binary ICC Master Key for Application Cryptography.
    icc_mk_smi : bytes
        16-byte binary ICC Master Key for Issuer Script Integrity.
    icc_mk_smc : bytes
        16-byte binary ICC Master Key for Issuer Script Confidentiality.
    """

    def __init__(
        self,
        iss_mk_ac: bytes,
        iss_mk_smi: bytes,
        iss_mk_smc: bytes,
        pan: _typing.Union[bytes, str],
        psn: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> None:
        # Derive AC, SMI, and SMC ICC Master Keys for a new card
        # using option A.
        psn = psn or "00"
        self.icc_mk_ac = _kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = _kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = _kd.derive_icc_mk_a(iss_mk_smc, pan, psn)

    def _derive_sk_ac_mastercard(self, tag_9f36: bytes, tag_9f37: bytes) -> bytes:
        """Derive Application Cryptogram Session Key using MasterCard method.

        Parameters
        ----------
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(self.icc_mk_ac, tag_9f36 + b"\x00" * 2 + tag_9f37)

    def generate_ac(
        self,
        tag_9f02: bytes,
        tag_9f03: bytes,
        tag_9f1a: bytes,
        tag_95: bytes,
        tag_5f2a: bytes,
        tag_9a: bytes,
        tag_9c: bytes,
        tag_9f37: bytes,
        tag_82: bytes,
        tag_9f36: bytes,
        cvr: bytes,
        counters: bytes,
    ) -> bytes:
        r"""Generate Application Cryptogram. Same process for
            - Authorisation Request Cryptogram (ARQC)
            - Transaction Cryptogram (TC)
            - Application Authentication Cryptogram (AAC)

        Parameters
        ----------
        tag_9f02 : bytes
            Binary data from tag 9F02 (Amount, Authorized).
        tag_9f03 : bytes
            Binary data from tag 9F03 (Amount, Other).
        tag_9f1a : bytes
            Binary data from tag 9F1A (Terminal Country Code).
        tag_95 : bytes
            Binary data from tag 95 (Terminal Verification Results).
        tag_5f2a : bytes
            Binary data from tag 5F2A (Transaction Currency Code).
        tag_9a : bytes
            Binary data from tag 9A (Transaction Date).
        tag_9c : bytes
            Binary Data from tag 9C (Transaction Type).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_82 : bytes
            Binary data from tag 82 (Application Interchange Profile).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        cvr : bytes
            6 bytes of binary Card Verification Results extracted from
            9F10 (Issuer Application Data).
        counters : bytes
            Counters include Cumulative Offline Transaction Amount
            (6 bytes), Consecutive Offline Transactions Number (1 byte) and
            1 byte set to \xFF.
            It's assumed that the counters are in the clear; not encrypted.
            These fields are extracted from 9F10 (Issuer Application Data).
            For M/Chip 4 counters are always 8 bytes long.
            For M/Chip Advance counters can be 8 or 16 bytes, with or without
            last online ATC.

        Returns
        -------
        ac : bytes
            Returns binary 8-byte cryptogram (ARQC, TC, AAC).
        """
        return _ac.generate_ac(
            self._derive_sk_ac_mastercard(tag_9f36, tag_9f37),
            tag_9f02
            + tag_9f03
            + tag_9f1a
            + tag_95
            + tag_5f2a
            + tag_9a
            + tag_9c
            + tag_9f37
            + tag_82
            + tag_9f36
            + cvr
            + counters,
            _ac.PaddingType.EMV,
            8,
        )

    def _derive_sk_arpc_none(self) -> bytes:
        """Derive Application Cryptogram Session Key.
        Use ICC Master Key, since Session Key is not applicable.

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return self.icc_mk_ac

    def generate_arpc(self, tag_9f26: bytes, arpc_rc: bytes) -> bytes:
        """Generate Authorisation Response Cryptogram (ARPC) using method 1.
        Method for the generation of a 8-byte ARPC consists of applying
        ISO/IEC 9797-1 MAC algorithm 3 to:

            - 8-byte binary ARQC
            - 2-byte binary ARPC response code

        Parameters
        ----------
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        arpc_rc : bytes
            Binary 2-byte ARPC response code.

        Returns
        -------
        arpc : bytes
            Returns binary 8-byte Authorisation Response Cryptogram (ARPC).
            The resulting issuer authentication data (tag 91) is:

                91 || Len || ARPC || ARPC-RC
        """
        return _ac.generate_arpc_1(self._derive_sk_arpc_none(), tag_9f26, arpc_rc)

    def _derive_sk_sm_common(self, icc_mk_sm: bytes, tag_9f26: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method.

        Parameters
        ----------
        icc_mk_sm : bytes
            16-byte binary ICC Master Key for Secure Messaging.
            Has to be a valid DES key.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).

        Returns
        -------
        sk_sm : bytes
            16-byte binary Session Key for Secure Messaging.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(icc_mk_sm, tag_9f26)

    def generate_command_mac(
        self,
        command_header: bytes,
        tag_9f26: bytes,
        tag_9f36: bytes,
        command_data: bytes = b"",
    ) -> bytes:
        r"""Message Authentication Code (MAC) for Secure Messaging Integrity.

        Parameters
        ----------
        command_header : bytes
            Binary command header, such as \x84\x24\x00\x00\x08 for PIN unblock.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        command_data : bytes, optional
            Binary command data, e.g. PUT DATA or PIN block.

        Returns
        -------
        mac : bytes
            Binary 8-byte command MAC.

        """
        return _sm.generate_command_mac(
            self._derive_sk_sm_common(self.icc_mk_smi, tag_9f26),
            command_header + tag_9f36 + tag_9f26 + command_data,
            8,
        )

    def encrypt_command_data(self, command_data: bytes, tag_9f26: bytes) -> bytes:
        r"""Command Data Encryption for Secure Messaging Confidentiality.

        Parameters
        ----------
        command_data : bytes
            Binary command data, e.g. PUT DATA or PIN block.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.

        Returns
        -------
        encrypted_command_data : bytes
            Binary encrypted command command data. Then the resulting command is:

                Header || Encrypted Data || MAC
        """
        return _sm.encrypt_command_data(
            self._derive_sk_sm_common(self.icc_mk_smc, tag_9f26),
            command_data,
            _sm.EncryptionType.MASTERCARD,
        )

    def generate_pin_change_command(
        self,
        pin: _typing.Union[bytes, str],
        tag_9f26: bytes,
        tag_9f36: bytes,
    ) -> bytes:
        r"""Generate a PIN change command with encrypted PIN block and MAC.

        Parameters
        ----------
        pin : bytes or str
            New ASCII Personal Identification Number.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        pin_change_command : bytes
            Binary PIN change command with encrypted PIN block and MAC.

        """
        enc_pin_block = self.encrypt_command_data(
            _sm.format_iso9564_2_pin_block(pin), tag_9f26
        )

        command_header = b"\x84\x24\x00\x02\x10"

        return (
            command_header
            + enc_pin_block
            + self.generate_command_mac(
                command_header, tag_9f26, tag_9f36, enc_pin_block
            )
        )


class MasterCardCVN20(object):
    """Cryptogram Version Number (CVN) defines Card Authentication Method (CAM).
    MasterCard Cryptogram Version Number (CVN) 20 defines the following:

        - ICC Master Key derivation method = Option A
        - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method = Common
        - Application Cryptogram (ARQC, TC, ACC) calculation method = EMV
        - Authorisation Response Cryptogram Session Key derivation method = Common
        - Authorisation Response Cryptogram calculation method = 1
        - Secure Messaging Session Key derivation method = Common
        - Secure Messaging Integrity (MAC) data format and padding = Format 2,
          padded with transaction data
        - Secure Messaging Confidentiality encryption method and padding = MasterCard

    MasterCard CVN 20 (binary 0001 0 10 0):

        - Bit 2-3 = 10: Uses EMV CSK session key
        - Bit 1 = 0:    Does not include counters in AC generation

    Parameters
    ----------
    iss_mk_ac : bytes
        16-byte binary Issuer Master Key for Application Cryptography.
        Has to be a valid DES key.
    iss_mk_smi : bytes
        16-byte binary Issuer Master Key for Issuer Script Integrity.
        Has to be a valid DES key.
    iss_mk_smc : bytes
        16-byte binary Issuer Master Key for Issuer Script Confidentiality.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Attributes
    ----------
    icc_mk_ac : bytes
        16-byte binary ICC Master Key for Application Cryptography.
    icc_mk_smi : bytes
        16-byte binary ICC Master Key for Issuer Script Integrity.
    icc_mk_smc : bytes
        16-byte binary ICC Master Key for Issuer Script Confidentiality.
    """

    def __init__(
        self,
        iss_mk_ac: bytes,
        iss_mk_smi: bytes,
        iss_mk_smc: bytes,
        pan: _typing.Union[bytes, str],
        psn: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> None:
        # Derive AC, SMI, and SMC ICC Master Keys for a new card
        # using option A.
        psn = psn or "00"
        self.icc_mk_ac = _kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = _kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = _kd.derive_icc_mk_a(iss_mk_smc, pan, psn)

    def _derive_sk_ac_common(self, tag_9f36: bytes) -> bytes:
        """Derive Application Cryptogram Session Key using EMV Common method.

        Parameters
        ----------
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(self.icc_mk_ac, tag_9f36 + b"\x00" * 6)

    def generate_ac(
        self,
        tag_9f02: bytes,
        tag_9f03: bytes,
        tag_9f1a: bytes,
        tag_95: bytes,
        tag_5f2a: bytes,
        tag_9a: bytes,
        tag_9c: bytes,
        tag_9f37: bytes,
        tag_82: bytes,
        tag_9f36: bytes,
        cvr: bytes,
    ) -> bytes:
        r"""Generate Application Cryptogram. Same process for
            - Authorisation Request Cryptogram (ARQC)
            - Transaction Cryptogram (TC)
            - Application Authentication Cryptogram (AAC)

        Parameters
        ----------
        tag_9f02 : bytes
            Binary data from tag 9F02 (Amount, Authorized).
        tag_9f03 : bytes
            Binary data from tag 9F03 (Amount, Other).
        tag_9f1a : bytes
            Binary data from tag 9F1A (Terminal Country Code).
        tag_95 : bytes
            Binary data from tag 95 (Terminal Verification Results).
        tag_5f2a : bytes
            Binary data from tag 5F2A (Transaction Currency Code).
        tag_9a : bytes
            Binary data from tag 9A (Transaction Date).
        tag_9c : bytes
            Binary Data from tag 9C (Transaction Type).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_82 : bytes
            Binary data from tag 82 (Application Interchange Profile).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        cvr : bytes
            6 bytes of binary Card Verification Results extracted from
            9F10 (Issuer Application Data).

        Returns
        -------
        ac : bytes
            Returns binary 8-byte cryptogram (ARQC, TC, AAC).
        """
        return _ac.generate_ac(
            self._derive_sk_ac_common(tag_9f36),
            tag_9f02
            + tag_9f03
            + tag_9f1a
            + tag_95
            + tag_5f2a
            + tag_9a
            + tag_9c
            + tag_9f37
            + tag_82
            + tag_9f36
            + cvr,
            _ac.PaddingType.EMV,
            8,
        )

    def generate_arpc(self, tag_9f26: bytes, tag_9f36: bytes, arpc_rc: bytes) -> bytes:
        """Generate Authorisation Response Cryptogram (ARPC) using method 1.
        Method for the generation of a 8-byte ARPC consists of applying
        ISO/IEC 9797-1 MAC algorithm 3 to:

            - 8-byte binary ARQC
            - 2-byte binary ARPC response code

        Parameters
        ----------
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        arpc_rc : bytes
            Binary 2-byte ARPC response code.

        Returns
        -------
        arpc : bytes
            Returns binary 8-byte Authorisation Response Cryptogram (ARPC).
            The resulting issuer authentication data (tag 91) is:

                91 || Len || ARPC || ARPC-RC
        """
        return _ac.generate_arpc_1(
            self._derive_sk_ac_common(tag_9f36), tag_9f26, arpc_rc
        )

    def _derive_sk_sm_common(self, icc_mk_sm: bytes, tag_9f26: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method.

        Parameters
        ----------
        icc_mk_sm : bytes
            16-byte binary ICC Master Key for Secure Messaging.
            Has to be a valid DES key.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).

        Returns
        -------
        sk_sm : bytes
            16-byte binary Session Key for Secure Messaging.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(icc_mk_sm, tag_9f26)

    def generate_command_mac(
        self,
        command_header: bytes,
        tag_9f26: bytes,
        tag_9f36: bytes,
        command_data: bytes = b"",
    ) -> bytes:
        r"""Message Authentication Code (MAC) for Secure Messaging Integrity.

        Parameters
        ----------
        command_header : bytes
            Binary command header, such as \x84\x24\x00\x00\x08 for PIN unblock.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        command_data : bytes, optional
            Binary command data, e.g. PUT DATA or PIN block.

        Returns
        -------
        mac : bytes
            Binary 8-byte command MAC.

        """
        return _sm.generate_command_mac(
            self._derive_sk_sm_common(self.icc_mk_smi, tag_9f26),
            command_header + tag_9f36 + tag_9f26 + command_data,
            8,
        )

    def encrypt_command_data(self, command_data: bytes, tag_9f26: bytes) -> bytes:
        r"""Command Data Encryption for Secure Messaging Confidentiality.

        Parameters
        ----------
        command_data : bytes
            Binary command data, e.g. PUT DATA or PIN block.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.

        Returns
        -------
        encrypted_command_data : bytes
            Binary encrypted command command data. Then the resulting command is:

                Header || Encrypted Data || MAC
        """
        return _sm.encrypt_command_data(
            self._derive_sk_sm_common(self.icc_mk_smc, tag_9f26),
            command_data,
            _sm.EncryptionType.MASTERCARD,
        )

    def generate_pin_change_command(
        self,
        pin: _typing.Union[bytes, str],
        tag_9f26: bytes,
        tag_9f36: bytes,
    ) -> bytes:
        r"""Generate a PIN change command with encrypted PIN block and MAC.

        Parameters
        ----------
        pin : bytes or str
            New ASCII Personal Identification Number.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        pin_change_command : bytes
            Binary PIN change command with encrypted PIN block and MAC.

        """
        enc_pin_block = self.encrypt_command_data(
            _sm.format_iso9564_2_pin_block(pin), tag_9f26
        )

        command_header = b"\x84\x24\x00\x02\x10"

        return (
            command_header
            + enc_pin_block
            + self.generate_command_mac(
                command_header, tag_9f26, tag_9f36, enc_pin_block
            )
        )


class MasterCardCVN21(object):
    """Cryptogram Version Number (CVN) defines Card Authentication Method (CAM).
    MasterCard Cryptogram Version Number (CVN) 21 defines the following:

        - ICC Master Key derivation method = Option A
        - Application Cryptogram (ARQC, TC, ACC) Session Key derivation method = Common
        - Application Cryptogram (ARQC, TC, ACC) calculation method = EMV
        - Authorisation Response Cryptogram Session Key derivation method = Common
        - Authorisation Response Cryptogram calculation method = 1
        - Secure Messaging Session Key derivation method = Common
        - Secure Messaging Integrity (MAC) data format and padding = Format 2,
          padded with transaction data
        - Secure Messaging Confidentiality encryption method and padding = MasterCard

    MasterCard CVN 20 (binary 0001 0 10 1):

        - Bit 2-3 = 10: Uses EMV CSK session key
        - Bit 1 = 1:    Includes counters in AC generation

    Parameters
    ----------
    iss_mk_ac : bytes
        16-byte binary Issuer Master Key for Application Cryptography.
        Has to be a valid DES key.
    iss_mk_smi : bytes
        16-byte binary Issuer Master Key for Issuer Script Integrity.
        Has to be a valid DES key.
    iss_mk_smc : bytes
        16-byte binary Issuer Master Key for Issuer Script Confidentiality.
        Has to be a valid DES key.
    pan : bytes or str
        ASCII Application Primary Account Number.
    psn : bytes or str, optional
        ASCII 2-digit PAN Sequence Number (default 00).

    Attributes
    ----------
    icc_mk_ac : bytes
        16-byte binary ICC Master Key for Application Cryptography.
    icc_mk_smi : bytes
        16-byte binary ICC Master Key for Issuer Script Integrity.
    icc_mk_smc : bytes
        16-byte binary ICC Master Key for Issuer Script Confidentiality.
    """

    def __init__(
        self,
        iss_mk_ac: bytes,
        iss_mk_smi: bytes,
        iss_mk_smc: bytes,
        pan: _typing.Union[bytes, str],
        psn: _typing.Optional[_typing.Union[bytes, str]] = None,
    ) -> None:
        # Derive AC, SMI, and SMC ICC Master Keys for a new card
        # using option A.
        psn = psn or "00"
        self.icc_mk_ac = _kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = _kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = _kd.derive_icc_mk_a(iss_mk_smc, pan, psn)

    def _derive_sk_ac_common(self, tag_9f36: bytes) -> bytes:
        """Derive Application Cryptogram Session Key using EMV Common method.

        Parameters
        ----------
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        sk_ac : bytes
            16-byte binary Session Key for Application Cryptogram.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(self.icc_mk_ac, tag_9f36 + b"\x00" * 6)

    def generate_ac(
        self,
        tag_9f02: bytes,
        tag_9f03: bytes,
        tag_9f1a: bytes,
        tag_95: bytes,
        tag_5f2a: bytes,
        tag_9a: bytes,
        tag_9c: bytes,
        tag_9f37: bytes,
        tag_82: bytes,
        tag_9f36: bytes,
        cvr: bytes,
        counters: bytes,
    ) -> bytes:
        r"""Generate Application Cryptogram. Same process for
            - Authorisation Request Cryptogram (ARQC)
            - Transaction Cryptogram (TC)
            - Application Authentication Cryptogram (AAC)

        Parameters
        ----------
        tag_9f02 : bytes
            Binary data from tag 9F02 (Amount, Authorized).
        tag_9f03 : bytes
            Binary data from tag 9F03 (Amount, Other).
        tag_9f1a : bytes
            Binary data from tag 9F1A (Terminal Country Code).
        tag_95 : bytes
            Binary data from tag 95 (Terminal Verification Results).
        tag_5f2a : bytes
            Binary data from tag 5F2A (Transaction Currency Code).
        tag_9a : bytes
            Binary data from tag 9A (Transaction Date).
        tag_9c : bytes
            Binary Data from tag 9C (Transaction Type).
        tag_9f37 : bytes
            Binary data from tag 9F37 (Unpredictable Number).
        tag_82 : bytes
            Binary data from tag 82 (Application Interchange Profile).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        cvr : bytes
            6 bytes of binary Card Verification Results extracted from
            9F10 (Issuer Application Data).
        counters : bytes
            Counters include Cumulative Offline Transaction Amount
            (6 bytes), Consecutive Offline Transactions Number (1 byte) and
            1 byte set to \xFF.
            It's assumed that the counters are in the clear; not encrypted.
            These fields are extracted from 9F10 (Issuer Application Data).
            For M/Chip 4 counters are always 8 bytes long.
            For M/Chip Advance counters can be 8 or 16 bytes, with or without
            last online ATC.

        Returns
        -------
        ac : bytes
            Returns binary 8-byte cryptogram (ARQC, TC, AAC).
        """
        return _ac.generate_ac(
            self._derive_sk_ac_common(tag_9f36),
            tag_9f02
            + tag_9f03
            + tag_9f1a
            + tag_95
            + tag_5f2a
            + tag_9a
            + tag_9c
            + tag_9f37
            + tag_82
            + tag_9f36
            + cvr
            + counters,
            _ac.PaddingType.EMV,
            8,
        )

    def generate_arpc(self, tag_9f26: bytes, tag_9f36: bytes, arpc_rc: bytes) -> bytes:
        """Generate Authorisation Response Cryptogram (ARPC) using method 1.
        Method for the generation of a 8-byte ARPC consists of applying
        ISO/IEC 9797-1 MAC algorithm 3 to:

            - 8-byte binary ARQC
            - 2-byte binary ARPC response code

        Parameters
        ----------
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        arpc_rc : bytes
            Binary 2-byte ARPC response code.

        Returns
        -------
        arpc : bytes
            Returns binary 8-byte Authorisation Response Cryptogram (ARPC).
            The resulting issuer authentication data (tag 91) is:

                91 || Len || ARPC || ARPC-RC
        """
        return _ac.generate_arpc_1(
            self._derive_sk_ac_common(tag_9f36), tag_9f26, arpc_rc
        )

    def _derive_sk_sm_common(self, icc_mk_sm: bytes, tag_9f26: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method.

        Parameters
        ----------
        icc_mk_sm : bytes
            16-byte binary ICC Master Key for Secure Messaging.
            Has to be a valid DES key.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).

        Returns
        -------
        sk_sm : bytes
            16-byte binary Session Key for Secure Messaging.
            Has to be a valid DES key.
        """
        return _kd.derive_common_sk(icc_mk_sm, tag_9f26)

    def generate_command_mac(
        self,
        command_header: bytes,
        tag_9f26: bytes,
        tag_9f36: bytes,
        command_data: bytes = b"",
    ) -> bytes:
        r"""Message Authentication Code (MAC) for Secure Messaging Integrity.

        Parameters
        ----------
        command_header : bytes
            Binary command header, such as \x84\x24\x00\x00\x08 for PIN unblock.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).
        command_data : bytes, optional
            Binary command data, e.g. PUT DATA or PIN block.

        Returns
        -------
        mac : bytes
            Binary 8-byte command MAC.

        """
        return _sm.generate_command_mac(
            self._derive_sk_sm_common(self.icc_mk_smi, tag_9f26),
            command_header + tag_9f36 + tag_9f26 + command_data,
            8,
        )

    def encrypt_command_data(self, command_data: bytes, tag_9f26: bytes) -> bytes:
        r"""Command Data Encryption for Secure Messaging Confidentiality.

        Parameters
        ----------
        command_data : bytes
            Binary command data, e.g. PUT DATA or PIN block.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.

        Returns
        -------
        encrypted_command_data : bytes
            Binary encrypted command command data. Then the resulting command is:

                Header || Encrypted Data || MAC
        """
        return _sm.encrypt_command_data(
            self._derive_sk_sm_common(self.icc_mk_smc, tag_9f26),
            command_data,
            _sm.EncryptionType.MASTERCARD,
        )

    def generate_pin_change_command(
        self,
        pin: _typing.Union[bytes, str],
        tag_9f26: bytes,
        tag_9f36: bytes,
    ) -> bytes:
        r"""Generate a PIN change command with encrypted PIN block and MAC.

        Parameters
        ----------
        pin : bytes or str
            New ASCII Personal Identification Number.
        tag_9f26 : bytes
            Binary data from tag 9F26 (Authorisation Request Cryptogram).
            This value should be increment by 1 for each process script command
            after the first command. For example, the first script command will
            use 9F26 as-is (e.g. \x12\x34\x56\x78\x12\x34\x56\x78).
            The second script command will use 9F26 + 1
            (e.g. \x12\x34\x56\x78\x12\x34\x56\x79). And so on.
        tag_9f36 : bytes
            Binary data from tag 9F36 (Application Transaction Counter).

        Returns
        -------
        pin_change_command : bytes
            Binary PIN change command with encrypted PIN block and MAC.

        """
        enc_pin_block = self.encrypt_command_data(
            _sm.format_iso9564_2_pin_block(pin), tag_9f26
        )

        command_header = b"\x84\x24\x00\x02\x10"

        return (
            command_header
            + enc_pin_block
            + self.generate_command_mac(
                command_header, tag_9f26, tag_9f36, enc_pin_block
            )
        )
