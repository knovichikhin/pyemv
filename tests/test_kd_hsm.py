from typing import Union
import pytest
from pyemv import ac, kd, sm, tools


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"12345678901234567", b"45"),
        (b"12345678901234567", "45"),
        ("12345678901234567", b"45"),
        ("12345678901234567", "45"),
    ],
)
def test_derive_icc_mk_a_psn(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """
    Verify ICC MK derivation method A with non-zero PSN.

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using ICC Master Key
    ARPC Method = 1
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "FF08"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "DF82"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "19C1FBC83EBDC0D5"

    # ARPC Method 1 using ICC Master Key
    arpc_rc = bytes.fromhex("0000")
    arpc = ac.generate_arpc_1(icc_mk, arqc, arpc_rc)
    assert arpc.hex().upper() == "78A372523FA35A03"


@pytest.mark.parametrize(
    "pan",
    [
        b"12345678901234567",
        "12345678901234567",
    ],
)
def test_derive_icc_mk_a_no_psn(pan: Union[bytes, str]) -> None:
    """
    Verify ICC MK derivation method A with a zero PSN.

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using ICC Master Key
    ARPC Method = 1
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan)

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "3F4F"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "8698A7319324FD93"

    # ARPC Method 1 using ICC Master Key
    arpc_rc = bytes.fromhex("0000")
    arpc = ac.generate_arpc_1(icc_mk, arqc, arpc_rc)
    assert arpc.hex().upper() == "BEA11C8F4A47EF6F"


def test_derive_common_sk() -> None:
    """
    Verify common session key derivation using algorithm
    type where both ARQC and ARPC are verified using derived
    session key.

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key Derivation
    ARPC Method = 1
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = "12345678901234567"
    psn = "45"
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "FF08"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "DF82"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "19C1FBC83EBDC0D5"

    # ARPC Method 1 using Session Key
    arpc_rc = bytes.fromhex("0000")
    arpc = ac.generate_arpc_1(sk_ac, arqc, arpc_rc)
    assert arpc.hex().upper() == "C3620580668E5B65"


def test_derive_icc_mk_b_pan16() -> None:
    """
    Verify ICC MK derivation method B using incompatible
    PAN length. Method B is applicable only if PAN is
    17-19 digits long.

    Master Key Derivation = Option B
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key Derivation
    ARPC Method = 2
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = "1234567890123456"
    icc_mk = kd.derive_icc_mk_b(iss_mk, pan)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "BAB0"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "BC19"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "0CE77D211CB5459A"

    # ARPC Method 2 using Session Key
    csu = bytes.fromhex("00000000")
    arpc = ac.generate_arpc_2(sk_ac, arqc, csu)
    assert arpc.hex().upper() == "8CD9AA5D"


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"12345678901234567", b"45"),
        (b"12345678901234567", "45"),
        ("12345678901234567", b"45"),
        ("12345678901234567", "45"),
    ],
)
def test_derive_icc_mk_b_pan17_psn(
    pan: Union[bytes, str], psn: Union[bytes, str]
) -> None:
    """
    Verify ICC MK derivation method B using 17 digit PAN.

    Master Key Derivation = Option B
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key Derivation
    ARPC Method = 2
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    icc_mk = kd.derive_icc_mk_b(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "0BAF"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "4262"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "5760EE07B4FA65D1"

    # ARPC Method 2 using Session Key
    csu = bytes.fromhex("00000000")
    arpc = ac.generate_arpc_2(sk_ac, arqc, csu)
    assert arpc.hex().upper() == "106B81D9"


@pytest.mark.parametrize(
    "pan",
    [
        b"12345678901234567",
        "12345678901234567",
    ],
)
def test_derive_icc_mk_b_pan17_no_psn(pan: Union[bytes, str]) -> None:
    """
    Verify ICC MK derivation method B using 17 digit PAN.

    Master Key Derivation = Option B
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key Derivation
    ARPC Method = 2
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    icc_mk = kd.derive_icc_mk_b(iss_mk, pan)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "4626"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "7F36"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "0BAA251EA8989442"

    # ARPC Method 2 using Session Key
    csu = bytes.fromhex("00000000")
    arpc = ac.generate_arpc_2(sk_ac, arqc, csu)
    assert arpc.hex().upper() == "C1C41F3A"


def test_derive_icc_mk_b_pan18() -> None:
    """
    Verify ICC MK derivation method B using 18 digit PAN.

    Master Key Derivation = Option B
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key Derivation
    ARPC Method = 2
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = "123456789012345679"
    psn = "00"
    icc_mk = kd.derive_icc_mk_b(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "C2F3"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "7C35"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "DC95BCE3EBBE0296"

    # ARPC Method 2 using Session Key
    csu = bytes.fromhex("00000000")
    arpc = ac.generate_arpc_2(sk_ac, arqc, csu)
    assert arpc.hex().upper() == "ECCA0C4B"


def test_derive_icc_mk_b_sha_pad() -> None:
    """
    Verify ICC MK derivation method B where the algorithm
    is forced to convert sha digest letters into numbers.

    Master Key Derivation = Option B
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key Derivation
    ARPC Method = 2

    Note: in this test sha1 does not produce 16 digits.
    Use decimalisation table to convert hexchars to digits.
        e -> 4
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = "000000000000000005"
    psn = "23"
    icc_mk = kd.derive_icc_mk_b(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "DD73"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("001C000000000000")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "04F8"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex(
        "00000000400000000000000001248000048000012"
        "41911050152BF45851800001C06011203A0B800"
    )
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "8CAD6F2489C640B1"

    # ARPC Method 2 using Session Key
    arqc = bytes.fromhex("8CAD6F2489C640B1")
    csu = bytes.fromhex("00000000")
    prop_auth_data = bytes.fromhex("12345678")
    arpc = ac.generate_arpc_2(sk_ac, arqc, csu, prop_auth_data)
    assert arpc.hex().upper() == "E39F1876"


def test_derive_visa_sm_sk() -> None:
    """
    Verify visa session key derivation for secure messaging.
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "7B83"

    # Derive ICC master key
    pan = "1234567890123456"
    icc_mk = kd.derive_icc_mk_b(iss_mk, pan)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "F010"

    # Verify AC session key
    atc = bytes.fromhex("001C")
    arqc = bytes.fromhex("29CCA15AE665FA2E")
    sk_sm = kd.derive_visa_sm_sk(icc_mk, atc)
    assert tools.key_check_digits(sk_sm, 2).hex().upper() == "DB10"

    # Command MAC generation using Session Key
    command_header = bytes.fromhex("8418000008")
    mac = sm.generate_command_mac(sk_sm, command_header + atc + arqc)

    assert mac.hex().upper() == "DB56BA60087CEFD3"


# fmt: off
@pytest.mark.parametrize(
    ["atc", "height", "branch", "iv", "sk"],
    [
        # Small ATC
        ("0000",  8, 4, "00000000000000000000000000000000", "80BF3145AECB948A5201DAB9EF469875"),
        ("0000",  8, 4, "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0", "DC31BC40B3AB8F73F2E3DA5EBF9DE59B"),
        ("0000", 16, 2, "00000000000000000000000000000000", "86AD9732D5A192A749ADCE31919DAE8A"),
        ("0000", 16, 2, "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0", "7C57A15261202A101C6DA29B16672A3E"),
        # Medium ATC
        ("00FF",  8, 4, "00000000000000000000000000000000", "981F9D208AE6132CBC8A7C97F42A5445"),
        ("00FF",  8, 4, "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0", "D579C8A4927589017FA1739B2C853BAD"),
        ("00FF", 16, 2, "00000000000000000000000000000000", "1F54F492EF104580B0F4B0F8910D0438"),
        ("00FF", 16, 2, "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0", "2086F81AAB731FF8CED9BF6DA7191CA2"),
        # Large ATC
        ("FFFF",  8, 4, "00000000000000000000000000000000", "D93D7A6B70F867615D4AAB79BF235B62"),
        ("FFFF",  8, 4, "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0", "A10EA78F2F1ACE203B3B402F6EE6CB29"),
        ("FFFF", 16, 2, "00000000000000000000000000000000", "F83E499EF786C20BC41310A176E3F84F"),
        ("FFFF", 16, 2, "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0", "73E3B0A1406E5E4908D5804C4970E520"),
    ],
)
# fmt: on
def test_derive_emv2000_tree_sk(
    atc: str,
    height: int,
    branch: int,
    iv: str,
    sk: str,
) -> None:
    assert bytes.fromhex(sk) == kd.derive_emv2000_tree_sk(
        bytes.fromhex("0123456789ABCDEF0123456789ABCDEF"),
        bytes.fromhex(atc),
        height,
        branch,
        bytes.fromhex(iv),
    )
