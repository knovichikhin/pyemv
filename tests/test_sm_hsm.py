from typing import Union

import pytest
from pyemv import kd, sm, tools


def test_generate_command_mac() -> None:
    """
    Test generation of script command data MAC

    Master Key Derivation = Option A
    SMI using Common Session Key Derivation (EMV SU-46)
    MAC generation script command is padded with 0x80
    """
    # Verify issuer master key check digits
    iss_mk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk_smi, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = "1234567890123456"
    psn = "01"
    icc_mk_smi = kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
    assert tools.key_check_digits(icc_mk_smi, 2).hex().upper() == "0239"

    # Verify SMI session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("ABCDEF1234567890")
    sk_smi = kd.derive_common_sk(icc_mk_smi, r)
    assert tools.key_check_digits(sk_smi, 2).hex().upper() == "F088"

    # Script MAC generated using Session Key
    script_command = bytes.fromhex("8424000008")
    mac = sm.generate_command_mac(sk_smi, script_command)
    assert mac.hex().upper() == "CF323F09A0F6AB9E"


@pytest.mark.parametrize(
    "pin",
    [
        b"9999",
        "9999",
    ],
)
def test_mastercard_pin_change(pin: Union[bytes, str]) -> None:
    """
    Test generation of offline PIN script with ISO format 2 PIN block

    Master Key Derivation = Option A
    SMI/SMC using Common Session Key Derivation (EMV SU-46)
    PIN encipherment with optional padding when block is not
    multiple of 8. However, no padding takes place because PIN
    block is 8 bytes long.
    """
    # Verify issuer master key check digits
    iss_mk_smc = bytes.fromhex("11111111111111112222222222222222")
    assert tools.key_check_digits(iss_mk_smc, 3).hex().upper() == "D2B91C"
    iss_mk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk_smi, 3).hex().upper() == "08D7B4"

    # Derive ICC master keys
    pan = "1234567890123456"
    psn = "01"
    icc_mk_smc = kd.derive_icc_mk_a(iss_mk_smc, pan, psn)
    assert tools.key_check_digits(icc_mk_smc, 3).hex().upper() == "6B0F76"
    icc_mk_smi = kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
    assert tools.key_check_digits(icc_mk_smi, 3).hex().upper() == "02396B"

    # Verify SMC/SMI session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("ABCDEF1234567890")
    sk_smc = kd.derive_common_sk(icc_mk_smc, r)
    assert tools.key_check_digits(sk_smc, 3).hex().upper() == "D694B8"
    sk_smi = kd.derive_common_sk(icc_mk_smi, r)
    assert tools.key_check_digits(sk_smi, 3).hex().upper() == "F088F8"

    # Encrypt new PIN
    pin_block = sm.format_iso9564_2_pin_block(pin)
    assert pin_block.hex().upper() == "249999FFFFFFFFFF"
    command_data = sm.encrypt_command_data(
        sk_smc, pin_block, sm.EncryptionType.MASTERCARD
    )
    assert command_data.hex().upper() == "28367E05DE3381C2"

    # Script MAC generated using Session Key
    command_header = bytes.fromhex("8424000210")
    mac = sm.generate_command_mac(sk_smi, command_header + command_data)
    assert mac.hex().upper() == "8C4D10091A093B5B"


@pytest.mark.parametrize(
    "pin",
    [
        b"999999999999",
        "999999999999",
    ],
)
def test_mastercard_pin_change_12(pin: Union[bytes, str]) -> None:
    """
    Test generation of offline PIN script with ISO format 2 PIN block
    PIN is 12 digits long.

    Master Key Derivation = Option A
    SMI/SMC using Common Session Key Derivation (EMV SU-46)
    PIN encipherment with optional padding when block is not
    multiple of 8. However, no padding takes place because PIN
    block is 8 bytes long.
    """
    # Verify issuer master key check digits
    iss_mk_smc = bytes.fromhex("11111111111111112222222222222222")
    assert tools.key_check_digits(iss_mk_smc, 3).hex().upper() == "D2B91C"
    iss_mk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk_smi, 3).hex().upper() == "08D7B4"

    # Derive ICC master keys
    pan = "1234567890123456"
    psn = "01"
    icc_mk_smc = kd.derive_icc_mk_a(iss_mk_smc, pan, psn)
    assert tools.key_check_digits(icc_mk_smc, 3).hex().upper() == "6B0F76"
    icc_mk_smi = kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
    assert tools.key_check_digits(icc_mk_smi, 3).hex().upper() == "02396B"

    # Verify SMC/SMI session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("ABCDEF1234567890")
    sk_smc = kd.derive_common_sk(icc_mk_smc, r)
    assert tools.key_check_digits(sk_smc, 3).hex().upper() == "D694B8"
    sk_smi = kd.derive_common_sk(icc_mk_smi, r)
    assert tools.key_check_digits(sk_smi, 3).hex().upper() == "F088F8"

    # Encrypt new PIN
    pin_block = sm.format_iso9564_2_pin_block(pin)
    assert pin_block.hex().upper() == "2C999999999999FF"
    command_data = sm.encrypt_command_data(
        sk_smc, pin_block, sm.EncryptionType.MASTERCARD
    )
    assert command_data.hex().upper() == "99AD3AF9EB3ECF0C"

    # Script MAC generated using Session Key
    command_header = bytes.fromhex("8424000210")
    mac = sm.generate_command_mac(sk_smi, command_header + command_data)
    assert mac.hex().upper() == "1471D88C6393BE21"


@pytest.mark.parametrize(
    "pin",
    [
        b"9999",
        "9999",
    ],
)
def test_vis_pin_change(pin: Union[bytes, str]) -> None:
    """
    Test generation of offline PIN script with VIS PIN block

    Master Key Derivation = Option A
    SMI/SMC using Visa Session Key Derivation
    PIN encipherment with mandatory Visa padding
    """
    # Verify issuer master key check digits
    iss_mk_ac = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
    assert tools.key_check_digits(iss_mk_ac, 3).hex().upper() == "7B8358"
    iss_mk_smc = bytes.fromhex("11111111111111112222222222222222")
    assert tools.key_check_digits(iss_mk_smc, 3).hex().upper() == "D2B91C"
    iss_mk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk_smi, 3).hex().upper() == "08D7B4"

    # Derive ICC master keys
    pan = "1234567890123456"
    psn = "01"
    icc_mk_ac = kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
    assert tools.key_check_digits(icc_mk_ac, 3).hex().upper() == "C5CACD"
    icc_mk_smc = kd.derive_icc_mk_a(iss_mk_smc, pan, psn)
    assert tools.key_check_digits(icc_mk_smc, 3).hex().upper() == "6B0F76"
    icc_mk_smi = kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
    assert tools.key_check_digits(icc_mk_smi, 3).hex().upper() == "02396B"

    # Verify SMC/SMI session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("FFFF")
    sk_smc = kd.derive_visa_sm_sk(icc_mk_smc, r)
    assert tools.key_check_digits(sk_smc, 3).hex().upper() == "BD7C46"
    sk_smi = kd.derive_visa_sm_sk(icc_mk_smi, r)
    assert tools.key_check_digits(sk_smi, 3).hex().upper() == "A41D47"

    # Encrypt new PIN
    pin_block = sm.format_vis_pin_block(icc_mk_ac, pin)
    assert pin_block.hex().upper() == "049999FFC4B001F1"
    command_data = sm.encrypt_command_data(sk_smc, pin_block, sm.EncryptionType.VISA)
    assert command_data.hex().upper() == "D421231A6FD2F0FAEE671384F0D3A7B9"

    # Script MAC generated using Session Key
    command_header = bytes.fromhex("8424000210")
    mac = sm.generate_command_mac(sk_smi, command_header + command_data)
    assert mac.hex().upper() == "F67E37E67B06AB99"


@pytest.mark.parametrize(
    ["pin", "current_pin"],
    [
        (b"9999", b"8888"),
        (b"9999", "8888"),
        ("9999", b"8888"),
        ("9999", "8888"),
    ],
)
def test_vis_change_change_current_pin(
    pin: Union[bytes, str], current_pin: Union[bytes, str]
) -> None:
    """
    Test generation of offline PIN script with VIS PIN block with current PIN

    Master Key Derivation = Option A
    SMI/SMC using Visa Session Key Derivation
    PIN encipherment with mandatory Visa padding
    """
    # Verify issuer master key check digits
    iss_mk_ac = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
    assert tools.key_check_digits(iss_mk_ac, 3).hex().upper() == "7B8358"
    iss_mk_smc = bytes.fromhex("11111111111111112222222222222222")
    assert tools.key_check_digits(iss_mk_smc, 3).hex().upper() == "D2B91C"
    iss_mk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk_smi, 3).hex().upper() == "08D7B4"

    # Derive ICC master keys
    pan = "1234567890123456"
    psn = "01"
    icc_mk_ac = kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
    assert tools.key_check_digits(icc_mk_ac, 3).hex().upper() == "C5CACD"
    icc_mk_smc = kd.derive_icc_mk_a(iss_mk_smc, pan, psn)
    assert tools.key_check_digits(icc_mk_smc, 3).hex().upper() == "6B0F76"
    icc_mk_smi = kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
    assert tools.key_check_digits(icc_mk_smi, 3).hex().upper() == "02396B"

    # Verify SMC/SMI session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("FFFF")
    sk_smc = kd.derive_visa_sm_sk(icc_mk_smc, r)
    assert tools.key_check_digits(sk_smc, 3).hex().upper() == "BD7C46"
    sk_smi = kd.derive_visa_sm_sk(icc_mk_smi, r)
    assert tools.key_check_digits(sk_smi, 3).hex().upper() == "A41D47"

    # Encrypt new PIN
    pin_block = sm.format_vis_pin_block(icc_mk_ac, pin, current_pin)
    assert pin_block.hex().upper() == "8C1199FFC4B001F1"
    command_data = sm.encrypt_command_data(sk_smc, pin_block, sm.EncryptionType.VISA)
    assert command_data.hex().upper() == "C29371CC36BA70C1EE671384F0D3A7B9"

    # Script MAC generated using Session Key
    command_header = bytes.fromhex("8424000110")
    mac = sm.generate_command_mac(sk_smi, command_header + command_data)
    assert mac.hex().upper() == "6AB3AD15D8B0621A"


@pytest.mark.parametrize(
    ["pin", "current_pin"],
    [
        (b"999999999999", b"888888888888"),
        (b"999999999999", "888888888888"),
        ("999999999999", b"888888888888"),
        ("999999999999", "888888888888"),
    ],
)
def test_vis_change_current_pin_12(
    pin: Union[bytes, str], current_pin: Union[bytes, str]
) -> None:
    """
    Test generation of offline PIN script with VIS PIN block with current PIN
    Both PINs are 12 digits long.

    Master Key Derivation = Option A
    SMI/SMC using Visa Session Key Derivation
    PIN encipherment with mandatory Visa padding
    """
    # Verify issuer master key check digits
    iss_mk_ac = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
    assert tools.key_check_digits(iss_mk_ac, 3).hex().upper() == "7B8358"
    iss_mk_smc = bytes.fromhex("11111111111111112222222222222222")
    assert tools.key_check_digits(iss_mk_smc, 3).hex().upper() == "D2B91C"
    iss_mk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk_smi, 3).hex().upper() == "08D7B4"

    # Derive ICC master keys
    pan = "1234567890123456"
    psn = "01"
    icc_mk_ac = kd.derive_icc_mk_a(iss_mk_ac, pan, psn)
    assert tools.key_check_digits(icc_mk_ac, 3).hex().upper() == "C5CACD"
    icc_mk_smc = kd.derive_icc_mk_a(iss_mk_smc, pan, psn)
    assert tools.key_check_digits(icc_mk_smc, 3).hex().upper() == "6B0F76"
    icc_mk_smi = kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
    assert tools.key_check_digits(icc_mk_smi, 3).hex().upper() == "02396B"

    # Verify SMC/SMI session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("FFFF")
    sk_smc = kd.derive_visa_sm_sk(icc_mk_smc, r)
    assert tools.key_check_digits(sk_smc, 3).hex().upper() == "BD7C46"
    sk_smi = kd.derive_visa_sm_sk(icc_mk_smi, r)
    assert tools.key_check_digits(sk_smi, 3).hex().upper() == "A41D47"

    # Encrypt new PIN
    pin_block = sm.format_vis_pin_block(icc_mk_ac, pin, current_pin)
    assert pin_block.hex().upper() == "841111112A5E67F1"
    command_data = sm.encrypt_command_data(sk_smc, pin_block, sm.EncryptionType.VISA)
    assert command_data.hex().upper() == "622066A74F1E974AEE671384F0D3A7B9"

    # Script MAC generated using Session Key
    command_header = bytes.fromhex("8424000110")
    mac = sm.generate_command_mac(sk_smi, command_header + command_data)
    assert mac.hex().upper() == "829AC5DE4B88074D"


@pytest.mark.parametrize(
    "pin",
    [
        b"9999",
        "9999",
    ],
)
def test_ccd_pin_change(pin: Union[bytes, str]) -> None:
    """
    Test generation of offline PIN script with ISO format 2 PIN block'
    Common Core Definition. Mandatory padding.

    Master Key Derivation = Option A
    SMI/SMC using Common Session Key Derivation (EMV SU-46)
    PIN encipherment with optional padding when block is not
    multiple of 8. However, no padding takes place because PIN
    block is 8 bytes long.
    """
    # Verify issuer master key check digits
    iss_mk_smc = bytes.fromhex("11111111111111112222222222222222")
    assert tools.key_check_digits(iss_mk_smc, 3).hex().upper() == "D2B91C"
    iss_mk_smi = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk_smi, 3).hex().upper() == "08D7B4"

    # Derive ICC master keys
    pan = "1234567890123456"
    psn = "01"
    icc_mk_smc = kd.derive_icc_mk_a(iss_mk_smc, pan, psn)
    assert tools.key_check_digits(icc_mk_smc, 3).hex().upper() == "6B0F76"
    icc_mk_smi = kd.derive_icc_mk_a(iss_mk_smi, pan, psn)
    assert tools.key_check_digits(icc_mk_smi, 3).hex().upper() == "02396B"

    # Verify SMC/SMI session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("ABCDEF1234567890")
    sk_smc = kd.derive_common_sk(icc_mk_smc, r)
    assert tools.key_check_digits(sk_smc, 3).hex().upper() == "D694B8"
    sk_smi = kd.derive_common_sk(icc_mk_smi, r)
    assert tools.key_check_digits(sk_smi, 3).hex().upper() == "F088F8"

    # Encrypt new PIN
    pin_block = sm.format_iso9564_2_pin_block(pin)
    assert pin_block.hex().upper() == "249999FFFFFFFFFF"
    command_data = sm.encrypt_command_data(sk_smc, pin_block, sm.EncryptionType.EMV)
    assert command_data.hex().upper() == "28367E05DE3381C29D30A6055A8DEB86"

    # Script MAC generated using Session Key
    command_header = bytes.fromhex("8424000210")
    mac = sm.generate_command_mac(sk_smi, command_header + command_data)
    assert mac.hex().upper() == "69DA1EE208823022"
