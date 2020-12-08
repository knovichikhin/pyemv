from typing import Union

import pytest
from pyemv import cvn
from pyemv.tools import key_check_digits


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"1234567890123456", b"00"),
        (b"1234567890123456", "00"),
        ("1234567890123456", b"00"),
        ("1234567890123456", "00"),
    ],
)
def test_visa_cvn10(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """Visa CVN 10"""
    cvn10 = cvn.VisaCVN10(
        iss_mk_ac=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
        iss_mk_smi=bytes.fromhex("FEDCBA98765432100123456789ABCDEF"),
        iss_mk_smc=bytes.fromhex("89ABCDEF0123456776543210FEDCBA98"),
        pan=pan,
        psn=psn,
    )

    # Check ICC Master Keys
    assert key_check_digits(cvn10.icc_mk_ac).hex().upper() == "BAB0"
    assert key_check_digits(cvn10.icc_mk_smi).hex().upper() == "F010"
    assert key_check_digits(cvn10.icc_mk_smc).hex().upper() == "B154"

    # ARQC and its session key
    atc = bytes.fromhex("001C")
    arqc = cvn10.generate_ac(
        tag_9f02=bytes.fromhex("000000004000"),
        tag_9f03=bytes.fromhex("000000000000"),
        tag_9f1a=bytes.fromhex("0124"),
        tag_95=bytes.fromhex("8000048000"),
        tag_5f2a=bytes.fromhex("0124"),
        tag_9a=bytes.fromhex("191105"),
        tag_9c=bytes.fromhex("01"),
        tag_9f37=bytes.fromhex("52BF4585"),
        tag_82=bytes.fromhex("1800"),
        tag_9f36=atc,
        cvr=bytes.fromhex("03A06010"),
    )
    assert arqc.hex().upper() == "29CCA15AE665FA2E"
    assert key_check_digits(cvn10._derive_sk_ac_none()).hex().upper() == "BAB0"

    # ARPC and its session key
    arpc = cvn10.generate_arpc(tag_9f26=arqc, arpc_rc=bytes.fromhex("3030"))
    assert arpc.hex().upper() == "28993816AFAE4AEB"
    assert key_check_digits(cvn10._derive_sk_ac_none()).hex().upper() == "BAB0"

    # MAC application unblock command and its session key
    mac = cvn10.generate_command_mac(
        bytes.fromhex("8418000008"),
        tag_9f26=arqc,
        tag_9f36=atc,
    )
    assert mac.hex().upper() == "DB56BA60087CEFD3"
    assert (
        key_check_digits(cvn10._derive_sk_sm_visa(cvn10.icc_mk_smi, atc)).hex().upper()
        == "DB10"
    )

    # PIN change without current PIN and its session keys
    pin_command = cvn10.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc
    )
    assert (
        pin_command.hex().upper()
        == "8424000218BB221AF527377A2811D2B6EBC396A9391A965A5CB2CE62DA"
    )
    assert (
        key_check_digits(cvn10._derive_sk_sm_visa(cvn10.icc_mk_smc, atc)).hex().upper()
        == "6D04"
    )
    assert (
        key_check_digits(cvn10._derive_sk_sm_visa(cvn10.icc_mk_smi, atc)).hex().upper()
        == "DB10"
    )

    # PIN change with current PIN and its session keys
    pin_command = cvn10.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc, current_pin=b"8888"
    )
    assert (
        pin_command.hex().upper()
        == "84240001182EE025E554BCD87E11D2B6EBC396A939C4A8393B57DD2F3F"
    )
    assert (
        key_check_digits(cvn10._derive_sk_sm_visa(cvn10.icc_mk_smc, atc)).hex().upper()
        == "6D04"
    )
    assert (
        key_check_digits(cvn10._derive_sk_sm_visa(cvn10.icc_mk_smi, atc)).hex().upper()
        == "DB10"
    )


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"1234567890123456", b"00"),
        (b"1234567890123456", "00"),
        ("1234567890123456", b"00"),
        ("1234567890123456", "00"),
    ],
)
def test_visa_cvn18(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """Visa CVN 18"""
    cvn18 = cvn.VisaCVN18(
        iss_mk_ac=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
        iss_mk_smi=bytes.fromhex("FEDCBA98765432100123456789ABCDEF"),
        iss_mk_smc=bytes.fromhex("89ABCDEF0123456776543210FEDCBA98"),
        pan=pan,
        psn=psn,
    )

    # Check ICC Master Keys
    assert key_check_digits(cvn18.icc_mk_ac).hex().upper() == "BAB0"
    assert key_check_digits(cvn18.icc_mk_smi).hex().upper() == "F010"
    assert key_check_digits(cvn18.icc_mk_smc).hex().upper() == "B154"

    # ARQC and its session key
    atc = bytes.fromhex("001C")
    arqc = cvn18.generate_ac(
        tag_9f02=bytes.fromhex("000000004000"),
        tag_9f03=bytes.fromhex("000000000000"),
        tag_9f1a=bytes.fromhex("0124"),
        tag_95=bytes.fromhex("8000048000"),
        tag_5f2a=bytes.fromhex("0124"),
        tag_9a=bytes.fromhex("191105"),
        tag_9c=bytes.fromhex("01"),
        tag_9f37=bytes.fromhex("52BF4585"),
        tag_82=bytes.fromhex("1800"),
        tag_9f36=atc,
        tag_9f10=bytes.fromhex("06011203A0B800"),
    )
    assert arqc.hex().upper() == "7A788EA6B8A3E733"
    assert key_check_digits(cvn18._derive_sk_ac_common(atc)).hex().upper() == "22C8"

    # ARPC and its session key
    arpc = cvn18.generate_arpc(
        tag_9f26=arqc, tag_9f36=atc, csu=bytes.fromhex("00000000")
    )
    assert arpc.hex().upper() == "9AF514C1"
    assert key_check_digits(cvn18._derive_sk_ac_common(atc)).hex().upper() == "22C8"

    # MAC application unblock command and its session key
    mac = cvn18.generate_command_mac(
        bytes.fromhex("8418000008"),
        tag_9f26=arqc,
        tag_9f36=atc,
    )
    assert mac.hex().upper() == "04EDE90BC24CC35E"
    assert (
        key_check_digits(cvn18._derive_sk_sm_visa(cvn18.icc_mk_smi, atc)).hex().upper()
        == "DB10"
    )

    # PIN change without current PIN and its session keys
    pin_command = cvn18.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc
    )
    assert (
        pin_command.hex().upper()
        == "8424000218BB221AF527377A2811D2B6EBC396A9391A22B480EF312F40"
    )
    assert (
        key_check_digits(cvn18._derive_sk_sm_visa(cvn18.icc_mk_smc, atc)).hex().upper()
        == "6D04"
    )
    assert (
        key_check_digits(cvn18._derive_sk_sm_visa(cvn18.icc_mk_smi, atc)).hex().upper()
        == "DB10"
    )

    # PIN change with current PIN and its session keys
    pin_command = cvn18.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc, current_pin=b"8888"
    )
    assert (
        pin_command.hex().upper()
        == "84240001182EE025E554BCD87E11D2B6EBC396A9390FB94A4E4EC10F41"
    )
    assert (
        key_check_digits(cvn18._derive_sk_sm_visa(cvn18.icc_mk_smc, atc)).hex().upper()
        == "6D04"
    )
    assert (
        key_check_digits(cvn18._derive_sk_sm_visa(cvn18.icc_mk_smi, atc)).hex().upper()
        == "DB10"
    )


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"1234567890123456", b"00"),
        (b"1234567890123456", "00"),
        ("1234567890123456", b"00"),
        ("1234567890123456", "00"),
    ],
)
def test_interac_cvn133(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """Interac CVN 133"""
    cvn133 = cvn.InteracCVN133(
        iss_mk_ac=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
        iss_mk_smi=bytes.fromhex("FEDCBA98765432100123456789ABCDEF"),
        iss_mk_smc=bytes.fromhex("89ABCDEF0123456776543210FEDCBA98"),
        pan=pan,
        psn=psn,
    )

    # Derive ICC Master Keys
    assert key_check_digits(cvn133.icc_mk_ac).hex().upper() == "BAB0"
    assert key_check_digits(cvn133.icc_mk_smi).hex().upper() == "F010"
    assert key_check_digits(cvn133.icc_mk_smc).hex().upper() == "B154"

    # ARQC and its session key
    atc = bytes.fromhex("001C")
    un = bytes.fromhex("ABCDEF12")
    arqc = cvn133.generate_ac(
        tag_9f02=bytes.fromhex("000000009999"),
        tag_9f03=bytes.fromhex("000000000000"),
        tag_9f1a=bytes.fromhex("0124"),
        tag_95=bytes.fromhex("8000000000"),
        tag_5f2a=bytes.fromhex("0124"),
        tag_9a=bytes.fromhex("209906"),
        tag_9c=bytes.fromhex("00"),
        tag_9f37=un,
        tag_82=bytes.fromhex("1800"),
        tag_9f36=atc,
        tag_9f10=bytes.fromhex("1501850440B100000000B00000000000000000000000"),
    )
    assert arqc.hex().upper() == "18932FECA2D84326"
    assert (
        key_check_digits(cvn133._derive_sk_ac_mastercard(atc, un)).hex().upper()
        == "2FD5"
    )

    # ARPC and its session key
    arpc = cvn133.generate_arpc(
        tag_9f26=arqc, tag_9f37=un, tag_9f36=atc, arpc_rc=bytes.fromhex("0000")
    )
    assert arpc.hex().upper() == "4DF171A49396C363"
    assert (
        key_check_digits(cvn133._derive_sk_ac_mastercard(atc, un)).hex().upper()
        == "2FD5"
    )

    # MAC PIN unblock command and its session key
    mac = cvn133.generate_command_mac(bytes.fromhex("8424000008"), tag_9f26=arqc)
    assert mac.hex().upper() == "B574ABB0A485A330"
    assert (
        key_check_digits(cvn133._derive_sk_sm_common(cvn133.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "08DF"
    )

    # PIN change without current PIN and its session keys
    pin_command = cvn133.generate_pin_change_command(b"9999", tag_9f26=arqc)
    assert pin_command.hex().upper() == "8424000210382F36D5920D23915CC7573F770298C9"
    assert (
        key_check_digits(cvn133._derive_sk_sm_common(cvn133.icc_mk_smc, arqc))
        .hex()
        .upper()
        == "748D"
    )
    assert (
        key_check_digits(cvn133._derive_sk_sm_common(cvn133.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "08DF"
    )


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"1234567890123456", b"00"),
        (b"1234567890123456", "00"),
        ("1234567890123456", b"00"),
        ("1234567890123456", "00"),
    ],
)
def test_mastercard_cvn16(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """MasterCard CVN 16"""
    cvn16 = cvn.MasterCardCVN16(
        iss_mk_ac=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
        iss_mk_smi=bytes.fromhex("FEDCBA98765432100123456789ABCDEF"),
        iss_mk_smc=bytes.fromhex("89ABCDEF0123456776543210FEDCBA98"),
        pan=pan,
        psn=psn,
    )

    # Derive ICC Master Keys
    assert key_check_digits(cvn16.icc_mk_ac).hex().upper() == "BAB0"
    assert key_check_digits(cvn16.icc_mk_smi).hex().upper() == "F010"
    assert key_check_digits(cvn16.icc_mk_smc).hex().upper() == "B154"

    # ARQC and its session key
    atc = bytes.fromhex("001C")
    un = bytes.fromhex("ABCDEF12")
    arqc = cvn16.generate_ac(
        tag_9f02=bytes.fromhex("000000009999"),
        tag_9f03=bytes.fromhex("000000000000"),
        tag_9f1a=bytes.fromhex("0124"),
        tag_95=bytes.fromhex("8000000000"),
        tag_5f2a=bytes.fromhex("0124"),
        tag_9a=bytes.fromhex("209906"),
        tag_9c=bytes.fromhex("00"),
        tag_9f37=un,
        tag_82=bytes.fromhex("1800"),
        tag_9f36=atc,
        cvr=bytes.fromhex("A00003220000"),  # 9F10: 0110A00003220000000000000000000000FF
    )
    assert arqc.hex().upper() == "24CCF3DEE3158C70"
    assert (
        key_check_digits(cvn16._derive_sk_ac_mastercard(atc, un)).hex().upper()
        == "2FD5"
    )

    # ARPC and its session key (no session key, uses ICC MK AC)
    arpc = cvn16.generate_arpc(tag_9f26=arqc, arpc_rc=bytes.fromhex("0010"))
    assert arpc.hex().upper() == "73F6BBF389A6586C"
    assert key_check_digits(cvn16._derive_sk_arpc_none()).hex().upper() == "BAB0"

    # MAC PIN unblock command and its session key
    # 72169F180400000000860D8424000008ED0AB162BAB1DE61
    mac = cvn16.generate_command_mac(
        bytes.fromhex("8424000008"), tag_9f26=arqc, tag_9f36=atc
    )
    assert mac.hex().upper() == "ED0AB162BAB1DE61"
    assert (
        key_check_digits(cvn16._derive_sk_sm_common(cvn16.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "FFA0"
    )

    # PIN change without current PIN and its session keys
    # 721E9F1804000000008615842400021000859B8FE53F316DED0AB162BAB1DE61
    pin_command = cvn16.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc
    )
    assert pin_command.hex().upper() == "842400021000859B8FE53F316DEB4B64C36BF88E39"
    assert (
        key_check_digits(cvn16._derive_sk_sm_common(cvn16.icc_mk_smc, arqc))
        .hex()
        .upper()
        == "0BCA"
    )
    assert (
        key_check_digits(cvn16._derive_sk_sm_common(cvn16.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "FFA0"
    )


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"1234567890123456", b"00"),
        (b"1234567890123456", "00"),
        ("1234567890123456", b"00"),
        ("1234567890123456", "00"),
    ],
)
def test_mastercard_cvn17(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """MasterCard CVN 17"""
    cvn17 = cvn.MasterCardCVN17(
        iss_mk_ac=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
        iss_mk_smi=bytes.fromhex("FEDCBA98765432100123456789ABCDEF"),
        iss_mk_smc=bytes.fromhex("89ABCDEF0123456776543210FEDCBA98"),
        pan=pan,
        psn=psn,
    )

    # Derive ICC Master Keys
    assert key_check_digits(cvn17.icc_mk_ac).hex().upper() == "BAB0"
    assert key_check_digits(cvn17.icc_mk_smi).hex().upper() == "F010"
    assert key_check_digits(cvn17.icc_mk_smc).hex().upper() == "B154"

    # ARQC and its session key
    atc = bytes.fromhex("001C")
    un = bytes.fromhex("ABCDEF12")
    arqc = cvn17.generate_ac(
        tag_9f02=bytes.fromhex("000000009999"),
        tag_9f03=bytes.fromhex("000000000000"),
        tag_9f1a=bytes.fromhex("0124"),
        tag_95=bytes.fromhex("8000000000"),
        tag_5f2a=bytes.fromhex("0124"),
        tag_9a=bytes.fromhex("209906"),
        tag_9c=bytes.fromhex("00"),
        tag_9f37=un,
        tag_82=bytes.fromhex("1800"),
        tag_9f36=atc,
        cvr=bytes.fromhex("A00003220000"),  # 9F10: 0111A00003220000000000000000000322FF
        counters=bytes.fromhex("00000000000322FF"),
    )

    assert arqc.hex().upper() == "EAE8A620A75648D8"
    assert (
        key_check_digits(cvn17._derive_sk_ac_mastercard(atc, un)).hex().upper()
        == "2FD5"
    )

    # ARPC and its session key (no session key, uses ICC MK AC)
    arpc = cvn17.generate_arpc(tag_9f26=arqc, arpc_rc=bytes.fromhex("0010"))
    assert arpc.hex().upper() == "29CF11FBDB9CA650"
    assert key_check_digits(cvn17._derive_sk_arpc_none()).hex().upper() == "BAB0"

    # MAC PIN unblock command and its session key
    # 72169F180400000000860D84240000084D1858456CD0F22A
    mac = cvn17.generate_command_mac(
        bytes.fromhex("8424000008"), tag_9f26=arqc, tag_9f36=atc
    )
    assert mac.hex().upper() == "4D1858456CD0F22A"
    assert (
        key_check_digits(cvn17._derive_sk_sm_common(cvn17.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "6CAF"
    )

    # PIN change without current PIN and its session keys
    # 721E9F180400000000861584240002108661C474E4940A4378390C64CB96756E
    pin_command = cvn17.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc
    )
    assert pin_command.hex().upper() == "84240002108661C474E4940A4378390C64CB96756E"
    assert (
        key_check_digits(cvn17._derive_sk_sm_common(cvn17.icc_mk_smc, arqc))
        .hex()
        .upper()
        == "3D99"
    )
    assert (
        key_check_digits(cvn17._derive_sk_sm_common(cvn17.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "6CAF"
    )


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"1234567890123456", b"00"),
        (b"1234567890123456", "00"),
        ("1234567890123456", b"00"),
        ("1234567890123456", "00"),
    ],
)
def test_mastercard_cvn20(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """MasterCard CVN 20"""
    cvn20 = cvn.MasterCardCVN20(
        iss_mk_ac=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
        iss_mk_smi=bytes.fromhex("FEDCBA98765432100123456789ABCDEF"),
        iss_mk_smc=bytes.fromhex("89ABCDEF0123456776543210FEDCBA98"),
        pan=pan,
        psn=psn,
    )

    # Derive ICC Master Keys
    assert key_check_digits(cvn20.icc_mk_ac).hex().upper() == "BAB0"
    assert key_check_digits(cvn20.icc_mk_smi).hex().upper() == "F010"
    assert key_check_digits(cvn20.icc_mk_smc).hex().upper() == "B154"

    # ARQC and its session key
    atc = bytes.fromhex("001C")
    un = bytes.fromhex("ABCDEF12")
    arqc = cvn20.generate_ac(
        tag_9f02=bytes.fromhex("000000009999"),
        tag_9f03=bytes.fromhex("000000000000"),
        tag_9f1a=bytes.fromhex("0124"),
        tag_95=bytes.fromhex("8000000000"),
        tag_5f2a=bytes.fromhex("0124"),
        tag_9a=bytes.fromhex("209906"),
        tag_9c=bytes.fromhex("00"),
        tag_9f37=un,
        tag_82=bytes.fromhex("1800"),
        tag_9f36=atc,
        cvr=bytes.fromhex("A00003220000"),  # 9F10: 0110A00003220000000000000000000000FF
    )
    assert arqc.hex().upper() == "CD29615D6452E70E"
    assert key_check_digits(cvn20._derive_sk_ac_common(atc)).hex().upper() == "22C8"

    # ARPC and its session key
    arpc = cvn20.generate_arpc(
        tag_9f26=arqc, tag_9f36=atc, arpc_rc=bytes.fromhex("0010")
    )
    assert arpc.hex().upper() == "DFD0956606B68D64"
    assert key_check_digits(cvn20._derive_sk_ac_common(atc)).hex().upper() == "22C8"

    # MAC PIN unblock command and its session key
    # 72169F180400000000860D842400000801C0F0DFBF6AA230
    mac = cvn20.generate_command_mac(
        bytes.fromhex("8424000008"), tag_9f26=arqc, tag_9f36=atc
    )
    assert mac.hex().upper() == "01C0F0DFBF6AA230"
    assert (
        key_check_digits(cvn20._derive_sk_sm_common(cvn20.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "9240"
    )

    # PIN change without current PIN and its session keys
    # 721E9F1804000000008615842400021000859B8FE53F316DED0AB162BAB1DE61
    pin_command = cvn20.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc
    )
    assert pin_command.hex().upper() == "84240002107647E71F85AA6A35AE4B4E838666773D"
    assert (
        key_check_digits(cvn20._derive_sk_sm_common(cvn20.icc_mk_smc, arqc))
        .hex()
        .upper()
        == "B087"
    )
    assert (
        key_check_digits(cvn20._derive_sk_sm_common(cvn20.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "9240"
    )


@pytest.mark.parametrize(
    ["pan", "psn"],
    [
        (b"1234567890123456", b"00"),
        (b"1234567890123456", "00"),
        ("1234567890123456", b"00"),
        ("1234567890123456", "00"),
    ],
)
def test_mastercard_cvn21(pan: Union[bytes, str], psn: Union[bytes, str]) -> None:
    """MasterCard CVN 21"""
    cvn21 = cvn.MasterCardCVN21(
        iss_mk_ac=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
        iss_mk_smi=bytes.fromhex("FEDCBA98765432100123456789ABCDEF"),
        iss_mk_smc=bytes.fromhex("89ABCDEF0123456776543210FEDCBA98"),
        pan=pan,
        psn=psn,
    )

    # Derive ICC Master Keys
    assert key_check_digits(cvn21.icc_mk_ac).hex().upper() == "BAB0"
    assert key_check_digits(cvn21.icc_mk_smi).hex().upper() == "F010"
    assert key_check_digits(cvn21.icc_mk_smc).hex().upper() == "B154"

    # ARQC and its session key
    atc = bytes.fromhex("001C")
    un = bytes.fromhex("ABCDEF12")
    arqc = cvn21.generate_ac(
        tag_9f02=bytes.fromhex("000000009999"),
        tag_9f03=bytes.fromhex("000000000000"),
        tag_9f1a=bytes.fromhex("0124"),
        tag_95=bytes.fromhex("8000000000"),
        tag_5f2a=bytes.fromhex("0124"),
        tag_9a=bytes.fromhex("209906"),
        tag_9c=bytes.fromhex("00"),
        tag_9f37=un,
        tag_82=bytes.fromhex("1800"),
        tag_9f36=atc,
        cvr=bytes.fromhex("A00003220000"),  # 9F10: 0115A00003220000000000000000000322FF
        counters=bytes.fromhex("00000000000322FF"),
    )

    assert arqc.hex().upper() == "C30E54BE496CF5E5"
    assert key_check_digits(cvn21._derive_sk_ac_common(atc)).hex().upper() == "22C8"

    # ARPC and its session key
    arpc = cvn21.generate_arpc(
        tag_9f26=arqc, tag_9f36=atc, arpc_rc=bytes.fromhex("0010")
    )
    assert arpc.hex().upper() == "4F51F9CC63CE8B3C"
    assert key_check_digits(cvn21._derive_sk_ac_common(atc)).hex().upper() == "22C8"

    # MAC PIN unblock command and its session key
    # 72169F180400000000860D84240000085E89E990C51CEE94
    mac = cvn21.generate_command_mac(
        bytes.fromhex("8424000008"), tag_9f26=arqc, tag_9f36=atc
    )
    assert mac.hex().upper() == "5E89E990C51CEE94"
    assert (
        key_check_digits(cvn21._derive_sk_sm_common(cvn21.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "F4C4"
    )

    # PIN change without current PIN and its session keys
    # 721E9F18040000000086158424000210D9F5896BE8E283C682264E1D32DF1D51
    pin_command = cvn21.generate_pin_change_command(
        b"9999", tag_9f26=arqc, tag_9f36=atc
    )
    assert pin_command.hex().upper() == "8424000210D9F5896BE8E283C682264E1D32DF1D51"
    assert (
        key_check_digits(cvn21._derive_sk_sm_common(cvn21.icc_mk_smc, arqc))
        .hex()
        .upper()
        == "BB95"
    )
    assert (
        key_check_digits(cvn21._derive_sk_sm_common(cvn21.icc_mk_smi, arqc))
        .hex()
        .upper()
        == "F4C4"
    )
