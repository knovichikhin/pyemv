from pyemv import cvv, kd, tools


def test_generate_cvc3_track2() -> None:
    # Device ICC CVC3 key from ISS CVC3 key using method A
    # Issuer may choose to use method A or B.
    iss_cvc3 = bytes.fromhex("01234567899876543210012345678998")
    pan = b"5123456789012345"
    psn = b"00"
    icc_cvc3 = kd.derive_icc_mk_a(iss_cvc3, pan, psn)
    assert tools.key_check_digits(icc_cvc3).hex().upper() == "BB8F"

    # Compute CVC3 - track2
    # Track2 must be converted to binary data where, for example,
    # characters "D3" are represented as "\xD3"
    track2 = bytes.fromhex("5123456789012345D35121010000000000000F")
    atc = bytes.fromhex("005E")
    un = bytes.fromhex("00000899")
    cvc3 = cvv.generate_cvc3(icc_cvc3, track2, atc, un)
    assert cvc3[-3:] == "488"


def test_generate_cvc3_track1() -> None:
    # Device ICC CVC3 key from ISS CVC3 key using method A
    # Issuer may choose to use method A or B.
    iss_cvc3 = bytes.fromhex("01234567899876543210012345678998")
    pan = b"5123456789012345"
    psn = b"00"
    icc_cvc3 = kd.derive_icc_mk_a(iss_cvc3, pan, psn)
    assert tools.key_check_digits(icc_cvc3).hex().upper() == "BB8F"

    # Compute CVC3 - track1
    # Track1 must be converted to binary data where, for example,
    # charater "B" is represented as "\x42".
    track1 = b"B5123456789012345^KENOBI/OBIWAN^3512101000000000000000000000000"
    atc = bytes.fromhex("005E")
    un = bytes.fromhex("00000899")
    cvc3 = cvv.generate_cvc3(icc_cvc3, track1, atc, un)
    assert cvc3[-3:] == "419"
