from pyemv import ac, kd, tools


def test_generate_ac_emv_arpc1():
    r"""
    Test generate AC with EMV padding (\x80 padding).

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using ICC Master Key
    ARPC Method = 1
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key.
    pan = b"9901234567890123"
    psn = b"45"
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "1DA5"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "0995"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text, ac.PaddingType.EMV)
    assert arqc.hex().upper() == "4B46013359B7A58B"

    # ARPC Method 1 using ICC Master Key
    arpc_rc = bytes.fromhex("0000")
    arpc = ac.generate_arpc_1(icc_mk, arqc, arpc_rc)
    assert arpc.hex().upper() == "F8C9CECAABD55AD1"


def test_generate_ac_default_emv_arpc1():
    r"""
    Test generate AC with default EMV padding (\x80 padding).

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using ICC Master Key
    ARPC Method = 1
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key.
    pan = b"9901234567890123"
    psn = b"45"
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "1DA5"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "0995"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text)
    assert arqc.hex().upper() == "4B46013359B7A58B"

    # ARPC Method 1 using ICC Master Key
    arpc_rc = bytes.fromhex("0000")
    arpc = ac.generate_arpc_1(icc_mk, arqc, arpc_rc)
    assert arpc.hex().upper() == "F8C9CECAABD55AD1"


def test_generate_ac_visa_aprc1():
    r"""
    Test generate AC with Visa padding (\x00 padding).

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using ICC Master Key
    ARPC Method = 1
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = b"9901234567890123"
    psn = b"45"
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "1DA5"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "0995"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF01")
    arqc = ac.generate_ac(sk_ac, cipher_text, ac.PaddingType.VISA)
    assert arqc.hex().upper() == "2E141C6BC4A20DA8"

    # ARPC Method 1 using ICC Master Key
    arpc_rc = bytes.fromhex("0000")
    arpc = ac.generate_arpc_1(icc_mk, arqc, arpc_rc)
    assert arpc.hex().upper() == "16A49AAB314B9262"


def test_generate_ac_visa_aprc1_no_padding_required():
    r"""
    Test generate AC with Visa padding (\x00 padding).
    However, no padding is required. The data is already multiple of 8.

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using ICC Master Key
    ARPC Method = 1
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = b"9901234567890123"
    psn = b"45"
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "1DA5"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "0995"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text, ac.PaddingType.VISA)
    assert arqc.hex().upper() == "922F3E83125EB46B"

    # ARPC Method 1 using ICC Master Key
    arpc_rc = bytes.fromhex("0000")
    arpc = ac.generate_arpc_1(icc_mk, arqc, arpc_rc)
    assert arpc.hex().upper() == "8AE6E836084B0E80"


def test_generate_arpc2():
    r"""
    Test generate ARPC using method 2.

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key
    ARPC Method = 2
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = b"9901234567890123"
    psn = b"45"
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "1DA5"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "0995"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text, ac.PaddingType.EMV)
    assert arqc.hex().upper() == "4B46013359B7A58B"

    # ARPC Method 2 using ICC Master Key
    csu = bytes.fromhex("00000000")
    prop_auth_data = bytes.fromhex("1234567890ABCDEF")
    arpc = ac.generate_arpc_2(sk_ac, arqc, csu, prop_auth_data)
    assert arpc.hex().upper() == "4962B76C"


def test_generate_arpc2_no_prop_auth_data():
    r"""
    Test generate ARPC using method 2 without prop auth data.

    Master Key Derivation = Option A
    ARQC verification using Common Session Key Derivation
    ARPC generation using Common Session Key
    ARPC Method = 2
    """
    # Verify issuer master key check digits
    iss_mk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert tools.key_check_digits(iss_mk, 2).hex().upper() == "08D7"

    # Derive ICC master key
    pan = b"9901234567890123"
    psn = b"45"
    icc_mk = kd.derive_icc_mk_a(iss_mk, pan, psn)
    assert tools.key_check_digits(icc_mk, 2).hex().upper() == "1DA5"

    # Verify AC session key
    # Common Session Key Derivation Option
    r = bytes.fromhex("1234567890123456")
    sk_ac = kd.derive_common_sk(icc_mk, r)
    assert tools.key_check_digits(sk_ac, 2).hex().upper() == "0995"

    # ARQC validation using Session Key
    cipher_text = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    arqc = ac.generate_ac(sk_ac, cipher_text, ac.PaddingType.EMV)
    assert arqc.hex().upper() == "4B46013359B7A58B"

    # ARPC Method 2 using ICC Master Key
    csu = bytes.fromhex("00000000")
    arpc = ac.generate_arpc_2(sk_ac, arqc, csu)
    assert arpc.hex().upper() == "7DFB1188"
