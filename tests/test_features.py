from phishdetect.features import (LAB_URL_COLUMNS, LEXICAL_COLUMNS, defang,
                                  extract_features, refang, split_url)


def test_column_sets():
    assert len(LAB_URL_COLUMNS) == 26
    assert len(LEXICAL_COLUMNS) == len(set(LEXICAL_COLUMNS)) == 98
    assert set(LAB_URL_COLUMNS) <= set(LEXICAL_COLUMNS)


def test_split_matches_dataset_layout():
    p = split_url("http://secure-bank.com/account/login.php?id=7")
    assert p["domain"] == "secure-bank.com"
    assert p["directory"] == "/account/login.php"  # directory includes the file
    assert p["file"] == "login.php"
    assert p["params"] == "id=7"


def test_missing_parts_are_minus_one():
    f = extract_features("google.com")
    assert f["directory_length"] == f["file_length"] == f["params_length"] == -1
    assert f["qty_dot_directory"] == -1
    assert f["qty_slash_url"] == 0


def test_trailing_slash_ignored():
    assert extract_features("https://google.com/") == extract_features("google.com")


def test_scheme_is_stripped():
    f = extract_features("https://www.wikipedia.org")
    assert f["length_url"] == len("www.wikipedia.org")


def test_counts():
    f = extract_features("http://paypal.com.secure-account-verification.xyz/login?user=client@mail.com")
    assert f["qty_hyphen_domain"] == 2
    assert f["qty_at_url"] == 1
    assert f["email_in_url"] == 1
    assert f["qty_params"] == 1
    assert f["tld_present_params"] == 1
    assert f["qty_tld_url"] == 3


def test_ip_and_shortener():
    assert extract_features("http://192.168.12.7/banque/connexion.php")["domain_in_ip"] == 1
    assert extract_features("http://bit.ly/3xYz9Q")["url_shortened"] == 1


def test_userinfo_is_not_the_host():
    assert split_url("http://www.google.com@evil.example/login")["domain"] == "evil.example"


def test_refang_defang_roundtrip():
    assert refang("hxxps://evil[.]com/login") == "https://evil.com/login"
    assert refang(defang("http://evil.com/a.php")) == "http://evil.com/a.php"
