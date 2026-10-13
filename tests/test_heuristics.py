import pytest

from phishdetect.heuristics import analyze, heuristic_score, is_trusted, registered_domain


def rules(url):
    return {f.rule for f in analyze(url)}


@pytest.mark.parametrize("host, expected", [
    ("a.b.example.com", "example.com"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("cmi.co.ma", "cmi.co.ma"),
])
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


@pytest.mark.parametrize("url, rule", [
    ("http://192.168.1.10/login", "ip_host"),
    ("http://www.google.com@evil.example/", "userinfo_trick"),
    ("https://paypa1.com/", "typosquat"),
    ("https://rnicrosoft.com/", "typosquat"),
    ("https://xn--pple-43d.com/", "homoglyph"),
    ("https://paypal.com.account-check.xyz/", "brand_in_subdomain"),
    ("https://secure-netflix-billing.com/", "brand_in_domain"),
    ("https://login-office365.support/", "brand_in_domain"),
    ("https://micros0ft-support.top/", "brand_in_domain"),
    ("https://evil.tk/", "suspicious_tld"),
    ("https://bit.ly/abc", "url_shortener"),
    ("https://x.000webhostapp.com/", "free_hosting"),
    ("https://a.com/doc.pdf.exe", "double_extension"),
    ("https://a.com/out?url=https://evil.tk", "open_redirect"),
    ("https://a.com/x?e=victim@corp.ma", "email_in_params"),
    ("javascript:alert(1)", "dangerous_scheme"),
    ("https://a.com:8443/", "non_standard_port"),
])
def test_rule_fires(url, rule):
    assert rule in rules(url)


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/",
    "https://outlook.office365.com/mail/",
    "https://www.purchase-orders.com/",   # 'chase' must not match inside 'purchase'
    "https://applet-dev.io/",             # 'apple' must not match inside 'applet'
    "https://github.com/microsoft/vscode",
])
def test_no_brand_false_positive(url):
    assert not rules(url) & {"brand_in_domain", "brand_in_subdomain", "brand_in_path", "typosquat"}


def test_trusted_but_not_free_hosting():
    assert is_trusted("https://en.wikipedia.org/wiki/Phishing")
    assert not is_trusted("https://sites.google.com/view/x")
    assert not is_trusted("http://10.0.0.1/")


def test_score_bounds():
    assert heuristic_score([]) == 0
    assert 0.7 < heuristic_score(analyze("http://paypal.com.secure-login.xyz/verify?u=a@b.com")) < 1
