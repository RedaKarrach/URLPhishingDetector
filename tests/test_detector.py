import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from phishdetect.detector import DEFAULT_MODEL, Detector
from phishdetect.mail import header_findings, parse_eml
from phishdetect.web import make_handler

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

pytestmark = pytest.mark.skipif(not DEFAULT_MODEL.exists(), reason="trained model not present")


@pytest.fixture(scope="module")
def det():
    return Detector()


@pytest.mark.parametrize("url, verdict", [
    ("google.com", "CLEAN"),
    ("https://en.wikipedia.org/wiki/Decision_tree", "CLEAN"),
    ("hxxp://paypal.com.secure-account-verification[.]xyz/login?user=client@mail.com", "PHISHING"),
    ("http://192.168.12.7/banque/connexion.php", "PHISHING"),
    ("https://paypa1.com/signin", "PHISHING"),
])
def test_verdicts(det, url, verdict):
    assert det.scan(url).verdict == verdict


def test_tree_alone_is_not_enough(det):
    # Ordinary deep link: the tree's path bias fires, no rule confirms it.
    r = det.scan("https://example-shop.com/products/shoes?id=42&color=red")
    assert r.tree_probability > 0.7
    assert r.verdict == "SUSPICIOUS"
    assert any(f.rule == "model_only" for f in r.findings)


def test_decision_path_ends_on_leaf(det):
    path = det.scan("http://192.168.12.7/banque/connexion.php").decision_path
    assert path and path[-1].startswith("leaf")


def test_eml(det):
    headers, links = parse_eml(EXAMPLES / "suspicious_mail.eml")
    assert any(l["mismatch"] for l in links)
    assert {"reply_to_mismatch", "display_name_spoof", "dmarc_fail"} <= {f.rule for f in header_findings(headers)}


def test_web_escapes_and_api(det):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(det))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        payload = urllib.parse.quote('http://a.xyz/"><script>alert(1)</script>')
        html = urllib.request.urlopen(f"{base}/?url={payload}").read().decode()
        assert "<script>alert(1)" not in html
        data = json.loads(urllib.request.urlopen(f"{base}/api/scan?url=bit.ly/x").read())
        assert data["verdict"] in ("CLEAN", "SUSPICIOUS", "PHISHING")
    finally:
        httpd.shutdown()
