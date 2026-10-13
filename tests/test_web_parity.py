"""The GitHub Pages demo (docs/engine.js) must give the same answers as the Python engine."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phishdetect.detector import DEFAULT_MODEL, Detector
from phishdetect.features import extract_features

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")

pytestmark = [
    pytest.mark.skipif(NODE is None, reason="node not installed"),
    pytest.mark.skipif(not DEFAULT_MODEL.exists(), reason="trained model not present"),
]

EXTRA = [
    "google.com", "https://google.com/", "https://www.amazon.fr/gp/cart/view.html",
    "https://example-shop.com/products/shoes?id=42&color=red",
    "https://www.lemonde.fr/international/article/2026/10/12/test.html",
    "https://sites.google.com/view/microsoft-account-verify", "https://github.com/microsoft/vscode",
    "https://www.google.com/url?q=https://evil.tk/login", "javascript:alert(document.cookie)",
    "https://rnicrosoft.com/", "https://login-office365.support/", "https://micros0ft-support.top/",
    "https://www.purchase-orders.com/", "https://applet-dev.io/", "http://[2001:db8::1]:8080/admin",
    "https://xkqzjw-vbnmrtyp.biz/a", "https://a.com:8443/x.php?url=//evil.com&e=victim%40corp.ma",
    "https://cdn.example.com/files/report.pdf.exe", "http://0x7f000001/login",
    "https://secure.login.account.verify.paypal.evil.com/", "ftp://files.example.org/pub/",
    "https://fr.wikipedia.org/wiki/Hame%C3%A7onnage", "https://bit.ly/3xYz9Q?x=%E2%82%AC%ZZ",
    "https://www.cihbank.ma/", "https://attijariwafa-secure.online/client/login.php",
    "https://xn--80ak6aa92e.com/", "https://shop.example.co.uk/a/b/c/d/e/f/g/h?a=1&b=2&c=3",
]


def corpus():
    lines = (ROOT / "examples" / "urls.txt").read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")] + EXTRA


def test_js_engine_matches_python(tmp_path):
    subprocess.run([sys.executable, "-m", "phishdetect", "export-web", "--out", str(tmp_path / "model.json")],
                   cwd=ROOT, check=True, capture_output=True)
    urls = corpus()
    (tmp_path / "urls.json").write_text(json.dumps(urls), encoding="utf-8")
    out = subprocess.run([NODE, str(ROOT / "tests" / "web_parity.mjs"), str(tmp_path / "model.json"),
                          str(tmp_path / "urls.json")], capture_output=True, check=True, encoding="utf-8")
    js_results = json.loads(out.stdout)

    det = Detector()
    for url, js in zip(urls, js_results):
        py = det.scan(url).to_dict()
        assert js["features"] == extract_features(py["url"]), url
        assert js["verdict"] == py["verdict"], url
        for key in ("risk", "tree_probability", "heuristic_score"):
            assert abs(js[key] - py[key]) < 1e-3, (url, key)
        assert js["trusted_domain"] == py["trusted_domain"], url
        assert js["findings"] == py["findings"], url
        assert js["decision_path"] == py["decision_path"], url
