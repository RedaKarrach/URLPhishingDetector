r"""
Lexical feature extraction.

Rebuilds, from the raw URL string only, the columns of the Vrbancic et al.
"Phishing Websites Dataset" (Data in Brief, 2020) that do not require any
network lookup. Nothing here resolves DNS or touches the target host, so a
suspicious URL can be triaged without tipping off whoever runs it.

URL layout used by the dataset (scheme is stripped before counting):

    secure-bank.com/account/login.php?id=7
    \_____________/\________________/ \__/
         domain         directory      params
                              \_______/
                                file

"directory" is the whole path (it includes the file name), "file" is what
follows the last "/". A missing part is encoded as -1, not 0.
"""

import re
from urllib.parse import unquote

# Character -> column name fragment, same order as the dataset.
SPECIAL_CHARS = {
    "dot": ".",
    "hyphen": "-",
    "underline": "_",
    "slash": "/",
    "questionmark": "?",
    "equal": "=",
    "at": "@",
    "and": "&",
    "exclamation": "!",
    "space": " ",
    "tilde": "~",
    "comma": ",",
    "plus": "+",
    "asterisk": "*",
    "hashtag": "#",
    "dollar": "$",
    "percent": "%",
}

# Small TLD list, enough to count TLD tokens the way the dataset does
# (qty_tld_url, tld_present_params). Not meant to be a public suffix list.
KNOWN_TLDS = {
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "co",
    "me", "tv", "cc", "ws", "app", "dev", "xyz", "top", "online", "site",
    "club", "shop", "store", "live", "life", "link", "click", "work", "tech",
    "space", "website", "fun", "icu", "buzz", "rest", "zip", "mov", "cfd",
    "sbs", "tk", "ml", "ga", "cf", "gq", "ru", "cn", "br", "in", "uk", "de",
    "fr", "it", "es", "nl", "be", "ch", "at", "pl", "pt", "se", "no", "dk",
    "fi", "cz", "sk", "hu", "ro", "bg", "gr", "tr", "ua", "by", "kz", "ir",
    "ma", "dz", "tn", "eg", "za", "ng", "ke", "us", "ca", "mx", "ar", "cl",
    "pe", "ve", "au", "nz", "jp", "kr", "tw", "hk", "sg", "my", "id", "th",
    "vn", "ph", "pk", "bd", "sa", "ae", "il", "eu", "asia", "mobi", "name",
    "pro", "su", "ly", "to", "gl", "gd", "am", "fm", "la", "pw", "nu",
}

URL_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bitly.com", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "s.id", "t.ly", "v.gd", "lnkd.in", "db.tt", "qr.ae", "bl.ink",
    "short.io", "x.co", "trib.al", "soo.gd", "clck.ru", "u.to", "shorte.st",
    "bc.vc", "ouo.io", "rotf.lol", "tny.im", "2no.co", "bitly.ws",
}

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_IP = re.compile(r"^0x[0-9a-f]{8}$", re.IGNORECASE)
_DEC_IP = re.compile(r"^\d{8,10}$")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_TLD_TOKEN = re.compile(r"\.([a-z]{2,})(?=$|[./?:#&=_\-])")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)

PARTS = ("url", "domain", "directory", "file", "params")


def _char_columns(part):
    return [f"qty_{name}_{part}" for name in SPECIAL_CHARS]


# Every column this module can compute, in dataset order.
LEXICAL_COLUMNS = (
    _char_columns("url") + ["qty_tld_url", "length_url"]
    + _char_columns("domain")
    + ["qty_vowels_domain", "domain_length", "domain_in_ip", "server_client_domain"]
    + _char_columns("directory") + ["directory_length"]
    + _char_columns("file") + ["file_length"]
    + _char_columns("params") + ["params_length", "tld_present_params", "qty_params"]
    + ["email_in_url", "url_shortened"]
)

# The 26 "URL text only" columns used in step 14 of the lab.
LAB_URL_COLUMNS = (
    [f"qty_{name}_url" for name in SPECIAL_CHARS] + ["length_url"]
    + [f"qty_{name}_domain" for name in ("dot", "hyphen", "underline", "at")]
    + ["qty_vowels_domain", "domain_length", "domain_in_ip", "server_client_domain"]
)

# Columns that need WHOIS / DNS / HTTP lookups at collection time.
NETWORK_COLUMNS = [
    "time_response", "domain_spf", "asn_ip", "time_domain_activation",
    "time_domain_expiration", "qty_ip_resolved", "qty_nameservers",
    "qty_mx_servers", "ttl_hostname", "tls_ssl_certificate", "qty_redirects",
    "url_google_index", "domain_google_index",
]


_REFANG = [
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"^fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\[://\]"), lambda m: m.group(0)[1:-1]),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
]


def refang(url):
    """Turn an IOC-style defanged URL (hxxp://evil[.]com) back into a URL."""
    out = url.strip().strip("<>\"'")
    for pattern, repl in _REFANG:
        out = pattern.sub(repl, out)
    return out


def defang(url):
    """Make a URL non-clickable for reports and tickets."""
    out = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
    return out.replace(".", "[.]")


def split_url(url):
    """
    Split a URL into the parts used by the dataset.

    Returns a dict with keys url, domain, directory, file, params, port.
    directory / file / params are None when absent.
    """
    text = refang(url)
    text = _SCHEME.sub("", text)
    # A bare trailing "/" carries no information ("google.com/" == "google.com").
    if text.endswith("/") and text.count("/") == 1:
        text = text[:-1]

    m = re.match(r"^([^/?#]*)(/[^?#]*)?(\?[^#]*)?(#.*)?$", text)
    authority, path, query = m.group(1), m.group(2), m.group(3)

    # Drop "user:pass@" so the hostname is what the browser will actually hit.
    host = authority.rsplit("@", 1)[-1]
    port = None
    if host.startswith("["):  # IPv6 literal
        end = host.find("]")
        port = host[end + 2:] if host[end + 1:end + 2] == ":" else None
        host = host[1:end]
    elif ":" in host:
        host, port = host.split(":", 1)

    directory = path if path else None
    file = path.rsplit("/", 1)[-1] if path else None
    params = query[1:] if query else None

    return {
        "url": text,
        "authority": authority,
        "domain": host.lower(),
        "port": port,
        "directory": directory,
        "file": file,
        "params": params,
    }


def is_ip_host(host):
    if _IPV4.match(host) or _HEX_IP.match(host) or _DEC_IP.match(host):
        return True
    return ":" in host  # IPv6 literal


def _count_chars(text, part, out):
    for name, char in SPECIAL_CHARS.items():
        out[f"qty_{name}_{part}"] = text.count(char) if text is not None else -1


def _tld_tokens(text):
    return [t for t in _TLD_TOKEN.findall(text.lower()) if t in KNOWN_TLDS]


def extract_features(url):
    """Compute every LEXICAL_COLUMNS value for one URL. Returns a dict."""
    p = split_url(url)
    text, domain = p["url"], p["domain"]
    f = {}

    _count_chars(text, "url", f)
    f["qty_tld_url"] = len(_tld_tokens(text))
    f["length_url"] = len(text)

    _count_chars(domain, "domain", f)
    f["qty_vowels_domain"] = sum(domain.count(v) for v in "aeiou")
    f["domain_length"] = len(domain)
    f["domain_in_ip"] = int(is_ip_host(domain))
    f["server_client_domain"] = int("server" in domain or "client" in domain)

    _count_chars(p["directory"], "directory", f)
    f["directory_length"] = len(p["directory"]) if p["directory"] is not None else -1

    _count_chars(p["file"], "file", f)
    f["file_length"] = len(p["file"]) if p["file"] is not None else -1

    params = p["params"]
    _count_chars(params, "params", f)
    if params is None:
        f["params_length"] = f["tld_present_params"] = f["qty_params"] = -1
    else:
        f["params_length"] = len(params)
        f["tld_present_params"] = int(bool(_tld_tokens(unquote(params))))
        f["qty_params"] = len([x for x in params.split("&") if x])

    f["email_in_url"] = int(bool(_EMAIL.search(unquote(text))))
    f["url_shortened"] = int(domain.removeprefix("www.") in URL_SHORTENERS)
    return f


def to_frame(urls, columns):
    """Feature matrix for a list of URLs, restricted to `columns` (model order)."""
    import pandas as pd

    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(rows, columns=LEXICAL_COLUMNS)[list(columns)]
