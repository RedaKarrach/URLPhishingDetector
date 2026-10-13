"""
Analyst rules applied on top of the decision tree.

The tree only sees character counts and lengths. These checks cover tricks
that counts cannot express (homoglyphs, brand abuse, typosquats, credential
in authority, open redirects...) and give the analyst a reason for the
verdict instead of just a probability.

All checks are offline: string analysis only, no DNS/WHOIS/HTTP.
"""

import math
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote

from .features import URL_SHORTENERS, is_ip_host, split_url

SEVERITY_WEIGHT = {"info": 0.0, "low": 0.10, "medium": 0.25, "high": 0.45, "critical": 0.75}


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str

    @property
    def weight(self):
        return SEVERITY_WEIGHT[self.severity]


# Brand keyword -> registrable domains that legitimately use it.
BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "azure.com"},
    "office365": {"office.com", "microsoft.com", "office365.com"},
    "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "onedrive": {"onedrive.com", "live.com", "microsoft.com", "sharepoint.com"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "google": {"google.com", "google.co.ma", "google.fr", "googleusercontent.com", "youtube.com"},
    "gmail": {"gmail.com", "google.com"},
    "amazon": {"amazon.com", "amazon.fr", "amazon.de", "amazon.co.uk", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.fr"},
    "fedex": {"fedex.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    # Moroccan banks / payment gateway, common lures locally.
    "attijariwafa": {"attijariwafabank.com", "attijarinet.com"},
    "cihbank": {"cihbank.ma"},
    "bmce": {"bankofafrica.ma", "bmcebank.ma"},
    "barid": {"albaridbank.ma", "poste.ma"},
    "cmi": {"cmi.co.ma"},
}

OFFICIAL_DOMAINS = set().union(*BRANDS.values())

# TLDs that are cheap/free or massively abused in phishing campaigns
# (Spamhaus / Interisle reports). Not malicious by themselves.
SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "buzz", "cfd", "sbs", "rest", "click", "link", "work",
    "online", "site", "live", "shop", "support", "zip", "mov", "tk", "ml",
    "ga", "cf", "gq", "pw", "monster", "quest", "cyou", "bond",
}

SENSITIVE_WORDS = {
    "login", "logon", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "security", "banking", "confirm", "password", "webscr",
    "wallet", "unlock", "suspended", "billing", "invoice", "auth", "sso",
    "recover", "validate", "authenticate",
}

FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com",
    "web.app", "pages.dev", "netlify.app", "vercel.app", "github.io",
    "glitch.me", "herokuapp.com", "blogspot.com", "sites.google.com",
    "docs.google.com", "forms.gle", "storage.googleapis.com", "web.core.windows.net",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "workers.dev",
    "duckdns.org", "r2.dev", "ipfs.io", "square.site", "godaddysites.com",
}

# Popular registrable domains, used to avoid flagging normal browsing.
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "wikipedia.org", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "instagram.com", "linkedin.com", "github.com",
    "stackoverflow.com", "paypal.com", "netflix.com", "office.com", "live.com",
    "microsoftonline.com", "yahoo.com", "twitter.com", "x.com", "reddit.com",
    "whatsapp.com", "cloudflare.com", "mozilla.org", "python.org", "gitlab.com",
    "gov.ma", "bing.com", "duckduckgo.com", "openai.com",
}

# Second-level labels under which a ccTLD sells registrations (co.uk, co.ma...).
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "gouv", "or", "ne"}

_EXEC_EXT = re.compile(r"\.(exe|scr|js|vbs|hta|jar|msi|bat|cmd|ps1|iso|img|lnk|apk)$", re.I)
_DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|hta|html?|zip)$", re.I)
_REDIRECT_KEYS = {"url", "q", "redirect", "redirect_uri", "redir", "next", "target", "dest",
                  "destination", "goto", "continue", "return", "returnurl", "r", "u"}

# Visual look-alikes folded before comparing against brands.
_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
               ("5", "s"), ("@", "a"), ("$", "s")]


def registered_domain(host):
    """example.co.uk -> example.co.uk, a.b.example.com -> example.com (approximate eTLD+1)."""
    labels = host.strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _fold(label):
    for src, dst in _HOMOGLYPHS:
        label = label.replace(src, dst)
    return label


def _on_free_hosting(host):
    return next((fh for fh in FREE_HOSTING if host == fh or host.endswith("." + fh)), None)


def _contains_brand(label, brand):
    # Short names need a token boundary ("chase" must not hit "purchase").
    if len(brand) >= 6:
        return brand in label
    return re.search(rf"(^|[\-\d]){brand}([\-\d]|$)", label) is not None


# Cyrillic / Greek / Armenian letters rendered like Latin ones (subset of
# Unicode confusables). Used on decoded punycode labels.
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0501": "d",
    "\u04cf": "l", "\u0261": "g", "\u0578": "n", "\u057d": "u", "\u03bf": "o",
    "\u03b1": "a", "\u03c1": "p", "\u0391": "a", "\u039f": "o", "\u0455": "s",
})


def unicode_host(host):
    """Decode punycode labels (xn--...) to Unicode, best effort."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except Exception:
                pass
        out.append(label)
    return ".".join(out)


def skeleton(text):
    return _fold(text.translate(_CONFUSABLES))


def _has_brand(label, brand):
    # Raw and folded: "micros0ft" needs folding, "office365" must not be folded.
    return _contains_brand(label, brand) or _contains_brand(_fold(label), brand)


def _typosquat_target(sld, reg):
    """Return the official domain `sld` imitates, or None."""
    folded = _fold(sld)
    for domains in BRANDS.values():
        if reg in domains:
            return None
    for domains in BRANDS.values():
        # Prefer the .com when a brand has several domains.
        for official in sorted(domains, key=lambda d: (not d.endswith(".com"), d)):
            target = official.split(".")[0]
            if sld == target or len(target) < 5:
                continue
            dist = levenshtein(folded, target)
            if folded == target or dist == 1 or (dist == 2 and len(target) >= 9):
                return official
    return None


def analyze(url):
    """Run every rule against a URL. Returns a list of Finding."""
    p = split_url(url)
    host, raw = p["domain"], p["url"]
    findings = []
    add = lambda rule, sev, detail: findings.append(Finding(rule, sev, detail))

    scheme = re.match(r"^\s*([a-z][a-z0-9+.\-]*):(?!\d)", url.strip(), re.I)
    scheme = scheme.group(1).lower() if scheme else None
    if scheme in {"data", "javascript", "vbscript", "file"}:
        add("dangerous_scheme", "critical", f"'{scheme}:' URI can run or load content without a website")
        return findings
    if scheme == "http":
        add("cleartext_http", "low", "no TLS: credentials would travel in clear text")

    if not host or "." not in host and not is_ip_host(host):
        add("malformed_host", "medium", f"host '{host}' is not a valid public hostname")
        return findings

    reg = registered_domain(host) if not is_ip_host(host) else host
    labels = host.split(".")
    sld = reg.split(".")[0]
    tld = labels[-1]
    path_and_query = unquote(((p["directory"] or "") + "?" + (p["params"] or "")).lower())

    if is_ip_host(host):
        add("ip_host", "high", f"host is a raw IP address ({host}) instead of a domain name")

    if "@" in p["authority"]:
        shown = p["authority"].split("@")[0]
        add("userinfo_trick", "critical",
            f"'{shown}@' before the host: the browser actually connects to {host}")

    if p["port"] and p["port"] not in {"80", "443"}:
        add("non_standard_port", "medium", f"explicit port :{p['port']}")

    if "xn--" in host or any(ord(c) > 127 for c in host):
        decoded = unicode_host(host)
        lookalike = skeleton(registered_domain(decoded).split(".")[0])
        hit = next((d for ds in BRANDS.values() for d in sorted(ds) if d.split(".")[0] == lookalike), None)
        if hit:
            add("homoglyph", "critical", f"'{decoded}' renders like {hit} but uses look-alike Unicode letters")
        else:
            add("idn_host", "medium", f"internationalized hostname, displays as '{decoded}'")

    if reg.removeprefix("www.") in URL_SHORTENERS or host in URL_SHORTENERS:
        add("url_shortener", "medium", f"{host} is a URL shortener: real destination is hidden")

    fh = _on_free_hosting(host)
    if fh:
        add("free_hosting", "medium", f"hosted on {fh} (free / user-generated hosting)")

    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", "medium", f".{tld} is heavily abused in phishing campaigns")

    if not is_ip_host(host):
        subdomains = labels[:-len(reg.split("."))]
        if len(subdomains) >= 3:
            add("deep_subdomains", "medium", f"{len(subdomains)} subdomain levels ({'.'.join(subdomains)})")

        # Brand name used outside the brand's own domains. Pages published on
        # free hosting under a big domain (sites.google.com) are still checked.
        known = (reg in OFFICIAL_DOMAINS or reg in TRUSTED_DOMAINS) and not fh
        for brand in BRANDS:
            if known:
                break
            if any(_has_brand(s, brand) for s in subdomains):
                add("brand_in_subdomain", "high",
                    f"'{brand}' appears in the subdomain but the real domain is {reg}")
                break
            if _has_brand(sld, brand):
                add("brand_in_domain", "high",
                    f"'{brand}' embedded in {reg}, which is not an official {brand} domain")
                break
            if re.search(rf"(^|[/._\-]){brand}([/._\-]|$)", path_and_query):
                add("brand_in_path", "medium", f"'{brand}' referenced in the path of {reg}")
                break

        # Typosquatting: close to a brand but not the brand.
        official = _typosquat_target(sld, reg)
        if official:
            target = official.split(".")[0]
            # Exact match once look-alikes are folded (paypa1, rnicrosoft) is the strong case.
            sev = "critical" if _fold(sld) == target else "high"
            add("typosquat", sev, f"{reg} imitates {official} (edit distance {levenshtein(sld, target)})")
            # paypa1 also folds to "paypal": keep the more precise finding only.
            findings[:] = [f for f in findings if f.rule != "brand_in_domain"]

        vowel_ratio = sum(sld.count(v) for v in "aeiou") / max(len(sld), 1)
        if len(sld) >= 12 and shannon_entropy(sld) > 3.5 and vowel_ratio < 0.3:
            add("high_entropy_domain", "medium",
                f"'{sld}' looks randomly generated (entropy {shannon_entropy(sld):.2f})")
        if sld.count("-") >= 2 and not sld.startswith("xn--"):
            add("hyphenated_domain", "low", f"{sld.count('-')} hyphens in '{sld}'")
        if not sld.startswith("xn--") and re.search(r"[a-z]", sld) and len(re.findall(r"\d", sld)) >= 4:
            add("digits_in_domain", "low", f"many digits mixed into '{sld}'")

    haystack = host + "/" + path_and_query
    hits = sorted(w for w in SENSITIVE_WORDS if re.search(rf"(?<![a-z]){re.escape(w)}", haystack))
    if hits:
        sev = "medium" if len(hits) >= 2 else "low"
        add("credential_keywords", sev, "lure keywords: " + ", ".join(hits))

    file = p["file"] or ""
    if _DOUBLE_EXT.search(file):
        add("double_extension", "critical", f"double extension in '{file}'")
    elif _EXEC_EXT.search(file):
        add("executable_download", "high", f"link points to an executable/script: '{file}'")

    if p["params"]:
        qs = parse_qs(p["params"], keep_blank_values=True)
        for key, values in qs.items():
            if key.lower() in _REDIRECT_KEYS and any(re.match(r"^(https?:)?//", v, re.I) for v in values):
                add("open_redirect", "high", f"parameter '{key}' forwards to another URL")
                break
        if re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", unquote(p["params"])):
            add("email_in_params", "medium", "victim e-mail address pre-filled in the URL (targeted lure)")

    if len(raw) > 100:
        add("long_url", "low", f"URL is {len(raw)} characters long")
    if "//" in (p["directory"] or ""):
        add("embedded_url", "medium", "'//' inside the path: URL nested in another URL")
    if "%" in host or re.search(r"(%[0-9a-f]{2}){5,}", raw, re.I):
        add("heavy_encoding", "low", "percent-encoding used to hide characters")

    return findings


def is_trusted(url, extra=()):
    host = split_url(url)["domain"]
    if is_ip_host(host) or not host:
        return False
    if _on_free_hosting(host):
        return False  # sites.google.com, github.io... anyone can publish there
    reg = registered_domain(host)
    return reg in TRUSTED_DOMAINS or reg in OFFICIAL_DOMAINS or reg in extra or host in extra


def heuristic_score(findings):
    """Noisy-OR of the rule weights: 0 = nothing found, close to 1 = many strong signals."""
    clean = 1.0
    for f in findings:
        clean *= 1 - f.weight
    return 1 - clean
