"""
Pull links out of a reported e-mail (.eml) for triage.

Besides the raw URLs, it flags the classic "display text != real target"
trick: <a href="http://evil.tld">https://www.paypal.com</a>.
The message is only parsed, never rendered, and nothing is fetched.
"""

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

from .features import split_url
from .heuristics import BRANDS, OFFICIAL_DOMAINS, Finding, analyze, registered_domain

URL_RE = re.compile(r"""(?:https?://|hxxps?://|www\.)[^\s<>"'\])]+""", re.IGNORECASE)


class _AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []  # (href, visible text)
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def _domain_of(text):
    try:
        return registered_domain(split_url(text)["domain"])
    except Exception:
        return None


def parse_eml(path):
    """
    Returns (headers, links) where links is a list of dicts:
    {url, source, display_text, mismatch}
    """
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    headers = {k: str(msg.get(k, "")) for k in ("From", "Reply-To", "Return-Path", "To", "Subject", "Date")}
    auth = str(msg.get("Authentication-Results", ""))
    headers["spf/dkim/dmarc"] = " ".join(re.findall(r"\b(?:spf|dkim|dmarc)=\w+", auth)) or "n/a"

    links, seen = [], {}

    def add(url, source, text=""):
        url = url.rstrip(".,;")
        if not url or url.lower().startswith(("mailto:", "tel:", "#", "cid:")):
            return
        mismatch = False
        if text and URL_RE.search(text):
            shown, real = _domain_of(URL_RE.search(text).group(0)), _domain_of(url)
            mismatch = bool(shown and real and shown != real)
        if url in seen:
            # Same target seen again (text + html parts): merge the evidence.
            prev = seen[url]
            if source not in prev["source"]:
                prev["source"] += ", " + source
            if mismatch:
                prev.update(display_text=text, mismatch=True)
            return
        seen[url] = {"url": url, "source": source, "display_text": text, "mismatch": mismatch}
        links.append(seen[url])

    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            body = part.get_payload(decode=True).decode("utf-8", "replace")
        if ctype == "text/html":
            parser = _AnchorParser()
            parser.feed(body)
            for href, text in parser.links:
                add(href, "html-href", text)
            for m in re.finditer(r"""(?:src|action)\s*=\s*["']([^"']+)""", body, re.I):
                if m.group(1).lower().startswith("http"):
                    add(m.group(1), "html-src/action")
        else:
            for m in URL_RE.finditer(body):
                add(m.group(0), "text")

    return headers, links


def _addr_domain(value):
    addr = parseaddr(value)[1]
    return registered_domain(addr.rsplit("@", 1)[1].lower()) if "@" in addr else None


def header_findings(headers):
    """Sender-side red flags (spoofing, reply diversion, failed authentication)."""
    out = []
    from_name, from_addr = parseaddr(headers.get("From", ""))
    from_dom = _addr_domain(headers.get("From", ""))
    reply_dom = _addr_domain(headers.get("Reply-To", ""))
    return_dom = _addr_domain(headers.get("Return-Path", ""))

    if reply_dom and from_dom and reply_dom != from_dom:
        out.append(Finding("reply_to_mismatch", "high",
                           f"replies go to {reply_dom}, not to the sender domain {from_dom}"))
    if return_dom and from_dom and return_dom != from_dom:
        out.append(Finding("return_path_mismatch", "medium",
                           f"envelope sender {return_dom} differs from From domain {from_dom}"))
    name = re.sub(r"[^a-z0-9]", "", from_name.lower())
    for brand in BRANDS:
        if brand in name and from_dom not in BRANDS[brand]:
            out.append(Finding("display_name_spoof", "high",
                               f"display name claims '{from_name}' but mail comes from {from_dom}"))
            break
    if from_dom and from_dom not in OFFICIAL_DOMAINS:
        for f in analyze("http://" + from_addr.rsplit("@", 1)[-1]):
            if f.rule in ("typosquat", "homoglyph", "brand_in_domain", "suspicious_tld"):
                out.append(Finding("sender_" + f.rule, f.severity, f"sender domain: {f.detail}"))
    for check in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{check}=(\w+)", headers.get("spf/dkim/dmarc", ""))
        if m and m.group(1) in ("fail", "softfail", "none"):
            sev = "high" if check == "dmarc" and m.group(1) == "fail" else "medium"
            out.append(Finding(f"{check}_{m.group(1)}", sev, f"{check.upper()} result: {m.group(1)}"))
    return out
