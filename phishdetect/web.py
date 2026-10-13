"""
Minimal local web UI + JSON API (standard library only).

    GET  /                  form
    GET  /api/scan?url=...  JSON report
    POST /api/scan          {"urls": [...]} -> list of JSON reports

Binds to 127.0.0.1 by default. Every reflected value is HTML-escaped:
this page displays attacker-controlled strings by design.
"""

import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MAX_BODY = 64 * 1024
MAX_URLS = 200

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>URL Phishing Detector</title>
<style>
 :root {{ --bg:#fff; --fg:#1a1a1a; --mute:#6b6b6b; --line:#e4e4e4; --ok:#1f7a3a; --warn:#a86400; --bad:#c4291c;
         --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
         --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
 @media (prefers-color-scheme: dark) {{ :root {{ --bg:#161616; --fg:#e8e8e8; --mute:#9a9a9a; --line:#2e2e2e;
         --ok:#5cc27a; --warn:#e0a040; --bad:#ff6b5e; }} }}
 * {{ box-sizing:border-box }}
 body {{ margin:0; background:var(--bg); color:var(--fg); font:16px/1.6 var(--font) }}
 main {{ max-width:760px; margin:0 auto; padding:40px 16px }}
 h1 {{ font-size:24px; font-weight:600; margin:0 0 4px }} .sub {{ color:var(--mute); margin:0 0 24px; font-size:14px }}
 form {{ display:flex; gap:8px }}
 input {{ flex:1; min-width:0; padding:10px 12px; background:var(--bg); border:1px solid var(--line);
         color:var(--fg); border-radius:6px; font:15px var(--mono) }}
 input:focus {{ outline:none; border-color:var(--mute) }}
 button {{ padding:10px 20px; border:0; border-radius:6px; background:var(--fg); color:var(--bg); font:600 15px var(--font); cursor:pointer }}
 .card {{ border-top:1px solid var(--line); padding-top:20px; margin-top:28px }}
 .verdict {{ font-size:22px; font-weight:700 }} .CLEAN {{ color:var(--ok) }} .SUSPICIOUS {{ color:var(--warn) }} .PHISHING {{ color:var(--bad) }}
 .url {{ font:14px var(--mono); color:var(--mute); word-break:break-all }}
 .bar {{ height:4px; background:var(--line); border-radius:2px; overflow:hidden; margin:12px 0 4px }}
 .bar > div {{ height:100%; background:var(--fg) }}
 .kv {{ display:flex; flex-wrap:wrap; gap:6px 24px; font-size:14px; color:var(--mute) }} .kv b {{ color:var(--fg) }}
 table {{ width:100%; border-collapse:collapse; margin-top:16px; font-size:14px }}
 td, th {{ text-align:left; padding:7px 10px 7px 0; border-bottom:1px solid var(--line); vertical-align:top }}
 th {{ color:var(--mute); font-weight:500 }}
 .sev {{ font-weight:600; text-transform:uppercase; font-size:12px; color:var(--mute) }}
 .critical, .high {{ color:var(--bad) }} .medium {{ color:var(--warn) }}
 details {{ margin-top:16px; font-size:14px }} summary {{ cursor:pointer; color:var(--mute) }}
 ol {{ font:13px/1.8 var(--mono); color:var(--mute); padding-left:24px }}
 footer {{ color:var(--mute); font-size:13px; margin-top:32px }}
</style></head><body><main>
<h1>URL Phishing Detector</h1>
<p class="sub">Decision tree + analyst rules. Offline: the URL is analyzed as text, the target is never contacted.</p>
<form method="get" action="/">
 <input name="url" placeholder="paste a URL (defanged hxxp://evil[.]com works too)" value="{value}" autofocus>
 <button>Scan</button>
</form>
{result}
<footer>model: {model}</footer>
</main></body></html>"""

def render_report(r):
    rows = "".join(
        f"<tr><td class='sev {escape(f.severity)}'>{escape(f.severity)}</td>"
        f"<td>{escape(f.rule)}</td><td>{escape(f.detail)}</td></tr>"
        for f in r.findings
    ) or "<tr><td colspan=3>no rule triggered</td></tr>"
    path = "".join(f"<li>{escape(s)}</li>" for s in r.decision_path)
    return f"""<div class="card">
 <div class="verdict {r.verdict}">{r.verdict}</div>
 <div class="url">{escape(r.url)}</div>
 <div class="bar"><div style="width:{r.risk * 100:.0f}%"></div></div>
 <div class="kv"><span>risk <b>{r.risk:.0%}</b></span><span>tree <b>{r.tree_probability:.0%}</b></span>
 <span>rules <b>{r.heuristic_score:.0%}</b></span><span>allowlisted <b>{"yes" if r.trusted else "no"}</b></span></div>
 <table><tr><th>severity</th><th>rule</th><th>detail</th></tr>{rows}</table>
 <details><summary>decision path in the tree ({len(r.decision_path)} steps)</summary><ol>{path}</ol></details>
</div>"""


def make_handler(detector):
    model_desc = escape(f"{detector.meta.get('feature_set', '?')} tree, {len(detector.columns)} features, "
                        f"test F1 {detector.meta.get('test_f1', '?')}")

    class Handler(BaseHTTPRequestHandler):
        server_version = "phishdetect"

        def _send(self, code, body, ctype):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, indent=2), "application/json")

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            url = (qs.get("url") or [""])[0].strip()
            if parsed.path == "/api/scan":
                if not url:
                    return self._json(400, {"error": "missing ?url="})
                return self._json(200, detector.scan(url).to_dict())
            if parsed.path != "/":
                return self._send(404, "not found", "text/plain")
            result = render_report(detector.scan(url)) if url else ""
            self._send(200, PAGE.format(value=escape(url), result=result, model=model_desc), "text/html; charset=utf-8")

        def do_POST(self):
            if urlparse(self.path).path != "/api/scan":
                return self._send(404, "not found", "text/plain")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "body too large"})
            try:
                urls = json.loads(self.rfile.read(length) or b"{}").get("urls", [])
                assert isinstance(urls, list) and all(isinstance(u, str) for u in urls)
            except Exception:
                return self._json(400, {"error": 'expected {"urls": ["..."]}'})
            self._json(200, [detector.scan(u).to_dict() for u in urls[:MAX_URLS]])

        def log_message(self, fmt, *args):
            pass

    return Handler


def serve(detector, host="127.0.0.1", port=8080):
    httpd = ThreadingHTTPServer((host, port), make_handler(detector))
    print(f"[+] listening on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
