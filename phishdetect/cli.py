"""
Command line interface.

    python -m phishdetect scan <url> [<url> ...] [--explain] [--json]
    python -m phishdetect scan -f urls.txt -o report.csv
    python -m phishdetect interactive
    python -m phishdetect eml suspicious.eml
    python -m phishdetect serve [--port 8080]
    python -m phishdetect features <url>
    python -m phishdetect train --data data/dataset_full.csv
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path

from .features import defang

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
if USE_COLOR and os.name == "nt":
    os.system("")  # enables ANSI escape codes in the Windows console

C = {
    "CLEAN": "\033[32m", "SUSPICIOUS": "\033[33m", "PHISHING": "\033[31;1m",
    "critical": "\033[31;1m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[2m", "info": "\033[2m", "dim": "\033[2m", "reset": "\033[0m",
}


def c(key, text):
    return f"{C[key]}{text}{C['reset']}" if USE_COLOR else text


def _detector(args):
    from .detector import Detector

    allow = []
    if getattr(args, "allowlist", None):
        allow = [l.strip().lower() for l in Path(args.allowlist).read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.startswith("#")]
    return Detector(args.model, allowlist=allow)


def print_report(r, explain=False, defanged=False):
    shown = defang(r.url) if defanged else r.url
    print(f"{c(r.verdict, f'{r.verdict:10s}')} risk {r.risk:5.1%}  "
          f"{c('dim', f'(tree {r.tree_probability:.0%} | rules {r.heuristic_score:.0%})')}  {shown}")
    for f in r.findings:
        print(f"    {c(f.severity, f'[{f.severity:8s}]')} {f.rule:20s} {f.detail}")
    if r.trusted:
        print(f"    {c('dim', '[allowlist]')} registrable domain is on the trusted list")
    if explain:
        print(c("dim", "    decision path:"))
        for step in r.decision_path:
            print(c("dim", f"      -> {step}"))


def _read_targets(args):
    urls = list(args.urls or [])
    if args.file:
        src = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
        with src:
            urls += [l.strip() for l in src if l.strip() and not l.lstrip().startswith("#")]
    return urls


def write_output(reports, path, defanged):
    rows = [r.to_dict(defanged) for r in reports]
    if path.endswith(".json"):
        Path(path).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "verdict", "risk", "tree_probability", "heuristic_score", "trusted_domain", "findings"])
        for d in rows:
            w.writerow([d["url"], d["verdict"], d["risk"], d["tree_probability"], d["heuristic_score"],
                        d["trusted_domain"], "; ".join(f"{f['severity']}:{f['rule']}" for f in d["findings"])])


def cmd_scan(args):
    det = _detector(args)
    urls = _read_targets(args)
    if not urls:
        sys.exit("no URL given (positional args, -f FILE or -f - for stdin)")
    reports = [det.scan(u) for u in urls]

    if args.json:
        print(json.dumps([r.to_dict(args.defang) for r in reports], indent=2))
    else:
        for r in reports:
            print_report(r, args.explain, args.defang)
        if len(reports) > 1:
            counts = {v: sum(r.verdict == v for r in reports) for v in ("PHISHING", "SUSPICIOUS", "CLEAN")}
            print(f"\n{len(reports)} URLs: " + ", ".join(f"{c(k, k)} {n}" for k, n in counts.items()))
    if args.output:
        write_output(reports, args.output, args.defang)
        print(f"[+] report written to {args.output}", file=sys.stderr)
    # Non-zero exit when something is flagged, handy in scripts / pipelines.
    sys.exit(2 if any(r.verdict == "PHISHING" for r in reports) else 0)


def cmd_interactive(args):
    det = _detector(args)
    print("URL Phishing Detector - interactive mode")
    print(f"model: {det.meta.get('feature_set')} tree, {len(det.columns)} features, "
          f"test F1 {det.meta.get('test_f1')}")
    print("paste a URL and press Enter. commands: :explain on|off, :features <url>, :q\n")
    explain = False
    while True:
        try:
            line = input("url> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in (":q", ":quit", "exit", "quit"):
            break
        if line.startswith(":explain"):
            explain = line.endswith("on")
            print(f"decision path {'on' if explain else 'off'}")
            continue
        if line.startswith(":features"):
            feats = det.features(line.split(None, 1)[1]) if " " in line else {}
            for k, v in feats.items():
                if v not in (0, -1):
                    print(f"  {k:28s} {v}")
            continue
        print_report(det.scan(line), explain)
        print()


def cmd_eml(args):
    from .mail import header_findings, parse_eml

    det = _detector(args)
    headers, links = parse_eml(args.file)
    for k, v in headers.items():
        print(f"{k:15s} {v}")
    hdr = header_findings(headers)
    if hdr:
        print("\nheader analysis:")
        for f in hdr:
            print(f"    {c(f.severity, f'[{f.severity:8s}]')} {f.rule:20s} {f.detail}")
    print(f"\n{len(links)} unique link(s) found\n")
    reports = []
    for link in links:
        r = det.scan(link["url"])
        reports.append(r)
        print_report(r, args.explain, args.defang)
        if link["mismatch"]:
            print(f"    {c('high', '[high    ]')} {'display_mismatch':20s} "
                  f"link text shows '{link['display_text']}' but points elsewhere")
        print(c("dim", f"    found in: {link['source']}"))
    if args.output:
        write_output(reports, args.output, args.defang)
    worst = max((r.verdict for r in reports), key=["CLEAN", "SUSPICIOUS", "PHISHING"].index, default="CLEAN")
    red_flags = any(l["mismatch"] for l in links) or any(f.severity in ("high", "critical") for f in hdr)
    if red_flags and worst == "CLEAN":
        worst = "SUSPICIOUS"
    print(f"\nmessage verdict: {c(worst, worst)}")


def cmd_serve(args):
    from .web import serve

    serve(_detector(args), args.host, args.port)


def cmd_features(args):
    from .features import extract_features, refang

    feats = extract_features(refang(args.url))
    if args.all:
        print(json.dumps(feats, indent=2))
    else:
        for k, v in feats.items():
            if v not in (0, -1):
                print(f"{k:28s} {v}")


def cmd_train(args):
    from .train import train

    train(args.data, args.features, None if args.no_save else args.model, args.reports, args.cost_fn,
          plots=not args.no_plots)


def build_parser():
    default_model = str(Path(__file__).resolve().parent.parent / "models" / "url_tree.joblib")
    p = argparse.ArgumentParser(prog="phishdetect", description="Phishing URL detection with a decision tree")
    p.add_argument("--model", default=default_model, help="model bundle (.joblib)")
    p.add_argument("--allowlist", help="file with extra trusted domains, one per line")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan one or more URLs")
    s.add_argument("urls", nargs="*")
    s.add_argument("-f", "--file", help="file with one URL per line ('-' = stdin)")
    s.add_argument("-o", "--output", help="write a .csv or .json report")
    s.add_argument("--json", action="store_true", help="JSON on stdout")
    s.add_argument("--explain", action="store_true", help="print the decision path in the tree")
    s.add_argument("--defang", action="store_true", help="defang URLs in the output")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("interactive", aliases=["i"], help="paste URLs one by one")
    s.set_defaults(func=cmd_interactive)

    s = sub.add_parser("eml", help="extract and scan every link of an .eml file")
    s.add_argument("file")
    s.add_argument("-o", "--output")
    s.add_argument("--explain", action="store_true")
    s.add_argument("--defang", action="store_true")
    s.set_defaults(func=cmd_eml)

    s = sub.add_parser("serve", help="local web UI and JSON API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("features", help="dump the lexical features of a URL")
    s.add_argument("url")
    s.add_argument("--all", action="store_true", help="include zero / -1 values")
    s.set_defaults(func=cmd_features)

    s = sub.add_parser("train", help="train the tree on the Vrbancic et al. CSV")
    s.add_argument("--data", required=True)
    s.add_argument("--features", choices=["lexical", "lab26", "full"], default="lexical")
    s.add_argument("--cost-fn", type=int, default=20, help="cost of a missed phish vs a false block")
    s.add_argument("--reports", default="reports")
    s.add_argument("--no-save", action="store_true", help="evaluate only, do not overwrite the model")
    s.add_argument("--no-plots", action="store_true")
    s.set_defaults(func=cmd_train)
    return p


def main(argv=None):
    # Homoglyph hosts must never crash a cp1252 console; show them escaped instead.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
