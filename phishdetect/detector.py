"""
Scoring engine: decision tree probability + analyst rules -> verdict.

    risk = 1 - (1 - p_tree) * (1 - h)

p_tree is the share of phishing URLs in the tree leaf the URL lands in,
h is the noisy-OR of the rule weights (see heuristics.py). Either source
alone can push the risk up; a URL is only "clean" if both agree.
"""

from dataclasses import dataclass, field
from pathlib import Path

import joblib

from . import heuristics
from .features import defang, extract_features, refang, to_frame

DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "models" / "url_tree.joblib"

# Verdict bands on the combined risk.
SUSPICIOUS_AT = 0.40
PHISHING_AT = 0.70
# Minimum rule score needed to confirm a PHISHING verdict (one "medium" rule).
CORROBORATION = 0.25


@dataclass
class Report:
    url: str
    verdict: str
    risk: float
    tree_probability: float
    heuristic_score: float
    trusted: bool
    findings: list = field(default_factory=list)
    decision_path: list = field(default_factory=list)

    def to_dict(self, defanged=False):
        return {
            "url": defang(self.url) if defanged else self.url,
            "verdict": self.verdict,
            "risk": round(self.risk, 4),
            "tree_probability": round(self.tree_probability, 4),
            "heuristic_score": round(self.heuristic_score, 4),
            "trusted_domain": self.trusted,
            "findings": [{"rule": f.rule, "severity": f.severity, "detail": f.detail} for f in self.findings],
            "decision_path": self.decision_path,
        }


def load_bundle(path=None):
    path = Path(path or DEFAULT_MODEL)
    if not path.exists():
        raise FileNotFoundError(
            f"model not found: {path}\n"
            "train one first: python -m phishdetect train --data data/dataset_full.csv"
        )
    return joblib.load(path)


def decision_path(model, columns, row):
    """Human-readable list of the tests the tree applied to one sample."""
    tree = model.tree_
    steps = []
    for node in model.decision_path(row).indices:
        if tree.children_left[node] == -1:
            counts = tree.value[node][0]
            share = counts[1] / counts.sum()
            steps.append(f"leaf #{node}: {share:.0%} of training URLs here were phishing")
        else:
            col = columns[tree.feature[node]]
            thr = tree.threshold[node]
            val = row.iloc[0][col]
            op = "<=" if val <= thr else ">"
            steps.append(f"{col} = {val:g} {op} {thr:.2f}")
    return steps


class Detector:
    def __init__(self, model_path=None, allowlist=(), suspicious_at=SUSPICIOUS_AT, phishing_at=PHISHING_AT):
        bundle = load_bundle(model_path)
        self.model = bundle["model"]
        self.columns = bundle["columns"]
        self.meta = bundle.get("meta", {})
        self.allowlist = set(allowlist)
        self.suspicious_at = suspicious_at
        self.phishing_at = phishing_at

    def scan(self, url):
        url = refang(url)
        row = to_frame([url], self.columns)
        p_tree = float(self.model.predict_proba(row)[0, 1])
        findings = heuristics.analyze(url)
        h = heuristics.heuristic_score(findings)
        risk = 1 - (1 - p_tree) * (1 - h)

        trusted = heuristics.is_trusted(url, self.allowlist)
        strong = any(f.severity in ("high", "critical") for f in findings)
        if trusted and not strong:
            # Known-good registrable domain: the tree's "has a path" bias
            # (see README, Limitations) should not block a Wikipedia article.
            risk = min(risk, h)

        corroborated = h >= CORROBORATION
        if risk >= self.phishing_at and not corroborated:
            # Tree-only alert. On this dataset the tree mostly learned
            # "URL has a path -> phishing" (legit samples are homepages),
            # so a structural signal alone is sent to review, not blocked.
            findings.append(heuristics.Finding(
                "model_only", "info",
                "tree flags the URL structure but no rule corroborates it; analyst review"))
            verdict = "SUSPICIOUS"
        elif risk >= self.phishing_at:
            verdict = "PHISHING"
        elif risk >= self.suspicious_at:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return Report(
            url=url,
            verdict=verdict,
            risk=risk,
            tree_probability=p_tree,
            heuristic_score=h,
            trusted=trusted,
            findings=sorted(findings, key=lambda f: -f.weight),
            decision_path=decision_path(self.model, self.columns, row),
        )

    def features(self, url):
        return extract_features(refang(url))
