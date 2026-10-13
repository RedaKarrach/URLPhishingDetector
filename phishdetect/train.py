"""
Training pipeline:

  1. drop duplicate rows and constant columns
  2. stratified 80/20 split (random_state=42)
  3. GridSearchCV on the TRAIN set only, 5-fold, scoring = F1 on phishing
  4. evaluation on TEST: metrics, confusion matrix, FPR / FNR
  5. cost-based threshold table (a missed phish costs COST_FN x a false block)
  6. per-subgroup check (URLs with / without a path)
  7. export: model bundle, metrics JSON, tree rules, plots
"""

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

from .features import LAB_URL_COLUMNS, LEXICAL_COLUMNS, NETWORK_COLUMNS

FEATURE_SETS = {
    # Offline, computable from the URL string -> usable by the scanner.
    "lexical": LEXICAL_COLUMNS,
    # The 26 URL-text columns of the original notebook.
    "lab26": LAB_URL_COLUMNS,
    # Everything, including WHOIS/DNS/HTTP columns. Benchmark only:
    # the scanner cannot rebuild these offline.
    "full": LEXICAL_COLUMNS + NETWORK_COLUMNS,
}

GRID = {
    "max_depth": [6, 8, 10, 12, 15, None],
    "min_samples_leaf": [1, 5, 20],
    "criterion": ["gini", "entropy"],
}


def _metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "fnr": fn / (fn + tp) if fn + tp else 0.0,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def _round(obj):
    if isinstance(obj, dict):
        return {k: _round(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round(v) for v in obj]
    if isinstance(obj, (float, np.floating)):
        return round(float(obj), 4)
    if isinstance(obj, np.integer):
        return int(obj)
    return obj


def load_dataset(path):
    df = pd.read_csv(path)
    if "phishing" not in df.columns:
        raise ValueError("expected the Vrbancic et al. CSV with a 'phishing' target column")
    n0 = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    constant = [c for c in df.columns if df[c].nunique() == 1]
    df = df.drop(columns=constant)
    return df, {"rows_raw": n0, "rows_dedup": len(df), "constant_columns": constant}


def cost_table(y_true, proba, cost_fn, cost_fp=1):
    rows = []
    for t in np.round(np.arange(0.1, 0.91, 0.1), 2):
        pred = (proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        rows.append({
            "threshold": float(t), "fp": int(fp), "fn": int(fn),
            "recall": tp / (tp + fn), "precision": tp / (tp + fp) if tp + fp else 0.0,
            "cost": int(fn * cost_fn + fp * cost_fp),
        })
    return rows


def save_plots(out_dir, model, columns, X_test, y_test, y_pred, importances):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay
    from sklearn.tree import plot_tree

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    ConfusionMatrixDisplay(cm, display_labels=["LEGIT", "PHISHING"]).plot(
        ax=axes[0], cmap="Blues", values_format="d", colorbar=False)
    axes[0].set_title("Confusion matrix (counts)")
    cmn = confusion_matrix(y_test, y_pred, labels=[0, 1], normalize="true")
    ConfusionMatrixDisplay(cmn, display_labels=["LEGIT", "PHISHING"]).plot(
        ax=axes[1], cmap="Blues", values_format=".1%", colorbar=False)
    axes[1].set_title("Normalized by true class")
    fig.tight_layout()
    fig.savefig(out_dir / "confusion_matrix.png", dpi=120)
    plt.close(fig)

    top = importances.head(15).sort_values()
    fig, ax = plt.subplots(figsize=(8, 6))
    top.plot.barh(ax=ax, color="steelblue")
    ax.set_title("Top 15 features (Gini importance)")
    fig.tight_layout()
    fig.savefig(out_dir / "feature_importance.png", dpi=120)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(22, 9))
    plot_tree(model, max_depth=3, feature_names=columns, class_names=["Legit", "Phishing"],
              filled=True, rounded=True, fontsize=9, ax=ax)
    ax.set_title("Top of the trained tree (first 3 levels)")
    fig.tight_layout()
    fig.savefig(out_dir / "tree_top.png", dpi=110)
    plt.close(fig)


def train(data, feature_set="lexical", out_model=None, report_dir="reports", cost_fn=20, plots=True, log=print):
    df, prep = load_dataset(data)
    columns = [c for c in FEATURE_SETS[feature_set] if c in df.columns]
    log(f"[+] {prep['rows_raw']} rows -> {prep['rows_dedup']} after dedup, "
        f"{len(prep['constant_columns'])} constant columns dropped, {len(columns)} features ({feature_set})")

    X, y = df[columns], df["phishing"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

    log(f"[+] grid search: {np.prod([len(v) for v in GRID.values()])} combinations x 5 folds")
    t0 = time.time()
    search = GridSearchCV(DecisionTreeClassifier(random_state=42), GRID, cv=5, scoring="f1", n_jobs=-1)
    search.fit(X_train, y_train)
    model = search.best_estimator_
    log(f"[+] best params {search.best_params_} (CV F1 {search.best_score_:.4f}, {time.time() - t0:.0f}s)")

    y_pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    test = _metrics(y_test, y_pred)
    train_acc = accuracy_score(y_train, model.predict(X_train))

    table = cost_table(y_test, proba, cost_fn)
    best_t = min(table, key=lambda r: r["cost"])["threshold"]

    subgroups = {}
    if "directory_length" in X_test.columns:
        no_path = (X_test["directory_length"] == -1).values
        for name, mask in (("without_path", no_path), ("with_path", ~no_path)):
            m = _metrics(y_test[mask], y_pred[mask])
            m["n"] = int(mask.sum())
            m["phishing_share"] = float(y_test[mask].mean())
            subgroups[name] = m

    importances = pd.Series(model.feature_importances_, index=columns).sort_values(ascending=False)

    report = _round({
        "dataset": {**prep, "file": Path(data).name, "phishing_share": float(y.mean())},
        "feature_set": feature_set,
        "n_features": len(columns),
        "best_params": search.best_params_,
        "cv_f1": search.best_score_,
        "tree": {"depth": model.get_depth(), "leaves": model.get_n_leaves()},
        "train_accuracy": train_acc,
        "test": test,
        "cost_fn_vs_fp": cost_fn,
        "threshold_table": table,
        "cost_optimal_threshold": best_t,
        "subgroups": subgroups,
        "top_features": importances.head(15).to_dict(),
        "unused_features": int((importances == 0).sum()),
    })

    out = Path(report_dir) / feature_set
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "tree_rules.txt").write_text(
        export_text(model, feature_names=columns, show_weights=True, max_depth=6), encoding="utf-8")
    if plots:
        save_plots(out, model, columns, X_test, y_test, y_pred, importances)

    if out_model and feature_set != "full":
        import joblib
        out_model = Path(out_model)
        out_model.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": model,
            "columns": columns,
            "meta": {
                "feature_set": feature_set,
                "params": search.best_params_,
                "test_f1": report["test"]["f1"],
                "cost_optimal_threshold": best_t,
                "trained": time.strftime("%Y-%m-%d"),
            },
        }, out_model, compress=3)
        log(f"[+] model saved to {out_model}")

    log(f"[+] TEST  acc {test['accuracy']:.4f}  prec {test['precision']:.4f}  "
        f"rec {test['recall']:.4f}  f1 {test['f1']:.4f}  FPR {test['fpr']:.4f}  FNR {test['fnr']:.4f}")
    log(f"[+] cost-optimal threshold (FN = {cost_fn} x FP): {best_t}")
    for name, m in subgroups.items():
        log(f"    {name:13s} n={m['n']:6d}  acc {m['accuracy']:.3f}  recall {m['recall']:.3f}  FPR {m['fpr']:.3f}")
    log(f"[+] reports written to {out}")
    return model, report
