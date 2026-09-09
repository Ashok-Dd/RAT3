"""
export_models_for_android.py
────────────────────────────────────────────────────────────────────────────
Converts the trained scikit-learn / XGBoost model bundles into compact JSON
that the Kotlin on-device evaluator (android/.../scanner/ml/) can run offline.

Run once on a dev machine:
    pip install scikit-learn==1.6.1 xgboost joblib numpy
    python export_models_for_android.py

Outputs:
    ../android/app/src/main/assets/ml/feature_list.json     (241 names, canonical order)
    ../android/app/src/main/assets/ml/variance_mask.json    (241 bools; VarianceThreshold support)
    ../android/app/src/main/assets/ml/random_forest.json
    ../android/app/src/main/assets/ml/decision_tree.json
    ../android/app/src/main/assets/ml/adaboost.json
    ../android/app/src/main/assets/ml/xgboost.json
    ./parity_samples.json   (feature vectors + expected probs — Kotlin parity test oracle)

Every model classifies an APK as goodware(0) / malware(1) from the 199 features
that survive VarianceThreshold. Stacking stays server-only (see main()).
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")

import joblib  # noqa: E402

HERE = Path(__file__).parent
MODELS = HERE / "models"
ASSETS = HERE.parent / "android" / "app" / "src" / "main" / "assets" / "ml"
ASSETS.mkdir(parents=True, exist_ok=True)

BUNDLES = {
    "random_forest": MODELS / "random_forest" / "rf_model.pkl",
    "decision_tree": MODELS / "decision_tree" / "dt_model.pkl",
    "adaboost": MODELS / "adaboost" / "adaboost_model.pkl",
    "xgboost": MODELS / "xgboost" / "xgb_model.pkl",
    "stacking": MODELS / "stacking" / "stacking_model.pkl",
}


# ── sklearn tree → node arrays ────────────────────────────────────────────────
def sk_tree(tree) -> dict:
    t = tree.tree_
    # value: (n_nodes, 1, n_classes) counts → store normalised malware prob per node
    val = t.value.reshape(t.value.shape[0], -1)
    prob = (val[:, 1] / np.clip(val.sum(axis=1), 1e-9, None)).tolist()
    return {
        "feat": t.feature.astype(int).tolist(),      # -2 for leaves
        "thr": t.threshold.astype(float).tolist(),
        "left": t.children_left.astype(int).tolist(),
        "right": t.children_right.astype(int).tolist(),
        "prob": [round(p, 6) for p in prob],          # P(malware) at each node
    }


def sk_forest(model, combine: str, weights=None) -> dict:
    estimators = getattr(model, "estimators_", None) or [model]
    return {
        "kind": "tree_ensemble",
        "combine": combine,                            # "avg" | "samme"
        "weights": (list(weights) if weights is not None else None),
        "trees": [sk_tree(e) for e in estimators],
    }


# ── XGBoost booster dump → node arrays ───────────────────────────────────────
def xgb_model(clf) -> dict:
    booster = clf.get_booster()
    dumps = booster.get_dump(dump_format="json", with_stats=False)
    feat_names = booster.feature_names  # ["f0","f1",...] or None
    trees = []
    for d in dumps:
        raw = json.loads(d)
        feat, thr, left, right, leaf = [], [], [], [], []

        def walk(node) -> int:
            idx = len(feat)
            feat.append(-2); thr.append(0.0); left.append(-1); right.append(-1); leaf.append(0.0)
            if "leaf" in node:
                leaf[idx] = float(node["leaf"])
                return idx
            fid = node["split"]
            if isinstance(fid, str) and fid.startswith("f"):
                fid = int(fid[1:])
            elif feat_names and fid in feat_names:
                fid = feat_names.index(fid)
            feat[idx] = int(fid)
            thr[idx] = float(node["split_condition"])
            kids = {c["nodeid"]: c for c in node["children"]}
            yes, no = node["yes"], node["no"]
            left[idx] = walk(kids[yes])    # xgb: "yes" = feature < threshold
            right[idx] = walk(kids[no])
            return idx

        walk(raw)
        trees.append({"feat": feat, "thr": thr, "left": left, "right": right, "leaf": leaf})

    cfg = json.loads(booster.save_config())
    raw = cfg["learner"]["learner_model_param"]["base_score"]
    base = float(str(raw).strip("[]").split(",")[0])   # probability space (~0.5)
    return {"kind": "xgboost", "base_score": base, "trees": trees}





def main() -> None:
    bundles = {n: joblib.load(p) for n, p in BUNDLES.items()}
    le = bundles["random_forest"]["label_encoder"]
    classes = list(le.classes_)
    assert classes == ["goodware", "malware"], classes

    vt = bundles["random_forest"]["variance_filter"]
    mask = vt.get_support().tolist()
    (ASSETS / "variance_mask.json").write_text(json.dumps([bool(m) for m in mask]))

    # feature_list.json (canonical 241 order)
    fl = json.loads((MODELS / "feature_list.json").read_text())
    assert len(fl) == 241, len(fl)
    (ASSETS / "feature_list.json").write_text(json.dumps(fl))

    rf = bundles["random_forest"]["model"]
    dt = bundles["decision_tree"]["model"]
    ada = bundles["adaboost"]["model"]
    xgb = bundles["xgboost"]["model"]

    (ASSETS / "random_forest.json").write_text(json.dumps(sk_forest(rf, "avg")))
    (ASSETS / "decision_tree.json").write_text(json.dumps(sk_forest(dt, "avg")))
    (ASSETS / "adaboost.json").write_text(
        json.dumps(sk_forest(ada, "samme", ada.estimator_weights_))
    )
    (ASSETS / "xgboost.json").write_text(json.dumps(xgb_model(xgb)))

    # NOTE: the Stacking ensemble is intentionally NOT exported for on-device use.
    # Its KNN base learner is fitted on a 5704-row SMOTE-resampled training set
    # with non-binary interpolated features — impractical to bundle faithfully.
    # Stacking remains available in the Flask app (ml/app.py) only.
    on_device = {k: v for k, v in bundles.items() if k != "stacking"}
    _write_parity_samples(on_device, vt, fl)
    print("Exported models to", ASSETS)


def _write_parity_samples(bundles, vt, feature_list, n=30):
    rng = np.random.RandomState(7)
    # Also fold in real TUANDROMD rows so the oracle covers genuine malware/goodware.
    real_vecs = []
    try:
        import pandas as pd
        csv = next(p for p in [HERE / "Data" / "TUANDROMD.csv", HERE / "TUANDROMD.csv"] if p.exists())
        d = pd.read_csv(csv).dropna(subset=["Label"]).drop(columns=["Label"]).fillna(0)
        idx = rng.choice(len(d), size=12, replace=False)
        real_vecs = [d.iloc[i].to_numpy(dtype=float)[:241] for i in idx]
    except Exception as e:  # noqa: BLE001
        print("parity: no real rows —", e)

    samples = []
    for i in range(n + len(real_vecs)):
        if i < len(real_vecs):
            vec = real_vecs[i]
        else:
            density = rng.uniform(0.05, 0.55)
            vec = (rng.rand(241) < density).astype(float)
        row = {"vector": [int(v) for v in vec], "models": {}}
        X = vt.transform(vec.reshape(1, -1))
        probs = []
        preds = []
        for name, b in bundles.items():
            p = float(b["model"].predict_proba(X)[0][1])
            row["models"][name] = round(p, 5)
            probs.append(p * 100)
            preds.append("malware" if p >= 0.5 else "goodware")
        mal = preds.count("malware")
        good = preds.count("goodware")
        row["ensemble"] = {
            "verdict": "malware" if mal >= good else "goodware",
            "score": round(sum(probs) / len(probs), 1),
            "mal_votes": mal,
            "good_votes": good,
        }
        samples.append(row)
    (HERE / "parity_samples.json").write_text(json.dumps(samples, indent=1))


if __name__ == "__main__":
    main()
