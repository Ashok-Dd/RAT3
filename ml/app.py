"""
app.py – Flask APK Malware Detection Interface
================================================
Routes:
  GET  /                    → APK upload page
  POST /analyze             → analyze uploaded APK → JSON
  GET  /result/<job_id>     → result page
  GET  /test                → manual feature tester (NEW)
  POST /api/test-features   → run models on manual feature vector (NEW)
  GET  /models              → model info page
  GET  /api/features        → feature list JSON
"""

import os
import uuid
import json
import time
import traceback
import numpy as np
from pathlib import Path
from flask import (Flask, render_template, request,
                   jsonify, redirect, url_for)
from werkzeug.utils import secure_filename
import joblib

from apk_extractor import feature_vector, FEATURE_LIST

# ─────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
MODEL_DIR     = BASE_DIR / "models"
ALLOWED_EXT   = {"apk"}
MAX_MB        = 100

UPLOAD_FOLDER.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["UPLOAD_FOLDER"]      = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024

JOBS: dict = {}

# ─────────────────────────────────────────────────────────
# Load models
# ─────────────────────────────────────────────────────────
MODELS: dict = {}

def load_models():
    specs = {
        "Random Forest": "random_forest/rf_model.pkl",
        "Decision Tree": "decision_tree/dt_model.pkl",
        "XGBoost":       "xgboost/xgb_model.pkl",
        "AdaBoost":      "adaboost/adaboost_model.pkl",
        "Stacking":      "stacking/stacking_model.pkl",
    }
    for name, rel_path in specs.items():
        full = MODEL_DIR / rel_path
        if full.exists():
            try:
                MODELS[name] = joblib.load(full)
                print(f"  ✓ Loaded {name}")
            except Exception as e:
                print(f"  ✗ Failed to load {name}: {e}")
        else:
            print(f"  ⚠  Model not found: {full}  (train first)")

load_models()

# ─────────────────────────────────────────────────────────
# Helpers  (shared by APK route and manual-test route)
# ─────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def run_models(vector: list) -> dict:
    """Run all loaded models on a 241-element feature vector."""
    X = np.array(vector, dtype=np.float32).reshape(1, -1)
    results = {}
    for name, bundle in MODELS.items():
        try:
            model = bundle["model"]
            le    = bundle["label_encoder"]
            vt    = bundle.get("variance_filter")
            X_in  = vt.transform(X) if vt is not None else X

            proba      = model.predict_proba(X_in)[0]
            pred_idx   = int(np.argmax(proba))
            pred_label = le.inverse_transform([pred_idx])[0]

            classes      = list(le.classes_)
            mal_idx      = classes.index("malware") if "malware" in classes else 1
            malware_prob = float(proba[mal_idx])

            results[name] = {
                "prediction":    pred_label,
                "malware_prob":  round(malware_prob * 100, 2),
                "goodware_prob": round((1 - malware_prob) * 100, 2),
                "confidence":    round(float(max(proba)) * 100, 2),
            }
        except Exception as e:
            results[name] = {"error": str(e)}
    return results


def ensemble_verdict(model_results: dict) -> dict:
    """Majority-vote ensemble across all models."""
    preds, probs = [], []
    for r in model_results.values():
        if "error" not in r:
            preds.append(r["prediction"])
            probs.append(r["malware_prob"])

    if not preds:
        return {"verdict": "unknown", "score": 0, "risk_level": "Unknown",
                "confidence": 0, "mal_votes": 0, "good_votes": 0, "total_models": 0}

    mal_votes  = preds.count("malware")
    good_votes = preds.count("goodware")
    avg_prob   = round(sum(probs) / len(probs), 2)
    verdict    = "malware" if mal_votes >= good_votes else "goodware"
    confidence = round(max(mal_votes, good_votes) / len(preds) * 100, 1)
    risk_score = round(avg_prob, 1)
    risk_level = (
        "Critical" if risk_score >= 80 else
        "High"     if risk_score >= 60 else
        "Medium"   if risk_score >= 40 else
        "Low"      if risk_score >= 20 else
        "Safe"
    )
    return {
        "verdict":      verdict,
        "score":        risk_score,
        "risk_level":   risk_level,
        "confidence":   confidence,
        "mal_votes":    mal_votes,
        "good_votes":   good_votes,
        "total_models": len(preds),
    }


# ─────────────────────────────────────────────────────────
# Categorise features for the manual tester UI
# ─────────────────────────────────────────────────────────
DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECORD_AUDIO",
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "CALL_PHONE", "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS",
    "GET_ACCOUNTS", "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE",
    "SYSTEM_ALERT_WINDOW", "INSTALL_PACKAGES", "DELETE_PACKAGES",
    "RECEIVE_BOOT_COMPLETED", "CHANGE_WIFI_STATE", "ACCESS_SUPERUSER",
    "MASTER_CLEAR", "REBOOT", "BRICK", "MODIFY_PHONE_STATE",
}

def _categorise_features():
    """Split FEATURE_LIST into labelled groups for the UI."""
    groups = {
        "Dangerous Permissions": [],
        "Network & Connectivity": [],
        "Storage & Files": [],
        "System & Device": [],
        "Accounts & Sync": [],
        "Media & Sensors": [],
        "Other Permissions": [],
        "Dangerous API Calls": [],
    }
    net_kw   = {"NETWORK","WIFI","INTERNET","BLUETOOTH","NFC","CHANGE_NETWORK",
                "CHANGE_WIFI","ACCESS_WIFI","ACCESS_NETWORK"}
    stor_kw  = {"STORAGE","EXTERNAL_STORAGE","INTERNAL_STORAGE","WRITE_EXTERNAL",
                "READ_EXTERNAL","SDCARD","MOUNT","DELETE_CACHE","CLEAR_APP"}
    sys_kw   = {"SYSTEM","DEVICE","REBOOT","BRICK","MASTER_CLEAR","INJECT",
                "FACTORY","HARDWARE","INSTALL_PACKAGES","DELETE_PACKAGES",
                "CHANGE_COMPONENT","BIND_DEVICE","CHANGE_CONFIG","SET_TIME",
                "RECEIVE_BOOT","BOOT","SUPERUSER","MODIFY_PHONE","WAKE_LOCK"}
    acct_kw  = {"ACCOUNT","SYNC","AUTH","GET_ACCOUNTS","MANAGE_ACCOUNTS",
                "AUTHENTICATE"}
    media_kw = {"CAMERA","AUDIO","RECORD","MEDIA","VIBRATE","SENSOR","BODY_SENSOR",
                "FLASHLIGHT","TRANSMIT_IR"}

    for feat in FEATURE_LIST:
        if feat.startswith("L"):                           # API call
            groups["Dangerous API Calls"].append(feat)
        elif feat in DANGEROUS_PERMS:
            groups["Dangerous Permissions"].append(feat)
        elif any(k in feat for k in net_kw):
            groups["Network & Connectivity"].append(feat)
        elif any(k in feat for k in stor_kw):
            groups["Storage & Files"].append(feat)
        elif any(k in feat for k in sys_kw):
            groups["System & Device"].append(feat)
        elif any(k in feat for k in acct_kw):
            groups["Accounts & Sync"].append(feat)
        elif any(k in feat for k in media_kw):
            groups["Media & Sensors"].append(feat)
        else:
            groups["Other Permissions"].append(feat)

    return {k: v for k, v in groups.items() if v}   # drop empty groups

FEATURE_GROUPS = _categorise_features()


# ─────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           model_names=list(MODELS.keys()) or ["No models loaded"],
                           models_loaded=len(MODELS))


# ── APK upload & analyze ──────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    if "apk_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["apk_file"]
    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    if not allowed_file(f.filename):
        return jsonify({"error": "Only .apk files are accepted"}), 400
    if not MODELS:
        return jsonify({"error": "No models loaded. Train first."}), 503

    job_id   = str(uuid.uuid4())
    filename = secure_filename(f.filename)
    apk_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{job_id}_{filename}")
    f.save(apk_path)

    t0 = time.time()
    try:
        vec, metadata  = feature_vector(apk_path)
        extract_ms     = round((time.time() - t0) * 1000)
        t1             = time.time()
        model_results  = run_models(vec)
        infer_ms       = round((time.time() - t1) * 1000)
        verdict        = ensemble_verdict(model_results)

        active             = [FEATURE_LIST[i] for i, v in enumerate(vec) if v == 1.0]
        permissions_active = [f for f in active if not f.startswith("L") and f != "activityCalled"]
        apis_active        = [f for f in active if f.startswith("L")]

        result = {
            "job_id": job_id, "filename": filename,
            "apk_size_kb": metadata["_apk_size_kb"],
            "dex_count":   metadata["_dex_count"],
            "extract_error": metadata["_error"],
            "extract_ms": extract_ms, "infer_ms": infer_ms,
            "features_total": len(FEATURE_LIST), "features_active": len(active),
            "permissions_active": permissions_active, "apis_active": apis_active,
            "model_results": model_results, "verdict": verdict,
        }
        JOBS[job_id] = result
        try: os.remove(apk_path)
        except Exception: pass
        return jsonify(result)

    except Exception as e:
        try: os.remove(apk_path)
        except Exception: pass
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500


@app.route("/result/<job_id>")
def result_page(job_id):
    job = JOBS.get(job_id)
    if not job:
        return redirect(url_for("index"))
    return render_template("result.html", result=job)


# ── Manual feature tester (NEW) ───────────────────────────
@app.route("/test")
def test_page():
    """Render the manual feature-toggle testing page."""
    return render_template(
        "test.html",
        feature_groups=FEATURE_GROUPS,
        feature_list=FEATURE_LIST,
        dangerous_perms=list(DANGEROUS_PERMS),
        models_loaded=len(MODELS),
        model_names=list(MODELS.keys()),
        total_features=len(FEATURE_LIST),
    )


@app.route("/api/test-features", methods=["POST"])
def api_test_features():
    """
    Accept a JSON body of {feature_name: 0|1, ...} (sparse – missing = 0),
    build the full 241-vector, run all models, return verdict JSON.
    """
    if not MODELS:
        return jsonify({"error": "No models loaded. Train first."}), 503

    try:
        data = request.get_json(force=True) or {}

        # Build full vector (default 0 for any feature not provided)
        active_features = {k: int(bool(v)) for k, v in data.items()
                           if k in set(FEATURE_LIST)}
        vector = [float(active_features.get(f, 0)) for f in FEATURE_LIST]

        t0            = time.time()
        model_results = run_models(vector)
        infer_ms      = round((time.time() - t0) * 1000)
        verdict       = ensemble_verdict(model_results)

        active             = [FEATURE_LIST[i] for i, v in enumerate(vector) if v == 1.0]
        permissions_active = [f for f in active if not f.startswith("L") and f != "activityCalled"]
        apis_active        = [f for f in active if f.startswith("L")]

        return jsonify({
            "model_results":       model_results,
            "verdict":             verdict,
            "infer_ms":            infer_ms,
            "features_active":     len(active),
            "features_total":      len(FEATURE_LIST),
            "permissions_active":  permissions_active,
            "apis_active":         apis_active,
            "vector_preview":      vector[:20],   # first 20 for debugging
        })

    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500


# ── Models info ───────────────────────────────────────────
@app.route("/models")
def models_page():
    info = {}
    for name, bundle in MODELS.items():
        model = bundle["model"]
        info[name] = {
            "type":    type(model).__name__,
            "params":  {k: str(v) for k, v in model.get_params().items()
                        if k in ["n_estimators", "max_depth", "learning_rate",
                                 "n_features_in_", "max_features"]},
            "classes": list(bundle["label_encoder"].classes_),
        }
        if hasattr(model, "oob_score_"):
            info[name]["oob_score"] = round(model.oob_score_, 4)
    return render_template("models.html", models_info=info,
                           feature_count=len(FEATURE_LIST))


@app.route("/api/features")
def api_features():
    return jsonify({"features": FEATURE_LIST,
                    "groups": {k: v for k, v in FEATURE_GROUPS.items()},
                    "count": len(FEATURE_LIST)})


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too large. Max {MAX_MB} MB."}), 413


# ─────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  Android APK Malware Detector – Flask Interface")
    print("=" * 55)
    print(f"  Models loaded : {list(MODELS.keys()) or 'None'}")
    print(f"  Features      : {len(FEATURE_LIST)}")
    print(f"  Routes        : /  /test  /models  /api/features")
    print("=" * 55 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)