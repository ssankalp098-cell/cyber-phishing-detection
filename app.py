import os
import json
import warnings
warnings.filterwarnings("ignore")
import joblib
import pandas as pd
from flask import Flask, render_template, request, jsonify

from feature_extraction import (
    extract_features,
    get_feature_details,
    check_typosquatting,
    evaluate_security_threat,
    FEATURE_NAMES
)

app = Flask(__name__)

# Global model state
MODELS = {}
METRICS = {}
FEATURE_COLS = FEATURE_NAMES


def load_all_models():
    global MODELS, METRICS
    if os.path.exists("phishing_models_bundle.pkl"):
        try:
            bundle = joblib.load("phishing_models_bundle.pkl")
            MODELS = bundle.get("models", {})
        except Exception as e:
            print(f"Error loading bundle: {e}")

    if not MODELS and os.path.exists("phishing_model.pkl"):
        try:
            MODELS["random_forest"] = joblib.load("phishing_model.pkl")
        except Exception as e:
            print(f"Error loading fallback model: {e}")

    if os.path.exists("models_metrics.json"):
        try:
            with open("models_metrics.json", "r") as f:
                METRICS = json.load(f)
        except Exception as e:
            print(f"Error loading metrics: {e}")


# Initialize models on startup
load_all_models()


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    result_class = ""
    url = ""
    selected_model_key = "all"
    selected_model_info = None
    confidence = None
    feature_details = None
    multi_model_results = []
    consensus_summary = None
    typosquat_info = None
    threat_intel = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        selected_model_key = request.form.get("model", "all")

        if url:
            if not (url.startswith("http://") or url.startswith("https://") or url.startswith("ftp://")):
                analyzed_url = "http://" + url
            else:
                analyzed_url = url

            features = extract_features(analyzed_url)
            df_features = pd.DataFrame([features], columns=FEATURE_COLS)
            feature_details = get_feature_details(analyzed_url)
            threat_intel = evaluate_security_threat(analyzed_url)
            typosquat_info = threat_intel["typosquat_info"]
            is_threat = threat_intel["is_threat"]

            # Check if all models or single model selected
            if selected_model_key == "all" and MODELS:
                phishing_votes = 0
                total_votes = len(MODELS)

                for key, mdl in MODELS.items():
                    try:
                        pred = int(mdl.predict(df_features)[0])
                        proba = mdl.predict_proba(df_features)[0]
                        conf = round(float(max(proba)) * 100, 1)
                        phish_prob = round(float(proba[1]) * 100, 1)
                    except Exception:
                        pred = int(mdl.predict(df_features)[0])
                        conf = 95.0
                        phish_prob = 100.0 if pred == 1 else 0.0

                    # If threat intelligence / typosquatting detected, factor into threat analysis
                    if is_threat:
                        pred = 1
                        phish_prob = max(phish_prob, float(threat_intel["threat_score"]))
                        conf = max(conf, float(threat_intel["threat_score"]))

                    if pred == 1:
                        phishing_votes += 1

                    meta = METRICS.get(key, {})
                    multi_model_results.append({
                        "key": key,
                        "name": meta.get("name", key.replace("_", " ").title()),
                        "type": meta.get("type", "Classifier"),
                        "accuracy": meta.get("accuracy", "N/A"),
                        "prediction": "Phishing" if pred == 1 else "Legitimate",
                        "is_phishing": pred == 1,
                        "confidence": conf,
                        "phishing_probability": phish_prob
                    })

                consensus_pct = round((phishing_votes / total_votes) * 100, 1)
                is_consensus_phish = phishing_votes > (total_votes / 2) or is_threat

                if is_threat:
                    verdict_msg = "CRITICAL RISK - MALICIOUS PHISHING DETECTED"
                    if typosquat_info["is_typosquat"]:
                        verdict_msg = f"CRITICAL RISK - BRAND TYPOSQUATTING ATTACK ({typosquat_info['target_brand']})"
                    elif threat_intel["threat_reasons"]:
                        verdict_msg = f"CRITICAL RISK - {threat_intel['threat_reasons'][0].upper()}"

                    consensus_summary = {
                        "phishing_votes": total_votes,
                        "safe_votes": 0,
                        "total_votes": total_votes,
                        "phishing_percentage": 100.0,
                        "verdict": verdict_msg
                    }
                    result = "⚠️ MALICIOUS PHISHING THREAT DETECTED!"
                    result_class = "danger"
                    confidence = float(threat_intel["threat_score"])
                elif is_consensus_phish:
                    consensus_summary = {
                        "phishing_votes": phishing_votes,
                        "safe_votes": total_votes - phishing_votes,
                        "total_votes": total_votes,
                        "phishing_percentage": consensus_pct,
                        "verdict": "CRITICAL RISK - PHISHING DETECTED"
                    }
                    result = "⚠️ PHISHING THREAT DETECTED!"
                    result_class = "danger"
                    confidence = consensus_pct
                else:
                    consensus_summary = {
                        "phishing_votes": phishing_votes,
                        "safe_votes": total_votes - phishing_votes,
                        "total_votes": total_votes,
                        "phishing_percentage": consensus_pct,
                        "verdict": "SAFE - LEGITIMATE WEBSITE"
                    }
                    result = "✅ LEGITIMATE SAFE URL"
                    result_class = "safe"
                    confidence = round(100 - consensus_pct, 1)

            else:
                # Single Model Prediction
                target_key = selected_model_key if selected_model_key in MODELS else list(MODELS.keys())[0]
                mdl = MODELS.get(target_key)
                selected_model_info = METRICS.get(target_key, {"name": target_key})

                if mdl:
                    pred = int(mdl.predict(df_features)[0])
                    try:
                        probabilities = mdl.predict_proba(df_features)[0]
                        confidence = round(float(max(probabilities)) * 100, 1)
                    except Exception:
                        confidence = 98.0

                    if is_threat:
                        pred = 1
                        confidence = float(threat_intel["threat_score"])

                    if pred == 1:
                        result = "⚠️ PHISHING / MALICIOUS DETECTED!"
                        result_class = "danger"
                    else:
                        result = "✅ LEGITIMATE URL"
                        result_class = "safe"

    return render_template(
        "index.html",
        result=result,
        result_class=result_class,
        url=url,
        selected_model=selected_model_key,
        selected_model_info=selected_model_info,
        confidence=confidence,
        feature_details=feature_details,
        multi_model_results=multi_model_results,
        consensus_summary=consensus_summary,
        available_models=METRICS,
        typosquat_info=typosquat_info,
        threat_intel=threat_intel
    )


@app.route("/api/predict", methods=["POST"])
def api_predict():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    model_key = data.get("model", "all")

    if not url:
        return jsonify({"error": "Missing 'url' field in request body"}), 400

    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("ftp://")):
        url = "http://" + url

    features = extract_features(url)
    df_features = pd.DataFrame([features], columns=FEATURE_COLS)
    feature_details = get_feature_details(url)
    threat_intel = evaluate_security_threat(url)

    results = {}
    for key, mdl in MODELS.items():
        pred = int(mdl.predict(df_features)[0])
        try:
            proba = mdl.predict_proba(df_features)[0]
            conf = round(float(max(proba)) * 100, 2)
            phish_proba = round(float(proba[1]) * 100, 2)
        except Exception:
            conf = 95.0
            phish_proba = 100.0 if pred == 1 else 0.0

        if threat_intel["is_threat"]:
            pred = 1
            phish_proba = max(phish_proba, float(threat_intel["threat_score"]))
            conf = max(conf, float(threat_intel["threat_score"]))

        results[key] = {
            "prediction": "Phishing" if pred == 1 else "Legitimate",
            "is_phishing": pred == 1,
            "confidence": conf,
            "phishing_probability": phish_proba
        }

    return jsonify({
        "url": url,
        "is_phishing": threat_intel["is_threat"] or any(r["is_phishing"] for r in results.values()),
        "results": results,
        "features": feature_details,
        "threat_intel": threat_intel
    })


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    return jsonify(METRICS)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)