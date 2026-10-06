import sys
import os
import warnings
warnings.filterwarnings("ignore")
import joblib
import pandas as pd
from feature_extraction import (
    extract_features,
    get_feature_details,
    check_typosquatting,
    evaluate_security_threat,
    FEATURE_NAMES
)


def load_model_suite():
    if os.path.exists("phishing_models_bundle.pkl"):
        bundle = joblib.load("phishing_models_bundle.pkl")
        return bundle.get("models", {}), bundle.get("metrics", {})
    elif os.path.exists("phishing_model.pkl"):
        model = joblib.load("phishing_model.pkl")
        return {"default": model}, {}
    else:
        raise FileNotFoundError("No trained model files found. Please run train_model.py first.")


def predict_url(url: str, model_name: str = "ensemble"):
    models, metrics = load_model_suite()
    features = extract_features(url)
    df_features = pd.DataFrame([features], columns=FEATURE_NAMES)
    threat_intel = evaluate_security_threat(url)
    is_threat = threat_intel["is_threat"]
    
    print("\n" + "=" * 60)
    print(f"[*] Target URL: {url}")
    if threat_intel["threat_reasons"]:
        print("[*] THREAT INTELLIGENCE WARNINGS:")
        for r in threat_intel["threat_reasons"]:
            print(f"    - {r}")
    print("=" * 60)

    if model_name == "all":
        print("\n--- [MULTI-MODEL PREDICTION COMPARISON] ---")
        phish_votes = 0
        total_votes = 0

        for key, model in models.items():
            pred = model.predict(df_features)[0]
            proba = model.predict_proba(df_features)[0]
            conf = max(proba) * 100
            
            if is_threat:
                pred = 1
                conf = max(conf, float(threat_intel["threat_score"]))

            label = "PHISHING [!]" if pred == 1 else "LEGITIMATE [OK]"
            
            if pred == 1:
                phish_votes += 1
            total_votes += 1

            display_name = metrics.get(key, {}).get("name", key.capitalize())
            print(f"  {display_name:<30} -> {label:<18} (Confidence: {conf:5.1f}%)")

        print("-" * 60)
        consensus = (phish_votes / total_votes) * 100
        print(f"  CONSENSUS VERDICT: {phish_votes}/{total_votes} models flagged as PHISHING ({consensus:.1f}%)")
        overall = "[!] PHISHING DETECTED (MALICIOUS THREAT)" if is_threat else ("[!] PHISHING DETECTED" if phish_votes > total_votes / 2 else "[SAFE] LEGITIMATE URL")
        print(f"  FINAL RESULT: {overall}")
        print("=" * 60)
        return overall

    else:
        chosen_key = model_name if model_name in models else list(models.keys())[0]
        model = models[chosen_key]
        pred = model.predict(df_features)[0]
        proba = model.predict_proba(df_features)[0]
        conf = round(max(proba) * 100, 2)
        if is_threat:
            pred = 1
            conf = float(threat_intel["threat_score"])
        model_display = metrics.get(chosen_key, {}).get("name", chosen_key)

        print(f"Using Model: {model_display}")
        print(f"Prediction : {'[!] PHISHING / MALICIOUS DETECTED' if pred == 1 else '[SAFE] LEGITIMATE URL'}")
        print(f"Confidence : {conf}%")
        print("=" * 60)
        return "PHISHING" if pred == 1 else "LEGITIMATE"


if __name__ == "__main__":
    test_url = input("\nEnter URL: ").strip()
    if not test_url:
        print("No URL provided.")
        sys.exit(0)

    mode = input("Select Model (all / ensemble / random_forest / svm / etc.) [default: all]: ").strip().lower()
    if not mode:
        mode = "all"

    predict_url(test_url, mode)