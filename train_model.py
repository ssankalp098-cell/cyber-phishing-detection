import os
import json
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from feature_extraction import extract_features, FEATURE_NAMES


def train_all_models():
    print("=" * 60)
    print("[*] CYBER PHISHING DETECTION - MULTI-MODEL TRAINING PIPELINE")
    print("=" * 60)

    # 1. Load Dataset
    dataset_path = "dataset/phishing_dataset.csv"
    if not os.path.exists(dataset_path):
        dataset_path = "dataset/phising_dataset.csv"

    data = pd.read_csv(dataset_path)
    print(f"\n[+] Loaded dataset from '{dataset_path}'")
    print(f"    Total Samples: {len(data)} (Legitimate: {sum(data['label'] == 0)}, Phishing: {sum(data['label'] == 1)})")

    # 2. Extract Features
    print("\n[+] Extracting URL security features...")
    X_raw = []
    y = []

    for _, row in data.iterrows():
        url = str(row["url"])
        label = int(row["label"])
        features = extract_features(url)
        X_raw.append(features)
        y.append(label)

    X = pd.DataFrame(X_raw, columns=FEATURE_NAMES)
    y = pd.Series(y)

    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )
    print(f"    Train size: {len(X_train)} | Test size: {len(X_test)}")

    # 4. Define Candidate ML Models
    # Using pipelines with StandardScaler for models sensitive to scale
    base_models = {
        "random_forest": {
            "name": "Random Forest",
            "type": "Ensemble (Bagging)",
            "description": "High accuracy ensemble using diverse decision trees with feature bagging.",
            "pipeline": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        },
        "gradient_boosting": {
            "name": "Gradient Boosting",
            "type": "Ensemble (Boosting)",
            "description": "Iterative boosting model that minimizes residual errors sequentially.",
            "pipeline": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, random_state=42)
        },
        "decision_tree": {
            "name": "Decision Tree",
            "type": "Tree-Based",
            "description": "Interpretable hierarchical decision rules for rapid classification.",
            "pipeline": DecisionTreeClassifier(max_depth=6, random_state=42)
        },
        "logistic_regression": {
            "name": "Logistic Regression",
            "type": "Linear Model",
            "description": "Probabilistic linear classifier with feature normalization.",
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", LogisticRegression(max_iter=1000, random_state=42))
            ])
        },
        "svm": {
            "name": "Support Vector Machine (SVM)",
            "type": "Kernel / Margin",
            "description": "Finds optimal hyperplane separator with calibrated probability estimation.",
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", SVC(probability=True, kernel="rbf", C=1.0, random_state=42))
            ])
        },
        "naive_bayes": {
            "name": "Naive Bayes (Gaussian)",
            "type": "Probabilistic",
            "description": "Fast Bayesian likelihood classifier assuming feature independence.",
            "pipeline": GaussianNB()
        },
        "knn": {
            "name": "K-Nearest Neighbors (KNN)",
            "type": "Instance-Based",
            "description": "Classifies URLs based on distance metrics to nearest neighbor samples.",
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", KNeighborsClassifier(n_neighbors=5))
            ])
        }
    }

    # 5. Train Base Models and Collect Metrics
    print("\n[+] Training and evaluating models...")
    trained_models = {}
    metrics_summary = {}

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for key, info in base_models.items():
        model = info["pipeline"]
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        
        # Cross-validation score
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy")
        cv_mean = float(np.mean(cv_scores))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        trained_models[key] = model
        metrics_summary[key] = {
            "key": key,
            "name": info["name"],
            "type": info["type"],
            "description": info["description"],
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "cv_accuracy": round(cv_mean * 100, 2),
            "confusion_matrix": cm
        }
        
        print(f"    [+] {info['name']:<28} | Acc: {acc*100:5.1f}% | Prec: {prec*100:5.1f}% | Rec: {rec*100:5.1f}% | F1: {f1*100:5.1f}% | CV: {cv_mean*100:5.1f}%")

    # 6. Build Ensemble Soft Voting Classifier
    print("\n[+] Building Ensemble Voting Classifier...")
    ensemble_estimators = [
        ("rf", trained_models["random_forest"]),
        ("gb", trained_models["gradient_boosting"]),
        ("dt", trained_models["decision_tree"]),
        ("lr", trained_models["logistic_regression"]),
        ("svm", trained_models["svm"]),
        ("knn", trained_models["knn"])
    ]
    
    ensemble = VotingClassifier(estimators=ensemble_estimators, voting="soft")
    ensemble.fit(X_train, y_train)
    
    y_pred_ens = ensemble.predict(X_test)
    acc_ens = float(accuracy_score(y_test, y_pred_ens))
    prec_ens = float(precision_score(y_test, y_pred_ens, zero_division=0))
    rec_ens = float(recall_score(y_test, y_pred_ens, zero_division=0))
    f1_ens = float(f1_score(y_test, y_pred_ens, zero_division=0))
    cv_scores_ens = cross_val_score(ensemble, X, y, cv=cv, scoring="accuracy")
    cv_mean_ens = float(np.mean(cv_scores_ens))

    trained_models["ensemble"] = ensemble
    metrics_summary["ensemble"] = {
        "key": "ensemble",
        "name": "Ensemble Voting (Soft Consensus)",
        "type": "Meta-Classifier Ensemble",
        "description": "Combines weighted probabilistic predictions from Random Forest, Gradient Boost, SVM, and LR.",
        "accuracy": round(acc_ens * 100, 2),
        "precision": round(prec_ens * 100, 2),
        "recall": round(rec_ens * 100, 2),
        "f1_score": round(f1_ens * 100, 2),
        "cv_accuracy": round(cv_mean_ens * 100, 2),
        "confusion_matrix": confusion_matrix(y_test, y_pred_ens).tolist()
    }
    print(f"    [+] {'Ensemble Voting Classifier':<28} | Acc: {acc_ens*100:5.1f}% | Prec: {prec_ens*100:5.1f}% | Rec: {rec_ens*100:5.1f}% | F1: {f1_ens*100:5.1f}% | CV: {cv_mean_ens*100:5.1f}%")

    # 7. Save Models and Metadata
    bundle = {
        "models": trained_models,
        "feature_names": FEATURE_NAMES,
        "metrics": metrics_summary
    }

    joblib.dump(bundle, "phishing_models_bundle.pkl")
    # Also save top model as legacy phishing_model.pkl
    best_model = trained_models["ensemble"] if acc_ens >= metrics_summary["random_forest"]["accuracy"]/100 else trained_models["random_forest"]
    joblib.dump(best_model, "phishing_model.pkl")

    with open("models_metrics.json", "w") as f:
        json.dump(metrics_summary, f, indent=4)

    print("\n" + "=" * 60)
    print("[SUCCESS] All 8 models trained, evaluated, and saved successfully!")
    print("   - Bundle saved: phishing_models_bundle.pkl")
    print("   - Default model: phishing_model.pkl")
    print("   - Metrics summary: models_metrics.json")
    print("=" * 60)


if __name__ == "__main__":
    train_all_models()