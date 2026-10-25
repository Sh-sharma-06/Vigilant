import csv
import json
import os
import pickle
from typing import Any, Dict

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from xgboost import XGBClassifier

from build_telemetry_dataset import FEATURE_COLUMNS, extract_model_features

MODEL_DIR = "/home/sandesh/vigilant-eval-triage/models"
XGB_PATH = os.path.join(MODEL_DIR, "telemetry_xgb.pkl")
STATS_PATH = os.path.join(MODEL_DIR, "baseline_stats.json")

def train():
    csv_path = "/home/sandesh/vigilant-eval-triage/telemetry_dataset.csv"
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Run build_telemetry_dataset.py first: {csv_path} not found")

    X, y, names = [], [], []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            names.append(row["model_name"])
            y.append(int(row["label"]))
            X.append([float(row[col]) for col in FEATURE_COLUMNS])

    X_arr = np.array(X, dtype=np.float32)
    y_arr = np.array(y, dtype=np.int32)

    benign_X = X_arr[y_arr == 0]
    means = np.mean(benign_X, axis=0)
    stds = np.where(np.std(benign_X, axis=0) < 1e-5, 1.0, np.std(benign_X, axis=0))

    xgb = XGBClassifier(
        n_estimators=120,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric="logloss",
        random_state=42,
    )
    xgb.fit(X_arr, y_arr)

    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(benign_X)

    preds = xgb.predict(X_arr)
    tn, fp, fn, tp = confusion_matrix(y_arr, preds).ravel()

    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(XGB_PATH, "wb") as f:
        pickle.dump({"xgb": xgb, "iso": iso, "features": FEATURE_COLUMNS}, f)

    stats = {
        "feature_columns": FEATURE_COLUMNS,
        "benign_mean": [round(float(m), 4) for m in means],
        "benign_std": [round(float(s), 4) for s in stds],
        "feature_importances": {
            col: round(float(imp), 4) for col, imp in zip(FEATURE_COLUMNS, xgb.feature_importances_)
        },
        "training_metrics": {
            "total_samples": len(y_arr),
            "TP": int(tp),
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "accuracy": round(float(accuracy_score(y_arr, preds)), 4),
            "precision": round(float(precision_score(y_arr, preds)), 4),
            "recall": round(float(recall_score(y_arr, preds)), 4),
            "f1": round(float(f1_score(y_arr, preds)), 4),
            "telemetry_dropout_rate": 0.0,
        },
    }
    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)

    print("=== TELEMETRY XGBOOST + ISOLATION FOREST TRAINING COMPLETE ===")
    print(json.dumps(stats["training_metrics"], indent=2))
    print("\nTop 5 Most Important Security Telemetry Features:")
    top_feats = sorted(stats["feature_importances"].items(), key=lambda x: x[1], reverse=True)[:5]
    for k, v in top_feats:
        print(f"  - {k:26s}: {v:.4f}")

def score_model_telemetry(file_path: str) -> Dict[str, Any]:
    feats = extract_model_features(file_path)
    vec = np.array([[float(feats[col]) for col in FEATURE_COLUMNS]], dtype=np.float32)

    if not os.path.exists(XGB_PATH) or not os.path.exists(STATS_PATH):
        return {"features": feats, "xgboost_malicious_prob": 0.5, "deviating_features": []}

    with open(XGB_PATH, "rb") as f:
        bundle = pickle.load(f)
    with open(STATS_PATH, "r") as f:
        stats = json.load(f)

    prob = float(bundle["xgb"].predict_proba(vec)[0, 1])
    iso_score = float(bundle["iso"].decision_function(vec)[0])

    means = np.array(stats["benign_mean"])
    stds = np.array(stats["benign_std"])
    z_scores = (vec[0] - means) / stds

    deviations = []
    for col, val, z in zip(FEATURE_COLUMNS, vec[0], z_scores):
        if abs(z) > 2.5 and val > 0:
            deviations.append({"feature": col, "value": round(float(val), 3), "z_score": round(float(z), 2)})

    return {
        "xgboost_malicious_probability": round(prob, 4),
        "isolation_forest_normality": round(iso_score, 4),
        "epistemic_uncertainty": bool(0.15 <= prob <= 0.85),
        "deviating_features": sorted(deviations, key=lambda d: abs(d["z_score"]), reverse=True)[:5],
        "raw_features": feats,
    }

if __name__ == "__main__":
    train()
