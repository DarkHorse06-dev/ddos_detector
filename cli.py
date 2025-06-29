#!/usr/bin/env python3

import os
import argparse
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.exceptions import NotFittedError

MODEL_DIR = "model/model"
DEFAULT_OUTPUT = "prediction_report.txt"

# === Load model artifacts
def load_artifacts():
    try:
        model = joblib.load(os.path.join(MODEL_DIR, "model.pkl"))
        scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
        iso = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
        feature_names = joblib.load(os.path.join(MODEL_DIR, "feature_names.pkl"))
        class_labels = joblib.load(os.path.join(MODEL_DIR, "class_labels.pkl"))
        return model, scaler, iso, feature_names, class_labels
    except Exception as e:
        print(f"[❌] Error loading model files: {e}")
        exit(1)

# === Clean and preprocess input
def preprocess_input(file_path, feature_names):
    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        print(f"[❌] Failed to read file: {e}")
        return None

    # Drop metadata and label columns
    for col in ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'Label', 'Unnamed: 0']:
        if col in df.columns:
            df.drop(columns=col, inplace=True)

    df = df.select_dtypes(include=[np.number])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    if df.empty:
        print("[❌] No usable numeric rows after preprocessing.")
        return None

    print(f"🔎 Usable rows after cleaning: {len(df)}")

    # Keep only training-time features
    missing_features = set(feature_names[:-1]) - set(df.columns)  # exclude 'anomaly_score'
    if missing_features:
        print(f"[❌] Missing required features: {missing_features}")
        return None

    df = df[feature_names[:-1]]  # exclude anomaly_score for now
    return df

# === Attack explanations
def explain_attack(label):
    notes = {
        "BENIGN": (
            "This traffic is classified as normal. No significant anomalies detected. "
            "Behavioral patterns (e.g., flow durations, packet rates) remain within safe operational thresholds."
        ),
        "DrDoS": (
            "DrDoS attacks use reflection and amplification via vulnerable third-party servers. "
            "They spoof source IPs, causing amplified traffic to flood the victim. "
            "Indicators include mismatched request-reply volumes and irregular IP patterns."
        ),
        "UDP": (
            "UDP-based DDoS floods exploit the connectionless nature of UDP to send high volumes of packets. "
            "This leads to server exhaustion due to lack of connection verification."
        ),
        "SYN": (
            "SYN floods abuse the TCP handshake by sending numerous SYN requests and not completing them, "
            "resulting in server-side half-open connections that drain resources."
        ),
        "TFTP": (
            "TFTP attacks leverage unauthenticated TFTP servers to reflect large volumes of data to victims. "
            "Such traffic is often repetitive and abnormally large."
        ),
        "NetBIOS": (
            "NetBIOS reflection attacks send crafted packets to NetBIOS-enabled devices, causing amplified replies to victims. "
            "Common indicators include port 137 and irregular packet signatures."
        ),
    }
    return notes.get(label, "No explanation available for this label.")

# === Prediction
def predict(file_path, output_file):
    print(f"\n📥 Predicting file: {file_path}")
    model, scaler, iso, feature_names, class_labels = load_artifacts()
    df = preprocess_input(file_path, feature_names)

    if df is None:
        return

    try:
        X_scaled = scaler.transform(df)
        anomaly_scores = -iso.decision_function(X_scaled).reshape(-1, 1)
        X_aug = np.hstack([X_scaled, anomaly_scores])
    except NotFittedError:
        print("[❌] Model or scaler not properly fitted.")
        return

    proba = model.predict_proba(X_aug)
    avg_proba = np.mean(proba, axis=0)
    top_idx = np.argmax(avg_proba)
    predicted_label = class_labels[top_idx]
    confidence = avg_proba[top_idx] * 100

    severity = (
        "None" if predicted_label == "BENIGN" else
        "Low" if confidence < 60 else
        "Medium" if confidence < 85 else
        "High"
    )

    explanation = explain_attack(predicted_label)

    # Prepare prediction report
    report = [
        "📄 Prediction Report",
        f"Status       : {predicted_label}",
        f"Confidence   : {confidence:.2f}%",
        f"Severity     : {severity}",
        f"Explanation  : {explanation}",
        "\n📊 Class Probabilities:"
    ] + [f"- {label:<10}: {prob * 100:.2f}%" for label, prob in zip(class_labels, avg_proba)]

    result = "\n".join(report)
    print(result)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result)
            print(f"\n📝 Report saved to: {output_file}")
        except Exception as e:
            print(f"[❌] Could not write to file: {e}")

# === CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🛡️ Predict DDoS attack types from CSV files")
    parser.add_argument("csv_file", help="Path to the input CSV file")
    parser.add_argument("-o", "--output", help="Path to save prediction report as .txt", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    predict(args.csv_file, args.output)
