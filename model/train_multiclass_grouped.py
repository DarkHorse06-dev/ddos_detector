#!/usr/bin/env python3
import os
import glob
import time
import random
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from datetime import datetime
from collections import Counter
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.preprocessing import StandardScaler

# === CONFIGURATION ===
DATA_DIR = "../data"
MODEL_DIR = "ddos_detector/model"
SAMPLES_DIR = "ddos_detector/samples"
PER_FILE_LIMIT = 10000
PER_CLASS_LIMIT = 1000

# === NORMALIZATION ===
def normalize_label(label):
    label = str(label).upper()
    if "BENIGN" in label:
        return "BENIGN"
    elif "DRDOS" in label:
        return "DrDoS"
    elif "UDP" in label:
        return "UDP"
    elif "SYN" in label:
        return "SYN"
    elif "TFTP" in label:
        return "TFTP"
    elif "NETBIOS" in label:
        return "NetBIOS"
    return "OTHER"

# === LABEL COLUMN FINDER ===
def find_label_column(df):
    for col in df.columns:
        if col.strip().lower() == "label":
            return col
    return None

# === LOAD AND SAMPLE DATA ===
def load_sampled_data():
    all_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    all_data = []

    for file in all_files:
        try:
            df = pd.read_csv(file, nrows=PER_FILE_LIMIT, low_memory=False)
            label_col = find_label_column(df)
            if label_col:
                df.rename(columns={label_col: "Label"}, inplace=True)
                df["Label"] = df["Label"].apply(normalize_label)
                all_data.append(df)
        except Exception as e:
            print(f"[!] Skipping {file}: {e}")

    if not all_data:
        raise RuntimeError("❌ No usable data found!")

    raw_df = pd.concat(all_data, ignore_index=True)
    sampled = []

    for label, group in raw_df.groupby("Label"):
        if len(group) >= PER_CLASS_LIMIT:
            sampled.append(group.sample(PER_CLASS_LIMIT, random_state=42))
    
    return pd.concat(sampled, ignore_index=True)

# === PREPROCESSING ===
def preprocess(df):
    df.columns = [c.strip() for c in df.columns]
    df.drop(columns=[col for col in ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'Unnamed: 0'] if col in df.columns], inplace=True)
    df.dropna(subset=["Label"], inplace=True)

    y_raw = df["Label"].astype(str)
    df.drop(columns=["Label"], inplace=True)
    df = df.select_dtypes(include=[np.number])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    y_raw = y_raw.loc[df.index]

    return df, y_raw

# === MAIN FUNCTION ===
def main():
    print("📥 Loading and sampling data...")
    df_raw = load_sampled_data()
    print(f"✅ Loaded samples per class:\n{df_raw['Label'].value_counts()}")

    X_raw, y_raw = preprocess(df_raw)
    y_cat = y_raw.astype("category")
    y = y_cat.cat.codes
    class_labels = list(y_cat.cat.categories)
    print(f"\n🎯 Training with classes: {class_labels}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    print("🕵️ Training Isolation Forest for anomaly scoring...")
    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(X_scaled)
    anomaly_scores = -iso.decision_function(X_scaled).reshape(-1, 1)

    X_aug = np.hstack([X_scaled, anomaly_scores])
    feature_names = list(X_raw.columns) + ["anomaly_score"]

    X_train, X_test, y_train, y_test = train_test_split(
        X_aug, y, test_size=0.2, stratify=y, random_state=42
    )

    class_counts = Counter(y_train)
    total = sum(class_counts.values())
    class_weights = {cls: total / (len(class_counts) * count) for cls, count in class_counts.items()}
    sample_weights = [class_weights[i] for i in y_train]

    print("🧠 Training Random Forest model...")
    start_train = time.time()
    model = RandomForestClassifier(n_estimators=150, class_weight="balanced", random_state=42)
    model.fit(X_train, y_train, sample_weight=sample_weights)
    train_time = time.time() - start_train

    print("🧪 Evaluating model...")
    start_infer = time.time()
    y_pred = model.predict(X_test)
    infer_time = time.time() - start_infer
    acc = accuracy_score(y_test, y_pred)
    print(f"\n🔍 Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=class_labels))

    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(cm, display_labels=class_labels)
    disp.plot(xticks_rotation=45)
    plt.title("Confusion Matrix")
    os.makedirs(MODEL_DIR, exist_ok=True)
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix.png"))
    plt.close()

    # === SAVE MODEL ARTIFACTS ===
    joblib.dump(model, os.path.join(MODEL_DIR, "model.pkl"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    joblib.dump(feature_names, os.path.join(MODEL_DIR, "feature_names.pkl"))
    joblib.dump(class_labels, os.path.join(MODEL_DIR, "class_labels.pkl"))

    print(f"💾 Model and metadata saved.")

    # === SAMPLE GENERATION ===
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    df_raw = df_raw.loc[X_raw.index]
    df_raw["Label"] = y_raw

    benign_sample = df_raw[df_raw["Label"] == "BENIGN"].sample(1, random_state=random.randint(1, 10000))
    attack_classes = [c for c in class_labels if c != "BENIGN"]
    attack_type = random.choice(attack_classes)
    attack_sample = df_raw[df_raw["Label"] == attack_type].sample(1, random_state=random.randint(1, 10000))

    benign_sample.to_csv(os.path.join(SAMPLES_DIR, "BENIGN.csv"), index=False)
    attack_sample.to_csv(os.path.join(SAMPLES_DIR, "attack.csv"), index=False)
    attack_sample.drop(columns=["Label"]).to_csv(os.path.join(SAMPLES_DIR, "attack_nolabel.csv"), index=False)

    print(f"📄 Samples saved:")
    print(f"   → BENIGN.csv")
    print(f"   → attack.csv ({attack_type})")
    print(f"   → attack_nolabel.csv")

    print(f"\n⏱️ Training time: {train_time:.2f}s")
    print(f"⚡ Inference time: {infer_time:.4f}s ({(infer_time / len(X_test)) * 1000:.2f} ms/sample)")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n✅ Finished at {now}")

if __name__ == "__main__":
    main()
