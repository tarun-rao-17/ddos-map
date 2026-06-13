import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib

DATA_DIR  = os.path.join(os.path.dirname(__file__), "data")
MODEL_OUT = os.path.join(os.path.dirname(__file__), "model.pkl")

FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Avg Fwd Segment Size",
    "Init_Win_bytes_forward",
]

def load_csv(path: str, sample: int = 20000) -> pd.DataFrame:
    print(f"  Loading {os.path.basename(path)} ...")
    df = pd.read_csv(path, encoding="utf-8", low_memory=False)

    # strip whitespace from column names (known CIC dataset issue)
    df.columns = df.columns.str.strip()

    # keep only the columns we need plus Label
    needed = FEATURES + ["Label"]
    missing = [c for c in needed if c not in df.columns]
    if missing:
        print(f"  Skipping — missing columns: {missing}")
        return pd.DataFrame()

    df = df[needed].copy()

    # drop rows with nulls or infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # sample to keep memory usage manageable
    if len(df) > sample:
        df = df.sample(n=sample, random_state=42)

    print(f"  Loaded {len(df)} rows")
    return df


def train():
    print("=== Loading data ===")
    frames = []

    for fname in os.listdir(DATA_DIR):
        if not fname.endswith(".csv"):
            continue
        path = os.path.join(DATA_DIR, fname)
        df = load_csv(path)
        if not df.empty:
            frames.append(df)

    if not frames:
        print("No CSV files loaded. Check your data/ folder.")
        return

    data = pd.concat(frames, ignore_index=True)
    print(f"\nTotal rows loaded: {len(data)}")
    print(f"Label distribution:\n{data['Label'].value_counts()}\n")

    # convert labels — BENIGN = 0, everything else = 1 (attack)
    data["target"] = (data["Label"].str.strip() != "BENIGN").astype(int)

    X = data[FEATURES]
    y = data["target"]

    print("=== Splitting data ===")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} rows | Test: {len(X_test)} rows")

    print("\n=== Training RandomForest ===")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    print("\n=== Evaluation ===")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred,
          target_names=["BENIGN", "ATTACK"]))

    joblib.dump(model, MODEL_OUT)
    print(f"\nModel saved → {MODEL_OUT}")

    print("\nTop 5 most important features:")
    importances = sorted(
        zip(FEATURES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    for name, score in importances[:5]:
        print(f"  {name:40s} {score:.4f}")


if __name__ == "__main__":
    train()