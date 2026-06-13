import pandas as pd
import numpy as np
import os

np.random.seed(42)

FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Bwd Packet Length Max",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Mean", "Bwd IAT Mean", "Fwd PSH Flags", "SYN Flag Count",
    "RST Flag Count", "ACK Flag Count", "Avg Fwd Segment Size",
    "Init_Win_bytes_forward",
]

def generate_benign(n=2000):
    df = pd.DataFrame({
        "Flow Duration":        np.random.randint(1000, 100000, n),
        "Total Fwd Packets":    np.random.randint(1, 20, n),
        "Total Length of Fwd Packets": np.random.randint(100, 5000, n),
        "Fwd Packet Length Max": np.random.randint(100, 1500, n),
        "Fwd Packet Length Min": np.random.randint(20, 100, n),
        "Bwd Packet Length Max": np.random.randint(100, 1500, n),
        "Flow Bytes/s":         np.random.uniform(100, 50000, n),
        "Flow Packets/s":       np.random.uniform(1, 100, n),
        "Flow IAT Mean":        np.random.uniform(1000, 500000, n),
        "Flow IAT Std":         np.random.uniform(100, 100000, n),
        "Fwd IAT Mean":         np.random.uniform(1000, 500000, n),
        "Bwd IAT Mean":         np.random.uniform(1000, 500000, n),
        "Fwd PSH Flags":        np.random.randint(0, 2, n),
        "SYN Flag Count":       np.random.randint(0, 2, n),
        "RST Flag Count":       np.random.randint(0, 1, n),
        "ACK Flag Count":       np.random.randint(0, 5, n),
        "Avg Fwd Segment Size": np.random.uniform(100, 1500, n),
        "Init_Win_bytes_forward": np.random.randint(1000, 65535, n),
        "Label": ["BENIGN"] * n
    })
    return df

def generate_attack(n=2000):
    df = pd.DataFrame({
        "Flow Duration":        np.random.randint(1, 500, n),
        "Total Fwd Packets":    np.random.randint(500, 10000, n),
        "Total Length of Fwd Packets": np.random.randint(0, 100, n),
        "Fwd Packet Length Max": np.random.randint(0, 100, n),
        "Fwd Packet Length Min": np.random.randint(0, 10, n),
        "Bwd Packet Length Max": np.random.randint(0, 50, n),
        "Flow Bytes/s":         np.random.uniform(100000, 10000000, n),
        "Flow Packets/s":       np.random.uniform(10000, 1000000, n),
        "Flow IAT Mean":        np.random.uniform(1, 100, n),
        "Flow IAT Std":         np.random.uniform(1, 50, n),
        "Fwd IAT Mean":         np.random.uniform(1, 100, n),
        "Bwd IAT Mean":         np.random.uniform(0, 10, n),
        "Fwd PSH Flags":        np.random.randint(0, 1, n),
        "SYN Flag Count":       np.random.randint(100, 5000, n),
        "RST Flag Count":       np.random.randint(50, 2000, n),
        "ACK Flag Count":       np.random.randint(0, 2, n),
        "Avg Fwd Segment Size": np.random.uniform(0, 50, n),
        "Init_Win_bytes_forward": np.random.randint(0, 100, n),
        "Label": ["DDoS"] * n
    })
    return df

benign = generate_benign(2000)
attack = generate_attack(2000)
df = pd.concat([benign, attack]).sample(frac=1, random_state=42).reset_index(drop=True)

out = os.path.join(os.path.dirname(__file__), "sample_training.csv")
df.to_csv(out, index=False)
print(f"Generated {len(df)} rows → {out}")
print(f"  BENIGN: {(df['Label']=='BENIGN').sum()}")
print(f"  DDoS:   {(df['Label']=='DDoS').sum()}")