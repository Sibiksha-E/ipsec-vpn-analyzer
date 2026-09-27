#!/usr/bin/env python3
"""Traffic classifier: windowed ESP features -> RandomForest.
Split is BY FILE (held-out captures), so test measures new tunnels, not memory.
Writes ml/rf_v1.joblib + ml/metrics.json."""
import os, json, numpy as np
from collections import Counter
from scapy.all import rdpcap, IP
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib

CLASSES = {
    "ping": ["sample_001_icmp_esp.pcap", "sample_004_tunnel_icmp.pcap",
             "sample_005_tunnel_aes256.pcap", "sample_006_weak_ikev1.pcap"],
    "web": ["sample_002_http_esp.pcap", "sample_007_strong_ikev2.pcap", "sample_012_web2.pcap"],
    "handshake": ["sample_003_ike_esp.pcap"],
    "voip": ["sample_008_voip.pcap", "sample_013_voip2.pcap"],
    "video": ["sample_009_video.pcap"],
    "bulk": ["sample_010_bulk.pcap", "sample_014_bulk2.pcap"],
}
# Held-out whole files for testing - never seen in training.
HOLDOUT = {"sample_005_tunnel_aes256.pcap", "sample_007_strong_ikev2.pcap",
           "sample_013_voip2.pcap", "sample_014_bulk2.pcap", "sample_012_web2.pcap"}
BASE = os.path.expanduser("~/ipsec-analyzer/samples")
WIN = 10

def feats(pkts):
    lens = np.array([len(p) for p in pkts], dtype=float)
    times = np.array([float(p.time) for p in pkts], dtype=float)
    iat = np.diff(times) if len(times) > 1 else np.array([0])
    srcs = [p[IP].src for p in pkts if p.haslayer(IP)]
    dom = Counter(srcs).most_common(1)[0][0] if srcs else None
    dirs = [1 if p.haslayer(IP) and p[IP].src == dom else 0 for p in pkts]
    return [len(pkts), float(times[-1] - times[0]) if len(times) > 1 else 0,
            float(lens.mean()), float(lens.std()), float(lens.min()), float(lens.max()),
            float(iat.mean()), float(iat.std()), float(np.mean(dirs))]

def windows_of(path):
    pkts = rdpcap(path)
    out = []
    for i in range(0, len(pkts), WIN):
        w = pkts[i:i + WIN]
        if len(w) >= 8:
            out.append(feats(w))
    return out

Xtr, ytr, Xte, yte, held = [], [], [], [], []
for label, files in CLASSES.items():
    for f in files:
        path = os.path.join(BASE, f)
        if not os.path.exists(path):
            continue
        ws = windows_of(path)
        if f in HOLDOUT:
            Xte += ws; yte += [label] * len(ws); held.append(f)
        else:
            Xtr += ws; ytr += [label] * len(ws)
Xtr, ytr, Xte, yte = map(np.array, (Xtr, ytr, Xte, yte))
print(f"train windows: {len(ytr)} {dict(zip(*np.unique(ytr, return_counts=True)))}")
print(f"held-out files: {sorted(held)}")
print(f"test windows: {len(yte)} {dict(zip(*np.unique(yte, return_counts=True)))}")
labels = sorted(set(ytr) | set(yte))
clf = RandomForestClassifier(n_estimators=200, random_state=7)
clf.fit(Xtr, ytr)
pred = clf.predict(Xte)
acc = round(float(accuracy_score(yte, pred)), 3)
cm = confusion_matrix(yte, pred, labels=labels).tolist()
per_class = {}
for i, lab in enumerate(labels):
    tp = cm[i][i]; tot = sum(cm[i])
    per_class[lab] = {"test_windows": int(tot), "recall": round(tp / tot, 3) if tot else 0}
print("held-out accuracy:", acc)
print("per-class:", per_class)
os.makedirs(os.path.expanduser("~/ipsec-analyzer/ml"), exist_ok=True)
joblib.dump(clf, os.path.expanduser("~/ipsec-analyzer/ml/rf_v1.joblib"))
json.dump({"accuracy": acc, "labels": labels, "confusion": cm,
           "per_class": per_class, "held_out_files": sorted(held),
           "train_windows": int(len(ytr)), "test_windows": int(len(yte)),
           "method": "held-out whole files; handshake excluded (1 file only)"},
          open(os.path.expanduser("~/ipsec-analyzer/ml/metrics.json"), "w"), indent=1)
print("saved ml/rf_v1.joblib + ml/metrics.json")
