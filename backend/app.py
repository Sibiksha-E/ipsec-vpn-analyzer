#!/usr/bin/env python3
"""MVP backend: upload PCAP -> parser -> security rules -> JSON. No DB yet, in-memory + disk."""
import os, uuid, json, shutil
from collections import Counter
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap, IP, ESP, UDP, TCP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE_DIR = os.environ.get("STORE_DIR", "/tmp/ipsec-uploads")
os.makedirs(STORE_DIR, exist_ok=True)
DB_PATH = os.path.join(ROOT, "captures.db")

def _db():
    import sqlite3
    c = sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS caps(id TEXT PRIMARY KEY, filename TEXT, path TEXT, observed TEXT, security TEXT)")
    return c

def db_save(cid, filename, path, obs, sec):
    c = _db()
    c.execute("REPLACE INTO caps VALUES (?,?,?,?,?)",
              (cid, filename, path, json.dumps(obs), json.dumps(sec)))
    c.commit(); c.close()

def db_get(cid):
    import sqlite3
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    r = c.execute("SELECT * FROM caps WHERE id=?", (cid,)).fetchone()
    c.close()
    if not r: return None
    return {"observed": json.loads(r["observed"]), "security": json.loads(r["security"]),
            "filename": r["filename"], "path": r["path"]}

def db_count():
    c = _db()
    n = c.execute("SELECT COUNT(*) FROM caps").fetchone()[0]
    c.close(); return n

DEFAULT_META = {
  "mode": "transport",
}

def ike_versions_in(pkts):
    """Real IKE header parsing. Byte 17 of the UDP payload holds the
    version nibble: 0x1? = IKEv1, 0x2? = IKEv2 (needs 28-byte header).
    Short payloads (NAT keepalives) are ignored."""
    vers = set()
    for p in pkts:
        if not (p.haslayer(UDP) and (p[UDP].sport in (500, 4500) or p[UDP].dport in (500, 4500))):
            continue
        try:
            raw = bytes(p[UDP].payload)
        except Exception:
            raw = b""
        if len(raw) < 28:
            continue
        major = raw[17] >> 4
        if major == 1:
            vers.add("IKEv1")
        elif major == 2:
            vers.add("IKEv2")
        else:
            vers.add("unknown")
    return sorted(vers)

def analyze(pcap_path, capture_id):
    pkts = rdpcap(pcap_path)
    times = [float(p.time) for p in pkts] if len(pkts) else [0]
    t0 = min(times) if times else 0
    duration = round(max(times)-min(times), 3) if len(times) > 1 else 0
    protos, flow_stat, spis, lens = set(), {}, set(), []
    ike_found, esp_count, ike_count = False, 0, 0
    for p in pkts:
        L = len(p); lens.append(L)
        spi, seq = None, None
        if p.haslayer(ESP):
            protos.add("ESP"); esp_count += 1
            try:
                spi = hex(int(p[ESP].spi)); spis.add(spi)
                seq = int(p[ESP].seq)
            except Exception: pass
        if p.haslayer(IP):
            proto = "ESP" if p[IP].proto == 50 else ("IKE" if p.haslayer(UDP) and (p[UDP].sport in (500, 4500) or p[UDP].dport in (500, 4500)) else str(p[IP].proto))
            key = (p[IP].src, p[IP].dst, proto)
            st = flow_stat.setdefault(key, {"count": 0, "bytes": 0, "first": float(p.time), "last": float(p.time)})
            st["count"] += 1; st["bytes"] += L
            st["first"] = min(st["first"], float(p.time)); st["last"] = max(st["last"], float(p.time))
        if p.haslayer(UDP):
            u = p[UDP]
            if u.sport in (500, 4500) or u.dport in (500, 4500):
                ike_found = True; ike_count += 1; protos.add("IKEv2-probable")
    if ike_found: protos.add("IKE")
    ivers = ike_versions_in(pkts)
    flows = [{"src_ip": s, "dst_ip": d, "protocol": pr, "packet_count": v["count"],
              "bytes": v["bytes"], "first_seen": round(v["first"]-t0, 3), "last_seen": round(v["last"]-t0, 3)}
             for (s, d, pr), v in sorted(flow_stat.items(), key=lambda kv: -kv[1]["count"])]
    import numpy as _np
    _lens = _np.array(lens, dtype=float) if lens else _np.array([0])
    _t = _np.array(times, dtype=float)
    _iat = _np.diff(_t) if len(_t) > 1 else _np.array([0])
    _hist, _edges = _np.histogram(_lens, bins=[0, 128, 512, 1024, 1500, 1000000])
    _seen, _dups = set(), 0
    _seqs = {}
    for p in pkts:
        if p.haslayer(ESP):
            try: k = (int(p[ESP].spi), int(p[ESP].seq))
            except Exception: continue
            if k in _seen: _dups += 1
            else: _seen.add(k)
            _seqs.setdefault(k[0], []).append(k[1])
    seq_loss = []
    for spi, seqs in sorted(_seqs.items()):
        lo, hi = min(seqs), max(seqs)
        expect = hi - lo + 1
        got = len(set(seqs))
        missing = sorted(set(range(lo, hi + 1)) - set(seqs))[:50]
        seq_loss.append({"spi": hex(spi), "from": lo, "to": hi,
                         "expected": expect, "seen": got,
                         "lost": expect - got,
                         "loss_pct": round((expect - got) / expect * 100, 2) if expect else 0,
                         "missing": missing, "truncated_list": (expect - got) > len(missing)})
    deep = {
        "size_hist": [{"range": r, "count": int(c)} for r, c in
                      zip(["tiny <128B", "small 128–511B", "medium 512–1023B", "large 1024–1500B", "huge 1500B+"], _hist)],
        "size_std": round(float(_lens.std()), 1),
        "gap_avg_ms": round(float(_iat.mean()) * 1000, 2),
        "gap_std_ms": round(float(_iat.std()) * 1000, 2),
        "dup_esp": _dups, "unique_esp": len(_seen),
        "seq_loss": seq_loss,
    }
    return {
        "capture_id": capture_id, "packet_count": len(pkts),
        "duration_sec": duration, "protocols_detected": sorted(protos),
        "esp_packets": esp_count, "ike_packets": ike_count, "ike_detected": ike_found,
        "ike_versions": ivers,
        "spis_observed": sorted(spis),
        "flows": flows, "conversation_count": len(flows),
        "data_volume_bytes": int(sum(lens)),
        "packet_length": {"min": min(lens or [0]), "max": max(lens or [0]),
                          "avg": round(sum(lens)/len(lens), 1) if lens else 0},
        "deep": deep,
    }

def packet_rows(pcap_path, limit=300):
    pkts = rdpcap(pcap_path)
    t0 = float(pkts[0].time) if len(pkts) else 0
    rows = []
    for i, p in enumerate(pkts[:limit]):
        src = dst, proto = "?", "?"
        spi, seq, ttl, sport, dport = None, None, None, None, None
        if p.haslayer(IP):
            src, dst = p[IP].src, p[IP].dst
            try: ttl = int(p[IP].ttl)
            except Exception: pass
            if p.haslayer(ESP):
                proto = "ESP"
                try: spi, seq = hex(int(p[ESP].spi)), int(p[ESP].seq)
                except Exception: pass
            elif p.haslayer(UDP) and (p[UDP].sport in (500, 4500) or p[UDP].dport in (500, 4500)):
                proto = "IKE"
            else:
                proto = str(p[IP].proto)
            if p.haslayer(UDP):
                try: sport, dport = int(p[UDP].sport), int(p[UDP].dport)
                except Exception: pass
            elif p.haslayer(TCP):
                try: sport, dport = int(p[TCP].sport), int(p[TCP].dport)
                except Exception: pass
        rows.append({"n": i+1, "time": round(float(p.time)-t0, 3), "src": src, "dst": dst,
                     "protocol": proto, "length": len(p), "spi": spi, "seq": seq,
                     "ttl": ttl, "sport": sport, "dport": dport})
    return {"total": len(pkts), "shown": len(rows), "truncated": len(pkts) > limit, "packets": rows}

def assess(observed, meta=DEFAULT_META):
    """Risk from the file itself. Cipher/PFS/DH need device config,
    so they are reported as info, never as file findings."""
    f = []
    def add(check, severity, desc, rec, source, evidence="", learn=""):
        f.append({"check": check, "severity": severity, "description": desc,
                  "recommendation": rec, "source": source, "evidence": evidence, "learn": learn})
    n, esp, ike = observed.get("packet_count", 0), observed.get("esp_packets", 0), observed.get("ike_detected", False)
    vers = observed.get("ike_versions", [])
    spis = ",".join(observed.get("spis_observed", [])) or "none"
    if n == 0:
        add("Capture", "high", "File is empty. Nothing to judge.",
            "Record again while traffic flows.", "observed", "0 packets.", "")
    elif esp == 0 and not ike:
        add("VPN data", "high", "No ESP and no handshake. This file shows no VPN.",
            "Capture on the VPN path with filter esp or udp port 500/4500.", "observed",
            f"{n} packets, none ESP/IKE.", "")
    if "IKEv1" in vers:
        add("Handshake version", "high", "Old IKEv1 handshake seen on the wire.",
            "Move both ends to IKEv2.", "observed",
            f"Versions in file: {', '.join(vers)}.", "ike")
    elif "IKEv2" in vers:
        add("Handshake version", "info", "Modern IKEv2 handshake seen.",
            "Keep IKEv2, block old IKEv1.", "observed",
            f"IKE packets={observed.get('ike_packets', 0)}.", "ike")
    elif esp > 0:
        add("Handshake version", "medium", "Locked traffic present but the handshake is missing. Version cannot be checked from this file.",
            "Capture from tunnel start to include the handshake.", "observed",
            f"{esp} ESP packets, 0 IKE packets.", "ike")
    if esp > 0 and ike and "IKEv1" not in vers:
        add("Tunnel health", "info", "Handshake plus locked data. Tunnel looks alive.",
            "No action.", "observed", f"ESP {esp}, SPIs {spis}.", "")
    elif esp > 0 and not ike:
        add("Tunnel health", "info", "Locked data flowing. Handshake happened before recording or keys are static.",
            "No action.", "observed", f"ESP {esp}, SPIs {spis}.", "")
    elif ike and esp == 0:
        add("Tunnel health", "medium", "Handshake seen but no locked data followed.",
            "Check the data path and policies.", "observed", "IKE yes, ESP 0.", "")
    add("Cipher detail", "info", "Exact cipher, DH group and PFS live in device settings, not in ESP bytes. This tool does not guess them.",
        "Compare device config separately.", "observed",
        "ESP hides payload by design.", "crypto")
    add("Metadata", "info", f"Outer IPs, SPIs ({spis}) and sizes/timing are visible by design. Messages stay hidden.",
        "Normal for IPsec.", "observed",
        f"{n} packets, avg size {observed.get('packet_length',{}).get('avg')}.", "limits")
    risk = "MEDIUM" if any(x["severity"] == "medium" for x in f) else "LOW"
    if any(x["severity"] == "high" for x in f): risk = "HIGH"
    return {"capture_id": observed.get("capture_id"), "risk": risk, "findings": f}

app = FastAPI(title="IPsec Analyzer MVP")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/captures/upload")
async def upload(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(400, "need .pcap file")
    cid = f"cap_{uuid.uuid4().hex[:8]}"
    path = os.path.join(STORE_DIR, f"{cid}_{file.filename}")
    size = 0
    with open(path, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > 50 * 1024 * 1024:
                out.close()
                try: os.remove(path)
                except Exception: pass
                raise HTTPException(413, "file over 50 MB cap - trim with: tcpdump -r in.pcap -c 20000 -w small.pcap")
            out.write(chunk)
    try:
        obs = analyze(path, cid)
    except Exception as e:
        raise HTTPException(400, f"parse failed: {e}")
    sec = assess(obs)
    db_save(cid, file.filename, path, obs, sec)
    return {"capture_id": cid, "observed": obs, "security": sec}

@app.get("/api/captures/{cid}")
def get_capture(cid: str):
    r = db_get(cid)
    if not r: raise HTTPException(404, "not found")
    return r["observed"]

@app.get("/api/captures/{cid}/security")
def get_security(cid: str):
    r = db_get(cid)
    if not r: raise HTTPException(404, "not found")
    return r["security"]

@app.get("/api/captures/{cid}/flows")
def get_flows(cid: str):
    r = db_get(cid)
    if not r: raise HTTPException(404, "not found")
    return {"capture_id": cid, "flows": r["observed"]["flows"]}

@app.get("/api/captures/{cid}/packets")
def get_packets(cid: str, limit: int = 300):
    r = db_get(cid)
    if not r: raise HTTPException(404, "not found")
    limit = max(1, min(limit, 2000))
    try:
        return {"capture_id": cid, **packet_rows(r["path"], limit)}
    except Exception as e:
        raise HTTPException(400, f"packet read failed: {e}")

MODEL_PATH = os.path.join(ROOT, "ml", "rf_v1.joblib")
_model = None
def get_model():
    global _model
    if _model is None:
        import joblib
        if not os.path.exists(MODEL_PATH):
            raise HTTPException(404, "model not trained yet")
        _model = joblib.load(MODEL_PATH)
    return _model

def window_feats(pkts):
    import numpy as np
    from collections import Counter as _C
    lens = np.array([len(p) for p in pkts], dtype=float)
    times = np.array([float(p.time) for p in pkts], dtype=float)
    iat = np.diff(times) if len(times) > 1 else np.array([0])
    srcs = [p[IP].src for p in pkts if p.haslayer(IP)]
    dom = _C(srcs).most_common(1)[0][0] if srcs else None
    dirs = [1 if p.haslayer(IP) and p[IP].src == dom else 0 for p in pkts]
    return [len(pkts), float(times[-1]-times[0]) if len(times) > 1 else 0,
            float(lens.mean()), float(lens.std()), float(lens.min()), float(lens.max()),
            float(iat.mean()), float(iat.std()), float(np.mean(dirs))]

def classify_data(pcap_path, cid, obs0):
    import numpy as np
    clf = get_model()
    pkts = rdpcap(pcap_path)
    preds, probas, wins = [], [], []
    for i in range(0, len(pkts), 10):
        w = pkts[i:i+10]
        if len(w) < 8: continue
        fv = window_feats(w)
        pr = str(clf.predict([fv])[0])
        preds.append(pr)
        try:
            pa = clf.predict_proba([fv])[0]
            probas.append({str(c): round(float(p), 3) for c, p in zip(clf.classes_, pa)})
            conf = float(max(pa))
        except Exception:
            probas.append({pr: 1.0}); conf = 1.0
        lens = [len(p) for p in w]
        wins.append({"window": i // 10, "pred": pr, "conf": round(conf, 3),
                     "packets": len(w), "avg_size": round(sum(lens)/len(lens), 1),
                     "size_min": min(lens), "size_max": max(lens)})
    from collections import Counter
    vote = Counter(preds).most_common(1)[0][0] if preds else "unknown"
    conf = round(sum(max(p.values()) for p in probas)/len(probas), 3) if probas else 0
    dist = {}
    for p in probas:
        for k, v in p.items(): dist[k] = dist.get(k, 0) + v
    dist = {k: round(v/len(probas), 3) for k, v in dist.items()} if probas else {}
    feats_used = ["packet size avg/spread/min/max", "gap-time avg/spread", "duration", "direction mix", "packet count"]
    dp = obs0.get("deep", {})
    reasons = []
    if dp.get("size_std", 0) < 20:
        reasons.append(f"All boxes nearly the same size (spread {dp.get('size_std')}B) — steady heartbeat traffic.")
    elif dp.get("size_std", 0) > 300:
        reasons.append(f"Box sizes jump a lot (spread {dp.get('size_std')}B) — mixed content like web pages.")
    sizes = [(s.get("range"), s.get("count")) for s in dp.get("size_hist", [])]
    big = sum(c for r, c in sizes if r in ("large 1024–1500B", "huge 1500B+"))
    if big > obs0.get("packet_count", 1) * 0.4:
        reasons.append(f"{big} big boxes over 1KB — bulk download shape.")
    if obs0.get("ike_detected"):
        reasons.append("Handshake hellos present — a full session start was recorded.")
    if len(preds) >= 3 and len(set(preds)) == 1:
        reasons.append(f"Every piece agrees ({vote}) — strong shape match.")
    elif len(set(preds)) > 1:
        reasons.append("Pieces disagree — mixed traffic or short capture.")
    return {"capture_id": cid, "label": vote, "confidence": conf,
            "windows": len(preds), "votes": dict(Counter(preds)), "dist": dist,
            "feats_used": feats_used, "reasons": reasons, "sample_windows": wins[:6],
            "note": "MVP on tiny data - demo only"}

@app.get("/api/captures/{cid}/classify")
def classify(cid: str):
    _r = db_get(cid)
    if not _r: raise HTTPException(404, "not found")
    return classify_data(_r["path"], cid, _r["observed"])

VERDICT = {
    "HIGH": "This capture shows a real weakness. Fix before trusting this tunnel.",
    "MEDIUM": "Basics work, but something cannot be verified or should be improved.",
    "LOW": "Nothing alarming in this capture. Keep settings as they are.",
}

@app.get("/api/captures/{cid}/summary")
def summary(cid: str):
    _r = db_get(cid)
    if not _r: raise HTTPException(404, "not found")
    obs, sec = _r["observed"], _r["security"]
    try:
        ai = classify_data(_r["path"], cid, obs)
    except Exception:
        ai = {"label": "unknown", "confidence": 0, "windows": 0, "votes": {}, "reasons": []}
    dp = obs.get("deep", {})
    flows = obs.get("flows", [])
    top = flows[0] if flows else {}
    parts = {
        "headline": f"{sec['risk']} risk · {obs['packet_count']} packets in {obs['duration_sec']}s",
        "verdict": VERDICT.get(sec["risk"], ""),
        "tunnel": (f"Tunnel is alive: {obs['esp_packets']} locked boxes between {top.get('src_ip')} and {top.get('dst_ip')}."
                   if obs["esp_packets"] else "No locked traffic in this file."),
        "handshake": ("Handshake recorded on the wire, so the key agreement is visible."
                      if obs["ike_detected"] else "No handshake in this file. The keys were agreed before recording, or set by hand, so version checks are limited."),
        "traffic": (f"Boxes average {obs['packet_length']['avg']}B (spread {dp.get('size_std')}B) arriving about every {dp.get('gap_avg_ms')} ms. "
                    + ("Sizes jump widely, like mixed web content. " if (dp.get('size_std') or 0) > 300 else
                       "Even sizes and steady rhythm, like machine heartbeat traffic. " if (dp.get('gap_std_ms') or 0) < 30 else
                       "Uneven timing, like human-driven browsing. "))
        if dp else "Shape statistics unavailable; re-upload the file.",
        "ai_reading": (f"Model reads this as {ai['label']} at {round(ai['confidence']*100)}% across {ai['windows']} pieces. " +
                       " ".join(ai.get("reasons", [])) + " This is a shape hint, not proof of the app.") if ai["windows"] else "Too few packets for an AI reading.",
        "loss": ("No numbered boxes to check." if not dp.get("seq_loss") else
                 "No loss: every numbered box arrived." if all(s["lost"] == 0 for s in dp["seq_loss"]) else
                 "Gaps found: " + "; ".join(f"{s['spi']} lost {s['lost']} ({s['loss_pct']}%)" for s in dp["seq_loss"] if s["lost"]) + ". Ask the network team about these drops."),
        "risks": [f"{x['check']}: {x['description']} Fix: {x['recommendation']}" for x in sec["findings"] if x["severity"] != "info"] or ["None urgent."],
        "next": ("Move both ends to IKEv2 and re-capture the handshake." if sec["risk"] == "HIGH" else
                 "Capture the handshake from tunnel start, then re-check." if not obs["ike_detected"] else
                 "Grow the dataset and re-train before trusting AI scores."),
    }
    return {"capture_id": cid, "sections": parts}

@app.get("/api/metrics")
def metrics():
    p = os.path.join(ROOT, "ml", "metrics.json")
    if not os.path.isfile(p):
        raise HTTPException(404, "model not trained yet")
    return json.load(open(p))

@app.get("/health")
def health():
    try:
        n = db_count()
    except Exception as e:
        return {"ok": False, "captures": 0, "db_error": f"{type(e).__name__}: {e}", "db_path": DB_PATH}
    return {"ok": True, "captures": n}

@app.get("/api/debug")
def debug():
    import sys
    def have(mod):
        try:
            m = __import__(mod)
            return getattr(m, "__version__", "installed")
        except Exception as e:
            return f"MISSING: {e}"
    sp = os.path.join(SAMPLE_DIR)
    try:
        samples = sorted(os.listdir(sp)) if os.path.isdir(sp) else []
    except Exception as e:
        samples = [f"LIST FAIL: {e}"]
    try:
        open(os.path.join(STORE_DIR, ".w"), "w").close()
        store = "writable"
    except Exception as e:
        store = f"READ-ONLY: {e}"
    return {"cwd": os.getcwd(), "root": ROOT, "python": sys.version.split()[0],
            "fastapi": have("fastapi"), "scapy": have("scapy"),
            "sklearn": have("sklearn"), "pandas": have("pandas"), "joblib": have("joblib"),
            "db_path": DB_PATH, "store": store, "samples_dir": SAMPLE_DIR,
            "samples": samples[:15], "model": os.path.isfile(MODEL_PATH)}

SAMPLE_DIR = os.path.join(ROOT, "samples")

@app.get("/api/samples")
def list_samples():
    out = []
    if os.path.isdir(SAMPLE_DIR):
        for f in sorted(os.listdir(SAMPLE_DIR)):
            if f.endswith((".pcap", ".pcapng", ".cap")):
                p = os.path.join(SAMPLE_DIR, f)
                out.append({"name": f, "size": os.path.getsize(p)})
    return {"samples": out}

@app.get("/api/samples/{name}")
def get_sample(name: str):
    from fastapi.responses import FileResponse
    if "/" in name or "\\" in name or not name.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(400, "bad name")
    p = os.path.join(SAMPLE_DIR, name)
    if not os.path.isfile(p):
        raise HTTPException(404, "not found")
    return FileResponse(p, media_type="application/octet-stream", filename=name)

class LiveReq(__import__("pydantic").BaseModel):
    seconds: int = 10
    filter: str = "esp or udp port 500 or udp port 4500"
    iface: str = "any"

LIVE = {}

@app.post("/api/live/start")
def live_start(req: LiveReq):
    import subprocess, time
    sid = f"live_{uuid.uuid4().hex[:8]}"
    path = os.path.join(STORE_DIR, f"{sid}.pcap")
    try:
        proc = subprocess.Popen(["tcpdump", "-i", req.iface, "-U", "-w", path, req.filter],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise HTTPException(500, "tcpdump not installed.")
    time.sleep(1)
    if proc.poll() is not None:
        raise HTTPException(500, "Capture died at once. Enable rights: "
                            "sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump), then restart backend.")
    LIVE[sid] = {"proc": proc, "path": path, "t0": time.time(), "off": 0}
    return {"session": sid}

@app.get("/api/live/poll")
def live_poll(session: str):
    import time
    s = LIVE.get(session)
    if not s: raise HTTPException(404, "session gone - start again")
    try:
        pkts = rdpcap(s["path"])
    except Exception:
        pkts = []
    new = pkts[s["off"]:]
    s["off"] = len(pkts)
    esp = sum(1 for p in new if p.haslayer(ESP))
    rows = [{"t": round(float(p.time) - s["t0"], 1),
             "d": f"{p[IP].src}→{p[IP].dst}" if p.haslayer(IP) else "?",
             "pr": "ESP" if p.haslayer(ESP) else ("IKE" if p.haslayer(UDP) else "?"),
             "len": len(p)} for p in new[-15:]]
    return {"alive": s["proc"].poll() is None, "total": len(pkts),
            "elapsed": round(time.time() - s["t0"], 1),
            "new": len(new), "new_esp": esp, "recent": rows}

@app.post("/api/live/stop")
def live_stop(session: str):
    s = LIVE.pop(session, None)
    if not s: raise HTTPException(404, "session gone")
    s["proc"].terminate()
    try: s["proc"].wait(timeout=5)
    except Exception: s["proc"].kill()
    cid = f"cap_{uuid.uuid4().hex[:8]}"
    try:
        obs = analyze(s["path"], cid)
    except Exception as e:
        raise HTTPException(400, f"parse failed: {e}")
    sec = assess(obs)
    db_save(cid, "live-capture.pcap", s["path"], obs, sec)
    return {"capture_id": cid, "observed": obs, "security": sec}

class LLMReq(__import__("pydantic").BaseModel):
    api_key: str
    model: str = "gemini-2.0-flash"
    base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai"

class ChatReq(__import__("pydantic").BaseModel):
    api_key: str = ""
    model: str = ""
    base_url: str = ""
    messages: list = []
    context: dict = {}

def _llm_conf(req_key="", req_model="", req_base=""):
    import os
    key = req_key or os.environ.get("LLM_KEY", "")
    model = req_model or os.environ.get("LLM_MODEL", "gemini-2.0-flash")
    base = req_base or os.environ.get("LLM_BASE", "https://generativelanguage.googleapis.com/v1beta/openai")
    return key, model, base

@app.get("/api/llm/status")
def llm_status():
    import os
    return {"configured": bool(os.environ.get("LLM_KEY", "")),
            "model": os.environ.get("LLM_MODEL", "gemini-2.0-flash")}

@app.post("/api/chat")
def chat(req: ChatReq):
    import json as _json, urllib.request as _url
    key, model, base = _llm_conf(req.api_key, req.model, req.base_url)
    if not key:
        raise HTTPException(400, "Chat brain not connected. Set LLM_KEY where the backend runs, then restart it.")
    sys = ("You are an assistant inside an IPsec VPN analysis dashboard. "
           "Answer briefly in plain words. Use the provided analysis context when relevant. "
           "Never invent packet numbers; say when something needs device config. "
           f"Context: {_json.dumps(req.context)[:3000]}")
    msgs = [{"role": "system", "content": sys}]
    for m in req.messages[-10:]:
        if isinstance(m, dict) and m.get("content"):
            msgs.append({"role": m.get("role", "user"), "content": str(m["content"])[:2000]})
    body = _json.dumps({"model": model, "messages": msgs,
                        "max_tokens": 300, "temperature": 0.3}).encode()
    q = _url.Request(base.rstrip("/") + "/chat/completions", data=body,
                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with _url.urlopen(q, timeout=40) as resp:
            out = _json.load(resp)
        return {"reply": out["choices"][0]["message"]["content"].strip(), "model": model}
    except Exception as e:
        raise HTTPException(502, f"Chat failed: {e}.")

@app.post("/api/captures/{cid}/llm")
def llm_enhance(cid: str, req: LLMReq):
    import json as _json, urllib.request as _url
    key, model, base = _llm_conf(req.api_key, req.model, req.base_url)
    if not key:
        raise HTTPException(400, "LLM not connected. Set LLM_KEY where the backend runs, then restart it.")
    r = db_get(cid)
    if not r: raise HTTPException(404, "not found")
    obs, sec = r["observed"], r["security"]
    try:
        ai = classify_data(r["path"], cid, obs)
    except Exception:
        ai = {"label": "unknown", "confidence": 0}
    prompt = ("You are a VPN security analyst. Write a short executive paragraph (max 120 words, plain words) "
              "from these tool findings. Do not invent numbers. End with the single most urgent fix.\n"
              f"Packets={obs['packet_count']} ESP={obs['esp_packets']} IKE={obs['ike_detected']} "
              f"versions={obs.get('ike_versions')} SPIs={obs.get('spis_observed')} risk={sec['risk']} "
              f"findings={[x['check']+':'+x['severity']+':'+x['description'] for x in sec['findings']]} "
              f"AI guess={ai.get('label')}@{ai.get('confidence')}.")
    body = _json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 250, "temperature": 0.3}).encode()
    q = _url.Request(base.rstrip("/") + "/chat/completions", data=body,
                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with _url.urlopen(q, timeout=40) as resp:
            out = _json.load(resp)
        text = out["choices"][0]["message"]["content"].strip()
    except Exception as e:
        raise HTTPException(502, f"LLM call failed: {e}.")
    return {"capture_id": cid, "llm_text": text, "model": model}
