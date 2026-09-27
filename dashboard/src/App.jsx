import { useState, useMemo, useEffect } from "react";

const API = "http://127.0.0.1:8000";
const SEV = { high: "#dc2626", medium: "#d97706", info: "#0284c7", low: "#16a34a" };
const RISK_STYLE = {
  HIGH: { bg: "#dc2626", plain: "Needs attention now. Something important looks weak." },
  MEDIUM: { bg: "#d97706", plain: "Basics are OK. A couple of things should be fixed." },
  LOW: { bg: "#16a34a", plain: "Looks healthy. Nothing urgent found." },
};

const NAV = [
  ["dash", "Dashboard", "M3 12l9-9 9 9 M5 10v10h5v-6h4v6h5V10"],
  ["history", "History", "M12 8v5l3 2 M21 12a9 9 0 1 1-9-9"],
  ["files", "Files", "M21 8l-9-5-9 5v8l9 5 9-5V8z M3 8l9 5 9-5 M12 13v8"],
  ["reports", "Reports", "M6 3h9l4 4v14H6z M14 3v5h5"],
  ["live", "Live", "M12 3v3 M12 18v3 M3 12h3 M18 12h3 M5.6 5.6l2.1 2.1 M16.3 16.3l2.1 2.1 M18.4 5.6l-2.1 2.1 M7.7 16.3l-2.1 2.1"],
  ["ask", "Assistant", "M21 12a8 8 0 0 1-8 8H5l-2 2V12a8 8 0 0 1 8-8h2a8 8 0 0 1 8 8z"],
  ["metrics", "Model", "M3 17l6-6 4 4 8-8 M15 7h6v6"],
  ["learn", "Learn", "M4 19.5A2.5 2.5 0 0 1 6.5 17H20 M4 19.5A2.5 2.5 0 0 0 6.5 22H20V2H6.5A2.5 2.5 0 0 0 4 4.5v15z"],
];
function Icon({ d }) {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d={d} /></svg>;
}

const SAMPLES = [
  { n: "Sample 01 · Ping", f: "sample_001_icmp_esp.pcap", e: "Even flows, one packet size.", p: "~/ipsec-analyzer/samples/sample_001_icmp_esp.pcap" },
  { n: "Sample 02 · Web", f: "sample_002_http_esp.pcap", e: "Mixed sizes 88–1476.", p: "~/ipsec-analyzer/samples/sample_002_http_esp.pcap" },
  { n: "Sample 03 · Handshake", f: "sample_003_ike_esp.pcap", e: "IKE true + ESP.", p: "~/ipsec-analyzer/samples/sample_003_ike_esp.pcap" },
  { n: "Sample 04 · Tunnel ping", f: "sample_004_tunnel_icmp.pcap", e: "Outer ESP only, inner hidden.", p: "~/ipsec-analyzer/samples/sample_004_tunnel_icmp.pcap" },
  { n: "Sample 05 · AES-256 tunnel", f: "sample_005_tunnel_aes256.pcap", e: "Stronger cipher in SA.", p: "~/ipsec-analyzer/samples/sample_005_tunnel_aes256.pcap" },
  { n: "Sample 06 · Old handshake", f: "sample_006_weak_ikev1.pcap", e: "IKEv1 on wire → expect HIGH risk.", p: "~/ipsec-analyzer/samples/sample_006_weak_ikev1.pcap" },
  { n: "Sample 07 · Healthy session", f: "sample_007_strong_ikev2.pcap", e: "IKEv2 + data → expect LOW risk.", p: "~/ipsec-analyzer/samples/sample_007_strong_ikev2.pcap" },
  { n: "Sample 08 · VoIP-like", f: "sample_008_voip.pcap", e: "Tiny steady boxes every 20ms both ways.", p: "~/ipsec-analyzer/samples/sample_008_voip.pcap" },
  { n: "Sample 09 · Video-like", f: "sample_009_video.pcap", e: "Big steady one-way flow.", p: "~/ipsec-analyzer/samples/sample_009_video.pcap" },
  { n: "Sample 10 · Bulk", f: "sample_010_bulk.pcap", e: "Big bursts, one direction.", p: "~/ipsec-analyzer/samples/sample_010_bulk.pcap" },
  { n: "Sample 11 · GCM tunnel", f: "sample_011_gcm_tunnel.pcap", e: "AES-GCM tunnel, inner hidden.", p: "~/ipsec-analyzer/samples/sample_011_gcm_tunnel.pcap" },
];

const STAT_INFO = {
  Packets: ["Total packets read from the file.", "Shows how busy the capture is. Under 20 = too short to trust.", "Counted line by line from the PCAP.", "Look for: 0 means empty or wrong filter; 500k+ means trim before upload."],
  ESP: ["Locked data boxes (protocol 50).", "High share means the tunnel carried real traffic, not just handshake.", "Packets with ESP header ÷ total.", "Look for: 90%+ in data captures; 0% means no VPN data."],
  Handshake: ["IKE hello on UDP 500/4500 at tunnel start.", "Proves keys were agreed in this file. Absent = static keys or late recording.", "UDP packets to/from ports 500 or 4500.", "Look for: Sample 03 shows Yes; 001/002 show No."],
  Time: ["Capture length in seconds.", "Short + many packets = burst. Long + few = idle.", "Last packet time minus first.", "Look for: under 1s with 5000 packets = iperf flood."],
  Volume: ["Bytes on the wire.", "Tells load size. Useful for cost and capacity.", "Sum of every packet length.", "Look for: KB = chat-like; MB+ = bulk."],
  Talks: ["Unique direction pairs.", "2 = one chat both ways. Many = busy network.", "Grouped by from→to + protocol.", "Look for: click a row to filter packets."],
  timeline: ["The file squeezed into 24 bars.", "Shows when traffic was busy or quiet. Bursts hint downloads; flat low bars hint heartbeats.", "Packets grouped into 24 equal time slices.", "Look for: click a bar to filter the packet table to that slice."],
  loss: ["Every ESP box carries a number per tunnel label.", "Missing numbers prove packets were lost or reordered. Zero loss with complaints means look at delay, not drops.", "Sequence numbers grouped per label; gaps counted.", "Look for: any lost % above 0, and which direction loses."],
};

const MODULES = [
  { id: "net", t: "Networking basics",
    b: "IP address = house number. Packet = letter. Port = room number. Protocol = delivery rules.",
    deep: ["Every packet has a header (from, to, protocol) and a payload (the message). Switches read headers, never payloads.",
      "Ports pick the program: 500/4500 means IKE handshake, web is 80/443. Our filter buttons use exactly this.",
      "MTU caps box size near 1500B. Bigger messages split into many boxes — that is why video makes big steady flows."],
    see: "Key numbers → Talks shows from→to pairs. Packets table shows ports and TTL per row.",
    q: ["What is a packet?", ["A letter with from/to addresses", "A password", "A VPN key"], 0] },
  { id: "vpn", t: "VPN basics",
    b: "A VPN is a locked tunnel. Outsiders see boxes moving, not the message inside.",
    deep: ["A tunnel wraps each original packet inside a new one. The outer addresses are the tunnel ends; inner addresses hide inside the lock.",
      "Why it matters: coffee-shop Wi-Fi snoopers see only locked boxes to one server, not your sites or logins.",
      "Cost: locks add bytes (overhead) and CPU. Small chats barely notice; bulk pays more."],
    see: "Sample 04 vs 01: same ping, tunnel boxes are bigger — that extra is the wrapping cost.",
    q: ["Why use a VPN?", ["Hide traffic on unsafe networks", "Make internet faster", "Remove passwords"], 0] },
  { id: "ipsec", t: "IPsec: ESP + IKE",
    b: "ESP carries locked data. IKE is the handshake that agrees the locks.",
    deep: ["ESP = protocol 50. IPsec tunnel mode ESP hides the whole inner packet; transport mode hides only the payload.",
      "IKE runs on UDP 500, switching to 4500 when NAT is in the way. No IKE in file = keys were set by hand or recording started late.",
      "AH (protocol 51) only signs, never locks — rare today. If you see it, ask why ESP was not used."],
    see: "Packets table: ESP rows vs IKE rows. Overview counts each share.",
    q: ["Which part carries data?", ["ESP", "IKE_SA_INIT", "SPI"], 0] },
  { id: "ike", t: "IKE handshake",
    b: "INIT swaps math pieces. AUTH proves identity. Then CHILD_SA carries data.",
    deep: ["IKE_SA_INIT: both sides shout proposals (ciphers, DH groups) and swap public math values. Nothing secret travels yet.",
      "IKE_AUTH: each side proves identity (password or certificate) and the first data tunnel (CHILD_SA) is born inside it.",
      "Rekeys repeat a smaller exchange later. New SPIs after rekey are normal — same tunnel, fresh keys, not an attack."],
    see: "VPN facts → handshake diagram. Sample 03 shows INIT then AUTH then ESP.",
    q: ["What is CHILD_SA?", ["The data tunnel agreed by IKE", "A password file", "A port number"], 0] },
  { id: "sa", t: "SA, SPI, lifetime",
    b: "SA = agreed rules + keys. SPI = its label. Lifetime = key age before fresh ones.",
    deep: ["One SA covers one direction, so a chat always has two SPIs. Rekey makes two more; old labels going quiet is healthy.",
      "Lifetime trades safety for smoothness: short life limits stolen-key damage, long life avoids rekey hiccups. Hours, not days, is typical.",
      "Our loss check groups boxes per SPI label and counts missing numbers per label — that only works because labels mark key eras."],
    see: "Overview labels, loss check per label, packet rows show label + number.",
    q: ["New SPI means?", ["Fresh keys/SA", "Broken VPN", "Plaintext leak"], 0] },
  { id: "crypto", t: "Ciphers",
    b: "AES-128 is fine. AES-256-GCM is stronger and checks tampering too.",
    deep: ["CBC locks in chains and needs a separate integrity tag (HMAC). GCM locks and tags in one pass — faster and safer against padding tricks.",
      "128 vs 256 bits: both unbroken today; 256 buys margin against future math and quantum-assisted search. GCM-256 is the modern default ask.",
      "Critical limit: none of this is visible in ESP bytes. Anyone claiming cipher-from-capture is guessing — demand device config."],
    see: "Safety details → Cipher detail finding is always info-grade for exactly this reason.",
    q: ["Best listed here?", ["AES-256-GCM", "DES", "None"], 0] },
  { id: "dh", t: "DH + PFS",
    b: "DH math makes secrets. Bigger group = stronger. PFS makes fresh keys each time.",
    deep: ["Diffie-Hellman lets two sides agree a secret over open air using public math pieces. Group number = math size: 1024 broken-ish, 2048 minimum, 3072+ comfortable.",
      "PFS forces a fresh DH run per rekey, so stealing today's key cannot unlock yesterday's chats. Without it, one leak decrypts history.",
      "Our stance: DH/PFS come from device settings. The dashboard flags them only when config is supplied, never from ESP."],
    see: "Safety details explains why each crypto item stays info-grade without config.",
    q: ["PFS disabled means?", ["A security finding", "ESP disappears", "Nothing"], 1] },
  { id: "modes", t: "Tunnel vs transport",
    b: "Transport = computer to computer. Tunnel = network to network, inner addresses hidden.",
    deep: ["Transport ESP keeps original IP headers visible — fine host-to-host. Tunnel wraps everything; watchers see only gateway IPs.",
      "Test: if inner office addresses never appear on the wire, it is tunnel mode. Our Sample 04 proves it: inner 192.168.x never shows.",
      "Gotcha we hit: routes and ping source must match tunnel selectors, or packets dodge the tunnel in plaintext."],
    see: "Who-talked flows: outer IPs only in tunnel captures.",
    q: ["Inner IPs hidden means?", ["Tunnel mode", "No VPN", "Error"], 0] },
  { id: "pcap", t: "Reading a capture",
    b: "Open Packets: locked rows vs handshake rows. Click any row for label, number and size.",
    deep: ["Read top-down: handshake first (UDP 500), then ESP flood. ESP before handshake = recording started late.",
      "Size column is the classifier's eyes: one repeated size = heartbeat app; mixed sizes = mixed content; 1400s = bulk.",
      "Time column is the other eye: 0.2s rhythm = scheduled pings; 0.02s both-ways = voice-like; bursts = downloads."],
    see: "Packets + timeline bars + AI numbers all read the same three columns.",
    q: ["An ESP row hides?", ["Message content", "Packet size", "Time"], 0] },
  { id: "risk", t: "Reading your risk",
    b: "HIGH = old handshake seen, fix now. MEDIUM = data without handshake, version unverified. LOW = modern handshake plus data.",
    deep: ["Risk is a rule score, not a lab certificate. It answers 'what did this file prove?' — nothing more.",
      "MEDIUM is the honest middle: tunnel works, but the file cannot prove the version. Fix by capturing from tunnel start.",
      "Empty file scores HIGH on purpose: judging nothing as safe would be the real bug."],
    see: "Safety result card + Why button list the exact causing findings.",
    q: ["MEDIUM often means?", ["Handshake missing from file", "No packets", "Broken lock"], 0] },
  { id: "practice", t: "Practice files",
    b: "Sample 06 gives HIGH, 07 gives LOW, 01 gives MEDIUM. Predict first, then Analyze to check yourself.",
    deep: ["Drill 1: open 02, guess web or bulk from the size mix, then check AI votes per piece.",
      "Drill 2: open 06, find the IKEv1 rows in Packets, then read why risk is HIGH.",
      "Drill 3: compare 01 vs 04 in History — same ping, different wrapping cost."],
    see: "History compare table is built for exactly these drills.",
    q: ["Sample 06 is HIGH because?", ["IKEv1 on the wire", "Big packets", "Many packets"], 0] },
];
const GLOSS = [
  ["AES", "Lock type. 128 fine, 256-GCM stronger.", "Security"],
  ["CHILD_SA", "Data tunnel agreed by IKE.", "VPN section"],
  ["DH", "Handshake math. Bigger group is stronger.", "Security"],
  ["ESP", "Locked data packets.", "Everywhere"],
  ["IKE", "Handshake on UDP 500/4500.", "VPN section"],
  ["PFS", "Fresh keys each time.", "Security"],
  ["PCAP", "Recorded packet file.", "Files"],
  ["SPI", "Tunnel label, e.g. 0xcb58.", "Overview"],
];

const fmtB = b => b > 1048576 ? (b / 1048576).toFixed(1) + " MB" : Math.round((b || 0) / 1024) + " KB";
const WHY = {
  "IKE version": "Old handshakes have known flaws. New one fixes them.",
  "Handshake version": "No handshake means we cannot prove the version. Attackers love unverified setups.",
  "Tunnel health": "A live tunnel means keys worked. Silence means broken path or policy.",
  "Encryption": "Weak locks can be broken with time and computers.",
  "Cipher detail": "You cannot judge a lock you cannot see. Check device settings instead.",
  "DH group": "Short handshake math can be cracked. Longer math resists.",
  "PFS": "Without fresh keys, one leak can unlock old chats.",
  "Authentication": "Guessable passwords let strangers join the tunnel.",
  "Metadata": "Visible labels and sizes are normal. Only content must stay hidden.",
  "Capture": "Empty files prove nothing. Record while traffic flows.",
  "VPN data": "No VPN packets means wrong capture point or filter.",
};
const fmtD = s => s >= 60 ? `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.round(s % 60)).padStart(2, "0")}` : s + "s";

function FlowRow({ f, pkts, dur, onPick }) {
  const N = 12;
  const bars = Array(N).fill(0);
  if (pkts) for (const p of pkts.packets) {
    if (p.src === f.src_ip && p.dst === f.dst_ip) {
      const bi = Math.min(N - 1, Math.floor((p.time / (dur || 1)) * N));
      bars[bi]++;
    }
  }
  const m = Math.max(1, ...bars);
  return <div style={{ marginBottom: 10 }}>
    <p style={{ margin: "0 0 4px" }}><code>{f.src_ip} → {f.dst_ip}</code> [{f.protocol}] × {f.packet_count} · {fmtB(f.bytes || 0)} <button className="btn ghost" onClick={onPick}>Only these →</button></p>
    <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 34, background: "#f8fafc", borderRadius: 8, padding: 4 }}>
      {bars.map((b, i) => <div key={i} style={{ flex: 1, background: "#0284c7", borderRadius: 2, height: Math.max(2, b / m * 26) }} title={`${b} packets`} />)}
    </div></div>;
}

export default function App() {
  const [page, setPage] = useState("dash");
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [cls, setCls] = useState(null);
  const [sum, setSum] = useState(null);
  const [pkts, setPkts] = useState(null);
  const [pktErr, setPktErr] = useState("");
  const [info, setInfo] = useState(null);
  const [hist, setHist] = useState([]);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [at, setAt] = useState("");
  const [why, setWhy] = useState(false);
  const [pf, setPf] = useState("All");
  const [dq, setDq] = useState("");
  function dqMatch(p) {
    const q = dq.trim().toLowerCase();
    if (!q) return true;
    return q.split(/\s+/).every(t => {
      let m = t.match(/^len([<>]=?)(\d+)$/);
      if (m) { const v = +m[2]; return m[1] === ">" ? p.length > v : m[1] === "<" ? p.length < v : m[1] === ">=" ? p.length >= v : p.length <= v; }
      m = t.match(/^(src|dst|proto|spi)=(.+)$/);
      if (m) { const f = m[1] === "proto" ? p.protocol : m[1] === "spi" ? (p.spi || "") : p[m[1]]; return String(f).toLowerCase().includes(m[2]); }
      m = t.match(/^port=(\d+)$/);
      if (m) return String(p.sport) === m[1] || String(p.dport) === m[1];
      return `${p.src} ${p.dst} ${p.protocol} ${p.spi || ""} ${p.length}`.toLowerCase().includes(t);
    });
  }
  const [tMode, setTMode] = useState("packets");
  const [bSel, setBSel] = useState(null);
  const [t0, setT0] = useState(null);
  const [t1, setT1] = useState(null);
  const [sel, setSel] = useState(null);
  const [flow, setFlow] = useState(null);
  const [mod, setMod] = useState(null);
  const [ans, setAns] = useState({});
  const [gq, setGq] = useState("");
  const [cmp, setCmp] = useState([]);
  const [liveS, setLiveS] = useState(10);
  const [liveF, setLiveF] = useState("esp or udp port 500 or udp port 4500");
  const [sess, setSess] = useState(null);
  const [tick, setTick] = useState(null);
  async function liveStart() {
    setErr(""); setLoading(true);
    try {
      const r = await fetch(`${API}/api/live/start`, { method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ seconds: liveS, filter: liveF, iface: "any" }) });
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setSess(j.session); setTick({ total: 0, elapsed: 0, recent: [] });
    } catch (e) { setErr("Live start failed: " + String(e)); }
    finally { setLoading(false); }
  }
  async function livePoll() {
    if (!sess) return;
    try {
      const r = await fetch(`${API}/api/live/poll?session=${sess}`);
      if (!r.ok) throw new Error(await r.text());
      setTick(await r.json());
    } catch (e) { setErr("Live feed lost: " + String(e)); setSess(null); }
  }
  useEffect(() => {
    if (!sess) return;
    const t = setInterval(livePoll, 2000);
    return () => clearInterval(t);
  });
  async function liveStop() {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/live/stop?session=${sess}`, { method: "POST" });
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setData(j); setCls(null); setSum(null); setPkts(null); setAt(new Date().toLocaleString());
      setFile({ name: "live capture" }); setSess(null); setTick(null);
      setHist(h => [{ cid: j.capture_id, name: "live capture", time: new Date().toLocaleString(), risk: j.security.risk, n: j.observed.packet_count, data: j }, ...h].slice(0, 20));
      fetch(`${API}/api/captures/${j.capture_id}/classify`).then(x => x.ok ? x.json().then(setCls) : null).catch(() => {});
      fetch(`${API}/api/captures/${j.capture_id}/summary`).then(x => x.ok ? x.json().then(setSum) : null).catch(() => {});
      fetch(`${API}/api/captures/${j.capture_id}/packets?limit=2000`).then(x => x.ok ? x.json().then(setPkts) : null).catch(() => {});
      setPage("dash");
    } catch (e) { setErr("Stop failed: " + String(e)); }
    finally { setLoading(false); }
  }
  const [llmT, setLlmT] = useState("");
  const [llmBusy, setLlmBusy] = useState(false);
  const [llmOk, setLlmOk] = useState(null);
  useEffect(() => { fetch(`${API}/api/llm/status`).then(x => x.ok ? x.json().then(s => setLlmOk(s.configured)) : null).catch(() => {}); }, []);
  const [chat, setChat] = useState([]);
  const [chatIn, setChatIn] = useState("");
  const [chatBusy, setChatBusy] = useState(false);
  const [met, setMet] = useState(null);
  useEffect(() => { fetch(`${API}/api/metrics`).then(x => x.ok ? x.json().then(setMet) : null).catch(() => {}); }, []);
  function localAnswer(q) {
    const t = q.toLowerCase();
    const has = !!obs;
    const num = (label, v) => `${label}: ${v}`;
    if (/summar|overview|what.*(file|found|show)|result/.test(t) && has) {
      return `This file holds ${obs.packet_count} packets over ${obs.duration_sec}s — ${obs.esp_packets} locked ESP boxes${obs.ike_detected ? " plus a handshake, so the key agreement is visible" : " with no handshake, so the version cannot be proven"}. Verdict: ${sec.risk} risk. ${cls ? `The shape reads as ${cls.label} traffic at ${Math.round(cls.confidence * 100)}%.` : ""} ${bad.length ? "Top fix: " + bad[0].recommendation : "Nothing urgent."} (offline answer from your file's numbers)`;
    }
    if (/why.*risk|risk.*why|why.*(high|medium|low)/.test(t) && has) {
      if (!bad.length) return `Risk is ${sec.risk} because nothing bad was found — every check passed or is healthy info. (offline answer)`;
      return `Risk is ${sec.risk} because: ` + bad.map(f => `${f.check} — ${f.description} Fix: ${f.recommendation}`).join(" ") + " (offline answer from your findings)";
    }
    if (/fix|improve|next|should.*do|recommend/.test(t) && has) {
      if (!bad.length) return "Nothing to fix. Keep settings and re-check after any change. (offline answer)";
      return "In order: " + bad.map((f, i) => `${i + 1}) ${f.check}: ${f.recommendation}`).join(" ") + " (offline answer)";
    }
    if (/spi|label/.test(t) && has) {
      return `Tunnel labels in this file: ${obs.spis_observed.join(", ") || "none"}. A label marks one key era — same label means same secret chat, a new label means fresh keys after rekey. Open Packets to see each box's label and number. (offline answer)`;
    }
    if (/loss|drop|missing|gap/.test(t) && has) {
      const sl = (obs.deep && obs.deep.seq_loss) || [];
      if (!sl.length) return "No numbered boxes to check in this file. (offline answer)";
      return sl.map(s => `${s.spi}: ${s.seen}/${s.expected} arrived${s.lost ? `, ${s.lost} missing (${s.loss_pct}%)` : ", nothing missing"}`).join(" ") + " Missing numbers mean lost or reordered packets. (offline answer)";
    }
    if (/ai|model|guess|predict|machine/.test(t)) {
      const cur = has && cls ? ` Right now it reads ${cls.label} at ${Math.round(cls.confidence * 100)}% across ${cls.windows} pieces.` : "";
      return `The AI cuts traffic into 10-packet pieces and reads 9 shape numbers per piece — sizes, gaps, duration, direction — then votes. It never reads messages.${cur} Demo model: small data, treat as hint. (offline answer)`;
    }
    if (/esp/.test(t)) return "ESP = locked data boxes (protocol 50). We see from, to, size, time and label — never the message. High ESP share means the tunnel carried real traffic. (offline answer)";
    if (/ike|handshake/.test(t)) return "IKE = the handshake on UDP 500/4500. INIT swaps math pieces, AUTH proves identity, then the data tunnel is born. No IKE in file = keys set by hand or recording started late. (offline answer)";
    if (/pfs/.test(t)) return "PFS = fresh keys every rekey, so stealing today's key cannot unlock yesterday's chats. Our dashboard reports it from device settings, never from ESP bytes. (offline answer)";
    if (/cipher|aes|encrypt/.test(t)) return "AES-128 is fine, AES-256-GCM is stronger and tamper-proof. Key point: cipher lives in device settings — no tool can read it from locked ESP bytes, and ours never pretends to. (offline answer)";
    if (/tunnel|transport|mode/.test(t)) return "Transport = computer to computer. Tunnel = network to network with inner addresses hidden. If inner office IPs never appear on the wire, it is tunnel mode. (offline answer)";
    if (/pcap|capture|record|tcpdump|wireshark|save|create|upload/.test(t)) return "Record: sudo tcpdump -i any -w myvpn.pcap 'esp or udp port 500 or udp port 4500'. Make traffic while it records, stop with Ctrl-C, check with tcpdump -r, then upload here. Or download a sample from Files. (offline answer)";
    if (/risk|safe|secur/.test(t) && has) return `Current file: ${sec.risk} risk across ${sec.findings.length} checks. ` + sec.findings.map(f => `${f.check} [${f.severity}]: ${f.description}`).join(" ") + " (offline answer)";
    if (/hello|hi|hey/.test(t)) return "Hello. Upload a file on the Dashboard, then ask me why the risk, what to fix, or what any term means. I answer from your file's numbers. (offline answer)";
    return "I answer from your loaded file and built-in lessons. Try: summarize this file, why this risk, what to fix first, what is ESP, how do I record. (offline answer)";
  }
  async function chatGo(preset) {
    const text = (preset !== undefined ? preset : chatIn).trim();
    if (!text) return;
    const mine = { role: "user", content: text };
    const log = [...chat, mine];
    setChat(log); setChatIn(""); setChatBusy(true); setErr("");
    try {
      const ctx = data ? { file: file?.name, observed: data.observed, security: data.security, ai: cls } : {};
      const r = await fetch(`${API}/api/chat`, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: log, context: ctx }) });
      if (!r.ok) throw new Error(await r.text());
      setChat([...log, { role: "assistant", content: (await r.json()).reply }]);
    } catch (e) {
      try {
        setChat([...log, { role: "assistant", content: localAnswer(text) }]);
      } catch (e2) { setErr("Chat failed: " + String(e)); setChat(log); }
    }
    finally { setChatBusy(false); }
  }
  const [theme, setTheme] = useState("light");
  function toggleTheme() {
    const t = theme === "light" ? "dark" : "light";
    setTheme(t); document.documentElement.dataset.theme = t;
  }

  async function analyze() {
    setErr(""); setCls(null); setSum(null); setPkts(null); setPktErr(""); setSel(null); setFlow(null); setBSel(null); setT0(null); setT1(null);
    if (!file) { setErr("Pick a file first. See the Files tab for sample paths."); return; }
    setLoading(true);
    try {
      const fd = new FormData(); fd.append("file", file);
      const r = await fetch(`${API}/api/captures/upload`, { method: "POST", body: fd });
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setData(j); setAt(new Date().toLocaleString());
      setHist(h => [{ cid: j.capture_id, name: file.name, time: new Date().toLocaleString(), risk: j.security.risk, n: j.observed.packet_count, data: j }, ...h].slice(0, 20));
      fetch(`${API}/api/captures/${j.capture_id}/classify`).then(x => x.ok ? x.json().then(setCls) : null).catch(() => {});
      fetch(`${API}/api/captures/${j.capture_id}/summary`).then(x => x.ok ? x.json().then(setSum) : null).catch(() => {});
      fetch(`${API}/api/captures/${j.capture_id}/packets?limit=2000`).then(x => x.ok ? x.json().then(setPkts) : setPktErr("Packet list needs a backend restart (new /packets endpoint).")).catch(() => setPktErr("Packet list failed to load."));
    } catch (e) { setErr("Could not analyze. Is the backend on port 8000? " + String(e)); }
    finally { setLoading(false); }
  }
  async function llmGo() {
    setLlmBusy(true); setErr("");
    try {
      const r = await fetch(`${API}/api/captures/${obs.capture_id}/llm`, { method: "POST",
        headers: { "Content-Type": "application/json" }, body: "{}" });
      if (!r.ok) throw new Error(await r.text());
      setLlmT((await r.json()).llm_text);
    } catch (e) { setErr("LLM failed: " + String(e)); }
    finally { setLlmBusy(false); }
  }
  function openHist(h) {
    setData(h.data); setCls(null); setSum(null); setPkts(null); setPktErr(""); setAt(h.time);
    setFile(null); setPage("dash");
    fetch(`${API}/api/captures/${h.cid}/classify`).then(x => x.ok ? x.json().then(setCls) : null).catch(() => {});
    fetch(`${API}/api/captures/${h.cid}/summary`).then(x => x.ok ? x.json().then(setSum) : null).catch(() => {});
    fetch(`${API}/api/captures/${h.cid}/packets?limit=2000`).then(x => x.ok ? x.json().then(setPkts) : setPktErr("Packet list needs a backend restart (new /packets endpoint).")).catch(() => setPktErr("Packet list failed to load."));
  }

  const obs = data?.observed, sec = data?.security;
  const rs = sec ? RISK_STYLE[sec.risk] : null;
  const bad = sec ? sec.findings.filter(f => f.severity !== "info") : [];
  const buckets = useMemo(() => {
    if (!pkts || !obs) return [];
    const N = 24, dur = obs.duration_sec || 1, out = Array.from({ length: N }, () => ({ n: 0, b: 0 }));
    for (const p of pkts.packets) {
      const bi = Math.min(N - 1, Math.floor((p.time / dur) * N));
      out[bi].n++; out[bi].b += p.length;
    }
    return out;
  }, [pkts, obs]);
  const maxB = Math.max(1, ...buckets.map(b => b.n));
  const shown = useMemo(() => pkts ? pkts.packets.filter(p =>
    (pf === "All" || p.protocol === pf) && (!flow || (p.src === flow.src_ip && p.dst === flow.dst_ip)) &&
    (t0 === null || (p.time >= t0 && p.time < t1)) && dqMatch(p)).slice(0, 150) : [], [pkts, pf, flow, t0, t1, dq]);

  function dl(name, text, type) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click();
  }

  return (
    <div className="layout">
      <div className="side">
        <h1>IPsec Analyzer</h1><small>Upload → understand → fix</small>
        {NAV.map(([id, label, d]) => (
          <button key={id} className={"navbtn" + (page === id ? " on" : "")} onClick={() => setPage(id)}><Icon d={d} /> {label}</button>))}
      </div>
      <div className="main">
        <div className="tophead">
          <b>IPsec VPN Security Analyzer</b>
          <span className="pill" style={{ background: loading ? "#d97706" : obs ? "#16a34a" : "#64748b" }}>{loading ? "Analyzing…" : obs ? "Analysis complete" : "Idle"}</span>
          {obs && <span className="muted">{obs.capture_id} · {at}</span>}
          <span style={{ marginLeft: "auto" }}><button className="btn ghost" onClick={toggleTheme}>{theme === "light" ? "Dark mode" : "Light mode"}</button></span>
        </div>
        <div className="wrap">
          {err && <div className="card" style={{ borderColor: "#dc2626" }}><b style={{ color: "#dc2626" }}>{err}</b></div>}

          {page === "dash" && <>
            <div className="hero"><h1>Drop a VPN file. Get plain answers.</h1>
              <p>We read sizes, times and labels — never messages. Then we say if the setup looks safe and what traffic it carries.</p></div>

            <div className="card"><h2>Check a file</h2>
              <div className="row">
                <input type="file" accept=".pcap,.pcapng,.cap" onChange={e => { setFile(e.target.files[0]); }} />
                <button className="btn" onClick={analyze} disabled={loading}>{loading ? "Reading…" : "Analyze"}</button>
                {file && <span className="muted">{file.name}</span>}
              </div>
              <details className="more"><summary><b>New? How to save your own capture (.pcap) from a terminal</b></summary>
                <p><b>1.</b> Record VPN traffic (10 seconds here): <code>sudo tcpdump -i any -w myvpn.pcap 'esp or udp port 500 or udp port 4500'</code></p>
                <p><b>2.</b> While it records, make traffic in another terminal: <code>ping -c 10 &lt;vpn-ip&gt;</code></p>
                <p><b>3.</b> Stop with <code>Ctrl-C</code>. Check it: <code>tcpdump -r myvpn.pcap -nn | head</code>. You should see ESP lines.</p>
                <p><b>4.</b> Back here: Choose File → pick <code>myvpn.pcap</code> → Analyze.</p>
                <p className="muted">No VPN? Use Wireshark instead: open it, pick your Wi-Fi → filter <code>esp</code> → browse for a minute → File → Save. Or skip all this and download a sample from the Files tab.</p></details>
            </div>

            {obs && <>
              <div className="card" style={{ borderTop: `6px solid ${rs.bg}` }}>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <div><small className="muted">SAFETY RESULT · simple rule score, demo only</small>
                    <h2 style={{ fontSize: 30, margin: "4px 0" }}><span className="pill" style={{ background: rs.bg, fontSize: 16 }}>{sec.risk} RISK</span></h2>
                    <p style={{ margin: 0 }}>{rs.plain}</p>
                    <p className="muted">VPN found ✓ · Handshake {obs.ike_detected ? `seen ✓ (${(obs.ike_versions || []).join(", ")})` : "not in file"} · Locked packets {obs.esp_packets} · AI guess {cls ? cls.label : "…"}</p></div>
                  <button className="btn ghost" onClick={() => setWhy(!why)}>Why this result? →</button>
                </div>
                {why && <div style={{ marginTop: 10 }}>{bad.length === 0
                  ? <p>Nothing bad found. Basics look fine.</p>
                  : bad.map((f, i) => <p key={i}>• <b>{f.check}:</b> {f.description} <span className="muted">Fix: {f.recommendation}</span></p>)}</div>}
              </div>

              <div className="card" style={{ border: "2px solid #0ea5e9" }}><h2>Ask about this file</h2>
                <p className="muted">The assistant sees this analysis. {llmOk ? "Brain connected ✓ — just ask." : llmOk === false ? "Brain not connected yet (needs the key where the backend runs)." : "Checking brain…"}</p>
                <div className="row noprint">
                  <button className="btn ghost" onClick={() => chatGo("Summarize this capture in 4 short lines: safety, traffic, AI reading, top fix.")}>Summarize this file</button>
                  <button className="btn ghost" onClick={() => chatGo("Why is the risk " + sec.risk + "? Explain each cause simply.")}>Why this risk?</button>
                  <button className="btn ghost" onClick={() => chatGo("What should I fix first, in order?")}>What to fix first?</button>
                  <button className="btn ghost" onClick={() => setPage("ask")}>Open chat →</button>
                </div>
                {chat.length > 0 && chat.slice(-2).map((m, i) => <p key={i} className={m.role === "user" ? "chat-u" : "chat-a"}><b>{m.role === "user" ? "You" : "Assistant"}:</b> {m.content}</p>)}
                {chatBusy && <p className="muted">Thinking…</p>}
                <div className="row noprint" style={{ marginTop: 8 }}>
                  <input value={chatIn} onChange={e => setChatIn(e.target.value)} onKeyDown={e => e.key === "Enter" && chatGo()} placeholder="Ask about this file…" style={{ flex: 1, padding: 8 }} />
                  <button className="btn" onClick={() => chatGo()} disabled={chatBusy}>{chatBusy ? "…" : "Ask"}</button>
                </div></div>

              <div className="card"><h2>Key numbers</h2><div className="grid">
                {[["Packets", obs.packet_count, "s-blue"], ["ESP", obs.esp_packets, "s-green"], ["Handshake", obs.ike_detected ? `Yes · ${obs.ike_packets}` : "No", "s-purple"],
                  ["Time", fmtD(obs.duration_sec), "s-orange"], ["Volume", fmtB(obs.data_volume_bytes || 0), "s-pink"], ["Talks", obs.conversation_count ?? obs.flows.length, "s-slate"]].map(([t, v, c]) => (
                  <div key={t} className={`stat ${c}`}><small>{t}<button className="ibtn" onClick={() => setInfo(t)} title="What is this?">?</button></small><b style={{ fontSize: 20 }}>{v}</b></div>))}
              </div>
                <p className="muted">Types: <b>{obs.protocols_detected.join(", ") || "—"}</b> · Labels: <b>{obs.spis_observed.join(", ") || "—"}</b> · Sizes {obs.packet_length.min}–{obs.packet_length.max} avg {obs.packet_length.avg}</p></div>

              <div className="card" style={{ border: "2px solid #7c3aed" }}><h2>AI guess — what traffic hides inside?</h2>
                {!cls && <p className="muted">Reading pieces… The AI looks only at sizes and gaps, never messages.</p>}
                {cls && <><p style={{ fontSize: 17 }}><b>In plain words:</b> this looks like <b>{cls.label}</b> traffic. {obs.packet_length.avg}B average boxes{obs.deep ? `, arriving every ${obs.deep.gap_avg_ms} ms` : ""}, and {cls.windows} out of {cls.windows} checked pieces agree.</p>
                <div className="row">
                  <div className="stat s-purple" style={{ minWidth: 170 }}><small>AI says</small><b>{cls.label}</b></div>
                  <div className="stat s-blue" style={{ minWidth: 170 }}><small>Sure?</small><b>{Math.round(cls.confidence * 100)}%</b></div>
                  <div className="stat s-green" style={{ minWidth: 170 }}><small>Pieces read</small><b>{cls.windows}</b></div></div>
                  <h3 style={{ marginTop: 14 }}>All guesses</h3>
                  {Object.entries(cls.dist || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
                    <div key={k} className="row" style={{ marginBottom: 6 }}><span style={{ width: 90 }}><b>{k}</b></span>
                      <div style={{ flex: 1, background: "#f1f5f9", borderRadius: 8, height: 12 }}>
                        <div style={{ width: `${Math.round(v * 100)}%`, background: k === cls.label ? "#7c3aed" : "#94a3b8", height: 12, borderRadius: 8 }} /></div>
                      <span className="muted" style={{ width: 120 }}>{Math.round(v * 100)}% · {cls.votes[k] || 0} pieces</span></div>))}
                  <h3 style={{ marginTop: 14 }}>Numbers behind the guess</h3>
                  {obs.deep ? <>
                    {obs.deep.size_hist.map(h => { const m = Math.max(1, ...obs.deep.size_hist.map(x => x.count)); return (
                      <div key={h.range} className="row" style={{ marginBottom: 4 }}><span style={{ width: 130 }} className="muted">{h.range}</span>
                        <div style={{ flex: 1, background: "#f1f5f9", borderRadius: 8, height: 10 }}>
                          <div style={{ width: `${Math.round(h.count / m * 100)}%`, background: "#7c3aed", height: 10, borderRadius: 8 }} /></div>
                        <span className="muted" style={{ width: 50 }}>{h.count}</span></div>); })}
                    <p>Boxes arrive about <b>every {obs.deep.gap_avg_ms} ms</b> (±{obs.deep.gap_std_ms} ms). Steady gaps = machine rhythm. Jump gaps = human clicks.</p>
                  </> : <p className="muted">Re-upload the file to see this.</p>}
                  <details className="more" open><summary><b>Why this guess? (from your file's numbers)</b></summary>
                    {(cls.reasons || []).length === 0 && <p className="muted">No strong pattern stood out.</p>}
                    {(cls.reasons || []).map((r, i) => <p key={i} style={{ margin: "4px 0" }}>• {r}</p>)}
                  </details>
                  <details className="more"><summary><b>What did it look at?</b></summary>
                    <p>{(cls.feats_used || []).join(" · ")}</p>
                    <p className="muted">Plain meaning: even small boxes with steady gaps → ping-like. Mixed small and big boxes → web-like. Big boxes one way → bulk-like. Handshake hellos on UDP 500 → handshake.</p></details>
                  <details className="more"><summary><b>Piece evidence (first {cls.sample_windows?.length || 0})</b></summary>
                    <table className="kv"><thead><tr><th>#</th><th>Guess</th><th>Sure</th><th>Avg size</th></tr></thead><tbody>
                      {(cls.sample_windows || []).map(w => <tr key={w.window}><td>{w.window}</td><td>{w.pred}</td><td>{Math.round(w.conf * 100)}%</td><td>{w.avg_size} ({w.size_min}–{w.size_max})</td></tr>)}
                    </tbody></table></details>
                  <p className="muted">Hint only, not proof. Demo model on tiny data — {cls.note}.</p></>}</div>

              <div className="card"><h2>Traffic over time <button className="ibtn" style={{ borderColor: "#cbd5e1", background: "#f1f5f9", color: "#0f172a" }} onClick={() => setInfo("timeline")}>?</button></h2>
                <p className="muted">What is this? The whole file squeezed into 24 bars. Tall bar = many packets there. Click a bar to filter packets below.</p>
                <details className="more"><summary><b>Read this graph deeply</b></summary>
                  <p><b>Flat even bars</b> mean steady rhythm — machines talking on schedule, like ping every 200 ms or voice packets every 20 ms.</p>
                  <p><b>One tall spike</b> means a sudden burst — a download starting, a page loading, or a flood. Check that slice's packets.</p>
                  <p><b>Gaps (missing bars)</b> mean silence — tunnel idle, or the recording paused. Long silence with complaints points at stalls, not loss.</p>
                  <p><b>Bytes vs packets:</b> packets show how chatty, bytes show how heavy. A tall byte bar with a short packet bar = few huge boxes (video/bulk). Tall in both = many boxes (flood/chat).</p>
                  <p><b>Duplicates:</b> files recorded on 'any' hear each packet twice, so counts double but the shape stays true.</p></details>
                {!pkts ? <p className="muted">{pktErr || "Loading packets…"}</p> :
                  <><div className="row noprint" style={{ marginBottom: 6 }}>
                    <button className={"btn " + (tMode === "packets" ? "" : "ghost")} onClick={() => setTMode("packets")}>Packets</button>
                    <button className={"btn " + (tMode === "bytes" ? "" : "ghost")} onClick={() => setTMode("bytes")}>Bytes</button>
                    <span className="muted">Packets = how many. Bytes = how much data.</span></div>
                    <div className="bars">{buckets.map((b, i) => { const v = tMode === "bytes" ? b.b : b.n; const mx = tMode === "bytes" ? Math.max(1, ...buckets.map(x => x.b)) : maxB; return (
                      <div key={i} className="bar" style={{ height: Math.max(3, v / mx * 110), background: bSel === i ? "#db2777" : undefined }} title={tMode === "bytes" ? `${v} bytes` : `${v} packets`} onClick={() => setBSel(bSel === i ? null : i)} />); })}</div>
                    <p className="muted">Tall bar = busy moment. {pkts.truncated ? `First ${pkts.shown} of ${pkts.total}.` : `${pkts.total} packets.`}
                    {bSel !== null && <> Slice {bSel}: <b>{buckets[bSel].n} packets, {fmtB(buckets[bSel].b)}</b> (≈{(obs.duration_sec / 24 * bSel).toFixed(1)}–{(obs.duration_sec / 24 * (bSel + 1)).toFixed(1)}s). <button className="btn ghost" onClick={() => { setT0(obs.duration_sec / 24 * bSel); setT1(obs.duration_sec / 24 * (bSel + 1)); }}>Show these packets ↓</button> <button className="btn ghost" onClick={() => { setBSel(null); setT0(null); }}>Clear</button></>}</p></>}</div>

              <div className="card"><h2>Packet loss check <button className="ibtn" style={{ borderColor: "#cbd5e1", background: "#f1f5f9", color: "#0f172a" }} onClick={() => setInfo("loss")}>?</button></h2>
                {!obs.deep ? <p className="muted">Re-upload the file to see this.</p> :
                  (obs.deep.seq_loss || []).length === 0 ? <p className="muted">No numbered ESP boxes to check.</p> :
                  (obs.deep.seq_loss || []).every(s => s.lost === 0)
                    ? <p>Clean run — every numbered box arrived ({(obs.deep.seq_loss || []).map(s => `${s.spi} ${s.seen}/${s.expected}`).join(" · ")}). {obs.deep.dup_esp > 0 ? `Note: ${obs.deep.dup_esp} repeats seen, recording heard twice.` : ""}</p>
                    : (obs.deep.seq_loss || []).map(s => <p key={s.spi}><code>{s.spi}</code> boxes {s.from}–{s.to}: seen <b>{s.seen}/{s.expected}</b> · lost <b>{s.lost} ({s.loss_pct}%)</b>
                      {s.lost === 0 ? " — clean." : <> — gaps at {s.missing.join(", ")}{s.truncated_list ? ",…" : ""}. Gaps mean lost or reordered packets.</>}</p>)}
                <p className="muted">What is this? Every locked box is numbered. Missing numbers = packets that never arrived.</p></div>

              <div className="card"><h2>Who talked</h2>
                {obs.flows.map((f, i) => <FlowRow key={i} f={f} pkts={pkts} dur={obs.duration_sec} onPick={() => setFlow(f)} />)}
                <p className="muted">Even both ways = chat. One side heavy = download. Bars show when each talker spoke.</p></div>

              <div className="card"><h2>Packets (showing {shown.length})</h2>
                {!pkts ? <p className="muted">{pktErr || "Loading…"}</p> :
                  <><div className="row noprint">{["All", "ESP", "IKE"].map(p => <button key={p} className={"btn " + (pf === p ? "" : "ghost")} onClick={() => setPf(p)}>{p}</button>)}
                    <input value={dq} onChange={e => setDq(e.target.value)} placeholder="Filter: len>500 proto=ESP src=10.10" title="Try: len>500, len<200, proto=ESP, src=10.10, port=500" style={{ flex: 1, padding: 8, minWidth: 200 }} />
                    {flow && <button className="btn ghost" onClick={() => setFlow(null)}>Clear ✕</button>}
                    {t0 !== null && <button className="btn ghost" onClick={() => { setT0(null); setT1(null); setBSel(null); }}>Clear time slice ✕</button>}</div>
                    <table className="kv"><thead><tr><th>#</th><th>Time</th><th>From → To</th><th>Proto</th><th>Len</th></tr></thead><tbody>
                      {shown.map(p => <tr key={p.n} onClick={() => setSel(p)} style={{ cursor: "pointer" }}><td>{p.n}</td><td>{p.time}</td><td><code>{p.src}→{p.dst}</code></td><td>{p.protocol}</td><td>{p.length}</td></tr>)}
                    </tbody></table>
                    {sel && <p><b>Packet {sel.n}:</b> t={sel.time}s, {sel.src}{sel.sport ? `:${sel.sport}` : ""}→{sel.dst}{sel.dport ? `:${sel.dport}` : ""}, {sel.protocol}, {sel.length}B{sel.ttl !== null && sel.ttl !== undefined ? `, TTL ${sel.ttl}` : ""}{sel.spi ? `, label ${sel.spi}, seq ${sel.seq}` : ""}. {sel.protocol === "ESP" ? "Locked box: size and time visible, message hidden." : "Handshake hello on UDP 500/4500."}</p>}
                    <div className="row">{obs.flows.map((f, i) => <button key={i} className="btn ghost" onClick={() => setFlow(f)}>Only {f.src_ip}→{f.dst_ip}</button>)}</div></>}</div>

              <div className="card"><h2>Safety details</h2>
                <div className="row" style={{ marginBottom: 12 }}>
                  {[["high", "#dc2626"], ["medium", "#d97706"], ["info", "#0284c7"]].map(([s, c]) => {
                    const n = sec.findings.filter(f => f.severity === s).length;
                    return <span key={s} className="pill" style={{ background: n ? c : "#94a3b8" }}>{n} {s}</span>; })}
                  <span className="muted">Red = fix now. Yellow = improve soon. Blue = healthy.</span>
                </div>
                {sec.findings.map((x, i) => <div key={i} className="finding" style={{ borderLeftColor: SEV[x.severity], borderLeftWidth: 8 }}>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <b style={{ fontSize: 16 }}>{i + 1}. {x.check}</b>
                    <span><span className="pill" style={{ background: SEV[x.severity] }}>{x.severity}</span> <span className="badge b-cfg">{x.source}</span></span>
                  </div>
                  <p style={{ margin: "6px 0" }}>{x.description}</p>
                  <p className="muted" style={{ margin: "4px 0" }}><b>Why care:</b> {WHY[x.check] || "Part of tunnel hygiene."}</p>
                  <details className="more"><summary>Proof from your file</summary>{x.evidence || "—"}</details>
                  <p style={{ margin: "6px 0" }}><b>Fix →</b> {x.recommendation}</p></div>)}
                <div className="tint"><h3>VPN facts used</h3>
                  <p>Handshake: <b>{obs.ike_detected ? `seen (${obs.ike_packets} pkts)` : "not in file"}</b> <span className="badge b-obs">SEEN</span> · Labels: <b>{obs.spis_observed.join(", ") || "—"}</b> <span className="badge b-obs">SEEN</span> · Cipher/PFS/DH: <b>from test settings</b> <span className="badge b-cfg">KNOWN</span> · Message text: <b>never visible</b> <span className="badge b-unk">HIDDEN</span></p>
                  {obs.ike_detected && <div className="seq">Client ── HELLO ──→ Server<br />Client ←── HELLO ── Server<br />···· locked tunnel up ····</div>}</div></div>
            </>}
          </>}

          {page === "history" && <div className="card"><h2>Past checks ({hist.length})</h2>
            {hist.length === 0 && <p className="muted">Nothing yet. Analyze a file on the Dashboard.</p>}
            {hist.map(h => <p key={h.cid}><input type="checkbox" checked={cmp.includes(h.cid)} onChange={() => setCmp(c => c.includes(h.cid) ? c.filter(x => x !== h.cid) : [...c, h.cid].slice(-2))} /> <b>{h.name}</b> · {h.n} packets · <span className="pill" style={{ background: RISK_STYLE[h.risk]?.bg || "#64748b" }}>{h.risk}</span> · {h.time} <button className="btn ghost" onClick={() => openHist(h)}>Open →</button></p>)}
            {cmp.length === 2 && (() => { const [a, b] = cmp.map(c => hist.find(h => h.cid === c)); if (!a || !b) return null;
              const rows = [["Packets", a.data.observed.packet_count, b.data.observed.packet_count], ["ESP", a.data.observed.esp_packets, b.data.observed.esp_packets],
                ["Handshake", a.data.observed.ike_detected ? "yes" : "no", b.data.observed.ike_detected ? "yes" : "no"], ["Time", a.data.observed.duration_sec + "s", b.data.observed.duration_sec + "s"],
                ["Avg size", a.data.observed.packet_length.avg, b.data.observed.packet_length.avg], ["Risk", a.risk, b.risk]];
              return <><h3>Compare: {a.name} vs {b.name}</h3>
                <table className="kv"><thead><tr><th></th><th>{a.name}</th><th>{b.name}</th></tr></thead><tbody>
                  {rows.map(([k, x, y]) => <tr key={k}><td><b>{k}</b></td><td>{x}</td><td>{y}</td></tr>)}
                </tbody></table>
                <button className="btn ghost" onClick={() => setCmp([])}>Clear</button></>; })()}
            {cmp.length > 0 && cmp.length < 2 && <p className="muted">Tick one more to compare two files side by side.</p>}
          </div>}

          {page === "live" && <div className="card"><h2>Live capture</h2>
            <p><b>Step 1.</b> Wake the VPN in a terminal: <code>sudo docker start vpn-server vpn-client</code></p>
            <p><b>Step 2.</b> Press Start below, then make traffic in another terminal: <code>sudo docker exec vpn-client ping -c 20 10.10.0.10</code></p>
            <p><b>Step 3.</b> Watch the counters, press Stop + analyze.</p>
            <p className="muted">One-time setup if the stream dies at once: <code>sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)</code> then restart the backend. Shortcut for all of it: <code>~/ipsec-analyzer/live-demo.sh 10</code></p>
            {!sess ? <div className="row">
              <label style={{ flex: 1 }}>Filter: <input value={liveF} onChange={e => setLiveF(e.target.value)} style={{ width: "100%", padding: 7 }} /></label>
              <button className="btn" onClick={liveStart} disabled={loading}>{loading ? "Starting…" : "Start live stream"}</button>
            </div> : <div>
              <div className="row">
                <div className="stat s-green" style={{ minWidth: 140 }}><small>Packets seen</small><b>{tick?.total ?? 0}</b></div>
                <div className="stat s-blue" style={{ minWidth: 140 }}><small>Seconds</small><b>{tick?.elapsed ?? 0}</b></div>
                <div className="stat s-purple" style={{ minWidth: 140 }}><small>New since tick</small><b>{tick ? `+${tick.new} (${tick.new_esp} ESP)` : "…"}</b></div>
                <button className="btn" onClick={liveStop} disabled={loading}>{loading ? "Stopping…" : "Stop + analyze"}</button>
              </div>
              <table className="kv" style={{ marginTop: 10 }}><thead><tr><th>Time</th><th>Talk</th><th>Type</th><th>Len</th></tr></thead><tbody>
                {(tick?.recent || []).map((r, i) => <tr key={i}><td>{r.t}s</td><td><code>{r.d}</code></td><td>{r.pr}</td><td>{r.len}</td></tr>)}
              </tbody></table>
              <p className="muted">Ticks every 2 seconds straight from the wire.</p>
            </div>}
            <p className="muted">First time? Run once in a terminal: <code>sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)</code> then restart the backend. Without it the stream dies at once.</p>
          </div>}

          {page === "ask" && <div className="card"><h2>Assistant — ask about your capture</h2>
            <p className="muted">Knows your current analysis when one is loaded. {llmOk ? "Brain connected ✓." : llmOk === false ? "Brain not connected yet — start the backend with LLM_KEY set." : "Checking brain…"}</p>
            <div style={{ border: "1px solid var(--line)", borderRadius: 10, padding: 10, margin: "10px 0", minHeight: 120, maxHeight: 320, overflowY: "auto" }}>
              {chat.length === 0 && <p className="muted">Try: "Why is my risk MEDIUM?" or "What should I fix first?"</p>}
              {chat.map((m, i) => <p key={i} className={m.role === "user" ? "chat-u" : "chat-a"}><b>{m.role === "user" ? "You" : "Assistant"}:</b> {m.content}</p>)}
            </div>
            <div className="row noprint">
              <input value={chatIn} onChange={e => setChatIn(e.target.value)} onKeyDown={e => e.key === "Enter" && chatGo()} placeholder="Ask…" style={{ flex: 1, padding: 8 }} />
              <button className="btn" onClick={chatGo} disabled={chatBusy}>{chatBusy ? "…" : "Send"}</button>
            </div>
          </div>}

          {page === "metrics" && <div className="card"><h2>Model scorecard — held-out files only</h2>
            {!met && <p className="muted">Loading… (needs backend with /api/metrics).</p>}
            {met && <>
              <div className="row">
                <div className="stat s-purple" style={{ minWidth: 160 }}><small>Held-out accuracy</small><b>{Math.round(met.accuracy * 100)}%</b></div>
                <div className="stat s-blue" style={{ minWidth: 160 }}><small>Test pieces</small><b>{met.test_windows}</b></div>
                <div className="stat s-green" style={{ minWidth: 160 }}><small>Train pieces</small><b>{met.train_windows}</b></div>
              </div>
              <p className="muted">Method: {met.method}. Test files never appeared in training — this measures new tunnels, not memory.</p>
              <table className="kv"><thead><tr><th>True ↓ / Guess →</th>{met.labels.map(l => <th key={l}>{l}</th>)}</tr></thead><tbody>
                {met.confusion.map((row, i) => <tr key={i}><td><b>{met.labels[i]}</b></td>{row.map((c, j) => <td key={j} style={{ background: i === j && c ? "#dcfce7" : undefined }}><b>{c}</b></td>)}</tr>)}
              </tbody></table>
              <p className="muted">Held-out files: {met.held_out_files.join(", ")}. Weak spots are shown, not hidden — web recall and untested handshake/video are the next dataset sprint.</p>
            </>}
          </div>}

          {page === "files" && <div className="card"><h2>Test files</h2>
            <p className="muted">On disk: <code>~/ipsec-analyzer/samples/</code>. Download any file, then open Dashboard, pick it, press Analyze.</p>
            {SAMPLES.map(s => <div key={s.f} className="finding" style={{ borderLeftColor: "#4f46e5" }}><b>{s.n} · <code>{s.f}</code></b><div>{s.e}</div><div className="muted">{s.p}</div>
              <button className="btn ghost" style={{ marginTop: 6 }} onClick={() => { const a = document.createElement("a"); a.href = `${API}/api/samples/${s.f}`; a.download = s.f; a.click(); }}>Download ↓</button></div>)}
          </div>}

          {page === "reports" && <div className="card"><h2>Security assessment report</h2>
            {!obs && <p className="muted">Analyze a file first.</p>}
            {obs && <><p className="muted">{at} · {obs.capture_id} · {file?.name || "uploaded file"} · prototype rule score, demo AI</p>
              {sum && <div className="tint" style={{ marginBottom: 12 }}>
                <h3>Analyst summary — read this first</h3>
                <p><b>{sum.sections.headline}.</b> {sum.sections.verdict}</p>
                <p>{sum.sections.tunnel} {sum.sections.handshake}</p>
                <p>{sum.sections.traffic}</p>
                <p>{sum.sections.ai_reading}</p>
                <p>{sum.sections.loss}</p>
                <p><b>Risks:</b> {sum.sections.risks.join(" ")}</p>
                <p><b>Next step:</b> {sum.sections.next}</p>
              </div>}
              <h3>Executive summary</h3>
              <p>Capture holds <b>{obs.packet_count}</b> packets over <b>{obs.duration_sec}s</b> ({fmtB(obs.data_volume_bytes || 0)}). Locked ESP traffic: <b>{obs.esp_packets}</b>. Handshake: <b>{obs.ike_detected ? `seen (${obs.ike_packets} packets)` : "not in this file"}</b>. Verdict: <b>{sec.risk} risk</b> from {sec.findings.length} checks ({bad.length} need action). {cls ? <>AI reads the shape as <b>{cls.label}</b> at {Math.round(cls.confidence * 100)}% — a hint, not proof.</> : ""}</p>
              <h3>Observed facts</h3>
              <table className="kv"><tbody>
                <tr><td>Packets / ESP / IKE</td><td>{obs.packet_count} / {obs.esp_packets} / {obs.ike_packets ?? (obs.ike_detected ? "yes" : "0")}</td></tr>
                <tr><td>Types · Labels</td><td>{obs.protocols_detected.join(", ")} · {obs.spis_observed.join(", ") || "—"}</td></tr>
                <tr><td>Sizes</td><td>min {obs.packet_length.min}, max {obs.packet_length.max}, avg {obs.packet_length.avg}</td></tr>
                <tr><td>Conversations</td><td>{obs.flows.map(f => `${f.src_ip}→${f.dst_ip} ×${f.packet_count}`).join("; ")}</td></tr>
              </tbody></table>
              <h3>Findings</h3>
              <table className="kv"><thead><tr><th>Check</th><th>Level</th><th>Finding</th><th>Proof</th><th>Fix</th></tr></thead><tbody>
                {sec.findings.map((x, i) => <tr key={i}><td><b>{x.check}</b></td><td>{x.severity}</td><td>{x.description}</td><td className="muted">{x.evidence || "—"}</td><td>{x.recommendation}</td></tr>)}
              </tbody></table>
              {cls && <><h3>AI classification</h3>
                <p>Label <b>{cls.label}</b>, confidence {Math.round(cls.confidence * 100)}%, {cls.windows} pieces. Spread: {Object.entries(cls.dist || {}).map(([k, v]) => `${k} ${Math.round(v * 100)}%`).join(" · ")}. {cls.note}.</p></>}
              <h3>Recommendations</h3>
              {bad.length === 0 ? <p>None urgent. Keep settings and re-check after changes.</p> :
                bad.map((x, i) => <p key={i}><b>{i + 1}. {x.check}:</b> {x.recommendation}</p>)}
              <h3>Limits</h3>
              <p className="muted">Cipher, PFS and DH come from test settings, not ESP bytes. AI is a shape hint. Counts double when recorded on 'any'.</p>
              <h3>Executive wording</h3>
              <p className="muted">Rewrites findings in executive words using the connected brain. {llmOk ? "Brain connected ✓." : "Needs the backend started with LLM_KEY."}</p>
              <div className="row noprint">
                <button className="btn" onClick={llmGo} disabled={llmBusy}>{llmBusy ? "Writing…" : "Enhance"}</button>
              </div>
              {llmT && <div className="okbox" style={{ marginTop: 8 }}><b>Executive wording:</b><p>{llmT}</p></div>}
              <div className="row noprint">
                <button className="btn" onClick={() => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([JSON.stringify({ observed: obs, security: sec, ai: cls }, null, 2)], { type: "application/json" })); a.download = obs.capture_id + ".json"; a.click(); }}>Download JSON</button>
                <button className="btn ghost" onClick={() => { const a = document.createElement("a"); const rows = (pkts?.packets || []).map(p => [p.n, p.time, p.src, p.dst, p.protocol, p.length, p.spi || "", p.seq ?? ""].join(",")).join("\n"); a.href = URL.createObjectURL(new Blob(["n,time,src,dst,proto,len,spi,seq\n" + rows], { type: "text/csv" })); a.download = obs.capture_id + ".csv"; a.click(); }}>Packets CSV</button>
                <button className="btn ghost" onClick={() => window.print()}>Print / PDF</button></div></>}
          </div>}

          {page === "learn" && <>
            <div className="hero"><h1>Learn VPN in plain words</h1><p>Short lessons. Each ends with a check.</p></div>
            <div className="learn-grid">{MODULES.map((m, i) => <div key={m.id} className="learn-card"><h4>{i + 1}. {m.t}</h4><p className="muted">{m.b}</p>
              <button className="btn ghost" onClick={() => setMod(m.id)}>Read lesson →</button></div>)}
            </div>
            {mod && (() => { const mi = MODULES.findIndex(m => m.id === mod); const m = MODULES[mi]; return (
              <div className="overlay" onClick={() => setMod(null)}><div className="modal" style={{ maxWidth: 620, maxHeight: "85vh", overflowY: "auto" }} onClick={e => e.stopPropagation()}>
                <p className="muted">LESSON {mi + 1} OF {MODULES.length}</p>
                <h3 style={{ fontSize: 22 }}>{m.t}</h3>
                <p>{m.b}</p>
                {(m.deep || []).map((d, i) => <p key={i} style={{ fontSize: 14 }}>• {d}</p>)}
                {m.see && <p className="chat-u" style={{ fontSize: 14 }}><b>Try it:</b> {m.see}</p>}
                <p><b>Quick check:</b> {m.q[0]}</p>
                {m.q[1].map((o, i) => <div key={i}><label><input type="radio" name={m.id} checked={ans[m.id] === i} onChange={() => setAns({ ...ans, [m.id]: i })} /> {o}</label></div>)}
                {ans[m.id] !== undefined && <p><b>{ans[m.id] === m.q[2] ? "✓ Right." : "Not quite — try again."}</b></p>}
                <div className="row" style={{ marginTop: 12 }}>
                  <button className="btn ghost" disabled={mi === 0} onClick={() => setMod(MODULES[mi - 1].id)}>← Prev</button>
                  <button className="btn ghost" disabled={mi === MODULES.length - 1} onClick={() => setMod(MODULES[mi + 1].id)}>Next →</button>
                  <button className="btn" style={{ marginLeft: "auto" }} onClick={() => setMod(null)}>Done</button>
                </div>
              </div></div>); })()}
            <div className="card"><h2>Words</h2>
              <input value={gq} onChange={e => setGq(e.target.value)} placeholder="Search: ESP, PFS…" style={{ padding: 8, width: "100%" }} />
              <table className="kv"><tbody>{GLOSS.filter(([t]) => t.toLowerCase().includes(gq.toLowerCase())).map(([t, d, w]) => <tr key={t}><td><b>{t}</b></td><td>{d}</td><td className="muted">{w}</td></tr>)}</tbody></table></div>
          </>}
          {info && <div className="overlay" onClick={() => setInfo(null)}><div className="modal" onClick={e => e.stopPropagation()}>
            <h3>{info}: what am I looking at?</h3>
            <p><b>What:</b> {STAT_INFO[info][0]}</p>
            <p><b>Why it matters:</b> {STAT_INFO[info][1]}</p>
            <p><b>How counted:</b> {STAT_INFO[info][2]}</p>
            <p><b>Look for:</b> {STAT_INFO[info][3]}</p>
            <button className="btn" onClick={() => setInfo(null)}>Got it</button>
          </div></div>}
        </div>
      </div>
    </div>
  );
}
