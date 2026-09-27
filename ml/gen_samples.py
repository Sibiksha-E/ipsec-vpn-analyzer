#!/usr/bin/env python3
"""Regenerate handshake + extra dataset samples with wire-real IKE bytes.
IKEv1 via scapy ISAKMP layer. IKEv2 via hand-built valid header+SA proposal.
Run: ~/ipsec-analyzer/venv/bin/python ~/ipsec-analyzer/ml/gen_samples.py"""
import os, struct, random, time
from scapy.all import Ether, IP, UDP, ESP, Raw, wrpcap
from scapy.layers.isakmp import ISAKMP

B = os.path.expanduser("~/ipsec-analyzer/samples")

def ikev2_sa_init(init_spi: bytes, msgid: int = 0) -> bytes:
    # Transforms: ENCR AES_CBC-128, PRF HMAC_SHA2_256, INTEG HMAC_SHA2_256_128, KE MODP2048
    t = b""
    t += struct.pack("!BBHBBH", 3, 0, 12, 1, 0, 12) + struct.pack("!HH", 0x800E, 128)  # ENCR, next=PRF
    t += struct.pack("!BBHBBH", 3, 0, 8, 2, 0, 5)    # PRF, next=INTEG
    t += struct.pack("!BBHBBH", 3, 0, 8, 3, 0, 12)   # INTEG, next=KE
    t += struct.pack("!BBHBBH", 0, 0, 8, 4, 0, 14)   # KE MODP2048, last
    prop = struct.pack("!BBHBBBH", 0, 0, 8 + len(t), 1, 1, 0, 4) + t
    sa = struct.pack("!BBH", 0, 0, 4 + len(prop)) + prop
    body = sa
    hdr = init_spi + b"\x00" * 8 + struct.pack("!BBBBI", 33, 0x20, 34, 0x08, msgid)
    total = 28 + len(body)
    return hdr[:24] + struct.pack("!I", total) + body

def ikev2_resp(init_spi: bytes, resp_spi: bytes, msgid: int = 0) -> bytes:
    hdr = init_spi + resp_spi + struct.pack("!BBBBI", 0, 0x20, 34, 0x20, msgid)
    return hdr[:24] + struct.pack("!I", 28)

def udp_pair(t, si, sp, di, dp, load, dt=0.04):
    a = Ether() / IP(src=si, dst=di, proto=17) / UDP(sport=sp, dport=dp) / Raw(load=load)
    a.time = t
    b = Ether() / IP(src=di, dst=si, proto=17) / UDP(sport=dp, dport=sp) / Raw(load=load)
    b.time = t + dt
    return [a, b]

def esp_pair(t, si, spi1, di, spi2, s1, s2, q, dt=0.01):
    a = Ether() / IP(src=si, dst=di, proto=50) / ESP(spi=spi1, seq=q) / Raw(load=b"X" * s1)
    a.time = t
    b = Ether() / IP(src=di, dst=si, proto=50) / ESP(spi=spi2, seq=q) / Raw(load=b"Y" * s2)
    b.time = t + dt
    return [a, b]

C, S = "10.10.0.20", "10.10.0.10"
t = time.time()

# 003: real IKEv2 SA_INIT exchange + ESP
p = []
spi = b"\xab\xcd" * 4
p += udp_pair(t, C, 500, S, 500, ikev2_sa_init(spi))
p += udp_pair(t + 0.2, C, 500, S, 500, ikev2_resp(spi, b"\x12\x34" * 4))
for i in range(10):
    p += esp_pair(t + 1 + i * 0.2, C, 0xAA11BB22, S, 0xCC33DD44, 100, 100, i)
wrpcap(f"{B}/sample_003_ike_esp.pcap", p)

# 006: real IKEv1 Main Mode + ESP -> HIGH risk file
p = []
for i in range(3):
    a = Ether() / IP(src=C, dst=S, proto=17) / UDP(sport=500, dport=500) / ISAKMP(init_cookie=bytes([i + 1]) * 8, exch_type=2)
    a.time = t + i * 0.1
    b = Ether() / IP(src=S, dst=C, proto=17) / UDP(sport=500, dport=500) / ISAKMP(init_cookie=bytes([i + 1]) * 8, exch_type=2)
    b.time = t + i * 0.1 + 0.04
    p += [a, b]
for i in range(12):
    p += esp_pair(t + 1 + i * 0.5, C, 0xDEAD0001, S, 0xDEAD0002, 64, 64, i, dt=0.05)
wrpcap(f"{B}/sample_006_weak_ikev1.pcap", p)

# 007: real IKEv2 + varied ESP -> LOW risk file
random.seed(7)
p = []
spi2 = b"\xef\x01" * 4
p += udp_pair(t, C, 500, S, 500, ikev2_sa_init(spi2))
p += udp_pair(t + 0.2, C, 500, S, 500, ikev2_resp(spi2, b"\x56\x78" * 4))
for i in range(25):
    s = random.choice([120, 200, 500, 1400])
    p += esp_pair(t + 1 + i * 0.1, C, 0xBEEF0001, S, 0xBEEF0002, s, random.choice([120, 200, 500]), i, dt=0.02)
wrpcap(f"{B}/sample_007_strong_ikev2.pcap", p)

# Extra dataset files for training depth
random.seed(21)
p = []
for i in range(25):
    s = random.choice([100, 180, 600, 1300])
    p += esp_pair(t, C, 0xC001, S, 0xC002, s, random.choice([100, 300, 700]), i, dt=0.03)
wrpcap(f"{B}/sample_012_web2.pcap", p)

p = []
for i in range(60):
    p += esp_pair(t + i * 0.02, C, 0xC011, S, 0xC012, 40, 40, i, dt=0.008)
wrpcap(f"{B}/sample_013_voip2.pcap", p)

p = []
for b in range(4):
    for i in range(25):
        a = Ether() / IP(src=C, dst=S, proto=50) / ESP(spi=0xE002, seq=b * 25 + i) / Raw(load=b"B" * 1350)
        a.time = t + b * 0.6 + i * 0.005
        p.append(a)
wrpcap(f"{B}/sample_014_bulk2.pcap", p)

print("regenerated 003/006/007 + new 012/013/014")
