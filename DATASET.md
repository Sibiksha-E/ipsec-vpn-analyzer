# Dataset manifest — `samples/`

| File | Traffic | Packets | Expected risk | Expected AI |
|---|---|---|---|---|
| sample_001_icmp_esp.pcap | ping-like, uniform | 40 | MEDIUM (no handshake) | ping |
| sample_002_http_esp.pcap | web-like, mixed sizes | 60 | MEDIUM (no handshake) | web |
| sample_003_ike_esp.pcap | IKEv2 + ESP | 18 | LOW | handshake |
| sample_004_tunnel_icmp.pcap | tunnel ping, inner hidden | 22 | MEDIUM | ping |
| sample_005_tunnel_aes256.pcap | AES-256 tunnel | 20 | MEDIUM | ping |
| sample_006_weak_ikev1.pcap | IKEv1 + ESP | 30 | HIGH | ping |
| sample_007_strong_ikev2.pcap | IKEv2 + varied ESP | 58 | LOW | web |
| sample_008_voip.pcap | tiny steady 20 ms | 120 | MEDIUM | voip |
| sample_009_video.pcap | big steady one-way | 96 | MEDIUM | video |
| sample_010_bulk.pcap | big bursts | 180 | MEDIUM | bulk |
| sample_011_gcm_tunnel.pcap | AES-GCM tunnel | 40 | MEDIUM | ping |
| sample_012_web2.pcap | web variant, held out | — | MEDIUM | web |
| sample_013_voip2.pcap | voip variant, held out | — | MEDIUM | voip |
| sample_014_bulk2.pcap | bulk variant, held out | — | MEDIUM | bulk |

Sources: 001/002/004/005/011 recorded with tcpdump from the Docker
strongSwan lab; 003/006/007 carry wire-real handshakes (IKEv1 via scapy
ISAKMP Main Mode, IKEv2 via valid header + SA proposal — both decode in
Wireshark); 008/009/010/012/013/014 lab-built traffic shapes.

Model v2: 56 train + 34 held-out windows, accuracy 0.824 on unseen files.
Handshake/video classes need more captures before claims.

Sources: 001/002/004/005/011 recorded with tcpdump from the Docker
strongSwan lab; 003/006/007/008/009/010 lab-built with scapy (IKE markers
`IKEV1..`/`IKEV2..` stand in for real handshake bytes).

Model v2: 64 windows, 6 classes, accuracy 0.95 (test split 20).
Weak spot: handshake class has few windows. Grow before claiming more.
