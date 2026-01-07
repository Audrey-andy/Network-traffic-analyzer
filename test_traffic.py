#!/usr/bin/env python3
"""
Génère du trafic suspect pour tester le détecteur
"""
from scapy.all import IP, TCP, send, wrpcap
import random

packets = []

# 1. Simule un port scan (scan de 50 ports différents)
print("[*] Génération d'un scan de ports...")
target_ip = "8.8.8.8"
for port in range(1, 51):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
    packets.append(pkt)

# 2. Simule du trafic HTTP non sécurisé avec credentials
print("[*] Génération de trafic HTTP non sécurisé...")
for _ in range(5):
    pkt = IP(dst="93.184.216.34")/TCP(dport=80, flags="PA")/"username=admin&password=test123"
    packets.append(pkt)

# 3. Simule connexions sur ports suspects
print("[*] Génération de connexions suspectes...")
suspicious_ports = [4444, 31337, 1337, 6667]
for port in suspicious_ports:
    pkt = IP(dst="10.0.0.1")/TCP(dport=port, flags="S")
    packets.append(pkt)

# 4. Trafic FTP non sécurisé
print("[*] Génération de trafic FTP...")
for _ in range(3):
    pkt = IP(dst="192.168.1.1")/TCP(dport=21, flags="PA")/"USER admin\r\n"
    packets.append(pkt)

output_file = "data/captures/test_malicious.pcap"
wrpcap(output_file, packets)
print(f"\n[+] {len(packets)} paquets malveillants générés dans {output_file}")