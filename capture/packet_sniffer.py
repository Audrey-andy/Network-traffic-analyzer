#!/usr/bin/env python3
"""
Module de capture de paquets réseau
Utilise Scapy pour intercepter et sauvegarder le trafic
"""

from scapy.all import sniff, wrpcap, IP, TCP, UDP
import datetime
import os

class PacketSniffer:
    def __init__(self, interface="eth0", packet_count=100):
        """
        Initialise le sniffer
        
        Args:
            interface: Interface réseau à écouter (eth0, wlan0, etc.)
            packet_count: Nombre de paquets à capturer (0 = illimité)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packets = []
        
    def packet_handler(self, packet):
        """Traite chaque paquet capturé"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            print(f"[+] {src_ip} → {dst_ip} | Protocole: {protocol}")
            
            self.packets.append(packet)
    
    def start_capture(self):
        """Démarre la capture de paquets"""
        print(f"\n Démarrage de la capture sur {self.interface}...")
        print(f" Capture de {self.packet_count if self.packet_count > 0 else 'paquets illimités'}...")
        print(" Appuyez sur Ctrl+C pour arrêter\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=self.packet_count,
                store=False
            )
        except KeyboardInterrupt:
            print("\n[!] Capture interrompue par l'utilisateur")
        except Exception as e:
            print(f"\n[!] Erreur : {e}")
    
    def save_capture(self, output_dir="data/captures"):
        """Sauvegarde les paquets au format PCAP"""
        if not self.packets:
            print("[!] Aucun paquet à sauvegarder")
            return None
        
        os.makedirs(output_dir, exist_ok=True)
    
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/capture_{timestamp}.pcap"
        
        wrpcap(filename, self.packets)
        print(f"\n[+] {len(self.packets)} paquets sauvegardés dans {filename}")
        
        return filename

# Test du module
if __name__ == "__main__":
    sniffer = PacketSniffer(interface="eth0", packet_count=50)
    sniffer.start_capture()
    sniffer.save_capture()