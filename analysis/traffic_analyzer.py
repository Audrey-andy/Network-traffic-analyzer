#!/usr/bin/env python3
"""
Module d'analyse de trafic réseau
Extrait des statistiques à partir des fichiers PCAP
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
from collections import Counter, defaultdict
import json

class TrafficAnalyzer:
    def __init__(self, pcap_file):
        """
        Initialise l'analyseur
        
        Args:
            pcap_file: Chemin vers le fichier PCAP à analyser
        """
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        self.stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'ip_sources': Counter(),
            'ip_destinations': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'connections': [],
            'dns_queries': []
        }
    
    def analyze(self):
        """Analyse tous les paquets"""
        print(f"\n[*] Analyse de {self.pcap_file}...")
        print(f"[*] Nombre de paquets : {len(self.packets)}\n")
        
        for packet in self.packets:
            self.stats['total_packets'] += 1
            
            if IP in packet:
                self._analyze_ip(packet)
            
            if TCP in packet:
                self._analyze_tcp(packet)
            
            if UDP in packet:
                self._analyze_udp(packet)
            
            if DNS in packet:
                self._analyze_dns(packet)
        
        return self.stats
    
    def _analyze_ip(self, packet):
        """Analyse la couche IP"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        
        self.stats['ip_sources'][src_ip] += 1
        self.stats['ip_destinations'][dst_ip] += 1
        self.stats['packet_sizes'].append(packet_size)
        
        protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        protocol_name = protocol_names.get(protocol, f'Autre ({protocol})')
        self.stats['protocols'][protocol_name] += 1
    
    def _analyze_tcp(self, packet):
        """Analyse TCP"""
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        self.stats['ports'][dst_port] += 1
        
        connection = {
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'sport': src_port,
            'dport': dst_port,
            'protocol': 'TCP',
            'flags': str(flags)
        }
        self.stats['connections'].append(connection)
    
    def _analyze_udp(self, packet):
        """Analyse UDP"""
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        
        self.stats['ports'][dst_port] += 1
        
        connection = {
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'sport': src_port,
            'dport': dst_port,
            'protocol': 'UDP'
        }
        self.stats['connections'].append(connection)
    
    def _analyze_dns(self, packet):
        """Analyse les requêtes DNS"""
        if packet[DNS].qr == 0:  
            query = packet[DNS].qd.qname.decode('utf-8')
            self.stats['dns_queries'].append(query)
    
    def print_summary(self):
        """Affiche un résumé des statistiques"""
        print("RÉSUMÉ DE L'ANALYSE")
        
        print(f"\n Total de paquets : {self.stats['total_packets']}")
        
        print(f"\n Protocoles utilisés :")
        for proto, count in self.stats['protocols'].most_common():
            percentage = (count / self.stats['total_packets']) * 100
            print(f"  • {proto}: {count} ({percentage:.1f}%)")
        
        print(f"\n Top 5 IPs sources :")
        for ip, count in self.stats['ip_sources'].most_common(5):
            print(f"  • {ip}: {count} paquets")
        
        print(f"\n Top 5 IPs destinations :")
        for ip, count in self.stats['ip_destinations'].most_common(5):
            print(f"  • {ip}: {count} paquets")
        
        print(f"\n Top 10 ports les plus utilisés :")
        for port, count in self.stats['ports'].most_common(10):
            service = self._get_port_service(port)
            print(f"  • Port {port} ({service}): {count} connexions")
        
        if self.stats['dns_queries']:
            print(f"\n Requêtes DNS ({len(self.stats['dns_queries'])}) :")
            for query in list(set(self.stats['dns_queries']))[:10]:
                print(f"  • {query}")
        
        if self.stats['packet_sizes']:
            avg_size = sum(self.stats['packet_sizes']) / len(self.stats['packet_sizes'])
            print(f"\n Taille moyenne des paquets : {avg_size:.2f} octets")
        
        print("\n" + "="*60)
    
    def _get_port_service(self, port):
        """Retourne le service associé à un port"""
        common_ports = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
            1900: 'SSDP', 5353: 'mDNS'
        }
        return common_ports.get(port, 'Inconnu')
    
    def save_to_json(self, output_file="data/analysis_results.json"):
        """Sauvegarde les statistiques en JSON"""
        # Convertit Counter en dict pour JSON
        json_stats = {
            'total_packets': self.stats['total_packets'],
            'protocols': dict(self.stats['protocols']),
            'ip_sources': dict(self.stats['ip_sources']),
            'ip_destinations': dict(self.stats['ip_destinations']),
            'ports': dict(self.stats['ports']),
            'avg_packet_size': sum(self.stats['packet_sizes']) / len(self.stats['packet_sizes']) if self.stats['packet_sizes'] else 0,
            'dns_queries': list(set(self.stats['dns_queries'])),
            'total_connections': len(self.stats['connections'])
        }
        
        with open(output_file, 'w') as f:
            json.dump(json_stats, f, indent=4)
        
        print(f"\n[+] Statistiques sauvegardées dans {output_file}")

# Test du module
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 traffic_analyzer.py <fichier.pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    analyzer = TrafficAnalyzer(pcap_file)
    
    analyzer.analyze()
    
    analyzer.print_summary()
    
    analyzer.save_to_json()