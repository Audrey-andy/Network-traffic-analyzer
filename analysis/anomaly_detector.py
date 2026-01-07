#!/usr/bin/env python3
"""
Module de détection d'anomalies réseau - VERSION AMÉLIORÉE
Intègre GeoIP, Blacklist et Corrélation d'alertes
"""

from scapy.all import rdpcap, IP, TCP, UDP, Raw
from collections import defaultdict, Counter
import datetime
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)


try:
    from geoip_detector import GeoIPDetector
    from blacklist_checker import BlacklistChecker
    from alert_correlator import AlertCorrelator
    ADVANCED_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"[!] Modules avancés non disponibles : {e}")
    print("[!] Le détecteur fonctionnera en mode basique")
    ADVANCED_MODULES_AVAILABLE = False

class AnomalyDetector:
    def __init__(self, pcap_file):
        """
        Initialise le détecteur d'anomalies amélioré
        
        Args:
            pcap_file: Chemin vers le fichier PCAP à analyser
        """
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        self.alerts = []
        
        # Seuils de détection
        self.PORT_SCAN_THRESHOLD = 10
        self.PORT_SCAN_TIME_WINDOW = 60
        self.HIGH_TRAFFIC_THRESHOLD = 1000000
        
        # Ports dangereux
        self.INSECURE_PORTS = {
            21: 'FTP', 23: 'Telnet', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 3306: 'MySQL', 5432: 'PostgreSQL'
        }
        
        self.SUSPICIOUS_PORTS = {
            1337: 'Elite/Backdoor', 31337: 'BackOrifice', 12345: 'NetBus',
            27374: 'SubSeven', 4444: 'Metasploit', 5555: 'Reverse Shell',
            6666: 'IRC Botnet', 6667: 'IRC', 6668: 'IRC', 6669: 'IRC'
        }
        
        if ADVANCED_MODULES_AVAILABLE:
            print("\n[*] Initialisation des modules avancés...")
            self.geoip_detector = GeoIPDetector()
            self.blacklist_checker = BlacklistChecker()
            self.alert_correlator = AlertCorrelator(time_window_seconds=300)
        else:
            self.geoip_detector = None
            self.blacklist_checker = None
            self.alert_correlator = None
    
    def detect_all(self):
        """Lance toutes les détections + corrélation"""
        print(f"\n[*] Détection d'anomalies sur {self.pcap_file}...")
        print(f"[*] Analyse de {len(self.packets)} paquets...\n")
        
        # Détections de base
        self._detect_port_scan()
        self._detect_insecure_protocols()
        self._detect_suspicious_ports()
        self._detect_excessive_traffic()
        self._detect_fragmented_packets()
        
        if ADVANCED_MODULES_AVAILABLE and self.geoip_detector:
            self._detect_geographical_anomalies()
        
        if ADVANCED_MODULES_AVAILABLE and self.blacklist_checker:
            self._detect_blacklisted_ips()
        
        
        if ADVANCED_MODULES_AVAILABLE and self.alert_correlator:
            print("\n[*] Corrélation des alertes...")
            self.alert_correlator.add_alerts_batch(self.alerts)
            self.incidents = self.alert_correlator.correlate()
        else:
            self.incidents = []
        
        return self.alerts
    
    def _detect_geographical_anomalies(self):
        """Détecte les connexions vers des pays à haut risque"""
        print("[*] Détection géographique...")
        
        destination_ips = set()
        for packet in self.packets:
            if IP in packet:
                destination_ips.add(packet[IP].dst)
        
        for ip in destination_ips:
            country = self.geoip_detector.get_country(ip)
            
            if self.geoip_detector.is_high_risk_country(country):
                self._add_alert(
                    severity='HIGH',
                    category='High Risk Country',
                    description=f"Connexion vers un pays à haut risque : {country}",
                    details=f"IP destination : {ip}",
                    destination_ip=ip
                )
    
    def _detect_blacklisted_ips(self):
        """Détecte les connexions vers des IPs malveillantes connues"""
        print("[*] Vérification des blacklists...")
        
        all_ips = set()
        for packet in self.packets:
            if IP in packet:
                all_ips.add(packet[IP].src)
                all_ips.add(packet[IP].dst)
        
        for ip in all_ips:
            result = self.blacklist_checker.check_ip(ip)
            
            if result['is_malicious']:
                self._add_alert(
                    severity='CRITICAL',
                    category='Malicious IP',
                    description=f"Connexion avec une IP malveillante connue",
                    details=f"IP: {ip} | Sources: {', '.join(result['sources'])} | Raisons: {'; '.join(result['reasons'])}",
                    source_ip=ip,
                    destination_ip=ip
                )
    
    def _detect_port_scan(self):
        """Détecte les tentatives de scan de ports"""
        ip_ports = defaultdict(set)
        ip_timestamps = defaultdict(list)
        
        for packet in self.packets:
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                
                ip_ports[src_ip].add(dst_port)
                
                if hasattr(packet, 'time'):
                    ip_timestamps[src_ip].append(packet.time)
        
        for ip, ports in ip_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                self._add_alert(
                    severity='HIGH',
                    category='Port Scan',
                    description=f"Scan de ports détecté depuis {ip}",
                    details=f"{len(ports)} ports différents contactés : {sorted(list(ports)[:10])}...",
                    source_ip=ip
                )
    
    def _detect_insecure_protocols(self):
        """Détecte l'utilisation de protocoles non sécurisés"""
        insecure_connections = defaultdict(list)
        
        for packet in self.packets:
            if IP in packet and TCP in packet:
                dst_port = packet[TCP].dport
                
                if dst_port in self.INSECURE_PORTS:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = self.INSECURE_PORTS[dst_port]
                    
                    insecure_connections[protocol].append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'port': dst_port
                    })
                    
                    if Raw in packet:
                        payload = packet[Raw].load
                        if self._contains_credentials(payload):
                            self._add_alert(
                                severity='CRITICAL',
                                category='Credentials in Clear',
                                description=f"Potentiels identifiants en clair détectés",
                                details=f"Protocole {protocol} (port {dst_port}) de {src_ip} vers {dst_ip}",
                                source_ip=src_ip,
                                destination_ip=dst_ip
                            )
        
        for protocol, connections in insecure_connections.items():
            self._add_alert(
                severity='MEDIUM',
                category='Insecure Protocol',
                description=f"Utilisation de {protocol} (non chiffré)",
                details=f"{len(connections)} connexions détectées",
                source_ip=connections[0]['src']
            )
    
    def _detect_suspicious_ports(self):
        """Détecte l'utilisation de ports suspects"""
        for packet in self.packets:
            if IP in packet and (TCP in packet or UDP in packet):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                
                if port in self.SUSPICIOUS_PORTS:
                    self._add_alert(
                        severity='HIGH',
                        category='Suspicious Port',
                        description=f"Connexion vers un port suspect : {port}",
                        details=f"{self.SUSPICIOUS_PORTS[port]} - {src_ip} → {dst_ip}:{port}",
                        source_ip=src_ip,
                        destination_ip=dst_ip
                    )
    
    def _detect_excessive_traffic(self):
        """Détecte un trafic anormalement élevé"""
        ip_traffic = defaultdict(int)
        
        for packet in self.packets:
            if IP in packet:
                src_ip = packet[IP].src
                packet_size = len(packet)
                ip_traffic[src_ip] += packet_size
        
        for ip, total_bytes in ip_traffic.items():
            if total_bytes > self.HIGH_TRAFFIC_THRESHOLD:
                self._add_alert(
                    severity='MEDIUM',
                    category='High Traffic',
                    description=f"Trafic excessif détecté depuis {ip}",
                    details=f"Volume total : {total_bytes / 1024 / 1024:.2f} MB",
                    source_ip=ip
                )
    
    def _detect_fragmented_packets(self):
        """Détecte les paquets fragmentés"""
        fragmented_count = 0
        
        for packet in self.packets:
            if IP in packet:
                if packet[IP].flags == 'MF' or packet[IP].frag > 0:
                    fragmented_count += 1
        
        if fragmented_count > 5:
            self._add_alert(
                severity='LOW',
                category='Packet Fragmentation',
                description=f"Fragmentation de paquets détectée",
                details=f"{fragmented_count} paquets fragmentés (possible évasion IDS)"
            )
    
    def _contains_credentials(self, payload):
        """Cherche des mots-clés liés aux credentials"""
        keywords = [b'user', b'pass', b'login', b'password', b'username', b'pwd']
        
        try:
            payload_lower = payload.lower()
            return any(keyword in payload_lower for keyword in keywords)
        except:
            return False
    
    def _add_alert(self, severity, category, description, details, source_ip=None, destination_ip=None):
        """Ajoute une alerte"""
        alert = {
            'timestamp': datetime.datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'description': description,
            'details': details,
            'source_ip': source_ip,
            'destination_ip': destination_ip
        }
        self.alerts.append(alert)
    
    def print_alerts(self):
        """Affiche toutes les alertes"""
        if not self.alerts:
            print(" Aucune anomalie détectée !")
            return
        
        print(f" ALERTES DE SÉCURITÉ ({len(self.alerts)} détectées)")
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        severity_icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵'
        }
        
        for severity in severity_order:
            severity_alerts = [a for a in self.alerts if a['severity'] == severity]
            
            if severity_alerts:
                print(f"\n{severity_icons[severity]} {severity} ({len(severity_alerts)}):")
                for i, alert in enumerate(severity_alerts, 1):
                    print(f"\n  [{i}] {alert['category']}")
                    print(f"      {alert['description']}")
                    print(f"      Détails: {alert['details']}")
                    if alert['source_ip']:
                        print(f"      Source: {alert['source_ip']}")
                    if alert['destination_ip']:
                        print(f"      Destination: {alert['destination_ip']}")
        
        
        if ADVANCED_MODULES_AVAILABLE and hasattr(self, 'incidents') and self.incidents:
            self.alert_correlator.print_incidents()
            self.alert_correlator.print_summary()
    
    def get_stats(self):
        """Retourne les statistiques des alertes"""
        if not self.alerts:
            return {
                'total': 0,
                'by_severity': {},
                'by_category': {}
            }
        
        severity_count = Counter([a['severity'] for a in self.alerts])
        category_count = Counter([a['category'] for a in self.alerts])
        
        return {
            'total': len(self.alerts),
            'by_severity': dict(severity_count),
            'by_category': dict(category_count),
            'alerts': self.alerts,
            'incidents': self.incidents if hasattr(self, 'incidents') else []
        }

# Test du module
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 anomaly_detector.py <fichier.pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    detector = AnomalyDetector(pcap_file)
    detector.detect_all()
    detector.print_alerts()