#!/usr/bin/env python3
"""
Serveur Flask pour le Dashboard Web
Interface en temps réel pour surveiller le trafic réseau
"""

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
from capture.packet_sniffer import PacketSniffer
from analysis.traffic_analyzer import TrafficAnalyzer
from analysis.anomaly_detector import AnomalyDetector

# Crée l'app Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'key-ici'  
socketio = SocketIO(app, cors_allowed_origins="*")

dashboard_data = {
    'is_capturing': False,  # Est-ce qu'on capture actuellement ?
    'total_packets': 0,      
    'alerts': [],            
    'stats': {},             
    'threat_intel': []       
}

#(pour capturer en arrière-plan)
capture_thread = None
sniffer = None


@app.route('/')
def index():
    """
    Page d'accueil du dashboard
    Quand tu vas sur http://localhost:5000, tu arrives ici
    """
    return render_template('dashboard.html')


@app.route('/api/stats')
def get_stats():
    """
    API qui renvoie les statistiques actuelles
    Format JSON pour que JavaScript puisse les lire
    """
    return jsonify(dashboard_data)


@socketio.on('connect')
def handle_connect():
    """
    Quand un utilisateur se connecte au dashboard
    On lui envoie les données actuelles
    """
    print(f" Client connecté au dashboard")
    emit('initial_data', dashboard_data)


@socketio.on('start_capture')
def handle_start_capture(data):
    """
    Quand l'utilisateur clique sur "Start Capture"
    On démarre la capture en arrière-plan
    """
    global capture_thread, sniffer, dashboard_data
    
    if dashboard_data['is_capturing']:
        emit('error', {'message': 'Capture déjà en cours '})
        return
    
    interface = data.get('interface', 'eth0')
    packet_count = data.get('packet_count', 0)  
    
    print(f" Démarrage de la capture sur {interface}")
    
    dashboard_data['is_capturing'] = True
    dashboard_data['total_packets'] = 0
    dashboard_data['alerts'] = []
    
    # Crée le sniffer
    sniffer = LiveSniffer(interface, socketio, dashboard_data)
    
    capture_thread = threading.Thread(target=sniffer.start)
    capture_thread.daemon = True  
    capture_thread.start()
    
    emit('capture_started', {'interface': interface})


@socketio.on('stop_capture')
def handle_stop_capture():
    """
    Quand l'utilisateur clique sur "Stop Capture"
    """
    global sniffer, dashboard_data
    
    if not dashboard_data['is_capturing']:
        emit('error', {'message': 'Aucune capture en cours !'})
        return
    
    print(" Arrêt de la capture...")
    
    dashboard_data['is_capturing'] = False
    
    if sniffer:
        sniffer.stop()
    
    emit('capture_stopped', {'total_packets': dashboard_data['total_packets']})


class LiveSniffer:
    """
    Classe pour capturer les paquets ET envoyer les alertes en temps réel
    """
    
    def __init__(self, interface, socketio, dashboard_data):
        self.interface = interface
        self.socketio = socketio  
        self.dashboard_data = dashboard_data
        self.running = True
        self.packets = []
    
    def start(self):
        """Démarre la capture"""
        from scapy.all import sniff, IP, TCP, UDP
        
        print(f"Capture démarrée sur {self.interface}")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,  
                stop_filter=lambda x: not self.running,  
                store=False  
            )
        except Exception as e:
            print(f" Erreur de capture : {e}")
            self.dashboard_data['is_capturing'] = False
    
    def packet_callback(self, packet):
        """
        Cette fonction est appelée pour CHAQUE paquet capturé
        C'est ici qu'on détecte les anomalies en temps réel
        """
        from scapy.all import IP, TCP, UDP, Raw
        
        self.dashboard_data['total_packets'] += 1
        self.packets.append(packet)
        
        # Envoie la mise à jour au navigateur (toutes les 10 paquets)
        if self.dashboard_data['total_packets'] % 10 == 0:
            self.socketio.emit('packet_count_update', {
                'count': self.dashboard_data['total_packets']
            })
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Liste des ports suspects
            suspicious_ports = {
                4444: 'Metasploit',
                31337: 'BackOrifice',
                1337: 'Elite/Backdoor',
                6667: 'IRC Botnet',
                12345: 'NetBus',
                27374: 'SubSeven'
            }
            
            # Liste des ports non sécurisés
            insecure_ports = {
                21: 'FTP',
                23: 'Telnet',
                80: 'HTTP'
            }
            
            # DÉTECTION 1 : Ports suspects 
            if TCP in packet:
                dst_port = packet[TCP].dport
                
                if dst_port in suspicious_ports:
                    alert = {
                        'timestamp': time.strftime('%H:%M:%S'),
                        'severity': 'HIGH',
                        'category': 'Suspicious Port',
                        'description': f'Connexion vers port suspect {dst_port}',
                        'details': f'{suspicious_ports[dst_port]} - {src_ip} → {dst_ip}:{dst_port}',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip
                    }
                    
                    self.dashboard_data['alerts'].append(alert)
                    self.socketio.emit('new_alert', alert)
                    print(f" 🟠 HIGH - {alert['description']}")
                
                # DÉTECTION 2 : Protocoles non sécurisés
                elif dst_port in insecure_ports:
                    has_credentials = False
                    if Raw in packet:
                        payload = packet[Raw].load
                        keywords = [b'user', b'pass', b'login', b'password', b'username']
                        has_credentials = any(kw in payload.lower() for kw in keywords)
                    
                    severity = 'CRITICAL' if has_credentials else 'MEDIUM'
                    category = 'Credentials in Clear' if has_credentials else 'Insecure Protocol'
                    
                    alert = {
                        'timestamp': time.strftime('%H:%M:%S'),
                        'severity': severity,
                        'category': category,
                        'description': f'Trafic {insecure_ports[dst_port]} non sécurisé détecté',
                        'details': f'{src_ip} → {dst_ip}:{dst_port}' + (' avec identifiants potentiels' if has_credentials else ''),
                        'source_ip': src_ip,
                        'destination_ip': dst_ip
                    }
                    
                    self.dashboard_data['alerts'].append(alert)
                    self.socketio.emit('new_alert', alert)
                    emoji = '🔴' if severity == 'CRITICAL' else '🟡'
                    print(f"[!] {emoji} {severity} - {alert['description']}")
            
            # DÉTECTION 3 : IPs malveillantes connues
            known_bad_ips = [
                '185.220.101.1',    # Tor Exit Node
                '45.142.212.61',    # Malware C2
                '104.248.144.120'   # Botnet
            ]
            
            if dst_ip in known_bad_ips or src_ip in known_bad_ips:
                bad_ip = dst_ip if dst_ip in known_bad_ips else src_ip
                alert = {
                    'timestamp': time.strftime('%H:%M:%S'),
                    'severity': 'CRITICAL',
                    'category': 'Malicious IP',
                    'description': f'Connexion avec IP malveillante connue',
                    'details': f'IP suspecte : {bad_ip}',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip
                }
                
                self.dashboard_data['alerts'].append(alert)
                self.socketio.emit('new_alert', alert)
                print(f"[!] 🔴 CRITICAL - {alert['description']}")

    def stop(self):
        """Arrête la capture"""
        self.running = False
        print(" Capture arrêtée")


if __name__ == '__main__':
    print(" Network Traffic Analyzer - Dashboard Web")
    print("\n Démarrage du serveur...")
    print("Ouvre ton navigateur sur : http://localhost:5000")
    print("Appuie sur Ctrl+C pour arrêter\n")
    
    # Démarrage du serveur Flask avec SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)