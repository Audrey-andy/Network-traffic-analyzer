#!/usr/bin/env python3
"""
Network Traffic Analyzer Daemon
Surveillance réseau  en arrière-plan
"""

import sys
import os
import time
import signal
import json
import schedule
from datetime import datetime
from threading import Thread

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from capture.packet_sniffer import PacketSniffer
from analysis.anomaly_detector import AnomalyDetector
from daemon.notification_manager import NotificationManager
from daemon.log_manager import LogManager

class NetworkAnalyzerDaemon:
    """
    Le daemon principal tourne en arrière-plan
    """
    
    def __init__(self, config_file='config.json'):
        """
        Initialise le daemon avec un fichier de config
        """
        print(" Network Traffic Analyzer Daemon")

        self.config = self._load_config(config_file)
        
        self.running = False
        self.paused = False
        
        self.log_manager = LogManager(self.config.get('log_dir', 'logs'))
        self.notification_manager = NotificationManager(self.config.get('notifications', {}))
        
        self.stats = {
            'start_time': None,
            'total_packets': 0,
            'total_alerts': 0,
            'alerts_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
        
        # PID file 
        self.pid_file = '/tmp/network-analyzer-daemon.pid'
        
        print("\n Daemon initialisé")
        print(f" • Interface : {self.config.get('interface', 'eth0')}")
        print(f" • Rotation logs : {self.config.get('log_rotation_hours', 24)}h")
        print(f" • Fichier PID : {self.pid_file}")
    
    def _load_config(self, config_file):
        """
        Charge le fichier de configuration JSON
        """
        if os.path.exists(config_file):
            print(f" Chargement de la config : {config_file}")
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            print(f" Config non trouvée, création de config par défaut")
            
            # Config par défaut
            default_config = {
                'interface': 'eth0',
                'log_dir': 'logs',
                'log_rotation_hours': 24,
                'capture_mode': 'continuous',  
                'buffer_size': 10000,  
                'notifications': {
                    # Ajout des configs de notifs
                }
            }
            
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            print(f" Config créée : {config_file}")
            
            return default_config
    
    def start(self):
        """
        Démarre le daemon
        """
        if os.path.exists(self.pid_file):
            print("Un daemon semble déjà en cours d'exécution")
            print(f"Si ce n'est pas le cas, supprime {self.pid_file}")
            return False
        
        print("\n Démarrage du daemon...")
        
        with open(self.pid_file, 'w') as f:
            f.write(str(os.getpid()))
        
        # Démarrage
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        self.log_manager.log_message("Daemon démarré", "INFO")
        
        self._setup_scheduled_tasks()
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        print(" Daemon démarré avec succès")
        print(" Appuie sur Ctrl+C pour arrêter")
        
        # Boucle principale
        try:
            self._main_loop()
        except KeyboardInterrupt:
            print("\n Arrêt demandé...")
            self.stop()
    
    def _main_loop(self):
        """
        Boucle principale 
        """
        from scapy.all import sniff, IP, TCP, UDP, Raw
        
        interface = None
        
        print(f"\n Capture en cours sur {interface}...")
        print(" Les alertes seront loggées dans logs/")
        
        def packet_callback(packet):
            """
            Appelé pour chaque paquet capturé
            """
            if not self.running or self.paused:
                return
            
            self.stats['total_packets'] += 1
            
            # Affiche un point tous les 100 paquets 
            if self.stats['total_packets'] % 100 == 0:
                print('.', end='', flush=True)

            alerts = self._quick_anomaly_detection(packet)
            
            for alert in alerts:
                self._handle_alert(alert)
        
        try:
            sniff(
                iface=interface,
                prn=packet_callback,
                store=False,  
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"\n Erreur de capture : {e}")
            self.log_manager.log_message(f"Erreur de capture : {e}", "ERROR")
    
    def _quick_anomaly_detection(self, packet):
        """
        Détection rapide d'anomalies
        Retourne une liste d'alertes
        """
        from scapy.all import IP, TCP, UDP, Raw
        
        alerts = []
        
        if IP not in packet:
            return alerts
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Ports suspects
        suspicious_ports = {
            4444: 'Metasploit',
            31337: 'BackOrifice',
            1337: 'Elite/Backdoor',
            6667: 'IRC Botnet'
        }
        
        # Ports non sécurisés
        insecure_ports = {21: 'FTP', 23: 'Telnet', 80: 'HTTP'}
        
        if TCP in packet:
            dst_port = packet[TCP].dport
            
            # Détection port suspect
            if dst_port in suspicious_ports:
                alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'category': 'Suspicious Port',
                    'description': f'Connexion vers port suspect {dst_port}',
                    'details': f'{suspicious_ports[dst_port]} - {src_ip} → {dst_ip}:{dst_port}',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip
                })
            
            # Détection protocole non sécurisé avec credentials
            if dst_port in insecure_ports and Raw in packet:
                payload = packet[Raw].load
                keywords = [b'user', b'pass', b'login', b'password']
                
                if any(kw in payload.lower() for kw in keywords):
                    alerts.append({
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'CRITICAL',
                        'category': 'Credentials in Clear',
                        'description': f'Identifiants en clair sur {insecure_ports[dst_port]}',
                        'details': f'{src_ip} → {dst_ip}:{dst_port}',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip
                    })
        
        return alerts
    
    def _handle_alert(self, alert):
        """
        Gère une alerte détectée :
        - Log dans le fichier
        - Notifie (email)
        - Met à jour les stats
        """
        self.stats['total_alerts'] += 1
        severity = alert.get('severity', 'UNKNOWN')
        if severity in self.stats['alerts_by_severity']:
            self.stats['alerts_by_severity'][severity] += 1
        
        # Log l'alerte
        self.log_manager.log_alert(alert)
        
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
        print(f"\n{emoji} {severity} - {alert['category']}")
        print(f"   {alert['description']}")
        
        self.notification_manager.send_alert(alert)
    
    def _setup_scheduled_tasks(self):
        """
        Configuration des tâches planifiées 
        """
        # Rotation des logs toutes les 24h
        rotation_hours = self.config.get('log_rotation_hours', 24)
        schedule.every(rotation_hours).hours.do(self._rotate_logs_task)
        
        def run_scheduler():
            while self.running:
                schedule.run_pending()
                time.sleep(60)  
        
        scheduler_thread = Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        print(f" Tâches planifiées configurées (rotation: {rotation_hours}h)")
    
    def _rotate_logs_task(self):
        """Tâche de rotation des logs"""
        print("\n Rotation programmée des logs...")
        self.log_manager.rotate_logs()
        self.log_manager.log_message("Rotation des logs effectuée", "INFO")
    
    def _signal_handler(self, signum, frame):
        """
        Gère les signaux (SIGTERM, SIGINT)
        Pour arrêter proprement le daemon
        """
        print(f"\n Signal {signum} reçu")
        self.stop()
    
    def stop(self):
        """
        Arrête le daemon proprement
        """
        if not self.running:
            return
        
        print("\n Arrêt du daemon...")
        
        self.running = False
        
        # Log l'arrêt
        uptime = datetime.now() - self.stats['start_time']
        self.log_manager.log_message(f"Daemon arrêté (uptime: {uptime})", "INFO")
        
        self._print_stats()
        
        if os.path.exists(self.pid_file):
            os.remove(self.pid_file)
        
        print(" Daemon arrêté proprement")
    
    def status(self):
        """
        Affiche le statut du daemon
        """
        print(" STATUT DU DAEMON")
        
        if os.path.exists(self.pid_file):
            with open(self.pid_file, 'r') as f:
                pid = f.read().strip()
            
            try:
                os.kill(int(pid), 0)  # Vérification
                print(f"\n Daemon EN COURS")
                print(f"   PID : {pid}")
            except:
                print(f"\n Fichier PID trouvé mais processus mort")
                print(f"   Supprime {self.pid_file} manuellement")
        else:
            print("\n  Daemon ARRÊTÉ")
        
        print("\n Statistiques des logs :")
        stats = self.log_manager.get_stats()
        print(f"• Fichiers de logs : {stats['total_files']}")
        print(f" • Taille totale : {stats['total_size_mb']:.2f} MB")
        
        if stats.get('oldest_log'):
            print(f"   • Plus ancien : {stats['oldest_log']}")
        if stats.get('newest_log'):
            print(f" • Plus récent : {stats['newest_log']}")
    
    def _print_stats(self):
        """Affiche les statistiques de la session"""
        print(" STATISTIQUES DE LA SESSION")
        
        if self.stats['start_time']:
            uptime = datetime.now() - self.stats['start_time']
            print(f"\n Uptime : {uptime}")
        
        print(f"\n Paquets capturés : {self.stats['total_packets']:,}")
        print(f" Alertes détectées : {self.stats['total_alerts']}")
        
        print(f"\nPar sévérité :")
        for severity, count in self.stats['alerts_by_severity'].items():
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[severity]
                print(f"   {emoji} {severity}: {count}")
    
    def logs(self, lines=20, follow=False):
        """
        Affiche les logs
        
        lines = Nombre de lignes à afficher
        follow = Si True, affiche en continu 
        """
        print(f" Dernières {lines} lignes de log :\n")
        
        log_lines = self.log_manager.tail_logs(lines)
        
        for line in log_lines:
            print(line.strip())
        
        if follow:
            print("\n Mode suivi activé (Ctrl+C pour arrêter)...")
            
            try:
                with open(self.log_manager.current_log_file, 'r') as f:
                    f.seek(0, 2)  
                    
                    while True:
                        line = f.readline()
                        if line:
                            print(line.strip())
                        else:
                            time.sleep(0.5)
            except KeyboardInterrupt:
                print("\n Suivi arrêté")
                
# CLI pour contrôler le daemon
def main():
    """
    Interface en ligne de commande
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Network Traffic Analyzer Daemon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  sudo python3 daemon/network_daemon.py start         # Démarre le daemon
  sudo python3 daemon/network_daemon.py stop          # Arrête le daemon
  sudo python3 daemon/network_daemon.py status        # Vérifie l'état
  sudo python3 daemon/network_daemon.py logs          # Affiche les logs
  sudo python3 daemon/network_daemon.py logs --follow # Suit les logs en temps réel
        """
    )
    
    parser.add_argument(
        'action',
        choices=['start', 'stop', 'restart', 'status', 'logs'],
        help='Action à effectuer'
    )
    
    parser.add_argument(
        '--config',
        default='config.json',
        help='Fichier de configuration'
    )
    
    parser.add_argument(
        '--lines',
        type=int,
        default=20,
        help='Nombre de lignes de logs à afficher'
    )
    
    parser.add_argument(
        '--follow',
        action='store_true',
        help='Suit les logs en temps réel'
    )
    
    args = parser.parse_args()
    
    daemon = NetworkAnalyzerDaemon(args.config)

    if args.action == 'start':
        daemon.start()
    
    elif args.action == 'stop':
        if os.path.exists(daemon.pid_file):
            with open(daemon.pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            try:
                os.kill(pid, signal.SIGTERM)
                print(f" Signal d'arrêt envoyé au daemon (PID {pid})")
                time.sleep(2)
                daemon.status()
            except:
                print(f"Impossible d'arrêter le daemon (PID {pid})")
        else:
            print(" Aucun daemon en cours")
    
    elif args.action == 'restart':
        print(" Redémarrage du daemon...")
        if os.path.exists(daemon.pid_file):
            with open(daemon.pid_file, 'r') as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(2)
            except:
                pass
        
        daemon.start()
    
    elif args.action == 'status':
        daemon.status()
    
    elif args.action == 'logs':
        daemon.logs(lines=args.lines, follow=args.follow)

if __name__ == '__main__':
    main()