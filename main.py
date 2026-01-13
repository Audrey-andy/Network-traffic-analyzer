#!/usr/bin/env python3
"""
Network Traffic Analyzer - Programme Principal
Orchestrateur complet du système de surveillance réseau
"""

import os
import sys
import subprocess
import time
from datetime import datetime

def print_menu():
    """Affiche le menu principal"""
    print(" MENU PRINCIPAL")
    print("\n TESTS INDIVIDUELS :")
    print("  1. Test de Capture (Packet Sniffer)")
    print("  2. Test d'Analyse (Traffic Analyzer)")
    print("  3. Test de Détection (Anomaly Detector)")
    print("  4. Test Complet")
    print("\n INTERFACE WEB :")
    print("  5. Lancer le Dashboard Web (Flask)")
    print("\n MODE DAEMON :")
    print("  6. Démarrer le Daemon (Surveillance 24/7)")
    print("  7. Arrêter le Daemon")
    print("  8. Statut du Daemon")
    print("  9. Voir les Logs du Daemon")
    print("\n DÉMONSTRATION COMPLÈTE :")
    print("  10.DÉMO COMPLÈTE ")
    print("\n  0. Quitter")


def test_capture():
    """Test 1 : Capture de paquets"""
    print(" TEST 1 : CAPTURE DE PAQUETS")
    print("\n Capture de 50 paquets sur eth0...")
    print("Appuyez sur Ctrl+C pour arrêter plus tôt\n")
    
    try:
        subprocess.run([
            'sudo', 'python3', 'capture/packet_sniffer.py'
        ], check=True)
        
        print("\n Capture terminée !")
        print(" Fichier PCAP créé dans data/captures/")
        
        captures = subprocess.run(
            ['ls', '-lht', 'data/captures/'],
            capture_output=True, text=True
        )
        print("\n" + captures.stdout)
        
    except KeyboardInterrupt:
        print("\n Capture interrompue par l'utilisateur")
    except Exception as e:
        print(f"\n Erreur : {e}")
    input("\n[Appuyez sur Entrée pour continuer...]")

def test_analyzer():
    """Test 2 : Analyse de trafic"""
    print(" TEST 2 : ANALYSE DE TRAFIC")
    print("\n Fichiers PCAP disponibles :")
    result = subprocess.run(
        ['ls', '-1t', 'data/captures/'],
        capture_output=True, text=True
    )
    
    files = result.stdout.strip().split('\n')
    if not files or files[0] == '':
        print(" Aucun fichier PCAP trouvé !")
        print(" Lancez d'abord la capture ")
        input("\n[Appuyez sur Entrée pour continuer...]")
        return
    
    for i, f in enumerate(files[:5], 1):
        print(f"  {i}. {f}")
    
    # Utiliser le plus récent par défaut
    pcap_file = f"data/captures/{files[0]}"
    print(f"\n Analyse de : {pcap_file}")
    
    try:
        subprocess.run([
            'python3', 'analysis/traffic_analyzer.py', pcap_file
        ], check=True)
        
        print("\nAnalyse terminée !")
        
    except Exception as e:
        print(f"\n Erreur : {e}")
    
    input("\n[Appuyez sur Entrée pour continuer...]")

def test_detector():
    """Test 3 : Détection d'anomalies"""
    print("TEST 3 : DÉTECTION D'ANOMALIES")
    print("\n Fichiers PCAP disponibles :")
    result = subprocess.run(
        ['ls', '-1t', 'data/captures/'],
        capture_output=True, text=True
    )
    
    files = result.stdout.strip().split('\n')
    if not files or files[0] == '':
        print(" Aucun fichier PCAP trouvé !")
        print("Lancez d'abord la capture)")
        input("\n[Appuyez sur Entrée pour continuer...]")
        return
    
    for i, f in enumerate(files[:5], 1):
        print(f"  {i}. {f}")
    
    pcap_file = f"data/captures/{files[0]}"
    print(f"\n Détection sur : {pcap_file}")
    try:
        subprocess.run([
            'sudo', 'python3', 'analysis/anomaly_detector.py', pcap_file
        ], check=True)
        print("\n Détection terminée !")
    except Exception as e:
        print(f"\n Erreur : {e}")
    
    input("\n[Appuyez sur Entrée pour continuer...]")

def test_complete():
    """Test 4 : Tout en un"""
    print("TEST 4 : ANALYSE COMPLÈTE")
    
    print("\n[Phase 1/3] Capture de paquets...")
    print(" Génération de trafic de test...")
    
    try:
        subprocess.run(['sudo', 'python3', 'test_traffic.py'], check=True)
        print("\n[Phase 2/3] Analyse des statistiques...")
        
        result = subprocess.run(
            ['ls', '-1t', 'data/captures/'],
            capture_output=True, text=True
        )
        files = result.stdout.strip().split('\n')
        
        if files and files[0]:
            pcap_file = f"data/captures/{files[0]}"
            
            subprocess.run(['python3', 'analysis/traffic_analyzer.py', pcap_file], check=True)
            
            print("\n[Phase 3/3]  Détection d'anomalies...")
            
            subprocess.run(['sudo', 'python3', 'analysis/anomaly_detector.py', pcap_file], check=True)
            
            print(" ANALYSE COMPLÈTE TERMINÉE !")
            print(f"\n Fichier analysé : {pcap_file}")
            print(f" Logs sauvegardés dans : logs/")
        
    except Exception as e:
        print(f"\n Erreur : {e}")
    input("\n[Appuyez sur Entrée pour continuer...]")


def launch_dashboard():
    """Test 5 : Dashboard Web"""
    print(" DASHBOARD WEB TEMPS RÉEL")
    print("\n Démarrage du serveur Flask ")
    print("URL : http://localhost:5000")
    print("Appuyez sur Ctrl+C pour arrêter\n")
    
    try:
        print(" Ouverture de Firefox...")
        subprocess.Popen(['firefox', 'http://localhost:5000'], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        subprocess.run(['sudo', 'python3', 'web/app.py'])
        
    except KeyboardInterrupt:
        print("\nServeur arrêté")
    except Exception as e:
        print(f"\nErreur : {e}")
    input("\n[Appuyez sur Entrée pour continuer...]")


def daemon_start():
    """Test 6 : Démarrer le daemon"""
    print(" DÉMARRAGE DU DAEMON")
    
    try:
        subprocess.run([
            'sudo', 'python3', 'daemon/network_daemon.py', 'start'
        ])
    except KeyboardInterrupt:
        print("\nDaemon interrompu")
    except Exception as e:
        print(f"\n Erreur : {e}")
    input("\n[Appuyez sur Entrée pour continuer...]")


def daemon_stop():
    """Test 7 : Arrêter le daemon"""
    print(" ARRÊT DU DAEMON")
    
    try:
        subprocess.run([
            'sudo', 'python3', 'daemon/network_daemon.py', 'stop'
        ], check=True)
    except Exception as e:
        print(f"\n Erreur : {e}")
    
    input("\n[Appuyez sur Entrée pour continuer...]")


def daemon_status():
    """Test 8 : Statut du daemon"""
    print(" STATUT DU DAEMON")
    
    try:
        subprocess.run([
            'sudo', 'python3', 'daemon/network_daemon.py', 'status'
        ], check=True)
    except Exception as e:
        print(f"\n Erreur : {e}")
    input("\n[Appuyez sur Entrée pour continuer...]")


def daemon_logs():
    """Test 9 : Voir les logs"""
    print(" LOGS DU DAEMON")
    
    try:
        subprocess.run([
            'sudo', 'python3', 'daemon/network_daemon.py', 'logs'
        ], check=True)
    except Exception as e:
        print(f"\n Erreur : {e}")
    input("\n[Appuyez sur Entrée pour continuer...]")


def demo_complete():
    """Test 10 : Démo complète"""
    print("DÉMONSTRATION COMPLÈTE DU SYSTÈME")
    print("\nCette démo va :")
    print("  1. Générer du trafic malveillant")
    print("  2. L'analyser avec tous les modules")
    print("  3. Ouvrir le dashboard web")
    print("  4. Démarrer le daemon en arrière-plan")
    print("\nDurée estimée : 5 minutes")
    input("\n[Appuyez sur Entrée pour commencer...]")
    
    try:
        print("\n[Étape 1/4] Génération de trafic de test...")
        subprocess.run(['sudo', 'python3', 'test_traffic.py'], check=True)
        
        print("\n[Étape 2/4]  Analyse complète...")
        result = subprocess.run(['ls', '-1t', 'data/captures/'], 
                              capture_output=True, text=True)
        files = result.stdout.strip().split('\n')
        
        if files and files[0]:
            pcap_file = f"data/captures/{files[0]}"
            subprocess.run(['sudo', 'python3', 'analysis/anomaly_detector.py', pcap_file], 
                         check=True)
        
        print("\n[Étape 3/4] Lancement du dashboard web...")
        print(" Ouverture de Firefox sur http://localhost:5000")
        subprocess.Popen(['firefox', 'http://localhost:5000'],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
        print("\n Démarrage du serveur Flask...")
        print(" Le dashboard va s'ouvrir dans Firefox")
        print("Appuyez sur Ctrl+C pour arrêter et passer à la suite\n")
        time.sleep(5)
        
        flask_process = subprocess.Popen(
            ['sudo', 'python3', 'web/app.py'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        print("\n Dashboard lancé ! (PID: {})".format(flask_process.pid))
        print("   Appuyez sur Ctrl+C quand vous avez fini de tester le dashboard...")
        
        try:
            time.sleep(100)  
        except KeyboardInterrupt:
            pass
        
        flask_process.terminate()
        print("\n Dashboard arrêté")
        
        print("\n[Étape 4/4] Configuration du daemon...")
        print("Le daemon peut être démarré avec : sudo systemctl start network-analyzer")
        print("Ou : sudo python3 daemon/network_daemon.py start")
        
        print(" DÉMONSTRATION COMPLÈTE TERMINÉE !")
        print("\n Résumé :")
        print("  Trafic généré et analysé")
        print("  Anomalies détectées")
        print("  Dashboard web testé")
        print("  Daemon configuré")
        print("\n Prochaines étapes :")
        print("  Configurer les notifications (config.json)")
        print("  Activer le daemon au boot : sudo systemctl enable network-analyzer")
        print("  Ajouter des clés API Threat Intelligence")
        
    except KeyboardInterrupt:
        print("\n Démo interrompue")
    except Exception as e:
        print(f"\n Erreur : {e}")
    input("\n[Appuyez sur Entrée pour revenir au menu...]")

def main():
    """Boucle principale"""
    
    if not os.path.exists('capture/packet_sniffer.py'):
        print(" Erreur : Lancez ce script depuis le dossier Network-traffic-analyzer/")
        sys.exit(1)
    
    os.makedirs('data/captures', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(" Système de Surveillance Réseau ")
        print_menu()
        
        try:
            choice = input("\n Votre choix : ").strip()    
            if choice == '1':
                test_capture()
            elif choice == '2':
                test_analyzer()
            elif choice == '3':
                test_detector()
            elif choice == '4':
                test_complete()
            elif choice == '5':
                launch_dashboard()
            elif choice == '6':
                daemon_start()
            elif choice == '7':
                daemon_stop()
            elif choice == '8':
                daemon_status()
            elif choice == '9':
                daemon_logs()
            elif choice == '10':
                demo_complete()
            elif choice == '0':
                sys.exit(0)
            else:
                print("\n Choix invalide !")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n\n Interruption détectée")
            print(" Retour au menu...")
            time.sleep(1)
        except Exception as e:
            print(f"\n Erreur : {e}")
            input("\n[Appuyez sur Entrée pour continuer...]")

if __name__ == "__main__":
    main()