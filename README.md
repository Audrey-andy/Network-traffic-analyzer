#  Network Traffic Analyzer - Advanced Security Platform

> **Système complet d'analyse de trafic réseau avec détection d'anomalies en temps réel, threat intelligence, dashboard web et surveillance 24/7**

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-red.svg)
---

## Table des matières

- [À propos](#-à-propos)
- [Fonctionnalités principales](#-fonctionnalités-principales)
- [Technologies utilisées](#-technologies-utilisées)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Configuration avancée](#-configuration-avancée)
- [Exemples de détections](#-exemples-de-détections)
---

## À propos

**Network Traffic Analyzer** est une plateforme professionnelle de cybersécurité développée pour la surveillance réseau en temps réel et la détection de menaces avancées. Le système combine analyse de paquets, corrélation d'incidents, threat intelligence externe et visualisation interactive.

### Contexte du projet

Développé dans le cadre d'un projet, cet outil démontre des compétences en :
- Programmation Python avancée 
- Sécurité réseau et analyse de protocoles
- Développement web (Flask, HTML/CSS/JavaScript)
- Intégration d'APIs externes (AbuseIPDB, VirusTotal)
- Architecture daemon et services système

### Cas d'usage professionnels

- **SOC Analyst** : Surveillance continue du trafic réseau d'entreprise
- **Incident Response** : Analyse forensique post-intrusion
- **Penetration Testing** : Validation de la détection d'attaques
- **Blue Team** : Entraînement et simulation d'incidents
- **Formation** : Apprentissage pratique de l'analyse réseau

---

## Fonctionnalités principales

### Détection d'Anomalies (8 Types)

| Type | Sévérité | Description |
|------|----------|-------------|
| **Scan de ports** | 🟠 HIGH | Détecte les tentatives de reconnaissance (10+ ports en 60s) |
| **Protocoles non sécurisés** | 🟡 MEDIUM | Identifie HTTP, FTP, Telnet, MySQL non chiffrés |
| **Ports suspects** | 🟠 HIGH | Détecte Metasploit (4444), BackOrifice (31337), IRC botnets |
| **Credentials en clair** | 🔴 CRITICAL | Repère les mots de passe transmis sans chiffrement |
| **Trafic excessif** | 🟡 MEDIUM | Identifie les transferts > 1GB (possible exfiltration) |
| **Fragmentation** | 🔵 LOW | Détecte les techniques d'évasion IDS |
| **Pays à haut risque** | 🟠 HIGH | Alerte sur connexions vers pays sensibles (GeoIP) |
| **IPs malveillantes** | 🔴 CRITICAL | Vérifie contre blacklist locale + APIs externes |

### Corrélation Intelligente d'Incidents

Le système analyse les relations temporelles entre alertes (fenêtre de 5 minutes) :

| Pattern | Sévérité | Conditions |
|---------|----------|------------|
| **Attaque Ciblée** | 🔴 CRITICAL | Port Scan → Connexion sur port suspect |
| **Exfiltration de Données** | 🔴 CRITICAL | Trafic massif + Protocole non sécurisé |
| **APT (Advanced Persistent Threat)** | 🔴 CRITICAL | Pays à risque + Port suspect + IP malveillante |
| **Vol de Credentials** | 🔴 CRITICAL | Credentials en clair → IP malveillante |
| **Tempête d'Alertes** | 🟠 HIGH | 10+ alertes en < 5 minutes |

### Threat Intelligence

Enrichissement automatique des IPs avec APIs externes :

- **AbuseIPDB** : Score de réputation, nombre de rapports (gratuit : 1000/jour)
- **VirusTotal** : Détections multi-antivirus (gratuit : 500/jour)
- **Shodan** : Ports ouverts, vulnérabilités CVE (payant)

###  Dashboard Web Temps Réel

Interface Flask avec WebSocket pour visualisation en direct :

-  Graphiques animés (Chart.js)
-  Carte géographique des menaces
-  Alertes en temps réel avec notifications sonores
-  Statistiques live (paquets/sec, alertes/min)
-  Contrôles Start/Stop de capture

###  Mode Daemon (Service Système)

Surveillance continue en arrière-plan :

-  Service systemd intégré
-  Démarrage automatique au boot
-  Rotation automatique des logs (compression gzip après 24h)
-  Notifications email sur alertes critiques
-  Gestion via commandes système (`systemctl`)

### Système de Notifications

- **Email (SMTP)** : Envoi immédiat sur alertes CRITICAL/HIGH
- Configuration Gmail/Outlook/Yahoo supportée
- Template HTML professionnel pour les emails

---

##  Technologies utilisées

### Langages & Frameworks
```python
Python 3.9+              # Langage principal
Flask 3.0.0              # Serveur web
Flask-SocketIO 5.3.0     # Communication temps réel
Scapy 2.5.0              # Manipulation paquets réseau
```

### Bibliothèques principales
```
geoip2==5.2.0           # Géolocalisation (MaxMind)
requests==2.32.5        # Requêtes HTTP (APIs)
schedule==1.2.0         # Tâches planifiées (rotation logs)
python-daemon==3.0.1    # Daemonisation Unix
```

### APIs externes (optionnelles)

- **AbuseIPDB** : https://www.abuseipdb.com 
- **VirusTotal** : https://www.virustotal.com 
- **Shodan** : https://www.shodan.io 

---

##  Installation

### Installation rapide 
```bash
# 1. Cloner le repository
git clone https://github.com/TON_USERNAME/network-traffic-analyzer.git
cd network-traffic-analyzer

# 2. Installer les dépendances Python
pip3 install -r requirements.txt --break-system-packages

# 3. Télécharger la base GeoIP 
mkdir -p data/geoip
wget -O data/geoip/GeoLite2-Country.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb

# 4. Créer les dossiers nécessaires
mkdir -p data/captures logs

# 5. Rendre les scripts exécutables
chmod +x main.py capture/*.py analysis/*.py

# 6. Tester l'installation
sudo python3 main.py
```

### Installation complète avec service systemd
```bash

# Activer le service
sudo systemctl daemon-reload
sudo systemctl enable network-analyzer
sudo systemctl start network-analyzer

# Vérifier le statut
sudo systemctl status network-analyzer
```
---

##  Utilisation

### Mode 1 : Menu interactif 
```bash
sudo python3 main.py
```

**Options disponibles :**
1. Test de Capture
2. Test d'Analyse
3. Test de Détection
4. Test Complet 
5. **Dashboard Web** (Interface graphique)
6. Démarrer le Daemon
7. Arrêter le Daemon
8. Statut du Daemon
9. Voir les Logs
10. **DÉMO COMPLÈTE** (Tout tester en 5 min)

### Mode 2 : Commandes directes

#### Capture de paquets
```bash
# Capture 100 paquets sur eth0
sudo python3 capture/packet_sniffer.py

# Options avancées
sudo python3 capture/packet_sniffer.py --interface wlan0 --count 200
```

#### Analyse d'un fichier PCAP
```bash
# Statistiques réseau
python3 analysis/traffic_analyzer.py data/captures/capture.pcap

# Détection d'anomalies + Threat Intelligence
sudo python3 analysis/anomaly_detector.py data/captures/capture.pcap
```

#### Dashboard Web
```bash
# Lancer le serveur Flask
sudo python3 web/app.py

# Ouvrir http://localhost:5000 dans le navigateur
firefox http://localhost:5000
```

#### Mode Daemon
```bash
# Via systemd
sudo systemctl start network-analyzer
sudo systemctl status network-analyzer
sudo systemctl stop network-analyzer

# Ou directement
sudo python3 daemon/network_daemon.py start
sudo python3 daemon/network_daemon.py status
sudo python3 daemon/network_daemon.py logs --follow
sudo python3 daemon/network_daemon.py stop
```

### Mode 3 : Démo rapide 
```bash
# Analyse avec toutes les fonctionnalités
sudo python3 analysis/anomaly_detector.py data/captures/test_threats.pcap

```

---

##  Configuration avancée

### Threat Intelligence (APIs)

Créer `config.json` à la racine :
```json
{
  "threat_intelligence": {
    "abuseipdb_key": "CLÉ_ABUSEIPDB",
    "virustotal_key": null,
    "shodan_key": null
  }
}
```

### Notifications Email

Ajouter dans `config.json` :
```json
{
  "notifications": {
    "email": {
      "enabled": true,
      "from": "email@gmail.com",
      "to": "destinataire@example.com",
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "username": "email@gmail.com",
      "password": "mot-de-passe-application-google"
    }
  }
}
```

### Configuration du Daemon

Éditer `config.json` :
```json
{
  "interface": "eth0",
  "log_dir": "logs",
  "log_rotation_hours": 24,
  "capture_mode": "continuous",
  "buffer_size": 10000
}
```
---

##  Exemples de détections

### Exemple 1 : Scan de ports → Attaque ciblée

**Scénario :** Un attaquant scanne 50 ports puis se connecte sur le port 4444 (Metasploit)
```
🟠 HIGH - Port Scan
Source: 192.168.1.100
Détails: 50 ports différents contactés

🟠 HIGH - Suspicious Port
Connexion vers port 4444 (Metasploit)
Source: 192.168.1.100 → 10.0.0.1:4444

🔴 INCIDENT CORRÉLÉ - Attaque Ciblée
Confiance: 100%
Description: Scan de ports suivi de connexion sur port suspect
```

### Exemple 2 : Vol de credentials avec threat intelligence

**Scénario :** Envoi de credentials HTTP vers une IP malveillante connue
```
🔴 CRITICAL - Credentials in Clear
Protocole HTTP (port 80)
Source: 10.0.0.50 → Destination: 185.220.101.1

🔴 CRITICAL - Malicious IP (Blacklist locale)
IP: 185.220.101.1 (Tor Exit Node)

 THREAT INTELLIGENCE ENRICHMENT:
  [1] 185.220.101.1
      Niveau: CRITICAL
      Score: 100/100
      AbuseIPDB: 100% confiance (201 rapports)
      Pays: Allemagne (DE)

🔴 INCIDENT CORRÉLÉ - Vol de Credentials
Confiance: 95%
```

### Exemple 3 : Tempête d'alertes (DDoS potentiel)

**Scénario :** 15 alertes en 2 minutes
```
🟠 INCIDENT - Tempête d'Alertes
Sévérité: HIGH
Description: 15 alertes en 300s
Timestamp: 2026-01-09 14:30:00
```

---

##  Performances

| Métrique | Valeur |
|----------|--------|
| **Paquets analysés/sec** | ~5000 |
| **Mémoire utilisée** | ~150 MB |
| **CPU (idle)** | ~5% |
| **CPU (capture active)** | ~25% |
| **Latence détection** | < 100ms |
| **Taux faux positifs** | < 2% |

**Testé sur :** Kali Linux 2024, Intel i5, 8GB RAM

