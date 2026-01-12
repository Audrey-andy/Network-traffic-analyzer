#!/usr/bin/env python3
"""
Module de corrélation d'alertes
Détecte les patterns d'attaques complexes
"""

from datetime import datetime, timedelta
from collections import Counter


class AlertCorrelator:
    def __init__(self, time_window_seconds=300):
        """Initialise le corrélateur """
        self.time_window = timedelta(seconds=time_window_seconds)
        self.alerts = []
        self.incidents = []
        
        # Règles de corrélation
        self.CORRELATION_RULES = {
            'targeted_attack': {
                'name': 'Attaque Ciblée',
                'severity': 'CRITICAL',
                'conditions': ['Port Scan', 'Suspicious Port'],
                'description': 'Scan de ports suivi de connexion sur port suspect'
            },
            'data_exfiltration': {
                'name': 'Exfiltration de Données',
                'severity': 'CRITICAL',
                'conditions': ['High Traffic', 'Insecure Protocol'],
                'description': 'Transfert massif via protocole non sécurisé'
            },
            'apt_activity': {
                'name': 'Menace Persistante Avancée',
                'severity': 'CRITICAL',
                'conditions': ['High Risk Country', 'Suspicious Port', 'Malicious IP'],
                'description': 'Pattern typique d\'une APT'
            },
            'credential_theft': {
                'name': 'Vol de Credentials',
                'severity': 'CRITICAL',
                'conditions': ['Credentials in Clear', 'Malicious IP'],
                'description': 'Identifiants vers IP malveillante'
            }
        }
        print(f"Corrélateur d'alertes initialisé")
        print(f"Fenêtre de corrélation : {time_window_seconds}s")
        print(f" {len(self.CORRELATION_RULES)} règles de corrélation chargées")
    
    def add_alert(self, alert):
        """Ajoute une alerte au système"""
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now()
        elif isinstance(alert['timestamp'], str):
            alert['timestamp'] = datetime.fromisoformat(alert['timestamp'])
        
        self.alerts.append(alert)
    
    def add_alerts_batch(self, alerts_list):
        """Ajoute plusieurs alertes en batch"""
        for alert in alerts_list:
            self.add_alert(alert)
    
    def correlate(self):
        """Analyse toutes les alertes et détecte les patterns"""
        if not self.alerts:
            print(" Aucune alerte à corréler")
            return []
        
        print(f"\nCorrélation de {len(self.alerts)} alertes...")
        
        self.incidents = []
        sorted_alerts = sorted(self.alerts, key=lambda x: x['timestamp'])
        
        for rule_id, rule in self.CORRELATION_RULES.items():
            incidents = self._check_rule(rule, sorted_alerts)
            self.incidents.extend(incidents)
        
        # Détection des tempêtes d'alertes
        storm_incidents = self._detect_alert_storm(sorted_alerts)
        self.incidents.extend(storm_incidents)
        
        print(f"{len(self.incidents)} incidents détectés")
        
        return self.incidents
    
    def _check_rule(self, rule, alerts):
        """Vérifie si une règle de corrélation est satisfaite"""
        incidents = []
        required_categories = set(rule['conditions'])
        
        for i, alert in enumerate(alerts):
            window_alerts = [
                a for a in alerts[i:]
                if a['timestamp'] <= alert['timestamp'] + self.time_window
            ]
            
            categories_present = set(a['category'] for a in window_alerts)
            
            # Toutes les conditions remplies ?
            if required_categories.issubset(categories_present):
                incident = {
                    'incident_type': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'timestamp': alert['timestamp'],
                    'related_alerts': [
                        a for a in window_alerts
                        if a['category'] in required_categories
                    ],
                    'alert_count': len(window_alerts),
                    'confidence': self._calculate_confidence(window_alerts, rule)
                }
                
                incidents.append(incident)
                break   
        return incidents
    
    def _detect_alert_storm(self, alerts):
        """Détecte les tempêtes d'alertes """
        incidents = []
        STORM_THRESHOLD = 10
        
        for i, alert in enumerate(alerts):
            window_alerts = [
                a for a in alerts[i:]
                if a['timestamp'] <= alert['timestamp'] + self.time_window
            ]
            
            if len(window_alerts) >= STORM_THRESHOLD:
                if not any(inc['incident_type'] == 'Tempête d\'Alertes' 
                          and abs((inc['timestamp'] - alert['timestamp']).total_seconds()) < 60
                          for inc in incidents):
                    
                    incident = {
                        'incident_type': 'Tempête d\'Alertes',
                        'severity': 'HIGH',
                        'description': f'{len(window_alerts)} alertes en {self.time_window.seconds}s',
                        'timestamp': alert['timestamp'],
                        'related_alerts': window_alerts,
                        'alert_count': len(window_alerts),
                        'confidence': 100
                    }
                    
                    incidents.append(incident)
        
        return incidents
    
    def _calculate_confidence(self, alerts, rule):
        """Calcule un score de confiance (0-100)"""
        base_confidence = 70
        alert_bonus = min(len(alerts) * 5, 20)
        critical_bonus = 10 if any(a['severity'] == 'CRITICAL' for a in alerts) else 0
        
        return min(base_confidence + alert_bonus + critical_bonus, 100)
    
    def get_statistics(self):
        """Retourne les statistiques"""
        if not self.alerts:
            return {'total_alerts': 0, 'total_incidents': 0}
        
        severity_count = Counter(a['severity'] for a in self.alerts)
        category_count = Counter(a['category'] for a in self.alerts)
        incident_types = Counter(i['incident_type'] for i in self.incidents)
        
        return {
            'total_alerts': len(self.alerts),
            'total_incidents': len(self.incidents),
            'by_severity': dict(severity_count),
            'by_category': dict(category_count),
            'incident_types': dict(incident_types),
            'critical_incidents': len([i for i in self.incidents if i['severity'] == 'CRITICAL'])
        }
    
    def print_incidents(self):
        """Affiche tous les incidents détectés"""
        if not self.incidents:
            print("\n Aucun incident corrélé détecté")
            return

        print(f" INCIDENTS CORRÉLÉS DÉTECTÉS ({len(self.incidents)})")
        
        # Trie par sévérité
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_incidents = sorted(
            self.incidents,
            key=lambda x: severity_order.get(x['severity'], 4)
        )
        
        for i, incident in enumerate(sorted_incidents, 1):
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵'
            }.get(incident['severity'], '⚪')
            
            print(f"\n{severity_icon} INCIDENT #{i} - {incident['incident_type']}")
            print(f"  Sévérité: {incident['severity']}")
            print(f"  Confiance: {incident['confidence']}%")
            print(f"  Description: {incident['description']}")
            print(f"  Timestamp: {incident['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Alertes impliquées: {incident['alert_count']}")
            
            print(f"  Détails:")
            for alert in incident['related_alerts'][:3]:
                print(f"• {alert['category']}: {alert['description']}")
            
            if incident['alert_count'] > 3:
                print(f" ... et {incident['alert_count'] - 3} autres alertes")

    def print_summary(self):
        """Affiche un résumé des statistiques"""
        stats = self.get_statistics()

        print("RÉSUMÉ DE CORRÉLATION")
        print(f"\nTotal d'alertes analysées : {stats['total_alerts']}")
        print(f" Incidents corrélés détectés : {stats['total_incidents']}")
        print(f"🔴 Incidents CRITIQUES : {stats['critical_incidents']}")
        
        if stats.get('by_severity'):
            print(f"\n Alertes par sévérité :")
            for severity, count in stats['by_severity'].items():
                print(f"  • {severity}: {count}")
        
        if stats.get('incident_types'):
            print(f"\n Types d'incidents détectés :")
            for inc_type, count in stats['incident_types'].items():
                print(f"  • {inc_type}: {count}")


# Test
if __name__ == "__main__":
    print(" Alert Correlator - Test")
    
    correlator = AlertCorrelator(time_window_seconds=300)
    
    test_alerts = [
        {
            'severity': 'HIGH',
            'category': 'Port Scan',
            'description': 'Scan de 50 ports',
            'source_ip': '192.168.1.100',
            'timestamp': datetime.now()
        },
        {
            'severity': 'HIGH',
            'category': 'Suspicious Port',
            'description': 'Connexion sur port 4444',
            'source_ip': '192.168.1.100',
            'timestamp': datetime.now() + timedelta(seconds=30)
        }
    ]
    
    print(f"\nAjout de {len(test_alerts)} alertes de test...")
    
    correlator.add_alerts_batch(test_alerts)
    correlator.correlate()
    correlator.print_incidents()
    correlator.print_summary()
    print("\n Test terminé !")