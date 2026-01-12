#!/usr/bin/env python3
"""
Module d'enrichissement avec Threat Intelligence
Intègre AbuseIPDB, VirusTotal et Shodan (nécessite clés API)
"""

import requests
import json
from datetime import datetime

class ThreatIntelligenceEnricher:
    def __init__(self, config=None):
        """Initialise l'enrichisseur avec les clés API"""
        self.config = config or {}
        
        # Clés API
        self.abuseipdb_key = self.config.get('abuseipdb_key', None)
        self.virustotal_key = self.config.get('virustotal_key', None)
        self.shodan_key = self.config.get('shodan_key', None)
        
        self.cache = {}
        self.stats = {
            'total_enriched': 0,
            'cache_hits': 0,
            'api_calls': 0
        }
        
        print("Threat Intelligence Enricher initialisé")
        if self.abuseipdb_key:
            print(" • AbuseIPDB: Activé")
        if self.virustotal_key:
            print(" • VirusTotal: Activé")
        if self.shodan_key:
            print(" • Shodan: Activé")
        
        if not any([self.abuseipdb_key, self.virustotal_key, self.shodan_key]):
            print(" Aucune clé API configurée")
            print(" Threat Intelligence désactivé")
    
    def enrich_ip(self, ip_address):
        """Enrichit une IP avec threat intelligence"""
        
        if ip_address in self.cache:
            self.stats['cache_hits'] += 1
            return self.cache[ip_address]
        
        if self._is_private_ip(ip_address):
            return {'ip': ip_address, 'enriched': False, 'reason': 'Private IP'}
        
        enriched_data = {
            'ip': ip_address,
            'enriched': True,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # AbuseIPDB
        if self.abuseipdb_key:
            abuse_data = self._check_abuseipdb(ip_address)
            if abuse_data:
                enriched_data['sources']['abuseipdb'] = abuse_data
        
        # VirusTotal
        if self.virustotal_key:
            vt_data = self._check_virustotal(ip_address)
            if vt_data:
                enriched_data['sources']['virustotal'] = vt_data
        
        # Shodan
        if self.shodan_key:
            shodan_data = self._check_shodan(ip_address)
            if shodan_data:
                enriched_data['sources']['shodan'] = shodan_data
        
        # Si aucune source configurée
        if not enriched_data['sources']:
            return {'ip': ip_address, 'enriched': False, 'reason': 'No API keys configured'}
        
        enriched_data['threat_score'] = self._calculate_threat_score(enriched_data)
        enriched_data['threat_level'] = self._get_threat_level(enriched_data['threat_score'])
        
        self.cache[ip_address] = enriched_data
        self.stats['total_enriched'] += 1
        
        return enriched_data
    
    def _check_abuseipdb(self, ip_address):
        """Vérification via AbuseIPDB API"""
        try:
            self.stats['api_calls'] += 1
            
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': self.abuseipdb_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country': data.get('countryCode', 'Unknown'),
                    'is_public': data.get('isPublic', True),
                    'last_reported': data.get('lastReportedAt', None)
                }
            
            return None   
        except Exception as e:
            print(f"Erreur AbuseIPDB pour {ip_address}: {e}")
            return None
    
    def _check_virustotal(self, ip_address):
        """Vérification via VirusTotal API"""
        try:
            self.stats['api_calls'] += 1
            
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {'x-apikey': self.virustotal_key}
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': attributes.get('reputation', 0),
                    'country': attributes.get('country', 'Unknown')
                }
            
            return None
            
        except Exception as e:
            print(f"Erreur VirusTotal pour {ip_address}: {e}")
            return None
    
    def _check_shodan(self, ip_address):
        """Vérification via Shodan API"""
        try:
            self.stats['api_calls'] += 1
            
            url = f"https://api.shodan.io/shodan/host/{ip_address}"
            params = {'key': self.shodan_key}
            
            response = requests.get(url, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'ports': data.get('ports', []),
                    'vulns': list(data.get('vulns', [])),
                    'org': data.get('org', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'services': [s.get('product', 'Unknown') for s in data.get('data', [])]
                }
            
            return None
            
        except Exception as e:
            print(f" Erreur Shodan pour {ip_address}: {e}")
            return None
    
    def _calculate_threat_score(self, enriched_data):
        """Calcule un score de menace de 0 à 100"""
        score = 0
        sources = enriched_data.get('sources', {})
        active_sources = len(sources)
        
        if active_sources == 0:
            return 0
        
        # AbuseIPDB 
        if 'abuseipdb' in sources:
            abuse = sources['abuseipdb']
            abuse_score = abuse.get('abuse_confidence_score', 0)
            
            # Si c'est la seule source 100% du poids
            if active_sources == 1:
                score = abuse_score
            else:
                score += abuse_score * 0.4
        
        # VirusTotal
        if 'virustotal' in sources:
            vt = sources['virustotal']
            malicious = vt.get('malicious', 0)
            suspicious = vt.get('suspicious', 0)
            vt_score = min((malicious * 5 + suspicious * 2), 40)
            
            if active_sources == 1:
                score = min(vt_score * 2.5, 100)
            else:
                score += vt_score
        
        # Shodan
        if 'shodan' in sources:
            shodan = sources['shodan']
            vulns = len(shodan.get('vulns', []))
            shodan_score = min(vulns * 10, 20)
            
            if active_sources == 1:
                score = min(shodan_score * 5, 100)
            else:
                score += shodan_score
        
        return min(int(score), 100)

    def _get_threat_level(self, score):
        """Convertit le score en niveau de menace"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'SAFE'
    
    def _is_private_ip(self, ip):
        """Vérifie si une IP est privée"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])

            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if ip == "127.0.0.1":
                return True
            
            return False
        except:
            return False
    
    def enrich_alerts(self, alerts):
        """Enrichit une liste d'alertes avec threat intelligence"""
        print(f"\n Enrichissement de {len(alerts)} alertes...")

        ips_to_check = set()
        for alert in alerts:
            if alert.get('source_ip'):
                ips_to_check.add(alert['source_ip'])
            if alert.get('destination_ip'):
                ips_to_check.add(alert['destination_ip'])
        
        print(f" {len(ips_to_check)} IPs uniques à vérifier...")
        
        for ip in ips_to_check:
            intel_data = self.enrich_ip(ip)
            
            if intel_data.get('threat_score', 0) > 50:
                threat_level = intel_data.get('threat_level', 'UNKNOWN')
                print(f"  🔴 {ip} → {threat_level} (Score: {intel_data['threat_score']})")
        
        enriched_alerts = []
        for alert in alerts:
            enriched_alert = alert.copy()
            
            if alert.get('source_ip'):
                src_intel = self.cache.get(alert['source_ip'])
                if src_intel and src_intel.get('enriched'):
                    enriched_alert['source_threat_intelligence'] = src_intel
            
            if alert.get('destination_ip'):
                dst_intel = self.cache.get(alert['destination_ip'])
                if dst_intel and dst_intel.get('enriched'):
                    enriched_alert['destination_threat_intelligence'] = dst_intel
            
            enriched_alerts.append(enriched_alert)
        
        print(f"\n Enrichissement terminé !")
        print(f" • {self.stats['total_enriched']} IPs enrichies")
        print(f"• {self.stats['cache_hits']} cache hits")
        print(f"• {self.stats['api_calls']} appels API")
        
        return enriched_alerts
    
    def get_statistics(self):
        """Retourne les statistiques d'enrichissement"""
        return self.stats


# Test 
if __name__ == "__main__":
    print(" Threat Intelligence Enricher")
    print("\n  Ce module nécessite des clés API pour fonctionner.")
    print("\nPour l'activer :")
    print("1. S'inscrire sur https://www.abuseipdb.com")
    print("2. Obtenir la clé API ")
    print("\n'No API keys configured'")