#!/usr/bin/env python3
"""
Module de détection géographique des connexions
Identifie le pays d'origine et détecte les connexions suspectes
"""

import geoip2.database
import os
from collections import Counter

class GeoIPDetector:
    def __init__(self, geoip_db_path="data/geoip/GeoLite2-Country.mmdb"):
        """
        Initialise le détecteur GeoIP
        
        Args:
            geoip_db_path: Chemin vers la base de données GeoIP
        """
        self.geoip_db_path = geoip_db_path
        self.reader = None
        self.country_stats = Counter() 
        
        # Pays considérés comme à haut risque
        # (Liste basée sur les rapports de cybersécurité publics)
        self.HIGH_RISK_COUNTRIES = [
            'North Korea', 'Iran', 'Syria', 'Russia', 'China'
        ]
        
        if not os.path.exists(geoip_db_path):
            print(f"! Base GeoIP introuvable : {geoip_db_path}")
            print(" Téléchargez-la depuis : https://github.com/P3TERX/GeoLite.mmdb")
        else:
            # Ouvre la base de données
            self.reader = geoip2.database.Reader(geoip_db_path)
            print(f"Base GeoIP chargée : {geoip_db_path}")
    
    def get_country(self, ip_address):
        """
        Récupère le pays d'une adresse IP
        
        Args:
            ip_address: Adresse IP à localiser
            
        Returns:
            Nom du pays ou "Unknown" si introuvable
        """
        if not self.reader:
            return "Unknown"
        
        try:
            
            if self._is_private_ip(ip_address):
                return "Private Network"
            
            
            response = self.reader.country(ip_address)
            country = response.country.name
            
            if country is None:
                return "Unknown"
            
            self.country_stats[country] += 1
            
            return country
            
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            print(f"[!] Erreur lors de la recherche de {ip_address}: {e}")
            return "Unknown"

    def _is_private_ip(self, ip):
        """
        Vérifie si une IP est privée (réseau local)
        
        IPs privées :
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 127.0.0.1
        """
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
    
    def is_high_risk_country(self, country):
        """
        Vérifie si un pays est à haut risque
        
        Args:
            country: Nom du pays
            
        Returns:
            True si à haut risque, False sinon
        """
        return country in self.HIGH_RISK_COUNTRIES
    
    def analyze_connections(self, ip_list):
        """
        Analyse une liste d'IPs et retourne les statistiques
        
        Args:
            ip_list: Liste d'adresses IP
            
        Returns:
            Dictionnaire avec les stats par pays et alertes
        """
        results = {
            'countries': {},
            'high_risk_connections': [],
            'total_analyzed': 0
        }
        
        for ip in ip_list:
            country = self.get_country(ip)
            
            if country not in results['countries']:
                results['countries'][country] = 0
            results['countries'][country] += 1
            
            if self.is_high_risk_country(country):
                results['high_risk_connections'].append({
                    'ip': ip,
                    'country': country
                })
            
            results['total_analyzed'] += 1
        
        return results
    
    def print_stats(self):
        """Affiche les statistiques de connexions par pays"""
        if not self.country_stats:
            print(" Aucune donnée géographique disponible")
            return
        
        print(" RÉPARTITION GÉOGRAPHIQUE DES CONNEXIONS")
        
        total = sum(self.country_stats.values())
        
        for country, count in self.country_stats.most_common(10):
            percentage = (count / total) * 100
            risk_indicator = "🔴" if self.is_high_risk_country(country) else "🟢"
            print(f"{risk_indicator} {country:20} : {count:4} ({percentage:5.1f}%)")
        
    
    def close(self):
        """Ferme la base de données"""
        if self.reader:
            self.reader.close()

# Test du module
if __name__ == "__main__":
    detector = GeoIPDetector()
    
    test_ips = [
        "8.8.8.8",          # Google DNS - USA
        "1.1.1.1",          # Cloudflare - USA
        "185.220.101.1",    # Russie
        "192.168.1.1",      # Privée
        "13.107.213.42"     # Microsoft - USA
    ]
    
    print("\n Test du détecteur GeoIP")
    for ip in test_ips:
        country = detector.get_country(ip)
        risk = " RISQUE" if detector.is_high_risk_country(country) else "OK"
        print(f"{ip:20} → {country:20} {risk}")
    
    detector.print_stats()
    detector.close()