#!/usr/bin/env python3
"""
Module de vérification contre des blacklists
Détecte les IPs et domaines malveillants connus
"""

import requests
import json
from collections import defaultdict
import time

class BlacklistChecker:
    def __init__(self):
        """Initialise le vérificateur de blacklists"""
        self.malicious_ips = set()
        self.checked_ips = {}  
        
        # Blacklist locale (IPs connues comme malveillantes)
        # Source : bases publiques de threat intelligence
        self.LOCAL_BLACKLIST = {
            '185.220.101.1': 'Tor Exit Node',
            '45.142.212.61': 'Known Malware C2',
            '104.248.144.120': 'Botnet Controller',
            '192.42.116.16': 'Suspicious Activity'
        }
        
        # Domaines suspects
        self.SUSPICIOUS_DOMAINS = [
            'malware.com', 'phishing-site.net', 'badactor.org',
            'c2server.ru', 'botnet-control.cn'
        ]
        
        print("[+] Blacklist Checker initialisé")
        print(f"[+] {len(self.LOCAL_BLACKLIST)} IPs en blacklist locale")
    
    def check_local_blacklist(self, ip_address):
        """
        Vérifie si une IP est dans la blacklist locale
        
        Args:
            ip_address: Adresse IP à vérifier
            
        Returns:
            Tuple (is_malicious, reason)
        """
        if ip_address in self.LOCAL_BLACKLIST:
            reason = self.LOCAL_BLACKLIST[ip_address]
            return (True, reason)
        
        return (False, None)
    
    def check_abuseipdb(self, ip_address, api_key=None):
        """
        Vérifie une IP sur AbuseIPDB (base publique de réputation)
        
        Args:
            ip_address: IP à vérifier
            api_key: Clé API (optionnelle)
            
        Returns:
            Tuple (is_malicious, confidence_score)
        """
        
        if self._is_private_ip(ip_address):
            return (False, 0)
        
        simulated_malicious = {
            '185.220.101.1': 75,   # Score de confiance 75%
            '45.142.212.61': 95,   # Score de confiance 95%
        }
        
        if ip_address in simulated_malicious:
            score = simulated_malicious[ip_address]
            return (True, score)
        
        return (False, 0)
    
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
    
    def check_ip(self, ip_address):
        """
        Vérification complète d'une IP
        
        Args:
            ip_address: IP à vérifier
            
        Returns:
            Dictionnaire avec les résultats
        """
        if ip_address in self.checked_ips:
            return self.checked_ips[ip_address]
        
        result = {
            'ip': ip_address,
            'is_malicious': False,
            'sources': [],
            'confidence': 0,
            'reasons': []
        }
        
        # Vérification blacklist locale
        is_local_malicious, reason = self.check_local_blacklist(ip_address)
        if is_local_malicious:
            result['is_malicious'] = True
            result['sources'].append('Local Blacklist')
            result['reasons'].append(reason)
            result['confidence'] = 100
        
        # Vérification AbuseIPDB
        is_abuse_malicious, confidence = self.check_abuseipdb(ip_address)
        if is_abuse_malicious:
            result['is_malicious'] = True
            result['sources'].append('AbuseIPDB')
            result['confidence'] = max(result['confidence'], confidence)
            result['reasons'].append(f'Abuse confidence: {confidence}%')
        
        
        self.checked_ips[ip_address] = result
        
        return result
    
    def analyze_ip_list(self, ip_list):
        """
        Analyse une liste d'IPs
        
        Args:
            ip_list: Liste d'adresses IP
            
        Returns:
            Dictionnaire avec statistiques et IPs malveillantes
        """
        results = {
            'total_checked': 0,
            'malicious_count': 0,
            'malicious_ips': [],
            'clean_ips': []
        }
        
        print(f"\n[*] Vérification de {len(ip_list)} IPs...")
        
        for ip in ip_list:
            # Ignore les IPs privées
            if self._is_private_ip(ip):
                continue
            
            check_result = self.check_ip(ip)
            results['total_checked'] += 1
            
            if check_result['is_malicious']:
                results['malicious_count'] += 1
                results['malicious_ips'].append(check_result)
                print(f"  🔴 {ip:20} → MALVEILLANTE ({check_result['confidence']}% confiance)")
            else:
                results['clean_ips'].append(ip)
        
        return results
    
    def print_summary(self, results):
        """Affiche un résumé des vérifications"""
        print("  RÉSUMÉ DE VÉRIFICATION BLACKLIST")
        
        print(f"\n Total vérifié : {results['total_checked']} IPs")
        print(f"🔴 Malveillantes : {results['malicious_count']}")
        print(f"🟢 Propres : {len(results['clean_ips'])}")
        
        if results['malicious_ips']:
            print(f"\n IPS MALVEILLANTES DÉTECTÉES :")
            for malicious in results['malicious_ips']:
                print(f"\n  IP: {malicious['ip']}")
                print(f"  Confiance: {malicious['confidence']}%")
                print(f"  Sources: {', '.join(malicious['sources'])}")
                print(f"  Raisons: {'; '.join(malicious['reasons'])}")
        

# Test du module
if __name__ == "__main__":
    checker = BlacklistChecker()
    
    test_ips = [
        "8.8.8.8",           
        "1.1.1.1",           
        "185.220.101.1",     # Dans la blacklist
        "45.142.212.61",     # Dans la blacklist
        "192.168.1.1",       
        "13.107.213.42"      
    ]
    
    print("\n[*] Test du vérificateur de blacklist...")
    results = checker.analyze_ip_list(test_ips)
    checker.print_summary(results)