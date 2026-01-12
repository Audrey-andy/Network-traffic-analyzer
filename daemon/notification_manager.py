#!/usr/bin/env python3
"""
Gestionnaire de notifications
Envoie des alertes par Email
"""

import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class NotificationManager:
    """
    Classe pour envoyer des notifications sur différents canaux
    """
    
    def __init__(self, config=None):
        """
        Initialise le gestionnaire avec la config
        config = {
            'email': {...},      # Config email
        }
        """
        self.config = config or {}
        
        self.email_enabled = 'email' in self.config
        
        print("Notification Manager initialisé")
        if self.email_enabled:
            print(" • Email: Active")
        
        if not any([self.email_enabled]):
            print(" Aucune notification configurée, Mode logs uniquement")
    
    def send_alert(self, alert):
        """
        Envoie une alerte sur tous les canaux configurés
        alert = {
            'severity': 'CRITICAL',
            'category': 'Port Scan',
            'description': '...',
            'details': '...',
            'source_ip': '192.168.1.100'
        }
        """
        if alert['severity'] not in ['CRITICAL', 'HIGH']:
            return
        
        print(f" Envoi de notification : {alert['severity']} - {alert['category']}")
        
        message = self._format_alert_message(alert)
        
        if self.email_enabled:
            self._send_email(alert, message)
    
    def _format_alert_message(self, alert):
        """Formate l'alerte en message texte lisible"""
        emoji = '🔴' if alert['severity'] == 'CRITICAL' else '🟠'
        
        message = f"""
{emoji} ALERTE DE SÉCURITÉ {emoji}

Sévérité : {alert['severity']}
Catégorie : {alert['category']}
Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Description :
{alert['description']}

Détails :
{alert['details']}
"""
        
        if alert.get('source_ip'):
            message += f"\nIP Source : {alert['source_ip']}"
        if alert.get('destination_ip'):
            message += f"\nIP Destination : {alert['destination_ip']}"
        
        return message
    
    def _send_email(self, alert, message):
        """Envoie un email"""
        try:
            config = self.config['email']
            
            msg = MIMEMultipart()
            msg['From'] = config['from']
            msg['To'] = config['to']
            msg['Subject'] = f" {alert['severity']} - {alert['category']}"
            
            msg.attach(MIMEText(message, 'plain'))
            
            # Connexion au serveur SMTP
            # Pour Gmail : smtp.gmail.com:587
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
            server.starttls()
            
            server.login(config['username'], config['password'])
            
            server.send_message(msg)
            server.quit()
            
            print(f"  Email envoyé à {config['to']}")
        except Exception as e:
            print(f"   Erreur email : {e}")

# Test
if __name__ == "__main__":
    print("Notification Manager")
    print("\nCe module envoie des notifications par :")
    print("  • Email (SMTP)")
    print("\nConfigurez config.json pour activer les notifications.")