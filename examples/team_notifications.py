"""
Example of integrating team notifications with MCP Server.
Demonstrates how to send security scan notifications to various team communication channels.
"""
import asyncio
import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient

class NotificationManager:
    def __init__(self, config: Dict):
        """
        Initialize notification manager with configuration.
        
        Args:
            config: Dictionary containing notification settings for different channels
        """
        self.client = MCPClient()
        self.config = config
        
    async def format_message(self, scan_id: str, alerts: List[Dict]) -> Dict:
        """Format scan results for different notification channels."""
        # Group alerts by risk level
        risk_groups = {
            'High': [],
            'Medium': [],
            'Low': [],
            'Info': []
        }
        
        for alert in alerts:
            risk_level = alert.get('risk', 'Info')
            risk_groups[risk_level].append(alert)
            
        # Create summary
        summary = f"Security Scan Results (ID: {scan_id})\n"
        summary += "=" * 40 + "\n\n"
        
        for risk_level, findings in risk_groups.items():
            if findings:
                summary += f"{risk_level} Risk Issues: {len(findings)}\n"
                
        # Create detailed report
        details = "\nDetailed Findings:\n"
        details += "=" * 40 + "\n\n"
        
        for risk_level, findings in risk_groups.items():
            if findings:
                details += f"\n{risk_level} Risk Findings:\n"
                for finding in findings:
                    details += f"\n- {finding['name']}\n"
                    details += f"  URL: {finding['url']}\n"
                    details += f"  Description: {finding['description']}\n"
                    if 'solution' in finding:
                        details += f"  Solution: {finding['solution']}\n"
                        
        return {
            'summary': summary,
            'details': details,
            'html': self.format_html_report(scan_id, risk_groups)
        }
        
    def format_html_report(self, scan_id: str, risk_groups: Dict) -> str:
        """Create HTML formatted report for email."""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .high {{ color: red; }}
                .medium {{ color: orange; }}
                .low {{ color: yellow; }}
                .info {{ color: blue; }}
                .finding {{ margin: 10px 0; padding: 10px; border: 1px solid #ccc; }}
            </style>
        </head>
        <body>
            <h2>Security Scan Results</h2>
            <p>Scan ID: {scan_id}</p>
            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h3>Summary</h3>
        """
        
        for risk_level, findings in risk_groups.items():
            html += f"<p class='{risk_level.lower()}'>{risk_level} Risk Issues: {len(findings)}</p>"
            
        html += "<h3>Detailed Findings</h3>"
        
        for risk_level, findings in risk_groups.items():
            if findings:
                html += f"<h4 class='{risk_level.lower()}'>{risk_level} Risk Findings</h4>"
                for finding in findings:
                    html += f"""
                    <div class='finding'>
                        <h4>{finding['name']}</h4>
                        <p><strong>URL:</strong> {finding['url']}</p>
                        <p><strong>Description:</strong> {finding['description']}</p>
                    </div>
                    """
                    
        html += "</body></html>"
        return html
        
    async def send_email(self, recipients: List[str], subject: str, 
                        text_content: str, html_content: str):
        """Send email notification."""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.config['email']['sender']
            msg['To'] = ', '.join(recipients)
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            with smtplib.SMTP(self.config['email']['smtp_server'], 
                            self.config['email']['smtp_port']) as server:
                if self.config['email'].get('use_tls', True):
                    server.starttls()
                server.login(self.config['email']['username'],
                           self.config['email']['password'])
                server.send_message(msg)
                
            print("✉️ Email notification sent successfully")
            
        except Exception as e:
            print(f"Error sending email: {e}")
            
    async def send_slack(self, message: str):
        """Send Slack notification."""
        try:
            response = requests.post(
                self.config['slack']['webhook_url'],
                json={'text': message}
            )
            response.raise_for_status()
            print("💬 Slack notification sent successfully")
            
        except Exception as e:
            print(f"Error sending Slack notification: {e}")
            
    async def send_teams(self, message: str):
        """Send Microsoft Teams notification."""
        try:
            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": "Security Scan Results",
                "themeColor": "0076D7",
                "sections": [{
                    "activityTitle": "Security Scan Results",
                    "text": message
                }]
            }
            
            response = requests.post(
                self.config['teams']['webhook_url'],
                json=card
            )
            response.raise_for_status()
            print("👥 Teams notification sent successfully")
            
        except Exception as e:
            print(f"Error sending Teams notification: {e}")
            
    async def notify_scan_results(self, target_url: str):
        """Run scan and send notifications."""
        try:
            async with self.client as client:
                print(f"\nStarting security scan of {target_url}")
                print("=" * 50)
                
                # Start scan
                scan_id = await client.start_scan(target_url)
                print(f"Scan started with ID: {scan_id}")
                
                # Monitor progress
                while True:
                    status = await client.get_status(scan_id)
                    print(f"Progress: {status.progress}%")
                    
                    if status.is_complete:
                        break
                        
                    await asyncio.sleep(2)
                
                # Get results
                alerts = await client.get_alerts(scan_id)
                
                # Format messages
                messages = await self.format_message(scan_id, alerts)
                
                # Send notifications based on configuration
                if 'email' in self.config:
                    await self.send_email(
                        recipients=self.config['email']['recipients'],
                        subject=f"Security Scan Results - {target_url}",
                        text_content=messages['summary'] + messages['details'],
                        html_content=messages['html']
                    )
                    
                if 'slack' in self.config:
                    await self.send_slack(messages['summary'] + messages['details'])
                    
                if 'teams' in self.config:
                    await self.send_teams(messages['summary'] + messages['details'])
                    
        except Exception as e:
            print(f"Error during scan and notification: {e}")
            sys.exit(1)

async def main():
    # Example notification configuration
    notification_config = {
        'email': {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'use_tls': True,
            'username': 'your-email@gmail.com',
            'password': 'your-app-password',
            'sender': 'security-scanner@example.com',
            'recipients': ['team@example.com', 'security@example.com']
        },
        'slack': {
            'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        },
        'teams': {
            'webhook_url': 'https://your-org.webhook.office.com/webhookb2/your-teams-webhook-url'
        }
    }
    
    notifier = NotificationManager(notification_config)
    
    # Run scan and send notifications
    await notifier.notify_scan_results("https://example.com")

if __name__ == "__main__":
    asyncio.run(main()) 