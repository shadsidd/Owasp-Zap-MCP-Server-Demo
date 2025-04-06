"""
Example of using custom scan policies with MCP Server.
Demonstrates how to configure and use custom security scanning rules.
"""
import asyncio
import sys
import os
from typing import Dict, List

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient

class CustomScanPolicy:
    def __init__(self):
        self.client = MCPClient()
        
    async def create_policy(self, name: str, alert_threshold: str = 'MEDIUM',
                          attack_strength: str = 'MEDIUM') -> Dict:
        """
        Create a custom scan policy with specific settings.
        
        Args:
            name: Name of the policy
            alert_threshold: LOW, MEDIUM, HIGH
            attack_strength: LOW, MEDIUM, HIGH
        """
        policy = {
            'name': name,
            'alert_threshold': alert_threshold,
            'attack_strength': attack_strength,
            'rules': {
                'xss': True,              # Cross-site scripting
                'sql_injection': True,     # SQL injection
                'cmd_injection': True,     # Command injection
                'lfi': True,              # Local file inclusion
                'rfi': True,              # Remote file inclusion
                'csrf': True,             # Cross-site request forgery
                'info_disclosure': False,  # Information disclosure
                'path_traversal': True,   # Directory traversal
            }
        }
        return policy
        
    async def scan_with_policy(self, target_url: str, policy: Dict):
        """Run a scan using a custom policy."""
        try:
            async with self.client as client:
                print(f"\nStarting scan of {target_url} with custom policy")
                print("=" * 50)
                
                # Configure scan with custom policy
                scan_id = await client.start_scan(target_url, policy=policy)
                print(f"Scan started with ID: {scan_id}")
                
                # Monitor progress
                while True:
                    status = await client.get_status(scan_id)
                    print(f"Progress: {status.progress}%")
                    
                    if status.is_complete:
                        break
                        
                    await asyncio.sleep(2)
                
                # Get and analyze results
                alerts = await client.get_alerts(scan_id)
                
                # Group alerts by rule type
                rule_alerts = {}
                for alert in alerts:
                    rule = alert['rule']
                    if rule not in rule_alerts:
                        rule_alerts[rule] = []
                    rule_alerts[rule].append(alert)
                
                # Print summary by rule
                print("\nScan Results by Rule:")
                print("=" * 50)
                for rule, rule_findings in rule_alerts.items():
                    print(f"\n{rule}:")
                    print(f"Found {len(rule_findings)} issues")
                    
                    # Group by risk level
                    risk_levels = {}
                    for finding in rule_findings:
                        risk = finding['risk']
                        risk_levels[risk] = risk_levels.get(risk, 0) + 1
                    
                    for risk, count in risk_levels.items():
                        print(f"- {risk}: {count} finding(s)")
                
        except Exception as e:
            print(f"Error during scan: {e}")
            sys.exit(1)

async def main():
    scanner = CustomScanPolicy()
    
    # Create a custom policy
    policy = await scanner.create_policy(
        name="Custom Web App Policy",
        alert_threshold="MEDIUM",
        attack_strength="HIGH"
    )
    
    # Run scan with custom policy
    target_url = "https://example.com"
    await scanner.scan_with_policy(target_url, policy)

if __name__ == "__main__":
    asyncio.run(main()) 