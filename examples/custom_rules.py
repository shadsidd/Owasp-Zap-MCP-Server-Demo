"""
Example of integrating custom security rules with MCP Server.
Demonstrates how to create, load and use custom security rules for scanning.
"""
import asyncio
import sys
import os
import json
from typing import Dict, List, Optional

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient

class CustomRuleManager:
    def __init__(self):
        self.client = MCPClient()
        
    async def create_custom_rule(self, rule_config: Dict) -> str:
        """
        Create a custom security rule.
        
        Args:
            rule_config: Dictionary containing rule configuration
            
        Returns:
            str: Rule ID of created rule
        """
        try:
            async with self.client as client:
                rule_id = await client.create_rule(rule_config)
                return rule_id
        except Exception as e:
            print(f"Error creating custom rule: {e}")
            return None
            
    async def load_rule_from_file(self, file_path: str) -> Dict:
        """Load rule configuration from JSON file."""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading rule file: {e}")
            return None
            
    async def validate_rule(self, rule_config: Dict) -> bool:
        """Validate rule configuration format."""
        required_fields = ['name', 'type', 'pattern', 'risk']
        
        # Check required fields
        for field in required_fields:
            if field not in rule_config:
                print(f"Missing required field: {field}")
                return False
                
        # Validate risk level
        valid_risks = ['High', 'Medium', 'Low', 'Info']
        if rule_config['risk'] not in valid_risks:
            print(f"Invalid risk level. Must be one of: {valid_risks}")
            return False
            
        return True
        
    async def scan_with_custom_rules(self, target_url: str, rules: List[Dict]):
        """
        Run scan with custom security rules.
        
        Args:
            target_url: URL to scan
            rules: List of rule configurations to apply
        """
        try:
            async with self.client as client:
                print(f"\nStarting scan with custom rules: {target_url}")
                print("=" * 50)
                
                # Create and validate rules
                rule_ids = []
                for rule in rules:
                    if await self.validate_rule(rule):
                        rule_id = await self.create_custom_rule(rule)
                        if rule_id:
                            rule_ids.append(rule_id)
                            print(f"Created rule: {rule['name']} (ID: {rule_id})")
                
                if not rule_ids:
                    print("No valid rules to apply")
                    return
                    
                # Start scan with custom rules
                scan_id = await client.start_scan(
                    target_url,
                    custom_rules=rule_ids
                )
                print(f"Scan started with ID: {scan_id}")
                
                # Monitor progress
                while True:
                    status = await client.get_status(scan_id)
                    print(f"Progress: {status.progress}%")
                    
                    if status.is_complete:
                        break
                        
                    await asyncio.sleep(2)
                
                # Get and process results
                alerts = await client.get_alerts(scan_id)
                
                # Group findings by rule
                rule_findings = {}
                for alert in alerts:
                    rule_name = alert.get('rule', 'Unknown Rule')
                    if rule_name not in rule_findings:
                        rule_findings[rule_name] = []
                    rule_findings[rule_name].append(alert)
                
                # Print findings
                print("\nScan Results:")
                print("=" * 50)
                
                for rule_name, findings in rule_findings.items():
                    print(f"\n🔍 Rule: {rule_name}")
                    print(f"Found {len(findings)} issue(s)")
                    
                    for finding in findings:
                        print(f"\n  🚨 {finding['risk']} Risk:")
                        print(f"     URL: {finding['url']}")
                        print(f"     Description: {finding['description']}")
                        if 'evidence' in finding:
                            print(f"     Evidence: {finding['evidence']}")
                
        except Exception as e:
            print(f"Error during scan: {e}")
            sys.exit(1)

async def main():
    # Example custom rules
    custom_rules = [
        {
            "name": "Sensitive Data Exposure",
            "type": "regex",
            "pattern": r"(?i)(password|secret|key)\\s*[:=]\\s*['\"]?[^'\"\\s]+['\"]?",
            "risk": "High",
            "description": "Detects exposed sensitive data in responses",
            "solution": "Ensure sensitive data is not exposed in responses"
        },
        {
            "name": "Insecure Direct Object Reference",
            "type": "pattern",
            "pattern": r"id=\\d+",
            "risk": "Medium",
            "description": "Detects potential IDOR vulnerabilities",
            "solution": "Implement proper access controls and use indirect references"
        },
        {
            "name": "Debug Information Disclosure",
            "type": "regex",
            "pattern": r"(?i)(debug|stack trace|exception).*",
            "risk": "Low",
            "description": "Detects debug information in responses",
            "solution": "Disable debug output in production"
        }
    ]
    
    manager = CustomRuleManager()
    
    # Run scan with custom rules
    await manager.scan_with_custom_rules(
        target_url="https://example.com",
        rules=custom_rules
    )

if __name__ == "__main__":
    asyncio.run(main()) 