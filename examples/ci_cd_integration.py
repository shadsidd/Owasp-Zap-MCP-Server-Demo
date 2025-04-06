"""
Example of integrating MCP Server into CI/CD pipelines.
Demonstrates automated security scanning with configurable thresholds and reporting.
"""
import asyncio
import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Optional

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient

class CIScanner:
    def __init__(self, risk_thresholds: Dict[str, int]):
        """
        Initialize CI Scanner with risk thresholds.
        
        Args:
            risk_thresholds: Dict mapping risk levels to maximum allowed findings
                           e.g. {'High': 0, 'Medium': 2, 'Low': 5}
        """
        self.client = MCPClient()
        self.risk_thresholds = risk_thresholds
        
    async def generate_report(self, alerts: List[Dict], scan_id: str) -> str:
        """Generate detailed HTML report from scan findings."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = f"security_scan_{scan_id}_{timestamp}.html"
        
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
            
        # Generate HTML report
        html = f"""
        <html>
        <head>
            <title>Security Scan Report - {timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .risk-high {{ color: red; }}
                .risk-medium {{ color: orange; }}
                .risk-low {{ color: yellow; }}
                .risk-info {{ color: blue; }}
                .finding {{ margin: 10px 0; padding: 10px; border: 1px solid #ccc; }}
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <p>Scan ID: {scan_id}</p>
            <p>Date: {timestamp}</p>
            
            <h2>Summary</h2>
            <ul>
        """
        
        # Add summary counts
        for risk_level, findings in risk_groups.items():
            html += f"<li class='risk-{risk_level.lower()}'>{risk_level}: {len(findings)}</li>"
            
        html += "</ul><h2>Detailed Findings</h2>"
        
        # Add detailed findings
        for risk_level, findings in risk_groups.items():
            if findings:
                html += f"<h3 class='risk-{risk_level.lower()}'>{risk_level} Risk Findings</h3>"
                for finding in findings:
                    html += f"""
                    <div class='finding'>
                        <h4>{finding['name']}</h4>
                        <p><strong>URL:</strong> {finding['url']}</p>
                        <p><strong>Description:</strong> {finding['description']}</p>
                        <p><strong>Solution:</strong> {finding.get('solution', 'N/A')}</p>
                    </div>
                    """
        
        html += "</body></html>"
        
        # Save report
        with open(report_file, 'w') as f:
            f.write(html)
            
        return report_file

    def check_thresholds(self, alerts: List[Dict]) -> bool:
        """Check if findings exceed configured thresholds."""
        risk_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for alert in alerts:
            risk_level = alert.get('risk')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
                
        # Check against thresholds
        for risk_level, max_allowed in self.risk_thresholds.items():
            if risk_counts.get(risk_level, 0) > max_allowed:
                print(f"❌ {risk_level} risk findings ({risk_counts[risk_level]}) "
                      f"exceed threshold ({max_allowed})")
                return False
                
        return True

    async def run_ci_scan(self, target_url: str, branch: str = 'main') -> bool:
        """
        Run security scan in CI environment.
        
        Args:
            target_url: URL to scan
            branch: Git branch being tested
            
        Returns:
            bool: True if scan passes thresholds, False otherwise
        """
        try:
            async with self.client as client:
                print(f"\nStarting CI security scan of {target_url}")
                print(f"Branch: {branch}")
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
                
                # Generate report
                report_file = await self.generate_report(alerts, scan_id)
                print(f"\nDetailed report saved to: {report_file}")
                
                # Check thresholds
                passed = self.check_thresholds(alerts)
                
                if passed:
                    print("\n✅ Security scan passed configured thresholds")
                else:
                    print("\n❌ Security scan failed - too many findings")
                    
                return passed
                
        except Exception as e:
            print(f"Error during CI scan: {e}")
            return False

async def main():
    # Configure risk thresholds
    risk_thresholds = {
        'High': 0,    # No high risk findings allowed
        'Medium': 2,  # Up to 2 medium risk findings allowed
        'Low': 5      # Up to 5 low risk findings allowed
    }
    
    scanner = CIScanner(risk_thresholds)
    
    # Run scan
    passed = await scanner.run_ci_scan(
        target_url="https://example.com",
        branch="feature/new-api"
    )
    
    # Exit with status code
    sys.exit(0 if passed else 1)

if __name__ == "__main__":
    asyncio.run(main()) 