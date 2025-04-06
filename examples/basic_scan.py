"""
Basic example of using MCP Server for security scanning.
Demonstrates core scanning functionality with proper error handling.
"""
import asyncio
import sys
import os
from datetime import datetime

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient

async def basic_scan(target_url: str):
    """
    Perform a basic security scan with proper error handling.
    
    Args:
        target_url: The URL to scan
    """
    try:
        async with MCPClient() as client:
            print(f"\nStarting scan of {target_url}")
            print("=" * 50)
            
            # Start the scan
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
            
            # Print summary
            print("\nScan Complete!")
            print("=" * 50)
            print(f"Found {len(alerts)} potential vulnerabilities")
            
            # Group alerts by risk level
            risk_levels = {}
            for alert in alerts:
                risk = alert['risk']
                risk_levels[risk] = risk_levels.get(risk, 0) + 1
            
            print("\nRisk Level Summary:")
            for risk, count in risk_levels.items():
                print(f"- {risk}: {count} finding(s)")
            
            # Print detailed findings
            print("\nDetailed Findings:")
            for alert in alerts:
                print(f"\n🚨 {alert['risk']} Risk: {alert['name']}")
                print(f"   URL: {alert['url']}")
                print(f"   Description: {alert['description']}")
                print(f"   Solution: {alert['solution']}")
                
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)

async def main():
    # Example usage
    target_url = "https://example.com"
    await basic_scan(target_url)

if __name__ == "__main__":
    asyncio.run(main()) 