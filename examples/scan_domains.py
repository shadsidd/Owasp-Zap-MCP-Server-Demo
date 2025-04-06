"""
Example script to demonstrate scanning multiple domains using the MCP Server.
"""
import asyncio
import sys
import os

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient
from batch_scanner import BatchScanner

async def main():
    # List of domains to scan
    domains = [
        "example.com",
        "test.example.com",
        "dev.example.com",
        # Add more domains as needed
    ]
    
    # Create scanner with 2 concurrent scans
    scanner = BatchScanner(concurrent_scans=2)
    
    try:
        # Start scanning
        results = await scanner.scan_domains(domains)
        
        # Print results
        print("\nScan Results Summary:")
        print("=" * 80)
        
        for domain, result in results.items():
            # Print status
            status = "✅" if result['status'] == 'success' else "❌"
            print(f"\n{status} Domain: {domain}")
            
            if result['status'] == 'success':
                # Print timing information
                print(f"Duration: {result['duration']}")
                print(f"Started: {result['start_time']}")
                print(f"Completed: {result['end_time']}")
                
                # Print alerts summary
                alerts = result['alerts']
                risk_levels = {}
                for alert in alerts:
                    risk = alert['risk']
                    risk_levels[risk] = risk_levels.get(risk, 0) + 1
                
                print("\nRisk Summary:")
                for risk, count in risk_levels.items():
                    print(f"- {risk}: {count} findings")
                
                # Print detailed findings
                print("\nDetailed Findings:")
                for alert in alerts:
                    print(f"\n🚨 {alert['risk']} Risk: {alert['name']}")
                    print(f"   URL: {alert['url']}")
                    print(f"   Description: {alert['description'][:100]}...")
            else:
                print(f"Error: {result['error']}")
            
            print("-" * 80)
    except Exception as e:
        print(f"Error during scanning: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 