#!/usr/bin/env python3
from zap_client import ZAPScanner, print_alerts, RiskLevel
import sys

def test_basic_scan(url: str):
    """Run a basic scan against a target"""
    print(f"\n🎯 Testing basic scan against {url}")
    print("=" * 50)
    
    # Initialize scanner
    scanner = ZAPScanner('http://localhost:3001')
    
    # Configure ZAP
    scanner.configure(
        zap_url='http://localhost:8080',
        api_key='nb5dlof24g342c6fhs4giicpeo'
    )
    
    # Run quick scan
    alerts = scanner.quick_scan(url)
    
    # Print results by risk level
    for risk in RiskLevel:
        print(f"\n{risk.value} Risk Alerts:")
        print("-" * 20)
        print_alerts(alerts, risk)

def main():
    # Get target URL from command line or use default
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    
    try:
        test_basic_scan(target)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 