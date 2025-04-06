#!/usr/bin/env python3
import requests
import time
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

class RiskLevel(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

@dataclass
class Alert:
    risk: str
    name: str
    description: str
    url: Optional[str] = None
    
    @property
    def risk_level(self) -> RiskLevel:
        return RiskLevel(self.risk)

class ZAPScanStatus:
    def __init__(self, scan_id: str, progress: int):
        self.scan_id = scan_id
        self.progress = progress
        
    @property
    def is_complete(self) -> bool:
        return self.progress >= 100
        
    def __str__(self) -> str:
        return f"Scan {self.scan_id} - Progress: {self.progress}%"

class ZAPScanner:
    """Enhanced ZAP Scanner client for easy security testing"""
    
    def __init__(self, mcp_server_url: str = 'http://localhost:3000', timeout: int = 30):
        """Initialize the ZAP Scanner
        
        Args:
            mcp_server_url: URL of the MCP server (default: http://localhost:3000)
            timeout: Request timeout in seconds (default: 30)
        """
        self.mcp_server_url = mcp_server_url.rstrip('/')
        self.timeout = timeout
        self.configured = False
        
    def configure(self, zap_url: str, api_key: str) -> None:
        """Configure ZAP connection
        
        Args:
            zap_url: URL of the ZAP instance (e.g., http://localhost:8080)
            api_key: ZAP API key
        """
        response = self._call_tool('configure', {
            'apiUrl': zap_url,
            'apiKey': api_key
        })
        self.configured = True
        print("✅ ZAP configured successfully")
        
    def quick_scan(self, target_url: str, wait_for_complete: bool = True) -> List[Alert]:
        """Perform a quick scan of a target URL
        
        This will:
        1. Run a spider scan
        2. Run an active scan
        3. Return the alerts
        
        Args:
            target_url: URL to scan
            wait_for_complete: Whether to wait for scans to complete (default: True)
            
        Returns:
            List of security alerts found
        """
        if not self._validate_url(target_url):
            raise ValueError(f"Invalid target URL: {target_url}")
            
        # Start spider scan
        print(f"🕷️ Starting spider scan of {target_url}")
        spider_id = self._start_spider(target_url)
        
        if wait_for_complete:
            self._wait_for_spider(spider_id)
        
        # Start active scan
        print(f"🔍 Starting active scan of {target_url}")
        scan_id = self._start_scan(target_url)
        
        if wait_for_complete:
            self._wait_for_scan(scan_id)
            
        # Get alerts
        print("📝 Retrieving security alerts")
        return self.get_alerts(target_url)
        
    def get_alerts(self, target_url: str) -> List[Alert]:
        """Get security alerts for a target URL
        
        Args:
            target_url: URL to get alerts for
            
        Returns:
            List of Alert objects
        """
        response = self._call_tool('get_alerts', {'targetUrl': target_url})
        alerts = []
        
        for alert_text in [c['text'] for c in response.get('content', [])]:
            # Parse alert text in format: "[Risk] Name: Description"
            try:
                risk = alert_text[1:alert_text.index(']')]
                name = alert_text[alert_text.index(']')+2:alert_text.index(':')]
                description = alert_text[alert_text.index(':')+2:]
                alerts.append(Alert(risk=risk, name=name, description=description))
            except:
                continue
                
        return alerts
        
    def _start_spider(self, target_url: str) -> str:
        """Start a spider scan
        
        Args:
            target_url: URL to spider
            
        Returns:
            Spider scan ID
        """
        response = self._call_tool('spider_url', {'targetUrl': target_url})
        scan_id = response['content'][0]['text'].split('Scan ID: ')[1]
        return scan_id
        
    def _start_scan(self, target_url: str) -> str:
        """Start an active scan
        
        Args:
            target_url: URL to scan
            
        Returns:
            Active scan ID
        """
        response = self._call_tool('start_scan', {'targetUrl': target_url})
        scan_id = response['content'][0]['text'].split('Scan ID: ')[1]
        return scan_id
        
    def _get_spider_status(self, scan_id: str) -> ZAPScanStatus:
        """Get spider scan status
        
        Args:
            scan_id: Spider scan ID
            
        Returns:
            Scan status object
        """
        response = self._call_tool('get_spider_status', {'scanId': scan_id})
        progress = int(response['content'][0]['text'].split('Progress: ')[1].rstrip('%'))
        return ZAPScanStatus(scan_id, progress)
        
    def _get_scan_status(self, scan_id: str) -> ZAPScanStatus:
        """Get active scan status
        
        Args:
            scan_id: Active scan ID
            
        Returns:
            Scan status object
        """
        response = self._call_tool('get_scan_status', {'scanId': scan_id})
        progress = int(response['content'][0]['text'].split('Progress: ')[1].rstrip('%'))
        return ZAPScanStatus(scan_id, progress)
        
    def _wait_for_spider(self, scan_id: str, check_interval: int = 2) -> None:
        """Wait for spider scan to complete
        
        Args:
            scan_id: Spider scan ID
            check_interval: Seconds between status checks
        """
        while True:
            status = self._get_spider_status(scan_id)
            print(f"Spider scan progress: {status.progress}%")
            if status.is_complete:
                break
            time.sleep(check_interval)
            
    def _wait_for_scan(self, scan_id: str, check_interval: int = 5) -> None:
        """Wait for active scan to complete
        
        Args:
            scan_id: Active scan ID
            check_interval: Seconds between status checks
        """
        while True:
            status = self._get_scan_status(scan_id)
            print(f"Active scan progress: {status.progress}%")
            if status.is_complete:
                break
            time.sleep(check_interval)
            
    def _call_tool(self, tool_name: str, params: Dict[str, Any]) -> dict:
        """Call an MCP server tool
        
        Args:
            tool_name: Name of the tool to call
            params: Parameters for the tool
            
        Returns:
            Tool response
        """
        url = f"{self.mcp_server_url}/tools/{tool_name}"
        
        try:
            response = requests.post(url, json=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error calling {tool_name}: {str(e)}")
            
    def _validate_url(self, url: str) -> bool:
        """Validate URL format
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

def print_alerts(alerts: List[Alert], risk_level: Optional[RiskLevel] = None) -> None:
    """Pretty print alerts
    
    Args:
        alerts: List of alerts to print
        risk_level: Optional filter by risk level
    """
    filtered = [a for a in alerts if not risk_level or a.risk_level == risk_level]
    
    if not filtered:
        print("No alerts found")
        return
        
    print(f"\nFound {len(filtered)} alerts:")
    for alert in filtered:
        print(f"\n[{alert.risk}] {alert.name}")
        print("=" * (len(alert.name) + len(alert.risk) + 3))
        print(alert.description)
        if alert.url:
            print(f"URL: {alert.url}")
            
def main():
    """Example usage"""
    # Initialize scanner
    scanner = ZAPScanner('http://localhost:3001')  # Update port if needed
    
    # Configure ZAP
    scanner.configure(
        zap_url='http://localhost:8080',
        api_key='nb5dlof24g342c6fhs4giicpeo'
    )
    
    # Perform quick scan
    target = 'http://flipkart.com'  # Replace with your target
    alerts = scanner.quick_scan(target)
    
    # Print all alerts
    print_alerts(alerts)
    
    # Print only high risk alerts
    print("\nHigh Risk Alerts:")
    print_alerts(alerts, RiskLevel.HIGH)

if __name__ == '__main__':
    main() 