import requests
import time
import json
from typing import Dict, Any

class SimpleZapScanner:
    def __init__(self, mcp_server_url: str = 'http://localhost:3000'):
        """Simple scanner using OWASP ZAP MCP server"""
        self.mcp_server_url = mcp_server_url.rstrip('/')
        
    def wait_for_server(self, max_retries: int = 5, delay: int = 2) -> bool:
        """Wait for MCP server to be ready"""
        for i in range(max_retries):
            try:
                response = requests.get(f"{self.mcp_server_url}/health")
                if response.status_code == 200:
                    return True
            except requests.exceptions.ConnectionError:
                print(f"Waiting for MCP server to start (attempt {i+1}/{max_retries})...")
                time.sleep(delay)
        return False
        
    def call_tool(self, tool_name: str, params: Dict[str, Any]) -> dict:
        """Call an MCP server tool with retry logic"""
        max_retries = 3
        for i in range(max_retries):
            try:
                url = f"{self.mcp_server_url}/tools/{tool_name}"
                response = requests.post(url, json=params, timeout=10)
                return response.json()
            except requests.exceptions.ConnectionError as e:
                if i == max_retries - 1:
                    raise Exception(f"Failed to connect to MCP server: {str(e)}")
                print(f"Retrying connection ({i+1}/{max_retries})...")
                time.sleep(2)

    def verify_zap_connection(self, zap_url: str, api_key: str) -> bool:
        """Verify ZAP is accessible"""
        try:
            response = requests.get(
                f"{zap_url}/JSON/core/view/version/",
                params={'apikey': api_key},
                verify=False,
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

    def scan_website(self, target_url: str, zap_url: str, api_key: str) -> dict:
        """Scan a website using OWASP ZAP"""
        try:
            # Wait for MCP server
            if not self.wait_for_server():
                return {
                    'content': [{'type': 'text', 'text': 'MCP server is not available'}],
                    'isError': True
                }

            # Verify ZAP connection
            if not self.verify_zap_connection(zap_url, api_key):
                return {
                    'content': [{'type': 'text', 'text': 'Cannot connect to ZAP. Please ensure ZAP is running.'}],
                    'isError': True
                }

            # Configure ZAP
            print("Configuring ZAP connection...")
            config = self.call_tool('configure', {
                'apiUrl': zap_url,
                'apiKey': api_key
            })
            if 'isError' in config:
                return config

            # Start spider scan
            print(f"Starting spider scan of {target_url}")
            spider_result = self.call_tool('spider_url', {
                'targetUrl': target_url
            })
            
            if 'isError' in spider_result:
                return spider_result
            
            spider_id = spider_result['content'][0]['text'].split('Scan ID: ')[1]
            
            # Monitor spider progress
            while True:
                status = self.call_tool('get_spider_status', {'scanId': spider_id})
                progress = int(status['content'][0]['text'].split('Progress: ')[1].split('%')[0])
                print(f"Spider progress: {progress}%")
                if progress >= 100:
                    break
                time.sleep(2)

            # Start active scan
            print(f"Starting active scan of {target_url}")
            scan_result = self.call_tool('start_scan', {
                'targetUrl': target_url
            })
            
            if 'isError' in scan_result:
                return scan_result
            
            scan_id = scan_result['content'][0]['text'].split('Scan ID: ')[1]
            
            # Monitor scan progress
            while True:
                status = self.call_tool('get_scan_status', {'scanId': scan_id})
                progress = int(status['content'][0]['text'].split('Progress: ')[1].split('%')[0])
                print(f"Scan progress: {progress}%")
                if progress >= 100:
                    break
                time.sleep(5)

            # Get alerts
            print("Getting security alerts...")
            return self.call_tool('get_alerts', {'targetUrl': target_url})

        except Exception as e:
            return {
                'content': [{'type': 'text', 'text': f'Error during scan: {str(e)}'}],
                'isError': True
            }

def main():
    # Configuration
    MCP_SERVER = 'http://localhost:3000'
    ZAP_URL = 'http://localhost:8080'
    ZAP_API_KEY = 'nb5dlof24g342c6fhs4giicpeo'
    TARGET_URL = 'http://example.com'  # Replace with your target URL
    
    # Create scanner
    scanner = SimpleZapScanner(MCP_SERVER)
    
    try:
        # Run scan
        results = scanner.scan_website(TARGET_URL, ZAP_URL, ZAP_API_KEY)
        
        # Print results
        if 'isError' in results:
            print("Error:", results['content'][0]['text'])
        else:
            print("\nScan Results:")
            print(json.dumps(results, indent=2))
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()