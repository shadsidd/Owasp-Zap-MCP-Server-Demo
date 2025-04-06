import requests
import time
import json
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse

class SimpleZapScanner:
    def __init__(self, mcp_server_url: str = 'http://localhost:3000', timeout: int = 30):
        """
        Simple scanner using OWASP ZAP MCP server
        
        Args:
            mcp_server_url: URL of the MCP server
            timeout: Request timeout in seconds
        """
        self.mcp_server_url = mcp_server_url.rstrip('/')
        self.timeout = timeout
        
    def _validate_url(self, url: str) -> bool:
        """Validate if a URL is properly formatted"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
            
    def _format_error_response(self, message: str) -> dict:
        """Format error response in a consistent way"""
        return {
            'content': [{'type': 'text', 'text': message}],
            'isError': True
        }

    def call_tool(self, tool_name: str, params: Dict[str, Any]) -> dict:
        """
        Call an MCP server tool
        
        Args:
            tool_name: Name of the tool to call
            params: Parameters for the tool
            
        Returns:
            dict: Response from the tool
        """
        if not tool_name or not isinstance(params, dict):
            return self._format_error_response("Invalid tool parameters")
            
        url = f"{self.mcp_server_url}/tools/{tool_name}"
        
        try:
            response = requests.post(url, json=params, timeout=self.timeout)
            response.raise_for_status()  # Raise exception for bad status codes
            response_data = response.json()
            
            # Validate response structure
            if not isinstance(response_data, dict):
                return self._format_error_response("Invalid response format from server")
                
            return response_data
            
        except requests.exceptions.Timeout:
            return self._format_error_response(f"Request to {tool_name} timed out")
        except requests.exceptions.RequestException as e:
            return self._format_error_response(f"HTTP Error: {str(e)}")
        except json.JSONDecodeError:
            return self._format_error_response("Invalid JSON response from server")
        except Exception as e:
            return self._format_error_response(f"Unexpected error: {str(e)}")

    def scan_website(self, target_url: str, zap_url: str, api_key: str) -> dict:
        """
        Scan a website using OWASP ZAP
        
        Args:
            target_url: URL to scan
            zap_url: URL of the ZAP instance
            api_key: ZAP API key
            
        Returns:
            dict: Scan results or error information
        """
        # Validate input URLs
        if not all(self._validate_url(url) for url in [target_url, zap_url]):
            return self._format_error_response("Invalid URL format provided")
            
        if not api_key or not isinstance(api_key, str):
            return self._format_error_response("Invalid API key")

        try:
            # 1. Configure ZAP connection
            print("Configuring ZAP connection...")
            config = self.call_tool('configure', {
                'apiUrl': zap_url,
                'apiKey': api_key
            })
            if config.get('isError', False):
                return config

            # 2. Start spider scan
            print(f"Starting spider scan of {target_url}")
            spider_result = self.call_tool('spider_url', {
                'targetUrl': target_url
            })
            
            if spider_result.get('isError', False):
                return spider_result
            
            # Safely extract spider ID with error handling
            try:
                spider_text = spider_result.get('content', [{}])[0].get('text', '')
                spider_id = re.search(r'Scan ID: (\d+)', spider_text)
                if not spider_id:
                    return self._format_error_response("Failed to extract spider scan ID")
                spider_id = spider_id.group(1)
            except (IndexError, AttributeError):
                return self._format_error_response('Failed to get spider scan ID from response')
            
            # 3. Monitor spider progress
            while True:
                status = self.call_tool('get_spider_status', {'scanId': spider_id})
                if status.get('isError', False):
                    return status
                    
                try:
                    status_text = status.get('content', [{}])[0].get('text', '0%')
                    progress_match = re.search(r'Progress: (\d+)%', status_text)
                    if not progress_match:
                        return self._format_error_response("Failed to parse spider progress")
                    progress = int(progress_match.group(1))
                except (IndexError, ValueError, AttributeError):
                    return self._format_error_response('Failed to parse spider progress')
                    
                print(f"Spider progress: {progress}%")
                if progress >= 100:
                    break
                time.sleep(2)

            # 4. Start active scan
            print(f"Starting active scan of {target_url}")
            scan_result = self.call_tool('start_scan', {
                'targetUrl': target_url
            })
            
            if scan_result.get('isError', False):
                return scan_result
            
            # Safely extract scan ID with error handling
            try:
                scan_text = scan_result.get('content', [{}])[0].get('text', '')
                scan_id = re.search(r'Scan ID: (\d+)', scan_text)
                if not scan_id:
                    return self._format_error_response("Failed to extract active scan ID")
                scan_id = scan_id.group(1)
            except (IndexError, AttributeError):
                return self._format_error_response('Failed to get active scan ID from response')
            
            # 5. Monitor scan progress
            while True:
                status = self.call_tool('get_scan_status', {'scanId': scan_id})
                if status.get('isError', False):
                    return status
                    
                try:
                    status_text = status.get('content', [{}])[0].get('text', '0%')
                    progress_match = re.search(r'Progress: (\d+)%', status_text)
                    if not progress_match:
                        return self._format_error_response("Failed to parse scan progress")
                    progress = int(progress_match.group(1))
                except (IndexError, ValueError, AttributeError):
                    return self._format_error_response('Failed to parse scan progress')
                    
                print(f"Scan progress: {progress}%")
                if progress >= 100:
                    break
                time.sleep(5)

            # 6. Get alerts
            print("Getting security alerts...")
            alerts = self.call_tool('get_alerts', {'targetUrl': target_url})
            if alerts.get('isError', False):
                return alerts
                
            # Validate alerts response
            if not isinstance(alerts.get('content'), list):
                return self._format_error_response('Invalid alerts response format')
                
            return alerts

        except Exception as e:
            return self._format_error_response(f'Error during scan: {str(e)}')

if __name__ == "__main__":
    # Configuration
    MCP_SERVER = 'http://localhost:3000'
    ZAP_URL = 'http://localhost:8080'
    ZAP_API_KEY = 'nb5dlof24g342c6fhs4giicpeo'
    TARGET_URL = 'http://zomato.com'  # Replace with your target URL
    
    # Create scanner and run scan
    scanner = SimpleZapScanner(MCP_SERVER)
    results = scanner.scan_website(TARGET_URL, ZAP_URL, ZAP_API_KEY)
    
    # Print results in a nice format
    if results.get('isError', False):
        print("Error:", results['content'][0]['text'])
    else:
        print("\nScan Results:")
        print(json.dumps(results, indent=2)) 