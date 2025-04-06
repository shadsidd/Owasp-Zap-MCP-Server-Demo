"""
Example of performing authenticated scans with MCP Server.
Demonstrates how to configure authentication and maintain session during scanning.
"""
import asyncio
import sys
import os
from typing import Dict, Optional

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient

class AuthenticatedScanner:
    def __init__(self):
        self.client = MCPClient()
        
    async def configure_auth(self, login_url: str, username: str, password: str,
                           auth_method: str = 'form') -> Dict:
        """
        Configure authentication settings.
        
        Args:
            login_url: URL of the login page
            username: Username for authentication
            password: Password for authentication
            auth_method: Authentication method ('form', 'basic', 'digest', 'ntlm')
        """
        auth_config = {
            'login_url': login_url,
            'method': auth_method,
            'credentials': {
                'username': username,
                'password': password
            },
            'verification': {
                'logged_in_indicator': 'Logout',  # String indicating successful login
                'logged_out_indicator': 'Login'   # String indicating logged out state
            }
        }
        
        if auth_method == 'form':
            # Add form-specific configuration
            auth_config.update({
                'form_target_url': login_url,
                'form_fields': {
                    'username_field': 'username',
                    'password_field': 'password',
                    'submit_field': 'submit'
                }
            })
            
        return auth_config

    async def verify_auth(self, auth_config: Dict) -> bool:
        """Verify authentication configuration works."""
        try:
            async with self.client as client:
                # Test authentication
                result = await client.test_authentication(auth_config)
                return result.get('success', False)
        except Exception as e:
            print(f"Authentication verification failed: {e}")
            return False

    async def scan_authenticated(self, target_url: str, auth_config: Dict,
                               scan_logged_out: bool = True):
        """
        Perform authenticated scan of target URL.
        
        Args:
            target_url: URL to scan
            auth_config: Authentication configuration
            scan_logged_out: Whether to also scan unauthenticated state
        """
        try:
            async with self.client as client:
                print(f"\nStarting authenticated scan of {target_url}")
                print("=" * 50)
                
                # Configure authenticated context
                context_id = await client.create_context("Auth Context")
                await client.set_context_auth(context_id, auth_config)
                
                # Start authenticated scan
                scan_id = await client.start_scan(
                    target_url,
                    context_id=context_id,
                    scan_logged_out=scan_logged_out
                )
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
                
                # Separate authenticated and unauthenticated findings
                auth_findings = []
                unauth_findings = []
                
                for alert in alerts:
                    if alert.get('authenticated', False):
                        auth_findings.append(alert)
                    else:
                        unauth_findings.append(alert)
                
                # Print summary
                print("\nScan Complete!")
                print("=" * 50)
                print(f"Authenticated findings: {len(auth_findings)}")
                print(f"Unauthenticated findings: {len(unauth_findings)}")
                
                # Print detailed findings
                print("\nAuthenticated Findings:")
                for finding in auth_findings:
                    print(f"\n🚨 {finding['risk']} Risk: {finding['name']}")
                    print(f"   URL: {finding['url']}")
                    print(f"   Description: {finding['description']}")
                
                if scan_logged_out:
                    print("\nUnauthenticated Findings:")
                    for finding in unauth_findings:
                        print(f"\n🚨 {finding['risk']} Risk: {finding['name']}")
                        print(f"   URL: {finding['url']}")
                        print(f"   Description: {finding['description']}")
                
        except Exception as e:
            print(f"Error during scan: {e}")
            sys.exit(1)

async def main():
    scanner = AuthenticatedScanner()
    
    # Configure authentication
    auth_config = await scanner.configure_auth(
        login_url="https://example.com/login",
        username="test_user",
        password="test_password",
        auth_method="form"
    )
    
    # Verify authentication works
    if await scanner.verify_auth(auth_config):
        # Run authenticated scan
        await scanner.scan_authenticated(
            target_url="https://example.com",
            auth_config=auth_config,
            scan_logged_out=True
        )
    else:
        print("Authentication verification failed!")

if __name__ == "__main__":
    asyncio.run(main()) 