"""
Example of real-time security scan monitoring with the MCP Server.
Demonstrates websocket-based live updates and alert notifications.
"""
import asyncio
import json
from datetime import datetime
import sys
import os

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient
import websockets

class SecurityMonitor:
    def __init__(self):
        self.client = MCPClient()
        self.active_scans = {}
        self.max_retries = 3
        self.retry_delay = 5  # seconds

    async def monitor_scan(self, scan_id: str):
        """Monitor a specific scan and process alerts in real-time."""
        retries = 0
        while retries < self.max_retries:
            try:
                async with self.client as client:
                    # Subscribe to real-time updates
                    async for message in client.subscribe_updates(scan_id):
                        if message['type'] == 'progress':
                            await self.handle_progress(scan_id, message)
                        elif message['type'] == 'alert':
                            await self.handle_alert(scan_id, message)
                        elif message['type'] == 'complete':
                            await self.handle_completion(scan_id, message)
                            return  # Successful completion
                        elif message['type'] == 'error':
                            print(f"Error in scan {scan_id}: {message['error']}")
                            if message.get('fatal', False):
                                return  # Fatal error, stop monitoring
            except websockets.exceptions.ConnectionClosed:
                print(f"Connection lost. Attempting to reconnect... (Attempt {retries + 1}/{self.max_retries})")
                await asyncio.sleep(self.retry_delay)
                try:
                    await self.client.reconnect()
                    retries += 1
                except Exception as e:
                    print(f"Reconnection failed: {e}")
                    retries += 1
            except Exception as e:
                print(f"Error monitoring scan {scan_id}: {e}")
                retries += 1
                await asyncio.sleep(self.retry_delay)

        print(f"Failed to monitor scan {scan_id} after {self.max_retries} attempts")

    async def handle_progress(self, scan_id: str, message: dict):
        """Process scan progress updates."""
        progress = message['progress']
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Scan {scan_id}: {progress}% complete")
        
        # Update scan status in memory
        self.active_scans[scan_id] = {
            'progress': progress,
            'last_update': timestamp
        }

    async def handle_alert(self, scan_id: str, message: dict):
        """Process new security alerts."""
        alert = message['alert']
        risk_level = alert['risk']
        
        # Format and display the alert
        print(f"\n🚨 New {risk_level} Risk Alert:")
        print(f"URL: {alert['url']}")
        print(f"Description: {alert['description']}")
        print(f"Solution: {alert['solution']}\n")
        
        # Trigger notifications for high-risk issues
        if risk_level.lower() == 'high':
            await self.notify_team(alert)

    async def handle_completion(self, scan_id: str, message: dict):
        """Process scan completion."""
        print(f"\n✅ Scan {scan_id} completed!")
        summary = message['summary']
        
        print("\nFinal Results:")
        print(json.dumps(summary, indent=2))
        
        # Cleanup
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]

    async def notify_team(self, alert: dict):
        """Simulate team notification for high-risk findings."""
        # In practice, this would integrate with your notification system
        print(f"🔔 Team notification sent for high-risk issue:")
        print(f"Priority: Immediate attention required")
        print(f"Issue: {alert['name']}")
        print(f"Impact: {alert['description']}")

    async def stop_scan(self, scan_id: str):
        """Stop a running scan."""
        try:
            async with self.client as client:
                await client.stop_scan(scan_id)
                print(f"Successfully stopped scan {scan_id}")
        except Exception as e:
            print(f"Failed to stop scan {scan_id}: {e}")

async def main():
    monitor = SecurityMonitor()
    
    # Example: Monitor multiple scans concurrently
    scan_ids = [
        "scan_staging_123",
        "scan_production_456"
    ]
    
    # Create monitoring tasks for each scan
    tasks = [monitor.monitor_scan(scan_id) for scan_id in scan_ids]
    
    # Run all monitoring tasks concurrently
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main()) 