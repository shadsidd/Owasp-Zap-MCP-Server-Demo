"""
MCP Client Library - Provides a high-level interface for interacting with the MCP Server.
"""
import asyncio
import json
import websockets
import socket
import os
import logging
from typing import AsyncGenerator, Dict, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('MCP-Client')

class MCPClient:
    def __init__(self, host: str = "localhost", port: int = 3000):
        self.host = host
        self.base_port = port  # Default port if can't read from file
        self.current_port = None
        self.websocket = None
        self.message_id = 0
        self.session_id = None

    async def get_server_port(self) -> int:
        """Get the actual port where MCP server is running."""
        port_file = ".mcp_server_port"
        
        # Try to read port from file first
        if os.path.exists(port_file):
            try:
                with open(port_file, "r") as f:
                    port = int(f.read().strip())
                    logger.info(f"Found server port {port} from config file")
                    return port
            except (ValueError, IOError) as e:
                logger.warning(f"Failed to read port from {port_file}: {e}")
        
        # Fall back to the default port
        logger.info(f"Using default port {self.base_port}")
        return self.base_port

    async def connect(self):
        """Establish WebSocket connection to MCP Server."""
        try:
            # Get the server port
            self.current_port = await self.get_server_port()
            self.uri = f"ws://{self.host}:{self.current_port}"
            logger.info(f"Connecting to MCP server on {self.uri}")
            
            # Connect to the server
            self.websocket = await websockets.connect(self.uri)
            
            # Get connection acknowledgment
            response = await self.websocket.recv()
            data = json.loads(response)
            
            if data.get('type') == 'connection' and data.get('status') == 'success':
                self.session_id = data['data']['session_id']
                logger.info(f"Connected to MCP Server on port {self.current_port}")
            else:
                raise ConnectionError(f"Failed to establish session with MCP Server: {data}")
        except Exception as e:
            logger.error(f"Failed to connect to MCP Server: {str(e)}")
            raise ConnectionError(f"Failed to connect to MCP Server: {str(e)}")

    async def _send_command(self, command: str, params: Optional[Dict] = None) -> Dict:
        """Send command to MCP Server and await response."""
        if not self.websocket:
            raise ConnectionError("Not connected to MCP Server")

        try:
            self.message_id += 1
            message = {
                "id": self.message_id,
                "command": command,
                "params": params or {}
            }

            logger.debug(f"Sending message: {json.dumps(message)}")
            await self.websocket.send(json.dumps(message))
            response = await self.websocket.recv()
            data = json.loads(response)
            logger.debug(f"Received response: {json.dumps(data)}")
            return data
        except Exception as e:
            logger.error(f"Error sending command {command}: {str(e)}")
            raise

    async def start_scan(self, target_url: str, scan_type: str = "spider") -> str:
        """Start a new security scan and return scan ID."""
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'

        try:
            # Use the format that the server expects in process_message -> start_scan
            response = await self._send_command("start_scan", {
                "config": {
                    "target_url": target_url,
                    "scan_type": scan_type
                }
            })
            
            if response.get("status") == "success" and "data" in response:
                scan_id = response["data"].get("scan_id")
                if not scan_id:
                    raise ValueError("No scan ID in response")
                return scan_id
            raise Exception(response.get('message', 'Unknown error'))
        except Exception as e:
            logger.error(f"Failed to start scan: {str(e)}")
            raise Exception(f"Failed to start scan: {str(e)}")

    async def get_status(self, scan_id: str) -> Dict:
        """Get current status of a scan."""
        try:
            response = await self._send_command("get_status", {"scan_id": scan_id})
            
            if response.get("status") == "success" and "data" in response:
                data = response["data"]
                return {
                    "progress": int(data.get("progress", 0)),
                    "is_complete": int(data.get("progress", 0)) >= 100,
                    "context": data.get("context", {})
                }
            raise Exception(response.get('message', 'Unknown error'))
        except Exception as e:
            logger.error(f"Failed to get scan status: {str(e)}")
            raise

    async def get_alerts(self, scan_id: str) -> list:
        """Get alerts from a completed scan."""
        try:
            response = await self._send_command("get_alerts", {"scan_id": scan_id})
            
            if response.get("status") == "success" and "data" in response:
                return response["data"].get("alerts", [])
            raise Exception(response.get('message', 'Unknown error'))
        except Exception as e:
            logger.error(f"Failed to get alerts: {str(e)}")
            raise

    async def disconnect(self):
        """Close WebSocket connection."""
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception as e:
                logger.error(f"Error closing connection: {str(e)}")
            finally:
                self.websocket = None
                self.session_id = None
                self.current_port = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()

    async def subscribe_updates(self, scan_id: str) -> AsyncGenerator[Dict, None]:
        """Subscribe to real-time updates for a scan."""
        await self._send_command("subscribe", {"scan_id": scan_id})
        
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)
                
                if data.get("type") == "complete":
                    yield data
                    break
                
                yield data
        except websockets.exceptions.ConnectionClosed:
            print("Connection to MCP Server closed")
        except Exception as e:
            print(f"Error in update subscription: {e}")
        finally:
            await self._send_command("unsubscribe", {"scan_id": scan_id})

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running security scan."""
        response = await self._send_command("stop_scan", {"scan_id": scan_id})
        
        if response.get("status") == "success":
            return True
        raise Exception(f"Failed to stop scan: {response.get('error')}")

    async def reconnect(self) -> None:
        """Attempt to reconnect to the MCP Server."""
        try:
            if self.websocket:
                await self.websocket.close()
            await self.connect()
        except Exception as e:
            raise ConnectionError(f"Failed to reconnect to MCP Server: {e}")

    async def full_scan(self, target_url: str) -> str:
        """Perform a full scan (spider + active scan) like ZAP UI would do."""
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'
            
        logger.info(f"Starting full scan of {target_url}")
        
        # First, run a spider scan to discover content
        spider_scan_id = await self.start_scan(target_url, "spider")
        logger.info(f"Spider scan started with ID {spider_scan_id}")
        
        # Wait for spider to complete
        while True:
            status = await self.get_status(spider_scan_id)
            if status.get("is_complete", False):
                logger.info("Spider scan completed")
                break
            await asyncio.sleep(2)
            
        # Now start an active scan 
        active_scan_id = await self.start_scan(target_url, "active")
        logger.info(f"Active scan started with ID {active_scan_id}")
        
        return active_scan_id  # Return the active scan ID for tracking 