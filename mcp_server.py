import asyncio
import websockets
import json
import logging
from zapv2 import ZAPv2
import time
from urllib.parse import urljoin
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('MCP-ZAP-Server')

# Server Configuration
SERVER_CONFIG = {
    'host': 'localhost',
    'port': 3000,
    'zap_host': 'localhost',
    'zap_port': 8080,
    'zap_api_key': 'mcp-zap-12345',  # Fixed API key that matches ZAP's configuration
    'debug': True
}

class MCPServer:
    def __init__(self, host=None, port=None):
        self.host = host or SERVER_CONFIG['host']
        self.port = port or SERVER_CONFIG['port']
        self.zap = None
        self.active_sessions = {}
        self.server = None

    def find_available_port(self, start_port=3000, max_port=3100):
        """Find an available port starting from start_port up to max_port."""
        for port in range(start_port, max_port + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind((self.host, port))
                    return port
                except OSError:
                    continue
        raise OSError(f"No available ports found between {start_port} and {max_port}")

    async def initialize_zap(self):
        """Initialize ZAP connection with retries."""
        try:
            # Initialize ZAP API client with direct configuration
            self.zap = ZAPv2(
                apikey=SERVER_CONFIG['zap_api_key'],
                proxies=None
            )
            
            # Set the correct API URL format
            self.zap._ZAPv2__base = f'http://{SERVER_CONFIG["zap_host"]}:{SERVER_CONFIG["zap_port"]}'
            
            # Wait for ZAP to be ready
            for _ in range(10):
                try:
                    version = self.zap.core.version
                    logger.info(f"Connected to ZAP version {version}")
                    return True
                except Exception as e:
                    logger.warning(f"Waiting for ZAP to be ready... ({str(e)})")
                    await asyncio.sleep(1)
            
            logger.error("ZAP API not available after 10 seconds")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize ZAP: {str(e)}")
            return False

    async def handle_client(self, websocket):
        """Handle WebSocket client connection."""
        try:
            # Generate session ID and send connection acknowledgment
            session_id = f"session_{int(time.time())}"
            self.active_sessions[session_id] = {
                'websocket': websocket,
                'context': None
            }
            
            await websocket.send(json.dumps({
                'type': 'connection',
                'status': 'success',
                'data': {'session_id': session_id}
            }))

            async for message in websocket:
                try:
                    data = json.loads(message)
                    response = await self.process_message(session_id, data)
                    await websocket.send(json.dumps(response))
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'status': 'error',
                        'message': 'Invalid JSON format'
                    }))
                except Exception as e:
                    logger.error(f"Error processing message: {str(e)}")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'status': 'error',
                        'message': str(e)
                    }))

        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client disconnected: {session_id}")
        finally:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]

    async def process_message(self, session_id, message):
        """Process incoming WebSocket messages."""
        try:
            command = message.get('command')
            params = message.get('params', {})
            
            if command == 'ping':
                return {'type': 'pong', 'status': 'success'}
                
            elif command == 'start_scan':
                config = params.get('config', {})
                if not config:
                    # Backward compatibility with the old format
                    config = params
                return await self.start_scan(session_id, config)
                
            elif command == 'get_status':
                scan_id = params.get('scan_id')
                return await self.get_scan_status(session_id, scan_id)
                
            elif command == 'stop_scan':
                scan_id = params.get('scan_id')
                return await self.stop_scan(session_id, scan_id)
                
            elif command == 'get_alerts':
                scan_id = params.get('scan_id')
                return await self.get_scan_alerts(session_id, scan_id)
                
            else:
                return {
                    'type': 'error',
                    'status': 'error',
                    'message': f'Unknown command: {command}'
                }
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")
            return {
                'type': 'error',
                'status': 'error',
                'message': str(e)
            }

    async def start_scan(self, session_id, params):
        """Start a new scan."""
        try:
            target_url = params.get('target_url')
            if not target_url:
                raise ValueError("target_url is required")

            scan_type = params.get('scan_type', 'spider')
            
            # Create new context
            context_name = f"ctx_{session_id}"
            context_id = self.zap.context.new_context(context_name)
            
            # Include target URL in context
            self.zap.context.include_in_context(context_name, f".*{target_url}.*")
            
            # Start scan based on type
            if scan_type == 'spider':
                # Configure more aggressive spider settings like ZAP UI
                self.zap.spider.set_option_max_depth(5)  # Increase from default 5
                self.zap.spider.set_option_thread_count(10)  # More threads for faster scanning
                scan_id = self.zap.spider.scan(target_url, contextname=context_name)
                logger.info(f"Spider scan started for {target_url} with ID {scan_id}")
            elif scan_type == 'active':
                # Configure more comprehensive active scan like ZAP UI
                self.zap.ascan.set_option_thread_per_host(10)  # More threads
                self.zap.ascan.set_option_host_per_scan(2)  # Scan multiple hosts
                
                # Enable all scan policies for thorough scanning
                scan_policy = 'Default Policy'
                for policy in self.zap.ascan.scan_policy_names:
                    if 'Default Policy' in policy:
                        scan_policy = policy
                        break
                
                # Set attack strength and alert threshold to match ZAP UI
                self.zap.ascan.set_scanner_attack_strength(id=0, attackstrength='HIGH')
                self.zap.ascan.set_scanner_alert_threshold(id=0, alertthreshold='MEDIUM')
                
                # Start the active scan with full configuration
                # Note: ZAP API changed parameter names, using correct ones
                scan_id = self.zap.ascan.scan(
                    url=target_url, 
                    contextid=context_id,
                    scanpolicyname=scan_policy,
                    recurse=True
                )
                logger.info(f"Active scan started for {target_url} with ID {scan_id}")
            else:  # fallback
                scan_id = self.zap.spider.scan(target_url, contextname=context_name)
                logger.info(f"Fallback spider scan started for {target_url} with ID {scan_id}")
            
            # Store context info
            self.active_sessions[session_id]['context'] = {
                'id': context_id,
                'name': context_name,
                'scan_id': scan_id,
                'scan_type': scan_type,
                'status': 'running',
                'target_url': target_url
            }
            
            return {
                'type': 'scan_started',
                'status': 'success',
                'data': {
                    'scan_id': scan_id,
                    'context_id': context_id
                }
            }
            
        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}")
            return {
                'type': 'error',
                'status': 'error',
                'message': str(e)
            }

    async def get_scan_status(self, session_id, scan_id=None):
        """Get scan status."""
        try:
            context = self.active_sessions[session_id]['context']
            if not context:
                return {
                    'type': 'scan_status',
                    'status': 'error',
                    'message': 'No active scan'
                }

            scan_id = scan_id or context['scan_id']
            scan_type = context['scan_type']
            
            if scan_type == 'spider':
                progress = self.zap.spider.status(scan_id)
            else:
                progress = self.zap.ascan.status(scan_id)
            
            return {
                'type': 'scan_status',
                'status': 'success',
                'data': {
                    'progress': int(progress),
                    'context': context
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return {
                'type': 'error',
                'status': 'error',
                'message': str(e)
            }

    async def stop_scan(self, session_id, scan_id=None):
        """Stop an active scan."""
        try:
            context = self.active_sessions[session_id]['context']
            if not context:
                return {
                    'type': 'error',
                    'status': 'error',
                    'message': 'No active scan to stop'
                }

            scan_id = scan_id or context['scan_id']
            scan_type = context['scan_type']
            
            if scan_type == 'spider':
                self.zap.spider.stop(scan_id)
            else:
                self.zap.ascan.stop(scan_id)
            
            context['status'] = 'stopped'
            
            return {
                'type': 'scan_stopped',
                'status': 'success'
            }
            
        except Exception as e:
            logger.error(f"Error stopping scan: {str(e)}")
            return {
                'type': 'error',
                'status': 'error',
                'message': str(e)
            }

    async def get_scan_alerts(self, session_id, scan_id=None):
        """Get alerts from the scan."""
        try:
            context = self.active_sessions[session_id]['context']
            if not context:
                return {
                    'type': 'error',
                    'status': 'error',
                    'message': 'No scan context found'
                }

            scan_id = scan_id or context['scan_id']
            alerts = self.zap.core.alerts()
            return {
                'type': 'alerts',
                'status': 'success',
                'data': {
                    'alerts': alerts,
                    'total': len(alerts)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting alerts: {str(e)}")
            return {
                'type': 'error',
                'status': 'error',
                'message': str(e)
            }

    async def start(self):
        """Start the WebSocket server."""
        if not await self.initialize_zap():
            raise Exception("Failed to initialize ZAP")
            
        while True:
            try:
                self.server = await websockets.serve(
                    self.handle_client,
                    self.host,
                    self.port,
                    ping_interval=None  # Disable automatic ping to handle it manually
                )
                
                # Save the port to a file for clients to read
                with open(".mcp_server_port", "w") as f:
                    f.write(str(self.port))
                    
                logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
                await self.server.wait_closed()
                break
            except OSError as e:
                if e.errno == 48:  # Address already in use
                    try:
                        self.port = self.find_available_port(self.port + 1)
                        logger.info(f"Port {self.port - 1} in use, trying port {self.port}")
                    except OSError as port_error:
                        logger.error(f"Failed to find available port: {str(port_error)}")
                        raise
                else:
                    logger.error(f"Failed to start server: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Failed to start server: {str(e)}")
                raise

if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.start())