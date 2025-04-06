#!/usr/bin/env python3
import websockets
import asyncio
import json
import sys

class MCPWebSocketClient:
    def __init__(self, url='ws://localhost:3001', session_id=None):
        self.url = url
        self.session_id = session_id
        self.ws = None
        self.active = False

    async def connect(self):
        """Connect to MCP server"""
        url = f"{self.url}{'?session=' + self.session_id if self.session_id else ''}"
        self.ws = await websockets.connect(url)
        self.active = True
        
        # Get initial session info
        response = await self.ws.recv()
        session_data = json.loads(response)
        self.session_id = session_data['sessionId']
        print(f"Connected to MCP server. Session: {self.session_id}")
        print("\nAvailable tools:")
        for tool in session_data['tools']:
            print(f"- {tool['name']}: {tool['description']}")

    async def execute_tool(self, tool_name, params):
        """Execute a tool and handle real-time updates"""
        if not self.ws:
            raise Exception("Not connected to server")

        # Send tool execution request
        await self.ws.send(json.dumps({
            'type': 'executeTool',
            'toolName': tool_name,
            'params': params
        }))

        # Handle responses until tool completion
        while self.active:
            response = await self.ws.recv()
            data = json.loads(response)
            
            if data['type'] == 'progress':
                print(f"\rProgress: {data['progress']}%", end='')
            elif data['type'] == 'result':
                print("\nTool execution completed:")
                print(json.dumps(data['result'], indent=2))
                break
            elif data['type'] == 'error':
                print(f"\nError: {data['message']}")
                break

    async def cancel_tool(self, tool_name):
        """Cancel a running tool"""
        if not self.ws:
            raise Exception("Not connected to server")

        await self.ws.send(json.dumps({
            'type': 'cancelTool',
            'toolName': tool_name
        }))

    async def close(self):
        """Close the connection"""
        if self.ws:
            self.active = False
            await self.ws.close()

async def main():
    # Create client
    client = MCPWebSocketClient('ws://localhost:3001')
    
    try:
        # Connect to server
        await client.connect()

        # Example: Configure ZAP
        print("\nConfiguring ZAP...")
        await client.execute_tool('configure', {
            'apiUrl': 'http://localhost:8080',
            'apiKey': 'your-api-key-here'
        })

        # Example: Run a scan
        print("\nStarting scan...")
        await client.execute_tool('spider_url', {
            'targetUrl': 'http://example.com'
        })

        # Example: Get alerts
        print("\nGetting alerts...")
        await client.execute_tool('get_alerts', {
            'targetUrl': 'http://example.com'
        })

    except KeyboardInterrupt:
        print("\nCancelling...")
        if client.ws:
            await client.cancel_tool('spider_url')
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        await client.close()

if __name__ == '__main__':
    asyncio.run(main()) 