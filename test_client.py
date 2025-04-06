import asyncio
import websockets
import json
import time

async def test_scan():
    uri = "ws://localhost:3000"
    async with websockets.connect(uri) as websocket:
        # Wait for connection acknowledgment
        response = await websocket.recv()
        print("Connected:", json.loads(response))
        
        # Start a scan
        scan_request = {
            "command": "start_scan",
            "config": {
                "target_url": "http://example.com",
                "scan_type": "spider"
            }
        }
        
        await websocket.send(json.dumps(scan_request))
        response = await websocket.recv()
        print("\nScan started:", json.loads(response))
        
        # Monitor scan progress
        while True:
            status_request = {
                "command": "get_status"
            }
            await websocket.send(json.dumps(status_request))
            response = json.loads(await websocket.recv())
            print(f"\rProgress: {response['data']['progress']}%", end="")
            
            if int(response['data']['progress']) >= 100:
                break
            await asyncio.sleep(1)
        
        # Get alerts
        alerts_request = {
            "command": "get_alerts"
        }
        await websocket.send(json.dumps(alerts_request))
        alerts = json.loads(await websocket.recv())
        print("\n\nAlerts:", json.dumps(alerts, indent=2))

if __name__ == "__main__":
    asyncio.run(test_scan()) 