# MCP Server Integration Examples

This directory contains example implementations showing different ways to integrate with the OWASP MCP Server.

## Available Examples

### 1. CI/CD Pipeline Integration (`ci_cd_integration.py`)
Demonstrates how to integrate security scanning into your CI/CD pipeline:
```python
from ci_cd_integration import SecurityGate

async def security_gate_check():
    gate = SecurityGate(risk_threshold={
        'high': 0,    # Block on any high risks
        'medium': 2   # Allow up to 2 medium risks
    })
    
    results = await gate.scan_deployment("https://staging.example.com")
    if not results['passed']:
        print("Security checks failed!")
        sys.exit(1)
```

### 2. Real-Time Security Monitoring (`real_time_monitor.py`)
Shows how to monitor multiple scans in real-time:
```python
from real_time_monitor import SecurityMonitor

async def monitor_multiple_scans():
    monitor = SecurityMonitor()
    scan_ids = ["scan_prod_123", "scan_staging_456"]
    await monitor.monitor_scans(scan_ids)
```

### 3. Batch Scanning (`batch_scanner.py`)
Example of scanning multiple domains in batch:
```python
from batch_scanner import BatchScanner

domains = ["example.com", "test.com", "demo.com"]
scanner = BatchScanner()
results = await scanner.scan_domains(domains)
```

### 4. Custom Scan Policies (`custom_policies.py`)
Shows how to use custom scanning policies:
```python
from custom_policies import PolicyScanner

scanner = PolicyScanner()
policy = {
    'strength': 'high',
    'threshold': 'medium',
    'rules': {
        'sql-injection': 'enable',
        'xss': 'enable',
        'csrf': 'disable'
    }
}
scan_id = await scanner.scan_with_policy("https://example.com", policy)
```

### 5. Client Library (`mcp_client.py`)
The base client library used by other examples:
```python
from mcp_client import MCPClient

async with MCPClient() as client:
    scan_id = await client.start_scan("https://example.com")
    alerts = await client.get_alerts(scan_id)
```

## WebSocket API Reference

### Commands

1. **Start Scan**
```json
{
    "command": "start_scan",
    "config": {
        "target_url": "https://example.com",
        "scan_type": "active|spider",
        "policy": {}
    }
}
```

2. **Get Status**
```json
{
    "command": "get_status",
    "scan_id": "scan_123"
}
```

3. **Get Alerts**
```json
{
    "command": "get_alerts",
    "scan_id": "scan_123"
}
```

4. **Stop Scan**
```json
{
    "command": "stop_scan",
    "scan_id": "scan_123"
}
```

### Real-time Updates

The server sends real-time updates in this format:
```json
{
    "type": "scan_update",
    "scan_id": "scan_123",
    "data": {
        "progress": 45,
        "alerts": [],
        "status": "running"
    }
}
``` 