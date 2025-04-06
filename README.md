# MCP OWASP ZAP Server

A Model Context Protocol (MCP) server for OWASP ZAP with bidirectional communication support.

## Why OWASP ZAP MCP Server better than ZAP API vs UI

### 1. Setup & Configuration

| Aspect | ZAP MCP Server | ZAP API | ZAP UI |
|--------|---------------|---------|---------|
| Installation Requirements | Node.js + Python + ZAP | ZAP only | ZAP only |
| Initial Setup Time | ~10 minutes | ~5 minutes | ~2 minutes |
| Configuration Method | Code-based (version controlled) | Script-based | GUI-based |
| Port Configuration | Auto-selects available port | Manual configuration | Fixed (8080) |

### 2. Ease of Use

| Aspect | ZAP MCP Server | ZAP API | ZAP UI |
|--------|---------------|---------|---------|
| Learning Curve | Moderate (Python basics) | Steep (API knowledge) | Gentle (GUI-based) |
| Time to First Scan | 5 minutes | 15+ minutes | 2 minutes |
| Documentation | Structured examples | API reference | Tutorial-based |
| Error Messages | Clear Python exceptions | Raw HTTP errors | Visual feedback |

### 3. Automation Capabilities

| Aspect | ZAP MCP Server | ZAP API | ZAP UI |
|--------|---------------|---------|---------|
| CI/CD Integration | ✅ Simple Python script | ⚠️ Complex custom code | ❌ Not possible |
| Batch Scanning | ✅ Built-in support | ⚠️ Manual implementation | ❌ One at a time |
| Scheduled Scans | ✅ Cron/scheduler ready | ⚠️ Requires setup | ❌ Manual only |
| Custom Workflows | ✅ Python automation | ✅ Full flexibility | ❌ UI workflow only |

### 4. Scanning Features

| Feature | ZAP MCP Server | ZAP API | ZAP UI |
|---------|---------------|---------|---------|
| Spider Scan | ```scanner.quick_scan(url)``` | Complex API calls | Click-based |
| Active Scan | Automated with spider | Separate API calls | Manual steps |
| Progress Tracking | Real-time with % | Raw numbers | Visual progress |
| Concurrent Scans | Single queue | Multiple possible | Single instance |

### 5. Results & Reporting

| Feature | ZAP MCP Server | ZAP API | ZAP UI |
|---------|---------------|---------|---------|
| Result Format | Python objects | Raw JSON | UI display |
| Filtering | ```alerts.filter(risk=HIGH)``` | Manual JSON parsing | UI filters |
| Export Options | Custom formats | Manual processing | Built-in formats |
| Storage | Database/Files/Custom | Custom implementation | Local files |

### 6. Team Collaboration

| Aspect | ZAP MCP Server | ZAP API | ZAP UI |
|--------|---------------|---------|---------|
| Sharing Configs | Git-versioned code | Script files | Manual export |
| Reproducibility | ✅ Code-based | ⚠️ Script-dependent | ❌ Manual steps |
| Knowledge Transfer | Documentation + Code | API docs | Screenshots |
| Multi-user Support | Git-based collaboration | Shared scripts | Single user |

### 7. Current Limitations

| Aspect | ZAP MCP Server | ZAP API | ZAP UI |
|--------|---------------|---------|---------|
| Feature Coverage | Basic scanning only | Full API access | All features |
| UI Availability | CLI/Code only | None | Full GUI |
| Scan Concurrency | Sequential | Parallel possible | Single instance |
| Custom Rules | Not supported yet | Fully supported | Configurable |

### Quick Feature Comparison

✅ Fully Supported | ⚠️ Possible with Work | ❌ Not Supported

| Feature | MCP Server | API | UI |
|---------|------------|-----|-----|
| Automated Scanning | ✅ | ⚠️ | ❌ |
| CI/CD Integration | ✅ | ⚠️ | ❌ |
| Progress Monitoring | ✅ | ⚠️ | ✅ |
| Custom Reports | ✅ | ⚠️ | ✅ |
| Version Control | ✅ | ⚠️ | ❌ |
| Team Collaboration | ✅ | ⚠️ | ❌ |
| Learning Curve | ⚠️ | ❌ | ✅ |
| Advanced Features | ❌ | ✅ | ✅ |

## Features

- ✅ Full MCP Protocol Support
- ✅ Real-time Bidirectional Communication
- ✅ Tool Chaining
- ✅ Session Management
- ✅ Progress Streaming
- ✅ Automatic Port Selection
- ✅ Rate Limiting
- ✅ Health Monitoring

## Prerequisites

- Node.js >= 14.x
- Python >= 3.7 (for client)
- OWASP ZAP running locally or remotely

## Quick Start

1. **Install Dependencies**:
```bash
npm install
pip install -r requirements.txt
```

2. **Start the Server**:
```bash
npm start
```
The server will automatically find an available port if 3000 is busy.

3. **Use the WebSocket Client**:
```bash
python examples/ws_client.py
```

## WebSocket API

Connect to `ws://localhost:3001` (or your server port)

### Messages

The included `test_scan.py` script provides an easy way to test the scanner:

```bash
# Test with default target (example.com)
python test_scan.py

# Test with a specific target
python test_scan.py http://your-target-url.com

# Test with a deliberately vulnerable application
python test_scan.py http://testphp.vulnweb.com
```

The test script will:
- Run a complete scan (spider + active scan)
- Show progress in real-time
- Group and display alerts by risk level
- Handle errors gracefully

### 2. Using the Python Client Directly

```python
from zap_client import ZAPScanner, print_alerts, RiskLevel

# Initialize scanner
scanner = ZAPScanner('http://localhost:3001')

# Configure ZAP
scanner.configure(
    zap_url='http://localhost:8080',
    api_key='your-zap-api-key'
)

# Test Options:

# Option 1: Quick scan with default settings
alerts = scanner.quick_scan('http://example.com')
print_alerts(alerts)

# Option 2: Filter alerts by risk level
print("\nHigh Risk Alerts Only:")
print_alerts(alerts, RiskLevel.HIGH)

# Option 3: Get alerts as objects for custom processing
high_risk_alerts = [a for a in alerts if a.risk_level == RiskLevel.HIGH]
for alert in high_risk_alerts:
    print(f"Alert: {alert.name}")
    print(f"Risk: {alert.risk}")
    print(f"Description: {alert.description}")
```

### 3. Testing Different Types of Applications

Here are some recommended targets for testing:

1. **Public Test Sites**:
   - OWASP Juice Shop: `http://juice-shop:3000` (if running locally)
   - Test PHP Site: `http://testphp.vulnweb.com`
   - WebGoat: `http://localhost:8080/WebGoat` (if running locally)

2. **Local Development**:
   - Your local development server
   - Docker containers
   - Test environments

3. **Safe Public Sites**:
   - `http://example.com`
   - Your own domains (with permission)

⚠️ **Important Security Notes**:
- Always ensure you have permission to scan the target
- Never scan websites without authorization
- Use test/vulnerable applications for learning
- Be cautious with active scanning in production

## Using the Python Client

The easiest way to use the MCP ZAP server is through the provided Python client:

```python
from zap_client import ZAPScanner, print_alerts, RiskLevel

# Initialize scanner (adjust port if needed)
scanner = ZAPScanner('http://localhost:3001')

# Configure ZAP
scanner.configure(
    zap_url='http://localhost:8080',
    api_key='your-zap-api-key'
)

# Perform quick scan
target = 'http://example.com'  # Replace with your target
alerts = scanner.quick_scan(target)

# Print all alerts
print_alerts(alerts)

# Print only high risk alerts
print_alerts(alerts, RiskLevel.HIGH)
```

### Features of the Python Client

1. **Quick Scan**: One-line command to:
   - Run spider scan
   - Run active scan
   - Get alerts
   ```python
   alerts = scanner.quick_scan('http://example.com')
   ```

2. **Risk Level Filtering**:
   ```python
   from zap_client import RiskLevel
   
   # Get only high risk alerts
   high_risk = [a for a in alerts if a.risk_level == RiskLevel.HIGH]
   ```

3. **Pretty Printing**:
   ```python
   from zap_client import print_alerts
   
   # Print all alerts
   print_alerts(alerts)
   
   # Print only medium risk alerts
   print_alerts(alerts, RiskLevel.MEDIUM)
   ```

4. **Progress Monitoring**:
   ```python
   # Scan with progress updates
   alerts = scanner.quick_scan('http://example.com', wait_for_complete=True)
   ```

## Direct API Access

While the Python client is recommended, you can also interact with the server directly via HTTP:

### Configuration
```bash
curl -X POST http://localhost:3001/tools/configure \
  -H "Content-Type: application/json" \
  -d '{
    "apiUrl": "http://localhost:8080",
    "apiKey": "your-zap-api-key"
  }'
```

### Available Endpoints

- POST `/tools/spider_url` - Start spider scan
- POST `/tools/start_scan` - Start active scan
- POST `/tools/get_spider_status` - Check spider progress
- POST `/tools/get_scan_status` - Check scan progress
- POST `/tools/get_alerts` - Get security alerts
- GET `/health` - Check server health

## Rate Limiting

The server includes rate limiting to prevent abuse:
- 100 requests per IP address per 15 minutes
- Configurable through environment variables:
  ```bash
  RATE_LIMIT_WINDOW_MS=900000 # 15 minutes
  RATE_LIMIT_MAX_REQUESTS=100
  ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
