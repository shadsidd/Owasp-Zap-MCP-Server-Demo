# OWASP ZAP MCP Server (v1)

> Security testing made simple. Get started in 5 minutes.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.7+-yellow)
![Node](https://img.shields.io/badge/node-14+-green)

## 🚀 5-Minute Quick Start

1. **Setup**
```bash
# Install dependencies
npm install
pip install -r requirements.txt

# Start server
npm start
# Server auto-selects port if 3000 is busy
# > MCP ZAP server running on port 3001
```

2. **Run Your First Scan**
```bash
# Test with a demo site
python test_scan.py http://testphp.vulnweb.com
```

That's it! You'll see results like:
```
🔍 Scanning http://testphp.vulnweb.com...
⚡ Spider Progress: [====================] 100%
🛡️ Scan Progress:  [====================] 100%

HIGH Risk Alerts:
- SQL Injection at /artists.php
- Cross Site Scripting at /search.php

MEDIUM Risk Alerts:
- Cookie No HttpOnly Flag
- X-Frame-Options Header Not Set
```

## 💡 Why Use This?

1. **Dead Simple API**
```python
from zap_client import ZAPScanner

# One line to scan
scanner = ZAPScanner('http://localhost:3001')
results = scanner.quick_scan('http://your-site.com')
```

2. **Real-time Progress**
```python
# With live updates
scanner.quick_scan('http://your-site.com', wait_for_complete=True)
# Spider: [======>              ] 35%
# Scan:   [============>        ] 65%
```

3. **CI/CD Ready**
```yaml
# In your GitHub Actions
steps:
  - name: Security Scan
    run: |
      python test_scan.py ${{ secrets.TARGET_URL }}
```

## 🛠️ Common Tasks

### Filter Alerts by Risk
```python
from zap_client import RiskLevel

# Show only high risks
scanner.print_alerts(alerts, RiskLevel.HIGH)

# Get medium and high risks
risks = [a for a in alerts 
         if a.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM)]
```

### WebSocket Updates
```python
async with ZAPWebSocketClient('ws://localhost:3001') as client:
    await client.start_scan('http://example.com')
    # Get live updates
```

### Health Check
```bash
curl http://localhost:3001/health
# Returns: {"status": "ok", "uptime": "1h 23m", "sessions": 2}
```

## 🎯 Test Sites

| Site | URL | Purpose |
|------|-----|---------|
| OWASP Juice Shop | `http://juice-shop:3000` | Modern vulnerabilities |
| Test PHP | `http://testphp.vulnweb.com` | Basic vulnerabilities |
| WebGoat | `http://localhost:8080/WebGoat` | Learning platform |

⚠️ **Note**: Only scan sites you have permission to test!

## 📊 Features vs Alternatives

What makes MCP Server special:

| Task | MCP Server | Raw ZAP API | ZAP UI |
|------|------------|-------------|---------|
| First Scan | `python test_scan.py url` | 15+ lines of code | 6+ clicks |
| CI/CD | One command | Custom script | Not possible |
| Updates | Real-time % | Polling needed | Manual check |
| Results | Structured data | Raw JSON | UI only |

## 🔧 Configuration

### Server Options
```bash
# In .env
PORT=3000
RATE_LIMIT=100  # requests per 15 min
ZAP_API_KEY=your-key
```

### Python Client Options
```python
scanner = ZAPScanner(
    url='http://localhost:3001',
    timeout=30,
    auto_retry=True
)
```

## 🚨 Troubleshooting

1. **Port in Use**
   ```bash
   Port 3000 is busy, trying port 3001...
   ```
   ✅ Server auto-selects next available port

2. **Connection Failed**
   ```python
   scanner.configure(
       zap_url='http://localhost:8080',  # Check ZAP is running
       api_key='your-key'                # Check key is correct
   )
   ```

3. **Scan Stuck**
   ```python
   # Use timeout
   scanner.quick_scan(url, timeout=300)  # 5 minutes
   ```

## 📚 Next Steps

1. Check [examples](/examples) for more use cases
2. Read [full docs](/docs) for advanced features
3. Join our [community](https://github.com/your-repo/discussions)

## 🤝 Contributing

1. Fork it
2. Create feature branch (`git checkout -b feature/xyz`)
3. Commit changes (`git commit -am 'Add XYZ'`)
4. Push (`git push origin feature/xyz`)
5. Create Pull Request

## 📮 Support

- 🐛 [Report Issues](https://github.com/your-repo/issues)
- 💡 [Request Features](https://github.com/your-repo/issues/new)
- 📖 [Read Docs](/docs)

## 📜 License

MIT License - do whatever you want, just don't blame us 😉 