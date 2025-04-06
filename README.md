# OWASP MCP Server

A WebSocket-based Mission Control Protocol (MCP) server for OWASP ZAP security scanning, enabling real-time control and monitoring of security assessments.

## Prerequisites

- Python 3.8+
- OWASP ZAP 2.12.0+
- Java Runtime Environment (JRE) 8+
- Sudo/Administrator privileges (required for ZAP)

## Why MCP Server?

| Feature | MCP Server | ZAP UI | ZAP API |
|---------|------------|---------|---------|
| Automation | ✅ Full | ❌ Limited | ✅ Basic |
| Real-time Updates | ✅ WebSocket | ✅ Visual | ❌ Polling |
| CI/CD Integration | ✅ Native | ❌ Manual | ✅ Complex |
| Batch Processing | ✅ Yes | ❌ No | ✅ Limited |
| Learning Curve | 🟡 Medium | 🟢 Easy | 🔴 Hard |
| Progress Tracking | ✅ Real-time | ✅ Visual | ❌ Manual |
| Multiple Domains | ✅ Concurrent | ❌ Sequential | 🟡 Limited |
| Error Handling | ✅ Robust | ✅ Basic | ❌ Manual |

## Core Components

- `mcp_server.py` - The engine that powers everything. Start this first - it's your security scanning powerhouse that connects to OWASP ZAP.

- `mcp_client.py` - The brains behind the operation. A powerful SDK that other components use to talk to the server (you won't use this directly).

- `mcp_cli.py` - Your go-to command line tool for scanning. Think of it as your Swiss Army knife for security scanning - simple to use, yet powerful.

- `test_client.py` - A learning tool that shows you the ropes. Perfect for understanding how everything works or testing your setup.

## Quick Start

1. **Install OWASP ZAP**:
   Download from https://www.zaproxy.org/download/

2. **Setup Project**:
   ```bash
   git clone https://github.com/yourusername/owasp-mcp-server
   cd owasp-mcp-server
   python -m venv venv
   source venv/bin/activate  # Windows: .\venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Start ZAP** (requires sudo/admin privileges):
   ```bash
   # macOS/Linux
   sudo /Applications/ZAP.app/Contents/Java/zap.sh -daemon -port 8080
   
   # Windows (as Administrator)
   "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -daemon -port 8080
   ```

4. **Start MCP Server**:
   ```bash
   python mcp_server.py
   ```

5. **Use the CLI**:
   ```bash
   # Quick spider scan (passive)
   python mcp_cli.py scan example.com

   # Full active scan (comprehensive)
   python mcp_cli.py fullscan example.com

   # Specific scan type with HTML report
   python mcp_cli.py scan --scan-type=active --output=html example.com

   # Multiple domains scan
   python mcp_cli.py scan domain1.com domain2.com

   # Scan from file
   python mcp_cli.py scan -f domains.txt
   ```

## Example Files

The `examples/` directory contains scripts demonstrating key features:

### Security Scanning
- `basic_scan.py` - Core scanning with error handling
- `authenticated_scan.py` - Form-based and other authentication methods
- `scan_domains.py` - Concurrent scanning of multiple domains
- `custom_scan_policy.py` - Custom rules and thresholds

### Integration & Monitoring
- `ci_cd_integration.py` - CI/CD pipeline integration
- `real_time_monitor.py` - Live progress and alert monitoring
- `team_notifications.py` - Email, Slack, and Teams notifications
- `custom_rules.py` - Specialized security rules



## Important Notes

1. **Sudo Requirements**: 
   - OWASP ZAP requires sudo/administrator privileges to run
   - You will be prompted for your password when starting ZAP

2. **Port Configuration**:
   - ZAP uses port 8080 by default
   - MCP Server uses port 3000
   - Ensure these ports are not in use before starting

3. **Common Issues**:
   - If you see "Address already in use" error:
     ```bash
     # Check what's using port 8080
     sudo lsof -i :8080
     # Kill the process if needed
     sudo kill -9 <PID>
     ```
   - If ZAP fails to start, try:
     ```bash
     # Clear any existing ZAP processes
     pkill -f zap
     ```


## Scan Types

The MCP Server supports multiple scan types:

- **Spider Scan** (Default): Crawls the website to discover content, fastest but finds fewer issues
- **Active Scan**: Performs security testing with actual attacks, finds more vulnerabilities
- **Full Scan**: Comprehensive scanning (spider + active), provides the most thorough results
