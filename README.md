# OWASP ZAP MCP Server

    This MCP server provides tools to interact with the OWASP ZAP (Zed Attack Proxy) API for security testing.

    ## Features

    - Configure ZAP API endpoint and authentication
    - Start active scans against target URLs
    - Monitor scan progress
    - Retrieve security alerts
    - Spider websites
    - Generate security reports

    ## Getting Started

    1. Install dependencies:
       ```
       npm install
       ```

    2. Run the server:
       ```
       npm run dev
       ```

    3. Test with MCP Inspector:
       ```
       npm run inspect
       ```

    ## Usage with ZAP

    1. Start ZAP with API enabled (typically on http://localhost:8080)
    2. Configure the MCP server with your ZAP API endpoint and API key
    3. Use the provided tools to interact with ZAP

    ## Available Tools

    - `configure`: Set up the ZAP API endpoint and API key
    - `start_scan`: Start a new active scan against a target URL
    - `get_scan_status`: Check the status of a running scan
    - `get_alerts`: Retrieve security alerts for a target
    - `spider_url`: Crawl a website using ZAP's spider
    - `get_spider_status`: Check the status of a spider scan
    - `generate_report`: Generate a security report in HTML format

    ## Development Notes

    The server includes mock responses for development and testing without a running ZAP instance.
