import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
    import { z } from 'zod';
    import { zapClient } from './zap-client.js';

    // Create an MCP server for ZAP testing
    const server = new McpServer({
      name: "OWASP ZAP Testing",
      version: "1.0.0",
      description: "MCP server for OWASP ZAP security testing automation"
    });

    // Add documentation resource
    server.resource(
      "documentation",
      new ResourceTemplate("zap://docs", { list: undefined }),
      async (uri) => {
        return {
          contents: [{
            uri: uri.href,
            text: `# OWASP ZAP MCP Server

            This MCP server provides tools to interact with the OWASP ZAP (Zed Attack Proxy) API for security testing.

            ## Configuration
            
            Before using the tools, configure the ZAP API endpoint and API key using the \`configure\` tool.

            ## Available Tools

            - \`configure\`: Set up the ZAP API endpoint and API key
            - \`start_scan\`: Start a new active scan against a target URL
            - \`get_scan_status\`: Check the status of a running scan
            - \`get_alerts\`: Retrieve security alerts for a target
            - \`spider_url\`: Crawl a website using ZAP's spider
            - \`get_spider_status\`: Check the status of a spider scan
            - \`generate_report\`: Generate a security report in HTML format
            `
          }]
        };
      }
    );

    // Configure ZAP API endpoint and key
    server.tool(
      "configure",
      {
        apiUrl: z.string().url().describe("ZAP API endpoint URL (e.g., http://localhost:8080)"),
        apiKey: z.string().describe("ZAP API key for authentication")
      },
      async ({ apiUrl, apiKey }) => {
        try {
          zapClient.configure(apiUrl, apiKey);
          return {
            content: [{ 
              type: "text", 
              text: `ZAP API configured successfully with endpoint: ${apiUrl}` 
            }]
          };
        } catch (error) {
          return {
            content: [{ type: "text", text: `Error configuring ZAP API: ${error.message}` }],
            isError: true
          };
        }
      },
      { description: "Configure the ZAP API endpoint and API key" }
    );

    // Start an active scan
    server.tool(
      "start_scan",
      {
        targetUrl: z.string().url().describe("Target URL to scan"),
        scanPolicyName: z.string().optional().describe("Name of the scan policy to use"),
        contextId: z.string().optional().describe("Context identifier to use for the scan")
      },
      async ({ targetUrl, scanPolicyName, contextId }) => {
        try {
          const result = await zapClient.startActiveScan(targetUrl, scanPolicyName, contextId);
          return {
            content: [{ 
              type: "text", 
              text: `Active scan started successfully.\nScan ID: ${result.scanId}` 
            }]
          };
        } catch (error) {
          return {
            content: [{ type: "text", text: `Error starting scan: ${error.message}` }],
            isError: true
          };
        }
      },
      { description: "Start a new active scan against a target URL" }
    );

    // Get scan status
    server.tool(
      "get_scan_status",
      {
        scanId: z.string().describe("ID of the scan to check")
      },
      async ({ scanId }) => {
        try {
          const status = await zapClient.getScanStatus(scanId);
          return {
            content: [{ 
              type: "text", 
              text: `Scan Status:\nProgress: ${status.status}%\nState: ${status.state}` 
            }]
          };
        } catch (error) {
          return {
            content: [{ type: "text", text: `Error getting scan status: ${error.message}` }],
            isError: true
          };
        }
      },
      { description: "Check the status of a running scan" }
    );

    // Get alerts for a target
    server.tool(
      "get_alerts",
      {
        targetUrl: z.string().url().describe("Target URL to get alerts for"),
        riskLevel: z.enum(["High", "Medium", "Low", "Informational"]).optional().describe("Filter alerts by risk level")
      },
      async ({ targetUrl, riskLevel }) => {
        try {
          const alerts = await zapClient.getAlerts(targetUrl, riskLevel);
          
          if (alerts.length === 0) {
            return {
              content: [{ type: "text", text: `No alerts found for ${targetUrl}` }]
            };
          }
          
          const alertSummary = alerts.map(alert => 
            `- [${alert.risk}] ${alert.name}: ${alert.description.substring(0, 100)}...`
          ).join('\n');
          
          return {
            content: [{ 
              type: "text", 
              text: `Found ${alerts.length} alerts for ${targetUrl}:\n\n${alertSummary}` 
            }]
          };
        } catch (error) {
          return {
            content: [{ type: "text", text: `Error getting alerts: ${error.message}` }],
            isError: true
          };
        }
      },
      { description: "Retrieve security alerts for a target" }
    );

    // Spider a URL
    server.tool(
      "spider_url",
      {
        targetUrl: z.string().url().describe("Target URL to spider"),
        maxChildren: z.number().optional().describe("Maximum number of child nodes to crawl"),
        recurse: z.boolean().optional().describe("Whether to recursively crawl the site")
      },
      async ({ targetUrl, maxChildren, recurse }) => {
        try {
          const result = await zapClient.spiderUrl(targetUrl, maxChildren, recurse);
          return {
            content: [{ 
              type: "text", 
              text: `Spider scan started successfully.\nScan ID: ${result.scanId}` 
            }]
          };
        } catch (error) {
          return {
            content: [{ type: "text", text: `Error starting spider: ${error.message}` }],
            isError: true
          };
        }
      },
      { description: "Crawl a website using ZAP's spider" }
    );

    // Get spider status
    server.tool(
      "get_spider_status",
      {
        scanId: z.string().describe("ID of the spider scan to check")
      },
      async ({ scanId }) => {
        try {
          const status = await zapClient.getSpiderStatus(scanId);
          return {
            content: [{ 
              type: "text", 
              text: `Spider Status:\nProgress: ${status.status}%\nState: ${status.state}` 
            }]
          };
        } catch (error) {
          return {
            content: [{ type: "text", text: `Error getting spider status: ${error.message}` }],
            isError: true
          };
        }
      },
      { description: "Check the status of a spider scan" }
    );

    // Generate report
    server.tool(
      "generate_report",
      {
        targetUrl: z.string().url().describe("Target URL for the report"),
        reportFormat: z.enum(["HTML", "XML", "JSON", "MD"]).default("HTML").describe("Format of the report")
      },
      async ({ targetUrl, reportFormat }) => {
        try {
          const report = await zapClient.generateReport(targetUrl, reportFormat);
          return {
            content: [{ 
              type: "text", 
              text: `Report generated successfully in ${reportFormat} format.\n\nReport Summary:\n${report.summary}` 
            }]
          };
        } catch (error) {
          return {
            content: [{ type: "text", text: `Error generating report: ${error.message}` }],
            isError: true
          };
        }
      },
      { description: "Generate a security report" }
    );

    export { server };
