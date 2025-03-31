import axios from 'axios';

    class ZapClient {
      constructor() {
        this.apiUrl = null;
        this.apiKey = null;
        this.isConfigured = false;
      }

      configure(apiUrl, apiKey) {
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.isConfigured = true;
        console.log(`ZAP API configured with endpoint: ${apiUrl}`);
      }

      checkConfiguration() {
        if (!this.isConfigured) {
          throw new Error('ZAP API not configured. Use the configure tool first.');
        }
      }

      async request(endpoint, params = {}) {
        this.checkConfiguration();
        
        try {
          // Add API key to all requests
          const requestParams = { ...params, apikey: this.apiKey };
          
          const response = await axios.get(`${this.apiUrl}/${endpoint}`, { 
            params: requestParams 
          });
          
          return response.data;
        } catch (error) {
          console.error('ZAP API request failed:', error.message);
          if (error.response) {
            throw new Error(`ZAP API error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
          }
          throw new Error(`ZAP API request failed: ${error.message}`);
        }
      }

      async startActiveScan(targetUrl, scanPolicyName, contextId) {
        console.log(`Starting active scan for ${targetUrl}`);
        
        const params = { url: targetUrl };
        if (scanPolicyName) params.scanPolicyName = scanPolicyName;
        if (contextId) params.contextId = contextId;
        
        const response = await this.request('ascan/action/scan', params);
        
        // Mock response for development
        if (!response || !this.apiUrl) {
          console.log('Using mock scan response');
          return { scanId: 'mock-scan-' + Date.now() };
        }
        
        return { scanId: response.scan };
      }

      async getScanStatus(scanId) {
        console.log(`Getting status for scan ${scanId}`);
        
        // Mock response for development
        if (!this.apiUrl || scanId.startsWith('mock-')) {
          console.log('Using mock scan status');
          return { 
            status: Math.floor(Math.random() * 100), 
            state: ['PENDING', 'RUNNING', 'FINISHED'][Math.floor(Math.random() * 3)] 
          };
        }
        
        const response = await this.request('ascan/view/status', { scanId });
        return { 
          status: parseInt(response.status), 
          state: parseInt(response.status) < 100 ? 'RUNNING' : 'FINISHED' 
        };
      }

      async getAlerts(targetUrl, riskLevel) {
        console.log(`Getting alerts for ${targetUrl}`);
        
        const params = { baseurl: targetUrl };
        if (riskLevel) params.riskLevel = riskLevel;
        
        // Mock response for development
        if (!this.apiUrl) {
          console.log('Using mock alerts');
          return [
            {
              id: '1',
              name: 'Cross Site Scripting (Reflected)',
              risk: 'High',
              confidence: 'Medium',
              description: 'Cross-site Scripting (XSS) is when an attacker can inject malicious code into a web page that is then executed in users\' browsers.'
            },
            {
              id: '2',
              name: 'SQL Injection',
              risk: 'High',
              confidence: 'Medium',
              description: 'SQL injection may be possible. This can allow an attacker to manipulate existing queries, execute new ones, or bypass authentication.'
            }
          ];
        }
        
        const response = await this.request('core/view/alerts', params);
        return response.alerts || [];
      }

      async spiderUrl(targetUrl, maxChildren, recurse) {
        console.log(`Starting spider for ${targetUrl}`);
        
        const params = { url: targetUrl };
        if (maxChildren !== undefined) params.maxChildren = maxChildren;
        if (recurse !== undefined) params.recurse = recurse;
        
        // Mock response for development
        if (!this.apiUrl) {
          console.log('Using mock spider response');
          return { scanId: 'mock-spider-' + Date.now() };
        }
        
        const response = await this.request('spider/action/scan', params);
        return { scanId: response.scan };
      }

      async getSpiderStatus(scanId) {
        console.log(`Getting status for spider ${scanId}`);
        
        // Mock response for development
        if (!this.apiUrl || scanId.startsWith('mock-')) {
          console.log('Using mock spider status');
          return { 
            status: Math.floor(Math.random() * 100), 
            state: ['PENDING', 'RUNNING', 'FINISHED'][Math.floor(Math.random() * 3)] 
          };
        }
        
        const response = await this.request('spider/view/status', { scanId });
        return { 
          status: parseInt(response.status), 
          state: parseInt(response.status) < 100 ? 'RUNNING' : 'FINISHED' 
        };
      }

      async generateReport(targetUrl, format) {
        console.log(`Generating ${format} report for ${targetUrl}`);
        
        // Mock response for development
        if (!this.apiUrl) {
          console.log('Using mock report');
          return { 
            summary: `Security report for ${targetUrl}\n\nHigh Risk Issues: 2\nMedium Risk Issues: 5\nLow Risk Issues: 10\n\nThis is a mock report summary.` 
          };
        }
        
        const formatMap = {
          'HTML': 'html',
          'XML': 'xml',
          'JSON': 'json',
          'MD': 'md'
        };
        
        const response = await this.request('reports/action/generate', { 
          title: `Security Report for ${targetUrl}`,
          template: formatMap[format],
          sites: targetUrl
        });
        
        return { 
          summary: `Report generated successfully. Saved to: ${response.reportPath || 'Unknown location'}` 
        };
      }
    }

    export const zapClient = new ZapClient();
