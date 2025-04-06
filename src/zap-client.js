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
            // Format URL correctly for ZAP API
            const url = `${this.apiUrl}/JSON/${endpoint}`;
            const requestParams = { ...params, apikey: this.apiKey };
            
            console.log(`Making request to: ${url} with params:`, requestParams);
            const response = await axios.get(url, { params: requestParams });
            console.log('ZAP Response:', response.data);
            
            return response.data;
        } catch (error) {
            console.error('ZAP API request failed:', error.message);
            if (error.response) {
                console.error('Error response:', error.response.data);
                throw new Error(`ZAP API error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
            }
            throw new Error(`ZAP API request failed: ${error.message}`);
        }
    }

    async startActiveScan(targetUrl) {
        console.log(`Starting active scan for ${targetUrl}`);
        const response = await this.request('ascan/action/scan', { url: targetUrl });
        const scanId = response.scan || '';
        console.log('Active scan started with ID:', scanId);
        return { scanId };
    }

    async getScanStatus(scanId) {
        console.log(`Getting status for scan ${scanId}`);
        const response = await this.request('ascan/view/status', { scanId });
        const status = parseInt(response.status || '0');
        console.log('Scan status:', status);
        return { status };
    }

    async spiderUrl(targetUrl) {
        console.log(`Starting spider for ${targetUrl}`);
        const response = await this.request('spider/action/scan', { url: targetUrl });
        const scanId = response.scan || '';
        console.log('Spider started with ID:', scanId);
        return { scanId };
    }

    async getSpiderStatus(scanId) {
        console.log(`Getting status for spider ${scanId}`);
        const response = await this.request('spider/view/status', { scanId });
        const status = parseInt(response.status || '0');
        console.log('Spider status:', status);
        return { status };
    }

    async getAlerts(targetUrl) {
        console.log(`Getting alerts for ${targetUrl}`);
        const response = await this.request('core/view/alerts', { baseurl: targetUrl });
        const alerts = response.alerts || [];
        console.log(`Found ${alerts.length} alerts`);
        return alerts.map(alert => ({
            risk: alert.risk,
            name: alert.name,
            description: alert.description,
            confidence: alert.confidence,
            url: alert.url
        }));
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
