const MCPTool = require('../tool');

class ZAPTool extends MCPTool {
    constructor(name, description, params = {}, zapClient) {
        super(name, description, params);
        this.zapClient = zapClient;
        this.supportsStreaming = true; // Enable streaming for progress updates
    }

    // Override to add ZAP-specific metadata
    getMetadata() {
        return {
            ...super.getMetadata(),
            category: 'security',
            provider: 'owasp-zap',
            contextRequired: ['zapConfig']
        };
    }

    // Helper for ZAP API calls with streaming support
    async callZAP(method, params = {}, context = {}, onProgress = null) {
        try {
            // If streaming is supported and progress callback provided
            if (this.supportsStreaming && onProgress) {
                const result = await this.zapClient[method]({
                    ...params,
                    onProgress: (progress) => {
                        onProgress(this.formatResponse(
                            `Progress: ${progress}%`,
                            false,
                            true
                        ));
                    }
                });
                return this.formatResponse(result);
            }

            // Regular non-streaming call
            const result = await this.zapClient[method](params);
            return this.formatResponse(result);
        } catch (error) {
            return this.formatError(error.message);
        }
    }

    // Override execute to handle streaming
    async _execute(params, context) {
        return new Promise((resolve, reject) => {
            const streamHandler = context.stream ? 
                (data) => context.stream.write(JSON.stringify(data) + '\n') : 
                null;

            this.callZAP(this.name, params, context, streamHandler)
                .then(resolve)
                .catch(reject);
        });
    }
}

module.exports = ZAPTool; 