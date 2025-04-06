class MCPTool {
    constructor(name, description, params = {}) {
        this.name = name;
        this.description = description;
        this.params = params;
        this.nextTools = new Map(); // For tool chaining
    }

    // MCP standard response formatter with streaming support
    formatResponse(content, isError = false, isStream = false) {
        return {
            content: Array.isArray(content) ? content : [{ type: 'text', text: content }],
            isError,
            isStream,
            toolName: this.name,
            timestamp: Date.now()
        };
    }

    // MCP standard error formatter
    formatError(message) {
        return this.formatResponse(message, true);
    }

    // MCP tool discovery metadata with dependencies
    getMetadata() {
        return {
            name: this.name,
            description: this.description,
            parameters: this.params,
            version: '1.0.0',
            dependencies: Array.from(this.nextTools.keys()),
            supportsStreaming: this.supportsStreaming || false
        };
    }

    // Chain this tool with another
    chain(tool, condition = null) {
        this.nextTools.set(tool.name, { tool, condition });
        return tool;
    }

    // Execute tool with context and chaining
    async execute(params, context = {}) {
        if (!this.validateParams(params)) {
            throw new Error('Invalid parameters');
        }

        // Execute current tool
        const result = await this._execute(params, context);

        // Check for chained tools
        for (const [_, { tool, condition }] of this.nextTools) {
            if (!condition || condition(result)) {
                const chainedResult = await tool.execute(params, {
                    ...context,
                    previousResult: result
                });
                result.chainedResults = result.chainedResults || [];
                result.chainedResults.push(chainedResult);
            }
        }

        return result;
    }

    // Validate required parameters
    validateParams(params) {
        for (const [key, config] of Object.entries(this.params)) {
            if (config.required && !params[key]) {
                return false;
            }
        }
        return true;
    }

    // Abstract method for tool execution
    async _execute(params, context) {
        throw new Error('Tool _execute method must be implemented');
    }
}

module.exports = MCPTool; 