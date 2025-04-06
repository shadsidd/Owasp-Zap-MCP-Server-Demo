#!/usr/bin/env node
const express = require('express');
const rateLimit = require('express-rate-limit');
const EventEmitter = require('events');
const WebSocket = require('ws');
const http = require('http');
const MCPTool = require('./mcp/tool');
const ZAPTool = require('./mcp/tools/zap-tool');
const { SessionManager } = require('./mcp/session');

class MCPServer extends EventEmitter {
    constructor() {
        super();
        this.app = express();
        this.server = http.createServer(this.app);
        this.wss = new WebSocket.Server({ server: this.server });
        this.tools = new Map();
        this.sessionManager = new SessionManager();
        this.clients = new Map(); // WebSocket clients
        this.setupMiddleware();
        this.setupRoutes();
        this.setupWebSocket();
    }

    setupMiddleware() {
        this.app.use(express.json());
        this.app.use(rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 100
        }));
    }

    setupRoutes() {
        // MCP protocol routes
        this.app.get('/mcp/discover', (req, res) => {
            const tools = Array.from(this.tools.values()).map(tool => tool.getMetadata());
            res.json({ tools });
        });

        // Session management
        this.app.post('/mcp/session', (req, res) => {
            const session = this.sessionManager.createSession();
            res.json(session.getMetadata());
        });

        // Tool execution endpoint with streaming support
        this.app.post('/tools/:toolName', async (req, res) => {
            const { toolName } = req.params;
            const { sessionId } = req.headers;
            const tool = this.tools.get(toolName);
            
            if (!tool) {
                return res.status(404).json({ 
                    content: [{ type: 'text', text: `Tool ${toolName} not found` }],
                    isError: true 
                });
            }

            // Get or create session
            const session = sessionId ? 
                this.sessionManager.getSession(sessionId) : 
                this.sessionManager.createSession();

            // Setup streaming if requested
            const useStream = req.headers['accept'] === 'text/event-stream';
            if (useStream) {
                res.setHeader('Content-Type', 'text/event-stream');
                res.setHeader('Cache-Control', 'no-cache');
                res.setHeader('Connection', 'keep-alive');
            }

            try {
                const context = {
                    session,
                    stream: useStream ? res : null,
                    previousResults: session.get('previousResults') || []
                };

                const result = await tool.execute(req.body, context);
                
                // Store result in session
                context.previousResults.push({
                    tool: toolName,
                    result,
                    timestamp: Date.now()
                });
                session.set('previousResults', context.previousResults);

                // Emit event
                this.emit('toolExecuted', { 
                    tool: toolName, 
                    params: req.body, 
                    result,
                    sessionId: session.id 
                });

                // Send response
                if (!useStream) {
                    res.json(result);
                } else {
                    res.write('data: ' + JSON.stringify({ complete: true }) + '\n\n');
                    res.end();
                }
            } catch (error) {
                const errorResponse = tool.formatError(error.message);
                if (!useStream) {
                    res.status(500).json(errorResponse);
                } else {
                    res.write('data: ' + JSON.stringify(errorResponse) + '\n\n');
                    res.end();
                }
            }
        });

        // Health check
        this.app.get('/health', (req, res) => {
            res.json({ 
                status: 'ok', 
                uptime: process.uptime(),
                sessions: this.sessionManager.sessions.size,
                tools: this.tools.size
            });
        });
    }

    setupWebSocket() {
        this.wss.on('connection', (ws, req) => {
            const sessionId = req.url.split('session=')[1];
            const session = sessionId ? 
                this.sessionManager.getSession(sessionId) : 
                this.sessionManager.createSession();

            // Store client connection
            this.clients.set(ws, {
                session,
                activeTool: null
            });

            console.log(`WebSocket client connected. Session: ${session.id}`);

            // Handle incoming messages
            ws.on('message', async (message) => {
                try {
                    const data = JSON.parse(message);
                    await this.handleWebSocketMessage(ws, data);
                } catch (error) {
                    this.sendWSError(ws, error.message);
                }
            });

            // Handle client disconnect
            ws.on('close', () => {
                const client = this.clients.get(ws);
                if (client?.activeTool) {
                    // Cleanup any active tool execution
                    this.emit('toolCancelled', {
                        sessionId: client.session.id,
                        tool: client.activeTool
                    });
                }
                this.clients.delete(ws);
                console.log(`WebSocket client disconnected. Session: ${session.id}`);
            });

            // Send initial session info
            ws.send(JSON.stringify({
                type: 'session',
                sessionId: session.id,
                tools: Array.from(this.tools.values()).map(tool => tool.getMetadata())
            }));
        });

        // Listen for tool events and broadcast to relevant clients
        this.on('toolExecuted', (data) => {
            this.broadcastToSession(data.sessionId, {
                type: 'toolComplete',
                ...data
            });
        });

        this.on('toolProgress', (data) => {
            this.broadcastToSession(data.sessionId, {
                type: 'progress',
                ...data
            });
        });

        this.on('toolError', (data) => {
            this.broadcastToSession(data.sessionId, {
                type: 'error',
                ...data
            });
        });
    }

    async handleWebSocketMessage(ws, message) {
        const client = this.clients.get(ws);
        const { type, toolName, params } = message;

        switch (type) {
            case 'executeTool':
                const tool = this.tools.get(toolName);
                if (!tool) {
                    return this.sendWSError(ws, `Tool ${toolName} not found`);
                }

                client.activeTool = toolName;
                
                try {
                    const context = {
                        session: client.session,
                        ws,
                        onProgress: (progress) => {
                            ws.send(JSON.stringify({
                                type: 'progress',
                                tool: toolName,
                                progress
                            }));
                        }
                    };

                    const result = await tool.execute(params, context);
                    
                    ws.send(JSON.stringify({
                        type: 'result',
                        tool: toolName,
                        result
                    }));

                    client.activeTool = null;
                } catch (error) {
                    this.sendWSError(ws, error.message);
                    client.activeTool = null;
                }
                break;

            case 'cancelTool':
                if (client.activeTool) {
                    this.emit('toolCancelled', {
                        sessionId: client.session.id,
                        tool: client.activeTool
                    });
                    client.activeTool = null;
                    ws.send(JSON.stringify({
                        type: 'cancelled',
                        tool: toolName
                    }));
                }
                break;

            default:
                this.sendWSError(ws, `Unknown message type: ${type}`);
        }
    }

    sendWSError(ws, message) {
        ws.send(JSON.stringify({
            type: 'error',
            message
        }));
    }

    broadcastToSession(sessionId, data) {
        for (const [ws, client] of this.clients.entries()) {
            if (client.session.id === sessionId) {
                ws.send(JSON.stringify(data));
            }
        }
    }

    registerTool(tool) {
        if (!(tool instanceof MCPTool)) {
            throw new Error('Tool must extend MCPTool');
        }
        this.tools.set(tool.name, tool);
        this.emit('toolRegistered', tool.getMetadata());
    }

    async start(port = 3000) {
        while (true) {
            try {
                await new Promise((resolve, reject) => {
                    this.server.listen(port, () => {
                        console.log(`MCP server running on port ${port}`);
                        console.log(`WebSocket server running on ws://localhost:${port}`);
                        resolve();
                    }).on('error', (err) => {
                        if (err.code === 'EADDRINUSE') {
                            console.log(`Port ${port} is busy, trying port ${port + 1}...`);
                            port++;
                            reject(err);
                        } else {
                            reject(err);
                        }
                    });
                });
                break;
            } catch (err) {
                if (err.code !== 'EADDRINUSE') throw err;
            }
        }
    }
}

// Initialize server
const server = new MCPServer();

// Register ZAP tools with chaining
const zapClient = require('./zap-client');

// Configure tool
const configureTool = new ZAPTool('configure', 'Configure ZAP connection', {
    apiUrl: { type: 'string', required: true },
    apiKey: { type: 'string', required: true }
}, zapClient);

// Spider tool
const spiderTool = new ZAPTool('spider_url', 'Spider a target URL', {
    targetUrl: { type: 'string', required: true }
}, zapClient);

// Active scan tool
const scanTool = new ZAPTool('start_scan', 'Start active scan', {
    targetUrl: { type: 'string', required: true }
}, zapClient);

// Alerts tool
const alertsTool = new ZAPTool('get_alerts', 'Get security alerts', {
    targetUrl: { type: 'string', required: true }
}, zapClient);

// Chain tools for automatic workflow
configureTool
    .chain(spiderTool)
    .chain(scanTool)
    .chain(alertsTool);

// Register all tools
server.registerTool(configureTool);
server.registerTool(spiderTool);
server.registerTool(scanTool);
server.registerTool(alertsTool);

// Start server
server.start(3000);

// Export for testing
module.exports = server;
