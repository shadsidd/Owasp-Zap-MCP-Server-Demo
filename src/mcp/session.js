class MCPSession {
    constructor(id) {
        this.id = id;
        this.context = new Map();
        this.created = Date.now();
        this.lastAccessed = Date.now();
    }

    get(key) {
        this.lastAccessed = Date.now();
        return this.context.get(key);
    }

    set(key, value) {
        this.lastAccessed = Date.now();
        this.context.set(key, value);
    }

    getMetadata() {
        return {
            id: this.id,
            created: this.created,
            lastAccessed: this.lastAccessed,
            contextSize: this.context.size
        };
    }
}

class SessionManager {
    constructor(cleanupInterval = 3600000) { // 1 hour
        this.sessions = new Map();
        setInterval(() => this.cleanup(), cleanupInterval);
    }

    createSession() {
        const id = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const session = new MCPSession(id);
        this.sessions.set(id, session);
        return session;
    }

    getSession(id) {
        return this.sessions.get(id);
    }

    cleanup() {
        const now = Date.now();
        for (const [id, session] of this.sessions.entries()) {
            if (now - session.lastAccessed > 86400000) { // 24 hours
                this.sessions.delete(id);
            }
        }
    }
}

module.exports = { MCPSession, SessionManager }; 