#!/usr/bin/env node
/**
 * AHP WebSocket Server (TypeScript)
 *
 * A WebSocket-based AHP harness server with bidirectional streaming support.
 *
 * Features:
 * - Persistent connections with low latency
 * - Concurrent client support
 * - Ping/Pong heartbeat
 * - Batch processing
 * - Depth-aware policy enforcement
 *
 * Usage:
 *   npm install ws
 *   npx ts-node examples/websocket_server.ts
 */

import WebSocket from 'ws';
import { createServer } from 'http';

// AHP Protocol Types
interface AhpRequest {
  jsonrpc: string;
  id: string;
  method: string;
  params: any;
}

interface AhpNotification {
  jsonrpc: string;
  method: string;
  params: any;
}

interface AhpResponse {
  jsonrpc: string;
  id: string;
  result?: any;
  error?: {
    code: number;
    message: string;
  };
}

interface AhpEvent {
  event_type: string;
  session_id: string;
  agent_id: string;
  timestamp: string;
  depth: number;
  payload: any;
  metadata?: Record<string, any>;
}

interface Decision {
  decision: 'allow' | 'block' | 'modify' | 'defer' | 'escalate';
  reason?: string;
  modified_payload?: any;
  retry_after_ms?: number;
  metadata?: Record<string, any>;
}

// Policy configuration
const DANGEROUS_PATTERNS = [
  /rm\s+-rf\s+\//,
  /dd\s+if=/,
  /mkfs/,
  /:\(\)\{\s*:\|:&\s*\};:/,
  />\s*\/dev\/sda/,
  /wget.*\|\s*sh/,
  /curl.*\|\s*bash/,
];

/**
 * Check if a command is dangerous
 */
function isDangerous(command: string): boolean {
  return DANGEROUS_PATTERNS.some(pattern => pattern.test(command));
}

/**
 * Handle handshake request
 */
function handleHandshake(params: any): any {
  console.log('[HANDSHAKE] Client:', params.agent_info?.framework, params.agent_info?.version);

  return {
    protocol_version: '2.0',
    harness_info: {
      name: 'typescript-websocket-harness',
      version: '1.0.0',
      capabilities: ['pre_action', 'post_action', 'pre_prompt', 'query', 'batch', 'streaming'],
    },
    config: {
      timeout_ms: 10000,
      batch_size: 100,
      max_depth: 10,
    },
  };
}

/**
 * Handle event with depth-aware policy
 */
function handleEvent(event: AhpEvent): Decision {
  const { event_type, depth, payload } = event;

  console.log(`[EVENT] ${event_type} (depth: ${depth}, session: ${event.session_id.substring(0, 8)}...)`);

  if (event_type === 'pre_action') {
    const command = payload?.arguments?.command;

    if (command) {
      // Depth-aware policy: stricter rules for nested agents
      const depthMultiplier = depth === 0 ? 1.0 : depth === 1 ? 1.3 : 1.8;

      if (isDangerous(command)) {
        console.log(`[BLOCK] Dangerous command at depth ${depth}: ${command}`);
        return {
          decision: 'block',
          reason: `Dangerous command detected: ${command}`,
          metadata: {
            policy: 'security',
            depth,
            severity: 'high',
          },
        };
      }

      // Block network access for deeply nested agents
      if (depth > 1 && /curl|wget|nc|telnet|ssh/.test(command)) {
        console.log(`[BLOCK] Network access denied at depth ${depth}`);
        return {
          decision: 'block',
          reason: `Network access not allowed at depth ${depth}`,
          metadata: {
            policy: 'network-isolation',
            depth,
          },
        };
      }

      // Rate limiting for high-depth agents
      if (depth > 2) {
        console.log(`[DEFER] Rate limiting at depth ${depth}`);
        return {
          decision: 'defer',
          retry_after_ms: 1000 * depthMultiplier,
          reason: 'Rate limiting for nested agents',
        };
      }
    }
  }

  return {
    decision: 'allow',
    metadata: {
      depth,
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Handle query request
 */
function handleQuery(params: any): any {
  const question = params.payload?.question || '';
  const filePath = params.payload?.file_path;

  console.log(`[QUERY] ${question}`);

  if (question.toLowerCase().includes('delete')) {
    return {
      answer: 'no',
      reason: 'Deletion requires explicit user confirmation',
      alternatives: ['Move to trash', 'Create backup first', 'Mark for review'],
    };
  }

  if (filePath && filePath.includes('important')) {
    return {
      answer: 'no',
      reason: 'File is marked as important',
      alternatives: ['Review file contents', 'Check file metadata'],
    };
  }

  return {
    answer: 'yes',
    reason: 'No concerns detected',
  };
}

/**
 * Handle batch request
 */
function handleBatch(params: any): any {
  const events: AhpEvent[] = params.events || [];
  console.log(`[BATCH] Processing ${events.length} events`);

  const decisions = events.map(event => handleEvent(event));

  const blocked = decisions.filter(d => d.decision === 'block').length;
  const allowed = decisions.filter(d => d.decision === 'allow').length;

  console.log(`[BATCH] Results: ${allowed} allowed, ${blocked} blocked`);

  return { decisions };
}

/**
 * Handle WebSocket message
 */
function handleMessage(ws: WebSocket, message: string) {
  try {
    const msg = JSON.parse(message);

    // Check if it's a request (has id) or notification (no id)
    if (msg.id) {
      // Request - send response
      const request: AhpRequest = msg;
      let result: any;

      switch (request.method) {
        case 'ahp/handshake':
          result = handleHandshake(request.params);
          break;

        case 'ahp/event':
          result = handleEvent(request.params);
          break;

        case 'ahp/query':
          result = handleQuery(request.params);
          break;

        case 'ahp/batch':
          result = handleBatch(request.params);
          break;

        default:
          ws.send(JSON.stringify({
            jsonrpc: '2.0',
            id: request.id,
            error: {
              code: -32601,
              message: `Method not found: ${request.method}`,
            },
          }));
          return;
      }

      const response: AhpResponse = {
        jsonrpc: '2.0',
        id: request.id,
        result,
      };

      ws.send(JSON.stringify(response));
    } else {
      // Notification - no response needed
      const notification: AhpNotification = msg;
      console.log(`[NOTIFICATION] ${notification.method}`);

      // Handle notification asynchronously
      if (notification.method === 'ahp/event') {
        handleEvent(notification.params);
      }
    }
  } catch (error) {
    console.error('[ERROR] Failed to handle message:', error);
    ws.send(JSON.stringify({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32700,
        message: 'Parse error',
      },
    }));
  }
}

/**
 * Start the WebSocket server
 */
function main() {
  const PORT = parseInt(process.env.PORT || '8081');

  // Create HTTP server for WebSocket upgrade
  const server = createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', protocol: 'AHP v2.0', transport: 'WebSocket' }));
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  });

  // Create WebSocket server
  const wss = new WebSocket.Server({ server, path: '/ahp' });

  let clientCount = 0;

  wss.on('connection', (ws: WebSocket, req) => {
    const clientId = ++clientCount;
    const clientIp = req.socket.remoteAddress;

    console.log(`\n[CONNECT] Client #${clientId} connected from ${clientIp}`);

    // Set up ping/pong heartbeat
    let isAlive = true;

    ws.on('pong', () => {
      isAlive = true;
    });

    const heartbeat = setInterval(() => {
      if (!isAlive) {
        console.log(`[DISCONNECT] Client #${clientId} timeout`);
        ws.terminate();
        return;
      }

      isAlive = false;
      ws.ping();
    }, 30000); // 30 seconds

    // Handle messages
    ws.on('message', (data: WebSocket.Data) => {
      const message = data.toString();
      handleMessage(ws, message);
    });

    // Handle close
    ws.on('close', () => {
      console.log(`[DISCONNECT] Client #${clientId} disconnected`);
      clearInterval(heartbeat);
    });

    // Handle errors
    ws.on('error', (error) => {
      console.error(`[ERROR] Client #${clientId}:`, error.message);
    });
  });

  // Start server
  server.listen(PORT, () => {
    console.log(`\n🚀 AHP WebSocket Server listening on ws://0.0.0.0:${PORT}/ahp`);
    console.log(`   Health check: http://0.0.0.0:${PORT}/health`);
    console.log(`   Protocol: AHP v2.0`);
    console.log(`   Transport: WebSocket`);
    console.log(`\nPress Ctrl+C to stop\n`);
  });

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n\n[SHUTDOWN] Closing server...');
    wss.clients.forEach(client => {
      client.close(1000, 'Server shutting down');
    });
    server.close(() => {
      console.log('[SHUTDOWN] Server closed');
      process.exit(0);
    });
  });
}

// Run if executed directly
if (require.main === module) {
  main();
}

export { handleMessage, handleEvent, handleQuery };
