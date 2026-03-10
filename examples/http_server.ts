#!/usr/bin/env node
/**
 * AHP HTTP Server (TypeScript)
 *
 * A simple HTTP-based AHP harness server that demonstrates:
 * - Handshake and capability negotiation
 * - Pre-action event handling with policy enforcement
 * - Query support
 * - Batch processing
 *
 * Usage:
 *   npm install express body-parser
 *   npx ts-node examples/http_server.ts
 *
 * Or compile and run:
 *   npx tsc examples/http_server.ts && node examples/http_server.js
 */

import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';

// AHP Protocol Types
interface AhpRequest {
  jsonrpc: string;
  id: string;
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

// Dangerous command patterns
const DANGEROUS_PATTERNS = [
  /rm\s+-rf\s+\//,
  /dd\s+if=/,
  /mkfs/,
  /:\(\)\{\s*:\|:&\s*\};:/,  // Fork bomb
  />\s*\/dev\/sda/,
  /wget.*\|\s*sh/,
  /curl.*\|\s*bash/,
];

// Sensitive keywords to detect in output
const SENSITIVE_KEYWORDS = [
  'password',
  'secret',
  'api_key',
  'private_key',
  'token',
  'credential',
];

/**
 * Check if a command is dangerous
 */
function isDangerous(command: string): boolean {
  return DANGEROUS_PATTERNS.some(pattern => pattern.test(command));
}

/**
 * Check if output contains sensitive information
 */
function containsSensitive(output: string): string | null {
  const lowerOutput = output.toLowerCase();
  for (const keyword of SENSITIVE_KEYWORDS) {
    if (lowerOutput.includes(keyword)) {
      return keyword;
    }
  }
  return null;
}

/**
 * Handle handshake request
 */
function handleHandshake(params: any): any {
  console.log('[INFO] Handshake from:', params.agent_info?.framework);

  return {
    protocol_version: '2.0',
    harness_info: {
      name: 'typescript-http-harness',
      version: '1.0.0',
      capabilities: ['pre_action', 'post_action', 'pre_prompt', 'query', 'batch'],
    },
    config: {
      timeout_ms: 10000,
      batch_size: 100,
      max_depth: 10,
    },
  };
}

/**
 * Handle event (pre_action, post_action, etc.)
 */
function handleEvent(event: AhpEvent): Decision {
  console.log(`[INFO] Event: ${event.event_type} (depth: ${event.depth})`);

  if (event.event_type === 'pre_action') {
    const command = event.payload?.arguments?.command;

    if (command) {
      console.log(`[INFO] Checking command: ${command}`);

      // Apply depth-aware policy (stricter for sub-agents)
      if (event.depth > 0 && isDangerous(command)) {
        console.log(`[BLOCK] Dangerous command at depth ${event.depth}: ${command}`);
        return {
          decision: 'block',
          reason: `Dangerous command blocked at depth ${event.depth}: ${command}`,
          metadata: {
            policy: 'depth-aware-security',
            depth: event.depth,
          },
        };
      }

      // Block network access for deeply nested agents
      if (event.depth > 2 && /curl|wget|nc|telnet/.test(command)) {
        console.log(`[BLOCK] Network access blocked at depth ${event.depth}`);
        return {
          decision: 'block',
          reason: 'Network access not allowed for deeply nested agents',
        };
      }
    }
  }

  return {
    decision: 'allow',
  };
}

/**
 * Handle query request
 */
function handleQuery(params: any): any {
  const question = params.payload?.question || '';
  console.log(`[INFO] Query: ${question}`);

  if (question.toLowerCase().includes('delete')) {
    return {
      answer: 'no',
      reason: 'Deletion requires explicit confirmation',
      alternatives: ['Move to trash', 'Create backup first'],
    };
  }

  if (question.toLowerCase().includes('dangerous')) {
    return {
      answer: 'no',
      reason: 'This operation is flagged as potentially dangerous',
      alternatives: ['Review the operation', 'Run in sandbox mode'],
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
  console.log(`[INFO] Batch processing ${events.length} events`);

  const decisions = events.map(event => handleEvent(event));

  return {
    decisions,
  };
}

/**
 * Main request handler
 */
function handleAhpRequest(req: Request, res: Response) {
  const request: AhpRequest = req.body;

  // Validate JSON-RPC 2.0
  if (request.jsonrpc !== '2.0') {
    return res.json({
      jsonrpc: '2.0',
      id: request.id,
      error: {
        code: -32600,
        message: 'Invalid Request: jsonrpc must be "2.0"',
      },
    });
  }

  let result: any;

  try {
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
        return res.json({
          jsonrpc: '2.0',
          id: request.id,
          error: {
            code: -32601,
            message: `Method not found: ${request.method}`,
          },
        });
    }

    const response: AhpResponse = {
      jsonrpc: '2.0',
      id: request.id,
      result,
    };

    res.json(response);
  } catch (error) {
    console.error('[ERROR]', error);
    res.json({
      jsonrpc: '2.0',
      id: request.id,
      error: {
        code: -32603,
        message: `Internal error: ${error}`,
      },
    });
  }
}

/**
 * Start the HTTP server
 */
function main() {
  const app = express();
  const PORT = process.env.PORT || 8080;

  // Middleware
  app.use(bodyParser.json());

  // CORS support
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');

    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }

    next();
  });

  // Authentication middleware (optional)
  app.use((req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const authHeader = req.headers['authorization'];

    // For demo purposes, accept any API key or skip auth
    // In production, validate against a real key store
    if (apiKey || authHeader) {
      console.log('[INFO] Authenticated request');
    }

    next();
  });

  // AHP endpoint
  app.post('/ahp', handleAhpRequest);

  // Health check
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', protocol: 'AHP v2.0' });
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`\n🚀 AHP HTTP Server listening on http://0.0.0.0:${PORT}/ahp`);
    console.log(`   Health check: http://0.0.0.0:${PORT}/health`);
    console.log(`   Protocol: AHP v2.0`);
    console.log(`\nPress Ctrl+C to stop\n`);
  });
}

// Run if executed directly
if (require.main === module) {
  main();
}

export { handleAhpRequest, handleEvent, handleQuery };
