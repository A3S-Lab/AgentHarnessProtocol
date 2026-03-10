#!/usr/bin/env python3
"""
AHP WebSocket Server (Python)

A WebSocket-based AHP harness server with bidirectional streaming support.

Features:
- Persistent connections with low latency
- Concurrent client support
- Ping/Pong heartbeat
- Batch processing
- Depth-aware policy enforcement

Usage:
    pip install websockets
    python examples/websocket_server.py

Or with custom port:
    python examples/websocket_server.py 8081
"""

import asyncio
import json
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import websockets
from websockets.server import WebSocketServerProtocol

# AHP Protocol Types
class Decision:
    def __init__(self, decision: str, reason: Optional[str] = None,
                 modified_payload: Any = None, retry_after_ms: Optional[int] = None,
                 metadata: Optional[Dict] = None):
        self.decision = decision
        self.reason = reason
        self.modified_payload = modified_payload
        self.retry_after_ms = retry_after_ms
        self.metadata = metadata or {}

    def to_dict(self) -> Dict:
        result = {"decision": self.decision}
        if self.reason:
            result["reason"] = self.reason
        if self.modified_payload:
            result["modified_payload"] = self.modified_payload
        if self.retry_after_ms:
            result["retry_after_ms"] = self.retry_after_ms
        if self.metadata:
            result["metadata"] = self.metadata
        return result

# Dangerous command patterns
DANGEROUS_PATTERNS = [
    re.compile(r'rm\s+-rf\s+/'),
    re.compile(r'dd\s+if='),
    re.compile(r'mkfs'),
    re.compile(r':\(\)\{\s*:\|:&\s*\};:'),  # Fork bomb
    re.compile(r'>\s*/dev/sda'),
    re.compile(r'wget.*\|\s*sh'),
    re.compile(r'curl.*\|\s*bash'),
]

def is_dangerous(command: str) -> bool:
    """Check if a command is dangerous"""
    return any(pattern.search(command) for pattern in DANGEROUS_PATTERNS)

def handle_handshake(params: Dict) -> Dict:
    """Handle handshake request"""
    agent_info = params.get('agent_info', {})
    framework = agent_info.get('framework', 'unknown')
    version = agent_info.get('version', 'unknown')
    print(f'[HANDSHAKE] Client: {framework} {version}')

    return {
        'protocol_version': '2.0',
        'harness_info': {
            'name': 'python-websocket-harness',
            'version': '1.0.0',
            'capabilities': ['pre_action', 'post_action', 'pre_prompt', 'query', 'batch', 'streaming'],
        },
        'config': {
            'timeout_ms': 10000,
            'batch_size': 100,
            'max_depth': 10,
        },
    }

def handle_event(event: Dict) -> Dict:
    """Handle event with depth-aware policy"""
    event_type = event.get('event_type')
    depth = event.get('depth', 0)
    payload = event.get('payload', {})
    session_id = event.get('session_id', '')

    print(f'[EVENT] {event_type} (depth: {depth}, session: {session_id[:8]}...)')

    if event_type == 'pre_action':
        command = payload.get('arguments', {}).get('command')

        if command:
            # Depth-aware policy: stricter rules for nested agents
            depth_multiplier = 1.0 if depth == 0 else (1.3 if depth == 1 else 1.8)

            if is_dangerous(command):
                print(f'[BLOCK] Dangerous command at depth {depth}: {command}')
                return Decision(
                    decision='block',
                    reason=f'Dangerous command detected: {command}',
                    metadata={
                        'policy': 'security',
                        'depth': depth,
                        'severity': 'high',
                    }
                ).to_dict()

            # Block network access for deeply nested agents
            if depth > 1 and re.search(r'curl|wget|nc|telnet|ssh', command):
                print(f'[BLOCK] Network access denied at depth {depth}')
                return Decision(
                    decision='block',
                    reason=f'Network access not allowed at depth {depth}',
                    metadata={
                        'policy': 'network-isolation',
                        'depth': depth,
                    }
                ).to_dict()

            # Rate limiting for high-depth agents
            if depth > 2:
                print(f'[DEFER] Rate limiting at depth {depth}')
                return Decision(
                    decision='defer',
                    retry_after_ms=int(1000 * depth_multiplier),
                    reason='Rate limiting for nested agents'
                ).to_dict()

    return Decision(
        decision='allow',
        metadata={
            'depth': depth,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
    ).to_dict()

def handle_query(params: Dict) -> Dict:
    """Handle query request"""
    question = params.get('payload', {}).get('question', '')
    file_path = params.get('payload', {}).get('file_path')

    print(f'[QUERY] {question}')

    if 'delete' in question.lower():
        return {
            'answer': 'no',
            'reason': 'Deletion requires explicit user confirmation',
            'alternatives': ['Move to trash', 'Create backup first', 'Mark for review'],
        }

    if file_path and 'important' in file_path:
        return {
            'answer': 'no',
            'reason': 'File is marked as important',
            'alternatives': ['Review file contents', 'Check file metadata'],
        }

    return {
        'answer': 'yes',
        'reason': 'No concerns detected',
    }

def handle_batch(params: Dict) -> Dict:
    """Handle batch request"""
    events = params.get('events', [])
    print(f'[BATCH] Processing {len(events)} events')

    decisions = [handle_event(event) for event in events]

    blocked = sum(1 for d in decisions if d['decision'] == 'block')
    allowed = sum(1 for d in decisions if d['decision'] == 'allow')

    print(f'[BATCH] Results: {allowed} allowed, {blocked} blocked')

    return {'decisions': decisions}

async def handle_message(websocket: WebSocketServerProtocol, message: str):
    """Handle WebSocket message"""
    try:
        msg = json.loads(message)

        # Check if it's a request (has id) or notification (no id)
        if 'id' in msg:
            # Request - send response
            method = msg.get('method')
            params = msg.get('params', {})
            req_id = msg.get('id')

            result = None

            if method == 'ahp/handshake':
                result = handle_handshake(params)
            elif method == 'ahp/event':
                result = handle_event(params)
            elif method == 'ahp/query':
                result = handle_query(params)
            elif method == 'ahp/batch':
                result = handle_batch(params)
            else:
                await websocket.send(json.dumps({
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'error': {
                        'code': -32601,
                        'message': f'Method not found: {method}',
                    },
                }))
                return

            response = {
                'jsonrpc': '2.0',
                'id': req_id,
                'result': result,
            }

            await websocket.send(json.dumps(response))
        else:
            # Notification - no response needed
            method = msg.get('method')
            print(f'[NOTIFICATION] {method}')

            # Handle notification asynchronously
            if method == 'ahp/event':
                handle_event(msg.get('params', {}))

    except json.JSONDecodeError:
        await websocket.send(json.dumps({
            'jsonrpc': '2.0',
            'id': None,
            'error': {
                'code': -32700,
                'message': 'Parse error',
            },
        }))
    except Exception as e:
        print(f'[ERROR] Failed to handle message: {e}', file=sys.stderr)
        await websocket.send(json.dumps({
            'jsonrpc': '2.0',
            'id': None,
            'error': {
                'code': -32603,
                'message': f'Internal error: {str(e)}',
            },
        }))

# Track connected clients
connected_clients: Set[WebSocketServerProtocol] = set()
client_counter = 0

async def handle_client(websocket: WebSocketServerProtocol, path: str):
    """Handle WebSocket client connection"""
    global client_counter
    client_counter += 1
    client_id = client_counter
    client_ip = websocket.remote_address[0] if websocket.remote_address else 'unknown'

    print(f'\n[CONNECT] Client #{client_id} connected from {client_ip}')
    connected_clients.add(websocket)

    try:
        # Heartbeat task
        async def heartbeat():
            try:
                while True:
                    await asyncio.sleep(30)
                    await websocket.ping()
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        heartbeat_task = asyncio.create_task(heartbeat())

        # Handle messages
        async for message in websocket:
            await handle_message(websocket, message)

    except websockets.exceptions.ConnectionClosed:
        print(f'[DISCONNECT] Client #{client_id} disconnected')
    except Exception as e:
        print(f'[ERROR] Client #{client_id}: {e}', file=sys.stderr)
    finally:
        heartbeat_task.cancel()
        connected_clients.discard(websocket)

async def main():
    """Start the WebSocket server"""
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

    print(f'\n🚀 AHP WebSocket Server listening on ws://0.0.0.0:{port}/ahp')
    print(f'   Protocol: AHP v2.0')
    print(f'   Transport: WebSocket')
    print(f'\nPress Ctrl+C to stop\n')

    async with websockets.serve(handle_client, '0.0.0.0', port, subprotocols=['ahp']):
        await asyncio.Future()  # Run forever

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n\n[SHUTDOWN] Server stopped')
        sys.exit(0)
