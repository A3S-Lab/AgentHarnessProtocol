#!/usr/bin/env python3
"""
AHP HTTP Server (Python)

A Flask-based AHP harness server that demonstrates:
- Handshake and capability negotiation
- Pre-action event handling with policy enforcement
- Query support
- Batch processing

Usage:
    pip install flask
    python examples/http_server.py

Or with gunicorn:
    pip install flask gunicorn
    gunicorn -w 4 -b 0.0.0.0:8080 examples.http_server:app
"""

import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, request, jsonify

# AHP Protocol Types
class AhpRequest:
    def __init__(self, jsonrpc: str, id: str, method: str, params: Any):
        self.jsonrpc = jsonrpc
        self.id = id
        self.method = method
        self.params = params

class AhpResponse:
    def __init__(self, jsonrpc: str, id: str, result: Any = None, error: Optional[Dict] = None):
        self.jsonrpc = jsonrpc
        self.id = id
        self.result = result
        self.error = error

    def to_dict(self) -> Dict:
        response = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error:
            response["error"] = self.error
        else:
            response["result"] = self.result
        return response

class AhpEvent:
    def __init__(self, event_type: str, session_id: str, agent_id: str,
                 timestamp: str, depth: int, payload: Any, metadata: Optional[Dict] = None):
        self.event_type = event_type
        self.session_id = session_id
        self.agent_id = agent_id
        self.timestamp = timestamp
        self.depth = depth
        self.payload = payload
        self.metadata = metadata or {}

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

# Sensitive keywords to detect in output
SENSITIVE_KEYWORDS = [
    'password',
    'secret',
    'api_key',
    'private_key',
    'token',
    'credential',
]

def is_dangerous(command: str) -> bool:
    """Check if a command is dangerous"""
    return any(pattern.search(command) for pattern in DANGEROUS_PATTERNS)

def contains_sensitive(output: str) -> Optional[str]:
    """Check if output contains sensitive information"""
    lower_output = output.lower()
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in lower_output:
            return keyword
    return None

def handle_handshake(params: Dict) -> Dict:
    """Handle handshake request"""
    agent_info = params.get('agent_info', {})
    print(f'[INFO] Handshake from: {agent_info.get("framework", "unknown")}')

    return {
        'protocol_version': '2.0',
        'harness_info': {
            'name': 'python-http-harness',
            'version': '1.0.0',
            'capabilities': ['pre_action', 'post_action', 'pre_prompt', 'query', 'batch'],
        },
        'config': {
            'timeout_ms': 10000,
            'batch_size': 100,
            'max_depth': 10,
        },
    }

def handle_event(event: Dict) -> Dict:
    """Handle event (pre_action, post_action, etc.)"""
    event_type = event.get('event_type')
    depth = event.get('depth', 0)
    payload = event.get('payload', {})

    print(f'[INFO] Event: {event_type} (depth: {depth})')

    if event_type == 'pre_action':
        command = payload.get('arguments', {}).get('command')

        if command:
            print(f'[INFO] Checking command: {command}')

            # Apply depth-aware policy (stricter for sub-agents)
            if depth > 0 and is_dangerous(command):
                print(f'[BLOCK] Dangerous command at depth {depth}: {command}')
                return Decision(
                    decision='block',
                    reason=f'Dangerous command blocked at depth {depth}: {command}',
                    metadata={
                        'policy': 'depth-aware-security',
                        'depth': depth,
                    }
                ).to_dict()

            # Block network access for deeply nested agents
            if depth > 2 and re.search(r'curl|wget|nc|telnet', command):
                print(f'[BLOCK] Network access blocked at depth {depth}')
                return Decision(
                    decision='block',
                    reason='Network access not allowed for deeply nested agents'
                ).to_dict()

    return Decision(decision='allow').to_dict()

def handle_query(params: Dict) -> Dict:
    """Handle query request"""
    question = params.get('payload', {}).get('question', '')
    print(f'[INFO] Query: {question}')

    if 'delete' in question.lower():
        return {
            'answer': 'no',
            'reason': 'Deletion requires explicit confirmation',
            'alternatives': ['Move to trash', 'Create backup first'],
        }

    if 'dangerous' in question.lower():
        return {
            'answer': 'no',
            'reason': 'This operation is flagged as potentially dangerous',
            'alternatives': ['Review the operation', 'Run in sandbox mode'],
        }

    return {
        'answer': 'yes',
        'reason': 'No concerns detected',
    }

def handle_batch(params: Dict) -> Dict:
    """Handle batch request"""
    events = params.get('events', [])
    print(f'[INFO] Batch processing {len(events)} events')

    decisions = [handle_event(event) for event in events]

    return {
        'decisions': decisions,
    }

# Create Flask app
app = Flask(__name__)

@app.route('/ahp', methods=['POST'])
def ahp_endpoint():
    """Main AHP endpoint"""
    try:
        req_data = request.get_json()

        # Validate JSON-RPC 2.0
        if req_data.get('jsonrpc') != '2.0':
            return jsonify({
                'jsonrpc': '2.0',
                'id': req_data.get('id'),
                'error': {
                    'code': -32600,
                    'message': 'Invalid Request: jsonrpc must be "2.0"',
                },
            })

        method = req_data.get('method')
        params = req_data.get('params', {})
        req_id = req_data.get('id')

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
            return jsonify({
                'jsonrpc': '2.0',
                'id': req_id,
                'error': {
                    'code': -32601,
                    'message': f'Method not found: {method}',
                },
            })

        return jsonify({
            'jsonrpc': '2.0',
            'id': req_id,
            'result': result,
        })

    except Exception as e:
        print(f'[ERROR] {e}', file=sys.stderr)
        return jsonify({
            'jsonrpc': '2.0',
            'id': req_data.get('id') if req_data else None,
            'error': {
                'code': -32603,
                'message': f'Internal error: {str(e)}',
            },
        })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'protocol': 'AHP v2.0'})

@app.before_request
def cors_preflight():
    """Handle CORS preflight"""
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key'
        return response

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to all responses"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key'
    return response

@app.before_request
def authenticate():
    """Authentication middleware (optional)"""
    api_key = request.headers.get('X-API-Key')
    auth_header = request.headers.get('Authorization')

    # For demo purposes, accept any API key or skip auth
    # In production, validate against a real key store
    if api_key or auth_header:
        print('[INFO] Authenticated request')

def main():
    """Start the HTTP server"""
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    print(f'\n🚀 AHP HTTP Server listening on http://0.0.0.0:{port}/ahp')
    print(f'   Health check: http://0.0.0.0:{port}/health')
    print(f'   Protocol: AHP v2.0')
    print(f'\nPress Ctrl+C to stop\n')

    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    main()
