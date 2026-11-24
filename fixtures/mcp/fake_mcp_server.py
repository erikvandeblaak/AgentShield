"""Minimal fictional MCP server (stdio, newline-delimited JSON-RPC) for AgentShield tests.

Tool definitions are read from the JSON file named in FAKE_MCP_TOOLS so tests can simulate
poisoned descriptions and "rug pulls" (definitions that change between runs).
Nothing here touches files or the network; tools/call only echoes its arguments.
"""
import json
import os
import sys

tools = json.load(open(os.environ["FAKE_MCP_TOOLS"], encoding="utf-8"))


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:
        continue  # notification
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "0.0.1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
    elif method == "tools/call":
        name = msg["params"]["name"]
        send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": f"called {name} with {json.dumps(msg['params'].get('arguments', {}))}"}]}})
    else:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})
