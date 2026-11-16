#!/usr/bin/env python3
"""
test_streamable_tool_calls_e2e.py - Verification for Claude Direct HTTP with Streamable HTTP & Cookie Forwarding.
Verifies:
1. Complete OAuth PKCE authorization flow against multi-replica gateway (Envoy :8080).
2. MCP initialize handshake via Streamable HTTP (POST /mcp).
3. Tool calls (user_info, list_datasources, search_dashboards) successfully authenticate
   against Grafana via forwarded Cookie (no HTTP 401 Unauthorized).
4. Reconnection and repeated calls across both replicas return 200 OK (no HTTP 404 session not found).
"""

import sys
import time
import json
import base64
import hashlib
import secrets
import threading
import urllib.parse
import requests

ENVOY_BASE_URL = "http://localhost:8080"
MCP_ENDPOINT = f"{ENVOY_BASE_URL}/mcp"

auth_code_received = None
callback_event = threading.Event()

class CallbackHandler:
    def __init__(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                global auth_code_received
                params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                if "code" in params:
                    auth_code_received = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Login Successful</h1></body></html>")
                    callback_event.set()
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing code")
            def log_message(self, format, *args):
                pass

        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True

        self.server = ReusableHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.server.timeout = 1.0

    def start(self):
        self.thread = threading.Thread(target=self.server.handle_request, daemon=True)
        self.thread.start()

def run_test():
    print("================================================================================")
    print("Step 1: Logging into Grafana directly to obtain verified grafana_session cookie")
    print("================================================================================")
    session = requests.Session()
    login_resp = session.post(
        f"{ENVOY_BASE_URL}/login",
        json={"user": "admin", "password": "admin"},
        headers={"Content-Type": "application/json"}
    )
    if login_resp.status_code != 200:
        print(f"FAILED: Grafana login failed: {login_resp.status_code} {login_resp.text}")
        sys.exit(1)
    
    grafana_session = session.cookies.get("grafana_session")
    print(f"Obtained Grafana session cookie: {grafana_session[:8]}... (Length: {len(grafana_session)})")

    print("\n================================================================================")
    print("Step 2: Performing PKCE Authorization Code Grant flow")
    print("================================================================================")
    cb = CallbackHandler()
    cb.start()
    redirect_uri = f"http://127.0.0.1:{cb.port}/callback"

    code_verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").replace("=", "")
    state = secrets.token_urlsafe(16)

    auth_query = urllib.parse.urlencode({
        "client_id": "claude-direct-agent",
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    auth_url = f"{ENVOY_BASE_URL}/mcp/auth/login?{auth_query}"
    auth_resp = session.get(auth_url, allow_redirects=True, timeout=10)
    if not callback_event.wait(timeout=10):
        print("FAILED: Did not receive authorization code callback")
        sys.exit(1)

    print(f"Received Authorization Code: {auth_code_received[:12]}...")

    # Exchange code for token
    token_resp = requests.post(
        f"{ENVOY_BASE_URL}/mcp/auth/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code_received,
            "redirect_uri": redirect_uri,
            "client_id": "claude-direct-agent",
            "code_verifier": code_verifier,
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        print(f"FAILED: Token exchange failed: {token_resp.status_code} {token_resp.text}")
        sys.exit(1)

    token_data = token_resp.json()
    bearer_token = token_data["access_token"]
    print(f"Obtained MCP Bearer Token: {bearer_token[:15]}... Expires in: {token_data.get('expires_in')}s")

    print("\n================================================================================")
    print("Step 3: MCP Initialize via Streamable HTTP (POST /mcp)")
    print("================================================================================")
    mcp_headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "claude-code", "version": "1.0.0"}
        }
    }
    init_resp = requests.post(MCP_ENDPOINT, json=init_payload, headers=mcp_headers, timeout=10)
    print(f"Initialize status: {init_resp.status_code}")
    if init_resp.status_code != 200:
        print(f"FAILED: Initialize failed: {init_resp.status_code} {init_resp.text}")
        sys.exit(1)
    
    init_res = init_resp.json()
    server_info = init_res.get("result", {}).get("serverInfo", {})
    print(f"Server Info: {server_info.get('name')} v{server_info.get('version')}")

    print("\n================================================================================")
    print("Step 4: Executing Read-Only Tool Calls (user_info, list_datasources, search_dashboards)")
    print("================================================================================")
    tools_to_test = [
        ("user_info", {}),
        ("list_datasources", {}),
        ("search_dashboards", {"query": ""}),
    ]

    for tool_name, args in tools_to_test:
        call_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        }
        resp = requests.post(MCP_ENDPOINT, json=call_payload, headers=mcp_headers, timeout=10)
        print(f"Tool '{tool_name}' HTTP Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"FAILED: Tool call '{tool_name}' failed with status {resp.status_code}: {resp.text}")
            sys.exit(1)
        
        data = resp.json()
        result = data.get("result", {})
        if result.get("isError"):
            print(f"FAILED: Tool '{tool_name}' returned error: {json.dumps(result)}")
            sys.exit(1)
        
        content = result.get("content", [{}])[0].get("text", "")
        # Check that we did NOT receive 401 Unauthorized
        if "Unauthorized" in content or "401" in content:
            print(f"FAILED: Tool '{tool_name}' returned Unauthorized: {content}")
            sys.exit(1)
        print(f"SUCCESS: Tool '{tool_name}' response preview: {content[:100]}...")

    print("\n================================================================================")
    print("Step 5: High-Availability Multi-Replica Resilience Test (20 requests across replicas)")
    print("================================================================================")
    for i in range(1, 21):
        call_payload = {
            "jsonrpc": "2.0",
            "id": 100 + i,
            "method": "tools/call",
            "params": {
                "name": "user_info",
                "arguments": {}
            }
        }
        resp = requests.post(MCP_ENDPOINT, json=call_payload, headers=mcp_headers, timeout=10)
        if resp.status_code != 200:
            print(f"FAILED on request {i}: status {resp.status_code}: {resp.text}")
            sys.exit(1)
        
        content = resp.json().get("result", {}).get("content", [{}])[0].get("text", "")
        if "admin" not in content:
            print(f"FAILED on request {i}: unexpected content: {content}")
            sys.exit(1)
        print(f"Request {i:02d}/20 -> HTTP {resp.status_code} OK (user verified: admin)")

    print("\n================================================================================")
    print("Step 6: Simulating New Claude Session Without Re-auth (Token Reusability & Persistence)")
    print("================================================================================")
    # Create fresh HTTP client session (simulating Claude exiting and starting fresh)
    fresh_session = requests.Session()
    fresh_headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    recheck_resp = fresh_session.post(
        MCP_ENDPOINT,
        json={
            "jsonrpc": "2.0",
            "id": 200,
            "method": "tools/call",
            "params": {"name": "user_info", "arguments": {}}
        },
        headers=fresh_headers,
        timeout=10,
    )
    if recheck_resp.status_code != 200:
        print(f"FAILED on fresh session: status {recheck_resp.status_code}: {recheck_resp.text}")
        sys.exit(1)
    
    content = recheck_resp.json().get("result", {}).get("content", [{}])[0].get("text", "")
    if "admin" not in content:
        print(f"FAILED on fresh session: unexpected content: {content}")
        sys.exit(1)
    print(f"SUCCESS: Fresh Claude session immediately succeeded with HTTP 200 OK: {content}")

    print("\n================================================================================")
    print("Step 7: Simulating Full Client Re-Auth Cycle (New PKCE Exchange & Continued Tool Calls)")
    print("================================================================================")
    cb2 = CallbackHandler()
    cb2.start()
    redirect_uri2 = f"http://127.0.0.1:{cb2.port}/callback"

    code_verifier2 = secrets.token_urlsafe(48)
    digest2 = hashlib.sha256(code_verifier2.encode("utf-8")).digest()
    code_challenge2 = base64.urlsafe_b64encode(digest2).decode("utf-8").replace("=", "")
    state2 = secrets.token_urlsafe(16)

    auth_query2 = urllib.parse.urlencode({
        "client_id": "claude-direct-agent",
        "response_type": "code",
        "redirect_uri": redirect_uri2,
        "code_challenge": code_challenge2,
        "code_challenge_method": "S256",
        "state": state2,
    })
    auth_url2 = f"{ENVOY_BASE_URL}/mcp/auth/login?{auth_query2}"
    session.get(auth_url2, allow_redirects=True, timeout=10)
    if not callback_event.wait(timeout=10):
        print("FAILED: Re-auth callback timeout")
        sys.exit(1)
    
    token_resp2 = requests.post(
        f"{ENVOY_BASE_URL}/mcp/auth/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code_received,
            "redirect_uri": redirect_uri2,
            "client_id": "claude-direct-agent",
            "code_verifier": code_verifier2,
        },
        timeout=10,
    )
    if token_resp2.status_code != 200:
        print(f"FAILED: Re-auth token exchange failed: {token_resp2.status_code} {token_resp2.text}")
        sys.exit(1)
    
    bearer_token2 = token_resp2.json()["access_token"]
    print(f"Obtained Re-authed Bearer Token: {bearer_token2[:15]}...")

    # Now invoke tools with the new token
    reauth_headers = {
        "Authorization": f"Bearer {bearer_token2}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    for tool_name, args in tools_to_test:
        resp = requests.post(
            MCP_ENDPOINT,
            json={"jsonrpc": "2.0", "id": 300, "method": "tools/call", "params": {"name": tool_name, "arguments": args}},
            headers=reauth_headers,
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"FAILED after re-auth on tool '{tool_name}': {resp.status_code} {resp.text}")
            sys.exit(1)
        res_data = resp.json().get("result", {})
        if res_data.get("isError"):
            print(f"FAILED after re-auth on tool '{tool_name}': error returned: {res_data}")
            sys.exit(1)
        text_content = res_data.get("content", [{}])[0].get("text", "")
        print(f"Tool '{tool_name}' after re-auth succeeded: {text_content[:80]}...")

    print("\n================================================================================")
    print("ALL TESTS PASSED WITH 100% SUCCESS!")
    print("Zero 401 Unauthorized errors on tool calls.")
    print("Zero 404 session not found errors on reconnect / multi-replica dispatch.")
    print("================================================================================")

if __name__ == "__main__":
    run_test()
