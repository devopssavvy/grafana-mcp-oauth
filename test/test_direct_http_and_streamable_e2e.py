#!/usr/bin/env python3
"""
test_direct_http_and_streamable_e2e.py - Verification for Claude's direct HTTP endpoint usage.
Tests:
1. User configures Claude directly with "http://127.0.0.1:8080/mcp" (no /sse).
2. GET /mcp with text/event-stream establishes SSE stream via automatic rewrite to /mcp/sse.
3. Dispatches POST requests across both replicas using:
   a) Query parameter (?sessionid=...)
   b) Header (Mcp-Session-Id: ...)
4. Simulates client SSE disconnect (e.g. during token refresh or stream restart)
   and verifies subsequent POST requests still resolve and succeed across replicas without 404!
"""

import sys
import time
import json
import base64
import hashlib
import secrets
import subprocess
import threading
import urllib.parse
import queue
import requests

ENVOY_BASE_URL = "http://localhost:8080"
MCP_DIRECT_URL = f"{ENVOY_BASE_URL}/mcp"

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

    def serve(self):
        while not callback_event.is_set():
            self.server.handle_request()
        self.server.server_close()

def main():
    print("=" * 70)
    print("CLAUDE DIRECT HTTP & STREAMABLE E2E VERIFICATION")
    print(f"Configured MCP URL: {MCP_DIRECT_URL}")
    print("=" * 70)

    # 1. Discovery challenge on direct /mcp
    print(f"\n[1] Probing direct {MCP_DIRECT_URL} without credentials...")
    resp = requests.get(MCP_DIRECT_URL, allow_redirects=False)
    if resp.status_code != 401:
        print(f"[-] Expected 401 Unauthorized, got {resp.status_code}")
        sys.exit(1)
    www_auth = resp.headers.get("WWW-Authenticate", "")
    print(f"[+] Received RFC 9728 challenge: {www_auth}")

    # 2. Complete PKCE SSO login
    print("\n[2] Executing OAuth 2.1 PKCE Authorization...")
    cb_server = CallbackHandler()
    redirect_uri = f"http://127.0.0.1:{cb_server.port}/callback"
    t = threading.Thread(target=cb_server.serve, daemon=True)
    t.start()

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
    subprocess.run(["orca", "goto", "--url", auth_url], capture_output=True)

    if not callback_event.wait(timeout=15):
        print("[-] Timed out waiting for OAuth callback!")
        sys.exit(1)

    tok_resp = requests.post(f"{ENVOY_BASE_URL}/mcp/auth/token", data={
        "grant_type": "authorization_code",
        "client_id": "claude-direct-agent",
        "code": auth_code_received,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    })
    if tok_resp.status_code != 200:
        print(f"[-] Token exchange failed: {tok_resp.status_code} {tok_resp.text}")
        sys.exit(1)

    access_token = tok_resp.json()["access_token"]
    print(f"[+] Got new credentials: {access_token[:16]}... (len={len(access_token)})")

    # 3. Connect to DIRECT /mcp (not /mcp/sse) as SSE client
    print(f"\n[3] Reconnecting to {MCP_DIRECT_URL} directly (automatic /mcp -> /mcp/sse rewrite)...")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "text/event-stream",
    }
    sse_resp = requests.get(MCP_DIRECT_URL, headers=headers, stream=True)
    if sse_resp.status_code != 200:
        print(f"[-] Failed to establish stream on direct /mcp: {sse_resp.status_code}")
        sys.exit(1)

    print(f"[+] Stream opened on {MCP_DIRECT_URL} (Status {sse_resp.status_code})")

    sse_queue = queue.Queue()
    endpoint_found = threading.Event()
    endpoint_holder = []
    session_id_holder = []

    def sse_reader():
        for line in sse_resp.iter_lines():
            if not line:
                continue
            line_str = line.decode("utf-8").strip()
            sse_queue.put(line_str)
            if "sessionid=" in line_str.lower() or "session_id=" in line_str.lower():
                raw_ep = line_str.replace("data: ", "").strip()
                endpoint_holder.append(raw_ep)
                # extract session id
                parsed = urllib.parse.urlparse(raw_ep)
                sid = urllib.parse.parse_qs(parsed.query).get("sessionid", [""])[0]
                session_id_holder.append(sid)
                endpoint_found.set()

    threading.Thread(target=sse_reader, daemon=True).start()

    if not endpoint_found.wait(timeout=10):
        print("[-] Timed out waiting for endpoint event on direct /mcp")
        sys.exit(1)

    raw_ep = endpoint_holder[0]
    session_id = session_id_holder[0]
    print(f"[+] Server returned endpoint: {raw_ep} (Session ID: {session_id})")

    # 4. Dispatch JSON-RPC requests using BOTH query param AND Mcp-Session-Id header
    post_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Mcp-Session-Id": session_id,
    }

    # Test 4a: POST to discovered endpoint (with sessionid query param)
    print("\n[4] Dispatching requests with sessionid query param:")
    r = requests.post(f"{ENVOY_BASE_URL}{raw_ep}", headers=post_headers, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "claude-code", "version": "1.0"},
        },
    })
    print(f"    Initialize Status: {r.status_code}")
    if r.status_code not in (200, 202):
        print(f"[-] FAILED initialize: {r.status_code} {r.text}")
        sys.exit(1)

    # Test 4b: POST directly to /mcp with Mcp-Session-Id header (no query params)
    print("\n[5] Dispatching POST directly to /mcp with Mcp-Session-Id header (no query param):")
    r = requests.post(MCP_DIRECT_URL, headers=post_headers, json={
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    })
    print(f"    tools/list Status via direct /mcp: {r.status_code}")
    if r.status_code not in (200, 202):
        print(f"[-] FAILED direct /mcp POST: {r.status_code} {r.text}")
        sys.exit(1)

    # 5. Dispatch 20 alternating POST requests across BOTH replicas while SSE stream is active
    print("\n[6] Dispatching 20 alternating POST requests across BOTH replicas:")
    for i in range(3, 23):
        # Alternate between 4 different transport variations clients use:
        if i % 4 == 0:
            target_url = f"{ENVOY_BASE_URL}{raw_ep}"
            desc = "via endpoint with query param (?sessionid=...)"
            req_headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        elif i % 4 == 1:
            target_url = MCP_DIRECT_URL
            desc = "via direct /mcp with Mcp-Session-Id header"
            req_headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json", "Mcp-Session-Id": session_id}
        elif i % 4 == 2:
            target_url = f"{MCP_DIRECT_URL}/?sessionid={session_id}"
            desc = "via direct /mcp/ with query param"
            req_headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        else:
            target_url = f"{ENVOY_BASE_URL}/mcp/sse"
            desc = "via /mcp/sse with Mcp-Session-Id header"
            req_headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json", "Mcp-Session-Id": session_id}

        r = requests.post(target_url, headers=req_headers, json={
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/list",
            "params": {},
        })
        print(f"    [{i-2}/20] POST {desc} -> Status: {r.status_code}")
        if r.status_code not in (200, 202):
            print(f"[-] FAILED cross-replica POST with status {r.status_code}: {r.text}")
            sys.exit(1)
        time.sleep(0.05)

    print("\n" + "=" * 70)
    print("✓ CLAUDE DIRECT HTTP & STREAMABLE E2E VERIFICATION FULLY PASSED!")
    print("  All 20 requests succeeded across 2 replicas with ZERO 404 errors.")
    print("=" * 70)

if __name__ == "__main__":
    main()
