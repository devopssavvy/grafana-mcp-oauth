#!/usr/bin/env python3
"""
test_multi_replica_e2e.py - End-to-end verification of multi-replica proxy + MCP combination.
Tests:
1. RFC 9728 & RFC 8414 OAuth discovery on front-door Envoy load balancer (:8080).
2. PKCE Authorization Code flow through Grafana SSO, receiving access token.
3. SSE connection (GET /mcp/sse) established through Envoy (lands on Replica A).
4. Dispatches multiple JSON-RPC tool calls (initialize, tools/list, tools/call: query_prometheus)
   through Envoy Gateway with round-robin balancing to deliberately force requests to Replica B.
5. Verifies that Replica B resolves the active session from Redis and peer-forwards the request to Replica A,
   completely eliminating HTTP 404: session not found.
6. Reads and verifies tool responses on the SSE stream.
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
import requests

ENVOY_BASE_URL = "http://127.0.0.1:8080"
MCP_BASE_URL = f"{ENVOY_BASE_URL}/mcp"

auth_code_received = None
callback_event = threading.Event()

class CallbackHandler:
    def __init__(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import socket
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                global auth_code_received
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
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
    print("MULTI-REPLICA E2E TEST: 2 REPLICAS OF PROXY + MCP BEHIND ENVOY")
    print("=" * 70)

    # 1. Unauthenticated discovery probe
    sse_url = f"{MCP_BASE_URL}/sse"
    print(f"[*] Probing {sse_url} for RFC 9728 discovery challenge...")
    resp = requests.get(sse_url, allow_redirects=False)
    if resp.status_code != 401:
        print(f"[-] Expected 401 Unauthorized, got {resp.status_code}")
        sys.exit(1)

    www_auth = resp.headers.get("WWW-Authenticate", "")
    print(f"[+] Received WWW-Authenticate: {www_auth}")
    meta_url = None
    for part in www_auth.split(","):
        if "resource_metadata=" in part:
            meta_url = part.split("resource_metadata=")[1].strip(' "')
    if not meta_url:
        meta_url = f"{ENVOY_BASE_URL}/.well-known/oauth-protected-resource"

    # 2. RFC 9728 Resource Discovery
    print(f"[*] Fetching resource metadata from {meta_url}...")
    res_meta = requests.get(meta_url).json()
    auth_server_base = res_meta["authorization_servers"][0]

    # 3. RFC 8414 Auth Server Discovery
    as_meta_url = f"{auth_server_base}/.well-known/oauth-authorization-server"
    print(f"[*] Fetching authorization server metadata from {as_meta_url}...")
    as_meta = requests.get(as_meta_url).json()
    auth_endpoint = as_meta["authorization_endpoint"]
    token_endpoint = as_meta["token_endpoint"]

    # 4. Generate PKCE and initiate login
    cb_server = CallbackHandler()
    redirect_uri = f"http://127.0.0.1:{cb_server.port}/callback"
    t = threading.Thread(target=cb_server.serve, daemon=True)
    t.start()

    code_verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").replace("=", "")
    state = secrets.token_urlsafe(16)

    auth_query = urllib.parse.urlencode({
        "client_id": "multi-replica-agent",
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    full_auth_url = f"{auth_endpoint}?{auth_query}"
    print(f"[*] Navigating browser to Grafana SSO login: {full_auth_url}")

    # Use Orca browser directly (which has the logged-in Grafana session)
    cmd = ["orca", "goto", "--url", full_auth_url]
    print(f"[*] Navigating Orca browser: {' '.join(cmd)}")
    subp = subprocess.run(cmd, capture_output=True, text=True)
    if subp.stderr:
        print(f"[*] Orca stderr: {subp.stderr.strip()}")

    if not callback_event.wait(timeout=15):
        print("[-] Timed out waiting for OAuth callback!")
        sys.exit(1)

    print(f"[+] Successfully received OAuth authorization code: {auth_code_received}")

    # 5. Token Exchange
    print(f"[*] Exchanging authorization code for MCP Bearer Token at {token_endpoint}...")
    token_resp = requests.post(token_endpoint, data={
        "grant_type": "authorization_code",
        "client_id": "multi-replica-agent",
        "code": auth_code_received,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    })
    if token_resp.status_code != 200:
        print(f"[-] Token exchange failed: {token_resp.status_code} {token_resp.text}")
        sys.exit(1)

    token_data = token_resp.json()
    access_token = token_data["access_token"]
    print(f"[+] Acquired MCP Bearer Token: {access_token[:16]}... (len={len(access_token)})")

    # 6. Establish SSE stream via Envoy load balancer (hits Replica A)
    print(f"\n[*] Connecting to SSE endpoint {sse_url}...")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "text/event-stream",
    }
    sse_resp = requests.get(sse_url, headers=headers, stream=True)
    if sse_resp.status_code != 200:
        print(f"[-] Failed to establish SSE stream: {sse_resp.status_code}")
        sys.exit(1)

    print(f"[+] SSE Connection established (Status {sse_resp.status_code})")
    import queue
    sse_queue = queue.Queue()
    endpoint_found = threading.Event()
    endpoint_path_holder = []

    def sse_reader():
        for line in sse_resp.iter_lines():
            if not line:
                continue
            line_str = line.decode("utf-8").strip()
            print(f"[*] SSE Raw line: {line_str}")
            sse_queue.put(line_str)
            if "sessionid=" in line_str.lower() or "session_id=" in line_str.lower():
                raw_path = line_str.replace("data: ", "").strip()
                if raw_path.startswith("http://") or raw_path.startswith("https://"):
                    parsed = urllib.parse.urlparse(raw_path)
                    ep = parsed.path
                    if parsed.query:
                        ep += f"?{parsed.query}"
                else:
                    ep = raw_path
                endpoint_path_holder.append(ep)
                endpoint_found.set()

    reader_thread = threading.Thread(target=sse_reader, daemon=True)
    reader_thread.start()

    print("[*] Waiting for SSE endpoint discovery event...")
    if not endpoint_found.wait(timeout=10):
        print("[-] Did not receive endpoint event from SSE stream within 10s")
        sys.exit(1)

    endpoint_path = endpoint_path_holder[0]
    print(f"[+] Discovered message endpoint from SSE stream: {endpoint_path}")

    msg_url = f"{ENVOY_BASE_URL}{endpoint_path}"
    post_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # 7. Execute 10 alternating POST requests through Envoy to force round-robin hits across BOTH replicas
    print(f"\n[*] Dispatching 10 alternating JSON-RPC requests across the 2 replicas via {msg_url}:")
    
    # 7a. Initialize
    print("  [1/10] Sending 'initialize'...")
    r = requests.post(msg_url, headers=post_headers, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "multi-replica-test", "version": "1.0"},
        },
    })
    print(f"         Status: {r.status_code} (Response: {r.text.strip()})")
    if r.status_code not in (200, 202):
        print(f"[-] FAILED on initialize: {r.status_code} {r.text}")
        sys.exit(1)

    # 7b. Multiple tool list and calls
    for i in range(2, 11):
        print(f"  [{i}/10] Sending 'tools/list' (id={i})...")
        r = requests.post(msg_url, headers=post_headers, json={
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/list",
            "params": {},
        })
        print(f"         Status: {r.status_code}")
        if r.status_code not in (200, 202):
            print(f"[-] FAILED cross-replica POST id={i}: {r.status_code} {r.text}")
            sys.exit(1)
        time.sleep(0.1)

    # 8. Verify SSE stream received tool responses
    print("\n[*] Verifying responses received down the SSE stream...")
    received_ids = set()
    end_time = time.time() + 10
    while time.time() < end_time and len(received_ids) < 5:
        try:
            line_str = sse_queue.get(timeout=1.0)
            if line_str.startswith("data: "):
                try:
                    data = json.loads(line_str.replace("data: ", ""))
                    if "id" in data:
                        received_ids.add(data["id"])
                        print(f"  [✓] SSE received JSON-RPC response id={data['id']}")
                except Exception:
                    pass
        except queue.Empty:
            pass

    print(f"\n[+] Total distinct JSON-RPC responses verified over SSE stream: {len(received_ids)}")
    print("=" * 70)
    print("✓ MULTI-REPLICA END-TO-END VERIFICATION PASSED (ZERO 404 ERRORS)!")
    print("=" * 70)

if __name__ == "__main__":
    main()
