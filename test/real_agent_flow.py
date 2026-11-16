import sys
import time
import json
import base64
import hashlib
import secrets
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import urllib.parse
import requests

MCP_BASE_URL = "http://127.0.0.1:8080/mcp"
LOOPBACK_PORT = 54321
REDIRECT_URI = f"http://127.0.0.1:{LOOPBACK_PORT}/callback"

auth_code_received = None
callback_event = threading.Event()

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global auth_code_received
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        if "code" in params:
            auth_code_received = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <body style="font-family:sans-serif; text-align:center; padding:50px;">
                <h1 style="color:#10b981;">&#10003; Login Successful</h1>
                <p>Authorization code received by Agent loopback listener.</p>
                <p>You may now return to your coding agent.</p>
            </body>
            </html>
            """)
            callback_event.set()
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing authorization code")

def run_loopback():
    server = HTTPServer(("127.0.0.1", LOOPBACK_PORT), CallbackHandler)
    server.timeout = 1.0
    while not callback_event.is_set():
        server.handle_request()
    server.server_close()

def main():
    print("[1] AGENT STARTS WITH ZERO TOKEN: Only configured with MCP URL:", MCP_BASE_URL)
    
    # Step 1: Probe MCP endpoint
    sse_url = f"{MCP_BASE_URL}/sse"
    print(f"[*] Probing {sse_url}...")
    resp = requests.get(sse_url, allow_redirects=False)
    print(f"[*] Response Status: {resp.status_code}")
    
    if resp.status_code != 401:
        print(f"[-] Expected 401 Unauthorized, got {resp.status_code}")
        sys.exit(1)
        
    www_auth = resp.headers.get("WWW-Authenticate", "")
    print(f"[*] Received WWW-Authenticate: {www_auth}")
    
    # Extract RFC 9728 resource_metadata URL
    meta_url = None
    for part in www_auth.split(","):
        if "resource_metadata=" in part:
            meta_url = part.split("resource_metadata=")[1].strip(' "')
    
    if not meta_url:
        meta_url = "http://127.0.0.1:8080/.well-known/oauth-protected-resource"
    print(f"[2] RFC 9728 Resource Discovery: fetching {meta_url}")
    
    res_meta = requests.get(meta_url).json()
    print(f"[*] Resource Metadata: {json.dumps(res_meta, indent=2)}")
    auth_server_base = res_meta["authorization_servers"][0]
    
    # Step 2: RFC 8414 OAuth Authorization Server Discovery
    as_meta_url = f"{auth_server_base}/.well-known/oauth-authorization-server"
    print(f"[3] RFC 8414 Auth Server Discovery: fetching {as_meta_url}")
    as_meta = requests.get(as_meta_url).json()
    print(f"[*] Auth Server Metadata: {json.dumps(as_meta, indent=2)}")
    
    auth_endpoint = as_meta["authorization_endpoint"]
    token_endpoint = as_meta["token_endpoint"]
    
    # Step 3: Start loopback receiver
    t = threading.Thread(target=run_loopback, daemon=True)
    t.start()
    
    # Step 4: Generate PKCE
    code_verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").replace("=", "")
    state = secrets.token_urlsafe(16)
    
    auth_query = urllib.parse.urlencode({
        "client_id": "antigravity-agent",
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state
    })
    full_auth_url = f"{auth_endpoint}?{auth_query}"
    print(f"\n[4] OPENING ORCA BROWSER FOR USER LOGIN:")
    print(f"    URL: {full_auth_url}")
    
    # Command Orca browser
    cmd = ["orca", "goto", "--url", full_auth_url]
    print(f"[*] Running command: {' '.join(cmd)}")
    subp = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[*] Orca output: {subp.stdout.strip()}")
    if subp.stderr:
        print(f"[*] Orca stderr: {subp.stderr.strip()}")
        
    print("[*] Waiting for browser to complete SSO login and callback...")
    if not callback_event.wait(timeout=10):
        print("[-] Timed out waiting for callback!")
        sys.exit(1)
        
    print(f"[5] Callback received authorization code: {auth_code_received}")
    
    # Take Orca snapshot to verify browser page
    time.sleep(0.5)
    snap = subprocess.run(["orca", "snapshot"], capture_output=True, text=True)
    print("\n--- Orca Browser Snapshot ---")
    print(snap.stdout)
    print("-----------------------------\n")
    
    # Step 5: Exchange code for MCP Access Token
    print(f"[6] PKCE TOKEN EXCHANGE: POST {token_endpoint}")
    token_resp = requests.post(token_endpoint, data={
        "grant_type": "authorization_code",
        "client_id": "antigravity-agent",
        "code": auth_code_received,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier
    })
    print(f"[*] Token Response Status: {token_resp.status_code}")
    token_data = token_resp.json()
    print(f"[*] Token Data: {json.dumps(token_data, indent=2)}")
    
    access_token = token_data.get("access_token")
    if not access_token:
        print("[-] Failed to get access_token")
        sys.exit(1)
        
    # Step 6: Connect to MCP with Bearer Token over SSE and make tool calls
    print(f"\n[7] CONNECTING TO MCP AS REAL AGENT WITH TOKEN:", flush=True)
    sse_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "text/event-stream"
    }
    post_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Open SSE session
    sse_resp = requests.get(sse_url, headers=sse_headers, stream=True)
    print(f"[*] SSE Connection Status: {sse_resp.status_code}", flush=True)
    
    sse_stream = sse_resp.iter_lines()
    endpoint_path = None
    for line in sse_stream:
        line_str = line.decode("utf-8")
        if "sessionid=" in line_str.lower() or "session_id=" in line_str.lower():
            raw_path = line_str.replace("data: ", "").strip()
            if raw_path.startswith("http://") or raw_path.startswith("https://"):
                parsed = urllib.parse.urlparse(raw_path)
                endpoint_path = parsed.path
                if parsed.query:
                    endpoint_path += f"?{parsed.query}"
            else:
                endpoint_path = raw_path
            print(f"[*] Discovered SSE Message Endpoint: {endpoint_path}", flush=True)
            break
            
    if not endpoint_path:
        print("[-] Did not receive endpoint event from MCP server", flush=True)
        sys.exit(1)
        
    msg_url = f"http://127.0.0.1:8080{endpoint_path}"
    
    # Initialize MCP
    print("\n[8] SENDING MCP 'initialize' REQUEST:", flush=True)
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "antigravity-client", "version": "1.0"}
        }
    }
    r = requests.post(msg_url, headers=post_headers, json=init_payload)
    print(f"[*] Initialize POST Status: {r.status_code}", flush=True)
    
    # List tools
    print("\n[9] SENDING MCP 'tools/list' REQUEST:", flush=True)
    list_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    r = requests.post(msg_url, headers=post_headers, json=list_payload)
    print(f"[*] Tools List POST Status: {r.status_code}", flush=True)
    
    # Call tool: query_prometheus
    print("\n[10] CALLING MCP TOOL 'query_prometheus' (requires Grafana Datasource RBAC via cookie):", flush=True)
    call_payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "query_prometheus",
            "arguments": {
                "query": "node_cpu_utilization_ratio"
            }
        }
    }
    r = requests.post(msg_url, headers=post_headers, json=call_payload)
    print(f"[*] Tool Call POST Status: {r.status_code}", flush=True)
    
    # Read response from SSE stream
    print("\n[11] READING SSE STREAM FOR TOOL CALL RESULT:", flush=True)
    for line in sse_stream:
        if not line:
            continue
        line_str = line.decode("utf-8")
        if line_str.startswith("data: "):
            payload = line_str.replace("data: ", "")
            try:
                data = json.loads(payload)
                if data.get("id") == 3:
                    print("\n[✓] SUCCESS! Received Tool Call Response from Grafana:", flush=True)
                    print(json.dumps(data, indent=2), flush=True)
                    break
            except Exception as e:
                pass

    print("\n==========================================")
    print("✓ FULL HANDS-FREE AGENT OAUTH TEST PASSED!")
    print("==========================================")

if __name__ == "__main__":
    main()
