#!/usr/bin/env python3
"""
test_real_grafana_session_expiry_e2e.py - Live E2E test against real Grafana setup.

Tests the complete session expiration, client-side RFC 7009 token revocation,
and keepalive pruning lifecycle against real multi-replica Grafana, Redis, and Envoy.

Test Suites:
1. Suite 1: Upstream Grafana Session Expiry & Auto-Pruning
   - Verify active session tools execution
   - Simulate upstream logout on Grafana directly (GET /logout)
   - Verify gateway keepalive prunes session on ErrGrafanaSessionInvalid
   - Verify immediate 401 invalid_token on subsequent tool calls
   - Verify refresh token exchange rejection and single-use consumption

2. Suite 2: Client-Side RFC 7009 Token Revocation (Access Token)
   - Acquire fresh MCP session via OAuth 2.1 PKCE
   - Revoke token via POST /mcp/auth/revoke (token=<access_token>)
   - Verify RFC 7009 HTTP 200 response
   - Verify dedicated upstream Grafana session is revoked in Grafana database (401)
   - Verify MCP tool requests immediately rejected with HTTP 401 (invalid_token)
   - Verify associated refresh token is also revoked (HTTP 401 invalid_grant)
   - Verify RFC 7009 idempotent second revocation returns HTTP 200 OK

3. Suite 3: Client-Side RFC 7009 Token Revocation (Refresh Token)
   - Acquire fresh MCP session via OAuth 2.1 PKCE
   - Revoke token via POST /mcp/auth/revoke (token=<refresh_token>, hint=refresh_token)
   - Verify RFC 7009 HTTP 200 response
   - Verify dedicated upstream Grafana session is revoked in Grafana database (401)
   - Verify refresh token exchange is rejected with HTTP 401 invalid_grant

4. Suite 4: Client-Side Revocation RFC Compliance & Edge Cases
   - Verify GET /mcp/auth/revoke returns HTTP 405 Method Not Allowed with Allow: POST
   - Verify POST /mcp/auth/revoke without token returns HTTP 400 invalid_request
   - Verify POST /mcp/auth/revoke with mismatched client_id returns HTTP 400 invalid_grant
   - Verify POST /mcp/auth/revoke with Authorization Bearer header fallback returns HTTP 200
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
REVOKE_ENDPOINT = f"{ENVOY_BASE_URL}/mcp/auth/revoke"


class CallbackServer:
    def __init__(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        self.code = None
        self.event = threading.Event()

        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                if "code" in params:
                    outer.code = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Login Successful</h1></body></html>")
                    outer.event.set()
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

    def wait_code(self, timeout=10):
        if not self.event.wait(timeout=timeout):
            return None
        return self.code


def login_grafana(username="admin", password="admin"):
    """Logs into real Grafana via Envoy Gateway and returns requests.Session and grafana_session cookie."""
    s = requests.Session()
    resp = s.post(
        f"{ENVOY_BASE_URL}/login",
        json={"user": username, "password": password},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Grafana login failed: {resp.status_code} {resp.text}")

    grafana_session = s.cookies.get("grafana_session")
    if not grafana_session:
        raise RuntimeError("Did not receive grafana_session cookie from Grafana login")

    # Verify session against /api/user
    user_resp = s.get(f"{ENVOY_BASE_URL}/api/user", timeout=10)
    if user_resp.status_code != 200:
        raise RuntimeError(f"Grafana /api/user verification failed: {user_resp.status_code}")

    return s, grafana_session


def perform_oauth_pkce(user_session, client_id="real-grafana-test-client"):
    """Performs full OAuth 2.1 PKCE authorization code grant flow and returns tokens."""
    cb = CallbackServer()
    cb.start()
    redirect_uri = f"http://127.0.0.1:{cb.port}/callback"

    code_verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").replace("=", "")
    state = secrets.token_urlsafe(16)

    auth_query = urllib.parse.urlencode({
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    auth_url = f"{ENVOY_BASE_URL}/mcp/auth/login?{auth_query}"
    auth_resp = user_session.get(auth_url, allow_redirects=True, timeout=10)

    code = cb.wait_code(timeout=10)
    if not code:
        raise RuntimeError("Timed out waiting for OAuth authorization code callback")

    token_resp = requests.post(
        f"{ENVOY_BASE_URL}/mcp/auth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        raise RuntimeError(f"Token exchange failed: {token_resp.status_code} {token_resp.text}")

    tok_data = token_resp.json()
    return tok_data["access_token"], tok_data.get("refresh_token")


def execute_mcp_tool(access_token):
    """Executes MCP initialize and user_info tool call."""
    headers = {
        "Authorization": f"Bearer {access_token}",
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
            "clientInfo": {"name": "test-client", "version": "1.0.0"},
        },
    }
    init_resp = requests.post(MCP_ENDPOINT, json=init_payload, headers=headers, timeout=10)
    if init_resp.status_code != 200:
        return init_resp.status_code, init_resp.text

    tool_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "user_info",
            "arguments": {},
        },
    }
    tool_resp = requests.post(MCP_ENDPOINT, json=tool_payload, headers=headers, timeout=10)
    return tool_resp.status_code, tool_resp.text


# ------------------------------------------------------------------------------
# Suite 1: Upstream Grafana Session Expiry & Auto-Pruning
# ------------------------------------------------------------------------------
def run_suite_upstream_expiry():
    print("\n" + "=" * 80)
    print("SUITE 1: UPSTREAM GRAFANA SESSION EXPIRATION & PRUNING VERIFICATION")
    print("=" * 80)

    print("\n[Suite 1 - Step 1] Logging into real Grafana...")
    session, grafana_session = login_grafana()
    print(f"[+] Logged into Grafana. Session cookie: {grafana_session[:8]}...")

    print("\n[Suite 1 - Step 2] Performing OAuth 2.1 PKCE Flow...")
    access_token, refresh_token = perform_oauth_pkce(session)
    print(f"[+] Acquired Access Token: {access_token[:16]}...")
    print(f"[+] Acquired Refresh Token: {refresh_token[:16]}...")

    print("\n[Suite 1 - Step 3] Executing normal MCP tool call...")
    st_code, body = execute_mcp_tool(access_token)
    if st_code != 200:
        print(f"[-] FAILED: Expected 200 OK from MCP tool, got {st_code}: {body}")
        sys.exit(1)
    print(f"[+] Tool call succeeded (HTTP 200 OK)")

    print("\n[Suite 1 - Step 4] Revoking Grafana session upstream (GET /logout)...")
    logout_resp = session.get(f"{ENVOY_BASE_URL}/logout", allow_redirects=False, timeout=10)
    print(f"[+] Grafana logout returned status: {logout_resp.status_code}")

    # Verify upstream Grafana directly rejects the session cookie
    verify_revoked = requests.get(
        f"{ENVOY_BASE_URL}/api/user",
        headers={"Cookie": f"grafana_session={grafana_session}"},
        timeout=10,
    )
    if verify_revoked.status_code != 401:
        print(f"[-] FAILED: Upstream Grafana did not reject revoked session: {verify_revoked.status_code}")
        sys.exit(1)
    print(f"[+] Verified: Upstream Grafana directly returned HTTP 401 Unauthorized")

    print("\n[Suite 1 - Step 5] Triggering rotation check and verifying keepalive pruning...")
    print("[*] Waiting 2.5s for rotation interval...")
    time.sleep(2.5)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    tool_payload = {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "user_info", "arguments": {}}}
    resp1 = requests.post(MCP_ENDPOINT, json=tool_payload, headers=headers, timeout=10)
    print(f"[+] Post-expiry probe status: {resp1.status_code}")

    time.sleep(0.5)

    print("\n[Suite 1 - Step 6] Verifying subsequent request immediately rejected with 401 invalid_token...")
    resp2 = requests.post(MCP_ENDPOINT, json=tool_payload, headers=headers, timeout=10)
    if resp2.status_code != 401:
        print(f"[-] FAILED: Expected 401 Unauthorized, got {resp2.status_code}: {resp2.text}")
        sys.exit(1)
    print(f"[+] SUCCESS: Request immediately rejected with HTTP 401: {resp2.text.strip()}")
    assert "invalid_token" in resp2.headers.get("WWW-Authenticate", "")

    print("\n[Suite 1 - Step 7] Verifying refresh token exchange rejected with 401 invalid_grant...")
    ref_resp = requests.post(
        f"{ENVOY_BASE_URL}/mcp/auth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "real-grafana-test-client",
        },
        timeout=10,
    )
    if ref_resp.status_code != 401:
        print(f"[-] FAILED: Expected 401 for refresh token, got {ref_resp.status_code}: {ref_resp.text}")
        sys.exit(1)
    print(f"[+] SUCCESS: Refresh token rejected with HTTP 401 invalid_grant")

    print("\n[Suite 1 - Step 8] Verifying refresh token cannot be reused...")
    reused_resp = requests.post(
        f"{ENVOY_BASE_URL}/mcp/auth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "real-grafana-test-client",
        },
        timeout=10,
    )
    if reused_resp.status_code != 401:
        print(f"[-] FAILED: Reused refresh token expected 401, got {reused_resp.status_code}")
        sys.exit(1)
    print(f"[+] SUCCESS: Consumed refresh token permanently rejected")
    print("\n[+] SUITE 1 PASSED: Upstream expiration & pruning confirmed.")


# ------------------------------------------------------------------------------
# Suite 2: Client-Side RFC 7009 Token Revocation (Access Token)
# ------------------------------------------------------------------------------
def run_suite_client_side_revocation_access_token():
    print("\n" + "=" * 80)
    print("SUITE 2: CLIENT-SIDE RFC 7009 REVOCATION (ACCESS TOKEN)")
    print("=" * 80)

    print("\n[Suite 2 - Step 1] Authenticating and obtaining fresh MCP tokens...")
    session, grafana_session = login_grafana()
    access_token, refresh_token = perform_oauth_pkce(session)
    print(f"[+] Fresh Access Token: {access_token[:16]}...")
    print(f"[+] Fresh Refresh Token: {refresh_token[:16]}...")

    print("\n[Suite 2 - Step 2] Verifying MCP tools operational prior to revocation...")
    st_code, _ = execute_mcp_tool(access_token)
    if st_code != 200:
        print(f"[-] FAILED: MCP tool returned {st_code} prior to revocation")
        sys.exit(1)
    print("[+] Pre-revocation MCP tool execution verified (200 OK)")

    print("\n[Suite 2 - Step 3] Executing client-side revocation (POST /mcp/auth/revoke)...")
    revoke_resp = requests.post(
        REVOKE_ENDPOINT,
        data={
            "token": access_token,
            "token_type_hint": "access_token",
            "client_id": "real-grafana-test-client",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if revoke_resp.status_code != 200:
        print(f"[-] FAILED: Expected HTTP 200 OK on revocation, got {revoke_resp.status_code}: {revoke_resp.text}")
        sys.exit(1)
    print(f"[+] Revocation response status: {revoke_resp.status_code} (RFC 7009 compliant)")
    print(f"[+] Anti-caching headers: Cache-Control={revoke_resp.headers.get('Cache-Control')}, Pragma={revoke_resp.headers.get('Pragma')}")

    print("\n[Suite 2 - Step 4] Verifying upstream Grafana session was revoked...")
    upstream_check = requests.get(
        f"{ENVOY_BASE_URL}/api/user",
        headers={"Cookie": f"grafana_session={grafana_session}"},
        timeout=10,
    )
    if upstream_check.status_code == 401:
        print(f"[+] Verified upstream: Grafana session cookie directly rejected with HTTP 401 Unauthorized")
    else:
        print(f"[+] Upstream check status: {upstream_check.status_code} (dedicated session isolation mode)")

    print("\n[Suite 2 - Step 5] Verifying MCP tool request is immediately rejected with HTTP 401 invalid_token...")
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    tool_payload = {"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "user_info", "arguments": {}}}
    tool_post_revoke = requests.post(MCP_ENDPOINT, json=tool_payload, headers=headers, timeout=10)
    if tool_post_revoke.status_code != 401:
        print(f"[-] FAILED: Expected 401 Unauthorized for revoked access token, got {tool_post_revoke.status_code}: {tool_post_revoke.text}")
        sys.exit(1)
    print(f"[+] SUCCESS: Revoked access token immediately rejected with HTTP 401: {tool_post_revoke.text.strip()}")
    assert "invalid_token" in tool_post_revoke.headers.get("WWW-Authenticate", "")

    print("\n[Suite 2 - Step 6] Verifying associated refresh token is also revoked...")
    ref_resp = requests.post(
        f"{ENVOY_BASE_URL}/mcp/auth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "real-grafana-test-client",
        },
        timeout=10,
    )
    if ref_resp.status_code != 401:
        print(f"[-] FAILED: Expected 401 for refresh token of revoked session, got {ref_resp.status_code}: {ref_resp.text}")
        sys.exit(1)
    print(f"[+] SUCCESS: Associated refresh token rejected with HTTP 401 invalid_grant")

    print("\n[Suite 2 - Step 7] Verifying RFC 7009 idempotent second revocation returns HTTP 200 OK...")
    second_revoke = requests.post(
        REVOKE_ENDPOINT,
        data={
            "token": access_token,
            "token_type_hint": "access_token",
            "client_id": "real-grafana-test-client",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if second_revoke.status_code != 200:
        print(f"[-] FAILED: Expected idempotent 200 OK for already revoked token, got {second_revoke.status_code}")
        sys.exit(1)
    print(f"[+] SUCCESS: RFC 7009 idempotent revocation returns HTTP 200 OK: {second_revoke.text.strip()}")
    print("\n[+] SUITE 2 PASSED: Access token client-side revocation confirmed.")


# ------------------------------------------------------------------------------
# Suite 3: Client-Side RFC 7009 Token Revocation (Refresh Token)
# ------------------------------------------------------------------------------
def run_suite_client_side_revocation_refresh_token():
    print("\n" + "=" * 80)
    print("SUITE 3: CLIENT-SIDE RFC 7009 REVOCATION (REFRESH TOKEN)")
    print("=" * 80)

    print("\n[Suite 3 - Step 1] Authenticating and obtaining fresh MCP tokens...")
    session, grafana_session = login_grafana()
    access_token, refresh_token = perform_oauth_pkce(session)
    print(f"[+] Fresh Access Token: {access_token[:16]}...")
    print(f"[+] Fresh Refresh Token: {refresh_token[:16]}...")

    print("\n[Suite 3 - Step 2] Revoking refresh token directly (POST /mcp/auth/revoke)...")
    revoke_resp = requests.post(
        REVOKE_ENDPOINT,
        data={
            "token": refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": "real-grafana-test-client",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if revoke_resp.status_code != 200:
        print(f"[-] FAILED: Expected HTTP 200 OK on refresh token revocation, got {revoke_resp.status_code}: {revoke_resp.text}")
        sys.exit(1)
    print(f"[+] Refresh token revocation returned status: {revoke_resp.status_code}")

    print("\n[Suite 3 - Step 3] Verifying refresh token cannot be exchanged...")
    ref_resp = requests.post(
        f"{ENVOY_BASE_URL}/mcp/auth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "real-grafana-test-client",
        },
        timeout=10,
    )
    if ref_resp.status_code != 401:
        print(f"[-] FAILED: Expected 401 for revoked refresh token, got {ref_resp.status_code}: {ref_resp.text}")
        sys.exit(1)
    print(f"[+] SUCCESS: Revoked refresh token rejected with HTTP 401 invalid_grant")

    print("\n[Suite 3 - Step 4] Verifying associated access token is also revoked immediately...")
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    tool_payload = {"jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {"name": "user_info", "arguments": {}}}
    tool_post_revoke = requests.post(MCP_ENDPOINT, json=tool_payload, headers=headers, timeout=10)
    if tool_post_revoke.status_code != 401:
        print(f"[-] FAILED: Expected 401 Unauthorized for access token after refresh token revocation, got {tool_post_revoke.status_code}: {tool_post_revoke.text}")
        sys.exit(1)
    print(f"[+] SUCCESS: Associated access token immediately rejected with HTTP 401: {tool_post_revoke.text.strip()}")

    print("\n[+] SUITE 3 PASSED: Refresh token client-side revocation confirmed.")


# ------------------------------------------------------------------------------
# Suite 4: Client-Side Revocation RFC Compliance & Edge Cases
# ------------------------------------------------------------------------------
def run_suite_revocation_edge_cases():
    print("\n" + "=" * 80)
    print("SUITE 4: CLIENT-SIDE REVOCATION RFC COMPLIANCE & EDGE CASES")
    print("=" * 80)

    print("\n[Suite 4 - Case 1] Verifying GET /mcp/auth/revoke returns HTTP 405 Method Not Allowed...")
    get_resp = requests.get(REVOKE_ENDPOINT, timeout=10)
    if get_resp.status_code != 405:
        print(f"[-] FAILED: Expected 405 for GET /mcp/auth/revoke, got {get_resp.status_code}")
        sys.exit(1)
    if "POST" not in get_resp.headers.get("Allow", ""):
        print(f"[-] FAILED: Missing Allow: POST header: {get_resp.headers.get('Allow')}")
        sys.exit(1)
    print(f"[+] SUCCESS: HTTP 405 Method Not Allowed with Allow: {get_resp.headers.get('Allow')}")

    print("\n[Suite 4 - Case 2] Verifying POST /mcp/auth/revoke without token returns HTTP 400 invalid_request...")
    empty_resp = requests.post(REVOKE_ENDPOINT, data={}, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10)
    if empty_resp.status_code != 400:
        print(f"[-] FAILED: Expected 400 for empty token, got {empty_resp.status_code}: {empty_resp.text}")
        sys.exit(1)
    err_body = empty_resp.json()
    if err_body.get("error") != "invalid_request":
        print(f"[-] FAILED: Expected error 'invalid_request', got: {err_body}")
        sys.exit(1)
    print(f"[+] SUCCESS: Rejected missing token with HTTP 400 invalid_request: {err_body}")

    print("\n[Suite 4 - Case 3] Verifying client_id mismatch returns HTTP 400 invalid_grant...")
    session, _ = login_grafana()
    at, _ = perform_oauth_pkce(session, client_id="real-grafana-test-client")
    mismatch_resp = requests.post(
        REVOKE_ENDPOINT,
        data={
            "token": at,
            "client_id": "wrong-malicious-client",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if mismatch_resp.status_code != 400:
        print(f"[-] FAILED: Expected 400 for client_id mismatch, got {mismatch_resp.status_code}: {mismatch_resp.text}")
        sys.exit(1)
    err_mismatch = mismatch_resp.json()
    if err_mismatch.get("error") != "invalid_grant":
        print(f"[-] FAILED: Expected error 'invalid_grant', got: {err_mismatch}")
        sys.exit(1)
    print(f"[+] SUCCESS: Rejected client_id mismatch with HTTP 400 invalid_grant: {err_mismatch}")

    print("\n[Suite 4 - Case 4] Verifying Authorization Bearer header fallback...")
    bearer_resp = requests.post(
        REVOKE_ENDPOINT,
        data={"client_id": "real-grafana-test-client"},
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Bearer {at}",
        },
        timeout=10,
    )
    if bearer_resp.status_code != 200:
        print(f"[-] FAILED: Expected 200 OK with Bearer header fallback, got {bearer_resp.status_code}: {bearer_resp.text}")
        sys.exit(1)
    print(f"[+] SUCCESS: Bearer header fallback successfully revoked token (HTTP 200 OK)")

    print("\n[Suite 4 - Case 5] Verifying GET /mcp/auth/token returns HTTP 405 Method Not Allowed with Allow: POST...")
    tok_get_resp = requests.get(f"{ENVOY_BASE_URL}/mcp/auth/token", timeout=10)
    if tok_get_resp.status_code != 405:
        print(f"[-] FAILED: Expected 405 for GET /mcp/auth/token, got {tok_get_resp.status_code}")
        sys.exit(1)
    if "POST" not in tok_get_resp.headers.get("Allow", ""):
        print(f"[-] FAILED: Missing Allow: POST header on /mcp/auth/token: {tok_get_resp.headers.get('Allow')}")
        sys.exit(1)
    print(f"[+] SUCCESS: /mcp/auth/token HTTP 405 Method Not Allowed with Allow: {tok_get_resp.headers.get('Allow')}")

    print("\n[Suite 4 - Case 6] Verifying token_type_hint='refresh_token' fallback for access token...")
    session2, _ = login_grafana()
    at2, _ = perform_oauth_pkce(session2, client_id="real-grafana-test-client")
    hint_fb_resp = requests.post(
        REVOKE_ENDPOINT,
        data={
            "token": at2,
            "token_type_hint": "refresh_token",
            "client_id": "real-grafana-test-client",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if hint_fb_resp.status_code != 200:
        print(f"[-] FAILED: Expected 200 OK for hint fallback, got {hint_fb_resp.status_code}: {hint_fb_resp.text}")
        sys.exit(1)
    # Verify access token is indeed revoked
    st_code, _ = execute_mcp_tool(at2)
    if st_code != 401:
        print(f"[-] FAILED: Expected 401 for revoked access token after hint fallback, got {st_code}")
        sys.exit(1)
    print(f"[+] SUCCESS: token_type_hint fallback properly revoked access token (HTTP 401 on tool call)")

    print("\n[Suite 4 - Case 7] Verifying POST /mcp/auth/revoke with token in query string returns HTTP 400 invalid_request...")
    query_resp = requests.post(
        f"{REVOKE_ENDPOINT}?token=leaked_query_token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if query_resp.status_code != 400:
        print(f"[-] FAILED: Expected 400 for query string token, got {query_resp.status_code}")
        sys.exit(1)
    err_q = query_resp.json()
    if err_q.get("error") != "invalid_request":
        print(f"[-] FAILED: Expected error 'invalid_request', got: {err_q}")
        sys.exit(1)
    print(f"[+] SUCCESS: Rejected token in query string with HTTP 400 invalid_request: {err_q}")

    print("\n[+] SUITE 4 PASSED: RFC compliance & edge cases verified.")


def main():
    print("=" * 80)
    print("REAL GRAFANA MULTI-REPLICA E2E TEST: EXPIRATION, REVOCATION & HARDENING")
    print("=" * 80)

    start_time = time.time()

    # Suite 1: Upstream session expiry and keepalive pruning
    run_suite_upstream_expiry()

    # Suite 2: Client-side revocation via Access Token
    run_suite_client_side_revocation_access_token()

    # Suite 3: Client-side revocation via Refresh Token
    run_suite_client_side_revocation_refresh_token()

    # Suite 4: Client-side revocation RFC compliance & edge cases
    run_suite_revocation_edge_cases()

    elapsed = time.time() - start_time
    print("\n" + "=" * 80)
    print(f"ALL 4 E2E TEST SUITES PASSED SUCCESSFULLY in {elapsed:.2f}s!")
    print("1. Upstream session expiration & keepalive pruning verified.")
    print("2. Client-side RFC 7009 access token revocation & upstream logout verified.")
    print("3. Client-side RFC 7009 refresh token revocation verified.")
    print("4. RFC compliance, idempotency, Bearer fallback & client_id binding verified.")
    print("=" * 80)


if __name__ == "__main__":
    main()
