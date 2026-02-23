#!/usr/bin/env python3
"""
Mock server for OpenStack Keystone v3 Identity API.

This server simulates the Keystone v3 authentication endpoint for testing
the reqsign-openstack-keystone credential provider.
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


MOCK_TOKEN = "mock-keystone-token-{timestamp}"

MOCK_CATALOG = [
    {
        "type": "object-store",
        "endpoints": [
            {
                "interface": "public",
                "url": "http://127.0.0.1:8080/v1/AUTH_test",
                "region": "RegionOne",
                "region_id": "RegionOne",
            },
            {
                "interface": "internal",
                "url": "http://swift-internal:8080/v1/AUTH_test",
                "region": "RegionOne",
                "region_id": "RegionOne",
            },
        ],
    },
    {
        "type": "identity",
        "endpoints": [
            {
                "interface": "public",
                "url": "http://127.0.0.1:5000/v3",
                "region": "RegionOne",
                "region_id": "RegionOne",
            },
        ],
    },
]


class KeystoneHandler(BaseHTTPRequestHandler):
    """Handler for Keystone v3 identity API requests."""

    def do_POST(self):
        """Handle POST requests (authentication)."""
        if self.path == "/v3/auth/tokens":
            self.handle_auth_tokens()
        else:
            self.send_error(404, "Not Found")

    def do_GET(self):
        """Handle GET requests (version discovery)."""
        if self.path == "/v3/" or self.path == "/v3":
            self.handle_version_discovery()
        else:
            self.send_error(404, "Not Found")

    def handle_auth_tokens(self):
        """Authenticate and return a token."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        # Validate the request structure
        auth = data.get("auth", {})
        identity = auth.get("identity", {})
        methods = identity.get("methods", [])

        if "password" not in methods:
            self.send_error(400, "Only password authentication is supported")
            return

        password_info = identity.get("password", {})
        user = password_info.get("user", {})
        username = user.get("name", "")
        password = user.get("password", "")

        if not username or not password:
            self.send_error(401, "Invalid credentials")
            return

        # Reject known-bad credentials for testing
        if password == "wrong-password":
            self.send_error(401, "Invalid credentials")
            return

        # Generate token response
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=1)
        token_value = MOCK_TOKEN.format(timestamp=int(now.timestamp()))

        # Check if scope is present — scoped tokens get the catalog,
        # unscoped tokens get an empty catalog (matching real Keystone behavior).
        scope = auth.get("scope")
        has_scope = scope and "project" in scope

        response = {
            "token": {
                "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "issued_at": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "methods": ["password"],
                "user": {
                    "name": username,
                    "domain": user.get("domain", {"name": "Default"}),
                },
                "catalog": MOCK_CATALOG if has_scope else [],
            }
        }

        if has_scope:
            response["token"]["project"] = {
                "name": scope["project"].get("name", ""),
                "domain": scope["project"].get("domain", {"name": "Default"}),
            }

        response_body = json.dumps(response).encode()

        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Subject-Token", token_value)
        self.end_headers()
        self.wfile.write(response_body)

    def handle_version_discovery(self):
        """Return version discovery information."""
        response = {
            "version": {
                "id": "v3.14",
                "status": "stable",
                "links": [
                    {
                        "rel": "self",
                        "href": f"http://127.0.0.1:{self.server.server_port}/v3/",
                    }
                ],
            }
        }

        response_body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        """Override to provide custom logging format."""
        sys.stderr.write(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}\n"
        )


def run_server(port=5000):
    """Run the mock Keystone server."""
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, KeystoneHandler)
    print(f"Mock Keystone Server running on http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop")
    print("")
    print("Test with:")
    print(f"  curl -X POST http://127.0.0.1:{port}/v3/auth/tokens \\")
    print('    -H "Content-Type: application/json" \\')
    print(
        '    -d \'{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"test","password":"test","domain":{"name":"Default"}}}}}}\''
    )
    print("")
    httpd.serve_forever()


if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port)
