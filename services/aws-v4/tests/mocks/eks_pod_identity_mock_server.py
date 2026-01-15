#!/usr/bin/env python3
"""
Mock EKS Pod Identity Agent Server

This server simulates the EKS Pod Identity Agent endpoint for testing purposes.
It responds to credential requests at /v1/credentials with Authorization header validation.

The EKS Pod Identity Agent runs at 169.254.170.23:80 on EKS nodes.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime, timedelta


class EKSPodIdentityHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/credentials":
            # Check for Authorization header (required for EKS Pod Identity)
            auth_header = self.headers.get("Authorization")
            if not auth_header:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"message": "Missing Authorization header"}
                self.wfile.write(json.dumps(response).encode())
                return

            # Return mock credentials
            expiration = (datetime.utcnow() + timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            response = {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "IQoJb3JpZ2luX2VjEEKSPodIdentityToken//////////wEaCXVzLWVhc3QtMSJGMEQCIDyJl0YXJwU8iBG4gLVxiNJTYfLp3oFxEOpGGHmQuWmFAiBHEK/GkClQFb0aQ/+kOZkzHKVAPItVJW/VEXAMPLE=",
                "AccountId": "123456789012",
                "Expiration": expiration,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"message": "Not found"}
            self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        # Suppress logs to stderr
        pass


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), EKSPodIdentityHandler)
    print(f"Mock EKS Pod Identity Agent running on port {port}")
    server.serve_forever()
