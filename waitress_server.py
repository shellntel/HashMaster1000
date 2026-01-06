"""
Waitress Production Server for Hash Master 1000 (Windows-compatible)

Waitress is a production-grade WSGI server that works on Windows, Linux, and macOS.
It provides multi-threading for concurrent user support without Unix-specific dependencies.

Usage:
    python waitress_server.py

For Linux/macOS, you can still use Gunicorn for better performance:
    gunicorn -c gunicorn.conf.py hm1k:app

Configuration:
- Threads: 8 concurrent requests (adjust based on CPU cores and expected load)
- Timeout: 900 seconds (15 minutes) for long-running AAIA analysis
- Port: 8443 (HTTPS)
- Host: 0.0.0.0 (all interfaces)

For systemd service on Windows (via NSSM), see: docs/MULTI_USER_DEPLOYMENT.md
"""

from waitress import serve
from hm1k import app
import os
import sys

def main():
    # Ensure required directories exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs("data/sessions", exist_ok=True)
    os.makedirs("flask_session", exist_ok=True)

    # Configuration
    host = "0.0.0.0"
    port = 8443
    threads = 8  # Concurrent request capacity
    timeout = 900  # 15 minutes for long AAIA runs

    # Startup banner
    print("=" * 70)
    print("Hash Master 1000 - Waitress Production Server")
    print("=" * 70)
    print(f"Server:          Waitress (Windows/Linux/macOS compatible)")
    print(f"Listening on:    https://{host}:{port}")
    print(f"Threads:         {threads} (concurrent request capacity)")
    print(f"Timeout:         {timeout}s (15 minutes for AAIA analysis)")
    print(f"Environment:     {'Windows' if sys.platform == 'win32' else sys.platform}")
    print("=" * 70)
    print("Press Ctrl+C to stop the server")
    print("=" * 70)
    print()

    try:
        serve(
            app,
            host=host,
            port=port,
            threads=threads,
            channel_timeout=timeout,
            url_scheme='https',
            ident='HM1K/1.0',
            # Waitress-specific tuning
            asyncore_use_poll=True,  # Better performance on Windows
            connection_limit=1000,   # Max simultaneous connections
            cleanup_interval=30,     # Clean up idle connections every 30s
            recv_bytes=8192,         # Receive buffer size
            send_bytes=8192          # Send buffer size
        )
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("Server stopped by user")
        print("=" * 70)
    except Exception as e:
        print("\n" + "=" * 70)
        print(f"ERROR: Server failed to start: {e}")
        print("=" * 70)
        sys.exit(1)

if __name__ == '__main__':
    main()
