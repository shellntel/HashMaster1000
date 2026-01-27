"""
Gunicorn Configuration for Hash Master 1000

This configuration enables production-grade multi-user support with:
- Multiple worker processes for concurrent users
- Hybrid threading model for optimal performance
- Extended timeout for long-running AAIA analysis
- HTTPS support with SSL certificates
- Logging for monitoring and debugging

Usage:
    gunicorn -c gunicorn.conf.py hm1k:app

For systemd service, see: docs/systemd/hm1k.service
"""

import os
import multiprocessing

# Paths - define early so they can be used throughout config
# Use absolute paths for production (systemd service)
# Falls back to relative paths for local development
_app_dir = os.environ.get("HM1K_APP_DIR", os.path.dirname(os.path.abspath(__file__)))
_log_dir = os.environ.get("HM1K_LOG_DIR", os.path.join(_app_dir, "logs"))

# Server Socket
bind = "0.0.0.0:8443"
backlog = 2048

# Worker Processes
# Calculate workers based on CPU cores: (2 x num_cores) + 1
# workers = multiprocessing.cpu_count() * 2 + 1
# Optimized for high-performance server (i9-13900K, 64GB RAM)
workers = 12  # 12 workers × 2 threads = 24 concurrent request capacity

# Worker Class
# 'gthread' = hybrid threading model (best for I/O-bound operations like AAIA)
# Each worker can handle multiple requests via threads
worker_class = "gthread"
threads = 2  # Threads per worker (total concurrent requests = workers * threads)

# Timeouts
# Extended timeout for long-running AAIA analysis (up to 15 minutes)
timeout = 900  # 15 minutes in seconds
graceful_timeout = 30
keepalive = 5

# SSL/HTTPS
# When running behind nginx, SSL is handled by nginx - no certs needed here
# Set HM1K_SSL=true for local development with HTTPS (not behind nginx)
if os.environ.get("HM1K_SSL", "").lower() in ("true", "1", "yes"):
    certfile = os.path.join(_app_dir, "cert.pem")
    keyfile = os.path.join(_app_dir, "key.pem")
else:
    certfile = None
    keyfile = None

# Logging
accesslog = os.path.join(_log_dir, "gunicorn_access.log")
errorlog = os.path.join(_log_dir, "gunicorn_error.log")
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process Naming
proc_name = "hm1k"

# Server Mechanics
daemon = False  # Run in foreground (use systemd for daemonization)
pidfile = None  # Let systemd manage PID
umask = 0
user = None  # Run as current user (or set to 'hm1k' if you create a dedicated user)
group = None
tmp_upload_dir = None

# Worker Lifecycle
max_requests = 1000  # Restart workers after N requests (prevents memory leaks)
max_requests_jitter = 50  # Add randomness to prevent all workers restarting at once

# SSL/Security
# Trust nginx reverse proxy for X-Forwarded-* headers
forwarded_allow_ips = "127.0.0.1"

# Preload Application
# Load application code before worker processes are forked
# Saves memory but makes code reloading harder
preload_app = False  # Set to True for production, False for development

# Worker Connections (for async workers only - not used with gthread)
# worker_connections = 1000

# Ensure log directory exists BEFORE any logging starts
# Uses absolute path determined above
os.makedirs(_log_dir, exist_ok=True)

def on_starting(server):
    """Callback when Gunicorn master starts."""
    print(f"Starting HM1K with {workers} workers, {threads} threads per worker")
    print(f"Total concurrent capacity: {workers * threads} requests")
    print(f"Timeout set to {timeout}s for long-running AAIA analysis")
