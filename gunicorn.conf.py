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

# Server Socket
bind = "0.0.0.0:8443"
backlog = 2048

# Worker Processes
# Calculate workers based on CPU cores: (2 x num_cores) + 1
workers = multiprocessing.cpu_count() * 2 + 1
# For small teams (2-5 users), you can use a fixed number:
# workers = 4

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
# Uses the same SSL certificates as Flask dev server
certfile = "cert.pem"
keyfile = "key.pem"

# Logging
accesslog = "logs/gunicorn_access.log"
errorlog = "logs/gunicorn_error.log"
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
forwarded_allow_ips = "*"  # Trust all proxies (adjust if behind Nginx)
# For production behind Nginx, set: forwarded_allow_ips = "127.0.0.1"

# Preload Application
# Load application code before worker processes are forked
# Saves memory but makes code reloading harder
preload_app = False  # Set to True for production, False for development

# Worker Connections (for async workers only - not used with gthread)
# worker_connections = 1000

# Ensure log directory exists BEFORE any logging starts
import os
os.makedirs("logs", exist_ok=True)

def on_starting(server):
    """Callback when Gunicorn master starts."""
    print(f"Starting HM1K with {workers} workers, {threads} threads per worker")
    print(f"Total concurrent capacity: {workers * threads} requests")
    print(f"Timeout set to {timeout}s for long-running AAIA analysis")
