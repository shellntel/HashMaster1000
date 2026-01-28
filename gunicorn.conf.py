"""
Gunicorn Configuration for Hash Master 1000

This configuration enables production-grade multi-user support with:
- Multiple worker processes for concurrent users
- Hybrid threading model for optimal performance
- Worker lifecycle management for resilience
- HTTPS support with SSL certificates
- Logging for monitoring and debugging

Usage:
    gunicorn -c gunicorn.conf.py hm1k:app

For systemd service, see: docs/systemd/hm1k.service
"""

import os
import multiprocessing
import signal
import sys

# Paths - define early so they can be used throughout config
# Use absolute paths for production (systemd service)
# Falls back to relative paths for local development
_app_dir = os.environ.get("HM1K_APP_DIR", os.path.dirname(os.path.abspath(__file__)))
_log_dir = os.environ.get("HM1K_LOG_DIR", os.path.join(_app_dir, "logs"))

# Server Socket
bind = "0.0.0.0:8443"
backlog = 2048

# Worker Processes
# Default: 4 workers for small/single-user deployments
# Set HM1K_WORKERS environment variable to increase for high-traffic servers
workers = int(os.environ.get("HM1K_WORKERS", 4))

# Worker Class
# 'gthread' = hybrid threading model (best for I/O-bound operations)
# Each worker can handle multiple requests via threads
worker_class = "gthread"
threads = 2  # Threads per worker (total concurrent requests = workers * threads)

# Timeouts
# Reduced from 900s to prevent worker zombie accumulation
# Long-running AAIA analysis should use background processing instead
timeout = 120  # 2 minutes - most requests should complete in this time
graceful_timeout = 30  # Time to wait for graceful shutdown
keepalive = 5

# SSL/HTTPS
# SSL is enabled by default for secure standalone deployments
# Set HM1K_SSL=false when running behind a reverse proxy (nginx) that handles SSL
if os.environ.get("HM1K_SSL", "").lower() in ("false", "0", "no"):
    certfile = None
    keyfile = None
else:
    certfile = os.path.join(_app_dir, "cert.pem")
    keyfile = os.path.join(_app_dir, "key.pem")

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
# Increased from 1000 to reduce worker restart frequency
# Workers that restart during requests can cause zombie accumulation
max_requests = 5000  # Restart workers after N requests (prevents memory leaks)
max_requests_jitter = 500  # Add randomness to prevent all workers restarting at once

# Worker Abort Behavior
# When a worker exceeds timeout, this controls how it's terminated
# SIGTERM = graceful, SIGKILL = forceful
worker_tmp_dir = "/dev/shm"  # Use shared memory for worker heartbeat (faster)

# SSL/Security
# Trust nginx reverse proxy for X-Forwarded-* headers
forwarded_allow_ips = "127.0.0.1"

# Preload Application
# Load application code before worker processes are forked
# Saves memory but makes code reloading harder
preload_app = False  # Set to True for production, False for development

# Ensure log directory exists BEFORE any logging starts
os.makedirs(_log_dir, exist_ok=True)


# =============================================================================
# Worker Lifecycle Hooks - for monitoring and debugging
# =============================================================================

def on_starting(server):
    """Callback when Gunicorn master starts."""
    print(f"[HM1K] Starting with {workers} workers, {threads} threads per worker")
    print(f"[HM1K] Total concurrent capacity: {workers * threads} requests")
    print(f"[HM1K] Worker timeout: {timeout}s")
    print(f"[HM1K] Max requests per worker: {max_requests} (jitter: {max_requests_jitter})")


def on_reload(server):
    """Callback when master receives SIGHUP for reload."""
    print("[HM1K] Reloading configuration...")


def when_ready(server):
    """Callback when master is ready to accept connections."""
    print(f"[HM1K] Server ready at {bind}")


def worker_int(worker):
    """Callback when worker receives SIGINT/SIGQUIT."""
    print(f"[HM1K] Worker {worker.pid} interrupted")


def worker_abort(worker):
    """Callback when worker is aborted (SIGABRT)."""
    print(f"[HM1K] CRITICAL: Worker {worker.pid} aborted - likely timeout or crash")
    # Log to error file for later analysis
    try:
        import datetime
        with open(os.path.join(_log_dir, "worker_aborts.log"), "a") as f:
            f.write(f"{datetime.datetime.now().isoformat()} Worker {worker.pid} aborted\n")
    except Exception:
        pass


def pre_fork(server, worker):
    """Callback before forking a new worker."""
    pass


def post_fork(server, worker):
    """Callback after forking a new worker."""
    print(f"[HM1K] Worker {worker.pid} forked")


def post_worker_init(worker):
    """Callback after worker has initialized."""
    print(f"[HM1K] Worker {worker.pid} initialized and ready")


def worker_exit(server, worker):
    """Callback when a worker exits."""
    print(f"[HM1K] Worker {worker.pid} exited")


def nworkers_changed(server, new_value, old_value):
    """Callback when number of workers changes."""
    if old_value is None:
        # Initial worker count set during startup
        return
    if new_value < old_value:
        print(f"[HM1K] WARNING: Worker count decreased: {old_value} -> {new_value}")
    else:
        print(f"[HM1K] Worker count changed: {old_value} -> {new_value}")


def child_exit(server, worker):
    """Callback when a worker child process exits."""
    print(f"[HM1K] Child worker {worker.pid} exited")
