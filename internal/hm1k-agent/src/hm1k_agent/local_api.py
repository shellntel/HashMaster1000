"""
Local REST API for agent health checks and testing.

Provides endpoints for:
- Health monitoring (for HM1K server to probe)
- Local status queries
- Test job submission (for development/testing)
- Benchmark execution

Runs on localhost by default, can be configured to bind to
all interfaces if needed for remote health checks.
"""

import threading
import time
from dataclasses import asdict
from functools import wraps
from typing import TYPE_CHECKING, Optional
import logging

from flask import Flask, jsonify, request, Response

from hm1k_agent import __version__
from hm1k_agent.config import Config
from hm1k_agent.hardware import refresh_dynamic_info

if TYPE_CHECKING:
    from hm1k_agent.agent import Agent

logger = logging.getLogger(__name__)


def create_app(agent: "Agent") -> Flask:
    """
    Create Flask app with agent reference.

    Args:
        agent: The running agent instance

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    app.config["agent"] = agent

    # Disable Flask's default logging to reduce noise
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    def get_agent() -> "Agent":
        return app.config["agent"]

    def require_api_key(f):
        """Decorator to require API key if configured."""
        @wraps(f)
        def decorated(*args, **kwargs):
            agent = get_agent()
            api_key = agent.config.api.key if hasattr(agent.config, 'api') else None

            if api_key:
                provided_key = request.headers.get("X-API-Key")
                if provided_key != api_key:
                    return jsonify({"error": "Invalid or missing API key"}), 401

            return f(*args, **kwargs)
        return decorated

    # =========================================================================
    # Health & Status Endpoints
    # =========================================================================

    @app.route("/health", methods=["GET"])
    def health():
        """
        Simple health check endpoint.

        Returns 200 if agent is running, 503 if unhealthy.
        Designed for load balancers and monitoring systems.
        """
        agent = get_agent()

        # Check if agent components are healthy
        is_healthy = agent.is_running

        if is_healthy:
            return jsonify({
                "status": "healthy",
                "version": __version__,
                "timestamp": time.time(),
            }), 200
        else:
            return jsonify({
                "status": "unhealthy",
                "version": __version__,
                "timestamp": time.time(),
            }), 503

    @app.route("/status", methods=["GET"])
    @require_api_key
    def status():
        """
        Detailed agent status.

        Returns comprehensive information about the agent state,
        current job, queue, and system resources.
        """
        agent = get_agent()

        current_job = None
        if agent.job_manager.current_job:
            job = agent.job_manager.current_job
            current_job = {
                "job_id": job.job_id,
                "state": job.state.value,
                "progress": job.progress,
                "speed": job.speed,
                "recovered": job.recovered,
                "total_hashes": job.total_hashes,
                "eta_seconds": job.eta_seconds,
                "started_at": job.started_at,
            }

        # Refresh dynamic hardware info (temp, utilization, memory)
        if hasattr(agent, 'hardware'):
            refresh_dynamic_info(agent.hardware)
            hardware_info = agent.hardware.to_dict()
        else:
            hardware_info = None

        return jsonify({
            "agent": {
                "id": agent.config.agent.id,
                "name": agent.config.agent.name,
                "version": __version__,
                "uptime": time.time() - agent._start_time if hasattr(agent, '_start_time') else 0,
            },
            "server": {
                "url": agent.config.server.url,
                "connected": agent.is_connected,
            },
            "hardware": hardware_info,
            "job": current_job,
            "queue_size": agent.job_manager.queue_size,
            "resources": agent.resource_cache.get_stats(),
            "offline_buffer": agent.offline_buffer.get_stats(),
            "hashcat": {
                "binary": agent.config.hashcat.binary,
                "running": agent.hashcat.is_running(),
            },
            "timestamp": time.time(),
        })

    @app.route("/metrics", methods=["GET"])
    def metrics():
        """
        Prometheus-compatible metrics endpoint.

        Returns metrics in Prometheus text format for monitoring integration.
        """
        agent = get_agent()
        current_job = agent.job_manager.current_job

        lines = [
            "# HELP hm1k_agent_info Agent information",
            "# TYPE hm1k_agent_info gauge",
            f'hm1k_agent_info{{version="{__version__}",agent_id="{agent.config.agent.id}"}} 1',
            "",
            "# HELP hm1k_agent_healthy Agent health status",
            "# TYPE hm1k_agent_healthy gauge",
            f"hm1k_agent_healthy {1 if agent.is_running else 0}",
            "",
            "# HELP hm1k_agent_connected Server connection status",
            "# TYPE hm1k_agent_connected gauge",
            f"hm1k_agent_connected {1 if agent.is_connected else 0}",
            "",
            "# HELP hm1k_agent_job_active Current job active",
            "# TYPE hm1k_agent_job_active gauge",
            f"hm1k_agent_job_active {1 if current_job else 0}",
            "",
            "# HELP hm1k_agent_queue_size Jobs in queue",
            "# TYPE hm1k_agent_queue_size gauge",
            f"hm1k_agent_queue_size {agent.job_manager.queue_size}",
            "",
            "# HELP hm1k_agent_offline_buffer_size Buffered messages",
            "# TYPE hm1k_agent_offline_buffer_size gauge",
            f"hm1k_agent_offline_buffer_size {agent.offline_buffer.pending_count}",
            "",
            "# HELP hm1k_agent_cache_size_bytes Resource cache size",
            "# TYPE hm1k_agent_cache_size_bytes gauge",
            f"hm1k_agent_cache_size_bytes {agent.resource_cache.cache_size_bytes}",
        ]

        if current_job:
            lines.extend([
                "",
                "# HELP hm1k_agent_job_progress Current job progress percentage",
                "# TYPE hm1k_agent_job_progress gauge",
                f"hm1k_agent_job_progress {current_job.progress}",
                "",
                "# HELP hm1k_agent_job_speed Current job speed H/s",
                "# TYPE hm1k_agent_job_speed gauge",
                f"hm1k_agent_job_speed {current_job.speed}",
                "",
                "# HELP hm1k_agent_job_recovered Hashes recovered",
                "# TYPE hm1k_agent_job_recovered gauge",
                f"hm1k_agent_job_recovered {current_job.recovered}",
            ])

        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    # =========================================================================
    # Device & Benchmark Endpoints
    # =========================================================================

    @app.route("/devices", methods=["GET"])
    @require_api_key
    def devices():
        """
        List available hashcat devices (GPUs/CPUs).
        """
        agent = get_agent()

        # Run hashcat -I to get device info
        import subprocess
        try:
            result = subprocess.run(
                [agent.config.hashcat.binary, "-I"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return jsonify({
                "success": True,
                "output": result.stdout,
                "devices": [],  # TODO: Parse device info
            })
        except Exception as e:
            return jsonify({
                "success": False,
                "error": str(e),
            }), 500

    @app.route("/benchmark", methods=["GET", "POST"])
    @require_api_key
    def benchmark():
        """
        Run or retrieve benchmark results.

        GET: Return cached benchmark results
        POST: Run new benchmark (with optional hash_mode parameter)
        """
        agent = get_agent()

        if request.method == "POST":
            data = request.get_json() or {}
            hash_mode = data.get("hash_mode", 1000)

            result = agent.hashcat.benchmark(hash_mode)

            if result.success:
                return jsonify({
                    "success": True,
                    "hash_mode": hash_mode,
                    "devices": [
                        {
                            "id": d.id,
                            "name": d.name,
                            "speed": d.speed,
                        }
                        for d in result.devices
                    ],
                    "total_speed": result.total_speed,
                })
            else:
                return jsonify({
                    "success": False,
                    "error": result.error,
                }), 500

        # GET - return cached results or run default benchmark
        return jsonify({
            "message": "POST with hash_mode to run benchmark",
            "example": {"hash_mode": 1000},
        })

    # =========================================================================
    # Job Management Endpoints (for testing)
    # =========================================================================

    @app.route("/job", methods=["GET"])
    @require_api_key
    def get_job():
        """Get current job status."""
        agent = get_agent()
        job = agent.job_manager.current_job

        if not job:
            return jsonify({
                "active": False,
                "message": "No job running",
            })

        return jsonify({
            "active": True,
            "job_id": job.job_id,
            "state": job.state.value,
            "progress": job.progress,
            "speed": job.speed,
            "recovered": job.recovered,
            "total_hashes": job.total_hashes,
            "eta_seconds": job.eta_seconds,
        })

    @app.route("/job/test", methods=["POST"])
    @require_api_key
    def submit_test_job():
        """
        Submit a test job for local testing.

        Uses passthrough model - hashcat_args contains raw hashcat arguments.
        Agent adds managed args (status, potfile, session, output).

        Required: hash_file, hashcat_args
        Example:
            {
                "hash_file": "/path/to/hashes.txt",
                "hashcat_args": ["-m", "3000", "-a", "3", "-1", "?u?d?s", "?1?1?1?1?1?1?1", "-i"]
            }
        """
        agent = get_agent()
        data = request.get_json()

        if not data:
            return jsonify({"error": "JSON body required"}), 400

        required = ["hash_file", "hashcat_args"]
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({"error": f"Missing required fields: {missing}"}), 400

        if not isinstance(data["hashcat_args"], list):
            return jsonify({"error": "hashcat_args must be a list of strings"}), 400

        # Check if job already running
        if agent.job_manager.is_busy:
            return jsonify({
                "error": "Agent is busy",
                "current_job": agent.job_manager.current_job.job_id,
            }), 409

        from hm1k_agent.job_manager import Job
        import uuid

        job = Job(
            job_id=data.get("job_id", f"test-{uuid.uuid4().hex[:8]}"),
            hash_file=data["hash_file"],
            hashcat_args=data["hashcat_args"],
            priority=data.get("priority", 0),
            metadata=data.get("metadata", {}),
        )

        # Start job directly (bypass SSE flow)
        agent.job_manager._start_job(job)

        return jsonify({
            "success": True,
            "job_id": job.job_id,
            "message": "Test job submitted",
        }), 201

    @app.route("/job/stop", methods=["POST"])
    @require_api_key
    def stop_job():
        """Stop the current job."""
        agent = get_agent()

        if not agent.job_manager.is_busy:
            return jsonify({"error": "No job running"}), 404

        job_id = agent.job_manager.current_job.job_id
        agent.job_manager._stop_current_job("Stopped via API")

        return jsonify({
            "success": True,
            "job_id": job_id,
            "message": "Job stopped",
        })

    @app.route("/job/pause", methods=["POST"])
    @require_api_key
    def pause_job():
        """Pause the current job."""
        agent = get_agent()

        if not agent.job_manager.is_busy:
            return jsonify({"error": "No job running"}), 404

        if agent.hashcat.pause_job():
            return jsonify({"success": True, "message": "Job paused"})
        else:
            return jsonify({"error": "Failed to pause job"}), 500

    @app.route("/job/resume", methods=["POST"])
    @require_api_key
    def resume_job():
        """Resume a paused job."""
        agent = get_agent()

        if not agent.job_manager.is_busy:
            return jsonify({"error": "No job running"}), 404

        if agent.hashcat.resume_job():
            return jsonify({"success": True, "message": "Job resumed"})
        else:
            return jsonify({"error": "Failed to resume job"}), 500

    # =========================================================================
    # Resource Verification Endpoint
    # =========================================================================

    @app.route("/verify-resources", methods=["POST"])
    @require_api_key
    def verify_resources():
        """
        Verify that resource files exist and are readable.

        Used before job submission to ensure wordlists, rules, and hash files
        are accessible. Handles symlinks by resolving them and checking the
        target file.

        Request body:
            {
                "paths": ["/path/to/wordlist.txt", "/path/to/rules.rule", ...]
            }

        Returns:
            {
                "success": true/false,
                "results": [
                    {
                        "path": "/path/to/file",
                        "exists": true/false,
                        "readable": true/false,
                        "is_symlink": true/false,
                        "resolved_path": "/actual/path" (if symlink),
                        "size_bytes": 12345 (if exists),
                        "error": "error message" (if any)
                    },
                    ...
                ],
                "all_accessible": true/false
            }
        """
        import os
        from pathlib import Path

        data = request.get_json()
        if not data or "paths" not in data:
            return jsonify({"error": "Missing 'paths' in request body"}), 400

        paths = data["paths"]
        if not isinstance(paths, list):
            return jsonify({"error": "'paths' must be a list"}), 400

        results = []
        all_accessible = True

        for path_str in paths:
            result = {
                "path": path_str,
                "exists": False,
                "readable": False,
                "is_symlink": False,
                "resolved_path": None,
                "size_bytes": None,
                "error": None,
            }

            try:
                path = Path(path_str)

                # Check if it's a symlink
                result["is_symlink"] = path.is_symlink()

                if result["is_symlink"]:
                    # Resolve symlink to get actual path
                    try:
                        resolved = path.resolve(strict=True)
                        result["resolved_path"] = str(resolved)
                        result["exists"] = resolved.exists()
                    except (OSError, FileNotFoundError) as e:
                        result["error"] = f"Broken symlink: {e}"
                        all_accessible = False
                        results.append(result)
                        continue
                else:
                    result["exists"] = path.exists()

                if not result["exists"]:
                    result["error"] = "File does not exist"
                    all_accessible = False
                    results.append(result)
                    continue

                # Check if readable
                actual_path = result["resolved_path"] or path_str
                result["readable"] = os.access(actual_path, os.R_OK)

                if not result["readable"]:
                    result["error"] = "File exists but is not readable (permission denied)"
                    all_accessible = False
                    results.append(result)
                    continue

                # Get file size
                result["size_bytes"] = os.path.getsize(actual_path)

            except Exception as e:
                result["error"] = str(e)
                all_accessible = False

            results.append(result)

        return jsonify({
            "success": True,
            "results": results,
            "all_accessible": all_accessible,
        })

    # =========================================================================
    # Configuration Management Endpoints
    # =========================================================================

    @app.route("/config/hashcat", methods=["GET", "POST"])
    @require_api_key
    def config_hashcat():
        """
        Get or update hashcat configuration.

        GET: Return current hashcat config and available versions
        POST: Update hashcat binary path
            Body: {"binary": "/opt/hashcat/current/hashcat"}
        """
        agent = get_agent()

        if request.method == "GET":
            # Return current config and available versions
            from hm1k_agent.hardware import detect_hashcat_versions
            # Pass configured binary so is_current reflects agent's config, not just symlink
            versions = detect_hashcat_versions(configured_binary=agent.config.hashcat.binary)
            return jsonify({
                "success": True,
                "current": {
                    "binary": agent.config.hashcat.binary,
                },
                "installed_versions": [v.to_dict() for v in versions],
            })

        # POST - update hashcat binary
        data = request.get_json()
        if not data:
            return jsonify({"error": "JSON body required"}), 400

        new_binary = data.get("binary")
        if not new_binary:
            return jsonify({"error": "Missing 'binary' field"}), 400

        # Validate the new binary exists and is executable
        import os
        if not os.path.isfile(new_binary):
            return jsonify({"error": f"Binary not found: {new_binary}"}), 400
        if not os.access(new_binary, os.X_OK):
            return jsonify({"error": f"Binary not executable: {new_binary}"}), 400

        # Update the config file
        try:
            config_path = agent.config._config_path if hasattr(agent.config, '_config_path') else "/etc/hm1k-agent/config.yaml"

            # Read current config
            import yaml
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)

            # Update hashcat binary
            if 'hashcat' not in config_data:
                config_data['hashcat'] = {}
            old_binary = config_data['hashcat'].get('binary', 'unknown')
            config_data['hashcat']['binary'] = new_binary

            # Write updated config
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False)

            # Update in-memory config
            agent.config.hashcat.binary = new_binary

            logger.info(f"Hashcat binary updated: {old_binary} -> {new_binary}")

            return jsonify({
                "success": True,
                "message": f"Hashcat binary updated to {new_binary}",
                "old_binary": old_binary,
                "new_binary": new_binary,
            })

        except Exception as e:
            logger.error(f"Failed to update hashcat config: {e}")
            return jsonify({"error": f"Failed to update config: {e}"}), 500

    return app


class LocalAPIServer:
    """
    Manages the local API server in a background thread.
    """

    def __init__(self, agent: "Agent", config: Config):
        """
        Initialize the API server.

        Args:
            agent: The agent instance
            config: Agent configuration
        """
        self.agent = agent
        self.config = config
        self.app = create_app(agent)
        self._thread: Optional[threading.Thread] = None
        self._running = False

        # Get API config with defaults
        self.host = getattr(config.api, 'host', '127.0.0.1') if hasattr(config, 'api') else '127.0.0.1'
        self.port = getattr(config.api, 'port', 8787) if hasattr(config, 'api') else 8787
        self.enabled = getattr(config.api, 'enabled', True) if hasattr(config, 'api') else True

    def start(self) -> None:
        """Start the API server in a background thread."""
        if not self.enabled:
            logger.info("Local API disabled in config")
            return

        if self._running:
            logger.warning("API server already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        logger.info(f"Local API server started on http://{self.host}:{self.port}")

    def _run_server(self) -> None:
        """Run the Flask server (blocking)."""
        from werkzeug.serving import make_server

        try:
            self.server = make_server(self.host, self.port, self.app, threaded=True)
            self.server.serve_forever()
        except Exception as e:
            logger.error(f"API server error: {e}")
            self._running = False

    def stop(self) -> None:
        """Stop the API server."""
        if not self._running:
            return

        self._running = False
        if hasattr(self, 'server'):
            self.server.shutdown()

        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        logger.info("Local API server stopped")

    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running
