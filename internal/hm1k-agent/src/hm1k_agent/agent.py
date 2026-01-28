"""
Main HM1K Agent daemon class.

Orchestrates all agent components:
- API client for REST communication
- SSE listener for real-time events
- Hashcat runner for job execution
- Job manager for lifecycle management
- Resource cache for wordlist/rule storage
- Offline buffer for resilience
- Local API server for health checks and testing
"""

import signal
import sys
import threading
import time
from typing import Optional
import logging

from hm1k_agent import __version__
from hm1k_agent.config import Config
from hm1k_agent.api_client import APIClient
from hm1k_agent.sse_listener import SSEListener, SSEEvent, EventType
from hm1k_agent.hashcat_runner import HashcatRunner
from hm1k_agent.job_manager import JobManager, JobState
from hm1k_agent.resource_cache import ResourceCache
from hm1k_agent.offline_buffer import OfflineBuffer, MessageType
from hm1k_agent.local_api import LocalAPIServer
from hm1k_agent.hardware import get_system_info, refresh_dynamic_info, get_software_status
from hm1k_agent.potfile_sync import PotfileSync

logger = logging.getLogger(__name__)


class Agent:
    """
    HM1K cracking agent daemon.

    Connects to HM1K server, receives jobs, executes hashcat,
    and reports results. Handles offline operation gracefully.
    """

    def __init__(self, config: Config):
        """
        Initialize the agent with configuration.

        Args:
            config: Agent configuration
        """
        self.config = config
        self._running = False
        self._shutdown_event = threading.Event()
        self._start_time: float = 0

        # Detect system hardware
        self.hardware = get_system_info()
        logger.info(f"Detected hardware: {self.hardware.hostname}, GPUs: {self.hardware.gpu_summary()}")

        # Initialize components
        self.api = APIClient(config)
        self.sse = SSEListener(config)
        self.hashcat = HashcatRunner(config)
        self.resource_cache = ResourceCache(config, self.api)
        self.offline_buffer = OfflineBuffer(config)
        self.potfile_sync = PotfileSync(config, self.api)
        self.job_manager = JobManager(
            config, self.hashcat, self.api, self.sse, self.potfile_sync, self.offline_buffer
        )

        # Local API server for health checks and testing
        self.local_api = LocalAPIServer(self, config)

        # Register additional SSE handlers
        self._register_event_handlers()

        # Set up offline buffer sender
        self.offline_buffer.set_sender(self._send_buffered_message)

        # Heartbeat thread
        self._heartbeat_thread: Optional[threading.Thread] = None

    def _register_event_handlers(self) -> None:
        """Register handlers for non-job SSE events."""
        self.sse.on(EventType.RESOURCE_SYNC, self._on_resource_sync)
        self.sse.on(EventType.SOFTWARE_INSTALL, self._on_software_install)
        self.sse.on(EventType.CONFIG_UPDATE, self._on_config_update)
        self.sse.on(EventType.BENCHMARK, self._on_benchmark)
        self.sse.on(EventType.PING, self._on_ping)

    def _on_resource_sync(self, event) -> None:
        """Handle resource:sync event - new resources available."""
        resource_ids = event.data.get("resources", [])
        if resource_ids:
            logger.info(f"Syncing {len(resource_ids)} resources")
            self.resource_cache.sync_resources(resource_ids)

    def _on_software_install(self, event) -> None:
        """Handle software:install event - install hashcat or driver."""
        data = event.data
        software_type = data.get("software_type")
        version = data.get("version")
        download_url = data.get("download_url")
        sha256 = data.get("sha256")
        make_current = data.get("make_current", True)

        logger.info(f"Received software install request: {software_type} {version}")

        if software_type == "hashcat":
            self._install_hashcat(
                download_url=download_url,
                version=version,
                sha256=sha256,
                make_current=make_current,
            )
        elif software_type in ["nvidia", "amd"]:
            logger.warning(f"Driver installation ({software_type}) requires manual intervention")
            # Driver installation is complex and requires root/reboot
            # For now, just log - could implement in future
        else:
            logger.warning(f"Unknown software type: {software_type}")

    def _install_hashcat(
        self,
        download_url: str,
        version: str,
        sha256: str,
        make_current: bool = True,
    ) -> bool:
        """
        Download and install a hashcat version.

        Args:
            download_url: URL to download from (relative to server)
            version: Hashcat version string
            sha256: Expected SHA256 hash
            make_current: Whether to set as current version

        Returns:
            True if installation succeeded
        """
        import hashlib
        import tarfile
        import py7zr
        import tempfile
        import shutil

        logger.info(f"Installing hashcat {version}...")

        # Installation directories
        install_base = "/opt/hashcat"
        install_dir = os.path.join(install_base, f"hashcat-{version}")
        current_link = os.path.join(install_base, "current")

        try:
            # Download the package
            full_url = f"{self.config.server.url}{download_url}"
            logger.info(f"Downloading from {full_url}")

            response = self.api._session.get(
                full_url,
                stream=True,
                timeout=600,  # 10 minute timeout for large files
            )
            response.raise_for_status()

            # Save to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".archive") as tmp:
                tmp_path = tmp.name
                for chunk in response.iter_content(chunk_size=8192):
                    tmp.write(chunk)

            # Verify hash
            computed_hash = hashlib.sha256()
            with open(tmp_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    computed_hash.update(chunk)

            if computed_hash.hexdigest() != sha256:
                logger.error(f"Hash mismatch: expected {sha256}, got {computed_hash.hexdigest()}")
                os.unlink(tmp_path)
                return False

            logger.info("Download complete, hash verified")

            # Ensure install base exists
            os.makedirs(install_base, exist_ok=True)

            # Extract archive
            logger.info(f"Extracting to {install_dir}")

            # Create temp extraction dir
            with tempfile.TemporaryDirectory() as extract_dir:
                if tmp_path.endswith(".7z") or download_url.endswith(".7z"):
                    with py7zr.SevenZipFile(tmp_path, mode="r") as archive:
                        archive.extractall(path=extract_dir)
                elif tmp_path.endswith(".tar.gz") or download_url.endswith(".tar.gz"):
                    with tarfile.open(tmp_path, "r:gz") as archive:
                        archive.extractall(path=extract_dir)
                elif tmp_path.endswith(".zip") or download_url.endswith(".zip"):
                    import zipfile
                    with zipfile.ZipFile(tmp_path, "r") as archive:
                        archive.extractall(extract_dir)
                else:
                    # Try 7z first, then tar.gz
                    try:
                        with py7zr.SevenZipFile(tmp_path, mode="r") as archive:
                            archive.extractall(path=extract_dir)
                    except Exception:
                        with tarfile.open(tmp_path, "r:gz") as archive:
                            archive.extractall(path=extract_dir)

                # Find the hashcat directory (usually hashcat-X.X.X)
                extracted_items = os.listdir(extract_dir)
                if len(extracted_items) == 1 and os.path.isdir(os.path.join(extract_dir, extracted_items[0])):
                    src_dir = os.path.join(extract_dir, extracted_items[0])
                else:
                    src_dir = extract_dir

                # Remove existing installation if present
                if os.path.exists(install_dir):
                    shutil.rmtree(install_dir)

                # Move to final location
                shutil.move(src_dir, install_dir)

            # Clean up temp file
            os.unlink(tmp_path)

            # Make hashcat executable
            hashcat_bin = os.path.join(install_dir, "hashcat")
            if os.path.exists(hashcat_bin):
                os.chmod(hashcat_bin, 0o755)

            # Update current symlink if requested
            if make_current:
                if os.path.islink(current_link):
                    os.unlink(current_link)
                elif os.path.exists(current_link):
                    shutil.rmtree(current_link)
                os.symlink(install_dir, current_link)
                logger.info(f"Set {version} as current version")

            logger.info(f"Hashcat {version} installed successfully")

            # Refresh software status cache
            from hm1k_agent.hardware import get_software_status
            get_software_status(refresh=True)

            return True

        except Exception as e:
            logger.error(f"Failed to install hashcat: {e}")
            return False

    def _on_config_update(self, event) -> None:
        """Handle config:update event - server changed agent config."""
        # For now, just log. Could reload config in future.
        logger.info("Config update received from server")

    def _on_ping(self, event) -> None:
        """Handle ping event - server checking connectivity."""
        logger.debug("Received ping from server")

    def _on_benchmark(self, event) -> None:
        """Handle benchmark event - server requesting benchmark run."""
        hash_modes = event.data.get("hash_modes")
        logger.info(f"Received benchmark request from server (modes: {hash_modes or 'all'})")
        # Run benchmark in background thread to not block other events
        thread = threading.Thread(target=self.run_benchmark, args=(hash_modes,))
        thread.daemon = True
        thread.start()

    def _send_buffered_message(self, msg_type: MessageType, payload: dict) -> bool:
        """
        Send a buffered message (callback for OfflineBuffer).

        Args:
            msg_type: Type of message
            payload: Message data

        Returns:
            True if sent successfully
        """
        try:
            if msg_type == MessageType.HEARTBEAT:
                return self.api.send_heartbeat(payload)
            elif msg_type == MessageType.JOB_STATUS:
                return self.api.send_job_status(
                    payload.pop("job_id"),
                    payload,
                )
            elif msg_type == MessageType.JOB_COMPLETE:
                return self.api.report_job_complete(
                    payload.get("job_id"),
                    payload.get("potfile_content", ""),
                    payload.get("stats", {}),
                )
            elif msg_type == MessageType.JOB_ERROR:
                return self.api.report_job_error(
                    payload.get("job_id"),
                    payload.get("error", "Unknown error"),
                    payload.get("logs"),
                )
            elif msg_type == MessageType.BENCHMARK:
                return self.api.report_benchmark(payload)
            else:
                logger.warning(f"Unknown message type: {msg_type}")
                return True  # Don't retry unknown types
        except Exception as e:
            logger.warning(f"Failed to send buffered message: {e}")
            return False

    def start(self) -> None:
        """
        Start the agent daemon.

        Connects to server, starts all components, and begins
        processing jobs. Blocks until stop() is called.
        """
        if self._running:
            logger.warning("Agent already running")
            return

        logger.info(f"Starting HM1K Agent v{__version__}")
        logger.info(f"Agent ID: {self.config.agent.id}")
        logger.info(f"Server: {self.config.server.url}")

        self._running = True
        self._start_time = time.time()
        self._shutdown_event.clear()

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        try:
            # Test server connection
            if not self.api.test_connection():
                logger.error("Failed to connect to server")
                # Continue anyway - offline buffer will queue messages
                logger.warning("Running in offline mode")

            # Start components
            self.offline_buffer.start()
            self.job_manager.start()
            self.sse.start()
            self.local_api.start()

            # Start heartbeat
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True,
            )
            self._heartbeat_thread.start()

            logger.info("Agent started successfully")

            # Send initial heartbeat
            self._send_heartbeat()

            # Wait for shutdown
            self._shutdown_event.wait()

        except Exception as e:
            logger.error(f"Agent error: {e}")
            raise
        finally:
            self._cleanup()

    def stop(self) -> None:
        """Stop the agent gracefully."""
        logger.info("Stopping agent...")
        self._running = False
        self._shutdown_event.set()

    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}")
        self.stop()

    def _cleanup(self) -> None:
        """Clean up all components."""
        logger.info("Cleaning up...")

        # Stop components in reverse order
        self.local_api.stop()
        self.sse.stop()
        self.job_manager.stop()
        self.offline_buffer.stop()

        logger.info("Agent stopped")

    def _heartbeat_loop(self) -> None:
        """Background thread to send periodic heartbeats."""
        while self._running:
            try:
                self._send_heartbeat()
            except Exception as e:
                logger.warning(f"Heartbeat error: {e}")

            # Wait for next heartbeat interval
            for _ in range(self.config.timing.heartbeat_interval):
                if not self._running:
                    break
                time.sleep(1)

    def _send_heartbeat(self) -> None:
        """Send heartbeat to server."""
        heartbeat_data = self._build_heartbeat()

        try:
            result = self.api.send_heartbeat(heartbeat_data)
            if result.success:
                logger.debug("Heartbeat sent")
                # Process any pending commands from the heartbeat response
                if result.pending_commands:
                    self._process_heartbeat_commands(result.pending_commands)
            else:
                # Queue for later
                self.offline_buffer.queue(
                    MessageType.HEARTBEAT,
                    heartbeat_data,
                )
        except Exception as e:
            logger.warning(f"Failed to send heartbeat: {e}")
            self.offline_buffer.queue(
                MessageType.HEARTBEAT,
                heartbeat_data,
            )

    def _process_heartbeat_commands(self, commands: list) -> None:
        """
        Process commands received via heartbeat response.

        Commands are converted to SSEEvent format and dispatched through
        the same handlers that process SSE events, ensuring consistent
        behavior whether jobs arrive via SSE or heartbeat.

        Args:
            commands: List of command dicts from heartbeat response
        """
        for cmd in commands:
            try:
                event_type_str = cmd.get("type", "unknown")
                event_type = EventType.from_string(event_type_str)
                data = cmd.get("data", {})

                logger.info(f"Processing heartbeat command: {event_type_str}")

                # Create SSEEvent to pass to handlers
                event = SSEEvent(
                    event_type=event_type,
                    data=data,
                )

                # Dispatch to registered handlers via SSE listener
                handlers = self.sse._handlers.get(event_type, [])
                for handler in handlers:
                    try:
                        handler(event)
                    except Exception as e:
                        logger.error(f"Command handler error: {e}")

            except Exception as e:
                logger.error(f"Failed to process heartbeat command: {e}")

    def _build_heartbeat(self) -> dict:
        """Build heartbeat payload with current status."""
        current_job = self.job_manager.current_job

        # Refresh dynamic hardware info
        refresh_dynamic_info(self.hardware)

        # Get software status (cached, refreshed periodically)
        software_status = get_software_status()

        return {
            "agent_id": self.config.agent.id,
            "agent_name": self.config.agent.name,
            "version": __version__,
            "timestamp": time.time(),
            "status": {
                "state": "busy" if current_job else "idle",
                "current_job": current_job.job_id if current_job else None,
                "job_state": current_job.state.value if current_job else None,
                "queue_size": self.job_manager.queue_size,
            },
            "hardware": self.hardware.to_dict(),
            "software": software_status.to_dict(),
            "resources": {
                "cache_size_mb": self.resource_cache.cache_size_mb,
                "cached_count": len(self.resource_cache.cached_resources),
            },
            "offline_buffer": {
                "pending": self.offline_buffer.pending_count,
            },
        }

    def run_benchmark(self, hash_modes: list[int] = None) -> dict:
        """
        Run hashcat benchmark for multiple hash modes and report to server.

        Args:
            hash_modes: List of hash modes to benchmark. If None, uses common modes.

        Returns:
            Dictionary with benchmark results
        """
        from datetime import datetime

        logger.info("Running comprehensive hashcat benchmark...")

        # Run benchmarks for all specified hash modes
        results = self.hashcat.benchmark_all(hash_modes)

        # Get hashcat version
        hashcat_version = self.hashcat.get_hashcat_version()

        # Build report data
        successful_results = [r for r in results if r.success]
        benchmark_data = {
            "agent_id": self.config.agent.id,
            "timestamp": datetime.now().isoformat(),
            "hashcat_version": hashcat_version,
            "results": [r.to_dict() for r in successful_results],
        }

        logger.info(f"Benchmark complete: {len(successful_results)}/{len(results)} hash types tested")

        # Report to server
        try:
            if self.api.report_benchmark(benchmark_data):
                logger.info("Benchmark results reported to server")
            else:
                logger.warning("Failed to report benchmark to server, queuing for later")
                self.offline_buffer.queue(MessageType.BENCHMARK, benchmark_data)
        except Exception as e:
            logger.warning(f"Failed to report benchmark: {e}")
            self.offline_buffer.queue(MessageType.BENCHMARK, benchmark_data)

        return benchmark_data

    @property
    def is_running(self) -> bool:
        """Check if agent is running."""
        return self._running

    @property
    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self.sse.is_connected

    @property
    def is_busy(self) -> bool:
        """Check if processing a job."""
        return self.job_manager.is_busy

    def get_status(self) -> dict:
        """
        Get comprehensive agent status.

        Returns:
            Dictionary with agent status
        """
        current_job = self.job_manager.current_job

        # Refresh dynamic hardware info (temp, utilization, memory)
        refresh_dynamic_info(self.hardware)

        return {
            "agent": {
                "id": self.config.agent.id,
                "name": self.config.agent.name,
                "version": __version__,
                "running": self._running,
            },
            "server": {
                "url": self.config.server.url,
                "connected": self.sse.is_connected,
            },
            "job": {
                "current": current_job.job_id if current_job else None,
                "state": current_job.state.value if current_job else "idle",
                "progress": current_job.progress if current_job else 0,
                "queue_size": self.job_manager.queue_size,
            },
            "hardware": self.hardware.to_dict(),
            "resources": self.resource_cache.get_stats(),
            "offline_buffer": self.offline_buffer.get_stats(),
            "hashcat": {
                "binary": self.config.hashcat.binary,
            },
        }
