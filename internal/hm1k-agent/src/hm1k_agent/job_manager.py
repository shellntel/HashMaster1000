"""
Job lifecycle management for HM1K agent.

Handles the complete lifecycle of cracking jobs:
- Receiving job assignments via SSE
- Starting hashcat with proper configuration
- Monitoring progress and reporting status
- Handling pause/resume/stop commands
- Completing or failing jobs with proper cleanup
"""

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional
import logging

from hm1k_agent.config import Config
from hm1k_agent.hashcat_runner import HashcatRunner, HashcatStatus, JobConfig
from hm1k_agent.api_client import APIClient, JobStatusUpdate
from hm1k_agent.sse_listener import SSEListener, SSEEvent, EventType
from hm1k_agent.potfile_sync import PotfileSync
from hm1k_agent.offline_buffer import OfflineBuffer, MessageType

logger = logging.getLogger(__name__)


class JobState(Enum):
    """States a job can be in."""

    PENDING = "pending"  # Job received, not yet started
    PREPARING = "preparing"  # Downloading resources
    RUNNING = "running"  # Hashcat actively cracking
    PAUSED = "paused"  # Hashcat paused (SIGUSR1)
    STOPPING = "stopping"  # Graceful stop in progress
    COMPLETED = "completed"  # Job finished successfully
    FAILED = "failed"  # Job failed with error
    CANCELLED = "cancelled"  # Job cancelled by user/server


@dataclass
class Job:
    """Represents a cracking job.

    Uses passthrough model - hashcat_args contains raw arguments
    from the server. Agent doesn't need to understand hashcat options.
    """

    job_id: str
    hash_file: str
    hashcat_args: list[str]  # Raw hashcat args from server
    priority: int = 0
    state: JobState = JobState.PENDING
    progress: float = 0.0
    speed: int = 0
    recovered: int = 0
    total_hashes: int = 0
    eta_seconds: Optional[int] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error_message: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    # Performance tracking fields
    speed_samples: list[float] = field(default_factory=list)
    peak_speed: float = 0.0
    gpu_temps: list[int] = field(default_factory=list)  # Max temps observed
    gpu_utils: list[int] = field(default_factory=list)  # Utilization readings
    gpu_speeds: list[float] = field(default_factory=list)  # Current speed per GPU
    keyspace_total: int = 0
    keyspace_processed: int = 0
    time_start: Optional[int] = None  # Unix timestamp when hashcat started
    # Multi-mask progress
    mask_current: int = 0  # Current mask index (1-based)
    mask_total: int = 0  # Total number of masks
    mask_pattern: Optional[str] = None  # Current mask pattern

    @classmethod
    def from_sse_event(cls, event: SSEEvent, jobs_dir: str = "/var/lib/hm1k-agent/jobs") -> "Job":
        """Create Job from SSE job:assigned event data.

        If hash_content is provided instead of hash_file, saves the content
        to a local file in the jobs directory.

        For NTLM toggle jobs (workflow step), also handles:
        - wordlist_content/wordlist_filename in metadata
        - rules_content/rules_filename in metadata
        """
        import os
        from pathlib import Path

        data = event.data
        job_id = data["job_id"]
        metadata = data.get("metadata", {})
        hashcat_args = list(data.get("hashcat_args", []))  # Make a copy

        # Ensure job directory exists
        job_dir = Path(jobs_dir) / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        # Handle hash_content (uploaded file) vs hash_file (remote path)
        if "hash_content" in data:
            # Save uploaded hash content to local file
            filename = data.get("hash_filename", "hashes.txt")
            hash_file = str(job_dir / filename)

            with open(hash_file, "w") as f:
                f.write(data["hash_content"])

            logger.info(f"Saved uploaded hashes to {hash_file}")
        else:
            hash_file = data["hash_file"]

        # Handle NTLM job special files from metadata
        # Supports both ntlm_toggle (uses rules) and ntlm_expanded (pre-computed permutations)
        if metadata.get("job_type") in ("ntlm_toggle", "ntlm_expanded"):
            # Save wordlist if provided
            if "wordlist_content" in metadata:
                wordlist_filename = metadata.get("wordlist_filename", "wordlist.txt")
                wordlist_path = str(job_dir / wordlist_filename)

                # Use latin-1 encoding to preserve extended ASCII characters from LM hashes
                with open(wordlist_path, "w", encoding="latin-1") as f:
                    f.write(metadata["wordlist_content"])

                # Add wordlist to hashcat args (after -a 0)
                # Find position after attack mode
                try:
                    a_idx = hashcat_args.index("-a")
                    insert_pos = a_idx + 2  # After "-a 0"
                except ValueError:
                    insert_pos = len(hashcat_args)

                hashcat_args.insert(insert_pos, wordlist_path)
                logger.info(f"Saved wordlist to {wordlist_path}")

            # Save rules file if provided
            if "rules_content" in metadata:
                rules_filename = metadata.get("rules_filename", "rules.rule")
                rules_path = str(job_dir / rules_filename)

                with open(rules_path, "w") as f:
                    f.write(metadata["rules_content"])

                # Add rules to hashcat args
                hashcat_args.extend(["-r", rules_path])
                logger.info(f"Saved rules to {rules_path}")

        # Handle mask file content for brute force attacks with mask groups
        if "mask_file_content" in metadata:
            mask_filename = metadata.get("mask_filename", "masks.hcmask")
            mask_path = str(job_dir / mask_filename)

            # Parse charset definitions from mask file content
            # Format: ?1=charset, ?2=charset, etc. at the beginning of the file
            mask_content = metadata["mask_file_content"]
            charset_args: list[str] = []
            clean_lines: list[str] = []

            for line in mask_content.split("\n"):
                stripped = line.strip()
                # Check for charset definition: ?N=charset where N is 1-4
                if stripped.startswith("?") and "=" in stripped and len(stripped) > 2:
                    # Extract charset number and value (e.g., "?2=0123456789")
                    try:
                        charset_num = stripped[1]
                        if charset_num in "1234" and stripped[2] == "=":
                            charset_value = stripped[3:]
                            if charset_value:
                                charset_args.extend([f"-{charset_num}", charset_value])
                                logger.info(f"Extracted charset -{charset_num} {charset_value}")
                                continue  # Don't include in mask file
                    except (IndexError, ValueError):
                        pass
                # Skip comment lines and empty lines for clean output
                if stripped and not stripped.startswith("#"):
                    clean_lines.append(stripped)

            # Write cleaned mask file (without charset definitions)
            with open(mask_path, "w") as f:
                f.write("\n".join(clean_lines))

            # Add charset args BEFORE the mask file path
            hashcat_args.extend(charset_args)

            # Add mask file to hashcat args (at the end, as it's the attack target)
            hashcat_args.append(mask_path)
            logger.info(f"Saved mask file to {mask_path} ({len(clean_lines)} masks)")

        return cls(
            job_id=job_id,
            hash_file=hash_file,
            hashcat_args=hashcat_args,
            priority=data.get("priority", 0),
            metadata=metadata,
        )

    def to_job_config(self) -> JobConfig:
        """Convert to HashcatRunner JobConfig."""
        return JobConfig(
            job_id=self.job_id,
            hash_file=self.hash_file,
            hashcat_args=self.hashcat_args,
        )


# Type alias for job state change callbacks
JobStateCallback = Callable[[Job, JobState, JobState], None]


class JobManager:
    """
    Manages the lifecycle of cracking jobs.

    Coordinates between:
    - SSE listener (receiving commands)
    - Hashcat runner (executing jobs)
    - API client (reporting status)
    """

    def __init__(
        self,
        config: Config,
        hashcat_runner: HashcatRunner,
        api_client: APIClient,
        sse_listener: SSEListener,
        potfile_sync: Optional[PotfileSync] = None,
        offline_buffer: Optional[OfflineBuffer] = None,
    ):
        """
        Initialize the job manager.

        Args:
            config: Agent configuration
            hashcat_runner: Hashcat execution manager
            api_client: REST API client for status reporting
            sse_listener: SSE event listener
            potfile_sync: Potfile synchronization manager (optional)
            offline_buffer: Buffer for queuing messages when server is unreachable
        """
        self.config = config
        self.hashcat = hashcat_runner
        self.api = api_client
        self.sse = sse_listener
        self.potfile_sync = potfile_sync
        self.offline_buffer = offline_buffer

        self._current_job: Optional[Job] = None
        self._job_queue: list[Job] = []
        self._lock = threading.Lock()
        self._running = False
        self._status_thread: Optional[threading.Thread] = None
        self._state_callbacks: list[JobStateCallback] = []

        # Register SSE handlers
        self._register_sse_handlers()

    def _register_sse_handlers(self) -> None:
        """Register handlers for job-related SSE events."""
        self.sse.on(EventType.JOB_ASSIGNED, self._on_job_assigned)
        self.sse.on(EventType.JOB_PAUSE, self._on_job_pause)
        self.sse.on(EventType.JOB_RESUME, self._on_job_resume)
        self.sse.on(EventType.JOB_STOP, self._on_job_stop)

    def on_state_change(self, callback: JobStateCallback) -> None:
        """
        Register a callback for job state changes.

        Args:
            callback: Function called with (job, old_state, new_state)
        """
        self._state_callbacks.append(callback)

    def _notify_state_change(self, job: Job, old_state: JobState, new_state: JobState) -> None:
        """Notify all registered callbacks of a state change."""
        for callback in self._state_callbacks:
            try:
                callback(job, old_state, new_state)
            except Exception as e:
                logger.error(f"State change callback error: {e}")

    def _set_job_state(self, job: Job, new_state: JobState) -> None:
        """Update job state and notify callbacks."""
        old_state = job.state
        if old_state != new_state:
            job.state = new_state
            logger.info(f"Job {job.job_id} state: {old_state.value} -> {new_state.value}")
            self._notify_state_change(job, old_state, new_state)

    def start(self) -> None:
        """Start the job manager."""
        if self._running:
            logger.warning("Job manager already running")
            return

        self._running = True
        self._status_thread = threading.Thread(target=self._status_loop, daemon=True)
        self._status_thread.start()
        logger.info("Job manager started")

    def stop(self) -> None:
        """Stop the job manager and any running job."""
        self._running = False

        # Stop current job if any
        if self._current_job:
            self._stop_current_job("Agent shutting down")

        if self._status_thread:
            self._status_thread.join(timeout=5)
            self._status_thread = None

        logger.info("Job manager stopped")

    def _on_job_assigned(self, event: SSEEvent) -> None:
        """Handle job:assigned SSE event."""
        try:
            job = Job.from_sse_event(event, jobs_dir=self.config.resources.jobs_dir)
            logger.info(f"Job assigned: {job.job_id} (hash_file={job.hash_file})")

            with self._lock:
                if self._current_job:
                    # Queue the job if one is already running
                    self._job_queue.append(job)
                    self._job_queue.sort(key=lambda j: j.priority, reverse=True)
                    logger.info(f"Job {job.job_id} queued (position {len(self._job_queue)})")
                else:
                    # Start immediately
                    self._start_job(job)

        except Exception as e:
            logger.error(f"Failed to handle job assignment: {e}")
            # Report error to server
            if "job_id" in event.data:
                job_id = event.data["job_id"]
                error_msg = str(e)
                try:
                    success = self.api.report_job_error(job_id, error_msg)
                    if not success:
                        raise Exception("Server returned failure")
                except Exception as report_err:
                    logger.warning(f"Failed to report job assignment error: {report_err}")
                    if self.offline_buffer:
                        self.offline_buffer.queue(
                            MessageType.JOB_ERROR,
                            {"job_id": job_id, "error": error_msg, "logs": None},
                            job_id=job_id,
                        )

    def _on_job_pause(self, event: SSEEvent) -> None:
        """Handle job:pause SSE event."""
        job_id = event.data.get("job_id")

        with self._lock:
            if not self._current_job or self._current_job.job_id != job_id:
                logger.warning(f"Received pause for unknown job: {job_id}")
                return

            if self._current_job.state != JobState.RUNNING:
                logger.warning(f"Cannot pause job in state: {self._current_job.state.value}")
                return

            if self.hashcat.pause_job():
                self._set_job_state(self._current_job, JobState.PAUSED)
                self._report_status()
            else:
                logger.error(f"Failed to pause job {job_id}")

    def _on_job_resume(self, event: SSEEvent) -> None:
        """Handle job:resume SSE event."""
        job_id = event.data.get("job_id")

        with self._lock:
            if not self._current_job or self._current_job.job_id != job_id:
                logger.warning(f"Received resume for unknown job: {job_id}")
                return

            if self._current_job.state != JobState.PAUSED:
                logger.warning(f"Cannot resume job in state: {self._current_job.state.value}")
                return

            if self.hashcat.resume_job():
                self._set_job_state(self._current_job, JobState.RUNNING)
                self._report_status()
            else:
                logger.error(f"Failed to resume job {job_id}")

    def _on_job_stop(self, event: SSEEvent) -> None:
        """Handle job:stop SSE event."""
        job_id = event.data.get("job_id")
        reason = event.data.get("reason", "Stopped by server")

        with self._lock:
            if self._current_job and self._current_job.job_id == job_id:
                self._stop_current_job(reason, cancelled=True)
            else:
                # Check queue
                self._job_queue = [j for j in self._job_queue if j.job_id != job_id]
                logger.info(f"Removed queued job {job_id}")

    def _start_job(self, job: Job) -> None:
        """Start executing a job (must hold lock)."""
        self._current_job = job
        self._set_job_state(job, JobState.PREPARING)

        try:
            # Sync potfile before starting job to get latest cracked hashes
            if self.potfile_sync:
                if not self.potfile_sync.sync_before_job():
                    logger.warning("Potfile sync failed before job, continuing anyway")

            # TODO: Download resources via ResourceCache if needed
            # For now, assume resources are already available

            job.started_at = time.time()
            job_config = job.to_job_config()

            if self.hashcat.start_job(job_config):
                self._set_job_state(job, JobState.RUNNING)
                logger.info(f"Job {job.job_id} started")
            else:
                raise RuntimeError("Failed to start hashcat process")

        except Exception as e:
            logger.error(f"Failed to start job {job.job_id}: {e}")
            self._fail_job(str(e))

    def _stop_current_job(self, reason: str, cancelled: bool = False) -> None:
        """Stop the current job (must hold lock or be called at shutdown)."""
        if not self._current_job:
            return

        job = self._current_job
        self._set_job_state(job, JobState.STOPPING)

        self.hashcat.stop_job()
        job.completed_at = time.time()

        if cancelled:
            self._set_job_state(job, JobState.CANCELLED)
            job.error_message = reason
        else:
            self._set_job_state(job, JobState.COMPLETED)

        self._report_completion()
        self._current_job = None
        self._start_next_job()

    def _fail_job(self, error: str) -> None:
        """Mark current job as failed (must hold lock)."""
        if not self._current_job:
            return

        job = self._current_job
        job.error_message = error
        job.completed_at = time.time()
        self._set_job_state(job, JobState.FAILED)

        # Get hashcat output logs for debugging
        logs = self.hashcat.get_output_logs(max_lines=100)

        try:
            success = self.api.report_job_error(job.job_id, error, logs)
            if not success:
                raise Exception("Server returned failure")
        except Exception as e:
            logger.warning(f"Failed to report job error: {e}")
            # Queue for retry when server is available
            if self.offline_buffer:
                self.offline_buffer.queue(
                    MessageType.JOB_ERROR,
                    {
                        "job_id": job.job_id,
                        "error": error,
                        "logs": logs,
                    },
                    job_id=job.job_id,
                )
                logger.info(f"Queued error report for job {job.job_id} for later retry")

        # Sync potfile after failed job - may have cracked some hashes before failing
        if self.potfile_sync:
            if not self.potfile_sync.sync_after_job():
                logger.warning("Potfile sync failed after job failure")

        self._current_job = None
        self._start_next_job()

    def _start_next_job(self) -> None:
        """Start the next queued job if any (must hold lock)."""
        if self._job_queue:
            next_job = self._job_queue.pop(0)
            logger.info(f"Starting next queued job: {next_job.job_id}")
            self._start_job(next_job)

    def _status_loop(self) -> None:
        """Background thread to monitor job status and report to server."""
        while self._running:
            try:
                with self._lock:
                    if self._current_job and self._current_job.state == JobState.RUNNING:
                        self._update_job_status()

                time.sleep(self.config.timing.status_interval)

            except Exception as e:
                logger.error(f"Status loop error: {e}")
                time.sleep(5)

    def _update_job_status(self) -> None:
        """Read hashcat status and update current job (must hold lock)."""
        if not self._current_job:
            return

        try:
            status = self.hashcat.get_latest_status()
            if status:
                self._apply_status(status)
                self._report_status()

            # Only mark complete when hashcat process actually exits.
            # Don't use status codes (5=Exhausted, 6=Cracked) because
            # increment mode reports Exhausted for each increment level.
            # Check if hashcat process has exited
            if not self.hashcat.is_running():
                if self._current_job and self._current_job.state == JobState.RUNNING:
                    logger.info("Hashcat process exited")
                    self._complete_job()

        except Exception as e:
            logger.error(f"Failed to read hashcat status: {e}")

    def _apply_status(self, status: HashcatStatus) -> None:
        """Apply hashcat status to current job and track performance metrics."""
        job = self._current_job
        if not job:
            return

        job.progress = status.progress_percent
        job.speed = int(status.speed_total)
        job.recovered = status.recovered_hashes[0]  # cracked count
        job.total_hashes = status.recovered_hashes[1]  # total count
        job.eta_seconds = status.estimated_stop

        # Track keyspace progress from raw JSON if available
        if status.raw_json:
            job.keyspace_total = status.progress[1] if status.progress else 0
            job.keyspace_processed = status.progress[0] if status.progress else 0

        # Track speed samples for performance analysis (limit to last 100)
        if status.speed_total > 0:
            job.speed_samples.append(status.speed_total)
            if len(job.speed_samples) > 100:
                job.speed_samples.pop(0)

            # Track peak speed
            if status.speed_total > job.peak_speed:
                job.peak_speed = status.speed_total

        # Track time_start from hashcat
        if status.time_start and not job.time_start:
            job.time_start = status.time_start

        # Track multi-mask progress
        job.mask_current = status.mask_current
        job.mask_total = status.mask_total
        job.mask_pattern = status.mask_pattern

        # Track GPU metrics
        for device in status.devices:
            if device.temp is not None:
                # Track max temp per GPU
                while len(job.gpu_temps) <= device.id:
                    job.gpu_temps.append(0)
                if device.temp > job.gpu_temps[device.id]:
                    job.gpu_temps[device.id] = device.temp

            if device.util is not None:
                # Track utilization (we'll average at the end)
                while len(job.gpu_utils) <= device.id:
                    job.gpu_utils.append(0)
                # Keep running sum for averaging (simplified approach)
                job.gpu_utils[device.id] = device.util

            # Track current speed per GPU
            while len(job.gpu_speeds) <= device.id:
                job.gpu_speeds.append(0.0)
            job.gpu_speeds[device.id] = device.speed

    def _report_status(self) -> None:
        """Report current job status to server."""
        job = self._current_job
        if not job:
            return

        # Get hashcat version for status updates
        hashcat_version = self.hashcat.get_hashcat_version()

        status = JobStatusUpdate(
            job_id=job.job_id,
            status=job.state.value,
            progress_percent=job.progress,
            speed_hashes_per_sec=job.speed,
            recovered_hashes=job.recovered,
            total_hashes=job.total_hashes,
            eta_seconds=job.eta_seconds,
            gpu_temps=job.gpu_temps if job.gpu_temps else None,
            gpu_utils=job.gpu_utils if job.gpu_utils else None,
            gpu_speeds=job.gpu_speeds if job.gpu_speeds else None,
            hashcat_version=hashcat_version,
            time_start=job.time_start,
            mask_current=job.mask_current,
            mask_total=job.mask_total,
            mask_pattern=job.mask_pattern,
        )

        try:
            self.api.send_job_status(status)
        except Exception as e:
            logger.warning(f"Failed to report status: {e}")

    def _complete_job(self) -> None:
        """Mark current job as completed (must hold lock)."""
        if not self._current_job:
            return

        job = self._current_job
        job.completed_at = time.time()
        self._set_job_state(job, JobState.COMPLETED)

        self._report_completion()
        self._current_job = None
        self._start_next_job()

    def _report_completion(self) -> None:
        """Report job completion to server including performance metrics."""
        job = self._current_job
        if not job:
            return

        potfile_content = self.hashcat.get_potfile_content() or ""
        duration = (job.completed_at or time.time()) - (job.started_at or time.time())

        # Get hashcat output logs - useful for debugging issues
        logs = self.hashcat.get_output_logs(max_lines=100)

        # Detect warnings/errors in hashcat output
        warnings = self._detect_hashcat_warnings(logs, job, duration)

        stats = {
            "state": job.state.value,
            "recovered": job.recovered,
            "total_hashes": job.total_hashes,
            "duration_seconds": duration,
            "error_message": job.error_message,
            "hashcat_logs": logs,
            "warnings": warnings,
        }

        try:
            success = self.api.report_job_complete(job.job_id, potfile_content, stats)
            if not success:
                raise Exception("Server returned failure")
        except Exception as e:
            logger.warning(f"Failed to report completion: {e}")
            # Queue for retry when server is available
            if self.offline_buffer:
                self.offline_buffer.queue(
                    MessageType.JOB_COMPLETE,
                    {
                        "job_id": job.job_id,
                        "potfile_content": potfile_content,
                        "stats": stats,
                    },
                    job_id=job.job_id,
                )
                logger.info(f"Queued completion report for job {job.job_id} for later retry")

        # Sync potfile after job to upload newly cracked hashes
        if self.potfile_sync:
            if not self.potfile_sync.sync_after_job():
                logger.warning("Potfile sync failed after job completion")

        # Report performance metrics
        self._report_performance_metrics(job, duration)

    def _detect_hashcat_warnings(self, logs: str, job: "Job", duration: float) -> list[str]:
        """Detect warnings and issues in hashcat output."""
        warnings = []
        logs_lower = logs.lower()

        # Common hashcat error patterns
        error_patterns = [
            ("no hashes loaded", "No hashes loaded - check hash file format"),
            ("separator unmatched", "Separator unmatched - invalid hash format"),
            ("line-length exception", "Line-length exception - hash format error"),
            ("token length exception", "Token length exception - hash format error"),
            ("salt-length exception", "Salt-length exception - hash format error"),
            ("signature unmatched", "Signature unmatched - wrong hash type"),
            ("hashfile corrupt", "Hash file corrupt or invalid"),
            ("cannot open wordlist", "Cannot open wordlist file"),
            ("cannot open mask", "Cannot open mask file"),
        ]

        for pattern, message in error_patterns:
            if pattern in logs_lower:
                warnings.append(message)

        # Check for suspicious completion (very short with 0 cracks)
        # Only flag if we expected to crack something (had hashes)
        if job.total_hashes and job.total_hashes > 0:
            if job.recovered == 0 and duration < 30:
                # Very short job with 0 cracks - might be an issue
                if "exhausted" not in logs_lower and "all hashes found" not in logs_lower:
                    warnings.append("Job completed very quickly with 0 cracks - check for issues")

        # Check for CUDA/driver warnings (not necessarily fatal but worth noting)
        if "cuda sdk toolkit not installed" in logs_lower:
            warnings.append("CUDA SDK not installed - using OpenCL fallback")

        return warnings

    def _report_performance_metrics(self, job: Job, duration: float) -> None:
        """Report job performance metrics to server."""
        from datetime import datetime

        # Calculate average speed from samples
        avg_speed = sum(job.speed_samples) / len(job.speed_samples) if job.speed_samples else 0

        # Calculate average GPU utilization
        avg_util = sum(job.gpu_utils) / len(job.gpu_utils) if job.gpu_utils else None
        max_temp = max(job.gpu_temps) if job.gpu_temps else None

        # Extract hash_mode and attack_mode from hashcat_args
        hash_mode = 0
        attack_mode = 0
        wordlist_path = None
        mask_used = None
        rules_used = []

        args = job.hashcat_args
        for i, arg in enumerate(args):
            if arg == "-m" and i + 1 < len(args):
                try:
                    hash_mode = int(args[i + 1])
                except ValueError:
                    pass
            elif arg == "-a" and i + 1 < len(args):
                try:
                    attack_mode = int(args[i + 1])
                except ValueError:
                    pass
            elif arg == "-r" and i + 1 < len(args):
                rules_used.append(args[i + 1])
            elif arg.startswith("?") or ("?" in arg and "/" not in arg):
                # Likely a mask
                mask_used = arg
            elif "/" in arg and not arg.startswith("-"):
                # Likely a wordlist path
                if not wordlist_path:
                    wordlist_path = arg

        # Build performance metrics
        metrics = {
            "agent_id": self.config.agent.id,
            "job_id": job.job_id,
            "hash_mode": hash_mode,
            "attack_mode": attack_mode,
            "started_at": datetime.fromtimestamp(job.started_at).isoformat() if job.started_at else None,
            "completed_at": datetime.fromtimestamp(job.completed_at).isoformat() if job.completed_at else None,
            "duration_seconds": duration,
            "total_hashes": job.total_hashes,
            "hashes_cracked": job.recovered,
            "keyspace_total": job.keyspace_total,
            "keyspace_processed": job.keyspace_processed,
            "avg_speed_hs": avg_speed,
            "peak_speed_hs": job.peak_speed,
            "speed_samples": job.speed_samples[-20:],  # Last 20 samples
            "max_gpu_temp": max_temp,
            "avg_gpu_util": avg_util,
            "wordlist_path": wordlist_path,
            "rules_used": rules_used if rules_used else None,
            "mask_used": mask_used,
        }

        try:
            if self.api.report_job_performance(metrics):
                logger.debug(f"Performance metrics reported for job {job.job_id}")
            else:
                logger.warning(f"Failed to report performance metrics for job {job.job_id}")
        except Exception as e:
            logger.warning(f"Failed to report performance metrics: {e}")

    @property
    def current_job(self) -> Optional[Job]:
        """Get the currently running job."""
        with self._lock:
            return self._current_job

    @property
    def queue_size(self) -> int:
        """Get the number of queued jobs."""
        with self._lock:
            return len(self._job_queue)

    @property
    def is_busy(self) -> bool:
        """Check if agent is currently processing a job."""
        with self._lock:
            return self._current_job is not None
