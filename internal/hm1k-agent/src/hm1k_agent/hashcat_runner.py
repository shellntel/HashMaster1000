"""
Hashcat subprocess management.

Handles:
- Starting hashcat with proper arguments
- Parsing --status-json output
- Managing hashcat process lifecycle
- Benchmark execution
"""

import json
import subprocess
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Iterator
import logging
import signal

from hm1k_agent.config import Config

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Information about a hashcat device (GPU/CPU)."""

    id: int
    name: str
    device_type: str  # GPU, CPU
    speed: float  # Hashes per second
    temp: Optional[int] = None  # Temperature in Celsius
    util: Optional[int] = None  # Utilization percentage


@dataclass
class HashcatStatus:
    """Parsed status from hashcat --status-json output."""

    status: int  # 0=init, 1=autotune, 2=selftest, 3=running, 5=exhausted, 6=cracked, 7=aborted
    status_text: str
    progress: tuple[int, int]  # (current, total)
    progress_percent: float
    speed_total: float  # Total H/s across all devices
    recovered_hashes: tuple[int, int]  # (cracked, total)
    time_start: int  # Unix timestamp
    estimated_stop: Optional[int]  # Unix timestamp
    devices: list[DeviceInfo] = field(default_factory=list)
    raw_json: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> "HashcatStatus":
        """Parse status from hashcat JSON output."""
        status_map = {
            0: "Initializing",
            1: "Autotuning",
            2: "Self-test",
            3: "Running",
            4: "Paused",
            5: "Exhausted",
            6: "Cracked",
            7: "Aborted",
            8: "Quit",
            9: "Bypass",
        }

        status_code = data.get("status", 0)
        progress = data.get("progress", [0, 1])
        recovered = data.get("recovered_hashes", [0, 1])

        # Parse device info
        devices = []
        for dev in data.get("devices", []):
            devices.append(
                DeviceInfo(
                    id=dev.get("device_id", 0),
                    name=dev.get("device_name", "Unknown"),
                    device_type=dev.get("device_type", "GPU"),
                    speed=dev.get("speed", 0),
                    temp=dev.get("temp"),
                    util=dev.get("util"),
                )
            )

        # Calculate total speed
        speed_total = sum(d.speed for d in devices)

        # Calculate progress percent
        if progress[1] > 0:
            progress_percent = (progress[0] / progress[1]) * 100
        else:
            progress_percent = 0

        return cls(
            status=status_code,
            status_text=status_map.get(status_code, "Unknown"),
            progress=tuple(progress),
            progress_percent=progress_percent,
            speed_total=speed_total,
            recovered_hashes=tuple(recovered),
            time_start=data.get("time_start", 0),
            estimated_stop=data.get("estimated_stop"),
            devices=devices,
            raw_json=data,
        )


@dataclass
class BenchmarkResult:
    """Result of a hashcat benchmark."""

    success: bool
    hash_mode: int
    devices: list[DeviceInfo] = field(default_factory=list)
    total_speed: float = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for API reporting."""
        return {
            "success": self.success,
            "hash_mode": self.hash_mode,
            "total_speed_hs": self.total_speed,
            "gpus": [
                {
                    "gpu_index": d.id,
                    "gpu_name": d.name,
                    "speed_hs": d.speed,
                    "temperature": d.temp,
                    "utilization": d.util,
                }
                for d in self.devices
            ],
            "error": self.error,
        }


@dataclass
class JobConfig:
    """Configuration for a hashcat cracking job.

    Uses passthrough model - the server builds the hashcat command,
    agent just adds managed args for monitoring and session control.
    """

    job_id: str
    hash_file: str
    hashcat_args: list[str]  # Raw hashcat arguments from server (e.g. ["-m", "3000", "-a", "3", "?a?a?a?a"])


class HashcatRunner:
    """
    Manages hashcat subprocess execution.

    Uses --status-json for machine-readable status output, avoiding
    the need for screen session manipulation.
    """

    def __init__(self, config: Config):
        """
        Initialize hashcat runner.

        Args:
            config: Agent configuration
        """
        self.config = config
        self.hashcat_binary = config.hashcat.binary
        self.workdir = Path(config.hashcat.workdir)
        self.status_timer = config.hashcat.status_timer
        self._process: Optional[subprocess.Popen] = None
        self._current_job: Optional[JobConfig] = None
        self._latest_status: Optional[HashcatStatus] = None
        self._status_thread: Optional[threading.Thread] = None
        self._potfile_start_lines: int = 0  # Track potfile size at job start
        self._output_lines: list[str] = []  # Capture non-JSON output for error reporting
        self._output_lock = threading.Lock()  # Protect output_lines access

    def verify_hashcat(self) -> tuple[bool, str]:
        """
        Verify hashcat is installed and working.

        Returns:
            Tuple of (success, version_string or error)
        """
        if not shutil.which(self.hashcat_binary):
            return False, f"Hashcat not found at {self.hashcat_binary}"

        try:
            result = subprocess.run(
                [self.hashcat_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            version = result.stdout.strip()
            return True, version
        except Exception as e:
            return False, str(e)

    def detect_devices(self) -> list[DeviceInfo]:
        """
        Detect available hashcat devices.

        Returns:
            List of available devices
        """
        try:
            # Ensure workdir exists for any hashcat output
            self.workdir.mkdir(parents=True, exist_ok=True)

            result = subprocess.run(
                [self.hashcat_binary, "-I", "--machine-readable"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self.workdir),
            )

            devices = []
            # Parse -I output (format varies by version)
            # For now, return empty and let benchmark fill in details
            return devices
        except Exception as e:
            logger.error(f"Failed to detect devices: {e}")
            return []

    def benchmark(self, hash_mode: int = 1000) -> BenchmarkResult:
        """
        Run hashcat benchmark for a specific hash mode.

        Args:
            hash_mode: Hash mode to benchmark (default: 1000 NTLM)

        Returns:
            BenchmarkResult with device speeds
        """
        try:
            # Ensure workdir exists for hashcat to write session files
            self.workdir.mkdir(parents=True, exist_ok=True)

            result = subprocess.run(
                [
                    self.hashcat_binary,
                    "-b",
                    "-m", str(hash_mode),
                    "--machine-readable",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(self.workdir),
            )

            if result.returncode != 0:
                return BenchmarkResult(
                    success=False,
                    hash_mode=hash_mode,
                    error=result.stderr or "Benchmark failed",
                )

            # Parse benchmark output
            # Format: device_id:hash_type:device_clock:device_processors:runtime_ms:speed
            # Example: 1:1000:2505:10801:8.38:159577977818
            devices = []
            total_speed = 0

            for line in result.stdout.strip().split("\n"):
                if not line or line.startswith("#") or line.startswith("*") or line.startswith("Success"):
                    continue

                parts = line.split(":")
                if len(parts) >= 6:
                    device_id = int(parts[0])
                    speed = float(parts[5])  # Speed is the 6th field
                    devices.append(
                        DeviceInfo(
                            id=device_id,
                            name=f"Device {device_id}",
                            device_type="GPU",
                            speed=speed,
                        )
                    )
                    total_speed += speed

            return BenchmarkResult(
                success=True,
                hash_mode=hash_mode,
                devices=devices,
                total_speed=total_speed,
            )

        except subprocess.TimeoutExpired:
            return BenchmarkResult(
                success=False,
                hash_mode=hash_mode,
                error="Benchmark timed out",
            )
        except Exception as e:
            return BenchmarkResult(
                success=False,
                hash_mode=hash_mode,
                error=str(e),
            )

    def start_job(self, job: JobConfig) -> bool:
        """
        Start a hashcat cracking job.

        Args:
            job: Job configuration

        Returns:
            True if job started successfully
        """
        if self._process and self._process.poll() is None:
            logger.error("Cannot start job: another job is running")
            return False

        # Create job working directory
        job_dir = self.workdir / job.job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        # Build command with managed args + passthrough args from server
        # Managed args: status monitoring, potfile, session, output file
        # Use the synced potfile path from config so hashcat skips already-cracked hashes
        potfile_path = self.config.resources.potfile_path

        # Track potfile line count before starting so we can report only new cracks
        self._potfile_start_lines = self._count_potfile_lines(potfile_path)
        logger.debug(f"Potfile has {self._potfile_start_lines} entries before job start")

        # Use sessions_dir for hashcat session files (avoids permission issues with hashcat install dir)
        sessions_dir = Path(self.config.resources.sessions_dir)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        # Sanitize session name - hashcat only allows alphanumeric characters
        session_name = job.job_id.replace("-", "_")
        session_path = str(sessions_dir / session_name)

        cmd = [
            self.hashcat_binary,
            "--status",
            "--status-json",
            "--status-timer", str(self.status_timer),
            "--potfile-path", potfile_path,
            "--session", session_path,
            "-o", str(job_dir / "cracked.txt"),
            job.hash_file,
        ]

        # Passthrough: add all hashcat args from server verbatim
        cmd.extend(job.hashcat_args)

        # Add any extra args from agent config (optional global overrides)
        if self.config.hashcat.extra_args:
            cmd.extend(self.config.hashcat.extra_args.split())

        logger.info(f"Starting hashcat job: {' '.join(cmd)}")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(job_dir),
            )
            self._current_job = job
            self._latest_status = None

            # Clear output buffer for new job
            with self._output_lock:
                self._output_lines = []

            # Start background thread to read status updates
            self._status_thread = threading.Thread(
                target=self._status_reader_loop,
                daemon=True,
            )
            self._status_thread.start()

            return True
        except Exception as e:
            logger.error(f"Failed to start hashcat: {e}")
            return False

    def _status_reader_loop(self) -> None:
        """Background thread to read and cache hashcat status updates."""
        for status in self.read_status():
            self._latest_status = status
            logger.debug(f"Hashcat status: progress={status.progress_percent:.1f}%, speed={status.speed_total}")

    def get_latest_status(self) -> Optional[HashcatStatus]:
        """
        Get the latest cached hashcat status.

        Returns:
            Most recent HashcatStatus, or None if no status available
        """
        return self._latest_status

    def read_status(self) -> Iterator[HashcatStatus]:
        """
        Read status updates from running hashcat process.

        Yields HashcatStatus objects as they are parsed from
        the --status-json output stream. Also captures non-JSON
        output for error reporting.

        Yields:
            HashcatStatus objects
        """
        if not self._process or not self._process.stdout:
            return

        buffer = ""
        for line in self._process.stdout:
            line = line.strip()
            if not line:
                continue

            # Look for JSON status output
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    yield HashcatStatus.from_json(data)
                except json.JSONDecodeError:
                    # Not valid JSON, might be partial
                    buffer = line
            elif buffer:
                # Try to complete partial JSON
                buffer += line
                try:
                    data = json.loads(buffer)
                    yield HashcatStatus.from_json(data)
                    buffer = ""
                except json.JSONDecodeError:
                    if len(buffer) > 10000:
                        buffer = ""  # Reset if too large
            else:
                # Non-JSON output - capture for error reporting
                with self._output_lock:
                    self._output_lines.append(line)
                    # Limit to last 500 lines to prevent memory issues
                    if len(self._output_lines) > 500:
                        self._output_lines.pop(0)
                logger.debug(f"Hashcat output: {line}")

    def pause_job(self) -> bool:
        """
        Pause the running job.

        Returns:
            True if pause signal sent successfully
        """
        if not self._process or self._process.poll() is not None:
            return False

        try:
            # Send SIGUSR1 to pause hashcat
            self._process.send_signal(signal.SIGUSR1)
            return True
        except Exception as e:
            logger.error(f"Failed to pause job: {e}")
            return False

    def resume_job(self) -> bool:
        """
        Resume a paused job.

        Returns:
            True if resume signal sent successfully
        """
        if not self._process or self._process.poll() is not None:
            return False

        try:
            # Send SIGUSR2 to resume hashcat
            self._process.send_signal(signal.SIGUSR2)
            return True
        except Exception as e:
            logger.error(f"Failed to resume job: {e}")
            return False

    def stop_job(self) -> bool:
        """
        Stop the running job gracefully.

        Returns:
            True if stop signal sent successfully
        """
        if not self._process or self._process.poll() is not None:
            return False

        try:
            # Send SIGINT for graceful shutdown (saves session)
            self._process.send_signal(signal.SIGINT)

            # Wait up to 30 seconds for graceful exit
            try:
                self._process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                # Force kill if needed
                self._process.kill()
                self._process.wait()

            return True
        except Exception as e:
            logger.error(f"Failed to stop job: {e}")
            return False

    def _count_potfile_lines(self, potfile_path: str) -> int:
        """Count lines in a potfile."""
        try:
            path = Path(potfile_path)
            if not path.exists():
                return 0
            with open(path, "r", errors="ignore") as f:
                return sum(1 for line in f if line.strip())
        except Exception as e:
            logger.warning(f"Failed to count potfile lines: {e}")
            return 0

    def get_potfile_content(self) -> Optional[str]:
        """
        Get newly cracked entries from the potfile (cracked during this job only).

        Returns only entries added during this job, not the full potfile history.

        Returns:
            Potfile content (new entries only) or None
        """
        if not self._current_job:
            return None

        potfile_path = Path(self.config.resources.potfile_path)
        if not potfile_path.exists():
            return None

        try:
            with open(potfile_path, "r", errors="ignore") as f:
                all_lines = [line for line in f if line.strip()]

            # Return only lines added after job started
            new_lines = all_lines[self._potfile_start_lines:]
            if new_lines:
                return "\n".join(line.strip() for line in new_lines)
            return ""
        except Exception as e:
            logger.error(f"Failed to read potfile: {e}")
            return None

    def is_running(self) -> bool:
        """Check if a job is currently running."""
        return self._process is not None and self._process.poll() is None

    def get_return_code(self) -> Optional[int]:
        """Get the return code of the last job."""
        if self._process:
            return self._process.poll()
        return None

    def get_output_logs(self, max_lines: int = 100) -> str:
        """
        Get captured non-JSON output from hashcat.

        Useful for debugging failed jobs - returns error messages,
        warnings, and other text output from hashcat.

        Args:
            max_lines: Maximum number of lines to return (from end)

        Returns:
            String containing captured output lines
        """
        with self._output_lock:
            lines = self._output_lines[-max_lines:] if max_lines else self._output_lines
            return "\n".join(lines)

    def benchmark_all(self, hash_modes: Optional[list[int]] = None) -> list[BenchmarkResult]:
        """
        Run hashcat benchmark for multiple hash modes.

        Args:
            hash_modes: List of hash modes to benchmark. If None, uses common modes.

        Returns:
            List of BenchmarkResult objects
        """
        # Default common hash modes to benchmark
        if hash_modes is None:
            hash_modes = [
                0,      # MD5
                100,    # SHA1
                1000,   # NTLM
                1400,   # SHA256
                1700,   # SHA512
                2100,   # DCC2
                3000,   # LM
                5500,   # NetNTLMv1
                5600,   # NetNTLMv2
                13100,  # Kerberos TGS-REP
                18200,  # Kerberos AS-REP
            ]

        results = []
        for mode in hash_modes:
            logger.info(f"Benchmarking hash mode {mode}...")
            result = self.benchmark(mode)
            results.append(result)
            if result.success:
                logger.info(f"Hash mode {mode}: {result.total_speed:.0f} H/s")
            else:
                logger.warning(f"Hash mode {mode} failed: {result.error}")

        return results

    def get_hashcat_version(self) -> Optional[str]:
        """Get hashcat version string."""
        success, version = self.verify_hashcat()
        return version if success else None
