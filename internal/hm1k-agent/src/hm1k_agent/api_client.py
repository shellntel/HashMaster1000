"""
REST API client for HM1K server communication.

Handles all agent → server REST API calls:
- Heartbeats and status updates
- Job completion/error reporting
- Resource metadata requests
- Registration requests
"""

from dataclasses import dataclass
from typing import Any, Optional
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from hm1k_agent.config import Config

logger = logging.getLogger(__name__)


@dataclass
class ConnectionTestResult:
    """Result of a connection test."""

    success: bool
    server_version: Optional[str] = None
    agent_recognized: bool = False
    error: Optional[str] = None


@dataclass
class HeartbeatResult:
    """Result of a heartbeat request."""

    success: bool
    server_time: Optional[str] = None
    pending_commands: list[dict] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.pending_commands is None:
            self.pending_commands = []


@dataclass
class JobStatusUpdate:
    """Job status update to send to server."""

    job_id: str
    status: str  # running, paused, completed, error
    progress_percent: float
    speed_hashes_per_sec: float
    recovered_hashes: int
    total_hashes: int
    eta_seconds: Optional[int] = None
    gpu_temps: Optional[list[int]] = None
    gpu_utils: Optional[list[int]] = None
    gpu_speeds: Optional[list[float]] = None
    hashcat_version: Optional[str] = None
    time_start: Optional[int] = None
    # Multi-mask progress
    mask_current: int = 0  # Current mask index (1-based)
    mask_total: int = 0  # Total number of masks
    mask_pattern: Optional[str] = None  # Current mask pattern


class APIClient:
    """
    REST API client for HM1K server.

    All requests are authenticated via JWT token in Authorization header.
    Implements automatic retry with exponential backoff.
    """

    def __init__(self, config: Config):
        """
        Initialize API client.

        Args:
            config: Agent configuration with server URL and token
        """
        self.config = config
        self.base_url = config.server.url.rstrip("/")
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create requests session with retry configuration."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"hm1k-agent/{self.config.agent.id}",
        }

        if self.config.server.token:
            headers["Authorization"] = f"Bearer {self.config.server.token}"

        return headers

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Make an authenticated API request.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path (e.g., "/api/agent/heartbeat")
            data: Request body data (for POST/PUT)
            params: Query parameters (for GET)
            timeout: Request timeout in seconds

        Returns:
            Response JSON as dictionary

        Raises:
            requests.RequestException: On network or HTTP errors
        """
        url = f"{self.base_url}{endpoint}"
        timeout = timeout or self.config.server.timeout

        response = self._session.request(
            method=method,
            url=url,
            json=data,
            params=params,
            headers=self._get_headers(),
            timeout=timeout,
            verify=self.config.server.verify_ssl,
        )

        response.raise_for_status()
        return response.json()

    def test_connection(self) -> ConnectionTestResult:
        """
        Test connectivity to the HM1K server.

        Returns:
            ConnectionTestResult with server info or error
        """
        try:
            response = self._request("GET", "/api/agent/ping")
            return ConnectionTestResult(
                success=True,
                server_version=response.get("version"),
                agent_recognized=response.get("agent_recognized", False),
            )
        except requests.RequestException as e:
            return ConnectionTestResult(success=False, error=str(e))

    def send_heartbeat(self, agent_state: dict) -> HeartbeatResult:
        """
        Send heartbeat to server.

        Args:
            agent_state: Current agent state (idle, running job, etc.)

        Returns:
            HeartbeatResult with server response
        """
        try:
            response = self._request(
                "POST",
                "/api/agent/heartbeat",
                data={
                    "agent_id": self.config.agent.id,
                    "state": agent_state,
                },
            )
            return HeartbeatResult(
                success=True,
                server_time=response.get("server_time"),
                pending_commands=response.get("commands", []),
            )
        except requests.RequestException as e:
            logger.warning(f"Heartbeat failed: {e}")
            return HeartbeatResult(success=False, error=str(e))

    def send_job_status(self, status: JobStatusUpdate) -> bool:
        """
        Send job status update to server.

        Args:
            status: Current job status

        Returns:
            True if update was accepted
        """
        try:
            self._request(
                "POST",
                "/api/agent/status",
                data={
                    "agent_id": self.config.agent.id,
                    "job_id": status.job_id,
                    "status": status.status,
                    "progress_percent": status.progress_percent,
                    "speed_hashes_per_sec": status.speed_hashes_per_sec,
                    "recovered_hashes": status.recovered_hashes,
                    "total_hashes": status.total_hashes,
                    "eta_seconds": status.eta_seconds,
                    "gpu_temps": status.gpu_temps,
                    "gpu_utils": status.gpu_utils,
                    "gpu_speeds": status.gpu_speeds,
                    "hashcat_version": status.hashcat_version,
                    "time_start": status.time_start,
                    "mask_current": status.mask_current,
                    "mask_total": status.mask_total,
                    "mask_pattern": status.mask_pattern,
                },
            )
            return True
        except requests.RequestException as e:
            logger.warning(f"Status update failed: {e}")
            return False

    def report_job_complete(
        self,
        job_id: str,
        potfile_content: str,
        stats: dict,
    ) -> bool:
        """
        Report job completion with results.

        Args:
            job_id: Completed job ID
            potfile_content: Contents of the potfile (cracked hashes)
            stats: Final job statistics

        Returns:
            True if report was accepted
        """
        try:
            self._request(
                "POST",
                "/api/agent/job/complete",
                data={
                    "agent_id": self.config.agent.id,
                    "job_id": job_id,
                    "potfile": potfile_content,
                    "stats": stats,
                },
            )
            return True
        except requests.RequestException as e:
            logger.error(f"Job completion report failed: {e}")
            return False

    def report_job_error(self, job_id: str, error: str, logs: Optional[str] = None) -> bool:
        """
        Report job failure with error details.

        Args:
            job_id: Failed job ID
            error: Error message
            logs: Hashcat output/logs

        Returns:
            True if report was accepted
        """
        try:
            self._request(
                "POST",
                "/api/agent/job/error",
                data={
                    "agent_id": self.config.agent.id,
                    "job_id": job_id,
                    "error": error,
                    "logs": logs,
                },
            )
            return True
        except requests.RequestException as e:
            logger.error(f"Job error report failed: {e}")
            return False

    def report_update_status(
        self,
        version: str,
        status: str,
        message: str,
        error: Optional[str] = None,
    ) -> bool:
        """
        Report agent update status to server.

        Args:
            version: Target version being updated to
            status: Status (downloading, installed, restarting, error)
            message: Human-readable status message
            error: Error details if status is 'error'

        Returns:
            True if report was accepted
        """
        try:
            self._request(
                "POST",
                "/api/agent/update/status",
                data={
                    "agent_id": self.config.agent.id,
                    "version": version,
                    "status": status,
                    "message": message,
                    "error": error,
                },
            )
            return True
        except requests.RequestException as e:
            logger.warning(f"Update status report failed: {e}")
            return False

    def get_resource_list(self, resource_type: str) -> list[dict]:
        """
        Get list of available resources.

        Args:
            resource_type: Type of resource (wordlists, rules, masks)

        Returns:
            List of resource metadata dictionaries
        """
        try:
            response = self._request("GET", f"/api/agent/resources/{resource_type}")
            return response.get("resources", [])
        except requests.RequestException as e:
            logger.error(f"Failed to get resource list: {e}")
            return []

    def get_resource_meta(self, resource_type: str, name: str) -> Optional[dict]:
        """
        Get metadata for a specific resource.

        Args:
            resource_type: Type of resource
            name: Resource name

        Returns:
            Resource metadata or None
        """
        try:
            return self._request("GET", f"/api/agent/resources/{resource_type}/{name}/meta")
        except requests.RequestException as e:
            logger.error(f"Failed to get resource metadata: {e}")
            return None

    def download_resource(self, resource_type: str, resource_id: str, dest_path: str) -> bool:
        """
        Download a resource file.

        Args:
            resource_type: Type of resource (wordlists, rules, masks)
            resource_id: Unique resource identifier
            dest_path: Local path to save file

        Returns:
            True if download succeeded
        """
        try:
            url = f"{self.base_url}/api/agent/resources/{resource_type}/{resource_id}"
            response = self._session.get(
                url,
                headers=self._get_headers(),
                timeout=600,  # 10 minute timeout for large files
                verify=self.config.server.verify_ssl,
                stream=True,
            )
            response.raise_for_status()

            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            return True
        except Exception as e:
            logger.error(f"Failed to download resource: {e}")
            return False

    def download_resource_compressed(self, resource_type: str, resource_id: str, dest_path: str) -> bool:
        """
        Download a compressed (.zst) version of a resource file.

        Args:
            resource_type: Type of resource (wordlists, rules, masks)
            resource_id: Unique resource identifier
            dest_path: Local path to save compressed file (should end in .zst)

        Returns:
            True if download succeeded, False if not available or failed
        """
        try:
            url = f"{self.base_url}/api/agent/resources/{resource_type}/{resource_id}/compressed"
            response = self._session.get(
                url,
                headers=self._get_headers(),
                timeout=600,  # 10 minute timeout for large files
                verify=self.config.server.verify_ssl,
                stream=True,
            )

            # 404 means compressed version not available
            if response.status_code == 404:
                logger.debug(f"Compressed version not available for {resource_id}")
                return False

            response.raise_for_status()

            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            return True
        except Exception as e:
            logger.error(f"Failed to download compressed resource: {e}")
            return False

    async def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        agent_description: str,
        registration_code: str,
    ) -> dict:
        """
        Register agent with server (discovery mode).

        Args:
            agent_id: Unique agent identifier
            agent_name: Human-friendly name
            agent_description: Description of hardware
            registration_code: One-time registration code

        Returns:
            Server response with status and optional token
        """
        return self._request(
            "POST",
            "/api/agent/register",
            data={
                "agent_id": agent_id,
                "name": agent_name,
                "description": agent_description,
                "registration_code": registration_code,
            },
        )

    async def check_registration_status(self, agent_id: str, registration_code: str) -> dict:
        """
        Check if registration has been approved.

        Args:
            agent_id: Agent identifier
            registration_code: Registration code to check

        Returns:
            Status response with token if approved
        """
        return self._request(
            "GET",
            "/api/agent/register/status",
            params={
                "agent_id": agent_id,
                "code": registration_code,
            },
        )

    def report_benchmark(self, benchmark_data: dict) -> bool:
        """
        Report benchmark results to server.

        Args:
            benchmark_data: Dictionary containing:
                - agent_id: Agent identifier
                - timestamp: When benchmark was run
                - hashcat_version: Version of hashcat
                - results: List of benchmark results per hash mode

        Returns:
            True if report was accepted
        """
        try:
            self._request(
                "POST",
                "/api/agent/performance/benchmark",
                data=benchmark_data,
            )
            return True
        except requests.RequestException as e:
            logger.error(f"Benchmark report failed: {e}")
            return False

    def report_job_performance(self, metrics: dict) -> bool:
        """
        Report job performance metrics to server.

        Args:
            metrics: Dictionary containing job performance data:
                - agent_id: Agent identifier
                - job_id: Job identifier
                - hash_mode: Hash mode used
                - attack_mode: Attack mode used
                - started_at, completed_at: Timestamps
                - duration_seconds: Job duration
                - total_hashes, hashes_cracked: Hash stats
                - avg_speed_hs, peak_speed_hs: Speed metrics
                - gpus: List of GPU metrics
                - etc.

        Returns:
            True if report was accepted
        """
        try:
            self._request(
                "POST",
                "/api/agent/performance/job",
                data=metrics,
            )
            return True
        except requests.RequestException as e:
            logger.error(f"Job performance report failed: {e}")
            return False

    def sync_potfile(
        self,
        entries: list[str],
        last_position: int,
    ) -> Optional[dict]:
        """
        Bidirectional potfile sync with server.

        Sends local new entries and receives entries from other agents.

        Args:
            entries: List of new hash:plaintext entries to upload
            last_position: Last known position in master potfile

        Returns:
            Dictionary with:
                - new_entries: List of entries since last_position
                - current_position: Current end position
                - merged_count: Number of entries merged from this agent
            Or None on failure
        """
        try:
            response = self._request(
                "POST",
                "/api/agent/potfile/sync",
                data={
                    "agent_id": self.config.agent.id,
                    "entries": entries,
                    "last_position": last_position,
                },
            )
            return response
        except requests.RequestException as e:
            logger.error(f"Potfile sync failed: {e}")
            return None

    def get_full_potfile(self) -> Optional[tuple[str, int]]:
        """
        Download the full master potfile from server.

        Used for initial sync or recovery.

        Returns:
            Tuple of (potfile_content, position) or None on failure
        """
        try:
            url = f"{self.base_url}/api/agent/potfile/full"
            response = self._session.get(
                url,
                params={"agent_id": self.config.agent.id},
                headers=self._get_headers(),
                timeout=600,  # 10 minute timeout for large files
                verify=self.config.server.verify_ssl,
            )
            response.raise_for_status()

            position = int(response.headers.get("X-Potfile-Position", 0))
            return response.text, position
        except Exception as e:
            logger.error(f"Failed to download full potfile: {e}")
            return None
