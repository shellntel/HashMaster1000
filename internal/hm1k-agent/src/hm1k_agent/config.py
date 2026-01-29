"""
Configuration management for HM1K Agent.

Loads and validates configuration from YAML file, typically located at
/etc/hm1k-agent/config.yaml. Provides typed access to all configuration
values with sensible defaults.
"""

import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# Default configuration paths
DEFAULT_CONFIG_PATH = Path("/etc/hm1k-agent/config.yaml")
DEFAULT_WORKDIR = Path("/var/lib/hm1k-agent")
DEFAULT_CACHE_DIR = DEFAULT_WORKDIR / "cache"
DEFAULT_JOBS_DIR = DEFAULT_WORKDIR / "jobs"
DEFAULT_POTFILES_DIR = DEFAULT_WORKDIR / "potfiles"
DEFAULT_SESSIONS_DIR = DEFAULT_WORKDIR / "sessions"
DEFAULT_DATA_DIR = DEFAULT_WORKDIR / "data"
DEFAULT_LOG_FILE = Path("/var/log/hm1k-agent/agent.log")
DEFAULT_HASHCAT_BINARY = "/opt/hashcat/current/hashcat"


@dataclass
class ServerConfig:
    """HM1K server connection settings."""

    url: str
    token: Optional[str] = None
    # verify_ssl: True (use system certs), False (disable), or path to cert file
    verify_ssl: bool | str = True
    timeout: int = 30  # Request timeout in seconds


@dataclass
class AgentConfig:
    """Agent identification settings."""

    id: str
    name: str
    description: str = ""


@dataclass
class HashcatConfig:
    """Hashcat execution settings."""

    binary: str = DEFAULT_HASHCAT_BINARY
    workdir: str = str(DEFAULT_SESSIONS_DIR)
    extra_args: str = ""
    status_timer: int = 10  # Seconds between --status-json updates


@dataclass
class ResourceConfig:
    """Resource and directory settings."""

    cache_dir: str = str(DEFAULT_CACHE_DIR)
    jobs_dir: str = str(DEFAULT_JOBS_DIR)
    potfiles_dir: str = str(DEFAULT_POTFILES_DIR)
    sessions_dir: str = str(DEFAULT_SESSIONS_DIR)
    data_dir: str = str(DEFAULT_DATA_DIR)
    max_cache_size_gb: int = 50

    @property
    def potfile_path(self) -> str:
        """Path to the agent's local potfile used by hashcat."""
        return str(Path(self.potfiles_dir) / "agent.potfile")


@dataclass
class TimingConfig:
    """Polling and timing settings."""

    heartbeat_interval: int = 60  # Seconds between heartbeats
    status_interval: int = 15  # Seconds between status updates (during job)
    reconnect_max_interval: int = 300  # Max seconds between reconnect attempts


@dataclass
class LoggingConfig:
    """Logging settings."""

    level: str = "INFO"
    file: str = str(DEFAULT_LOG_FILE)
    max_size_mb: int = 100
    backup_count: int = 5


@dataclass
class APIConfig:
    """Local API server settings."""

    enabled: bool = True
    host: str = "127.0.0.1"  # Bind to localhost by default
    port: int = 8787
    key: Optional[str] = None  # Optional API key for authentication


@dataclass
class Config:
    """
    Complete agent configuration.

    Typically loaded from /etc/hm1k-agent/config.yaml via Config.load().
    """

    server: ServerConfig
    agent: AgentConfig
    hashcat: HashcatConfig = field(default_factory=HashcatConfig)
    resources: ResourceConfig = field(default_factory=ResourceConfig)
    timing: TimingConfig = field(default_factory=TimingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    api: APIConfig = field(default_factory=APIConfig)

    @classmethod
    def load(cls, path: Path | str = DEFAULT_CONFIG_PATH) -> "Config":
        """
        Load configuration from YAML file.

        Args:
            path: Path to config file. Defaults to /etc/hm1k-agent/config.yaml

        Returns:
            Config object with loaded values

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config file is invalid
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        if not data:
            raise ValueError(f"Empty config file: {path}")

        # Parse server config (required)
        server_data = data.get("server", {})
        if not server_data.get("url"):
            raise ValueError("server.url is required in config")

        server = ServerConfig(
            url=server_data["url"],
            token=server_data.get("token"),
            verify_ssl=server_data.get("verify_ssl", True),
            timeout=server_data.get("timeout", 30),
        )

        # Parse agent config (required)
        agent_data = data.get("agent", {})
        if not agent_data.get("id"):
            raise ValueError("agent.id is required in config")

        # Default agent name to hostname if not specified
        default_name = socket.gethostname()

        agent = AgentConfig(
            id=agent_data["id"],
            name=agent_data.get("name") or default_name,
            description=agent_data.get("description", ""),
        )

        # Parse optional sections with defaults
        hashcat_data = data.get("hashcat", {})
        hashcat = HashcatConfig(
            binary=hashcat_data.get("binary", DEFAULT_HASHCAT_BINARY),
            workdir=hashcat_data.get("workdir", str(DEFAULT_SESSIONS_DIR)),
            extra_args=hashcat_data.get("extra_args", ""),
            status_timer=hashcat_data.get("status_timer", 10),
        )

        resources_data = data.get("resources", {})
        resources = ResourceConfig(
            cache_dir=resources_data.get("cache_dir", str(DEFAULT_CACHE_DIR)),
            jobs_dir=resources_data.get("jobs_dir", str(DEFAULT_JOBS_DIR)),
            potfiles_dir=resources_data.get("potfiles_dir", str(DEFAULT_POTFILES_DIR)),
            sessions_dir=resources_data.get("sessions_dir", str(DEFAULT_SESSIONS_DIR)),
            data_dir=resources_data.get("data_dir", str(DEFAULT_DATA_DIR)),
            max_cache_size_gb=resources_data.get("max_cache_size_gb", 50),
        )

        timing_data = data.get("timing", {})
        timing = TimingConfig(
            heartbeat_interval=timing_data.get("heartbeat_interval", 60),
            status_interval=timing_data.get("status_interval", 15),
            reconnect_max_interval=timing_data.get("reconnect_max_interval", 300),
        )

        logging_data = data.get("logging", {})
        logging_config = LoggingConfig(
            level=logging_data.get("level", "INFO"),
            file=logging_data.get("file", str(DEFAULT_LOG_FILE)),
            max_size_mb=logging_data.get("max_size_mb", 100),
            backup_count=logging_data.get("backup_count", 5),
        )

        api_data = data.get("api", {})
        api_config = APIConfig(
            enabled=api_data.get("enabled", True),
            host=api_data.get("host", "127.0.0.1"),
            port=api_data.get("port", 8787),
            key=api_data.get("key"),
        )

        return cls(
            server=server,
            agent=agent,
            hashcat=hashcat,
            resources=resources,
            timing=timing,
            logging=logging_config,
            api=api_config,
        )

    def save(self, path: Path | str = DEFAULT_CONFIG_PATH) -> None:
        """
        Save configuration to YAML file.

        Args:
            path: Path to save config file
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "server": {
                "url": self.server.url,
                "token": self.server.token,
                "verify_ssl": self.server.verify_ssl,
                "timeout": self.server.timeout,
            },
            "agent": {
                "id": self.agent.id,
                "name": self.agent.name,
                "description": self.agent.description,
            },
            "hashcat": {
                "binary": self.hashcat.binary,
                "workdir": self.hashcat.workdir,
                "extra_args": self.hashcat.extra_args,
                "status_timer": self.hashcat.status_timer,
            },
            "resources": {
                "cache_dir": self.resources.cache_dir,
                "jobs_dir": self.resources.jobs_dir,
                "potfiles_dir": self.resources.potfiles_dir,
                "sessions_dir": self.resources.sessions_dir,
                "data_dir": self.resources.data_dir,
                "max_cache_size_gb": self.resources.max_cache_size_gb,
            },
            "timing": {
                "heartbeat_interval": self.timing.heartbeat_interval,
                "status_interval": self.timing.status_interval,
                "reconnect_max_interval": self.timing.reconnect_max_interval,
            },
            "logging": {
                "level": self.logging.level,
                "file": self.logging.file,
                "max_size_mb": self.logging.max_size_mb,
                "backup_count": self.logging.backup_count,
            },
            "api": {
                "enabled": self.api.enabled,
                "host": self.api.host,
                "port": self.api.port,
                "key": self.api.key,
            },
        }

        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def create_default(
        cls,
        server_url: str,
        agent_id: str,
        agent_name: str = "",
        hashcat_binary: str = DEFAULT_HASHCAT_BINARY,
    ) -> "Config":
        """
        Create a new config with default values.

        Args:
            server_url: HM1K server URL
            agent_id: Unique agent identifier
            agent_name: Human-friendly agent name (defaults to hostname)
            hashcat_binary: Path to hashcat binary

        Returns:
            New Config object with defaults
        """
        return cls(
            server=ServerConfig(url=server_url),
            agent=AgentConfig(id=agent_id, name=agent_name or socket.gethostname()),
            hashcat=HashcatConfig(binary=hashcat_binary),
        )
