"""
Software Manager for HM1K.

Manages centralized storage of:
- Hashcat versions (cracking software)
- NVIDIA drivers (GPU drivers)
- AMD drivers (GPU drivers)

Software packages are stored on the server and deployed to agents on demand.
"""

import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional

logger = logging.getLogger(__name__)

SoftwareType = Literal["hashcat", "nvidia", "amd"]


@dataclass
class SoftwarePackage:
    """Represents a stored software package."""
    package_id: str
    name: str  # e.g., "hashcat-6.2.6" or "NVIDIA-Linux-x86_64-550.54.14"
    software_type: SoftwareType
    version: str  # e.g., "6.2.6" or "550.54.14"
    description: str
    file_path: str
    filename: str  # Original filename
    size_bytes: int
    sha256: str
    uploaded_at: str
    uploaded_by: Optional[str] = None
    is_current: bool = False  # Whether this is the "current" version for deployment
    platform: str = "linux-x86_64"  # Platform identifier
    notes: str = ""  # Additional notes (e.g., compatibility info)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "name": self.name,
            "software_type": self.software_type,
            "version": self.version,
            "description": self.description,
            "file_path": self.file_path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "uploaded_at": self.uploaded_at,
            "uploaded_by": self.uploaded_by,
            "is_current": self.is_current,
            "platform": self.platform,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SoftwarePackage":
        return cls(
            package_id=data["package_id"],
            name=data["name"],
            software_type=data["software_type"],
            version=data["version"],
            description=data.get("description", ""),
            file_path=data["file_path"],
            filename=data["filename"],
            size_bytes=data["size_bytes"],
            sha256=data["sha256"],
            uploaded_at=data["uploaded_at"],
            uploaded_by=data.get("uploaded_by"),
            is_current=data.get("is_current", False),
            platform=data.get("platform", "linux-x86_64"),
            notes=data.get("notes", ""),
        )


@dataclass
class AgentSoftwareStatus:
    """Software status reported by an agent."""
    agent_id: str
    hashcat_versions: list[dict[str, Any]] = field(default_factory=list)
    # Each entry: {"path": "/opt/hashcat/6.2.6/hashcat", "version": "6.2.6", "is_current": True}
    nvidia_driver: Optional[dict[str, Any]] = None
    # {"version": "550.54.14", "cuda_version": "12.4", "gpus": [...]}
    amd_driver: Optional[dict[str, Any]] = None
    # {"version": "23.40", "gpus": [...]}
    last_updated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "hashcat_versions": self.hashcat_versions,
            "nvidia_driver": self.nvidia_driver,
            "amd_driver": self.amd_driver,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentSoftwareStatus":
        return cls(
            agent_id=data["agent_id"],
            hashcat_versions=data.get("hashcat_versions", []),
            nvidia_driver=data.get("nvidia_driver"),
            amd_driver=data.get("amd_driver"),
            last_updated=data.get("last_updated", ""),
        )


class SoftwareManager:
    """
    Manages centralized software storage for HM1K.

    Software packages are stored in the data directory with an index file
    tracking metadata. Files are organized by type:
      software/
        hashcat/
        nvidia/
        amd/
        index.json
        agent_status.json  (tracks what's installed on each agent)
    """

    INDEX_FILE = "index.json"
    AGENT_STATUS_FILE = "agent_status.json"

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.software_dir = self.data_dir / "software"
        self._packages: dict[str, SoftwarePackage] = {}
        self._agent_status: dict[str, AgentSoftwareStatus] = {}
        self._ensure_directories()
        self._load_index()
        self._load_agent_status()

    def _ensure_directories(self) -> None:
        """Create software directories if they don't exist."""
        for subdir in ["hashcat", "nvidia", "amd"]:
            (self.software_dir / subdir).mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> None:
        """Load software index from disk."""
        index_path = self.software_dir / self.INDEX_FILE
        if index_path.exists():
            try:
                with open(index_path, "r") as f:
                    data = json.load(f)
                    for item in data.get("packages", []):
                        package = SoftwarePackage.from_dict(item)
                        # Verify file still exists
                        if Path(package.file_path).exists():
                            self._packages[package.package_id] = package
                        else:
                            logger.warning(f"Software package file missing: {package.file_path}")
                logger.info(f"Loaded software index with {len(self._packages)} packages")
            except Exception as e:
                logger.error(f"Error loading software index: {e}")

    def _save_index(self) -> None:
        """Save software index to disk."""
        index_path = self.software_dir / self.INDEX_FILE
        data = {
            "packages": [p.to_dict() for p in self._packages.values()],
            "updated_at": datetime.utcnow().isoformat()
        }
        with open(index_path, "w") as f:
            json.dump(data, f, indent=2)

    def _load_agent_status(self) -> None:
        """Load agent software status from disk."""
        status_path = self.software_dir / self.AGENT_STATUS_FILE
        if status_path.exists():
            try:
                with open(status_path, "r") as f:
                    data = json.load(f)
                    for item in data.get("agents", []):
                        status = AgentSoftwareStatus.from_dict(item)
                        self._agent_status[status.agent_id] = status
            except Exception as e:
                logger.error(f"Error loading agent status: {e}")

    def _save_agent_status(self) -> None:
        """Save agent software status to disk."""
        status_path = self.software_dir / self.AGENT_STATUS_FILE
        data = {
            "agents": [s.to_dict() for s in self._agent_status.values()],
            "updated_at": datetime.utcnow().isoformat()
        }
        with open(status_path, "w") as f:
            json.dump(data, f, indent=2)

    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _generate_package_id(self, software_type: str, version: str) -> str:
        """Generate a unique package ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"{software_type}-{version}-{timestamp}"

    def _parse_hashcat_filename(self, filename: str) -> Optional[str]:
        """Extract version from hashcat filename."""
        # Patterns: hashcat-6.2.6.7z, hashcat-6.2.6.tar.gz, etc.
        import re
        match = re.search(r"hashcat[_-]?(\d+\.\d+\.\d+)", filename, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _parse_nvidia_filename(self, filename: str) -> Optional[str]:
        """Extract version from NVIDIA driver filename."""
        # Pattern: NVIDIA-Linux-x86_64-550.54.14.run
        import re
        match = re.search(r"(\d+\.\d+\.?\d*)", filename)
        if match:
            return match.group(1)
        return None

    def _parse_amd_filename(self, filename: str) -> Optional[str]:
        """Extract version from AMD driver filename."""
        # Pattern: amdgpu-pro-23.40-...
        import re
        match = re.search(r"amdgpu[_-]?pro[_-]?(\d+\.\d+)", filename, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def add_package(
        self,
        file_path: str,
        software_type: SoftwareType,
        version: Optional[str] = None,
        description: str = "",
        uploaded_by: Optional[str] = None,
        notes: str = "",
        make_current: bool = False,
    ) -> SoftwarePackage:
        """
        Add a new software package from a file.

        Args:
            file_path: Path to the software package file
            software_type: Type of software (hashcat, nvidia, amd)
            version: Version string (auto-detected if not provided)
            description: Optional description
            uploaded_by: Username of uploader
            notes: Additional notes
            make_current: Whether to mark this as the current version

        Returns:
            The created SoftwarePackage
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        filename = file_path.name

        # Auto-detect version if not provided
        if not version:
            if software_type == "hashcat":
                version = self._parse_hashcat_filename(filename)
            elif software_type == "nvidia":
                version = self._parse_nvidia_filename(filename)
            elif software_type == "amd":
                version = self._parse_amd_filename(filename)

            if not version:
                raise ValueError(f"Could not detect version from filename: {filename}")

        # Generate package ID and name
        package_id = self._generate_package_id(software_type, version)
        name = f"{software_type}-{version}"

        # Calculate hash
        sha256 = self._calculate_sha256(str(file_path))

        # Check for duplicates by hash
        for existing in self._packages.values():
            if existing.sha256 == sha256:
                logger.warning(f"Package with same hash already exists: {existing.name}")
                return existing

        # Copy file to storage
        dest_dir = self.software_dir / software_type
        dest_path = dest_dir / filename

        # Handle filename collision
        if dest_path.exists():
            base, ext = os.path.splitext(filename)
            dest_path = dest_dir / f"{base}_{package_id[:8]}{ext}"

        shutil.copy2(file_path, dest_path)

        # Create package record
        package = SoftwarePackage(
            package_id=package_id,
            name=name,
            software_type=software_type,
            version=version,
            description=description,
            file_path=str(dest_path),
            filename=filename,
            size_bytes=dest_path.stat().st_size,
            sha256=sha256,
            uploaded_at=datetime.utcnow().isoformat(),
            uploaded_by=uploaded_by,
            is_current=make_current,
            notes=notes,
        )

        # If marking as current, unmark others of same type
        if make_current:
            for p in self._packages.values():
                if p.software_type == software_type and p.is_current:
                    p.is_current = False

        self._packages[package_id] = package
        self._save_index()

        logger.info(f"Added software package: {name} ({package_id})")
        return package

    def remove_package(self, package_id: str) -> bool:
        """Remove a software package."""
        if package_id not in self._packages:
            return False

        package = self._packages[package_id]

        # Delete file
        file_path = Path(package.file_path)
        if file_path.exists():
            file_path.unlink()

        del self._packages[package_id]
        self._save_index()

        logger.info(f"Removed software package: {package.name}")
        return True

    def set_current(self, package_id: str) -> bool:
        """Mark a package as the current version."""
        if package_id not in self._packages:
            return False

        package = self._packages[package_id]

        # Unmark other packages of same type
        for p in self._packages.values():
            if p.software_type == package.software_type:
                p.is_current = (p.package_id == package_id)

        self._save_index()
        logger.info(f"Set current {package.software_type} version to: {package.version}")
        return True

    def get_package(self, package_id: str) -> Optional[SoftwarePackage]:
        """Get a specific package by ID."""
        return self._packages.get(package_id)

    def get_current(self, software_type: SoftwareType) -> Optional[SoftwarePackage]:
        """Get the current version of a software type."""
        for p in self._packages.values():
            if p.software_type == software_type and p.is_current:
                return p
        return None

    def list_packages(
        self,
        software_type: Optional[SoftwareType] = None
    ) -> list[SoftwarePackage]:
        """List all packages, optionally filtered by type."""
        packages = list(self._packages.values())
        if software_type:
            packages = [p for p in packages if p.software_type == software_type]
        # Sort by version (descending) then by upload date
        packages.sort(key=lambda p: (p.version, p.uploaded_at), reverse=True)
        return packages

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about stored software."""
        stats = {
            "hashcat": {"count": 0, "total_size": 0, "current": None},
            "nvidia": {"count": 0, "total_size": 0, "current": None},
            "amd": {"count": 0, "total_size": 0, "current": None},
        }

        for p in self._packages.values():
            stats[p.software_type]["count"] += 1
            stats[p.software_type]["total_size"] += p.size_bytes
            if p.is_current:
                stats[p.software_type]["current"] = p.version

        return stats

    # Agent status management

    def update_agent_status(
        self,
        agent_id: str,
        hashcat_versions: Optional[list[dict]] = None,
        nvidia_driver: Optional[dict] = None,
        amd_driver: Optional[dict] = None,
    ) -> AgentSoftwareStatus:
        """Update the software status for an agent."""
        if agent_id in self._agent_status:
            status = self._agent_status[agent_id]
        else:
            status = AgentSoftwareStatus(agent_id=agent_id)

        if hashcat_versions is not None:
            status.hashcat_versions = hashcat_versions
        if nvidia_driver is not None:
            status.nvidia_driver = nvidia_driver
        if amd_driver is not None:
            status.amd_driver = amd_driver

        status.last_updated = datetime.utcnow().isoformat()
        self._agent_status[agent_id] = status
        self._save_agent_status()

        return status

    def get_agent_status(self, agent_id: str) -> Optional[AgentSoftwareStatus]:
        """Get the software status for an agent."""
        return self._agent_status.get(agent_id)

    def list_agent_status(self) -> list[AgentSoftwareStatus]:
        """List software status for all agents."""
        return list(self._agent_status.values())


# Singleton instance
_software_manager: Optional[SoftwareManager] = None


def get_software_manager(data_dir: Optional[str] = None) -> SoftwareManager:
    """Get the singleton SoftwareManager instance."""
    global _software_manager
    if _software_manager is None:
        if data_dir is None:
            # Default to data directory
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        _software_manager = SoftwareManager(data_dir)
    return _software_manager
