"""
Hardware detection for HM1K Agent.

Detects system hardware including:
- Hostname
- GPUs (via nvidia-smi)
- CPU model and cores
- Total RAM
"""

import json
import logging
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class GPUInfo:
    """Information about a GPU device."""

    index: int
    name: str
    memory_total_mb: int
    memory_free_mb: int = 0
    driver_version: str = ""
    cuda_version: str = ""
    temperature: Optional[int] = None
    utilization: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "memory_total_mb": self.memory_total_mb,
            "memory_free_mb": self.memory_free_mb,
            "driver_version": self.driver_version,
            "cuda_version": self.cuda_version,
            "temperature": self.temperature,
            "utilization": self.utilization,
        }


@dataclass
class CPUInfo:
    """Information about the CPU."""

    model: str
    cores: int
    threads: int

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "cores": self.cores,
            "threads": self.threads,
        }


@dataclass
class DiskInfo:
    """Information about disk storage for a specific path."""

    path: str
    total_gb: float
    used_gb: float
    free_gb: float
    used_percent: float

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "total_gb": round(self.total_gb, 2),
            "used_gb": round(self.used_gb, 2),
            "free_gb": round(self.free_gb, 2),
            "used_percent": round(self.used_percent, 1),
        }


@dataclass
class SystemInfo:
    """Complete system hardware information."""

    hostname: str
    os_name: str = ""
    os_version: str = ""
    cpu: Optional[CPUInfo] = None
    gpus: list[GPUInfo] = field(default_factory=list)
    memory_total_mb: int = 0
    memory_available_mb: int = 0
    disk: list[DiskInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "cpu": self.cpu.to_dict() if self.cpu else None,
            "gpus": [gpu.to_dict() for gpu in self.gpus],
            "memory_total_mb": self.memory_total_mb,
            "memory_available_mb": self.memory_available_mb,
            "disk": [d.to_dict() for d in self.disk],
        }

    def gpu_summary(self) -> str:
        """Return a short summary of GPUs for display."""
        if not self.gpus:
            return "No GPUs"
        if len(self.gpus) == 1:
            return self.gpus[0].name
        # Multiple GPUs - group by name
        gpu_counts: dict[str, int] = {}
        for gpu in self.gpus:
            gpu_counts[gpu.name] = gpu_counts.get(gpu.name, 0) + 1
        parts = []
        for name, count in gpu_counts.items():
            if count > 1:
                parts.append(f"{count}x {name}")
            else:
                parts.append(name)
        return ", ".join(parts)


def get_hostname() -> str:
    """Get the system hostname."""
    return socket.gethostname()


def detect_gpus() -> list[GPUInfo]:
    """
    Detect NVIDIA GPUs using nvidia-smi.

    Returns:
        List of GPUInfo objects for each detected GPU
    """
    gpus = []

    try:
        # Query nvidia-smi with CSV format for easy parsing
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=index,name,memory.total,memory.free,driver_version,temperature.gpu,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            logger.debug(f"nvidia-smi failed: {result.stderr}")
            return gpus

        # Get CUDA version separately
        cuda_version = ""
        cuda_result = subprocess.run(
            ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if cuda_result.returncode == 0:
            # Try to get CUDA version from nvidia-smi header
            header_result = subprocess.run(
                ["nvidia-smi"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if header_result.returncode == 0:
                # Look for CUDA Version in output
                match = re.search(r"CUDA Version:\s*([\d.]+)", header_result.stdout)
                if match:
                    cuda_version = match.group(1)

        # Parse CSV output
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 6:
                try:
                    gpu = GPUInfo(
                        index=int(parts[0]),
                        name=parts[1],
                        memory_total_mb=int(parts[2]),
                        memory_free_mb=int(parts[3]) if parts[3] != "[N/A]" else 0,
                        driver_version=parts[4],
                        cuda_version=cuda_version,
                        temperature=int(parts[5]) if parts[5] != "[N/A]" else None,
                        utilization=int(parts[6]) if len(parts) > 6 and parts[6] != "[N/A]" else None,
                    )
                    gpus.append(gpu)
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse GPU info: {e}")

    except FileNotFoundError:
        logger.debug("nvidia-smi not found - no NVIDIA GPUs available")
    except subprocess.TimeoutExpired:
        logger.warning("nvidia-smi timed out")
    except Exception as e:
        logger.warning(f"Error detecting GPUs: {e}")

    return gpus


def detect_cpu() -> Optional[CPUInfo]:
    """
    Detect CPU information from /proc/cpuinfo.

    Returns:
        CPUInfo object or None if detection fails
    """
    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()

        # Get model name
        model_match = re.search(r"model name\s*:\s*(.+)", cpuinfo)
        model = model_match.group(1).strip() if model_match else "Unknown"

        # Count physical cores (unique core ids per physical id)
        physical_ids = set()
        core_ids = set()
        threads = 0

        for line in cpuinfo.split("\n"):
            if line.startswith("physical id"):
                physical_ids.add(line.split(":")[1].strip())
            elif line.startswith("core id"):
                core_ids.add(line.split(":")[1].strip())
            elif line.startswith("processor"):
                threads += 1

        # If we couldn't determine cores, use thread count
        cores = len(core_ids) * max(len(physical_ids), 1) if core_ids else threads

        return CPUInfo(
            model=model,
            cores=cores,
            threads=threads,
        )

    except Exception as e:
        logger.warning(f"Error detecting CPU: {e}")
        return None


def detect_memory() -> tuple[int, int]:
    """
    Detect system memory from /proc/meminfo.

    Returns:
        Tuple of (total_mb, available_mb)
    """
    try:
        with open("/proc/meminfo") as f:
            meminfo = f.read()

        total_kb = 0
        available_kb = 0

        for line in meminfo.split("\n"):
            if line.startswith("MemTotal:"):
                total_kb = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                available_kb = int(line.split()[1])

        return (total_kb // 1024, available_kb // 1024)

    except Exception as e:
        logger.warning(f"Error detecting memory: {e}")
        return (0, 0)


def detect_os() -> tuple[str, str]:
    """
    Detect OS name and version.

    Returns:
        Tuple of (os_name, os_version)
    """
    os_name = ""
    os_version = ""

    try:
        # Try /etc/os-release first (most Linux distros)
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("NAME="):
                        os_name = line.split("=")[1].strip().strip('"')
                    elif line.startswith("VERSION_ID="):
                        os_version = line.split("=")[1].strip().strip('"')
        else:
            # Fallback to uname
            import platform
            os_name = platform.system()
            os_version = platform.release()

    except Exception as e:
        logger.warning(f"Error detecting OS: {e}")

    return (os_name, os_version)


def detect_disk(paths: list[str] | None = None) -> list[DiskInfo]:
    """
    Detect disk usage for specified paths.

    Args:
        paths: List of paths to check. Defaults to ["/", "/var/lib/hm1k-agent"]

    Returns:
        List of DiskInfo objects for each valid path
    """
    if paths is None:
        paths = ["/"]
        # Add agent data dir if it exists
        agent_data_dir = "/var/lib/hm1k-agent"
        if os.path.exists(agent_data_dir):
            paths.append(agent_data_dir)

    disks = []
    seen_devices = set()

    for path in paths:
        try:
            if not os.path.exists(path):
                continue

            usage = shutil.disk_usage(path)

            # Get device for this path to avoid duplicates
            try:
                stat_info = os.stat(path)
                device = stat_info.st_dev
                if device in seen_devices:
                    continue
                seen_devices.add(device)
            except OSError:
                pass

            total_gb = usage.total / (1024**3)
            used_gb = usage.used / (1024**3)
            free_gb = usage.free / (1024**3)
            used_percent = (usage.used / usage.total) * 100 if usage.total > 0 else 0

            disks.append(
                DiskInfo(
                    path=path,
                    total_gb=total_gb,
                    used_gb=used_gb,
                    free_gb=free_gb,
                    used_percent=used_percent,
                )
            )

        except Exception as e:
            logger.warning(f"Error detecting disk for {path}: {e}")

    return disks


def detect_system() -> SystemInfo:
    """
    Detect all system hardware information.

    Returns:
        SystemInfo object with all detected hardware
    """
    hostname = get_hostname()
    os_name, os_version = detect_os()
    cpu = detect_cpu()
    gpus = detect_gpus()
    memory_total, memory_available = detect_memory()
    disk = detect_disk()

    return SystemInfo(
        hostname=hostname,
        os_name=os_name,
        os_version=os_version,
        cpu=cpu,
        gpus=gpus,
        memory_total_mb=memory_total,
        memory_available_mb=memory_available,
        disk=disk,
    )


# Cache the system info to avoid repeated detection
_cached_system_info: Optional[SystemInfo] = None


def get_system_info(refresh: bool = False) -> SystemInfo:
    """
    Get cached system hardware information.

    Args:
        refresh: If True, re-detect hardware instead of using cache

    Returns:
        SystemInfo object
    """
    global _cached_system_info

    if _cached_system_info is None or refresh:
        _cached_system_info = detect_system()

    return _cached_system_info


def refresh_dynamic_info(info: SystemInfo) -> None:
    """
    Refresh dynamic hardware info (temperature, utilization, memory, disk).

    Updates the SystemInfo object in place with current values.
    """
    # Refresh GPU stats
    fresh_gpus = detect_gpus()
    for cached_gpu in info.gpus:
        for fresh_gpu in fresh_gpus:
            if cached_gpu.index == fresh_gpu.index:
                cached_gpu.memory_free_mb = fresh_gpu.memory_free_mb
                cached_gpu.temperature = fresh_gpu.temperature
                cached_gpu.utilization = fresh_gpu.utilization
                break

    # Refresh memory
    info.memory_total_mb, info.memory_available_mb = detect_memory()

    # Refresh disk stats
    paths = [d.path for d in info.disk] if info.disk else None
    fresh_disk = detect_disk(paths)
    info.disk = fresh_disk


# =============================================================================
# Software Detection
# =============================================================================

@dataclass
class HashcatInstall:
    """Information about a hashcat installation."""
    path: str
    version: str
    is_current: bool = False  # True if this is /opt/hashcat/current

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "version": self.version,
            "is_current": self.is_current,
        }


@dataclass
class NvidiaDriverInfo:
    """Information about installed NVIDIA driver."""
    version: str
    cuda_version: str
    gpus: list[dict]  # List of GPU info dicts

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "cuda_version": self.cuda_version,
            "gpus": self.gpus,
        }


@dataclass
class AmdDriverInfo:
    """Information about installed AMD driver."""
    version: str
    gpus: list[dict]  # List of GPU info dicts

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "gpus": self.gpus,
        }


@dataclass
class SoftwareStatus:
    """Complete software installation status."""
    hashcat_versions: list[HashcatInstall] = field(default_factory=list)
    nvidia_driver: Optional[NvidiaDriverInfo] = None
    amd_driver: Optional[AmdDriverInfo] = None

    def to_dict(self) -> dict:
        return {
            "hashcat_versions": [h.to_dict() for h in self.hashcat_versions],
            "nvidia_driver": self.nvidia_driver.to_dict() if self.nvidia_driver else None,
            "amd_driver": self.amd_driver.to_dict() if self.amd_driver else None,
        }


def detect_hashcat_versions() -> list[HashcatInstall]:
    """
    Detect all installed hashcat versions.

    Checks common installation paths:
    - /opt/hashcat/current (symlink to current version)
    - /opt/hashcat/hashcat-* (version directories)
    - /opt/hashcat/hashcat (direct install)
    - /usr/bin/hashcat
    - /usr/local/bin/hashcat

    Returns:
        List of HashcatInstall objects
    """
    installations = []
    seen_versions = set()

    # Check for /opt/hashcat/current symlink first
    current_path = "/opt/hashcat/current"
    current_real_path = None
    if os.path.islink(current_path):
        try:
            current_real_path = os.path.realpath(current_path)
        except OSError:
            pass

    # Common search paths
    search_paths = [
        "/opt/hashcat/current/hashcat",
        "/opt/hashcat/hashcat",
        "/usr/local/bin/hashcat",
        "/usr/bin/hashcat",
    ]

    # Also check for versioned directories in /opt/hashcat
    opt_hashcat = "/opt/hashcat"
    if os.path.isdir(opt_hashcat):
        try:
            for entry in os.listdir(opt_hashcat):
                entry_path = os.path.join(opt_hashcat, entry)
                if os.path.isdir(entry_path) and entry.startswith("hashcat-"):
                    hashcat_bin = os.path.join(entry_path, "hashcat")
                    if os.path.isfile(hashcat_bin) and os.access(hashcat_bin, os.X_OK):
                        search_paths.append(hashcat_bin)
        except OSError as e:
            logger.debug(f"Error scanning /opt/hashcat: {e}")

    for path in search_paths:
        if not os.path.isfile(path):
            continue
        if not os.access(path, os.X_OK):
            continue

        # Get version
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                # Parse version string (e.g., "v6.2.6" -> "6.2.6")
                if version.startswith("v"):
                    version = version[1:]

                # Skip duplicates
                if version in seen_versions:
                    continue
                seen_versions.add(version)

                # Check if this is the current version
                real_path = os.path.realpath(path)
                is_current = (
                    current_real_path is not None and
                    real_path.startswith(current_real_path)
                ) or path == "/opt/hashcat/current/hashcat"

                installations.append(HashcatInstall(
                    path=path,
                    version=version,
                    is_current=is_current,
                ))
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Failed to get hashcat version from {path}: {e}")

    # Sort by version (descending)
    installations.sort(key=lambda h: h.version, reverse=True)
    return installations


def detect_nvidia_driver() -> Optional[NvidiaDriverInfo]:
    """
    Detect installed NVIDIA driver version.

    Returns:
        NvidiaDriverInfo object or None if not installed
    """
    try:
        # Get driver version and CUDA version from nvidia-smi
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None

        driver_version = result.stdout.strip().split("\n")[0].strip()

        # Get CUDA version
        cuda_version = ""
        header_result = subprocess.run(
            ["nvidia-smi"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if header_result.returncode == 0:
            match = re.search(r"CUDA Version:\s*([\d.]+)", header_result.stdout)
            if match:
                cuda_version = match.group(1)

        # Get GPU list
        gpus = detect_gpus()
        gpu_dicts = [g.to_dict() for g in gpus]

        return NvidiaDriverInfo(
            version=driver_version,
            cuda_version=cuda_version,
            gpus=gpu_dicts,
        )

    except FileNotFoundError:
        logger.debug("nvidia-smi not found")
        return None
    except Exception as e:
        logger.debug(f"Error detecting NVIDIA driver: {e}")
        return None


def detect_amd_driver() -> Optional[AmdDriverInfo]:
    """
    Detect installed AMD driver version.

    Returns:
        AmdDriverInfo object or None if not installed
    """
    try:
        # Try to detect AMD driver using clinfo or amdgpu-pro-info
        version = None

        # Method 1: Check amdgpu-pro version file
        version_file = "/opt/amdgpu-pro/VERSION"
        if os.path.exists(version_file):
            try:
                with open(version_file) as f:
                    version = f.read().strip()
            except OSError:
                pass

        # Method 2: Try dpkg for amdgpu-pro package
        if not version:
            try:
                result = subprocess.run(
                    ["dpkg", "-l", "amdgpu-pro"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "amdgpu-pro" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                version = parts[2]
                                break
            except (FileNotFoundError, OSError):
                pass

        # Method 3: Try rocm-smi for ROCm
        if not version:
            try:
                result = subprocess.run(
                    ["rocm-smi", "--showdriverversion"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    match = re.search(r"Driver version:\s*([\d.]+)", result.stdout)
                    if match:
                        version = match.group(1)
            except (FileNotFoundError, OSError):
                pass

        if not version:
            return None

        # Detect AMD GPUs using clinfo or lspci
        gpus = []
        try:
            result = subprocess.run(
                ["lspci", "-nn"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "VGA" in line and ("AMD" in line or "ATI" in line):
                        gpus.append({"name": line.split(": ")[1] if ": " in line else line})
        except (FileNotFoundError, OSError):
            pass

        return AmdDriverInfo(
            version=version,
            gpus=gpus,
        )

    except Exception as e:
        logger.debug(f"Error detecting AMD driver: {e}")
        return None


def detect_software() -> SoftwareStatus:
    """
    Detect all installed software (hashcat, drivers).

    Returns:
        SoftwareStatus object with all detected software
    """
    return SoftwareStatus(
        hashcat_versions=detect_hashcat_versions(),
        nvidia_driver=detect_nvidia_driver(),
        amd_driver=detect_amd_driver(),
    )


# Cache for software status
_cached_software_status: Optional[SoftwareStatus] = None


def get_software_status(refresh: bool = False) -> SoftwareStatus:
    """
    Get cached software installation status.

    Args:
        refresh: If True, re-detect software instead of using cache

    Returns:
        SoftwareStatus object
    """
    global _cached_software_status

    if _cached_software_status is None or refresh:
        _cached_software_status = detect_software()

    return _cached_software_status
