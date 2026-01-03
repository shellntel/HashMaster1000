"""
Timing Statistics Collection and Estimation

Collects granular timing data from key operations to provide accurate
load time estimates based on dataset sizes and system performance.

Data is persisted to JSON for use across app restarts and to build
better estimates over time.
"""

import json
import logging
import os
import statistics
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Default storage location
DEFAULT_STATS_FILE = "data/timing_stats.json"

# Fun messages to show during processing (Claude-style)
PROCESSING_MESSAGES = [
    "Crunching the numbers...",
    "Analyzing password patterns...",
    "Searching for weak passwords...",
    "Cross-referencing breach data...",
    "Building security insights...",
    "Detecting common patterns...",
    "Calculating risk metrics...",
    "Processing hash lookups...",
    "Mapping password reuse...",
    "Generating statistics...",
    "Almost there...",
    "Finalizing analysis...",
    "Running deep analysis...",
    "Checking breach databases...",
    "Evaluating password strength...",
    "Identifying security gaps...",
    "Compiling results...",
    "Wrapping up the analysis...",
]


@dataclass
class TimingSample:
    """A single timing measurement."""
    timestamp: str  # ISO format
    duration_seconds: float

    # Context about the operation
    item_count: int = 0  # e.g., number of hashes, accounts, potfile lines
    unique_count: int = 0  # e.g., unique hashes (for deduplication tracking)

    # Rate calculations
    items_per_second: float = 0.0

    # Additional context
    mode: str | None = None  # e.g., "sqlite", "binary_search", "api"
    cache_warm: bool = False
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "item_count": self.item_count,
            "unique_count": self.unique_count,
            "items_per_second": self.items_per_second,
            "mode": self.mode,
            "cache_warm": self.cache_warm,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimingSample":
        return cls(
            timestamp=data.get("timestamp", ""),
            duration_seconds=data.get("duration_seconds", 0),
            item_count=data.get("item_count", 0),
            unique_count=data.get("unique_count", 0),
            items_per_second=data.get("items_per_second", 0),
            mode=data.get("mode"),
            cache_warm=data.get("cache_warm", False),
            notes=data.get("notes"),
        )


@dataclass
class OperationStats:
    """Statistics for a specific operation type."""
    operation_name: str
    samples: list[TimingSample] = field(default_factory=list)

    # Calculated statistics (updated on save)
    avg_items_per_second: float = 0.0
    median_items_per_second: float = 0.0
    min_items_per_second: float = 0.0
    max_items_per_second: float = 0.0
    sample_count: int = 0

    # Duration statistics
    avg_duration_seconds: float = 0.0
    min_duration_seconds: float = 0.0
    max_duration_seconds: float = 0.0
    total_duration_seconds: float = 0.0
    total_items_processed: int = 0

    # Mode-specific rates (for HIBP with multiple modes)
    mode_rates: dict[str, float] = field(default_factory=dict)
    mode_durations: dict[str, float] = field(default_factory=dict)  # avg duration per mode

    def add_sample(self, sample: TimingSample) -> None:
        """Add a sample and recalculate statistics."""
        self.samples.append(sample)

        # Keep only last 100 samples to avoid unbounded growth
        if len(self.samples) > 100:
            self.samples = self.samples[-100:]

        self._recalculate_stats()

    def _recalculate_stats(self) -> None:
        """Recalculate aggregate statistics from samples."""
        if not self.samples:
            return

        rates = [s.items_per_second for s in self.samples if s.items_per_second > 0]
        if rates:
            self.avg_items_per_second = statistics.mean(rates)
            self.median_items_per_second = statistics.median(rates)
            self.min_items_per_second = min(rates)
            self.max_items_per_second = max(rates)

        # Duration statistics
        durations = [s.duration_seconds for s in self.samples if s.duration_seconds > 0]
        if durations:
            self.avg_duration_seconds = statistics.mean(durations)
            self.min_duration_seconds = min(durations)
            self.max_duration_seconds = max(durations)
            self.total_duration_seconds = sum(durations)

        # Total items processed
        self.total_items_processed = sum(s.item_count for s in self.samples)

        self.sample_count = len(self.samples)

        # Calculate mode-specific rates and durations
        mode_rate_samples: dict[str, list[float]] = {}
        mode_duration_samples: dict[str, list[float]] = {}
        for s in self.samples:
            if s.mode:
                if s.items_per_second > 0:
                    if s.mode not in mode_rate_samples:
                        mode_rate_samples[s.mode] = []
                    mode_rate_samples[s.mode].append(s.items_per_second)
                if s.duration_seconds > 0:
                    if s.mode not in mode_duration_samples:
                        mode_duration_samples[s.mode] = []
                    mode_duration_samples[s.mode].append(s.duration_seconds)

        self.mode_rates = {
            mode: statistics.mean(rates)
            for mode, rates in mode_rate_samples.items()
        }
        self.mode_durations = {
            mode: statistics.mean(durations)
            for mode, durations in mode_duration_samples.items()
        }

    def estimate_duration(
        self,
        item_count: int,
        mode: str | None = None
    ) -> float | None:
        """
        Estimate duration for a given item count.

        Returns estimated seconds, or None if no data available.
        """
        # Use mode-specific rate if available
        if mode and mode in self.mode_rates:
            rate = self.mode_rates[mode]
        elif self.median_items_per_second > 0:
            rate = self.median_items_per_second
        else:
            return None

        if rate <= 0:
            return None

        return item_count / rate

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_name": self.operation_name,
            "samples": [s.to_dict() for s in self.samples],
            "avg_items_per_second": self.avg_items_per_second,
            "median_items_per_second": self.median_items_per_second,
            "min_items_per_second": self.min_items_per_second,
            "max_items_per_second": self.max_items_per_second,
            "sample_count": self.sample_count,
            "avg_duration_seconds": self.avg_duration_seconds,
            "min_duration_seconds": self.min_duration_seconds,
            "max_duration_seconds": self.max_duration_seconds,
            "total_duration_seconds": self.total_duration_seconds,
            "total_items_processed": self.total_items_processed,
            "mode_rates": self.mode_rates,
            "mode_durations": self.mode_durations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OperationStats":
        stats = cls(operation_name=data.get("operation_name", "unknown"))
        stats.samples = [
            TimingSample.from_dict(s) for s in data.get("samples", [])
        ]
        stats.avg_items_per_second = data.get("avg_items_per_second", 0)
        stats.median_items_per_second = data.get("median_items_per_second", 0)
        stats.min_items_per_second = data.get("min_items_per_second", 0)
        stats.max_items_per_second = data.get("max_items_per_second", 0)
        stats.sample_count = data.get("sample_count", 0)
        stats.avg_duration_seconds = data.get("avg_duration_seconds", 0)
        stats.min_duration_seconds = data.get("min_duration_seconds", 0)
        stats.max_duration_seconds = data.get("max_duration_seconds", 0)
        stats.total_duration_seconds = data.get("total_duration_seconds", 0)
        stats.total_items_processed = data.get("total_items_processed", 0)
        stats.mode_rates = data.get("mode_rates", {})
        stats.mode_durations = data.get("mode_durations", {})
        return stats


@dataclass
class SystemInfo:
    """System information that affects performance."""
    # CPU info
    cpu_model: str = ""
    cpu_cores_physical: int = 0
    cpu_cores_logical: int = 0
    cpu_freq_mhz: float = 0.0
    cpu_freq_max_mhz: float = 0.0

    # Memory info
    memory_total_gb: float = 0.0
    memory_available_gb: float = 0.0

    # Disk info
    disk_type: str = ""  # "SSD", "HDD", "NVMe", "unknown"
    disk_total_gb: float = 0.0
    disk_free_gb: float = 0.0

    # OS info
    os_name: str = ""
    os_version: str = ""
    hostname: str = ""

    # Python info
    python_version: str = ""

    # Timestamp
    collected_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_model": self.cpu_model,
            "cpu_cores_physical": self.cpu_cores_physical,
            "cpu_cores_logical": self.cpu_cores_logical,
            "cpu_freq_mhz": self.cpu_freq_mhz,
            "cpu_freq_max_mhz": self.cpu_freq_max_mhz,
            "memory_total_gb": self.memory_total_gb,
            "memory_available_gb": self.memory_available_gb,
            "disk_type": self.disk_type,
            "disk_total_gb": self.disk_total_gb,
            "disk_free_gb": self.disk_free_gb,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "hostname": self.hostname,
            "python_version": self.python_version,
            "collected_at": self.collected_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SystemInfo":
        return cls(
            cpu_model=data.get("cpu_model", ""),
            cpu_cores_physical=data.get("cpu_cores_physical", 0),
            cpu_cores_logical=data.get("cpu_cores_logical", 0),
            cpu_freq_mhz=data.get("cpu_freq_mhz", 0.0),
            cpu_freq_max_mhz=data.get("cpu_freq_max_mhz", 0.0),
            memory_total_gb=data.get("memory_total_gb", 0.0),
            memory_available_gb=data.get("memory_available_gb", 0.0),
            disk_type=data.get("disk_type", ""),
            disk_total_gb=data.get("disk_total_gb", 0.0),
            disk_free_gb=data.get("disk_free_gb", 0.0),
            os_name=data.get("os_name", ""),
            os_version=data.get("os_version", ""),
            hostname=data.get("hostname", ""),
            python_version=data.get("python_version", ""),
            collected_at=data.get("collected_at", ""),
        )

    def summary(self) -> str:
        """One-line summary for display."""
        return (
            f"{self.hostname}: {self.cpu_model} ({self.cpu_cores_physical}c/{self.cpu_cores_logical}t), "
            f"{self.memory_total_gb:.1f}GB RAM, {self.disk_type}"
        )


def collect_system_info() -> SystemInfo:
    """Collect current system information."""
    import platform
    import socket
    import sys

    info = SystemInfo(collected_at=datetime.now().isoformat())

    # OS info
    info.os_name = platform.system()
    info.os_version = platform.release()
    info.hostname = socket.gethostname()
    info.python_version = sys.version.split()[0]

    # Try to get detailed CPU/memory/disk info
    try:
        import psutil

        # CPU
        info.cpu_cores_physical = psutil.cpu_count(logical=False) or 0
        info.cpu_cores_logical = psutil.cpu_count(logical=True) or 0

        freq = psutil.cpu_freq()
        if freq:
            info.cpu_freq_mhz = freq.current
            info.cpu_freq_max_mhz = freq.max if freq.max else freq.current

        # Memory
        mem = psutil.virtual_memory()
        info.memory_total_gb = round(mem.total / (1024**3), 2)
        info.memory_available_gb = round(mem.available / (1024**3), 2)

        # Disk
        disk = psutil.disk_usage('/')
        info.disk_total_gb = round(disk.total / (1024**3), 2)
        info.disk_free_gb = round(disk.free / (1024**3), 2)

    except ImportError:
        logger.debug("psutil not available, using fallback methods")
        info.cpu_cores_logical = os.cpu_count() or 0

        # Fallback for Linux: read from /proc and df
        if info.os_name == "Linux":
            try:
                # Memory from /proc/meminfo
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            kb = int(line.split()[1])
                            info.memory_total_gb = round(kb / (1024**2), 2)
                        elif line.startswith("MemAvailable:"):
                            kb = int(line.split()[1])
                            info.memory_available_gb = round(kb / (1024**2), 2)
            except Exception:
                pass

            try:
                # CPU cores from /proc/cpuinfo
                physical_ids = set()
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if line.startswith("physical id"):
                            physical_ids.add(line.split(":")[1].strip())
                        elif line.startswith("cpu cores"):
                            cores = int(line.split(":")[1].strip())
                            info.cpu_cores_physical = len(physical_ids) * cores if physical_ids else cores
                            break
                # Fallback: assume physical = logical / 2 for hyper-threaded
                if info.cpu_cores_physical == 0 and info.cpu_cores_logical > 0:
                    info.cpu_cores_physical = info.cpu_cores_logical // 2 or 1
            except Exception:
                pass

            try:
                # CPU frequency from /proc/cpuinfo or /sys
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if line.startswith("cpu MHz"):
                            info.cpu_freq_mhz = float(line.split(":")[1].strip())
                            break

                # Try to get max frequency from sysfs
                try:
                    with open("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", "r") as f:
                        khz = int(f.read().strip())
                        info.cpu_freq_max_mhz = khz / 1000
                except Exception:
                    info.cpu_freq_max_mhz = info.cpu_freq_mhz
            except Exception:
                pass

            try:
                # Disk from df command
                import subprocess
                result = subprocess.run(
                    ["df", "-B1", "/"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    if len(lines) >= 2:
                        parts = lines[1].split()
                        if len(parts) >= 4:
                            info.disk_total_gb = round(int(parts[1]) / (1024**3), 2)
                            info.disk_free_gb = round(int(parts[3]) / (1024**3), 2)
            except Exception:
                pass

    # CPU model (platform-specific)
    try:
        if info.os_name == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("model name"):
                        info.cpu_model = line.split(":")[1].strip()
                        break
        elif info.os_name == "Darwin":  # macOS
            import subprocess
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                info.cpu_model = result.stdout.strip()
        elif info.os_name == "Windows":
            info.cpu_model = platform.processor()
    except Exception as e:
        logger.debug(f"Could not get CPU model: {e}")
        info.cpu_model = platform.processor() or "unknown"

    # Disk type detection (Linux)
    try:
        if info.os_name == "Linux":
            # Try to detect if root disk is SSD/NVMe
            import subprocess
            result = subprocess.run(
                ["lsblk", "-d", "-o", "NAME,ROTA", "-n"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 2:
                        name, rotational = parts[0], parts[1]
                        # Check if this is the root device
                        if name.startswith("nvme"):
                            info.disk_type = "NVMe"
                            break
                        elif rotational == "0":
                            info.disk_type = "SSD"
                        else:
                            info.disk_type = "HDD"
            if not info.disk_type:
                info.disk_type = "unknown"
        else:
            info.disk_type = "unknown"
    except Exception as e:
        logger.debug(f"Could not detect disk type: {e}")
        info.disk_type = "unknown"

    return info


@dataclass
class StartupTiming:
    """Timing data for app startup operations."""
    timestamp: str
    total_startup_seconds: float = 0.0
    potfile_load_seconds: float = 0.0
    potfile_entries: int = 0
    hibp_init_seconds: float = 0.0
    hibp_mode: str | None = None
    hibp_hash_count: int = 0
    cache_warm: bool = False
    system_info: SystemInfo | None = None  # Capture system info at startup

    def to_dict(self) -> dict[str, Any]:
        result = {
            "timestamp": self.timestamp,
            "total_startup_seconds": self.total_startup_seconds,
            "potfile_load_seconds": self.potfile_load_seconds,
            "potfile_entries": self.potfile_entries,
            "hibp_init_seconds": self.hibp_init_seconds,
            "hibp_mode": self.hibp_mode,
            "hibp_hash_count": self.hibp_hash_count,
            "cache_warm": self.cache_warm,
        }
        if self.system_info:
            result["system_info"] = self.system_info.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StartupTiming":
        system_info = None
        if "system_info" in data and data["system_info"]:
            system_info = SystemInfo.from_dict(data["system_info"])
        return cls(
            timestamp=data.get("timestamp", ""),
            total_startup_seconds=data.get("total_startup_seconds", 0),
            potfile_load_seconds=data.get("potfile_load_seconds", 0),
            potfile_entries=data.get("potfile_entries", 0),
            hibp_init_seconds=data.get("hibp_init_seconds", 0),
            hibp_mode=data.get("hibp_mode"),
            hibp_hash_count=data.get("hibp_hash_count", 0),
            cache_warm=data.get("cache_warm", False),
            system_info=system_info,
        )


class TimingStats:
    """
    Singleton class for collecting and persisting timing statistics.

    Thread-safe for concurrent access.
    """

    _instance: "TimingStats | None" = None
    _lock = threading.Lock()

    # Operation types we track
    HIBP_CHECK = "hibp_check"  # HIBP hash lookups
    HIBP_RESULT_BUILD = "hibp_result_build"  # Building results with account data
    POTFILE_VALIDATION = "potfile_validation"  # Parsing potfile
    POTFILE_MASTER_LOAD = "potfile_master_load"  # Loading master potfile
    PWDUMP_VALIDATION = "pwdump_validation"  # Parsing pwdump file
    ADD_VALIDATION = "add_validation"  # Parsing ADD JSON
    ACCOUNT_DATA_BUILD = "account_data_build"  # Building account data
    CRACK_STATS = "crack_stats"  # Statistical analysis
    SUBSTRING_ANALYSIS = "substring_analysis"
    DICTIONARY_ANALYSIS = "dictionary_analysis"
    BAD_PRACTICES = "bad_practices"
    PASSWORD_REUSE = "password_reuse"
    PASSWORD_HISTORY = "password_history"
    SESSION_SAVE = "session_save"  # Saving session files
    REPORT_RENDER = "report_render"  # Rendering report page
    # Step 2 Validation additional operations
    HASH_EXTRACTION = "hash_extraction"  # Extracting hashes from pwdump for filtering
    MASTER_POTFILE_MERGE = "master_potfile_merge"  # Merging/filtering master potfile
    VALIDATION_RENDER = "validation_render"  # Rendering validate.html template
    VALIDATION_TOTAL = "validation_total"  # Total validation flow time
    # Step 3 Configuration operations
    MASTER_POTFILE_COUNT = "master_potfile_count"  # Counting entries in master potfile
    CONFIG_RENDER = "config_render"  # Rendering configuration template
    CONFIG_LOAD = "config_load"  # Total config page load time

    # Operation metadata: step number and display name
    # Steps: 1=Input, 2=Validation, 3=Configuration, 4=Report
    # is_total=True marks aggregate timings that include sub-operations
    OPERATION_METADATA: dict[str, dict[str, Any]] = {
        "pwdump_validation": {"step": 2, "name": "Pwdump Validation", "order": 1},
        "potfile_validation": {"step": 2, "name": "Potfile Validation", "order": 2},
        "potfile_master_load": {"step": 2, "name": "Master Potfile Load", "order": 3},
        "add_validation": {"step": 2, "name": "ADD JSON Validation", "order": 4},
        "hash_extraction": {"step": 2, "name": "Hash Extraction", "order": 5},
        "master_potfile_merge": {"step": 2, "name": "Master Potfile Merge", "order": 6},
        "validation_render": {"step": 2, "name": "Validation Page Render", "order": 7},
        "validation_total": {"step": 2, "name": "Total Validation Time", "order": 99, "is_total": True},
        # Step 3 Configuration
        "master_potfile_count": {"step": 3, "name": "Master Potfile Count", "order": 10},
        "config_render": {"step": 3, "name": "Template Rendering", "order": 11},
        "config_load": {"step": 3, "name": "Total Config Load", "order": 99, "is_total": True},
        # Step 4 Report
        "hibp_check": {"step": 4, "name": "HIBP Hash Lookups", "order": 20},
        "hibp_result_build": {"step": 4, "name": "HIBP Result Building", "order": 21},
        "crack_stats": {"step": 4, "name": "Crack Statistics", "order": 22},
        "substring_analysis": {"step": 4, "name": "Substring Analysis", "order": 23},
        "dictionary_analysis": {"step": 4, "name": "Dictionary Analysis", "order": 24},
        "bad_practices": {"step": 4, "name": "Bad Practices Analysis", "order": 25},
        "password_reuse": {"step": 4, "name": "Password Reuse Check", "order": 26},
        "password_history": {"step": 4, "name": "Password History Analysis", "order": 27},
        "session_save": {"step": 4, "name": "Session Save", "order": 28},
        "report_render": {"step": 4, "name": "Report Rendering", "order": 29},
        "report_generation": {"step": 4, "name": "Total Report Time", "order": 99, "is_total": True},
    }

    def __new__(cls) -> "TimingStats":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._stats_file = DEFAULT_STATS_FILE
        self._file_lock = threading.Lock()

        # In-memory storage
        self._operations: dict[str, OperationStats] = {}
        self._startup_history: list[StartupTiming] = []
        self._current_startup: StartupTiming | None = None

        # Active timers (for nested timing)
        self._active_timers: dict[str, float] = {}

        # Load existing data
        self._load()

    def set_stats_file(self, path: str) -> None:
        """Set custom path for stats file."""
        self._stats_file = path
        self._load()

    def _load(self) -> None:
        """Load timing data from disk."""
        if not os.path.exists(self._stats_file):
            return

        try:
            with open(self._stats_file, 'r') as f:
                data = json.load(f)

            # Load operations
            for op_name, op_data in data.get("operations", {}).items():
                self._operations[op_name] = OperationStats.from_dict(op_data)

            # Load startup history (keep last 20)
            startup_data = data.get("startup_history", [])
            self._startup_history = [
                StartupTiming.from_dict(s) for s in startup_data[-20:]
            ]

            logger.debug(f"Loaded timing stats: {len(self._operations)} operations")

        except Exception as e:
            logger.warning(f"Failed to load timing stats: {e}")

    def _save(self) -> None:
        """Save timing data to disk."""
        with self._file_lock:
            try:
                # Ensure directory exists
                os.makedirs(os.path.dirname(self._stats_file), exist_ok=True)

                data = {
                    "operations": {
                        name: stats.to_dict()
                        for name, stats in self._operations.items()
                    },
                    "startup_history": [
                        s.to_dict() for s in self._startup_history[-20:]
                    ],
                    "last_updated": datetime.now().isoformat(),
                }

                with open(self._stats_file, 'w') as f:
                    json.dump(data, f, indent=2)

            except Exception as e:
                logger.warning(f"Failed to save timing stats: {e}")

    # =========================================================================
    # Timer Context Manager
    # =========================================================================

    def timer(
        self,
        operation: str,
        item_count: int = 0,
        unique_count: int = 0,
        mode: str | None = None,
        cache_warm: bool = False,
        notes: str | None = None,
    ) -> "TimerContext":
        """
        Context manager for timing an operation.

        Usage:
            with timing_stats.timer("hibp_check", item_count=1000, mode="sqlite") as t:
                # do work
                t.update_count(actual_count)  # optional: update count if not known upfront
        """
        return TimerContext(
            self, operation, item_count, unique_count, mode, cache_warm, notes
        )

    def start_timer(self, operation: str) -> None:
        """Start a named timer (for manual timing)."""
        self._active_timers[operation] = time.time()

    def stop_timer(
        self,
        operation: str,
        item_count: int = 0,
        unique_count: int = 0,
        mode: str | None = None,
        cache_warm: bool = False,
        notes: str | None = None,
    ) -> float:
        """Stop a named timer and record the sample."""
        if operation not in self._active_timers:
            logger.warning(f"No active timer for operation: {operation}")
            return 0.0

        start_time = self._active_timers.pop(operation)
        duration = time.time() - start_time

        self.record_sample(
            operation, duration, item_count, unique_count, mode, cache_warm, notes
        )

        return duration

    def record_sample(
        self,
        operation: str,
        duration_seconds: float,
        item_count: int = 0,
        unique_count: int = 0,
        mode: str | None = None,
        cache_warm: bool = False,
        notes: str | None = None,
    ) -> None:
        """Record a timing sample for an operation."""
        # Calculate rate
        items_per_second = 0.0
        count_for_rate = unique_count if unique_count > 0 else item_count
        if duration_seconds > 0 and count_for_rate > 0:
            items_per_second = count_for_rate / duration_seconds

        sample = TimingSample(
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration_seconds,
            item_count=item_count,
            unique_count=unique_count,
            items_per_second=items_per_second,
            mode=mode,
            cache_warm=cache_warm,
            notes=notes,
        )

        # Get or create operation stats
        if operation not in self._operations:
            self._operations[operation] = OperationStats(operation_name=operation)

        self._operations[operation].add_sample(sample)

        # Log the timing
        rate_str = f" ({items_per_second:.0f}/s)" if items_per_second > 0 else ""
        logger.debug(
            f"Timing [{operation}]: {duration_seconds:.2f}s for {item_count} items{rate_str}"
        )

        # Save immediately after each operation to ensure persistence across restarts
        self._save()

    # =========================================================================
    # Startup Timing
    # =========================================================================

    def start_startup_timing(self) -> None:
        """Begin tracking app startup and capture system info."""
        self._current_startup = StartupTiming(
            timestamp=datetime.now().isoformat(),
            system_info=collect_system_info()
        )
        self._active_timers["_startup_total"] = time.time()

    def record_potfile_load(self, duration: float, entries: int) -> None:
        """Record potfile load timing during startup."""
        if self._current_startup:
            self._current_startup.potfile_load_seconds = duration
            self._current_startup.potfile_entries = entries

    def record_hibp_init(
        self,
        duration: float,
        mode: str,
        hash_count: int
    ) -> None:
        """Record HIBP initialization timing during startup."""
        if self._current_startup:
            self._current_startup.hibp_init_seconds = duration
            self._current_startup.hibp_mode = mode
            self._current_startup.hibp_hash_count = hash_count

    def finish_startup_timing(self) -> StartupTiming | None:
        """Complete startup timing and save."""
        if not self._current_startup:
            return None

        if "_startup_total" in self._active_timers:
            start_time = self._active_timers.pop("_startup_total")
            self._current_startup.total_startup_seconds = time.time() - start_time

        startup = self._current_startup
        self._startup_history.append(startup)
        self._current_startup = None

        self._save()

        logger.info(
            f"Startup complete in {startup.total_startup_seconds:.2f}s "
            f"(potfile: {startup.potfile_load_seconds:.2f}s, "
            f"hibp: {startup.hibp_init_seconds:.2f}s)"
        )

        return startup

    # =========================================================================
    # Estimation
    # =========================================================================

    def estimate_duration(
        self,
        operation: str,
        item_count: int,
        mode: str | None = None,
    ) -> float | None:
        """
        Estimate how long an operation will take.

        Returns estimated seconds, or None if no historical data.
        """
        if operation not in self._operations:
            return None

        return self._operations[operation].estimate_duration(item_count, mode)

    def estimate_hibp_check(
        self,
        total_accounts: int,
        unique_hashes: int | None = None,
        mode: str | None = None,
    ) -> dict[str, Any]:
        """
        Estimate HIBP check duration with detailed breakdown.

        Returns dict with:
            - lookup_seconds: Time for hash lookups
            - build_seconds: Time for building results
            - total_seconds: Total estimated time
            - confidence: "high", "medium", "low" based on sample count
        """
        result = {
            "lookup_seconds": None,
            "build_seconds": None,
            "total_seconds": None,
            "confidence": "low",
        }

        # Estimate lookup time based on unique hashes
        hash_count = unique_hashes if unique_hashes else total_accounts
        lookup_est = self.estimate_duration(self.HIBP_CHECK, hash_count, mode)
        if lookup_est:
            result["lookup_seconds"] = lookup_est

        # Estimate result building time based on total accounts
        build_est = self.estimate_duration(self.HIBP_RESULT_BUILD, total_accounts)
        if build_est:
            result["build_seconds"] = build_est

        # Calculate total
        if result["lookup_seconds"] is not None:
            result["total_seconds"] = result["lookup_seconds"]
            if result["build_seconds"]:
                result["total_seconds"] += result["build_seconds"]

        # Determine confidence based on sample count
        hibp_stats = self._operations.get(self.HIBP_CHECK)
        if hibp_stats:
            if hibp_stats.sample_count >= 10:
                result["confidence"] = "high"
            elif hibp_stats.sample_count >= 3:
                result["confidence"] = "medium"

        return result

    def estimate_processing_phase(
        self,
        account_count: int,
        cracked_count: int,
        hibp_enabled: bool = False,
        hibp_mode: str | None = None,
        unique_hash_count: int | None = None,
    ) -> dict[str, Any]:
        """
        Estimate total processing time for Phase 3 (Configuration & Processing).

        Returns dict with component breakdown and total.
        """
        estimates = {}
        total = 0.0

        # Account data build
        est = self.estimate_duration(self.ACCOUNT_DATA_BUILD, account_count)
        if est:
            estimates["account_data_build"] = est
            total += est

        # Crack stats
        est = self.estimate_duration(self.CRACK_STATS, account_count)
        if est:
            estimates["crack_stats"] = est
            total += est

        # Analysis operations (based on cracked count)
        for op in [self.SUBSTRING_ANALYSIS, self.DICTIONARY_ANALYSIS,
                   self.BAD_PRACTICES, self.PASSWORD_REUSE]:
            est = self.estimate_duration(op, cracked_count)
            if est:
                estimates[op] = est
                total += est

        # HIBP check
        if hibp_enabled:
            hibp_est = self.estimate_hibp_check(
                account_count, unique_hash_count, hibp_mode
            )
            if hibp_est["total_seconds"]:
                estimates["hibp_check"] = hibp_est["total_seconds"]
                total += hibp_est["total_seconds"]

        # Session save
        est = self.estimate_duration(self.SESSION_SAVE, account_count)
        if est:
            estimates["session_save"] = est
            total += est

        return {
            "estimates": estimates,
            "total_seconds": total if total > 0 else None,
            "components_available": len(estimates),
        }

    # =========================================================================
    # Status / Reporting
    # =========================================================================

    def get_status(self) -> dict[str, Any]:
        """Get comprehensive timing status for display."""
        status = {
            "operations": {},
            "startup_history": [s.to_dict() for s in self._startup_history[-5:]],
            "last_startup": None,
            "current_system": collect_system_info().to_dict(),
        }

        # Add operation summaries with metadata
        for name, stats in self._operations.items():
            # Get metadata for this operation
            metadata = self.OPERATION_METADATA.get(name, {"step": 0, "name": name, "order": 99})

            # Get last 3 durations from samples
            last_3_durations = []
            if stats.samples:
                recent_samples = stats.samples[-3:]
                last_3_durations = [round(s.duration_seconds, 4) for s in recent_samples]

            status["operations"][name] = {
                "sample_count": stats.sample_count,
                "avg_items_per_second": round(stats.avg_items_per_second, 2),
                "median_items_per_second": round(stats.median_items_per_second, 2),
                "min_items_per_second": round(stats.min_items_per_second, 2),
                "max_items_per_second": round(stats.max_items_per_second, 2),
                "avg_duration_seconds": round(stats.avg_duration_seconds, 4),
                "min_duration_seconds": round(stats.min_duration_seconds, 4),
                "max_duration_seconds": round(stats.max_duration_seconds, 4),
                "total_duration_seconds": round(stats.total_duration_seconds, 2),
                "total_items_processed": stats.total_items_processed,
                "mode_rates": {
                    k: round(v, 2) for k, v in stats.mode_rates.items()
                },
                "mode_durations": {
                    k: round(v, 4) for k, v in stats.mode_durations.items()
                },
                # New fields for enhanced display
                "step": metadata["step"],
                "display_name": metadata["name"],
                "order": metadata["order"],
                "last_3_durations": last_3_durations,
                "is_total": metadata.get("is_total", False),
            }

        # Last startup info
        if self._startup_history:
            status["last_startup"] = self._startup_history[-1].to_dict()

        return status

    def get_systems_comparison(self) -> list[dict[str, Any]]:
        """Get comparison of all systems that have run the app."""
        systems = {}
        for startup in self._startup_history:
            if startup.system_info and startup.system_info.hostname:
                hostname = startup.system_info.hostname
                if hostname not in systems:
                    systems[hostname] = {
                        "system_info": startup.system_info.to_dict(),
                        "runs": [],
                    }
                systems[hostname]["runs"].append({
                    "timestamp": startup.timestamp,
                    "total_startup_seconds": startup.total_startup_seconds,
                    "potfile_load_seconds": startup.potfile_load_seconds,
                    "potfile_entries": startup.potfile_entries,
                    "hibp_init_seconds": startup.hibp_init_seconds,
                    "hibp_mode": startup.hibp_mode,
                })
        return list(systems.values())

    def get_operation_details(self, operation: str) -> dict[str, Any] | None:
        """Get detailed info about a specific operation."""
        if operation not in self._operations:
            return None

        stats = self._operations[operation]
        return {
            "operation_name": operation,
            "sample_count": stats.sample_count,
            "avg_items_per_second": stats.avg_items_per_second,
            "median_items_per_second": stats.median_items_per_second,
            "min_items_per_second": stats.min_items_per_second,
            "max_items_per_second": stats.max_items_per_second,
            "mode_rates": stats.mode_rates,
            "recent_samples": [s.to_dict() for s in stats.samples[-10:]],
        }

    def clear_stats(self) -> None:
        """Clear all collected statistics."""
        self._operations.clear()
        self._startup_history.clear()
        self._save()
        logger.info("Timing statistics cleared")


class TimerContext:
    """Context manager for timing operations."""

    def __init__(
        self,
        stats: TimingStats,
        operation: str,
        item_count: int,
        unique_count: int,
        mode: str | None,
        cache_warm: bool,
        notes: str | None,
    ):
        self.stats = stats
        self.operation = operation
        self.item_count = item_count
        self.unique_count = unique_count
        self.mode = mode
        self.cache_warm = cache_warm
        self.notes = notes
        self.start_time: float = 0
        self.duration: float = 0

    def __enter__(self) -> "TimerContext":
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.duration = time.time() - self.start_time
        self.stats.record_sample(
            self.operation,
            self.duration,
            self.item_count,
            self.unique_count,
            self.mode,
            self.cache_warm,
            self.notes,
        )

    def update_count(self, item_count: int, unique_count: int = 0) -> None:
        """Update counts if not known at start."""
        self.item_count = item_count
        if unique_count > 0:
            self.unique_count = unique_count


# =========================================================================
# Module-level singleton access
# =========================================================================

def get_timing_stats() -> TimingStats:
    """Get the global TimingStats instance."""
    return TimingStats()


def get_processing_message(index: int | None = None) -> str:
    """Get a fun processing message (Claude-style)."""
    import random
    if index is not None:
        return PROCESSING_MESSAGES[index % len(PROCESSING_MESSAGES)]
    return random.choice(PROCESSING_MESSAGES)


def format_duration(seconds: float | None) -> str:
    """Format seconds as human-readable string."""
    if seconds is None:
        return "unknown"

    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_rate(items_per_second: float) -> str:
    """Format rate as human-readable string."""
    if items_per_second >= 1_000_000:
        return f"{items_per_second/1_000_000:.1f}M/s"
    elif items_per_second >= 1_000:
        return f"{items_per_second/1_000:.1f}K/s"
    else:
        return f"{items_per_second:.0f}/s"
