"""
Performance Tracking for HM1K.

Stores and analyzes:
- Job performance metrics (actual crack speeds)
- Benchmark results (per agent, per hash mode)
- GPU utilization and temperature data

Uses this data to estimate job durations based on real historical performance.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import sqlite3
import threading

logger = logging.getLogger(__name__)


@dataclass
class GPUMetrics:
    """GPU performance metrics during a job or benchmark."""
    gpu_index: int
    gpu_name: str
    speed_hs: float  # Hash/second for this GPU
    temperature: Optional[int] = None
    utilization: Optional[int] = None
    memory_used_mb: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "gpu_index": self.gpu_index,
            "gpu_name": self.gpu_name,
            "speed_hs": self.speed_hs,
            "temperature": self.temperature,
            "utilization": self.utilization,
            "memory_used_mb": self.memory_used_mb,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GPUMetrics":
        return cls(
            gpu_index=data["gpu_index"],
            gpu_name=data["gpu_name"],
            speed_hs=data["speed_hs"],
            temperature=data.get("temperature"),
            utilization=data.get("utilization"),
            memory_used_mb=data.get("memory_used_mb"),
        )


@dataclass
class BenchmarkResult:
    """A benchmark result for a specific hash mode on an agent."""
    agent_id: str
    hash_mode: int
    total_speed_hs: float  # Total hash/second across all devices
    gpus: list[GPUMetrics] = field(default_factory=list)
    timestamp: Optional[str] = None
    hashcat_version: Optional[str] = None
    cuda_version: Optional[str] = None
    driver_version: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "hash_mode": self.hash_mode,
            "total_speed_hs": self.total_speed_hs,
            "gpus": [g.to_dict() for g in self.gpus],
            "timestamp": self.timestamp,
            "hashcat_version": self.hashcat_version,
            "cuda_version": self.cuda_version,
            "driver_version": self.driver_version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BenchmarkResult":
        return cls(
            agent_id=data["agent_id"],
            hash_mode=data["hash_mode"],
            total_speed_hs=data["total_speed_hs"],
            gpus=[GPUMetrics.from_dict(g) for g in data.get("gpus", [])],
            timestamp=data.get("timestamp"),
            hashcat_version=data.get("hashcat_version"),
            cuda_version=data.get("cuda_version"),
            driver_version=data.get("driver_version"),
        )


@dataclass
class JobPerformanceMetrics:
    """Performance metrics from a completed crack job."""
    agent_id: str
    job_id: str
    hash_mode: int
    attack_mode: int

    # Timing
    started_at: str
    completed_at: str
    duration_seconds: float

    # Work done
    total_hashes: int
    hashes_cracked: int
    keyspace_total: int  # Total keyspace for brute force
    keyspace_processed: int

    # Speed metrics
    avg_speed_hs: float  # Average hash/second during job
    peak_speed_hs: float  # Peak speed observed
    speed_samples: list[float] = field(default_factory=list)  # Speed samples over time

    # GPU metrics during job
    gpus: list[GPUMetrics] = field(default_factory=list)
    max_gpu_temp: Optional[int] = None
    avg_gpu_util: Optional[float] = None

    # Attack-specific info
    wordlist_path: Optional[str] = None
    wordlist_size: Optional[int] = None
    rules_used: Optional[list[str]] = None
    mask_used: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "job_id": self.job_id,
            "hash_mode": self.hash_mode,
            "attack_mode": self.attack_mode,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "total_hashes": self.total_hashes,
            "hashes_cracked": self.hashes_cracked,
            "keyspace_total": self.keyspace_total,
            "keyspace_processed": self.keyspace_processed,
            "avg_speed_hs": self.avg_speed_hs,
            "peak_speed_hs": self.peak_speed_hs,
            "speed_samples": self.speed_samples,
            "gpus": [g.to_dict() for g in self.gpus],
            "max_gpu_temp": self.max_gpu_temp,
            "avg_gpu_util": self.avg_gpu_util,
            "wordlist_path": self.wordlist_path,
            "wordlist_size": self.wordlist_size,
            "rules_used": self.rules_used,
            "mask_used": self.mask_used,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JobPerformanceMetrics":
        return cls(
            agent_id=data["agent_id"],
            job_id=data["job_id"],
            hash_mode=data["hash_mode"],
            attack_mode=data["attack_mode"],
            started_at=data["started_at"],
            completed_at=data["completed_at"],
            duration_seconds=data["duration_seconds"],
            total_hashes=data["total_hashes"],
            hashes_cracked=data["hashes_cracked"],
            keyspace_total=data.get("keyspace_total", 0),
            keyspace_processed=data.get("keyspace_processed", 0),
            avg_speed_hs=data["avg_speed_hs"],
            peak_speed_hs=data.get("peak_speed_hs", data["avg_speed_hs"]),
            speed_samples=data.get("speed_samples", []),
            gpus=[GPUMetrics.from_dict(g) for g in data.get("gpus", [])],
            max_gpu_temp=data.get("max_gpu_temp"),
            avg_gpu_util=data.get("avg_gpu_util"),
            wordlist_path=data.get("wordlist_path"),
            wordlist_size=data.get("wordlist_size"),
            rules_used=data.get("rules_used"),
            mask_used=data.get("mask_used"),
        )


# Common hash modes to benchmark
BENCHMARK_HASH_MODES = [
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


class PerformanceTracker:
    """
    Tracks and stores performance metrics for crack jobs and benchmarks.

    Data is stored per-agent so Hash Master knows each agent's capabilities.
    """

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "performance.db"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database with required tables."""
        with sqlite3.connect(str(self.db_path)) as conn:
            # Check if we need to migrate the old schema
            cursor = conn.execute("PRAGMA table_info(benchmarks)")
            columns = {row[1] for row in cursor.fetchall()}

            if "cuda_version" not in columns and "benchmarks" in [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
                # Migrate existing table: add new columns and recreate with new unique constraint
                conn.execute("ALTER TABLE benchmarks RENAME TO benchmarks_old")
                conn.execute("""
                    CREATE TABLE benchmarks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_id TEXT NOT NULL,
                        hash_mode INTEGER NOT NULL,
                        total_speed_hs REAL NOT NULL,
                        gpus_json TEXT,
                        timestamp TEXT NOT NULL,
                        hashcat_version TEXT,
                        cuda_version TEXT,
                        driver_version TEXT,
                        UNIQUE(agent_id, hash_mode, hashcat_version)
                    )
                """)
                # Copy data from old table
                conn.execute("""
                    INSERT INTO benchmarks (agent_id, hash_mode, total_speed_hs, gpus_json, timestamp, hashcat_version)
                    SELECT agent_id, hash_mode, total_speed_hs, gpus_json, timestamp, hashcat_version
                    FROM benchmarks_old
                """)
                conn.execute("DROP TABLE benchmarks_old")
            else:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS benchmarks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_id TEXT NOT NULL,
                        hash_mode INTEGER NOT NULL,
                        total_speed_hs REAL NOT NULL,
                        gpus_json TEXT,
                        timestamp TEXT NOT NULL,
                        hashcat_version TEXT,
                        cuda_version TEXT,
                        driver_version TEXT,
                        UNIQUE(agent_id, hash_mode, hashcat_version)
                    )
                """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS job_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    hash_mode INTEGER NOT NULL,
                    attack_mode INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    total_hashes INTEGER NOT NULL,
                    hashes_cracked INTEGER NOT NULL,
                    keyspace_total INTEGER DEFAULT 0,
                    keyspace_processed INTEGER DEFAULT 0,
                    avg_speed_hs REAL NOT NULL,
                    peak_speed_hs REAL,
                    speed_samples_json TEXT,
                    gpus_json TEXT,
                    max_gpu_temp INTEGER,
                    avg_gpu_util REAL,
                    wordlist_path TEXT,
                    wordlist_size INTEGER,
                    rules_json TEXT,
                    mask_used TEXT,
                    UNIQUE(job_id)
                )
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_benchmarks_agent ON benchmarks(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_benchmarks_hash ON benchmarks(hash_mode)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_benchmarks_version ON benchmarks(hashcat_version)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_agent ON job_metrics(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_hash ON job_metrics(hash_mode)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_attack ON job_metrics(attack_mode)")
            conn.commit()

    def save_benchmark(self, result: BenchmarkResult) -> None:
        """
        Save a benchmark result. Replaces existing benchmark for same agent/hash_mode/version.

        Args:
            result: BenchmarkResult to save
        """
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO benchmarks
                    (agent_id, hash_mode, total_speed_hs, gpus_json, timestamp, hashcat_version, cuda_version, driver_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.agent_id,
                    result.hash_mode,
                    result.total_speed_hs,
                    json.dumps([g.to_dict() for g in result.gpus]),
                    result.timestamp or datetime.now().isoformat(),
                    result.hashcat_version,
                    result.cuda_version,
                    result.driver_version,
                ))
                conn.commit()
        logger.info(f"Saved benchmark for agent {result.agent_id}, hash mode {result.hash_mode}: {result.total_speed_hs:.0f} H/s")

    def save_job_metrics(self, metrics: JobPerformanceMetrics) -> None:
        """
        Save job performance metrics.

        Args:
            metrics: JobPerformanceMetrics to save
        """
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO job_metrics
                    (agent_id, job_id, hash_mode, attack_mode, started_at, completed_at,
                     duration_seconds, total_hashes, hashes_cracked, keyspace_total,
                     keyspace_processed, avg_speed_hs, peak_speed_hs, speed_samples_json,
                     gpus_json, max_gpu_temp, avg_gpu_util, wordlist_path, wordlist_size,
                     rules_json, mask_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metrics.agent_id,
                    metrics.job_id,
                    metrics.hash_mode,
                    metrics.attack_mode,
                    metrics.started_at,
                    metrics.completed_at,
                    metrics.duration_seconds,
                    metrics.total_hashes,
                    metrics.hashes_cracked,
                    metrics.keyspace_total,
                    metrics.keyspace_processed,
                    metrics.avg_speed_hs,
                    metrics.peak_speed_hs,
                    json.dumps(metrics.speed_samples),
                    json.dumps([g.to_dict() for g in metrics.gpus]),
                    metrics.max_gpu_temp,
                    metrics.avg_gpu_util,
                    metrics.wordlist_path,
                    metrics.wordlist_size,
                    json.dumps(metrics.rules_used) if metrics.rules_used else None,
                    metrics.mask_used,
                ))
                conn.commit()
        logger.info(f"Saved metrics for job {metrics.job_id}: {metrics.avg_speed_hs:.0f} H/s avg")

    def get_agent_benchmarks(self, agent_id: str) -> list[BenchmarkResult]:
        """
        Get all benchmark results for an agent.

        Args:
            agent_id: Agent ID to query

        Returns:
            List of BenchmarkResult objects
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM benchmarks WHERE agent_id = ?
            """, (agent_id,))

            results = []
            for row in cursor:
                results.append(BenchmarkResult(
                    agent_id=row["agent_id"],
                    hash_mode=row["hash_mode"],
                    total_speed_hs=row["total_speed_hs"],
                    gpus=[GPUMetrics.from_dict(g) for g in json.loads(row["gpus_json"] or "[]")],
                    timestamp=row["timestamp"],
                    hashcat_version=row["hashcat_version"],
                    cuda_version=row["cuda_version"],
                    driver_version=row["driver_version"],
                ))
            return results

    def get_benchmark(self, agent_id: str, hash_mode: int) -> Optional[BenchmarkResult]:
        """
        Get benchmark result for specific agent and hash mode.

        Args:
            agent_id: Agent ID
            hash_mode: Hash mode

        Returns:
            BenchmarkResult or None if not found
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM benchmarks WHERE agent_id = ? AND hash_mode = ?
            """, (agent_id, hash_mode))

            row = cursor.fetchone()
            if not row:
                return None

            return BenchmarkResult(
                agent_id=row["agent_id"],
                hash_mode=row["hash_mode"],
                total_speed_hs=row["total_speed_hs"],
                gpus=[GPUMetrics.from_dict(g) for g in json.loads(row["gpus_json"] or "[]")],
                timestamp=row["timestamp"],
                hashcat_version=row["hashcat_version"],
                cuda_version=row["cuda_version"],
                driver_version=row["driver_version"],
            )

    def get_fastest_benchmark(self, hash_mode: int) -> Optional[BenchmarkResult]:
        """
        Get the fastest benchmark for a hash mode across all agents.

        Args:
            hash_mode: Hash mode to query

        Returns:
            BenchmarkResult with highest speed or None if not found
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM benchmarks
                WHERE hash_mode = ?
                ORDER BY total_speed_hs DESC
                LIMIT 1
            """, (hash_mode,))

            row = cursor.fetchone()
            if not row:
                return None

            return BenchmarkResult(
                agent_id=row["agent_id"],
                hash_mode=row["hash_mode"],
                total_speed_hs=row["total_speed_hs"],
                gpus=[GPUMetrics.from_dict(g) for g in json.loads(row["gpus_json"] or "[]")],
                timestamp=row["timestamp"],
                hashcat_version=row["hashcat_version"],
                cuda_version=row["cuda_version"],
                driver_version=row["driver_version"],
            )

    def get_agent_job_history(
        self,
        agent_id: str,
        hash_mode: Optional[int] = None,
        attack_mode: Optional[int] = None,
        limit: int = 50
    ) -> list[JobPerformanceMetrics]:
        """
        Get job performance history for an agent.

        Args:
            agent_id: Agent ID
            hash_mode: Optional filter by hash mode
            attack_mode: Optional filter by attack mode
            limit: Maximum results to return

        Returns:
            List of JobPerformanceMetrics
        """
        query = "SELECT * FROM job_metrics WHERE agent_id = ?"
        params: list = [agent_id]

        if hash_mode is not None:
            query += " AND hash_mode = ?"
            params.append(hash_mode)

        if attack_mode is not None:
            query += " AND attack_mode = ?"
            params.append(attack_mode)

        query += " ORDER BY completed_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)

            results = []
            for row in cursor:
                results.append(JobPerformanceMetrics(
                    agent_id=row["agent_id"],
                    job_id=row["job_id"],
                    hash_mode=row["hash_mode"],
                    attack_mode=row["attack_mode"],
                    started_at=row["started_at"],
                    completed_at=row["completed_at"],
                    duration_seconds=row["duration_seconds"],
                    total_hashes=row["total_hashes"],
                    hashes_cracked=row["hashes_cracked"],
                    keyspace_total=row["keyspace_total"] or 0,
                    keyspace_processed=row["keyspace_processed"] or 0,
                    avg_speed_hs=row["avg_speed_hs"],
                    peak_speed_hs=row["peak_speed_hs"] or row["avg_speed_hs"],
                    speed_samples=json.loads(row["speed_samples_json"] or "[]"),
                    gpus=[GPUMetrics.from_dict(g) for g in json.loads(row["gpus_json"] or "[]")],
                    max_gpu_temp=row["max_gpu_temp"],
                    avg_gpu_util=row["avg_gpu_util"],
                    wordlist_path=row["wordlist_path"],
                    wordlist_size=row["wordlist_size"],
                    rules_used=json.loads(row["rules_json"]) if row["rules_json"] else None,
                    mask_used=row["mask_used"],
                ))
            return results

    def estimate_job_duration(
        self,
        agent_id: str,
        hash_mode: int,
        attack_mode: int,
        hash_count: int,
        keyspace: Optional[int] = None,
        wordlist_size: Optional[int] = None,
    ) -> Optional[dict]:
        """
        Estimate job duration based on historical data.

        Uses benchmark data for speed, then adjusts based on:
        - Attack mode (brute force uses keyspace, wordlist uses wordlist size)
        - Historical job performance for this hash mode/attack mode

        Args:
            agent_id: Agent to estimate for
            hash_mode: Target hash mode
            attack_mode: Attack mode (0=wordlist, 3=brute force, etc.)
            hash_count: Number of hashes to crack
            keyspace: Keyspace size for brute force attacks
            wordlist_size: Wordlist size for dictionary attacks

        Returns:
            Dict with estimate details or None if insufficient data
        """
        # First try to get benchmark speed for this hash mode
        benchmark = self.get_benchmark(agent_id, hash_mode)

        # Also get historical job data
        history = self.get_agent_job_history(
            agent_id,
            hash_mode=hash_mode,
            attack_mode=attack_mode,
            limit=10
        )

        if not benchmark and not history:
            return None

        # Calculate estimated speed
        if history:
            # Use average of historical speeds (more accurate than benchmark)
            historical_speed = sum(j.avg_speed_hs for j in history) / len(history)
        else:
            historical_speed = None

        benchmark_speed = benchmark.total_speed_hs if benchmark else None

        # Prefer historical speed if available, fall back to benchmark
        estimated_speed = historical_speed or benchmark_speed
        if not estimated_speed:
            return None

        # Calculate estimated duration based on attack type
        if attack_mode == 3 and keyspace:  # Brute force
            # For brute force, time = keyspace / speed
            estimated_seconds = keyspace / estimated_speed
            work_unit = "keyspace"
            work_total = keyspace
        elif attack_mode == 0 and wordlist_size:  # Wordlist
            # For wordlist, time = (wordlist_size * hash_count) / speed
            # Each word is tested against each hash
            estimated_seconds = (wordlist_size * hash_count) / estimated_speed
            work_unit = "candidates"
            work_total = wordlist_size * hash_count
        else:
            # Fallback: use hash count as rough estimate
            estimated_seconds = hash_count / estimated_speed
            work_unit = "hashes"
            work_total = hash_count

        return {
            "agent_id": agent_id,
            "hash_mode": hash_mode,
            "attack_mode": attack_mode,
            "estimated_seconds": estimated_seconds,
            "estimated_speed_hs": estimated_speed,
            "speed_source": "historical" if historical_speed else "benchmark",
            "work_total": work_total,
            "work_unit": work_unit,
            "benchmark_available": benchmark is not None,
            "historical_jobs": len(history),
            "confidence": "high" if history else ("medium" if benchmark else "low"),
        }

    def agent_needs_benchmark(self, agent_id: str) -> dict:
        """
        Check if an agent needs to run benchmarks.

        Returns:
            Dict with benchmark status and recommendations
        """
        benchmarks = self.get_agent_benchmarks(agent_id)
        existing_modes = {b.hash_mode for b in benchmarks}

        missing_modes = [m for m in BENCHMARK_HASH_MODES if m not in existing_modes]

        # Check benchmark freshness (recommend re-benchmark after 30 days)
        stale_modes = []
        for b in benchmarks:
            if b.timestamp:
                try:
                    bench_time = datetime.fromisoformat(b.timestamp)
                    age_days = (datetime.now() - bench_time).days
                    if age_days > 30:
                        stale_modes.append(b.hash_mode)
                except (ValueError, TypeError):
                    pass

        return {
            "agent_id": agent_id,
            "needs_benchmark": len(missing_modes) > 0,
            "has_any_benchmarks": len(benchmarks) > 0,
            "benchmarked_modes": len(existing_modes),
            "total_recommended_modes": len(BENCHMARK_HASH_MODES),
            "missing_modes": missing_modes,
            "stale_modes": stale_modes,
            "recommendation": self._get_benchmark_recommendation(benchmarks, missing_modes, stale_modes),
        }

    def _get_benchmark_recommendation(
        self,
        benchmarks: list,
        missing: list,
        stale: list
    ) -> str:
        """Generate a human-readable benchmark recommendation."""
        if not benchmarks:
            return "No benchmarks found. Running benchmarks is recommended to enable job time estimates."

        if missing:
            return f"Benchmarks available for {len(benchmarks)} hash types. {len(missing)} common types not yet benchmarked."

        if stale:
            return f"All common hash types benchmarked. {len(stale)} benchmarks are over 30 days old and may benefit from refresh."

        return "All benchmarks are current."

    def get_all_agents_summary(self) -> list[dict]:
        """
        Get performance summary for all agents.

        Returns:
            List of agent performance summaries
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row

            # Get unique agents
            agents_cursor = conn.execute("""
                SELECT DISTINCT agent_id FROM (
                    SELECT agent_id FROM benchmarks
                    UNION
                    SELECT agent_id FROM job_metrics
                )
            """)

            summaries = []
            for row in agents_cursor:
                agent_id = row["agent_id"]

                # Count benchmarks
                bench_count = conn.execute(
                    "SELECT COUNT(*) FROM benchmarks WHERE agent_id = ?",
                    (agent_id,)
                ).fetchone()[0]

                # Count jobs
                job_count = conn.execute(
                    "SELECT COUNT(*) FROM job_metrics WHERE agent_id = ?",
                    (agent_id,)
                ).fetchone()[0]

                # Get latest benchmark timestamp
                latest_bench = conn.execute(
                    "SELECT MAX(timestamp) FROM benchmarks WHERE agent_id = ?",
                    (agent_id,)
                ).fetchone()[0]

                # Get latest job timestamp
                latest_job = conn.execute(
                    "SELECT MAX(completed_at) FROM job_metrics WHERE agent_id = ?",
                    (agent_id,)
                ).fetchone()[0]

                summaries.append({
                    "agent_id": agent_id,
                    "benchmark_count": bench_count,
                    "job_count": job_count,
                    "latest_benchmark": latest_bench,
                    "latest_job": latest_job,
                    "needs_benchmark": self.agent_needs_benchmark(agent_id)["needs_benchmark"],
                })

            return summaries
