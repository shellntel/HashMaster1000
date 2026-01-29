"""
Resource cache for wordlists, rules, and other job resources.

Provides:
- Automatic download of resources from HM1K server
- LRU eviction when cache exceeds size limit
- Hash verification for integrity
- Background sync of commonly used resources
- Compressed download support (zstd) for faster transfers
"""

import hashlib
import json
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import logging

try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False

from hm1k_agent.config import Config
from hm1k_agent.api_client import APIClient

logger = logging.getLogger(__name__)


@dataclass
class CachedResource:
    """Metadata for a cached resource."""

    resource_id: str
    name: str
    resource_type: str  # "wordlist", "rules", "masks"
    local_path: str
    size_bytes: int
    sha256: str
    downloaded_at: float
    last_accessed: float
    access_count: int = 0
    partial_hash: Optional[str] = None  # Fast verification hash

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "resource_type": self.resource_type,
            "local_path": self.local_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "partial_hash": self.partial_hash,
            "downloaded_at": self.downloaded_at,
            "last_accessed": self.last_accessed,
            "access_count": self.access_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CachedResource":
        """Create from dictionary."""
        return cls(
            resource_id=data["resource_id"],
            name=data["name"],
            resource_type=data["resource_type"],
            local_path=data["local_path"],
            size_bytes=data["size_bytes"],
            sha256=data["sha256"],
            downloaded_at=data["downloaded_at"],
            last_accessed=data["last_accessed"],
            access_count=data.get("access_count", 0),
            partial_hash=data.get("partial_hash"),
        )


@dataclass
class ResourceInfo:
    """Information about a remote resource from the server."""

    resource_id: str
    name: str
    resource_type: str
    size_bytes: int
    sha256: str
    updated_at: str
    partial_hash: Optional[str] = None  # Fast verification hash


class ResourceCache:
    """
    Manages local cache of wordlists, rules, and other resources.

    Features:
    - Downloads resources on-demand from HM1K server
    - LRU eviction when cache exceeds configured size
    - Integrity verification via SHA256
    - Persistent index stored in JSON
    """

    INDEX_FILE = "cache_index.json"

    def __init__(self, config: Config, api_client: APIClient):
        """
        Initialize the resource cache.

        Args:
            config: Agent configuration
            api_client: REST API client for downloads
        """
        self.config = config
        self.api = api_client
        self.cache_dir = Path(config.resources.cache_dir)
        self.max_size = config.resources.max_cache_size_gb * 1024 * 1024 * 1024

        self._resources: dict[str, CachedResource] = {}
        self._lock = threading.Lock()
        self._download_in_progress: set[str] = set()

        self._ensure_cache_dir()
        self._load_index()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory structure if it doesn't exist."""
        for subdir in ["wordlists", "rules", "masks"]:
            (self.cache_dir / subdir).mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> None:
        """Load cache index from disk."""
        index_path = self.cache_dir / self.INDEX_FILE
        if index_path.exists():
            try:
                with open(index_path, "r") as f:
                    data = json.load(f)
                    for item in data.get("resources", []):
                        resource = CachedResource.from_dict(item)
                        # Verify file still exists
                        if Path(resource.local_path).exists():
                            self._resources[resource.resource_id] = resource
                        else:
                            logger.warning(f"Cached file missing: {resource.local_path}")
                logger.info(f"Loaded cache index with {len(self._resources)} resources")
            except Exception as e:
                logger.error(f"Failed to load cache index: {e}")
                self._resources = {}

    def _save_index(self) -> None:
        """Save cache index to disk."""
        index_path = self.cache_dir / self.INDEX_FILE
        try:
            data = {
                "version": 1,
                "updated_at": datetime.utcnow().isoformat(),
                "resources": [r.to_dict() for r in self._resources.values()],
            }
            with open(index_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache index: {e}")

    def get(self, resource_id: str) -> Optional[str]:
        """
        Get local path for a resource, downloading if necessary.

        Args:
            resource_id: Unique resource identifier

        Returns:
            Local file path, or None if download failed
        """
        with self._lock:
            if resource_id in self._resources:
                resource = self._resources[resource_id]
                resource.last_accessed = time.time()
                resource.access_count += 1
                self._save_index()
                return resource.local_path

        # Need to download - get resource info first
        resource_info = self._get_resource_info(resource_id)
        if not resource_info:
            logger.error(f"Resource not found on server: {resource_id}")
            return None

        return self._download_resource(resource_info)

    def _get_resource_info(self, resource_id: str) -> Optional[ResourceInfo]:
        """Get resource information from server."""
        try:
            # Search across all resource types to find the resource by ID
            for resource_type in ["wordlists", "rules", "masks"]:
                resources = self.api.get_resource_list(resource_type)
                for r in resources:
                    if r.get("resource_id") == resource_id:
                        return ResourceInfo(
                            resource_id=r["resource_id"],
                            name=r["name"],
                            resource_type=r.get("type", resource_type),
                            size_bytes=r["size_bytes"],
                            sha256=r["sha256"],
                            updated_at=r.get("updated_at", ""),
                            partial_hash=r.get("partial_hash"),
                        )
            return None
        except Exception as e:
            logger.error(f"Failed to get resource info: {e}")
            return None

    # Minimum size to attempt compressed download (100 MB)
    COMPRESSION_THRESHOLD = 100 * 1024 * 1024

    def _download_resource(self, info: ResourceInfo) -> Optional[str]:
        """
        Download a resource from the server.

        For large files (>100MB), attempts compressed download first if zstd is available.
        Falls back to regular download if compressed version not available.

        Args:
            info: Resource information

        Returns:
            Local file path, or None if download failed
        """
        # Check if already downloading
        with self._lock:
            if info.resource_id in self._download_in_progress:
                logger.info(f"Download already in progress: {info.name}")
                # Wait for download to complete
                while info.resource_id in self._download_in_progress:
                    self._lock.release()
                    time.sleep(0.5)
                    self._lock.acquire()
                return self._resources.get(info.resource_id, {}).local_path if info.resource_id in self._resources else None

            self._download_in_progress.add(info.resource_id)

        try:
            # Ensure we have space
            self._ensure_space(info.size_bytes)

            # Determine local path
            subdir = self.cache_dir / info.resource_type
            local_path = subdir / f"{info.resource_id}_{info.name}"

            logger.info(f"Downloading resource: {info.name} ({info.size_bytes / 1024 / 1024:.1f} MB)")

            # Try compressed download for large files if zstd is available
            download_success = False
            used_compression = False

            if ZSTD_AVAILABLE and info.size_bytes >= self.COMPRESSION_THRESHOLD:
                compressed_path = Path(str(local_path) + ".zst")
                logger.info(f"Attempting compressed download for {info.name}...")

                if self.api.download_resource_compressed(info.resource_type, info.resource_id, str(compressed_path)):
                    # Decompress the file
                    try:
                        logger.info(f"Decompressing {info.name}...")
                        dctx = zstd.ZstdDecompressor()
                        with open(compressed_path, "rb") as f_in:
                            with open(local_path, "wb") as f_out:
                                dctx.copy_stream(f_in, f_out)

                        # Remove compressed file
                        compressed_path.unlink(missing_ok=True)
                        download_success = True
                        used_compression = True
                        logger.info(f"Decompressed {info.name} successfully")
                    except Exception as e:
                        logger.warning(f"Decompression failed for {info.name}: {e}")
                        compressed_path.unlink(missing_ok=True)
                        local_path.unlink(missing_ok=True)
                else:
                    logger.debug(f"Compressed version not available for {info.name}")

            # Fall back to regular download if compressed didn't work
            if not download_success:
                if not self.api.download_resource(info.resource_type, info.resource_id, str(local_path)):
                    logger.error(f"Failed to download resource: {info.name}")
                    return None
                download_success = True

            # Verify downloaded file size first
            actual_size = local_path.stat().st_size
            if actual_size != info.size_bytes:
                logger.error(f"Size mismatch for {info.name}: expected {info.size_bytes}, got {actual_size}")
                local_path.unlink(missing_ok=True)
                return None

            # Verify integrity using partial hash (fast) or full SHA256 (fallback)
            if info.partial_hash:
                # Use fast partial hash verification
                actual_hash = self._compute_partial_hash(str(local_path), actual_size)
                if actual_hash != info.partial_hash:
                    logger.error(f"Partial hash mismatch for {info.name}: expected {info.partial_hash}, got {actual_hash}")
                    local_path.unlink(missing_ok=True)
                    return None
                logger.debug(f"Verified {info.name} using partial hash")
            elif not info.sha256.startswith("large_file_"):
                # Fall back to full SHA256 if available (not a placeholder)
                actual_hash = self._compute_sha256(str(local_path))
                if actual_hash != info.sha256:
                    logger.error(f"SHA256 mismatch for {info.name}: expected {info.sha256}, got {actual_hash}")
                    local_path.unlink(missing_ok=True)
                    return None
                logger.debug(f"Verified {info.name} using full SHA256")
            else:
                # No verification available (legacy large file without partial hash)
                logger.warning(f"No hash verification available for {info.name}, relying on size check only")

            # Add to cache
            now = time.time()
            resource = CachedResource(
                resource_id=info.resource_id,
                name=info.name,
                resource_type=info.resource_type,
                local_path=str(local_path),
                size_bytes=info.size_bytes,
                sha256=info.sha256,
                downloaded_at=now,
                last_accessed=now,
                access_count=1,
                partial_hash=info.partial_hash,
            )

            with self._lock:
                self._resources[info.resource_id] = resource
                self._save_index()

            transfer_method = "compressed + decompressed" if used_compression else "uncompressed"
            logger.info(f"Resource cached ({transfer_method}): {info.name}")
            return str(local_path)

        except Exception as e:
            logger.error(f"Download failed for {info.name}: {e}")
            return None

        finally:
            with self._lock:
                self._download_in_progress.discard(info.resource_id)

    def _compute_sha256(self, file_path: str) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    # Size of chunks for partial hash (1MB) - must match server
    PARTIAL_HASH_CHUNK_SIZE = 1024 * 1024

    def _compute_partial_hash(self, file_path: str, size_bytes: int) -> str:
        """
        Compute a fast partial hash for verification.

        This matches the server's partial hash computation:
        - First 1MB of the file
        - Last 1MB of the file (if file > 2MB)
        - File size

        Args:
            file_path: Path to the file
            size_bytes: Size of the file in bytes

        Returns:
            Hexadecimal hash string
        """
        sha256 = hashlib.sha256()
        chunk_size = self.PARTIAL_HASH_CHUNK_SIZE

        with open(file_path, "rb") as f:
            # Read first chunk
            first_chunk = f.read(chunk_size)
            sha256.update(first_chunk)

            # If file is larger than 2 chunks, read the last chunk
            if size_bytes > 2 * chunk_size:
                f.seek(-chunk_size, 2)  # Seek to last 1MB
                last_chunk = f.read(chunk_size)
                sha256.update(last_chunk)

        # Include file size in the hash
        sha256.update(str(size_bytes).encode())

        return sha256.hexdigest()

    def _ensure_space(self, needed_bytes: int) -> None:
        """Ensure there's enough space in cache, evicting if necessary."""
        with self._lock:
            current_size = sum(r.size_bytes for r in self._resources.values())

            while current_size + needed_bytes > self.max_size and self._resources:
                # Evict least recently used
                lru_resource = min(self._resources.values(), key=lambda r: r.last_accessed)
                self._evict(lru_resource)
                current_size = sum(r.size_bytes for r in self._resources.values())

    def _evict(self, resource: CachedResource) -> None:
        """Remove a resource from cache (must hold lock)."""
        logger.info(f"Evicting cached resource: {resource.name}")

        # Delete file
        try:
            Path(resource.local_path).unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to delete cached file: {e}")

        # Remove from index
        del self._resources[resource.resource_id]
        self._save_index()

    def sync_resources(self, resource_ids: list[str]) -> None:
        """
        Pre-download resources in the background.

        Args:
            resource_ids: List of resource IDs to sync
        """
        for resource_id in resource_ids:
            if resource_id not in self._resources:
                threading.Thread(
                    target=self.get,
                    args=(resource_id,),
                    daemon=True,
                ).start()

    def invalidate(self, resource_id: str) -> None:
        """
        Remove a resource from cache (e.g., if server has newer version).

        Args:
            resource_id: Resource to invalidate
        """
        with self._lock:
            if resource_id in self._resources:
                self._evict(self._resources[resource_id])

    def clear(self) -> None:
        """Clear all cached resources."""
        with self._lock:
            for resource in list(self._resources.values()):
                self._evict(resource)
            logger.info("Cache cleared")

    @property
    def cached_resources(self) -> list[CachedResource]:
        """Get list of all cached resources."""
        with self._lock:
            return list(self._resources.values())

    @property
    def cache_size_bytes(self) -> int:
        """Get total size of cached resources in bytes."""
        with self._lock:
            return sum(r.size_bytes for r in self._resources.values())

    @property
    def cache_size_mb(self) -> float:
        """Get total size of cached resources in MB."""
        return self.cache_size_bytes / 1024 / 1024

    def get_stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            resources = list(self._resources.values())

        return {
            "total_resources": len(resources),
            "total_size_mb": sum(r.size_bytes for r in resources) / 1024 / 1024,
            "max_size_gb": self.max_size / 1024 / 1024 / 1024,
            "by_type": {
                "wordlists": len([r for r in resources if r.resource_type == "wordlists"]),
                "rules": len([r for r in resources if r.resource_type == "rules"]),
                "masks": len([r for r in resources if r.resource_type == "masks"]),
            },
        }
