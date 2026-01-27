"""
Resource Manager for HM1K.

Manages centralized storage of:
- Wordlists (dictionaries for password cracking)
- Rules (hashcat rule files for word mutations)
- Masks (custom mask files for brute force)

Resources are stored on the server and synced to agents on demand.
"""

import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import threading

logger = logging.getLogger(__name__)


@dataclass
class Resource:
    """Represents a stored resource (wordlist, rules, etc.)."""
    resource_id: str
    name: str
    resource_type: str  # "wordlists", "rules", "masks"
    description: str
    file_path: str
    size_bytes: int
    sha256: str
    line_count: Optional[int]  # Number of entries/rules
    uploaded_at: str
    uploaded_by: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    is_builtin: bool = False

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "resource_type": self.resource_type,
            "type": self.resource_type,  # Alias for agent compatibility
            "description": self.description,
            "file_path": self.file_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "line_count": self.line_count,
            "uploaded_at": self.uploaded_at,
            "uploaded_by": self.uploaded_by,
            "tags": self.tags,
            "is_builtin": self.is_builtin,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Resource":
        return cls(
            resource_id=data["resource_id"],
            name=data["name"],
            resource_type=data.get("resource_type", data.get("type", "wordlists")),
            description=data.get("description", ""),
            file_path=data["file_path"],
            size_bytes=data["size_bytes"],
            sha256=data["sha256"],
            line_count=data.get("line_count"),
            uploaded_at=data["uploaded_at"],
            uploaded_by=data.get("uploaded_by"),
            tags=data.get("tags", []),
            is_builtin=data.get("is_builtin", False),
        )


class ResourceManager:
    """
    Manages centralized resource storage for HM1K.

    Resources are stored in the data directory with an index file
    tracking metadata. Files are organized by type:
      resources/
        wordlists/
        rules/
        masks/
        index.json
    """

    INDEX_FILE = "index.json"

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.resources_dir = self.data_dir / "resources"
        self._resources: dict[str, Resource] = {}
        self._lock = threading.Lock()

        self._ensure_directories()
        self._load_index()

    def _ensure_directories(self) -> None:
        """Create resource directories if they don't exist."""
        for subdir in ["wordlists", "rules", "masks"]:
            (self.resources_dir / subdir).mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> None:
        """Load resource index from disk."""
        index_path = self.resources_dir / self.INDEX_FILE
        if index_path.exists():
            try:
                with open(index_path, "r") as f:
                    data = json.load(f)
                    for item in data.get("resources", []):
                        resource = Resource.from_dict(item)
                        # Verify file still exists
                        if Path(resource.file_path).exists():
                            self._resources[resource.resource_id] = resource
                        else:
                            logger.warning(f"Resource file missing: {resource.file_path}")
                logger.info(f"Loaded resource index with {len(self._resources)} resources")
            except Exception as e:
                logger.error(f"Failed to load resource index: {e}")
                self._resources = {}

    def _save_index(self) -> None:
        """Save resource index to disk."""
        index_path = self.resources_dir / self.INDEX_FILE
        try:
            data = {
                "version": 1,
                "updated_at": datetime.now().isoformat(),
                "resources": [r.to_dict() for r in self._resources.values()],
            }
            with open(index_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save resource index: {e}")

    def _generate_id(self, name: str, resource_type: str) -> str:
        """Generate a unique resource ID."""
        import uuid
        # Use first 8 chars of UUID + sanitized name
        base = f"{resource_type}_{name.lower().replace(' ', '_')}"
        return f"{base}_{uuid.uuid4().hex[:8]}"

    def _compute_sha256(self, file_path: str) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _count_lines(self, file_path: str) -> int:
        """Count lines in a file."""
        try:
            with open(file_path, "rb") as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    def _sanitize_filename(self, name: str) -> str:
        """
        Sanitize a filename for safe filesystem storage.

        Replaces spaces and other problematic characters with underscores.
        """
        import re
        # Replace spaces and other problematic characters
        sanitized = re.sub(r'[\s\\/:"*?<>|]+', '_', name)
        # Remove leading/trailing underscores
        sanitized = sanitized.strip('_')
        return sanitized or 'unnamed'

    def add_resource(
        self,
        name: str,
        resource_type: str,
        file_content: bytes,
        description: str = "",
        uploaded_by: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Resource:
        """
        Add a new resource to the storage.

        Args:
            name: Resource name (e.g., "rockyou.txt")
            resource_type: Type ("wordlists", "rules", "masks")
            file_content: Raw file content
            description: Optional description
            uploaded_by: Username who uploaded
            tags: Optional list of tags

        Returns:
            Created Resource object
        """
        if resource_type not in ["wordlists", "rules", "masks"]:
            raise ValueError(f"Invalid resource type: {resource_type}")

        resource_id = self._generate_id(name, resource_type)

        # Save file with sanitized filename (no spaces or special chars)
        safe_name = self._sanitize_filename(name)
        file_path = self.resources_dir / resource_type / f"{resource_id}_{safe_name}"
        with open(file_path, "wb") as f:
            f.write(file_content)

        # Compute metadata
        sha256 = self._compute_sha256(str(file_path))
        size_bytes = len(file_content)
        line_count = self._count_lines(str(file_path))

        resource = Resource(
            resource_id=resource_id,
            name=name,
            resource_type=resource_type,
            description=description,
            file_path=str(file_path),
            size_bytes=size_bytes,
            sha256=sha256,
            line_count=line_count,
            uploaded_at=datetime.now().isoformat(),
            uploaded_by=uploaded_by,
            tags=tags or [],
            is_builtin=False,
        )

        with self._lock:
            self._resources[resource_id] = resource
            self._save_index()

        logger.info(f"Added resource: {name} ({resource_type}), {size_bytes / 1024:.1f} KB, {line_count} lines")
        return resource

    def get_resource(self, resource_id: str) -> Optional[Resource]:
        """Get a resource by ID."""
        with self._lock:
            return self._resources.get(resource_id)

    def get_resource_file(self, resource_id: str) -> Optional[str]:
        """Get the file path for a resource."""
        resource = self.get_resource(resource_id)
        if resource and Path(resource.file_path).exists():
            return resource.file_path
        return None

    def delete_resource(self, resource_id: str) -> bool:
        """
        Delete a resource.

        Args:
            resource_id: Resource to delete

        Returns:
            True if deleted, False if not found or is builtin
        """
        with self._lock:
            resource = self._resources.get(resource_id)
            if not resource:
                return False

            if resource.is_builtin:
                logger.warning(f"Cannot delete builtin resource: {resource.name}")
                return False

            # Delete file
            try:
                Path(resource.file_path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"Failed to delete resource file: {e}")

            del self._resources[resource_id]
            self._save_index()

        logger.info(f"Deleted resource: {resource.name}")
        return True

    def list_resources(
        self,
        resource_type: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> list[Resource]:
        """
        List resources with optional filtering.

        Args:
            resource_type: Filter by type
            tags: Filter by tags (any match)

        Returns:
            List of matching resources
        """
        with self._lock:
            resources = list(self._resources.values())

        if resource_type:
            resources = [r for r in resources if r.resource_type == resource_type]

        if tags:
            resources = [r for r in resources if any(t in r.tags for t in tags)]

        # Sort by name
        resources.sort(key=lambda r: r.name.lower())
        return resources

    def get_resource_by_name(self, name: str, resource_type: str) -> Optional[Resource]:
        """Get a resource by name and type."""
        with self._lock:
            for resource in self._resources.values():
                if resource.name == name and resource.resource_type == resource_type:
                    return resource
        return None

    def update_resource(
        self,
        resource_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Optional[Resource]:
        """
        Update resource metadata.

        Args:
            resource_id: Resource to update
            name: New name (or None to keep)
            description: New description (or None to keep)
            tags: New tags (or None to keep)

        Returns:
            Updated resource or None if not found
        """
        with self._lock:
            resource = self._resources.get(resource_id)
            if not resource:
                return None

            if name is not None:
                resource.name = name
            if description is not None:
                resource.description = description
            if tags is not None:
                resource.tags = tags

            self._save_index()
            return resource

    def get_stats(self) -> dict:
        """Get resource storage statistics."""
        with self._lock:
            resources = list(self._resources.values())

        stats_by_type = {}
        for resource_type in ["wordlists", "rules", "masks"]:
            type_resources = [r for r in resources if r.resource_type == resource_type]
            stats_by_type[resource_type] = {
                "count": len(type_resources),
                "total_size_bytes": sum(r.size_bytes for r in type_resources),
                "total_lines": sum(r.line_count or 0 for r in type_resources),
            }

        return {
            "total_resources": len(resources),
            "total_size_bytes": sum(r.size_bytes for r in resources),
            "by_type": stats_by_type,
        }

    def import_builtin(self, name: str, resource_type: str, source_path: str, description: str = "") -> Optional[Resource]:
        """
        Import a builtin resource from a local path.

        Used to add standard wordlists/rules that ship with hashcat.

        Args:
            name: Resource name
            resource_type: Type
            source_path: Path to source file
            description: Description

        Returns:
            Created resource or None if failed
        """
        try:
            with open(source_path, "rb") as f:
                content = f.read()

            resource = self.add_resource(
                name=name,
                resource_type=resource_type,
                file_content=content,
                description=description,
            )

            # Mark as builtin
            with self._lock:
                if resource.resource_id in self._resources:
                    self._resources[resource.resource_id].is_builtin = True
                    self._save_index()

            return resource
        except Exception as e:
            logger.error(f"Failed to import builtin resource: {e}")
            return None

    def scan_untracked(self) -> list[Resource]:
        """
        Scan resource directories for untracked files and import them.

        This allows users to copy files directly into the resource folders
        and have them appear in the UI without using the upload feature.

        Returns:
            List of newly imported resources
        """
        imported = []

        # Get all tracked file paths
        with self._lock:
            tracked_paths = {r.file_path for r in self._resources.values()}

        # Scan each resource type directory
        for resource_type in ["wordlists", "rules", "masks"]:
            type_dir = self.resources_dir / resource_type
            if not type_dir.exists():
                continue

            # Find all files in the directory
            for file_path in type_dir.iterdir():
                if not file_path.is_file():
                    continue

                # Skip if already tracked
                if str(file_path) in tracked_paths:
                    continue

                # Skip hidden files and temp files
                if file_path.name.startswith('.') or file_path.name.endswith('.tmp'):
                    continue

                try:
                    # Import the file
                    resource = self._import_existing_file(file_path, resource_type)
                    if resource:
                        imported.append(resource)
                        logger.info(f"Imported untracked file: {file_path.name}")
                except Exception as e:
                    logger.error(f"Failed to import {file_path}: {e}")

        return imported

    def _import_existing_file(self, file_path: Path, resource_type: str) -> Optional[Resource]:
        """
        Import an existing file into the resource index without copying it.

        Args:
            file_path: Path to the file
            resource_type: Type of resource

        Returns:
            Created Resource or None if failed
        """
        try:
            # Use filename as the name (clean it up)
            name = file_path.name

            # Generate unique ID
            resource_id = self._generate_id(name, resource_type)

            # Compute metadata
            sha256 = self._compute_sha256(str(file_path))
            size_bytes = file_path.stat().st_size
            line_count = self._count_lines(str(file_path))

            resource = Resource(
                resource_id=resource_id,
                name=name,
                resource_type=resource_type,
                description=f"Imported from {file_path.name}",
                file_path=str(file_path),
                size_bytes=size_bytes,
                sha256=sha256,
                line_count=line_count,
                uploaded_at=datetime.now().isoformat(),
                uploaded_by="system",
                tags=[],
                is_builtin=False,
            )

            with self._lock:
                self._resources[resource_id] = resource
                self._save_index()

            return resource
        except Exception as e:
            logger.error(f"Failed to import existing file {file_path}: {e}")
            return None

    def get_untracked_count(self) -> dict[str, int]:
        """
        Count untracked files in each resource directory.

        Returns:
            Dict mapping resource type to count of untracked files
        """
        counts = {}

        # Get all tracked file paths
        with self._lock:
            tracked_paths = {r.file_path for r in self._resources.values()}

        for resource_type in ["wordlists", "rules", "masks"]:
            type_dir = self.resources_dir / resource_type
            count = 0
            if type_dir.exists():
                for file_path in type_dir.iterdir():
                    if (file_path.is_file() and
                        str(file_path) not in tracked_paths and
                        not file_path.name.startswith('.') and
                        not file_path.name.endswith('.tmp')):
                        count += 1
            counts[resource_type] = count

        return counts

    def migrate_filenames(self) -> list[tuple[str, str, str]]:
        """
        Rename resource files that have spaces or special characters.

        This fixes the issue where files with spaces cause problems in
        hashcat command lines.

        Returns:
            List of (resource_id, old_path, new_path) tuples for renamed files
        """
        import re
        renamed = []

        with self._lock:
            for resource_id, resource in self._resources.items():
                old_path = Path(resource.file_path)
                if not old_path.exists():
                    continue

                old_name = old_path.name
                # Check if filename has spaces or other problematic characters
                if re.search(r'[\s\\/:"*?<>|]', old_name):
                    # Generate new sanitized filename
                    new_name = self._sanitize_filename(old_name)
                    new_path = old_path.parent / new_name

                    # Avoid collision
                    if new_path.exists() and new_path != old_path:
                        # Add a suffix to make unique
                        import uuid
                        base, ext = new_name.rsplit('.', 1) if '.' in new_name else (new_name, '')
                        new_name = f"{base}_{uuid.uuid4().hex[:4]}" + (f".{ext}" if ext else "")
                        new_path = old_path.parent / new_name

                    try:
                        old_path.rename(new_path)
                        resource.file_path = str(new_path)
                        renamed.append((resource_id, str(old_path), str(new_path)))
                        logger.info(f"Renamed resource file: {old_name} -> {new_name}")
                    except Exception as e:
                        logger.error(f"Failed to rename {old_path}: {e}")

            if renamed:
                self._save_index()

        return renamed
