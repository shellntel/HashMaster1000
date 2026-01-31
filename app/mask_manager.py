"""
Mask Manager for HM1K.

Manages hashcat masks with:
- Keyspace calculation
- Crack time estimation based on benchmark data
- Mask groups for organizing related masks
- JSON storage with fcntl locking for multi-worker safety
"""

import fcntl
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Hashcat charset sizes
CHARSET_SIZES = {
    "l": 26,   # Lowercase: a-z
    "u": 26,   # Uppercase: A-Z
    "d": 10,   # Digits: 0-9
    "s": 33,   # Special: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~<space>
    "a": 95,   # All printable ASCII
    "b": 256,  # Binary: 0x00-0xff
}

# Hash mode for NTLM (used for crack time estimation)
NTLM_HASH_MODE = 1000

# Mask length limits
MIN_LENGTH = 8
MAX_LENGTH = 32


@dataclass
class Mask:
    """A hashcat mask with metadata."""
    mask_id: str
    pattern: str
    length: int
    keyspace: int
    description: str = ""
    tags: list[str] = field(default_factory=list)
    custom_charsets: dict[str, str] = field(default_factory=dict)
    created_at: str = ""
    created_by: str = ""

    def to_dict(self) -> dict:
        return {
            "mask_id": self.mask_id,
            "pattern": self.pattern,
            "length": self.length,
            "keyspace": self.keyspace,
            "description": self.description,
            "tags": self.tags,
            "custom_charsets": self.custom_charsets,
            "created_at": self.created_at,
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Mask":
        return cls(
            mask_id=data["mask_id"],
            pattern=data["pattern"],
            length=data["length"],
            keyspace=data["keyspace"],
            description=data.get("description", ""),
            tags=data.get("tags", []),
            custom_charsets=data.get("custom_charsets", {}),
            created_at=data.get("created_at", ""),
            created_by=data.get("created_by", ""),
        )


@dataclass
class MaskGroup:
    """A group of related masks."""
    group_id: str
    name: str
    description: str = ""
    mask_ids: list[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "description": self.description,
            "mask_ids": self.mask_ids,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MaskGroup":
        return cls(
            group_id=data["group_id"],
            name=data["name"],
            description=data.get("description", ""),
            mask_ids=data.get("mask_ids", []),
            created_at=data.get("created_at", ""),
        )


def format_keyspace(n: int) -> str:
    """Format keyspace as human-readable string (e.g., '3.089T', '456.789B')."""
    if n < 1000:
        return str(n)
    elif n < 1_000_000:
        return f"{n / 1_000:.3f}K"
    elif n < 1_000_000_000:
        return f"{n / 1_000_000:.3f}M"
    elif n < 1_000_000_000_000:
        return f"{n / 1_000_000_000:.3f}B"
    elif n < 1_000_000_000_000_000:
        return f"{n / 1_000_000_000_000:.3f}T"
    elif n < 1_000_000_000_000_000_000:
        return f"{n / 1_000_000_000_000_000:.3f}P"
    else:
        return f"{n / 1_000_000_000_000_000_000:.3f}E"


def format_duration(seconds: float) -> str:
    """Format duration as human-readable string (e.g., '2.5h', '3.2d')."""
    if seconds < 0:
        return "N/A"
    if seconds < 1:
        return "<1s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f}d"
    return f"{seconds / (86400 * 365):.1f}y"


class MaskManager:
    """
    Manages hashcat masks and mask groups.

    Stores masks in a JSON file with fcntl locking for multi-worker safety.
    Integrates with PerformanceTracker for crack time estimation.
    """

    def __init__(self, data_dir: str, performance_tracker=None):
        """
        Initialize MaskManager.

        Args:
            data_dir: Base data directory
            performance_tracker: Optional PerformanceTracker for crack time estimation
        """
        self.data_dir = Path(data_dir)
        self.masks_dir = self.data_dir / "agents"
        self.masks_file = self.masks_dir / "masks.json"
        self.performance_tracker = performance_tracker
        self.masks_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_file()

    def _ensure_file(self) -> None:
        """Create masks file if it doesn't exist."""
        if not self.masks_file.exists():
            self._save_data({
                "version": 1,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "masks": [],
                "groups": [],
            })

    def _load_data(self) -> dict:
        """Load masks data with file locking."""
        try:
            with open(self.masks_file, "r") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "version": 1,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "masks": [],
                "groups": [],
            }

    def _save_data(self, data: dict) -> None:
        """Save masks data with file locking."""
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        with open(self.masks_file, "w") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                json.dump(data, f, indent=2)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def calculate_keyspace(pattern: str, custom_charsets: Optional[dict[str, str]] = None) -> int:
        """
        Calculate keyspace for a mask pattern.

        Args:
            pattern: Hashcat mask pattern (e.g., '?u?l?l?l?d?d')
            custom_charsets: Optional dict of custom charsets (e.g., {'1': 'abc123'})

        Returns:
            Total keyspace (product of charset sizes)
        """
        if custom_charsets is None:
            custom_charsets = {}

        keyspace = 1
        i = 0
        while i < len(pattern):
            if pattern[i] == "?" and i + 1 < len(pattern):
                char = pattern[i + 1]
                if char in CHARSET_SIZES:
                    keyspace *= CHARSET_SIZES[char]
                elif char in "1234" and char in custom_charsets:
                    keyspace *= len(custom_charsets[char])
                elif char == "?":
                    # Literal '?' character
                    pass
                i += 2
            else:
                # Literal character (keyspace *= 1)
                i += 1
        return keyspace

    @staticmethod
    def calculate_mask_length(pattern: str) -> int:
        """
        Calculate the character length of a mask.

        Args:
            pattern: Hashcat mask pattern

        Returns:
            Number of characters the mask will generate
        """
        length = 0
        i = 0
        while i < len(pattern):
            if pattern[i] == "?" and i + 1 < len(pattern):
                length += 1
                i += 2
            else:
                length += 1
                i += 1
        return length

    @staticmethod
    def validate_mask(pattern: str, custom_charsets: Optional[dict[str, str]] = None) -> tuple[bool, str]:
        """
        Validate a mask pattern.

        Args:
            pattern: Hashcat mask pattern
            custom_charsets: Optional custom charsets

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not pattern or not pattern.strip():
            return False, "Mask pattern cannot be empty"

        pattern = pattern.strip()

        # Check for valid charset references
        valid_chars = set("ludsab1234?")
        i = 0
        while i < len(pattern):
            if pattern[i] == "?" and i + 1 < len(pattern):
                char = pattern[i + 1]
                if char not in valid_chars:
                    return False, f"Invalid charset '?{char}'"
                # Check custom charset is defined
                if char in "1234":
                    if custom_charsets is None or char not in custom_charsets:
                        return False, f"Custom charset ?{char} not defined"
                    if not custom_charsets[char]:
                        return False, f"Custom charset ?{char} is empty"
                i += 2
            else:
                i += 1

        # Check length
        length = MaskManager.calculate_mask_length(pattern)
        if length < MIN_LENGTH:
            return False, f"Mask length ({length}) is less than minimum ({MIN_LENGTH})"
        if length > MAX_LENGTH:
            return False, f"Mask length ({length}) exceeds maximum ({MAX_LENGTH})"

        return True, ""

    def get_fastest_ntlm_speed(self) -> Optional[float]:
        """
        Get the fastest NTLM benchmark speed across all agents.

        Returns:
            Speed in H/s or None if no benchmarks available
        """
        if self.performance_tracker is None:
            return None

        result = self.performance_tracker.get_fastest_benchmark(NTLM_HASH_MODE)
        return result.total_speed_hs if result else None

    def estimate_crack_time(self, keyspace: int) -> Optional[float]:
        """
        Estimate crack time for a given keyspace.

        Args:
            keyspace: Total keyspace to crack

        Returns:
            Estimated time in seconds or None if no benchmark data
        """
        speed = self.get_fastest_ntlm_speed()
        if speed is None or speed <= 0:
            return None
        return keyspace / speed

    def add_mask(
        self,
        pattern: str,
        description: str = "",
        tags: Optional[list[str]] = None,
        custom_charsets: Optional[dict[str, str]] = None,
        created_by: str = "",
    ) -> tuple[Optional[Mask], str]:
        """
        Add a new mask.

        Args:
            pattern: Hashcat mask pattern
            description: Optional description
            tags: Optional list of tags
            custom_charsets: Optional custom charsets
            created_by: User who created the mask

        Returns:
            Tuple of (Mask or None, error_message)
        """
        pattern = pattern.strip()
        if custom_charsets is None:
            custom_charsets = {}
        if tags is None:
            tags = []

        # Validate
        is_valid, error = self.validate_mask(pattern, custom_charsets)
        if not is_valid:
            return None, error

        # Check for duplicates
        data = self._load_data()
        for existing in data["masks"]:
            if existing["pattern"] == pattern:
                if existing.get("custom_charsets", {}) == custom_charsets:
                    return None, f"Mask '{pattern}' already exists"

        # Create mask
        mask = Mask(
            mask_id=f"mask_{uuid.uuid4().hex[:12]}",
            pattern=pattern,
            length=self.calculate_mask_length(pattern),
            keyspace=self.calculate_keyspace(pattern, custom_charsets),
            description=description,
            tags=tags,
            custom_charsets=custom_charsets,
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=created_by,
        )

        # Save
        data["masks"].append(mask.to_dict())
        self._save_data(data)

        logger.info(f"Added mask {mask.mask_id}: {pattern} (keyspace: {mask.keyspace})")
        return mask, ""

    def add_masks_bulk(
        self,
        patterns: list[str],
        custom_charsets: Optional[dict[str, str]] = None,
        created_by: str = "",
    ) -> tuple[list[Mask], list[dict]]:
        """
        Add multiple masks at once.

        Args:
            patterns: List of mask patterns
            custom_charsets: Shared custom charsets for all masks
            created_by: User who created the masks

        Returns:
            Tuple of (list of added masks, list of errors with pattern and message)
        """
        added = []
        errors = []

        for pattern in patterns:
            pattern = pattern.strip()
            if not pattern:
                continue

            mask, error = self.add_mask(
                pattern=pattern,
                custom_charsets=custom_charsets,
                created_by=created_by,
            )
            if mask:
                added.append(mask)
            else:
                errors.append({"pattern": pattern, "error": error})

        return added, errors

    def get_mask(self, mask_id: str) -> Optional[Mask]:
        """Get a mask by ID."""
        data = self._load_data()
        for mask_data in data["masks"]:
            if mask_data["mask_id"] == mask_id:
                return Mask.from_dict(mask_data)
        return None

    def update_mask(
        self,
        mask_id: str,
        description: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> tuple[Optional[Mask], str]:
        """
        Update mask metadata.

        Args:
            mask_id: Mask ID to update
            description: New description (if provided)
            tags: New tags (if provided)

        Returns:
            Tuple of (updated Mask or None, error_message)
        """
        data = self._load_data()

        for i, mask_data in enumerate(data["masks"]):
            if mask_data["mask_id"] == mask_id:
                if description is not None:
                    mask_data["description"] = description
                if tags is not None:
                    mask_data["tags"] = tags

                data["masks"][i] = mask_data
                self._save_data(data)
                return Mask.from_dict(mask_data), ""

        return None, f"Mask not found: {mask_id}"

    def delete_mask(self, mask_id: str) -> tuple[bool, str]:
        """
        Delete a mask.

        Args:
            mask_id: Mask ID to delete

        Returns:
            Tuple of (success, error_message)
        """
        data = self._load_data()

        # Remove from masks list
        original_count = len(data["masks"])
        data["masks"] = [m for m in data["masks"] if m["mask_id"] != mask_id]

        if len(data["masks"]) == original_count:
            return False, f"Mask not found: {mask_id}"

        # Remove from any groups
        for group in data["groups"]:
            if mask_id in group.get("mask_ids", []):
                group["mask_ids"].remove(mask_id)

        self._save_data(data)
        logger.info(f"Deleted mask {mask_id}")
        return True, ""

    def list_masks(self) -> list[Mask]:
        """List all masks."""
        data = self._load_data()
        return [Mask.from_dict(m) for m in data["masks"]]

    def get_masks_by_length(self) -> dict[int, list[Mask]]:
        """
        Get masks grouped by length.

        Returns:
            Dict mapping length to list of masks, sorted by length
        """
        masks = self.list_masks()
        grouped: dict[int, list[Mask]] = {}

        for mask in masks:
            if mask.length not in grouped:
                grouped[mask.length] = []
            grouped[mask.length].append(mask)

        # Sort masks within each group by keyspace
        for length in grouped:
            grouped[length].sort(key=lambda m: m.keyspace)

        return dict(sorted(grouped.items()))

    def parse_mask_input(self, content: str) -> list[str]:
        """
        Parse mask input from user (supports newlines and commas).

        Args:
            content: Raw input string

        Returns:
            List of individual mask patterns
        """
        # Split by newlines first, then commas
        patterns = []
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Split by commas if present
            if "," in line:
                patterns.extend([p.strip() for p in line.split(",") if p.strip()])
            else:
                patterns.append(line)
        return patterns

    # Group operations

    def create_group(
        self,
        name: str,
        description: str = "",
        mask_ids: Optional[list[str]] = None,
    ) -> tuple[Optional[MaskGroup], str]:
        """
        Create a new mask group.

        Args:
            name: Group name
            description: Optional description
            mask_ids: Optional list of mask IDs to include

        Returns:
            Tuple of (MaskGroup or None, error_message)
        """
        if not name or not name.strip():
            return None, "Group name cannot be empty"

        name = name.strip()
        if mask_ids is None:
            mask_ids = []

        data = self._load_data()

        # Check for duplicate names
        for group in data["groups"]:
            if group["name"].lower() == name.lower():
                return None, f"Group '{name}' already exists"

        # Verify mask IDs exist
        existing_ids = {m["mask_id"] for m in data["masks"]}
        invalid_ids = [mid for mid in mask_ids if mid not in existing_ids]
        if invalid_ids:
            return None, f"Invalid mask IDs: {', '.join(invalid_ids)}"

        group = MaskGroup(
            group_id=f"grp_{uuid.uuid4().hex[:12]}",
            name=name,
            description=description,
            mask_ids=mask_ids,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        data["groups"].append(group.to_dict())
        self._save_data(data)

        logger.info(f"Created group {group.group_id}: {name}")
        return group, ""

    def get_group(self, group_id: str) -> Optional[MaskGroup]:
        """Get a group by ID."""
        data = self._load_data()
        for group_data in data["groups"]:
            if group_data["group_id"] == group_id:
                return MaskGroup.from_dict(group_data)
        return None

    def update_group(
        self,
        group_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        mask_ids: Optional[list[str]] = None,
    ) -> tuple[Optional[MaskGroup], str]:
        """
        Update a group.

        Args:
            group_id: Group ID to update
            name: New name (if provided)
            description: New description (if provided)
            mask_ids: New mask IDs (if provided)

        Returns:
            Tuple of (updated MaskGroup or None, error_message)
        """
        data = self._load_data()

        for i, group_data in enumerate(data["groups"]):
            if group_data["group_id"] == group_id:
                if name is not None:
                    name = name.strip()
                    if not name:
                        return None, "Group name cannot be empty"
                    # Check for duplicate names (excluding self)
                    for other in data["groups"]:
                        if other["group_id"] != group_id and other["name"].lower() == name.lower():
                            return None, f"Group '{name}' already exists"
                    group_data["name"] = name

                if description is not None:
                    group_data["description"] = description

                if mask_ids is not None:
                    # Verify mask IDs exist
                    existing_ids = {m["mask_id"] for m in data["masks"]}
                    invalid_ids = [mid for mid in mask_ids if mid not in existing_ids]
                    if invalid_ids:
                        return None, f"Invalid mask IDs: {', '.join(invalid_ids)}"
                    group_data["mask_ids"] = mask_ids

                data["groups"][i] = group_data
                self._save_data(data)
                return MaskGroup.from_dict(group_data), ""

        return None, f"Group not found: {group_id}"

    def delete_group(self, group_id: str) -> tuple[bool, str]:
        """
        Delete a group.

        Args:
            group_id: Group ID to delete

        Returns:
            Tuple of (success, error_message)
        """
        data = self._load_data()

        original_count = len(data["groups"])
        data["groups"] = [g for g in data["groups"] if g["group_id"] != group_id]

        if len(data["groups"]) == original_count:
            return False, f"Group not found: {group_id}"

        self._save_data(data)
        logger.info(f"Deleted group {group_id}")
        return True, ""

    def list_groups(self) -> list[MaskGroup]:
        """List all groups."""
        data = self._load_data()
        return [MaskGroup.from_dict(g) for g in data["groups"]]

    def get_group_with_masks(self, group_id: str) -> Optional[tuple[MaskGroup, list[Mask]]]:
        """
        Get a group with its masks.

        Args:
            group_id: Group ID

        Returns:
            Tuple of (group, list of masks) or None
        """
        group = self.get_group(group_id)
        if not group:
            return None

        masks = []
        for mask_id in group.mask_ids:
            mask = self.get_mask(mask_id)
            if mask:
                masks.append(mask)

        return group, masks

    def export_group_hcmask(self, group_id: str) -> Optional[str]:
        """
        Export a group as .hcmask file content.

        Args:
            group_id: Group ID

        Returns:
            File content or None if group not found
        """
        result = self.get_group_with_masks(group_id)
        if not result:
            return None

        group, masks = result
        lines = [f"# {group.name}"]
        if group.description:
            lines.append(f"# {group.description}")
        lines.append("")

        for mask in masks:
            # Include custom charset definitions if needed
            if mask.custom_charsets:
                charset_defs = ",".join(f"{mask.custom_charsets[k]}" for k in sorted(mask.custom_charsets.keys()))
                lines.append(f"{charset_defs},{mask.pattern}")
            else:
                lines.append(mask.pattern)

        return "\n".join(lines)

    def get_stats(self) -> dict:
        """
        Get statistics about masks and groups.

        Returns:
            Dict with mask count, group count, and fastest NTLM speed
        """
        data = self._load_data()
        return {
            "mask_count": len(data["masks"]),
            "group_count": len(data["groups"]),
            "fastest_ntlm_speed": self.get_fastest_ntlm_speed(),
        }
