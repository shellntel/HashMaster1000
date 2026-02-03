"""
Mask Manager for HM1K.

Manages hashcat masks with:
- Keyspace calculation
- Crack time estimation based on benchmark data
- Mask groups for organizing related masks
- SQLite storage for multi-worker safety
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .mask_db import get_mask_db, MaskDB

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
    custom_charsets: dict[str, str] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "description": self.description,
            "mask_ids": self.mask_ids,
            "custom_charsets": self.custom_charsets,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MaskGroup":
        return cls(
            group_id=data["group_id"],
            name=data["name"],
            description=data.get("description", ""),
            mask_ids=data.get("mask_ids", []),
            custom_charsets=data.get("custom_charsets", {}),
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

    Uses SQLite for storage via MaskDB for multi-worker safety.
    Integrates with PerformanceTracker for crack time estimation.
    """

    def __init__(self, data_dir: str, performance_tracker=None):
        """
        Initialize MaskManager.

        Args:
            data_dir: Base data directory
            performance_tracker: Optional PerformanceTracker for crack time estimation
        """
        self.data_dir = data_dir
        self.db: MaskDB = get_mask_db(data_dir)
        self.performance_tracker = performance_tracker

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

        # Calculate properties
        length = self.calculate_mask_length(pattern)
        keyspace = self.calculate_keyspace(pattern, custom_charsets)

        # Add to database
        mask_id, error = self.db.add_mask(
            pattern=pattern,
            length=length,
            keyspace=keyspace,
            description=description,
            tags=tags,
            custom_charsets=custom_charsets,
            created_by=created_by,
        )

        if mask_id is None:
            return None, error

        # Return mask object
        mask = Mask(
            mask_id=mask_id,
            pattern=pattern,
            length=length,
            keyspace=keyspace,
            description=description,
            tags=tags,
            custom_charsets=custom_charsets,
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=created_by,
        )

        logger.info(f"Added mask {mask_id}: {pattern} (keyspace: {keyspace})")
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
        data = self.db.get_mask(mask_id)
        if data is None:
            return None
        return Mask.from_dict(data)

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
        success, error = self.db.update_mask(mask_id, description, tags)
        if not success:
            return None, error

        return self.get_mask(mask_id), ""

    def delete_mask(self, mask_id: str) -> tuple[bool, str]:
        """
        Delete a mask.

        Args:
            mask_id: Mask ID to delete

        Returns:
            Tuple of (success, error_message)
        """
        return self.db.delete_mask(mask_id)

    def list_masks(self) -> list[Mask]:
        """List all masks."""
        masks_data = self.db.get_all_masks()
        return [Mask.from_dict(m) for m in masks_data]

    def get_all_masks(self) -> list[Mask]:
        """Alias for list_masks."""
        return self.list_masks()

    def get_ungrouped_masks(self) -> list[Mask]:
        """Get masks that are not in any group."""
        masks_data = self.db.get_ungrouped_masks()
        return [Mask.from_dict(m) for m in masks_data]

    def get_masks_by_length(self) -> dict[int, list[Mask]]:
        """
        Get masks grouped by length.

        Returns:
            Dict mapping length to list of masks, sorted by length
        """
        masks_by_length = self.db.get_masks_by_length()
        result: dict[int, list[Mask]] = {}

        for length, masks_data in masks_by_length.items():
            masks = [Mask.from_dict(m) for m in masks_data]
            # Sort by keyspace
            masks.sort(key=lambda m: m.keyspace)
            result[length] = masks

        return dict(sorted(result.items()))

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

    def parse_mask_file(self, content: str) -> tuple[list[str], dict[str, str]]:
        """
        Parse mask file content with embedded charset definitions.

        Supports two formats:
        1. JSON format (detected by starting with '{'):
           {
             "custom_charsets": {"2": "!@#$%&*"},
             "masks": ["Fall?2?d?d?d?d", "Spring?2?d?d?d?d"]
           }

        2. Text format with ?N=charset lines:
           # Custom charsets
           ?2=!@#$%&*

           # Masks
           Fall?2?d?d?d?d
           Spring?2?d?d?d?d

        Args:
            content: File content

        Returns:
            Tuple of (list of mask patterns, dict of custom charsets)
        """
        import json

        content = content.strip()

        # Try JSON format first
        if content.startswith("{"):
            try:
                data = json.loads(content)
                masks = data.get("masks", [])
                charsets = data.get("custom_charsets", {})
                # Normalize charset keys to strings
                charsets = {str(k): v for k, v in charsets.items()}
                return masks, charsets
            except json.JSONDecodeError:
                pass  # Fall through to text format

        # Text format with ?N=charset lines
        patterns = []
        charsets = {}

        for line in content.split("\n"):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Check for charset definition: ?1=abc or ?2=!@#$%
            if line.startswith("?") and "=" in line and len(line) > 3:
                char_num = line[1]
                if char_num in "1234":
                    charset_value = line[3:]  # Everything after "?N="
                    if charset_value:
                        charsets[char_num] = charset_value
                    continue

            # Regular mask pattern
            patterns.append(line)

        return patterns, charsets

    # Group operations

    def create_group(
        self,
        name: str,
        description: str = "",
        mask_ids: Optional[list[str]] = None,
        custom_charsets: Optional[dict[str, str]] = None,
    ) -> tuple[Optional[MaskGroup], str]:
        """
        Create a new mask group.

        Args:
            name: Group name
            description: Optional description
            mask_ids: Optional list of mask IDs to include
            custom_charsets: Optional shared charsets for the group

        Returns:
            Tuple of (MaskGroup or None, error_message)
        """
        if not name or not name.strip():
            return None, "Group name cannot be empty"

        name = name.strip()
        if mask_ids is None:
            mask_ids = []
        if custom_charsets is None:
            custom_charsets = {}

        group_id, error = self.db.create_group(
            name=name,
            description=description,
            mask_ids=mask_ids,
            custom_charsets=custom_charsets,
        )

        if group_id is None:
            return None, error

        group = MaskGroup(
            group_id=group_id,
            name=name,
            description=description,
            mask_ids=mask_ids,
            custom_charsets=custom_charsets,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        logger.info(f"Created group {group_id}: {name}")
        return group, ""

    def get_group(self, group_id: str) -> Optional[MaskGroup]:
        """Get a group by ID."""
        data = self.db.get_group(group_id)
        if data is None:
            return None

        # Get mask IDs
        full_data = self.db.get_group_with_masks(group_id)
        if full_data:
            data['mask_ids'] = full_data.get('mask_ids', [])

        return MaskGroup.from_dict(data)

    def update_group(
        self,
        group_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        mask_ids: Optional[list[str]] = None,
        custom_charsets: Optional[dict[str, str]] = None,
    ) -> tuple[Optional[MaskGroup], str]:
        """
        Update a group.

        Args:
            group_id: Group ID to update
            name: New name (if provided)
            description: New description (if provided)
            mask_ids: New mask IDs (if provided)
            custom_charsets: New custom charsets (if provided)

        Returns:
            Tuple of (updated MaskGroup or None, error_message)
        """
        if name is not None:
            name = name.strip()
            if not name:
                return None, "Group name cannot be empty"

        success, error = self.db.update_group(
            group_id=group_id,
            name=name,
            description=description,
            mask_ids=mask_ids,
            custom_charsets=custom_charsets,
        )

        if not success:
            return None, error

        return self.get_group(group_id), ""

    def delete_group(self, group_id: str) -> tuple[bool, str]:
        """
        Delete a group.

        Args:
            group_id: Group ID to delete

        Returns:
            Tuple of (success, error_message)
        """
        return self.db.delete_group(group_id)

    def list_groups(self) -> list[MaskGroup]:
        """List all groups."""
        groups_data = self.db.get_all_groups()
        return [MaskGroup.from_dict(g) for g in groups_data]

    def get_group_with_masks(self, group_id: str) -> Optional[tuple[MaskGroup, list[Mask]]]:
        """
        Get a group with its masks.

        Args:
            group_id: Group ID

        Returns:
            Tuple of (group, list of masks) or None
        """
        data = self.db.get_group_with_masks(group_id)
        if data is None:
            return None

        masks = [Mask.from_dict(m) for m in data.get('masks', [])]
        group = MaskGroup(
            group_id=data['group_id'],
            name=data['name'],
            description=data['description'],
            mask_ids=data.get('mask_ids', []),
            custom_charsets=data['custom_charsets'],
            created_at=data['created_at'],
        )

        return group, masks

    def export_group_hcmask(self, group_id: str) -> Optional[str]:
        """
        Export a group as .hcmask file content.

        Includes group-level custom charsets as ?N=charset definitions
        at the top of the file. Individual mask charsets are also included
        inline if they differ from group charsets.

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

        # Add group-level charset definitions
        if group.custom_charsets:
            lines.append("# Custom Charsets")
            for key in sorted(group.custom_charsets.keys()):
                lines.append(f"?{key}={group.custom_charsets[key]}")
            lines.append("")
            lines.append("# Masks")

        for mask in masks:
            # Include inline charset definitions if mask has its own charsets
            # that differ from group charsets
            mask_charsets = mask.custom_charsets or {}
            group_charsets = group.custom_charsets or {}

            # Check if mask has additional/different charsets
            extra_charsets = {k: v for k, v in mask_charsets.items()
                             if k not in group_charsets or group_charsets[k] != v}

            if extra_charsets:
                charset_defs = ",".join(f"{extra_charsets[k]}" for k in sorted(extra_charsets.keys()))
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
        stats = self.db.get_stats()
        stats["fastest_ntlm_speed"] = self.get_fastest_ntlm_speed()
        return stats

    # ==================== Performance Tracking ====================

    def record_mask_performance(
        self,
        job_id: str,
        agent_id: str,
        hash_count: int,
        hash_mode: int,
        avg_speed_hps: float,
        duration_seconds: float,
        group_id: Optional[str] = None,
        group_name: Optional[str] = None,
        agent_name: Optional[str] = None,
        peak_speed_hps: Optional[float] = None,
        keyspace_total: Optional[int] = None,
        masks_in_file: Optional[int] = None,
    ) -> tuple[bool, str]:
        """
        Record performance data from a completed mask attack job.

        This builds up historical data for accurate time estimation.
        """
        return self.db.record_mask_performance(
            job_id=job_id,
            agent_id=agent_id,
            hash_count=hash_count,
            hash_mode=hash_mode,
            avg_speed_hps=avg_speed_hps,
            duration_seconds=duration_seconds,
            group_id=group_id,
            group_name=group_name,
            agent_name=agent_name,
            peak_speed_hps=peak_speed_hps,
            keyspace_total=keyspace_total,
            masks_in_file=masks_in_file,
        )

    def get_group_performance(
        self,
        group_id: str,
        agent_id: Optional[str] = None,
        hash_mode: int = NTLM_HASH_MODE,
        limit: int = 10,
    ) -> list[dict]:
        """Get historical performance data for a mask group."""
        return self.db.get_group_performance(group_id, agent_id, hash_mode, limit)

    def get_group_avg_speed(
        self,
        group_id: str,
        agent_id: Optional[str] = None,
        hash_mode: int = NTLM_HASH_MODE,
        hash_count_min: Optional[int] = None,
        hash_count_max: Optional[int] = None,
    ) -> Optional[float]:
        """Get average historical speed for a mask group."""
        return self.db.get_group_avg_speed(
            group_id, agent_id, hash_mode, hash_count_min, hash_count_max
        )

    def estimate_group_crack_time(
        self,
        group_id: str,
        keyspace: int,
        agent_id: Optional[str] = None,
        hash_count: Optional[int] = None,
        hash_mode: int = NTLM_HASH_MODE,
    ) -> dict:
        """
        Estimate crack time for a mask group using historical data.

        Falls back to benchmark-based estimation if no historical data.

        Args:
            group_id: Mask group ID
            keyspace: Total keyspace to crack
            agent_id: Optional specific agent for estimation
            hash_count: Optional hash count for better multi-hash scaling
            hash_mode: Hash mode (default NTLM)

        Returns:
            Dict with:
                - estimated_seconds: Time estimate
                - speed_hps: Speed used for estimate
                - source: 'historical' or 'benchmark'
                - confidence: 'high', 'medium', or 'low'
                - sample_count: Number of historical samples used
        """
        result = {
            'estimated_seconds': None,
            'speed_hps': None,
            'source': 'benchmark',
            'confidence': 'low',
            'sample_count': 0,
        }

        # Try to get historical data
        # If hash_count provided, look for similar workloads (within 2x range)
        hash_count_min = None
        hash_count_max = None
        if hash_count:
            hash_count_min = hash_count // 2
            hash_count_max = hash_count * 2

        historical_speed = self.db.get_group_avg_speed(
            group_id=group_id,
            agent_id=agent_id,
            hash_mode=hash_mode,
            hash_count_min=hash_count_min,
            hash_count_max=hash_count_max,
        )

        # Get sample count for confidence
        performance_data = self.db.get_group_performance(
            group_id=group_id,
            agent_id=agent_id,
            hash_mode=hash_mode,
            limit=100,
        )
        result['sample_count'] = len(performance_data)

        if historical_speed and historical_speed > 0:
            result['speed_hps'] = historical_speed
            result['source'] = 'historical'
            result['estimated_seconds'] = keyspace / historical_speed

            # Determine confidence based on sample count and agent match
            if agent_id and result['sample_count'] >= 3:
                result['confidence'] = 'high'
            elif result['sample_count'] >= 5:
                result['confidence'] = 'high'
            elif result['sample_count'] >= 2:
                result['confidence'] = 'medium'
            else:
                result['confidence'] = 'medium'
        else:
            # Fall back to benchmark-based estimation
            benchmark_speed = self.get_fastest_ntlm_speed()
            if benchmark_speed and benchmark_speed > 0:
                result['speed_hps'] = benchmark_speed
                result['estimated_seconds'] = keyspace / benchmark_speed
                result['confidence'] = 'low'

        return result

    def get_all_performance_data(
        self,
        hash_mode: int = NTLM_HASH_MODE,
        limit: int = 100,
    ) -> list[dict]:
        """Get all performance records for analysis."""
        return self.db.get_all_performance_data(hash_mode, limit)

    def get_agent_performance_summary(
        self,
        agent_id: str,
        hash_mode: int = NTLM_HASH_MODE,
    ) -> dict:
        """Get performance summary for an agent."""
        return self.db.get_agent_performance_summary(agent_id, hash_mode)
