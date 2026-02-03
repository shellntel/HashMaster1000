#!/usr/bin/env python3
"""
Bulk import script for Extreme Breach Masks.

Imports .hcmask files from the Extreme_Breach_Masks folder into mask groups.
Only imports individual character-length files (e.g., 1-hour_7.hcmask, 1-hour_8.hcmask),
not combined range files (e.g., 1-hour_7-16.hcmask).

Usage:
    python import_extreme_masks.py /path/to/extreme_masks /path/to/data/agents
"""

import os
import re
import sys

# Add the hm1k directory to the path
hm1k_dir = os.environ.get("HM1K_DIR", "/opt/hm1k")
sys.path.insert(0, hm1k_dir)

from app.mask_manager import MaskManager


# Mapping of folder names to group name prefixes
FOLDER_MAPPINGS = {
    "04 1-hour": "1 Hour",
    "05 3-hours": "3 Hour",
    "06 6-hours": "6 Hour",
    "07 12-hours": "12 Hour",
    "08 1-day": "1 Day",
}

# Regex to match individual character-length files (e.g., 1-hour_7.hcmask, 3-hours_10.hcmask)
# This excludes range files like 1-hour_7-16.hcmask
SINGLE_CHAR_FILE_PATTERN = re.compile(r"^.+_(\d+)\.hcmask$")


def import_masks_from_folder(manager: MaskManager, masks_dir: str, folder_name: str, prefix: str) -> dict:
    """
    Import masks from a single folder.

    Args:
        manager: MaskManager instance
        masks_dir: Base directory containing mask folders
        folder_name: Folder name (e.g., "04 1-hour")
        prefix: Group name prefix (e.g., "1 Hour")

    Returns:
        Dict with import statistics
    """
    folder_path = os.path.join(masks_dir, folder_name)
    if not os.path.isdir(folder_path):
        return {"error": f"Folder not found: {folder_path}"}

    stats = {
        "groups_created": 0,
        "masks_added": 0,
        "masks_skipped": 0,
        "errors": [],
    }

    # Get all .hcmask files
    files = sorted([f for f in os.listdir(folder_path) if f.endswith(".hcmask")])

    for filename in files:
        # Only process single character-length files (not range files)
        match = SINGLE_CHAR_FILE_PATTERN.match(filename)
        if not match:
            print(f"  Skipping range file: {filename}")
            continue

        char_length = match.group(1)
        group_name = f"{prefix} - {char_length} Character"

        filepath = os.path.join(folder_path, filename)
        print(f"  Processing {filename} -> '{group_name}'")

        # Read mask patterns from file
        with open(filepath, "r") as f:
            content = f.read()

        patterns = [line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")]

        if not patterns:
            print(f"    No patterns found in {filename}")
            continue

        # Add masks in bulk
        added_masks, errors = manager.add_masks_bulk(
            patterns=patterns,
            custom_charsets={},
            created_by="extreme_import",
        )

        stats["masks_added"] += len(added_masks)
        stats["masks_skipped"] += len(errors)

        if errors:
            for err in errors[:5]:  # Only show first 5 errors
                print(f"    Skip: {err['pattern'][:30]}... - {err['error']}")
            if len(errors) > 5:
                print(f"    ... and {len(errors) - 5} more skipped")

        # Create group with mask IDs
        mask_ids = [m.mask_id for m in added_masks]

        # Also check if there are existing masks with the same patterns (for duplicates)
        if len(mask_ids) < len(patterns):
            # Some masks already existed - get their IDs
            existing_count = 0
            for pattern in patterns:
                existing = manager.db.get_mask_by_pattern(pattern)
                if existing and existing["mask_id"] not in mask_ids:
                    mask_ids.append(existing["mask_id"])
                    existing_count += 1
            if existing_count:
                print(f"    Added {existing_count} existing masks to group")

        if not mask_ids:
            print(f"    No masks to add to group '{group_name}'")
            continue

        # Check if group already exists
        existing_groups = manager.list_groups()
        existing_group = next((g for g in existing_groups if g.name == group_name), None)

        if existing_group:
            # Update existing group with new masks
            success, error = manager.update_group(
                group_id=existing_group.group_id,
                mask_ids=list(set(existing_group.mask_ids + mask_ids)),  # Combine and dedupe
            )
            if success:
                print(f"    Updated existing group '{group_name}' with {len(mask_ids)} masks")
            else:
                stats["errors"].append(f"Failed to update group '{group_name}': {error}")
        else:
            # Create new group
            group, error = manager.create_group(
                name=group_name,
                description=f"Extreme Breach Masks - {prefix} at {char_length} characters",
                mask_ids=mask_ids,
            )

            if group:
                print(f"    Created group '{group_name}' with {len(mask_ids)} masks")
                stats["groups_created"] += 1
            else:
                stats["errors"].append(f"Failed to create group '{group_name}': {error}")

    return stats


def main():
    if len(sys.argv) < 3:
        print("Usage: python import_extreme_masks.py <masks_dir> <data_dir>")
        print("  masks_dir: Directory containing the mask folders (04 1-hour, etc.)")
        print("  data_dir: HM1K data directory (e.g., /opt/hm1k/data/agents)")
        sys.exit(1)

    masks_dir = sys.argv[1]
    data_dir = sys.argv[2]

    if not os.path.isdir(masks_dir):
        print(f"Error: Masks directory not found: {masks_dir}")
        sys.exit(1)

    if not os.path.isdir(data_dir):
        print(f"Error: Data directory not found: {data_dir}")
        sys.exit(1)

    print(f"Importing Extreme Breach Masks")
    print(f"  Source: {masks_dir}")
    print(f"  Data dir: {data_dir}")
    print()

    manager = MaskManager(data_dir)

    total_stats = {
        "groups_created": 0,
        "masks_added": 0,
        "masks_skipped": 0,
        "errors": [],
    }

    for folder_name, prefix in FOLDER_MAPPINGS.items():
        print(f"\n=== {folder_name} ({prefix}) ===")
        stats = import_masks_from_folder(manager, masks_dir, folder_name, prefix)

        if "error" in stats:
            print(f"  Error: {stats['error']}")
            continue

        total_stats["groups_created"] += stats["groups_created"]
        total_stats["masks_added"] += stats["masks_added"]
        total_stats["masks_skipped"] += stats["masks_skipped"]
        total_stats["errors"].extend(stats["errors"])

    print("\n" + "=" * 50)
    print("IMPORT COMPLETE")
    print(f"  Groups created: {total_stats['groups_created']}")
    print(f"  Masks added: {total_stats['masks_added']}")
    print(f"  Masks skipped (duplicates): {total_stats['masks_skipped']}")

    if total_stats["errors"]:
        print(f"\nErrors ({len(total_stats['errors'])}):")
        for err in total_stats["errors"]:
            print(f"  - {err}")


if __name__ == "__main__":
    main()
