#!/usr/bin/env python3
"""
Extract NTLM and LM hashes from ADD (Active Directory Dump) JSON files.

Outputs lists of hashes suitable for use with hashcat.

Usage:
    python extract_ntlm_hashes.py input.json -o hashes.txt
    python extract_ntlm_hashes.py input.json  # outputs to stdout
    python extract_ntlm_hashes.py input.json --include-historical -o all_hashes.txt
    python extract_ntlm_hashes.py input.json -o ntlm.txt --lm-output lm.txt
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Set, Tuple


# Common field names for LM hashes in ADD exports
LM_HASH_FIELDS = ["LMHash", "LanmanHash", "LM", "lmHash", "lanmanHash"]

# Blank/empty hash values
BLANK_NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"
BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"


def parse_hash_value(value: str) -> Tuple[str, str]:
    """
    Parse a hash value that may be in various formats.

    Supported formats:
    - Plain 32-char hash: "77cb8886bd7149479631e65e49dc0753"
    - LM:NTLM format: "aad3b435b51404eeaad3b435b51404ee:77cb8886bd7149479631e65e49dc0753"

    Returns:
        Tuple of (lm_hash, ntlm_hash), either may be empty string if not present
    """
    value = value.strip().lower()

    if not value:
        return "", ""

    # Check for LM:NTLM format (65 chars: 32 + colon + 32)
    if ":" in value:
        parts = value.split(":")
        if len(parts) == 2:
            lm_part = parts[0].strip()
            ntlm_part = parts[1].strip()
            # Validate both parts are 32-char hex
            if len(lm_part) == 32 and len(ntlm_part) == 32:
                return lm_part, ntlm_part

    # Plain 32-char hash (assume it's NTLM)
    if len(value) == 32:
        return "", value

    return "", ""


def extract_hashes(
    add_data: dict,
    include_historical: bool = False,
    include_blank: bool = False
) -> Tuple[Set[str], Set[str]]:
    """
    Extract NTLM and LM hashes from ADD JSON data.

    Args:
        add_data: Parsed ADD JSON dictionary
        include_historical: If True, also extract historical password hashes
        include_blank: If True, include blank/empty password hashes

    Returns:
        Tuple of (NTLM hashes set, LM hashes set), both lowercase
    """
    ntlm_hashes: Set[str] = set()
    lm_hashes: Set[str] = set()

    users = add_data.get("Users", [])

    for user in users:
        # Get current NTLM hash (may be in LM:NTLM format)
        ntlm_field = user.get("NTLMHash", "")
        lm_from_ntlm, ntlm_hash = parse_hash_value(ntlm_field)

        if ntlm_hash:
            if include_blank or ntlm_hash != BLANK_NTLM:
                ntlm_hashes.add(ntlm_hash)

        # LM hash may come from the NTLMHash field (LM:NTLM format) or separate LM fields
        if lm_from_ntlm:
            if include_blank or lm_from_ntlm != BLANK_LM:
                lm_hashes.add(lm_from_ntlm)

        # Also check dedicated LM hash fields
        for field in LM_HASH_FIELDS:
            lm_field = user.get(field, "")
            _, lm_hash = parse_hash_value(lm_field)
            # If parse_hash_value returns empty ntlm, the value might be a plain LM hash
            if not lm_hash:
                lm_hash = lm_field.strip().lower() if len(lm_field.strip()) == 32 else ""
            if lm_hash:
                if include_blank or lm_hash != BLANK_LM:
                    lm_hashes.add(lm_hash)
                break

        # Get historical hashes if requested
        if include_historical:
            # Historical NTLM hashes (may be in LM:NTLM format)
            historical_ntlm = user.get("HistoricalNTHashes", [])
            for h in historical_ntlm:
                if isinstance(h, str):
                    hist_lm, hist_ntlm = parse_hash_value(h)
                    if hist_ntlm:
                        if include_blank or hist_ntlm != BLANK_NTLM:
                            ntlm_hashes.add(hist_ntlm)
                    if hist_lm:
                        if include_blank or hist_lm != BLANK_LM:
                            lm_hashes.add(hist_lm)

            # Historical LM hashes (try multiple field names)
            for field in ["HistoricalLMHashes", "HistoricalLanmanHashes"]:
                historical_lm = user.get(field, [])
                for h in historical_lm:
                    if isinstance(h, str):
                        _, hist_lm = parse_hash_value(h)
                        if not hist_lm:
                            hist_lm = h.strip().lower() if len(h.strip()) == 32 else ""
                        if hist_lm:
                            if include_blank or hist_lm != BLANK_LM:
                                lm_hashes.add(hist_lm)

    return ntlm_hashes, lm_hashes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract NTLM and LM hashes from ADD JSON files for use with hashcat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s dump.json -o hashes.txt                    Extract NTLM hashes to file
  %(prog)s dump.json -o ntlm.txt --lm-output lm.txt   Extract both NTLM and LM hashes
  %(prog)s dump.json --include-historical             Include historical password hashes
  %(prog)s dump.json --include-blank                  Include blank password hashes
  %(prog)s dump.json | sort -u > hashes.txt           Pipe to sort and save

Hashcat modes:
  NTLM: hashcat -m 1000 hashes.txt wordlist.txt
  LM:   hashcat -m 3000 lm_hashes.txt wordlist.txt
"""
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Input ADD JSON file"
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file for NTLM hashes (default: stdout)"
    )

    parser.add_argument(
        "--lm-output",
        type=Path,
        help="Output file for LM hashes (if present in dump)"
    )

    parser.add_argument(
        "--include-historical",
        action="store_true",
        help="Include historical password hashes"
    )

    parser.add_argument(
        "--include-blank",
        action="store_true",
        help="Include blank password hashes"
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress info messages (only output hashes)"
    )

    args = parser.parse_args()

    # Validate input file
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        return 1

    # Load JSON
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            add_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    # Extract hashes
    ntlm_hashes, lm_hashes = extract_hashes(
        add_data,
        include_historical=args.include_historical,
        include_blank=args.include_blank
    )

    user_count = len(add_data.get("Users", []))
    domain = add_data.get("Name", "Unknown")

    if not ntlm_hashes and not lm_hashes:
        print("Warning: No hashes found in input file", file=sys.stderr)
        return 0

    # Sort hashes for consistent output
    sorted_ntlm = sorted(ntlm_hashes)
    sorted_lm = sorted(lm_hashes)

    # Output NTLM hashes
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for h in sorted_ntlm:
                f.write(h + "\n")

        if not args.quiet:
            print(f"Domain: {domain}", file=sys.stderr)
            print(f"Users in dump: {user_count}", file=sys.stderr)
            print(f"NTLM hashes extracted: {len(ntlm_hashes)}", file=sys.stderr)
            if args.include_historical:
                print("  (includes historical hashes)", file=sys.stderr)
            print(f"NTLM output: {args.output}", file=sys.stderr)
    else:
        # Output NTLM to stdout
        for h in sorted_ntlm:
            print(h)

        if not args.quiet:
            print(f"# {len(ntlm_hashes)} unique NTLM hashes from {user_count} users", file=sys.stderr)

    # Output LM hashes if requested
    if args.lm_output:
        if lm_hashes:
            with open(args.lm_output, "w", encoding="utf-8") as f:
                for h in sorted_lm:
                    f.write(h + "\n")

            if not args.quiet:
                print(f"LM hashes extracted: {len(lm_hashes)}", file=sys.stderr)
                print(f"LM output: {args.lm_output}", file=sys.stderr)
        else:
            if not args.quiet:
                print("LM hashes: None found in dump (LM hashing may be disabled)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
