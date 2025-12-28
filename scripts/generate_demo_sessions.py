#!/usr/bin/env python3
"""
Generate Demo Historical Sessions for HM1K

This script creates historical analysis sessions by using the actual HM1K
analysis functions. This ensures all report sections are properly populated
with realistic data.

The script creates 3 sessions for Q1, Q2, and Q3 2025, each showing
progressive improvement in password security.

Prerequisites:
    - Run create_demo_dataset.py first to generate example_ADD_expanded.json
    - The master.potfile should exist in data/

Usage:
    python scripts/generate_demo_sessions.py

Output:
    - data/sessions/demo_q1_2025/ - Q1 2025 session (58% crack rate)
    - data/sessions/demo_q2_2025/ - Q2 2025 session (42% crack rate)
    - data/sessions/demo_q3_2025/ - Q3 2025 session (28% crack rate)

Note: This script imports and uses the actual HM1K analysis functions
to ensure data accuracy and consistency with real analysis runs.
"""

import binascii
import json
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import HM1K analysis functions
try:
    import password_analysis_tools
except ImportError:
    print("Error: Could not import password_analysis_tools")
    print("Make sure you're running from the HM1K project directory")
    sys.exit(1)


def decode_hex_password(password: str) -> str:
    """
    Decode $HEX[] encoded passwords from hashcat.

    Args:
        password: The password string, possibly $HEX[] encoded

    Returns:
        Decoded password string
    """
    if password.startswith("$HEX[") and password.endswith("]"):
        hex_string = password[5:-1]
        try:
            return binascii.unhexlify(hex_string).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return password  # Return original if decode fails
    return password

# Session configurations
COMPANY_NAME = "DemoCorp"

SESSION_CONFIGS = {
    "demo_q1_2025": {
        "project_description": "Q1 2025 Security Assessment",
        "date": datetime(2025, 3, 31, 9, 0, 0),
        "crack_rate": 0.25,  # 25% - worst (all crackable passwords cracked)
        "notes": "First quarterly assessment - baseline metrics",
    },
    "demo_q2_2025": {
        "project_description": "Q2 2025 Mid-Year Review",
        "date": datetime(2025, 6, 30, 9, 0, 0),
        "crack_rate": 0.18,  # 18% - improved
        "notes": "Mid-year review showing improvement from Q1",
    },
    "demo_q3_2025": {
        "project_description": "Q3 2025 Security Assessment",
        "date": datetime(2025, 9, 30, 9, 0, 0),
        "crack_rate": 0.12,  # 12% - best
        "notes": "Q3 assessment showing continued improvement",
    },
}


def load_add_json(file_path: str) -> Dict[str, Any]:
    """Load ADD JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)


def load_potfile(file_path: str) -> Dict[str, str]:
    """Load potfile and return hash -> password mapping with HEX decoding."""
    hash_to_pw = {}
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2 and len(parts[0]) == 32:
                    # Decode HEX-encoded passwords to cleartext
                    password = decode_hex_password(parts[1])
                    hash_to_pw[parts[0].lower()] = password
    return hash_to_pw


def build_account_data(
    add_json: Dict[str, Any],
    hash_to_pw: Dict[str, str],
    target_crack_rate: float,
    seed: int = 42,
) -> Tuple[Dict[str, Dict[str, Any]], int, int]:
    """
    Build account_data dictionary with cracked passwords based on target rate.

    Returns:
        (account_data, cracked_count, total_count)
    """
    random.seed(seed)

    account_data = {}
    users = add_json.get("Users", [])
    total = len(users)

    # Calculate how many should be cracked
    target_cracked = int(total * target_crack_rate)

    # Get list of users whose hashes we can "crack"
    crackable = []
    uncrackable = []

    for user in users:
        username = user.get("SamAccountName", "")
        ntlm_hash_field = user.get("NTLMHash", "")

        # Parse hash (format: lm_hash:ntlm_hash)
        if ":" in ntlm_hash_field:
            parts = ntlm_hash_field.split(":")
            lm_hash = parts[0] if len(parts) > 0 else ""
            ntlm_hash = parts[1] if len(parts) > 1 else ""
        else:
            lm_hash = ""
            ntlm_hash = ntlm_hash_field

        ntlm_hash = ntlm_hash.lower()

        if ntlm_hash in hash_to_pw:
            crackable.append((user, ntlm_hash, hash_to_pw[ntlm_hash]))
        else:
            uncrackable.append((user, ntlm_hash, None))

    # Randomly select which crackable accounts to "crack"
    random.shuffle(crackable)
    to_crack = crackable[:min(target_cracked, len(crackable))]
    not_cracked = crackable[min(target_cracked, len(crackable)):]

    cracked_count = 0

    # Build account data for cracked accounts
    for user, ntlm_hash, password in to_crack:
        username = user.get("SamAccountName", "")
        pwd_last_set = user.get("PwdLastSet", "")
        is_disabled = "ACCOUNTDISABLE" in user.get("UserAccountControl", [])

        account_data[username] = {
            "lm_hash": user.get("LMHash", ""),  # Use LMHash field if present
            "ntlm_hash": ntlm_hash,
            "cracked_pw": password,
            "pw_last_set": pwd_last_set,
            "groups": user.get("MemberOf", []),
            "description": user.get("Description", ""),
            "disabled": is_disabled,  # Use 'disabled' key for check_blank compatibility
        }
        cracked_count += 1

    # Build account data for non-cracked accounts
    for user, ntlm_hash, _ in not_cracked + uncrackable:
        username = user.get("SamAccountName", "")
        pwd_last_set = user.get("PwdLastSet", "")
        is_disabled = "ACCOUNTDISABLE" in user.get("UserAccountControl", [])

        account_data[username] = {
            "lm_hash": user.get("LMHash", ""),  # Use LMHash field if present
            "ntlm_hash": ntlm_hash,
            "cracked_pw": None,
            "pw_last_set": pwd_last_set,
            "groups": user.get("MemberOf", []),
            "description": user.get("Description", ""),
            "disabled": is_disabled,  # Use 'disabled' key for check_blank compatibility
        }

    return account_data, cracked_count, total


def generate_session(
    session_id: str,
    config: Dict[str, Any],
    add_json: Dict[str, Any],
    hash_to_pw: Dict[str, str],
    sessions_dir: Path,
    seed: int,
) -> None:
    """Generate a complete session with all analysis data."""

    print(f"\n  Generating {session_id}...")
    print(f"    Target crack rate: {config['crack_rate']*100:.0f}%")

    # Build account data with target crack rate
    account_data, cracked_count, total_count = build_account_data(
        add_json, hash_to_pw, config["crack_rate"], seed=seed
    )

    actual_rate = cracked_count / total_count if total_count > 0 else 0
    print(f"    Actual crack rate: {actual_rate*100:.1f}% ({cracked_count}/{total_count})")

    # Run crack_stats analysis
    stats_report = password_analysis_tools.crack_stats(
        account_data,
        min_len=12,  # Policy minimum
        complexity=3,  # Policy complexity
        ignore_blank_passwords=False,
        max_pw_age=90,  # Policy max age
    )

    # Build stats table in correct format
    key_order = [
        "Cracked Accounts: ",
        "Uncracked Accounts: ",
        "Total Accounts Analyzed: ",
        "Percent of Accounts Cracked: ",
        "Cracked NTLM Hashes: ",
        "Uncracked NTLM Hashes: ",
        "Unique NTLM Hashes Analyzed: ",
        "Percent of NTLM Hashes Cracked: ",
        "Total LANMan Hashes: ",
        "Shortest Cracked Password: ",
        "Longest Cracked Password: ",
        "Average Password Length: ",
    ]
    stats_table = [
        {"key": key, "value": stats_report["cracking_stats"][key]}
        for key in key_order
    ]

    # Get cracked passwords for dictionary analysis
    cracked_passwords = [
        account["cracked_pw"]
        for account in account_data.values()
        if account.get("cracked_pw")
    ]

    # Create list of account/password entries (for substring analysis)
    account_password_entries = [
        {"account": username, "password": account["cracked_pw"]}
        for username, account in account_data.items()
        if account.get("cracked_pw")
    ]

    # Run substring analysis
    substrings = password_analysis_tools.substring_analysis(
        account_password_entries,
        min_length=4,
        max_length=20,
        frequency_threshold=5,
        normalize=False,
        suppress_nested=False,
    )

    # Run dictionary analysis
    detailed_results, english_words = password_analysis_tools.dictionary_analysis(
        cracked_passwords,
        min_word_length=4,
        omit_nested=False,
    )

    # Run bad practices analysis
    bad_practices = password_analysis_tools.bad_practices_analysis(
        cracked_passwords,
        custom_keywords=["demo", "corp", "democorp"],  # Company-related keywords
    )

    # Build password reuse table
    from collections import defaultdict
    hash_users = defaultdict(list)
    for username, data in account_data.items():
        if data.get("cracked_pw"):
            hash_users[data["ntlm_hash"]].append(username)

    pw_reuse_table = [
        [hash_val, len(users), users]
        for hash_val, users in hash_users.items()
        if len(users) >= 2
    ]
    pw_reuse_table.sort(key=lambda x: -x[1])

    # Create session directory
    session_dir = sessions_dir / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    # Save all session files
    def save_json(filename: str, data: Any) -> None:
        with open(session_dir / filename, 'w') as f:
            json.dump(data, f, indent=2)

    # Core analysis files
    save_json("cracking_stats_table.json", stats_table)
    save_json("pw_account_pie.json", stats_report["pw_account_pie"])
    save_json("pw_ntlm_hash_pie.json", stats_report["pw_ntlm_hash_pie"])
    save_json("pw_length_distribution.json", stats_report["pw_length_distribution"])
    save_json("pw_top_passwords.json", stats_report["pw_top_passwords"])
    save_json("pw_substrings.json", substrings)
    save_json("pw_dict_words.json", english_words)
    save_json("pw_reuse_table.json", pw_reuse_table)
    save_json("pw_fails_min_length.json", stats_report["pw_fails_min_length"])
    save_json("pw_fails_complexity.json", stats_report["pw_fails_complexity"])
    save_json("pw_fails_blank.json", stats_report["pw_fails_blank"])
    save_json("pw_fails_max_age.json", stats_report["pw_fails_max_age"])
    save_json("pw_lm_hashes.json", stats_report["pw_lm_hashes"])
    save_json("pw_bad_practices.json", bad_practices)
    save_json("account_data.json", account_data)

    # Session metadata
    metadata = {
        "session_id": session_id,
        "name": f"{COMPANY_NAME} - {config['project_description']}",
        "created_at": config["date"].isoformat(),
        "updated_at": config["date"].isoformat(),
        "created_by": "admin",
        "company_name": COMPANY_NAME,
        "project_description": config["project_description"],
        "source_files": {"add_json": "demo_ADD.json"},
        "source_hash": "demo_dataset",
        "total_accounts": total_count,
        "cracked_accounts": cracked_count,
        "crack_rate": actual_rate * 100,
        "notes": config["notes"],
        "aaia_generated": False,
        "aaia_timestamp": "",
    }
    save_json("session_meta.json", metadata)

    # Analysis options
    options = {
        "company_name": COMPANY_NAME,
        "project_description": config["project_description"],
        "policy_min_pw_len": "12",
        "policy_max_pw_age": "90",
        "policy_complexity_req": "3",
    }
    save_json("analysis_options.json", options)

    # Print summary
    print(f"    Created {len(list(session_dir.glob('*.json')))} JSON files")
    print(f"    Substrings found: {len(substrings)}")
    print(f"    Dictionary words found: {len(english_words)}")
    print(f"    Password reuse groups: {len(pw_reuse_table)}")

    # Count bad practices
    total_bad = sum(len(v) for v in bad_practices.values())
    print(f"    Bad practices found: {total_bad}")


def main():
    """Main function."""
    print("=" * 70)
    print("HM1K Demo Historical Sessions Generator")
    print("=" * 70)

    # Paths
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent
    test_data_dir = project_dir / "testData"
    sessions_dir = project_dir / "data" / "sessions"

    # Load ADD JSON
    add_path = test_data_dir / "example_ADD_expanded.json"
    if not add_path.exists():
        print(f"\nError: ADD JSON not found at {add_path}")
        print("Run 'python scripts/create_demo_dataset.py' first")
        return 1

    print(f"\nLoading ADD JSON from: {add_path}")
    add_json = load_add_json(str(add_path))
    print(f"  Total accounts: {len(add_json.get('Users', []))}")

    # Load potfile
    potfile_path = test_data_dir / "example_expanded.potfile"
    if not potfile_path.exists():
        print(f"\nError: Potfile not found at {potfile_path}")
        print("Run 'python scripts/create_demo_dataset.py' first")
        return 1

    print(f"\nLoading potfile from: {potfile_path}")
    hash_to_pw = load_potfile(str(potfile_path))
    print(f"  Loaded {len(hash_to_pw)} hash:password pairs")

    # Generate sessions
    print("\nGenerating historical sessions...")

    seed_base = 2025
    for session_id, config in SESSION_CONFIGS.items():
        generate_session(
            session_id,
            config,
            add_json,
            hash_to_pw,
            sessions_dir,
            seed=seed_base,
        )
        seed_base += 100

    print("\n" + "=" * 70)
    print("Demo sessions generated successfully!")
    print("\nCreated sessions:")
    for session_id, config in SESSION_CONFIGS.items():
        print(f"  - {session_id}: {config['project_description']}")
    print("\nTo test historical trend analysis:")
    print("  1. Start HM1K and log in")
    print("  2. Load any DemoCorp session")
    print("  3. Navigate to Historical Trend Analysis section")
    print("  4. Select sessions to compare")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
