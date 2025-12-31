#!/usr/bin/env python3
"""
Test script to verify crack_stats() and crack_stats_single_pass() produce identical results.

This ensures the single-pass optimization doesn't change behavior.
"""

import json
import time
from typing import Any

from password_analysis_tools import crack_stats, crack_stats_single_pass


def create_test_account_data() -> dict[str, dict[str, Any]]:
    """Create realistic test data covering all edge cases."""
    account_data = {}

    # Normal cracked accounts with various password lengths
    passwords = [
        "Password1", "Welcome123", "Summer2024!", "qwerty", "12345678",
        "SecureP@ss123", "admin", "letmein", "P@ssw0rd!", "Company2024",
        "Winter2023", "test", "hunter2", "password", "abc123",
    ]

    for i, pw in enumerate(passwords):
        account_data[f"user{i}"] = {
            "ntlm_hash": f"hash{i:032d}",
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",  # blank LM
            "cracked_pw": pw,
            "disabled": False,
            "last_pw_change": "01/15/2024",
        }

    # Accounts with valid LM hashes
    for i in range(15, 18):
        account_data[f"lm_user{i}"] = {
            "ntlm_hash": f"hash{i:032d}",
            "lm_hash": f"lmhash{i:026d}",  # non-blank LM
            "cracked_pw": f"LMPass{i}",
            "disabled": False,
            "last_pw_change": "06/01/2023",
        }

    # Blank password accounts (using blank NTLM hash)
    for i in range(18, 21):
        account_data[f"blank_user{i}"] = {
            "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",  # blank NTLM
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "cracked_pw": None,
            "disabled": i == 19,  # One disabled
            "last_pw_change": "12/01/2022",
        }

    # Blank password with empty string cracked_pw
    account_data["blank_explicit"] = {
        "ntlm_hash": "somehash00000000000000000000001",
        "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
        "cracked_pw": "",
        "disabled": False,
        "last_pw_change": "01/01/2020",
    }

    # Uncracked accounts
    for i in range(22, 27):
        account_data[f"uncracked{i}"] = {
            "ntlm_hash": f"uncracked{i:023d}",
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "cracked_pw": None,
            "disabled": False,
            "last_pw_change": "03/15/2024",
        }

    # Password reuse (same password, different hashes - shared passwords)
    for i in range(27, 30):
        account_data[f"shared_pw_user{i}"] = {
            "ntlm_hash": f"sharedpwhash{i:020d}",
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "cracked_pw": "SharedPassword123!",
            "disabled": False,
            "last_pw_change": "02/01/2024",
        }

    # Hash reuse (same hash, therefore same password)
    for i in range(30, 33):
        account_data[f"hash_reuse_user{i}"] = {
            "ntlm_hash": "reusedhashabcdef1234567890abcd",  # same hash
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "cracked_pw": "ReusedPassword!",
            "disabled": False,
            "last_pw_change": "04/01/2024",
        }

    # Accounts with old passwords (fail max age)
    for i in range(33, 36):
        account_data[f"old_pw_user{i}"] = {
            "ntlm_hash": f"oldpwhash{i:022d}",
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "cracked_pw": f"OldPassword{i}",
            "disabled": False,
            "last_pw_change": "01/01/2020",  # Very old
        }

    # Account with no last_pw_change
    account_data["no_pw_change_date"] = {
        "ntlm_hash": "nopwchangehash0000000000000001",
        "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
        "cracked_pw": "NoDate123!",
        "disabled": False,
        "last_pw_change": None,
    }

    # Simple passwords (fail complexity)
    simple_passwords = ["123456", "abcdef", "ABCDEF", "!!!!!!"]
    for i, pw in enumerate(simple_passwords):
        account_data[f"simple_user{i}"] = {
            "ntlm_hash": f"simplehash{i:022d}",
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "cracked_pw": pw,
            "disabled": False,
            "last_pw_change": "05/01/2024",
        }

    return account_data


def deep_compare(obj1: Any, obj2: Any, path: str = "") -> list[str]:
    """
    Deeply compare two objects and return list of differences.
    """
    differences = []

    if type(obj1) != type(obj2):
        differences.append(f"{path}: type mismatch {type(obj1).__name__} vs {type(obj2).__name__}")
        return differences

    if isinstance(obj1, dict):
        keys1 = set(obj1.keys())
        keys2 = set(obj2.keys())

        for key in keys1 - keys2:
            differences.append(f"{path}.{key}: missing in second")
        for key in keys2 - keys1:
            differences.append(f"{path}.{key}: missing in first")

        for key in keys1 & keys2:
            differences.extend(deep_compare(obj1[key], obj2[key], f"{path}.{key}"))

    elif isinstance(obj1, list):
        if len(obj1) != len(obj2):
            differences.append(f"{path}: list length {len(obj1)} vs {len(obj2)}")
        else:
            for i, (item1, item2) in enumerate(zip(obj1, obj2)):
                differences.extend(deep_compare(item1, item2, f"{path}[{i}]"))

    elif isinstance(obj1, set):
        if obj1 != obj2:
            differences.append(f"{path}: set mismatch {obj1} vs {obj2}")

    elif obj1 != obj2:
        differences.append(f"{path}: value mismatch {repr(obj1)} vs {repr(obj2)}")

    return differences


def test_equivalence(account_data: dict, ignore_blank: bool, min_len: int, complexity: int, max_age: int) -> bool:
    """Test that both functions produce identical results for given parameters."""
    print(f"\nTesting with ignore_blank={ignore_blank}, min_len={min_len}, complexity={complexity}, max_age={max_age}")

    # Run both functions
    result_original = crack_stats(
        account_data,
        min_len=min_len,
        complexity=complexity,
        ignore_blank_passwords=ignore_blank,
        max_pw_age=max_age,
    )

    result_optimized = crack_stats_single_pass(
        account_data,
        min_len=min_len,
        complexity=complexity,
        ignore_blank_passwords=ignore_blank,
        max_pw_age=max_age,
    )

    # Compare results
    differences = deep_compare(result_original, result_optimized, "root")

    if differences:
        print(f"  FAIL: {len(differences)} differences found:")
        for diff in differences[:10]:  # Show first 10
            print(f"    - {diff}")
        if len(differences) > 10:
            print(f"    ... and {len(differences) - 10} more")
        return False
    else:
        print("  PASS: Results are identical")
        return True


def test_performance(account_data: dict) -> None:
    """Compare performance of both functions."""
    print("\n" + "=" * 60)
    print("Performance Comparison")
    print("=" * 60)

    # Warm up
    crack_stats(account_data)
    crack_stats_single_pass(account_data)

    # Time original
    iterations = 100
    start = time.perf_counter()
    for _ in range(iterations):
        crack_stats(account_data)
    original_time = (time.perf_counter() - start) / iterations * 1000

    # Time optimized
    start = time.perf_counter()
    for _ in range(iterations):
        crack_stats_single_pass(account_data)
    optimized_time = (time.perf_counter() - start) / iterations * 1000

    speedup = original_time / optimized_time if optimized_time > 0 else float('inf')

    print(f"\nWith {len(account_data)} accounts ({iterations} iterations each):")
    print(f"  Original:  {original_time:.3f} ms/call")
    print(f"  Optimized: {optimized_time:.3f} ms/call")
    print(f"  Speedup:   {speedup:.2f}x faster")


def main():
    print("=" * 60)
    print("crack_stats() vs crack_stats_single_pass() Equivalence Test")
    print("=" * 60)

    # Create test data
    account_data = create_test_account_data()
    print(f"\nCreated test dataset with {len(account_data)} accounts")

    # Test various parameter combinations
    test_cases = [
        # (ignore_blank, min_len, complexity, max_age)
        (False, 8, 3, 90),   # Default-ish settings
        (True, 8, 3, 90),    # Ignore blanks
        (False, 14, 3, 90),  # Higher min length
        (False, 8, 4, 90),   # Higher complexity
        (False, 8, 3, 30),   # Shorter max age
        (False, 8, 3, 0),    # No max age (never expire)
        (True, 14, 4, 365),  # All strict settings
    ]

    all_passed = True
    for ignore_blank, min_len, complexity, max_age in test_cases:
        if not test_equivalence(account_data, ignore_blank, min_len, complexity, max_age):
            all_passed = False

    # Performance comparison
    test_performance(account_data)

    # Summary
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL TESTS PASSED - Functions are equivalent")
    else:
        print("SOME TESTS FAILED - Functions are NOT equivalent")
    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == "__main__":
    exit(main())
