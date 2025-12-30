"""
Hash Master 1000 - Substring Analysis (Account-Accurate, Chart.js-Compatible)

Goal:
- Count UNIQUE ACCOUNTS impacted by each substring (not unique password strings).
- Keep JSON output compatible with the existing Chart.js "Top Substrings Used" chart.

Existing report.html expects pw_substrings.json to be an ARRAY of objects like:
    [{"substring": "acker", "count": 3}, {"substring": "2025", "count": 2}, ...]

So this function returns that same structure.
It does NOT include account names in the output.

Input format (account is required for accurate counting):
    entries = [
        {"account": "jsmith", "password": "IPC$2025#"},
        {"account": "adoe", "password": "thisisIPC$pass"},
    ]

Output format:
    [
        {"substring": "IPC$", "count": 2},
        ...
    ]

Nested suppression:
- Uses ACCOUNT SETS for subset checks, which is more accurate than password-string sets.
"""

from __future__ import annotations

from typing import Any


def substring_analysis(
    entries: list[dict[str, str]],
    min_length: int = 4,
    max_length: int = 8,
    frequency_threshold: int = 2,
    normalize: bool = False,
    suppress_nested: bool = True,
) -> list[dict[str, Any]]:
    """
    Account-based substring analysis that returns Chart.js-compatible output.

    Args:
        entries:
            List of dicts with keys:
              - "account": unique account identifier (username/email/etc.)
              - "password": cracked plaintext password
        min_length:
            Minimum substring length to consider.
        max_length:
            Maximum substring length to consider.
        frequency_threshold:
            Minimum number of UNIQUE accounts that must contain the substring.
        normalize:
            If True, performs substring detection on lowercase passwords.
        suppress_nested:
            If True, suppresses substrings that are fully explained by longer substrings
            affecting the same set of accounts.

    Returns:
        List[{"substring": str, "count": int}] sorted later by the report (client-side).
    """

    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    if max_length < min_length:
        raise ValueError("max_length must be >= min_length")
    if frequency_threshold < 1:
        raise ValueError("frequency_threshold must be >= 1")

    # Key: substring
    # Value: set of account_ids that contain that substring
    substring_accounts: dict[str, set[str]] = {}

    for row in entries:
        if "account" not in row or "password" not in row:
            raise KeyError('Each entry must include keys "account" and "password"')

        account_id = row["account"]
        password = row["password"]

        match_password = password.lower() if normalize else password

        # Count each substring only once per account/password
        seen_in_this_password: set[str] = set()

        for length in range(min_length, max_length + 1):
            if length > len(match_password):
                continue
            for i in range(len(match_password) - length + 1):
                seen_in_this_password.add(match_password[i : i + length])

        for substring in seen_in_this_password:
            if substring not in substring_accounts:
                substring_accounts[substring] = set()
            substring_accounts[substring].add(account_id)

    # Filter by UNIQUE account count threshold
    filtered: dict[str, set[str]] = {
        substring: acct_set
        for substring, acct_set in substring_accounts.items()
        if len(acct_set) >= frequency_threshold
    }

    if not filtered:
        return []

    if suppress_nested:
        non_nested: dict[str, set[str]] = {}

        # Sort: longer substrings first, then higher account counts
        sorted_substrings = sorted(
            filtered.items(),
            key=lambda item: (-len(item[0]), -len(item[1])),
        )

        for substr, acct_set in sorted_substrings:
            should_suppress = False

            for longer_substr, longer_acct_set in non_nested.items():
                if substr in longer_substr and substr != longer_substr:
                    if acct_set <= longer_acct_set:
                        should_suppress = True
                        break

            if not should_suppress:
                non_nested[substr] = acct_set

        return [{"substring": s, "count": len(a)} for s, a in non_nested.items()]

    return [{"substring": s, "count": len(a)} for s, a in filtered.items()]
