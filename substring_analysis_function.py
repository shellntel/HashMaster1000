"""
Substring Analysis Function
Extracted from password_analysis_tools.py for review
"""
from typing import Any


def substring_analysis(
    passwords: list[str],
    min_length: int = 4,
    max_length: int = 8,
    frequency_threshold: int = 2,
    normalize: bool = False,
    suppress_nested: bool = True,
) -> list[dict[str, Any]]:
    """
    Analyze substrings within a range of lengths across passwords and find common patterns,
    with an option to suppress nested substrings in longer substrings.

    Parameters:
    - passwords (list of str): List of cracked passwords.
    - min_length (int): Minimum length for substrings to analyze.
    - max_length (int): Maximum length for substrings to analyze.
    - frequency_threshold (int): Minimum number of unique passwords containing the substring.
    - normalize (bool): Whether to convert passwords to lowercase for case-insensitive analysis.
    - suppress_nested (bool): Whether to suppress shorter substrings that appear in the same
                              passwords as longer substrings that contain them.

    Returns:
    - list of dict: A list of substrings with `substring`, `count` (unique passwords),
                    and `passwords` (dict of password -> occurrence count).
    """
    # Track which passwords contain each substring
    # Key: substring, Value: dict of {password: count_in_that_password}
    substring_passwords: dict[str, dict[str, int]] = {}

    for password in passwords:
        # Normalize for matching if requested, but store original password
        match_password = password.lower() if normalize else password

        # Track substrings found in this password to count unique passwords
        found_in_this_password: dict[str, int] = {}

        # Generate substrings using a sliding window
        for length in range(min_length, max_length + 1):
            for i in range(len(match_password) - length + 1):
                substring = match_password[i : i + length]
                found_in_this_password[substring] = found_in_this_password.get(substring, 0) + 1

        # Add this password to each substring's password dict
        for substring, count_in_pw in found_in_this_password.items():
            if substring not in substring_passwords:
                substring_passwords[substring] = {}
            # Store the original password (not normalized) with its count
            substring_passwords[substring][password] = count_in_pw

    # Filter substrings by frequency threshold (number of unique passwords)
    filtered_substrings = {
        substring: pw_dict
        for substring, pw_dict in substring_passwords.items()
        if len(pw_dict) >= frequency_threshold
    }

    # Option to suppress nested substrings
    if suppress_nested:
        non_nested_results: dict[str, dict[str, int]] = {}

        # Sort substrings by length (longest first) and by password count (highest first)
        sorted_substrings = sorted(
            filtered_substrings.items(),
            key=lambda item: (-len(item[0]), -len(item[1]))
        )

        for substr, pw_dict in sorted_substrings:
            # Check if this substring should be suppressed
            # A substring is suppressed if:
            # 1. It's contained within a longer substring already in results
            # 2. AND all passwords containing this substring also contain the longer one
            should_suppress = False

            for longer_substr, longer_pw_dict in non_nested_results.items():
                if substr in longer_substr and substr != longer_substr:
                    # Check if all passwords with shorter substring also have the longer one
                    shorter_passwords = set(pw_dict.keys())
                    longer_passwords = set(longer_pw_dict.keys())

                    # If shorter substring appears in same or subset of passwords as longer,
                    # suppress it (the longer one already captures this pattern)
                    if shorter_passwords <= longer_passwords:
                        should_suppress = True
                        break

            if not should_suppress:
                non_nested_results[substr] = pw_dict

        # Return results with password examples
        return [
            {
                "substring": substr,
                "count": len(pw_dict),
                "passwords": pw_dict
            }
            for substr, pw_dict in non_nested_results.items()
        ]

    # Return all substrings with password examples
    return [
        {
            "substring": substr,
            "count": len(pw_dict),
            "passwords": pw_dict
        }
        for substr, pw_dict in filtered_substrings.items()
    ]
