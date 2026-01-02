import string
from collections import defaultdict, Counter
import re
from english_words import get_english_words_set
from typing import Any, TypedDict

# Module-level cache for the English dictionary (loaded once on first use)
_english_words_cache: set[str] | None = None


def _get_english_words() -> set[str]:
    """
    Get the cached English words set, loading it on first call.
    Uses the web2 dictionary from english-words package (~234K words).
    """
    global _english_words_cache
    if _english_words_cache is None:
        _english_words_cache = get_english_words_set(['web2'], lower=True)
    return _english_words_cache


def _load_exclusions(file_path: str = "dictionary_exclusions.conf") -> set[str]:
    """
    Load exclusions from a configuration file.
    Supports comments (lines starting with #) and empty lines.
    """
    exclusions: set[str] = set()
    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    exclusions.add(line.lower())
    except FileNotFoundError:
        pass  # No exclusions file is fine
    except Exception:
        pass  # Silently ignore other errors
    return exclusions


class Account(TypedDict):
    lm_hash: str
    ntlm_hash: str
    cracked_pw: str


class PieChart(TypedDict):
    Cracked: int
    Uncracked: int


class Report(TypedDict):
    cracking_stats: dict[str, int | None]
    pw_account_pie: PieChart
    pw_ntlm_hash_pie: PieChart
    pw_length_distribution: dict[int, int]
    ignore_blank_passwords: bool
    pw_top_passwords: dict[str, int]
    pw_fails_min_length: dict[str, dict[str, Any]]
    pw_fails_complexity: dict[str, dict[str, str | int]]
    pw_fails_blank: list[str]
    pw_fails_max_age: dict[str, dict[str, Any]]


# Function to check for Lanman hashes (pwdump_file based)
def check_lm(pwdump_file: str) -> list[str]:
    lanman_accounts = []

    with open(pwdump_file, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if (
                len(parts) > 3
                and parts[2] != ""
                and parts[2] != "aad3b435b51404eeaad3b435b51404ee"
            ):
                lanman_accounts.append(parts[0])

    lanman_accounts = sorted(lanman_accounts)

    return lanman_accounts


# Function to count LANMan hashes (account_data based)
def lm_count(account_data: dict[str, dict[str, str | int | None]]) -> int:
    count = sum(
        1
        for account in account_data.values()
        if account.get("lm_hash") and account["lm_hash"] != "aad3b435b51404eeaad3b435b51404ee"
    )
    return count


# Function to get accounts with valid (non-blank) LANMan hashes (account_data based)
def get_lm_accounts(account_data: dict[str, dict[str, str | int | None]]) -> list[dict[str, str]]:
    """
    Returns a sorted list of dicts containing account names, LM hashes, and cracked passwords
    for accounts that have a valid (non-blank) LM hash.
    LM hashes are weaker than NTLM and should be disabled in modern environments.

    Including the cracked password helps pentesters identify LM hash accounts
    that haven't been cracked yet - these may have easily crackable passwords
    that were missed because cracking focused on NTLM hashes.
    """
    lm_accounts = [
        {
            "account": account_name,
            "lm_hash": account.get("lm_hash") or "",
            "cracked_pw": account.get("cracked_pw") or ""
        }
        for account_name, account in account_data.items()
        if account.get("lm_hash") and account["lm_hash"] != "aad3b435b51404eeaad3b435b51404ee"
    ]
    return sorted(lm_accounts, key=lambda x: x["account"])


# Function to check for password reuse
def check_pw_reuse(pwdump_file: str) -> list[tuple[str, int, list[str]]]:
    ntlm_hashes = defaultdict(list)

    with open(pwdump_file, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) > 3 and parts[3] != "":
                ntlm_hashes[parts[3]].append(parts[0])

    reuse_report = [
        (hash_val, len(accounts), accounts)
        for hash_val, accounts in ntlm_hashes.items()
        if len(accounts) > 1
    ]
    reuse_report.sort(key=lambda x: x[1], reverse=True)

    return reuse_report


def check_pw_reuse_from_account_data(
    account_data: dict[str, dict[str, str | int | None]]
) -> list[tuple[str, int, list[str]]]:
    """
    Check for password reuse using account_data dictionary format.

    This function is used for ADD JSON analysis where we have account_data
    instead of a pwdump file.

    Args:
        account_data: Dictionary mapping account names to their data including ntlm_hash

    Returns:
        List of tuples: (ntlm_hash, count, [account_names])
        Only includes hashes shared by 2+ accounts, sorted by count descending.
    """
    ntlm_hashes: dict[str, list[str]] = defaultdict(list)

    # Blank NTLM hash should be excluded from reuse analysis
    blank_ntlm_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

    for account_name, data in account_data.items():
        ntlm_hash = data.get("ntlm_hash", "")
        # Skip empty hashes and blank password hash
        if ntlm_hash and ntlm_hash != blank_ntlm_hash:
            ntlm_hashes[ntlm_hash].append(account_name)

    # Only include hashes used by more than one account
    reuse_report = [
        (hash_val, len(accounts), sorted(accounts))
        for hash_val, accounts in ntlm_hashes.items()
        if len(accounts) > 1
    ]
    reuse_report.sort(key=lambda x: x[1], reverse=True)

    return reuse_report


# List accounts with blank passwords (only if the ignore blanks option wasn't checked)
def check_blank(
    accounts_info: dict[str, dict[str, str | int | None]],
    ignore_blank_passwords: bool = False,
) -> tuple[list[str], list[str]]:
    """
    Identifies accounts with blank passwords.
    Includes accounts with either an empty string or "{Blank Password}" as the password.
    """
    blank_ntlm_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

    # Identify blank accounts based on NTLM hash or placeholder value
    # Returns list of dicts with account name and status
    all_blank_accounts = [
        {
            "account": account_name,
            "status": "Disabled" if account_data.get("disabled") is True
                     else "Enabled" if account_data.get("disabled") is False
                     else "Unknown"
        }
        for account_name, account_data in accounts_info.items()
        if account_data.get("ntlm_hash") == blank_ntlm_hash
        or account_data.get("cracked_pw") in ("", "{Blank Password}")
    ]

    blank_accounts_for_reporting = [] if ignore_blank_passwords else all_blank_accounts

    return all_blank_accounts, blank_accounts_for_reporting


def check_max_age(
    accounts_info: dict[str, dict[str, str | int | None]],
    max_age_days: int = 90,
) -> dict[str, dict[str, Any]]:
    """
    Identifies accounts with passwords older than the maximum age policy.

    Uses the 'last_pw_change' field from account_data (populated from ADD JSON's PwdLastSet).

    Args:
        accounts_info: Dictionary of account data
        max_age_days: Maximum password age in days (from domain policy or user setting).
                      If 0, passwords never expire and no accounts will be flagged.

    Returns:
        Dictionary of {account_name: {"pw_changed": date_string, "pw_age": days_old}}
    """
    from datetime import datetime, date

    failing_accounts: dict[str, dict[str, Any]] = {}

    # If max_age_days is 0, passwords never expire - return empty result
    if max_age_days == 0:
        return failing_accounts

    today = date.today()

    for account_name, account_data in accounts_info.items():
        last_pw_change = account_data.get("last_pw_change")

        # Skip if no password change date available
        if not last_pw_change or last_pw_change == "0" or last_pw_change == "":
            continue

        # Try to parse the date (expected format: MM/DD/YYYY from ADD JSON)
        try:
            # Handle various date formats
            pw_change_date = None
            if isinstance(last_pw_change, str):
                # Try MM/DD/YYYY format first (ADD JSON format)
                for fmt in ["%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y"]:
                    try:
                        pw_change_date = datetime.strptime(last_pw_change, fmt).date()
                        break
                    except ValueError:
                        continue

            if pw_change_date is None:
                continue

            # Calculate password age in days
            pw_age = (today - pw_change_date).days

            # Check if password exceeds max age
            if pw_age > max_age_days:
                failing_accounts[account_name] = {
                    "pw_changed": last_pw_change,
                    "pw_age": pw_age,
                }
        except (ValueError, TypeError):
            # Skip accounts with unparseable dates
            continue

    return failing_accounts


# List accounts failing password complexity
def get_non_compliant_accounts(
    account_data: dict[str, dict[str, str | int | None]], num_categories_req: int
) -> dict[str, dict[str, str | int]]:
    def check_complexity(password: str) -> int:
        if not password:  # Catch blank passwords
            return 0
        categories = {
            "uppercase": any(char.isupper() for char in password),
            "lowercase": any(char.islower() for char in password),
            "digits": any(char.isdigit() for char in password),
            "specials": any(
                char in string.punctuation or char.isspace() for char in password
            ),
        }
        return sum(categories.values())  # Count of categories present

    non_compliant_accounts: dict[str, dict[str, str | int]] = {}
    for account, details in account_data.items():
        password = details.get("cracked_pw")
        if isinstance(password, str):  # Ensure password is a string
            complexity_count = check_complexity(password)
            if complexity_count < num_categories_req:
                non_compliant_accounts[account] = {
                    "cracked_pw": password,
                    "complexity_count": complexity_count,
                }

    return non_compliant_accounts


# Function to report general statistics from the source hashes and cracked passwords
def crack_stats(
    account_data: dict[str, dict[str, str | int | None]],
    min_len: int = 14,
    complexity: int = 3,
    ignore_blank_passwords: bool = False,
    max_pw_age: int = 90,
) -> dict[str, Any]:
    """
    Calculate password cracking statistics.

    This function delegates to crack_stats_single_pass() which collects all metrics
    in a single iteration over account_data for better performance with large datasets.

    :param account_data: A dictionary where each key is an account name, and the value is another dictionary with account details.
    :param min_len: Minimum password length for compliance.
    :param complexity: Minimum number of complexity categories for compliance.
    :param ignore_blank_passwords: Whether to exclude blank passwords from analysis.
    :param max_pw_age: Maximum password age in days for compliance (requires last_pw_change in account_data).
    :return: A dictionary containing various password cracking statistics and reports.
    """
    from timing_stats import get_timing_stats, TimingStats

    timing = get_timing_stats()
    with timing.timer(TimingStats.CRACK_STATS, item_count=len(account_data)):
        return crack_stats_single_pass(
            account_data,
            min_len=min_len,
            complexity=complexity,
            ignore_blank_passwords=ignore_blank_passwords,
            max_pw_age=max_pw_age,
        )


def crack_stats_single_pass(
    account_data: dict[str, dict[str, str | int | None]],
    min_len: int = 14,
    complexity: int = 3,
    ignore_blank_passwords: bool = False,
    max_pw_age: int = 90,
) -> dict[str, Any]:
    """
    Calculate password cracking statistics in a single pass over account_data.

    This is an optimized version of crack_stats() that collects all metrics
    in one iteration instead of 12 separate iterations.

    Performance improvement: ~5-10 seconds → ~1-2 seconds for 600K accounts.

    :param account_data: A dictionary where each key is an account name, and the value is another dictionary with account details.
    :param min_len: Minimum password length for compliance.
    :param complexity: Minimum number of complexity categories for compliance.
    :param ignore_blank_passwords: Whether to exclude blank passwords from analysis.
    :param max_pw_age: Maximum password age in days for compliance (requires last_pw_change in account_data).
    :return: A dictionary containing various password cracking statistics and reports.
    """
    from datetime import datetime, date

    print(
        f"crack_stats_single_pass function called with ignore_blank_passwords={ignore_blank_passwords}"
    )

    # Constants
    BLANK_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
    BLANK_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

    # Helper function for complexity check (inlined for single-pass)
    def check_complexity(password: str) -> int:
        if not password:
            return 0
        categories = {
            "uppercase": any(char.isupper() for char in password),
            "lowercase": any(char.islower() for char in password),
            "digits": any(char.isdigit() for char in password),
            "specials": any(
                char in string.punctuation or char.isspace() for char in password
            ),
        }
        return sum(categories.values())

    # Accumulators for single-pass collection
    total_accounts = 0
    cracked_accounts_count = 0
    unique_ntlm_hashes: set[str] = set()
    cracked_ntlm_hashes: set[str] = set()
    has_blank_hash_in_dataset = False
    total_lm_hashes = 0
    cracked_pw_lengths: list[int] = []
    password_counter: Counter = Counter()

    # Result collections
    all_blank_accounts: list[dict[str, str]] = []
    pw_fails_min_length: dict[str, dict[str, Any]] = {}
    pw_fails_complexity: dict[str, dict[str, str | int]] = {}
    pw_fails_max_age: dict[str, dict[str, Any]] = {}
    lm_accounts: list[dict[str, str]] = []

    # For max age calculations
    today = date.today()

    # Single pass over account_data
    for account_name, account in account_data.items():
        total_accounts += 1

        ntlm_hash = account.get("ntlm_hash")
        lm_hash = account.get("lm_hash")
        cracked_pw = account.get("cracked_pw")
        last_pw_change = account.get("last_pw_change")
        is_disabled = account.get("disabled")

        # --- Unique NTLM hashes ---
        if isinstance(ntlm_hash, str):
            unique_ntlm_hashes.add(ntlm_hash)

        # --- Blank account detection ---
        is_blank_account = (
            ntlm_hash == BLANK_NTLM_HASH
            or cracked_pw in ("", "{Blank Password}")
        )

        if is_blank_account:
            has_blank_hash_in_dataset = True
            status = "Disabled" if is_disabled is True else "Enabled" if is_disabled is False else "Unknown"
            all_blank_accounts.append({"account": account_name, "status": status})

        # --- LM hash detection ---
        if lm_hash and lm_hash != BLANK_LM_HASH:
            total_lm_hashes += 1
            lm_accounts.append({
                "account": account_name,
                "lm_hash": lm_hash or "",
                "cracked_pw": cracked_pw or ""
            })

        # --- Cracked account detection ---
        has_cracked_pw = isinstance(cracked_pw, str) and cracked_pw != ""

        if has_cracked_pw:
            cracked_accounts_count += 1
            password_counter[cracked_pw] += 1

            # Cracked NTLM hash (excluding blank hash)
            if ntlm_hash and ntlm_hash != BLANK_NTLM_HASH:
                cracked_ntlm_hashes.add(ntlm_hash)

            # Password length
            pw_len = len(cracked_pw)
            cracked_pw_lengths.append(pw_len)

            # Min length check
            if pw_len < min_len:
                pw_fails_min_length[account_name] = {
                    "cracked_pw": cracked_pw,
                    "pw_length": pw_len,
                }

            # Complexity check
            complexity_count = check_complexity(cracked_pw)
            if complexity_count < complexity:
                pw_fails_complexity[account_name] = {
                    "cracked_pw": cracked_pw,
                    "complexity_count": complexity_count,
                }

        # Handle blank passwords with empty string cracked_pw
        elif cracked_pw == "":
            # Empty string password - counted as cracked
            if not ignore_blank_passwords:
                cracked_accounts_count += 1
                password_counter[""] += 1
                cracked_pw_lengths.append(0)

                # Empty string fails min length
                pw_fails_min_length[account_name] = {
                    "cracked_pw": "",
                    "pw_length": 0,
                }

                # Empty string fails complexity (0 categories)
                pw_fails_complexity[account_name] = {
                    "cracked_pw": "",
                    "complexity_count": 0,
                }

        # Handle blank accounts detected by NTLM hash alone (cracked_pw is None)
        # These ARE counted as cracked accounts, but are NOT added to:
        # - cracked_pw_lengths (since cracked_pw is not a string)
        # - password_counter (original doesn't count these in top passwords)
        # - pw_fails_min_length or pw_fails_complexity
        elif is_blank_account and cracked_pw is None:
            if not ignore_blank_passwords:
                cracked_accounts_count += 1
                # Note: NOT added to password_counter or cracked_pw_lengths
                # to match original behavior

        # --- Max age check ---
        if max_pw_age > 0 and last_pw_change and last_pw_change not in ("0", ""):
            try:
                pw_change_date = None
                if isinstance(last_pw_change, str):
                    for fmt in ["%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y"]:
                        try:
                            pw_change_date = datetime.strptime(last_pw_change, fmt).date()
                            break
                        except ValueError:
                            continue

                if pw_change_date is not None:
                    pw_age = (today - pw_change_date).days
                    if pw_age > max_pw_age:
                        pw_fails_max_age[account_name] = {
                            "pw_changed": last_pw_change,
                            "pw_age": pw_age,
                        }
            except (ValueError, TypeError):
                pass

    # --- Post-processing ---

    # Include blank NTLM hash in cracked set if present and not ignored
    if not ignore_blank_passwords and has_blank_hash_in_dataset:
        cracked_ntlm_hashes.add(BLANK_NTLM_HASH)

    # Sort LM accounts
    lm_accounts.sort(key=lambda x: x["account"])

    # Blank accounts for reporting
    blank_accounts_for_reporting = [] if ignore_blank_passwords else all_blank_accounts
    pw_fails_blank = all_blank_accounts  # Full list regardless of ignore option

    # Filter out blank accounts from complexity failures if ignored
    if ignore_blank_passwords:
        pw_fails_complexity = {
            account: details
            for account, details in pw_fails_complexity.items()
            if details["cracked_pw"] != ""
        }

    # Calculate statistics
    total_ntlm_hashes = len(unique_ntlm_hashes)
    cracked_ntlm_hashes_count = len(cracked_ntlm_hashes)
    uncracked_accounts = total_accounts - cracked_accounts_count
    uncracked_ntlm_hashes = total_ntlm_hashes - cracked_ntlm_hashes_count

    cracked_hash_percent = (
        (str(round((cracked_ntlm_hashes_count / total_ntlm_hashes * 100), 1)) + "%")
        if total_ntlm_hashes > 0
        else 0
    )
    cracked_account_pw_percent = (
        (str(round((cracked_accounts_count / total_accounts * 100), 1)) + "%")
        if total_accounts > 0
        else 0
    )

    # Password length statistics
    if ignore_blank_passwords:
        cracked_pw_lengths = [length for length in cracked_pw_lengths if length > 0]

    shortest_pw_len = min(cracked_pw_lengths) if cracked_pw_lengths else None
    longest_pw_len = max(cracked_pw_lengths) if cracked_pw_lengths else None
    avg_pw_len = (
        (str(round((sum(cracked_pw_lengths) / len(cracked_pw_lengths)), 2)))
        if cracked_pw_lengths
        else None
    )

    # Length distribution
    length_distribution = {length: 0 for length in range(0, (longest_pw_len or 0) + 1)}
    for length in cracked_pw_lengths:
        length_distribution[length] += 1

    if ignore_blank_passwords:
        length_distribution = {
            length: count for length, count in length_distribution.items() if length > 0
        }

    # Top reused passwords
    top_reused_passwords = {
        "{blank}" if pw == "" else pw: count
        for pw, count in password_counter.items()
        if count >= 2 and not (ignore_blank_passwords and pw == "")
    }

    # Pie charts
    pw_account_pie = {"Cracked": cracked_accounts_count, "Uncracked": uncracked_accounts}
    pw_hash_pie = {
        "Cracked": cracked_ntlm_hashes_count,
        "Uncracked": uncracked_ntlm_hashes,
    }

    # Build final report
    cracking_stats = {
        "Cracked Accounts: ": cracked_accounts_count,
        "Uncracked Accounts: ": uncracked_accounts,
        "Total Accounts Analyzed: ": total_accounts,
        "Percent of Accounts Cracked: ": cracked_account_pw_percent,
        "Cracked NTLM Hashes: ": cracked_ntlm_hashes_count,
        "Uncracked NTLM Hashes: ": uncracked_ntlm_hashes,
        "Unique NTLM Hashes Analyzed: ": total_ntlm_hashes,
        "Percent of NTLM Hashes Cracked: ": cracked_hash_percent,
        "Total LANMan Hashes: ": total_lm_hashes,
        "Shortest Cracked Password: ": shortest_pw_len,
        "Longest Cracked Password: ": longest_pw_len,
        "Average Password Length: ": avg_pw_len,
    }

    report = {
        "cracking_stats": cracking_stats,
        "pw_account_pie": pw_account_pie,
        "pw_ntlm_hash_pie": pw_hash_pie,
        "pw_length_distribution": length_distribution,
        "ignore_blank_passwords": ignore_blank_passwords,
        "pw_top_passwords": top_reused_passwords,
        "pw_fails_min_length": pw_fails_min_length,
        "pw_fails_complexity": pw_fails_complexity,
        "pw_fails_blank": pw_fails_blank,
        "pw_fails_max_age": pw_fails_max_age,
        "pw_lm_hashes": lm_accounts,
    }

    return report


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

    This function counts UNIQUE ACCOUNTS impacted by each substring, not unique
    password strings. This ensures accurate counting when multiple accounts share
    the same password.

    Parameters:
    - entries (list of dict): List of dicts with keys:
        - "account": unique account identifier (username/email/etc.)
        - "password": cracked plaintext password
    - min_length (int): Minimum length for substrings to analyze.
    - max_length (int): Maximum length for substrings to analyze.
    - frequency_threshold (int): Minimum number of UNIQUE accounts containing the substring.
    - normalize (bool): If True, performs substring detection on lowercase passwords.
    - suppress_nested (bool): If True, suppresses substrings that are fully explained by
                              longer substrings affecting the same set of accounts.

    Returns:
    - list of dict: A list of substrings with `substring` and `count` (unique accounts).
    """
    from timing_stats import get_timing_stats, TimingStats

    timing = get_timing_stats()
    timing.start_timer(TimingStats.SUBSTRING_ANALYSIS)

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

        result = [{"substring": s, "count": len(a)} for s, a in non_nested.items()]
        timing.stop_timer(TimingStats.SUBSTRING_ANALYSIS, item_count=len(entries))
        return result

    result = [{"substring": s, "count": len(a)} for s, a in filtered.items()]
    timing.stop_timer(TimingStats.SUBSTRING_ANALYSIS, item_count=len(entries))
    return result


def dictionary_analysis(
    passwords: list[str],
    min_word_length: int = 4,
    omit_nested: bool = False,
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """
    Analyze a list of passwords to identify dictionary words.

    :param passwords: List of passwords to analyze.
    :param min_word_length: Minimum length of dictionary words to consider.
    :param omit_nested: Whether to omit nested words within longer words.
    :return: Tuple of two dictionaries:
             1. Password-to-matched-words mapping.
             2. Word-to-occurrence-count mapping.
    """
    from timing_stats import get_timing_stats, TimingStats

    timing = get_timing_stats()
    timing.start_timer(TimingStats.DICTIONARY_ANALYSIS)

    # Use cached dictionary for better performance
    all_english_words = _get_english_words()
    english_words = {word for word in all_english_words if len(word) >= min_word_length}

    # Load and apply exclusions
    exclusions = _load_exclusions()
    english_words -= exclusions

    password_analysis: dict[str, list[str]] = {}  # Store each password with its dictionary words
    word_count: dict[str, int] = {}  # Store each English dictionary word with its count

    for password in passwords:
        # Extract alphabetic substrings from the password with their positions
        # Each match contains: (word, start_in_password, end_in_password)
        matches_with_positions: list[tuple[str, int, int]] = []

        # Find all alphabetic substrings and their positions in the original password
        for match in re.finditer(r"[a-zA-Z]+", password):
            substring = match.group()
            substring_start = match.start()

            # Check each possible substring against the dictionary
            for i in range(len(substring)):
                for j in range(i + min_word_length, len(substring) + 1):
                    candidate = substring[i:j].lower()
                    if candidate in english_words:
                        # Store with absolute position in original password
                        start_pos = substring_start + i
                        end_pos = substring_start + j
                        matches_with_positions.append((candidate, start_pos, end_pos))

        # Optionally filter out overlapping words, keeping longer ones
        if omit_nested:
            # Sort by length (longest first), then by start position
            matches_with_positions.sort(key=lambda x: (-len(x[0]), x[1]))

            filtered_matches: list[tuple[str, int, int]] = []
            covered_positions: set = set()

            for word, start, end in matches_with_positions:
                word_positions = set(range(start, end))
                # Only include this word if it doesn't overlap with already-covered positions
                if not word_positions & covered_positions:
                    filtered_matches.append((word, start, end))
                    covered_positions.update(word_positions)

            # Extract just the words
            matches = {word for word, _, _ in filtered_matches}
        else:
            # Extract unique words without position filtering
            matches = {word for word, _, _ in matches_with_positions}

        # Add matches to the analysis dictionary
        password_analysis[password] = list(matches)

        # Update the word count based on filtered matches
        for word in matches:
            word_count[word] = word_count.get(word, 0) + 1

    timing.stop_timer(TimingStats.DICTIONARY_ANALYSIS, item_count=len(passwords))
    return password_analysis, word_count


def bad_practices_analysis(
    passwords: list[str],
    custom_keywords: list[str] | None = None,
    account_entries: list[dict[str, str]] | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Analyze passwords for common bad practices and anti-patterns.

    Categories detected:
    1. Password-based passwords (including leet-speak variations)
    2. Season + Year patterns (Winter2023, Summer@2024, etc.)
    3. Keyboard walks (qwerty, asdf, 1234, etc.)
    4. Common weak bases (letmein, welcome, admin, etc.)
    5. Top common passwords (from rockyou-style patterns)
    6. Sequential/repeated characters (aaa, 111, abc, 123)
    7. Bible verses (john316, psalm23, etc.)
    8. Sports teams/mascots
    9. Passwords ending with # or ! (lazy special char)
    10. Leet-speak substitutions (p@ssw0rd, @dm1n, etc.)
    11. Custom keywords (company name, departments, team names, etc.)
    12. Username in password (including leet-speak variations)

    :param passwords: List of passwords to analyze
    :param custom_keywords: Optional list of custom keywords to detect (e.g., company name)
    :param account_entries: Optional list of dicts with 'account' and 'password' keys for username-in-password detection
    :return: Dictionary with category names as keys, containing counts and example passwords
    """
    from timing_stats import get_timing_stats, TimingStats

    timing = get_timing_stats()
    timing.start_timer(TimingStats.BAD_PRACTICES)

    results: dict[str, dict[str, Any]] = {
        "Password Variants": {"count": 0, "examples": {}},
        "Season + Year": {"count": 0, "examples": {}},
        "Keyboard Walks": {"count": 0, "examples": {}},
        "Common Weak Bases": {"count": 0, "examples": {}},
        "Top Common Passwords": {"count": 0, "examples": {}},
        "Sequential/Repeated": {"count": 0, "examples": {}},
        "Bible Verses": {"count": 0, "examples": {}},
        "Sports Teams/Mascots": {"count": 0, "examples": {}},
        "Ends with # or !": {"count": 0, "examples": {}},
        "Leet-Speak": {"count": 0, "examples": {}},
    }

    # Add Company Terms category only if keywords were provided
    if custom_keywords:
        results["Company Terms"] = {"count": 0, "examples": {}}

    # Add Username in Password category only if account_entries were provided
    if account_entries:
        results["Username in Password"] = {"count": 0, "examples": {}}

    # --- Pattern definitions ---

    # Password variants - must contain "password" or "passwd" (with common leet substitutions)
    # This is stricter - requires the full word, not just partial matches
    password_patterns = [
        # "password" with leet variations: p@ssw0rd, p4ssword, pa$$word, etc.
        r"p[a@4][s$5][s$5]w[o0][r][d]",
        # "passwd" with leet variations
        r"p[a@4][s$5][s$5]w[d]",
        # German "passwort" with leet variations
        r"p[a@4][s$5][s$5]w[o0]r[t+7]",
    ]
    password_regex = re.compile("|".join(password_patterns), re.IGNORECASE)

    # Season + Year patterns
    seasons = ["winter", "spring", "summer", "fall", "autumn"]
    season_year_regex = re.compile(
        r"(" + "|".join(seasons) + r")[^a-z]*\d{2,4}",
        re.IGNORECASE
    )

    # Keyboard walks (common patterns)
    keyboard_walks = [
        # Horizontal rows
        "qwerty", "qwert", "qwertyuiop", "asdf", "asdfgh", "asdfghjkl",
        "zxcv", "zxcvbn", "zxcvbnm",
        # Number sequences on keyboard
        "1234", "12345", "123456", "1234567", "12345678", "123456789",
        "1234567890", "0987654321", "987654321",
        # Diagonal patterns
        "qazwsx", "1qaz", "2wsx", "3edc", "1qaz2wsx",
        # Other common patterns
        "1q2w3e", "1q2w3e4r", "qwe123", "asd123",
    ]

    # Common weak password bases
    weak_bases = [
        "letmein", "welcome", "admin", "administrator", "root", "login",
        "master", "monkey", "dragon", "baseball", "iloveyou", "trustno1",
        "sunshine", "princess", "football", "shadow", "superman", "michael",
        "jennifer", "hunter", "batman", "andrew", "charlie", "thomas",
        "hockey", "ranger", "daniel", "starwars", "klaster", "george",
        "computer", "michelle", "jessica", "pepper", "patrick", "buster",
        "ginger", "joshua", "mustang", "corvette", "merlin", "access",
        "secret", "changeme", "test", "guest", "default", "temp",
    ]
    weak_bases_lower = {w.lower() for w in weak_bases}

    # Top common passwords (exact matches or with minor variations)
    top_common = [
        "password", "123456", "12345678", "qwerty", "abc123", "monkey",
        "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
        "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
        "123123", "654321", "superman", "qazwsx", "michael", "football",
        "password1", "password123", "welcome", "welcome1", "admin", "hello",
        "charlie", "donald", "password!", "p@ssword", "p@ssw0rd",
    ]
    top_common_lower = {p.lower() for p in top_common}

    # Sequential and repeated character patterns
    sequential_patterns = [
        r"(.)\1{2,}",  # Repeated chars: aaa, 111, etc.
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
        r"(123|234|345|456|567|678|789|890)",
        r"(321|432|543|654|765|876|987|098)",
    ]
    sequential_regex = re.compile("|".join(sequential_patterns), re.IGNORECASE)

    # Bible verse patterns - must have chapter:verse or chapter.verse format to avoid
    # false positives on common names like James, Daniel, Peter, John, Phil, etc.
    # Use word boundaries (?<![a-z]) to prevent matching substrings like "AMcor" or "Nicol"
    bible_patterns = [
        # Book names that are NOT common first names - can match with just chapter number
        # These are clearly biblical and unlikely to be used as personal names
        # Require word boundary at start to avoid matching "AMcor", "Nicol", etc.
        r"(?<![a-z])(psalm|psalms|proverbs|prov|isaiah|ezekiel|revelations?|revelation|corinthians|ephesians|colossians|thessalonians|hebrews|jeremiah|exodus|leviticus|deuteronomy|ecclesiastes|lamentations|galatians)[^a-z]*\d+[:\.,]?\d*",
        # Book names that ARE common first names - REQUIRE chapter:verse format (colon, period, or comma separator)
        # This prevents "James1", "Daniel2023", "John2024", "Genesis123" from matching
        r"(?<![a-z])(john|luke|mark|daniel|james|peter|timothy|titus|acts|philippians|joseph|matthew|romans|genesis)[^a-z]*\d+[:\.,]\d+",
        # Well-known specific verse references (these are unambiguous even without separator)
        # Require word boundary to prevent false matches
        r"(?<![a-z])john3[:\.]?16",
        r"(?<![a-z])psalm23",
        r"(?<![a-z])psalm91",
        r"(?<![a-z])phil[^a-z]*4[:\.,]13",  # Philippians 4:13
        r"(?<![a-z])phil[^a-z]*4[:\.,]7",   # Philippians 4:7
        r"(?<![a-z])jer29[:\.]?11",
        r"(?<![a-z])rom8[:\.]?28",
        r"(?<![a-z])john14[:\.]?6",
        r"(?<![a-z])matt6[:\.]?33",
        r"(?<![a-z])prov3[:\.]?5",
    ]
    bible_regex = re.compile("|".join(bible_patterns), re.IGNORECASE)

    # Sports teams and mascots
    sports_teams = [
        # NFL teams
        "patriots", "cowboys", "eagles", "steelers", "packers", "bears",
        "broncos", "raiders", "chiefs", "seahawks", "49ers", "niners",
        "ravens", "saints", "falcons", "panthers", "dolphins", "jets",
        "giants", "redskins", "commanders", "vikings", "lions", "bengals",
        "browns", "colts", "texans", "titans", "jaguars", "chargers",
        "cardinals", "buccaneers", "bucs", "rams",
        # MLB teams
        "yankees", "redsox", "dodgers", "cubs", "mets", "astros", "braves",
        "phillies", "padres", "mariners", "angels", "athletics", "orioles",
        "bluejays", "royals", "tigers", "whitesox", "twins", "indians",
        "guardians", "brewers", "reds", "pirates", "rockies", "diamondbacks",
        "marlins", "nationals", "rangers",
        # NBA teams
        "lakers", "celtics", "bulls", "warriors", "heat", "knicks", "nets",
        "sixers", "76ers", "spurs", "mavs", "mavericks", "rockets", "suns",
        "clippers", "nuggets", "jazz", "blazers", "thunder", "timberwolves",
        "pelicans", "grizzlies", "hawks", "hornets", "wizards", "pistons",
        "pacers", "cavaliers", "cavs", "magic", "raptors", "bucks", "kings",
        # NHL teams
        "bruins", "blackhawks", "penguins", "redwings", "flyers", "oilers",
        "canadiens", "leafs", "canucks", "flames", "avalanche", "blues",
        "predators", "lightning", "hurricanes", "senators", "sabres",
        "islanders", "devils", "wild", "ducks", "sharks", "coyotes", "kraken",
        "golden knights", "knights",
        # College mascots and teams
        "wildcats", "bulldogs", "tigers", "lions", "bears", "wolverines",
        "buckeyes", "gators", "seminoles", "hurricanes", "crimson", "tide",
        "longhorns", "aggies", "sooners", "jayhawks", "spartans", "badgers",
        "hawkeyes", "huskies", "trojans", "bruins", "ducks", "beavers",
        "cougars", "utes", "aztecs", "rebels", "volunteers", "gamecocks",
        "yellowjackets", "hokies", "cavaliers", "tarheels",
    ]
    sports_lower = {s.lower() for s in sports_teams}

    # Load English dictionary for leet-speak detection (words of 4+ chars)
    english_words = {word for word in _get_english_words() if len(word) >= 4}

    # Leet-speak substitution patterns (detect passwords using common substitutions)
    leet_map = {
        "@": "a", "4": "a", "^": "a",
        "8": "b",
        "(": "c", "{": "c", "<": "c",
        "3": "e",
        "6": "g", "9": "g",
        "#": "h",
        "1": "i", "!": "i", "|": "i",
        "7": "l",
        "0": "o",
        "$": "s", "5": "s",
        "+": "t", "7": "t",
        "2": "z",
    }

    def deleet(text: str) -> str:
        """Convert leet-speak to regular text."""
        result = []
        for char in text.lower():
            result.append(leet_map.get(char, char))
        return "".join(result)

    def has_leet_speak(password: str) -> bool:
        """Check if password contains leet-speak substitutions WITHIN the word.

        Trailing/leading numbers and special chars don't count as leet-speak.
        True leet-speak has substitutions embedded in the alphabetic portion.
        """
        # Strip common prefix/suffix patterns (numbers, special chars)
        stripped = password.strip("0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?`~")
        if not stripped:
            return False

        # Check if the stripped (core) portion contains leet characters
        leet_chars = set(leet_map.keys())
        return any(c in leet_chars for c in stripped)

    def extract_username_base(username: str) -> str:
        """Extract the base username for matching (strip domain prefix and _history suffix)."""
        # Remove domain prefix (e.g., "DOMAIN\\jsmith" -> "jsmith")
        if "\\" in username:
            username = username.split("\\")[-1]
        # Remove _history suffix (e.g., "jsmith_history0" -> "jsmith")
        if "_history" in username.lower():
            username = re.sub(r"_history\d*$", "", username, flags=re.IGNORECASE)
        return username.lower()

    def username_in_password(username: str, password: str) -> bool:
        """Check if username (or leet variations) appears in password.

        Detects:
        - Direct username matches (case-insensitive)
        - Leet-speak variations of username in password
        - Password containing deleeted version of username
        - Username variations (first/last name parts if separated by dots/underscores)
        - Meaningful substrings from longer usernames (e.g., "admin" from "administrator")
        """
        if not username or not password:
            return False

        username_base = extract_username_base(username)
        # Require at least 4 chars to avoid false positives on very short names
        if len(username_base) < 4:
            return False

        pw_lower = password.lower()
        pw_deleet = deleet(password)

        # Check 1: Direct username match in password
        if username_base in pw_lower:
            return True

        # Check 2: Deleeted password contains username
        if username_base in pw_deleet:
            return True

        # Check 3: Deleeted username found in password
        username_deleet = deleet(username_base)
        if username_deleet in pw_lower:
            return True

        # Check 4: Both deleeted
        if username_deleet in pw_deleet:
            return True

        # Check 5: Handle usernames with separators (e.g., "john.smith", "john_smith")
        # Check each part independently
        parts = re.split(r"[._\-]", username_base)
        for part in parts:
            if len(part) >= 4:  # Only check meaningful parts (4+ chars)
                if part in pw_lower or part in pw_deleet:
                    return True
                part_deleet = deleet(part)
                if part_deleet in pw_lower or part_deleet in pw_deleet:
                    return True

        # Check 6: For longer usernames, check meaningful substrings
        # e.g., "administrator" -> check if "admin" appears
        if len(username_base) >= 6:
            # Check all substrings of length 4-8 from start of username
            for sub_len in range(4, min(9, len(username_base))):
                substring = username_base[:sub_len]
                substring_deleet = deleet(substring)
                if substring in pw_lower or substring in pw_deleet:
                    return True
                if substring_deleet in pw_lower or substring_deleet in pw_deleet:
                    return True

        # Check 7: First name or initials + last name patterns
        # e.g., "jsmith" -> check "smith" and "j"+"smith" variations
        if len(username_base) >= 5:
            # Check if last N chars (potential last name) appear in password
            for name_len in range(4, min(len(username_base), 8)):
                potential_name = username_base[-name_len:]
                if potential_name in pw_lower or potential_name in pw_deleet:
                    # Only flag if there's also some connection to initial
                    first_char = username_base[0]
                    if first_char in pw_lower[:3]:  # Initial near start
                        return True

        return False

    # Build password-to-username mapping if account_entries provided
    # Maps password -> list of accounts (same password can be used by multiple users)
    password_to_usernames: dict[str, list[str]] = {}
    if account_entries:
        for entry in account_entries:
            pw = entry.get("password", "")
            acct = entry.get("account", "")
            if pw and acct:
                if pw not in password_to_usernames:
                    password_to_usernames[pw] = []
                password_to_usernames[pw].append(acct)

    # Process each password
    for password in passwords:
        if not password:  # Skip empty passwords
            continue

        pw_lower = password.lower()
        matched_categories: set = set()

        # 1. Check for password variants (password, passwd, passwort)
        if password_regex.search(password):
            results["Password Variants"]["count"] += 1
            results["Password Variants"]["examples"][password] = results["Password Variants"]["examples"].get(password, 0) + 1
            matched_categories.add("Password Variants")

        # 2. Check for season + year patterns
        if season_year_regex.search(password):
            results["Season + Year"]["count"] += 1
            results["Season + Year"]["examples"][password] = results["Season + Year"]["examples"].get(password, 0) + 1
            matched_categories.add("Season + Year")

        # 3. Check for keyboard walks
        for walk in keyboard_walks:
            if walk in pw_lower:
                results["Keyboard Walks"]["count"] += 1
                results["Keyboard Walks"]["examples"][password] = results["Keyboard Walks"]["examples"].get(password, 0) + 1
                matched_categories.add("Keyboard Walks")
                break

        # 4. Check for common weak bases
        for base in weak_bases_lower:
            if base in pw_lower and len(base) >= 4:
                results["Common Weak Bases"]["count"] += 1
                results["Common Weak Bases"]["examples"][password] = results["Common Weak Bases"]["examples"].get(password, 0) + 1
                matched_categories.add("Common Weak Bases")
                break

        # 5. Check for top common passwords (exact or with simple suffix)
        # Check both the raw password and deleet version
        pw_deleet = deleet(password)
        base_pw = re.sub(r"[^a-z0-9]", "", pw_lower)  # Remove special chars
        base_deleet = re.sub(r"[^a-z0-9]", "", pw_deleet)

        if (pw_lower in top_common_lower or
            base_pw in top_common_lower or
            base_deleet in top_common_lower):
            results["Top Common Passwords"]["count"] += 1
            results["Top Common Passwords"]["examples"][password] = results["Top Common Passwords"]["examples"].get(password, 0) + 1
            matched_categories.add("Top Common Passwords")

        # 6. Check for sequential/repeated patterns
        if sequential_regex.search(password):
            results["Sequential/Repeated"]["count"] += 1
            results["Sequential/Repeated"]["examples"][password] = results["Sequential/Repeated"]["examples"].get(password, 0) + 1
            matched_categories.add("Sequential/Repeated")

        # 7. Check for Bible verse patterns
        if bible_regex.search(password):
            results["Bible Verses"]["count"] += 1
            results["Bible Verses"]["examples"][password] = results["Bible Verses"]["examples"].get(password, 0) + 1
            matched_categories.add("Bible Verses")

        # 8. Check for sports teams/mascots
        # Use word boundary check to avoid matching substrings within other words
        # e.g., "suns" shouldn't match "sunshine"
        for team in sports_lower:
            if len(team) >= 4:
                # Check if team appears as a standalone word or at word boundaries
                # Allow team at start/end of password or surrounded by non-alpha chars
                pattern = r'(?<![a-z])' + re.escape(team) + r'(?![a-z])'
                if re.search(pattern, pw_lower):
                    results["Sports Teams/Mascots"]["count"] += 1
                    results["Sports Teams/Mascots"]["examples"][password] = results["Sports Teams/Mascots"]["examples"].get(password, 0) + 1
                    matched_categories.add("Sports Teams/Mascots")
                    break

        # 9. Check for passwords ending with # or ! (lazy special char)
        if password.endswith("#") or password.endswith("!"):
            results["Ends with # or !"]["count"] += 1
            results["Ends with # or !"]["examples"][password] = results["Ends with # or !"]["examples"].get(password, 0) + 1
            matched_categories.add("Ends with # or !")

        # 10. Check for leet-speak usage - find dictionary words with leet substitutions
        if has_leet_speak(password):
            # Try multiple strategies to find English words hidden in leet-speak
            found_leet = False

            # Strategy 1: Check if full deleet password is a dictionary word
            if pw_deleet in english_words:
                found_leet = True

            # Strategy 2: Strip trailing numbers/specials and check
            if not found_leet:
                stripped_deleet = deleet(pw_lower.rstrip("0123456789!@#$%^&*"))
                if stripped_deleet in english_words:
                    found_leet = True

            # Strategy 3: Strip leading/trailing numbers/specials and check
            if not found_leet:
                core = pw_lower.strip("0123456789!@#$%^&*")
                if core:
                    core_deleet = deleet(core)
                    if core_deleet in english_words:
                        found_leet = True

            # Strategy 4: Check base_deleet (alphanumeric only, deleeted)
            if not found_leet:
                if base_deleet in english_words:
                    found_leet = True

            # Strategy 5: Also check against weak bases and common passwords
            if not found_leet:
                if (pw_deleet in weak_bases_lower or
                    pw_deleet in top_common_lower):
                    found_leet = True

            if found_leet:
                results["Leet-Speak"]["count"] += 1
                results["Leet-Speak"]["examples"][password] = results["Leet-Speak"]["examples"].get(password, 0) + 1

        # 11. Check for custom keywords (company name, departments, etc.)
        if custom_keywords:
            for keyword in custom_keywords:
                keyword_lower = keyword.lower()
                if len(keyword_lower) >= 3 and keyword_lower in pw_lower:
                    results["Company Terms"]["count"] += 1
                    # Store password with account info if available: {password: {"count": N, "accounts": [...]}}
                    if password_to_usernames and password in password_to_usernames:
                        if password not in results["Company Terms"]["examples"]:
                            results["Company Terms"]["examples"][password] = {"count": 0, "accounts": []}
                        results["Company Terms"]["examples"][password]["count"] += 1
                        # Add all accounts that use this password (if not already added)
                        for acct in password_to_usernames[password]:
                            if acct not in results["Company Terms"]["examples"][password]["accounts"]:
                                results["Company Terms"]["examples"][password]["accounts"].append(acct)
                    else:
                        # No account info - use simple count format
                        results["Company Terms"]["examples"][password] = results["Company Terms"]["examples"].get(password, 0) + 1
                    break

        # 12. Check for username in password (with leet-speak variations)
        if password_to_usernames and password in password_to_usernames:
            # Check each account that uses this password
            for username in password_to_usernames[password]:
                if username_in_password(username, password):
                    results["Username in Password"]["count"] += 1
                    # Store password with account info: {password: {"count": N, "accounts": [...]}}
                    if password not in results["Username in Password"]["examples"]:
                        results["Username in Password"]["examples"][password] = {"count": 0, "accounts": []}
                    results["Username in Password"]["examples"][password]["count"] += 1
                    results["Username in Password"]["examples"][password]["accounts"].append(username)

    timing.stop_timer(TimingStats.BAD_PRACTICES, item_count=len(passwords))
    return results
