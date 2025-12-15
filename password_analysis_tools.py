import string
from collections import defaultdict, Counter
import re
from english_words import get_english_words_set
from typing import List, Dict, Tuple, Union, Any, TypedDict, Optional, Set

# Module-level cache for the English dictionary (loaded once on first use)
_english_words_cache: Optional[Set[str]] = None


def _get_english_words() -> Set[str]:
    """
    Get the cached English words set, loading it on first call.
    Uses the web2 dictionary from english-words package (~234K words).
    """
    global _english_words_cache
    if _english_words_cache is None:
        _english_words_cache = get_english_words_set(['web2'], lower=True)
    return _english_words_cache


def _load_exclusions(file_path: str = "dictionary_exclusions.conf") -> Set[str]:
    """
    Load exclusions from a configuration file.
    Supports comments (lines starting with #) and empty lines.
    """
    exclusions: Set[str] = set()
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
def check_lm(pwdump_file: str) -> List[str]:
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
def lm_count(account_data: Dict[str, Dict[str, Union[str, int, None]]]) -> int:
    count = sum(
        1
        for account in account_data.values()
        if account["lm_hash"] != "aad3b435b51404eeaad3b435b51404ee"
    )
    return count


# Function to get accounts with valid (non-blank) LANMan hashes (account_data based)
def get_lm_accounts(account_data: Dict[str, Dict[str, Union[str, int, None]]]) -> List[str]:
    """
    Returns a sorted list of account names that have a valid (non-blank) LM hash.
    LM hashes are weaker than NTLM and should be disabled in modern environments.
    """
    lm_accounts = [
        account_name
        for account_name, account in account_data.items()
        if account.get("lm_hash") and account["lm_hash"] != "aad3b435b51404eeaad3b435b51404ee"
    ]
    return sorted(lm_accounts)


# Function to check for password reuse
def check_pw_reuse(pwdump_file: str) -> List[Tuple[str, int, List[str]]]:
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


# List accounts with blank passwords (only if the ignore blanks option wasn't checked)
def check_blank(
    accounts_info: Dict[str, Dict[str, Union[str, int, None]]],
    ignore_blank_passwords: bool = False,
) -> Tuple[List[str], List[str]]:
    """
    Identifies accounts with blank passwords.
    Includes accounts with either an empty string or "{Blank Password}" as the password.
    """
    blank_ntlm_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

    # Identify blank accounts based on NTLM hash or placeholder value
    all_blank_accounts = [
        account_name
        for account_name, account_data in accounts_info.items()
        if account_data.get("ntlm_hash") == blank_ntlm_hash
        or account_data.get("cracked_pw") in ("", "{Blank Password}")
    ]

    blank_accounts_for_reporting = [] if ignore_blank_passwords else all_blank_accounts

    return all_blank_accounts, blank_accounts_for_reporting


# List accounts failing password complexity
def get_non_compliant_accounts(
    account_data: Dict[str, Dict[str, Union[str, int, None]]], num_categories_req: int
) -> Dict[str, Dict[str, Union[str, int]]]:
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

    non_compliant_accounts: Dict[str, Dict[str, Union[str, int]]] = {}
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
    account_data: Dict[str, Dict[str, Union[str, int, None]]],
    min_len: int = 14,
    complexity: int = 3,
    ignore_blank_passwords: bool = False,
) -> Dict[str, Any]:
    """
    Calculate password cracking statistics.

    :param account_data: A dictionary where each key is an account name, and the value is another dictionary with account details.
    :param min_len: Minimum password length for compliance.
    :param complexity: Minimum number of complexity categories for compliance.
    :param ignore_blank_passwords: Whether to exclude blank passwords from analysis.
    :return: A dictionary containing various password cracking statistics and reports.
    """
    print(
        f"crack_stats function called with ignore_blank_passwords={ignore_blank_passwords}"
    )
    # Get accounts with blank passwords and create a 2nd list of acccounts based on whether the ignore_blank_passwors option was enabled.
    all_blank_accounts, blank_accounts_for_reporting = check_blank(
        account_data, ignore_blank_passwords
    )

    # Count of cracked accounts based on whether the ignore blank password option was checked
    # Count cracked accounts
    cracked_accounts = sum(
        1
        for account in account_data.values()
        if isinstance(account.get("cracked_pw"), str)
        and account.get("cracked_pw") != ""
    )

    # Include blank passwords if they are not ignored
    if not ignore_blank_passwords:
        cracked_accounts += len(all_blank_accounts)

    # Report accounts with a blank password
    pw_fails_blank = all_blank_accounts  # Use the full list regardless of ignore option

    # Unique NTLM hashes
    unique_ntlm_hashes = {
        account.get("ntlm_hash")
        for account in account_data.values()
        if isinstance(account.get("ntlm_hash"), str)
    }
    total_ntlm_hashes = len(unique_ntlm_hashes)

    # Cracked NTLM hashes
    cracked_ntlm_hashes = {
        account["ntlm_hash"]
        for account in account_data.values()
        if isinstance(account.get("cracked_pw"), str)
        and account.get("cracked_pw") != ""
        and account["ntlm_hash"] != "31d6cfe0d16ae931b73c59d7e0c089c0"
    }

    # Include blank NTLM hash only if it exists in the dataset and not ignored
    if not ignore_blank_passwords and any(
        account["ntlm_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
        for account in account_data.values()
    ):
        cracked_ntlm_hashes.add("31d6cfe0d16ae931b73c59d7e0c089c0")

    cracked_ntlm_hashes_count = len(cracked_ntlm_hashes)
    uncracked_ntlm_hashes = total_ntlm_hashes - cracked_ntlm_hashes_count

    # Basic statistic counters
    total_accounts = len(account_data)
    total_lm_hashes = lm_count(account_data)  # Ensure lm_count accepts the updated type

    # Calculations for cracked vs uncracked accounts and hashes
    uncracked_accounts = total_accounts - cracked_accounts
    uncracked_ntlm_hashes = total_ntlm_hashes - cracked_ntlm_hashes_count

    cracked_hash_percent = (
        (str(round((cracked_ntlm_hashes_count / total_ntlm_hashes * 100), 1)) + "%")
        if total_ntlm_hashes > 0
        else 0
    )
    cracked_account_pw_percent = (
        (str(round((cracked_accounts / total_accounts * 100), 1)) + "%")
        if total_accounts > 0
        else 0
    )

    # Password length distribution table w/ignore blank feature support
    cracked_pw_lengths = [
        0 if account_name in blank_accounts_for_reporting else len(pw)
        for account_name, pw in (
            (account_name, account.get("cracked_pw"))
            for account_name, account in account_data.items()
        )
        if isinstance(pw, str)  # Exclude uncracked passwords and invalid types
    ]

    # Exclude 0-length passwords if ignore_blank_passwords is True
    if ignore_blank_passwords:
        cracked_pw_lengths = [length for length in cracked_pw_lengths if length > 0]

    # Shortest, longest, and average password length calculations
    shortest_pw_len = min(cracked_pw_lengths) if cracked_pw_lengths else None
    longest_pw_len = max(cracked_pw_lengths) if cracked_pw_lengths else None
    avg_pw_len = (
        (str(round((sum(cracked_pw_lengths) / len(cracked_pw_lengths)), 2)))
        if cracked_pw_lengths
        else None
    )

    # Create the length distribution
    length_distribution = {length: 0 for length in range(0, (longest_pw_len or 0) + 1)}

    # Populate the length distribution
    for length in cracked_pw_lengths:
        length_distribution[length] += 1

    # Filter out 0 if ignore_blank_passwords is True
    if ignore_blank_passwords:
        length_distribution = {
            length: count for length, count in length_distribution.items() if length > 0
        }

    # Report accounts with cracked passwords that fail the minimum length requirement
    pw_fails_min_length = {
        account_name: {
            "cracked_pw": account["cracked_pw"],
            "pw_length": (
                len(account["cracked_pw"])
                if isinstance(account["cracked_pw"], str)
                else 0
            ),
        }
        for account_name, account in account_data.items()
        if account.get("cracked_pw") is not None
        and (not ignore_blank_passwords or account["cracked_pw"] != "")
        and isinstance(account["cracked_pw"], str)
        and len(account["cracked_pw"]) < min_len
    }

    # Report accounts with cracked passwords that fail the complexity requirement
    pw_fails_complexity = get_non_compliant_accounts(account_data, complexity)

    # Exclude blank accounts if ignore_blank_passwords is True
    if ignore_blank_passwords:
        pw_fails_complexity = {
            account: details
            for account, details in pw_fails_complexity.items()
            if account not in blank_accounts_for_reporting
            and details["cracked_pw"] != ""
        }

    # Report accounts that fail max age requirement
    pw_fails_max_age = {
        "Required Source Data Not Provided": {"pw_changed": "12/23/2024", "pw_age": 93},
        "Need Dates for Password Last Changed": {
            "pw_changed": "12/24/2024",
            "pw_age": 92,
        },
        "Feature Coming Soon": {"pw_changed": "12/25/2025", "pw_age": 91},
    }

    # Cracked passwords by account donut chart
    pw_account_pie = {"Cracked": cracked_accounts, "Uncracked": uncracked_accounts}

    # Cracked passwords by NTLM hashes donut chart
    pw_hash_pie = {
        "Cracked": cracked_ntlm_hashes_count,
        "Uncracked": uncracked_ntlm_hashes,
    }

    # Identify Top X Reused Passwords
    cracked_passwords = [
        account.get("cracked_pw")
        for account in account_data.values()
        if isinstance(account.get("cracked_pw"), str)
    ]

    password_counts = Counter(cracked_passwords)

    # Replace blank passwords with "{blank}" and handle ignore_blank_passwords
    top_reused_passwords = {
        "{blank}" if pw == "" else pw: count
        for pw, count in password_counts.items()
        if count >= 2 and not (ignore_blank_passwords and pw == "")
    }

    # Get accounts with valid LM hashes
    pw_lm_hashes = get_lm_accounts(account_data)

    # Return the stats in a dictionary
    cracking_stats = {
        "Cracked Accounts: ": cracked_accounts,
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
        "pw_lm_hashes": pw_lm_hashes,
    }

    return report


def substring_analysis(
    passwords: List[str],
    min_length: int = 4,
    max_length: int = 8,
    frequency_threshold: int = 2,
    normalize: bool = False,
    suppress_nested: bool = True,
) -> List[Dict[str, Any]]:
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
    substring_passwords: Dict[str, Dict[str, int]] = {}

    for password in passwords:
        # Normalize for matching if requested, but store original password
        match_password = password.lower() if normalize else password

        # Track substrings found in this password to count unique passwords
        found_in_this_password: Dict[str, int] = {}

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
        non_nested_results: Dict[str, Dict[str, int]] = {}

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


def dictionary_analysis(
    passwords: List[str],
    min_word_length: int = 4,
    omit_nested: bool = False,
) -> Tuple[Dict[str, List[str]], Dict[str, int]]:
    """
    Analyze a list of passwords to identify dictionary words.

    :param passwords: List of passwords to analyze.
    :param min_word_length: Minimum length of dictionary words to consider.
    :param omit_nested: Whether to omit nested words within longer words.
    :return: Tuple of two dictionaries:
             1. Password-to-matched-words mapping.
             2. Word-to-occurrence-count mapping.
    """

    # Use cached dictionary for better performance
    all_english_words = _get_english_words()
    english_words = {word for word in all_english_words if len(word) >= min_word_length}

    # Load and apply exclusions
    exclusions = _load_exclusions()
    english_words -= exclusions

    password_analysis: Dict[str, List[str]] = {}  # Store each password with its dictionary words
    word_count: Dict[str, int] = {}  # Store each English dictionary word with its count

    for password in passwords:
        # Extract alphabetic substrings from the password with their positions
        # Each match contains: (word, start_in_password, end_in_password)
        matches_with_positions: List[Tuple[str, int, int]] = []

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

            filtered_matches: List[Tuple[str, int, int]] = []
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

    return password_analysis, word_count


def bad_practices_analysis(
    passwords: List[str],
    custom_keywords: List[str] = None,
) -> Dict[str, Dict[str, Any]]:
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

    :param passwords: List of passwords to analyze
    :param custom_keywords: Optional list of custom keywords to detect (e.g., company name)
    :return: Dictionary with category names as keys, containing counts and example passwords
    """

    results: Dict[str, Dict[str, Any]] = {
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

    # Bible verse patterns
    bible_patterns = [
        # Book + chapter:verse or chapter.verse patterns
        r"(john|psalm|psalms|genesis|matthew|mark|luke|romans|proverbs|isaiah|jeremiah|ezekiel|daniel|acts|james|peter|revelations?|revelation|rev|gen|matt|rom|cor|corinthians|ephesians|eph|philippians|phil|colossians|col|thessalonians|thess|timothy|tim|titus|hebrews|heb)[^a-z]*\d+[:\.]?\d*",
        # Common verse references
        r"john3[:\.]?16",
        r"psalm23",
        r"psalm91",
        r"phil4[:\.]?13",
        r"jer29[:\.]?11",
        r"rom8[:\.]?28",
        r"john14[:\.]?6",
        r"matt6[:\.]?33",
        r"prov3[:\.]?5",
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
                    results["Company Terms"]["examples"][password] = results["Company Terms"]["examples"].get(password, 0) + 1
                    break

    return results
