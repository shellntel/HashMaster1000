import string
from collections import defaultdict, Counter
import re
import nltk
from nltk.corpus import words
from typing import List, Dict, Tuple, Union, Any, TypedDict


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
    }

    return report


def substring_analysis(
    passwords: List[str],
    min_length: int = 4,
    max_length: int = 8,
    frequency_threshold: int = 2,
    normalize: bool = False,
    suppress_nested: bool = True,
) -> List[Dict[str, int | str]]:
    """
    Analyze substrings within a range of lengths across passwords and find common patterns,
    with an option to suppress nested substrings in longer substrings.

    Parameters:
    - passwords (list of str): List of cracked passwords.
    - min_length (int): Minimum length for substrings to analyze.
    - max_length (int): Maximum length for substrings to analyze.
    - frequency_threshold (int): Minimum occurrence for a substring to be considered significant.
    - normalize (bool): Whether to convert passwords to lowercase for case-insensitive analysis.
    - suppress_nested (bool): Whether to suppress shorter substrings that exist within longer substrings.

    Returns:
    - list of dict: A concise list of substrings with `substring` and `count`.
    """
    substrings = []

    # Normalize passwords if requested
    for password in passwords:
        if normalize:
            password = password.lower()

        # Generate substrings using a sliding window
        for length in range(min_length, max_length + 1):
            for i in range(len(password) - length + 1):
                substring = password[i : i + length]
                substrings.append(substring)

    # Count frequencies of each substring
    substring_counts = Counter(substrings)

    # Filter substrings by frequency threshold
    filtered_substrings = {
        substring: count
        for substring, count in substring_counts.items()
        if count >= frequency_threshold
    }

    # Option to suppress nested substrings
    if suppress_nested:
        non_nested_results: Dict[str, int] = {}
        seen_substrings: set[str] = (
            set()
        )  # Explicitly type-annotated as a set of strings

        # Sort substrings by length (longest first) and frequency (highest first)
        sorted_substrings = sorted(
            filtered_substrings.items(), key=lambda item: (-len(item[0]), -item[1])
        )

        for substr, count in sorted_substrings:
            # Check if the substring is already contained within any longer substring
            if not any(
                longer_substr
                for longer_substr in seen_substrings
                if substr in longer_substr and substr != longer_substr
            ):
                non_nested_results[substr] = count
                seen_substrings.add(substr)

        # Return concise output
        return [
            {"substring": substr, "count": count}
            for substr, count in non_nested_results.items()
        ]

    # Return all substrings (concise format)
    return [
        {"substring": substr, "count": count}
        for substr, count in filtered_substrings.items()
    ]


def ensure_nltk_words_downloaded() -> None:
    # Ensure the NLTK English word corpus is available
    nltk.download("words", quiet=True)


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

    # Ensure the corpus is downloaded
    ensure_nltk_words_downloaded()

    # Load English words into a set for fast lookup
    english_words = {
        word.lower() for word in words.words() if len(word) >= min_word_length
    }

    # Exclude known non-English words (built-in list here)
    exclusions = set()  # Add exclusions to dictionary_exclusions.conf

    # File path to the exclusions file
    file_path = "dictionary_exclusions.conf"

    # Try to read and add entries from the file
    try:
        with open(file_path, "r") as file:
            # Read each line, strip whitespace, and add it to the set
            file_exclusions = {
                line.strip() for line in file if line.strip()
            }  # Exclude empty lines
            exclusions.update(file_exclusions)
        print(f"Updated exclusions: {exclusions}")
    except FileNotFoundError:
        print(f"File '{file_path}' not found. Using default exclusions.")
    except Exception as e:
        print(f"An error occurred while reading '{file_path}': {e}")

    english_words -= exclusions

    password_analysis: Dict[str, List[str]] = (
        {}
    )  # Store each password with its dictionary words
    word_count: Dict[str, int] = {}  # Store each English dictionary word with its count

    for password in passwords:
        # Extract alphabetic substrings from the password
        substrings = re.findall(r"[a-zA-Z]+", password)
        matches = set()

        # Check each substring against the dictionary
        for substring in substrings:
            for i in range(len(substring)):
                for j in range(i + min_word_length, len(substring) + 1):
                    candidate = substring[i:j].lower()
                    if candidate in english_words:
                        matches.add(candidate)

        # Optionally filter out nested words
        if omit_nested:
            matches = {
                word
                for word in matches
                if not any(
                    word in other_word and word != other_word for other_word in matches
                )
            }

        # Add matches to the analysis dictionary
        password_analysis[password] = list(matches)

        # Update the word count based on filtered matches
        for word in matches:
            word_count[word] = word_count.get(word, 0) + 1

    return password_analysis, word_count
