#!/usr/bin/env python3
"""
Generate Historical Test Sessions for Trend Analysis

Creates 4 sessions with progressively improving metrics for testing the
historical trend analysis feature:
- 1 year ago: Worst (72% crack rate, many violations)
- 9 months ago: Slight improvement (58% crack rate)
- 6 months ago: More improvement (42% crack rate)
- 3 months ago: Best/current (28% crack rate)

Usage:
    python scripts/generate_historical_test_data.py

This script:
1. Expands the example ADD JSON to ~250 accounts
2. Creates 4 historical session directories with all JSON analysis files
3. Each session shows progressively improving password security
"""

import hashlib
import json
import os
import random
import re
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple, Set

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Improvement profiles for each historical period
IMPROVEMENT_PROFILES = {
    "year_ago": {
        "crack_rate": 0.72,
        "avg_password_length": 7.2,
        "min_length_violations_rate": 0.45,
        "complexity_violations_rate": 0.65,
        "blank_password_rate": 0.04,
        "password_reuse_rate": 0.35,
        "bad_practices_multiplier": 2.5,
    },
    "9_months": {
        "crack_rate": 0.58,
        "avg_password_length": 8.1,
        "min_length_violations_rate": 0.32,
        "complexity_violations_rate": 0.50,
        "blank_password_rate": 0.03,
        "password_reuse_rate": 0.25,
        "bad_practices_multiplier": 1.8,
    },
    "6_months": {
        "crack_rate": 0.42,
        "avg_password_length": 9.5,
        "min_length_violations_rate": 0.18,
        "complexity_violations_rate": 0.35,
        "blank_password_rate": 0.015,
        "password_reuse_rate": 0.15,
        "bad_practices_multiplier": 1.2,
    },
    "3_months": {
        "crack_rate": 0.28,
        "avg_password_length": 11.2,
        "min_length_violations_rate": 0.08,
        "complexity_violations_rate": 0.15,
        "blank_password_rate": 0.004,
        "password_reuse_rate": 0.08,
        "bad_practices_multiplier": 0.6,
    },
}

# Test company name
COMPANY_NAME = "DemoCorp"

# Departments for generating users
DEPARTMENTS = [
    ("IT", 35),
    ("Finance", 30),
    ("HR", 20),
    ("Marketing", 25),
    ("Sales", 40),
    ("Engineering", 45),
    ("Legal", 15),
    ("Operations", 25),
    ("Executive", 10),
    ("Support", 20),
]

# First and last names for generating users
FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kenneth", "Dorothy", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
    "Edward", "Deborah", "Ronald", "Stephanie", "Timothy", "Rebecca", "Jason", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen", "Gary", "Amy",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill",
    "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell",
    "Mitchell", "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz",
]

# Passwords to exclude (real client data)
EXCLUDED_PASSWORDS = {
    "Brookfield53005$",
    "Doctor Manhattan!!",
    "Everyonelovesracing2",
    "Greenbaypackers0202!!",
    "SCtemp123!@#",
}

# Real password patterns categorized for bad practices
SEASON_YEAR_PASSWORDS = [
    "Spring2020*", "Spring2021", "Spring2022", "Spring2022!", "Spring2023",
    "Spring2023!!", "Spring2023#", "Spring2024", "Springtime01", "Springtime1",
    "Springtime22", "Summer2020", "Summer2020!", "Summer2020$", "Summer2021",
    "Summer2021!", "Summer2022", "Summer2022!", "Summer2022!!", "Summer2022#",
    "Summer2022$", "Summer2022*", "Summer2022+", "Summer2022@", "Summer2022?",
    "Summer2023", "Summer2023!", "Summer2024", "Summer2025", "Summertime2022",
    "Summertime2023", "Fall2018!!", "Fall2022", "Fall2022!", "Fall2022!!",
    "Fall2022!@", "Fall2022**", "Fall2022+1", "Falltime22", "Falltime22!",
    "Falltime123", "Falltime2022", "Winter2018", "Winter2018!", "Winter2019",
    "Winter2021", "Winter2021$", "Winter2022", "Winter2022#", "Winter2022%",
    "Winter2022*", "Winter2023", "Winter2026", "Winteriscoming!",
]

KEYBOARD_PATTERN_PASSWORDS = [
    "qwerty123", "asdf1234!", "zxcv9876", "1234qwer!", "qazwsx123",
]

COMMON_WORD_PASSWORDS = [
    "password", "password1", "Password1", "Password1!", "Password1*",
    "Password1.", "Password02", "Password06", "Password10!", "Password#1",
    "Password.4!", "Password!227", "password#1", "P@ssw0rd", "P@ssw0rd!@#$",
    "P@ssw10rd!@#$", "P@ssw0rd@3", "P@55w0rd", "P@55w.rd", "1password!",
    "Changepassword", "Changepassword2022$", "letmein123!", "welcome1!",
]

SEQUENTIAL_PASSWORDS = [
    "123456.a", "Password1234!", "abc123456!", "111222333!",
]

USERNAME_PASSWORDS = [
    # These will be generated based on actual usernames
]

DICTIONARY_WORD_PASSWORDS = [
    "Princess1", "Sunshine123!", "Dragon2022!", "Monkey123!",
    "Shadow2023", "Master1234", "Freedom02", "Harmony1088",
]

DATE_PATTERN_PASSWORDS = [
    "January2022!", "March2023!", "October27!", "Birthday1990!",
]

SPORTS_TEAM_PASSWORDS = [
    "Packers4ever1!", "Cowboys2023!", "Lakers123!", "Yankees2022!",
]

POP_CULTURE_PASSWORDS = [
    "StarWars123!", "GameOfThrones1!", "Marvel2023!", "Batman2022!",
]

# Additional realistic passwords from potfile
REALISTIC_PASSWORDS = [
    "MagneticBlue2@", "Oconomowoc2023!", "Safecracker021!", "I_have_no_idea!",
    "Iwillnotbetheone3#", "Makeitgreatnow2", "Nevergonnauseagain!",
    "Thisisthenewpassword!", "Springfield1!", "Stupidpassword01!",
    "Ktspassword12!", "2Manypasswords", "New@password", "Ihatepasswords1!",
    "Ihatepasswords!16", "Ilovespring!?", "Carespring1!", "Carespring2!",
    "Carespring22", "Carespring5000", "Thisisnotagoodpassword1",
    "Nice2MeetU!", "70YearsOld!", "Going2disney!", "Jetset50!",
    "GreenDay1993!$", "RedDrag0n64!", "TailFeather23", "MallMania23",
]

# Strong passwords (for uncracked simulation)
STRONG_PASSWORDS = [
    "X10sionZ", "c0MpacT", "V3r1fy", "b0x3rZ", "N0Mag1c", "PCB0ard",
    "T3chnical", "Translati0n", "N3verGuess", "N3v3RGu3$$!",
]


def generate_ntlm_hash(password: str) -> str:
    """Generate a fake NTLM-like hash from a password string."""
    return hashlib.md5(password.encode('utf-16-le')).hexdigest()


def load_master_potfile(potfile_path: str) -> List[Tuple[str, str]]:
    """Load hash:password pairs from the master potfile."""
    entries = []
    try:
        with open(potfile_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2 and len(parts[0]) == 32:
                        password = parts[1]
                        # Skip excluded passwords and hex-encoded ones
                        if password not in EXCLUDED_PASSWORDS and not password.startswith('$HEX['):
                            entries.append((parts[0], password))
    except Exception as e:
        print(f"Warning: Could not load potfile: {e}")
    return entries


def categorize_password(password: str, username: str = "") -> List[str]:
    """Categorize a password into bad practice categories."""
    categories = []
    pw_lower = password.lower()

    # Season/Year patterns
    seasons = ['spring', 'summer', 'fall', 'autumn', 'winter']
    if any(s in pw_lower for s in seasons) and re.search(r'\d{2,4}', password):
        categories.append("season_year")

    # Keyboard patterns
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', 'qazwsx']
    if any(p in pw_lower for p in keyboard_patterns):
        categories.append("keyboard_patterns")

    # Common words
    common = ['password', 'passw0rd', 'p@ssw', 'letmein', 'welcome', 'admin', 'login']
    if any(c in pw_lower for c in common):
        categories.append("common_words")

    # Sequential numbers
    if re.search(r'(123|234|345|456|567|678|789|012|111|222|333|444|555|666|777|888|999)', password):
        categories.append("sequential_numbers")

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        categories.append("repeated_characters")

    # Username in password
    if username and len(username) >= 3 and username.lower() in pw_lower:
        categories.append("username_in_password")

    # Dictionary words (common English words)
    dict_words = ['dragon', 'monkey', 'shadow', 'master', 'princess', 'sunshine',
                  'freedom', 'harmony', 'love', 'hate', 'change', 'new', 'stupid']
    if any(w in pw_lower for w in dict_words):
        categories.append("dictionary_words")

    # Personal info patterns (dates, names)
    if re.search(r'(19|20)\d{2}', password) or re.search(r'\d{1,2}/\d{1,2}', password):
        categories.append("date_patterns")

    # Sports teams
    sports = ['packers', 'cowboys', 'lakers', 'yankees', 'bears', 'cubs', 'bulls']
    if any(s in pw_lower for s in sports):
        categories.append("sports_teams")

    # Pop culture
    pop = ['starwars', 'marvel', 'batman', 'superman', 'disney', 'gameofthrones']
    if any(p in pw_lower for p in pop):
        categories.append("pop_culture")

    # Company related (for DemoCorp)
    company_words = ['demo', 'corp', 'company', 'test', 'acme']
    if any(c in pw_lower for c in company_words):
        categories.append("company_related")

    return categories


def extract_dictionary_words(password: str) -> List[str]:
    """Extract English dictionary words from a password."""
    # Common English words that might appear in passwords
    common_words = {
        'spring', 'summer', 'fall', 'winter', 'autumn', 'password', 'dragon',
        'monkey', 'shadow', 'master', 'princess', 'sunshine', 'freedom',
        'welcome', 'hello', 'love', 'hate', 'time', 'work', 'change', 'new',
        'stupid', 'never', 'gonna', 'care', 'nice', 'meet', 'going', 'magic',
        'harmony', 'magnetic', 'blue', 'red', 'green', 'yellow', 'cold', 'hot',
        'star', 'wars', 'marvel', 'batman', 'disney', 'game', 'thrones',
        'packers', 'cowboys', 'lakers', 'yankees', 'football', 'baseball',
        'this', 'that', 'will', 'have', 'make', 'great', 'good', 'bad',
        'first', 'last', 'year', 'day', 'night', 'morning', 'evening',
        'january', 'february', 'march', 'april', 'may', 'june', 'july',
        'august', 'september', 'october', 'november', 'december',
    }

    found = []
    pw_lower = password.lower()

    # Extract alphabetic sequences
    alpha_sequences = re.findall(r'[a-zA-Z]+', pw_lower)

    for seq in alpha_sequences:
        # Check if the sequence itself is a word
        if seq in common_words and len(seq) >= 4:
            found.append(seq)
        else:
            # Check for words within the sequence
            for word in common_words:
                if len(word) >= 4 and word in seq:
                    found.append(word)

    return list(set(found))


def extract_substrings(passwords: List[str], min_len: int = 4) -> Dict[str, Dict[str, int]]:
    """Extract common substrings from passwords."""
    substring_passwords: Dict[str, Dict[str, int]] = {}

    for password in passwords:
        pw_lower = password.lower()
        found_in_pw: Set[str] = set()

        for length in range(min_len, min(len(pw_lower) + 1, 12)):
            for i in range(len(pw_lower) - length + 1):
                substr = pw_lower[i:i + length]
                # Only keep meaningful substrings
                if re.match(r'^[a-z0-9]+$', substr):
                    found_in_pw.add(substr)

        for substr in found_in_pw:
            if substr not in substring_passwords:
                substring_passwords[substr] = {}
            substring_passwords[substr][password] = 1

    # Filter to substrings appearing in 3+ passwords
    return {s: p for s, p in substring_passwords.items() if len(p) >= 3}


def generate_user(
    first_name: str,
    last_name: str,
    department: str,
    user_idx: int,
    base_date: datetime,
) -> Dict[str, Any]:
    """Generate a user dictionary in ADD JSON format."""
    sam_account = f"{first_name[0].lower()}{last_name.lower()}"

    # Random creation date (1-5 years ago from base_date)
    created_days_ago = random.randint(365, 1825)
    created = base_date - timedelta(days=created_days_ago)

    # Password last set (0-180 days ago from base_date)
    pwd_set_days_ago = random.randint(0, 180)
    pwd_last_set = base_date - timedelta(days=pwd_set_days_ago)

    # Generate a placeholder hash (will be replaced based on profile)
    placeholder_hash = generate_ntlm_hash(f"placeholder_{user_idx}")

    # Determine group membership
    groups = ["Domain Users"]
    if department == "IT":
        if random.random() < 0.2:
            groups.extend(["Domain Admins", "Administrators"])
        elif random.random() < 0.5:
            groups.append("Remote Desktop Users")
    elif department == "Executive":
        groups.append("Remote Desktop Users")

    # User account control flags
    uac = ["NORMAL_ACCOUNT"]
    if random.random() < 0.05:  # 5% disabled
        uac.append("ACCOUNT_DISABLED")
    if random.random() < 0.1:  # 10% don't expire
        uac.append("DONT_EXPIRE_PASSWORD")

    return {
        "Cn": f"{first_name} {last_name}",
        "Name": f"{first_name} {last_name}",
        "First": first_name,
        "Last": last_name,
        "SamAccountName": sam_account,
        "GroupMemberCount": str(len(groups)),
        "MemberOf": groups,
        "DisplayName": f"{first_name} {last_name}",
        "PrimaryGroupId": "513",
        "WhenCreated": created.strftime("%m/%d/%Y %I:%M:%S %p"),
        "WhenChanged": (base_date - timedelta(days=random.randint(0, 30))).strftime("%m/%d/%Y %I:%M:%S %p"),
        "LastLogon": base_date.strftime("%m/%d/%Y") if random.random() > 0.1 else "0",
        "UserAccountControl": uac,
        "PwdLastSet": pwd_last_set.strftime("%m/%d/%Y"),
        "LockoutTime": "",
        "ObjectSid": f"S-1-5-21-1234567890-1234567890-1234567890-{1500 + user_idx}",
        "Description": f"{department} department user",
        "NTLMHash": f"aad3b435b51404eeaad3b435b51404ee:{placeholder_hash}",
        "HistoricalNTHashes": [],
        "LogonName": f"DEMOCORP\\{sam_account}",
        "_department": department,
        "_user_idx": user_idx,
        "_pwd_last_set_days_ago": pwd_set_days_ago,
    }


def generate_expanded_add_json(num_accounts: int = 250, seed: int = 42) -> Dict[str, Any]:
    """Generate an expanded ADD JSON with the specified number of accounts."""
    random.seed(seed)

    users = []
    base_date = datetime.now()
    user_idx = 0

    # Generate users for each department
    for dept, base_count in DEPARTMENTS:
        count = int(base_count * (num_accounts / sum(c for _, c in DEPARTMENTS)))

        for _ in range(count):
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)

            # Avoid duplicates
            while any(u.get("SamAccountName") == f"{first[0].lower()}{last.lower()}" for u in users):
                first = random.choice(FIRST_NAMES)
                last = random.choice(LAST_NAMES)

            user = generate_user(first, last, dept, user_idx, base_date)
            users.append(user)
            user_idx += 1

    # Add standard accounts (Administrator, Guest, krbtgt)
    standard_accounts = [
        {
            "Cn": "Administrator",
            "Name": "Administrator",
            "First": "",
            "Last": "",
            "SamAccountName": "Administrator",
            "GroupMemberCount": "5",
            "MemberOf": ["Group Policy Creator Owners", "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"],
            "DisplayName": "",
            "PrimaryGroupId": "513",
            "WhenCreated": "01/01/2020 08:00:00 AM",
            "WhenChanged": base_date.strftime("%m/%d/%Y %I:%M:%S %p"),
            "LastLogon": base_date.strftime("%m/%d/%Y"),
            "UserAccountControl": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"],
            "PwdLastSet": (base_date - timedelta(days=60)).strftime("%m/%d/%Y"),
            "LockoutTime": "",
            "ObjectSid": "S-1-5-21-1234567890-1234567890-1234567890-500",
            "Description": "Built-in account for administering the computer/domain",
            "NTLMHash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "HistoricalNTHashes": [],
            "LogonName": "DEMOCORP\\Administrator",
            "_department": "IT",
            "_user_idx": 9998,
            "_pwd_last_set_days_ago": 60,
        },
        {
            "Cn": "Guest",
            "Name": "Guest",
            "First": "",
            "Last": "",
            "SamAccountName": "Guest",
            "GroupMemberCount": "1",
            "MemberOf": ["Guests"],
            "DisplayName": "",
            "PrimaryGroupId": "514",
            "WhenCreated": "01/01/2020 08:00:00 AM",
            "WhenChanged": "01/01/2020 08:00:00 AM",
            "LastLogon": "0",
            "UserAccountControl": ["ACCOUNT_DISABLED", "PASSWD_NOTREQD", "NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"],
            "PwdLastSet": "0",
            "LockoutTime": "",
            "ObjectSid": "S-1-5-21-1234567890-1234567890-1234567890-501",
            "Description": "Built-in account for guest access to the computer/domain",
            "NTLMHash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "HistoricalNTHashes": [],
            "LogonName": "DEMOCORP\\Guest",
            "_department": "System",
            "_user_idx": 9999,
            "_pwd_last_set_days_ago": 0,
        },
    ]

    users = standard_accounts + users

    return {
        "Name": "democorp.local",
        "PullDate": base_date.strftime("%m/%d/%Y"),
        "UserCount": len(users),
        "MinPwdAge": 1,
        "MaxPwdAge": 90,
        "MinPasswordLength": 12,
        "PwdProperties": 1,
        "LockoutDuration": 30,
        "LockoutObservationWindow": 30,
        "LockoutThreshold": 5,
        "PwdHistoryLength": 24,
        "DomainTrusts": None,
        "Users": users,
    }


def assign_passwords_to_users(
    users: List[Dict[str, Any]],
    profile: Dict[str, float],
    all_passwords: List[str],
    seed: int = 42,
) -> Tuple[Dict[str, str], List[str]]:
    """
    Assign passwords to users based on the profile.
    Returns (user_password_map, list_of_cracked_passwords)
    """
    random.seed(seed)

    total_users = len(users)
    cracked_count = int(total_users * profile["crack_rate"])

    # Build password pools by category
    weak_passwords = (
        SEASON_YEAR_PASSWORDS[:int(len(SEASON_YEAR_PASSWORDS) * profile["bad_practices_multiplier"] / 2)] +
        COMMON_WORD_PASSWORDS[:int(len(COMMON_WORD_PASSWORDS) * profile["bad_practices_multiplier"] / 2)] +
        REALISTIC_PASSWORDS[:int(len(REALISTIC_PASSWORDS) * profile["bad_practices_multiplier"] / 2)]
    )

    # Add additional passwords from all_passwords pool
    additional_passwords = [p for p in all_passwords if p not in weak_passwords]
    password_pool = weak_passwords + additional_passwords[:50]

    # Shuffle users
    shuffled_users = users.copy()
    random.shuffle(shuffled_users)

    user_passwords: Dict[str, str] = {}
    cracked_passwords: List[str] = []

    # Assign passwords to cracked users
    for i, user in enumerate(shuffled_users[:cracked_count]):
        username = user["SamAccountName"]

        # Pick a password from the pool, with some reuse
        if i < len(password_pool):
            password = password_pool[i % len(password_pool)]
        else:
            password = random.choice(password_pool)

        user_passwords[username] = password
        cracked_passwords.append(password)

    # Some users get blank passwords
    blank_count = int(total_users * profile["blank_password_rate"])
    for user in shuffled_users[cracked_count:cracked_count + blank_count]:
        username = user["SamAccountName"]
        user_passwords[username] = ""
        cracked_passwords.append("")

    return user_passwords, cracked_passwords


def generate_cracking_stats(
    total_accounts: int,
    cracked_count: int,
    cracked_passwords: List[str],
) -> List[Dict[str, str]]:
    """Generate cracking statistics table."""
    # Filter out blank passwords for length stats
    non_blank = [p for p in cracked_passwords if p]

    if non_blank:
        shortest = min(len(p) for p in non_blank)
        longest = max(len(p) for p in non_blank)
        avg_len = sum(len(p) for p in non_blank) / len(non_blank)
    else:
        shortest = 0
        longest = 0
        avg_len = 0

    unique_passwords = len(set(cracked_passwords))
    unique_hashes = int(total_accounts * 0.85)
    cracked_hashes = int(cracked_count * 0.9)  # Some hash reuse

    crack_rate = (cracked_count / total_accounts * 100) if total_accounts > 0 else 0
    hash_crack_rate = (cracked_hashes / unique_hashes * 100) if unique_hashes > 0 else 0

    return [
        {"key": "Cracked Accounts: ", "value": cracked_count},
        {"key": "Uncracked Accounts: ", "value": total_accounts - cracked_count},
        {"key": "Total Accounts Analyzed: ", "value": total_accounts},
        {"key": "Percent of Accounts Cracked: ", "value": f"{crack_rate:.1f}%"},
        {"key": "Cracked NTLM Hashes: ", "value": cracked_hashes},
        {"key": "Uncracked NTLM Hashes: ", "value": unique_hashes - cracked_hashes},
        {"key": "Unique NTLM Hashes Analyzed: ", "value": unique_hashes},
        {"key": "Percent of NTLM Hashes Cracked: ", "value": f"{hash_crack_rate:.1f}%"},
        {"key": "Total LANMan Hashes: ", "value": 0},
        {"key": "Shortest Cracked Password: ", "value": shortest},
        {"key": "Longest Cracked Password: ", "value": longest},
        {"key": "Average Password Length: ", "value": f"{avg_len:.1f}"},
    ]


def generate_length_distribution(cracked_passwords: List[str]) -> List[Dict[str, int]]:
    """Generate password length distribution."""
    from collections import Counter

    lengths = [len(p) for p in cracked_passwords if p]  # Exclude blank
    length_counts = Counter(lengths)

    distribution = []
    for length in range(1, max(lengths) + 1 if lengths else 1):
        if length in length_counts:
            distribution.append({"length": length, "count": length_counts[length]})

    return distribution


def generate_top_passwords(cracked_passwords: List[str]) -> List[Dict[str, Any]]:
    """Generate top reused passwords list."""
    from collections import Counter

    # Count password occurrences
    pw_counts = Counter(cracked_passwords)

    # Filter to passwords used 2+ times, sort by count
    top_passwords = [
        {"password": pw if pw else "{blank}", "count": count}
        for pw, count in pw_counts.most_common(20)
        if count >= 2
    ]

    return top_passwords


def generate_substrings(cracked_passwords: List[str]) -> List[Dict[str, Any]]:
    """Generate common substrings analysis."""
    substring_data = extract_substrings(cracked_passwords, min_len=4)

    # Sort by count and take top 20
    sorted_substrings = sorted(
        substring_data.items(),
        key=lambda x: (-len(x[1]), -len(x[0]))
    )[:20]

    return [
        {
            "substring": substr,
            "count": len(pw_dict),
            "passwords": pw_dict
        }
        for substr, pw_dict in sorted_substrings
    ]


def generate_dict_words(cracked_passwords: List[str]) -> Dict[str, int]:
    """Generate dictionary words analysis."""
    from collections import Counter

    all_words = []
    for pw in cracked_passwords:
        if pw:
            all_words.extend(extract_dictionary_words(pw))

    word_counts = Counter(all_words)

    # Return top words as dict
    return dict(word_counts.most_common(30))


def generate_policy_violations(
    users: List[Dict[str, Any]],
    user_passwords: Dict[str, str],
    profile: Dict[str, float],
) -> Tuple[Dict, Dict, List, Dict]:
    """Generate policy violation data."""
    total = len(users)

    min_length_violations = {}
    complexity_violations = {}
    blank_passwords = []
    max_age_violations = {}

    for user in users:
        username = user["SamAccountName"]
        password = user_passwords.get(username)

        if password is None:
            continue

        # Blank password check
        if password == "":
            blank_passwords.append({"username": username})
            continue

        # Min length check (policy is 12)
        if len(password) < 12:
            min_length_violations[username] = {
                "cracked_pw": password,
                "pw_length": len(password)
            }

        # Complexity check
        complexity_count = 0
        if re.search(r'[a-z]', password):
            complexity_count += 1
        if re.search(r'[A-Z]', password):
            complexity_count += 1
        if re.search(r'\d', password):
            complexity_count += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            complexity_count += 1

        if complexity_count < 3:
            complexity_violations[username] = {
                "cracked_pw": password,
                "complexity_count": complexity_count
            }

        # Max age check (from user metadata)
        pwd_age = user.get("_pwd_last_set_days_ago", 0)
        if pwd_age > 90:
            max_age_violations[username] = {
                "pw_changed": (datetime.now() - timedelta(days=pwd_age)).strftime('%Y-%m-%d'),
                "pw_age": pwd_age
            }

    return min_length_violations, complexity_violations, blank_passwords, max_age_violations


def generate_bad_practices(
    users: List[Dict[str, Any]],
    user_passwords: Dict[str, str],
    profile: Dict[str, float],
) -> Dict[str, List[Dict[str, str]]]:
    """Generate bad practices findings."""
    bad_practices = {
        "season_year": [],
        "company_related": [],
        "keyboard_patterns": [],
        "common_words": [],
        "sequential_numbers": [],
        "repeated_characters": [],
        "username_in_password": [],
        "dictionary_words": [],
        "personal_info": [],
        "date_patterns": [],
        "sports_teams": [],
        "pop_culture": [],
        "profanity": [],
    }

    for user in users:
        username = user["SamAccountName"]
        password = user_passwords.get(username)

        if not password:
            continue

        categories = categorize_password(password, username)

        for category in categories:
            if category in bad_practices:
                bad_practices[category].append({
                    "username": username,
                    "password": password
                })

    return bad_practices


def generate_password_reuse(
    users: List[Dict[str, Any]],
    user_passwords: Dict[str, str],
) -> List[List[Any]]:
    """Generate password reuse findings."""
    from collections import defaultdict

    # Group users by password hash
    hash_users: Dict[str, List[str]] = defaultdict(list)

    for user in users:
        username = user["SamAccountName"]
        password = user_passwords.get(username)

        if password:
            pw_hash = generate_ntlm_hash(password)
            hash_users[pw_hash].append(username)

    # Build reuse table (only groups with 2+ users)
    reuse_table = [
        [pw_hash, len(usernames), usernames]
        for pw_hash, usernames in hash_users.items()
        if len(usernames) >= 2
    ]

    # Sort by count descending
    reuse_table.sort(key=lambda x: -x[1])

    return reuse_table[:20]  # Top 20


def create_session_files(
    session_dir: Path,
    add_data: Dict[str, Any],
    profile: Dict[str, float],
    session_date: datetime,
    project_desc: str,
    all_passwords: List[str],
    profile_seed: int,
) -> None:
    """Create all JSON files for a session."""
    users = add_data["Users"]
    total_accounts = len(users)

    # Assign passwords based on profile
    user_passwords, cracked_passwords = assign_passwords_to_users(
        users, profile, all_passwords, seed=profile_seed
    )

    cracked_count = len([p for p in cracked_passwords if p is not None])

    # Create session directory
    session_dir.mkdir(parents=True, exist_ok=True)

    # Generate and save all data files
    stats = generate_cracking_stats(total_accounts, cracked_count, cracked_passwords)
    with open(session_dir / "cracking_stats_table.json", 'w') as f:
        json.dump(stats, f, indent=2)

    length_dist = generate_length_distribution(cracked_passwords)
    with open(session_dir / "pw_length_distribution.json", 'w') as f:
        json.dump(length_dist, f, indent=2)

    top_passwords = generate_top_passwords(cracked_passwords)
    with open(session_dir / "pw_top_passwords.json", 'w') as f:
        json.dump(top_passwords, f, indent=2)

    substrings = generate_substrings(cracked_passwords)
    with open(session_dir / "pw_substrings.json", 'w') as f:
        json.dump(substrings, f, indent=2)

    dict_words = generate_dict_words(cracked_passwords)
    with open(session_dir / "pw_dict_words.json", 'w') as f:
        json.dump(dict_words, f, indent=2)

    min_len, complexity, blank, max_age = generate_policy_violations(
        users, user_passwords, profile
    )
    with open(session_dir / "pw_fails_min_length.json", 'w') as f:
        json.dump(min_len, f, indent=2)
    with open(session_dir / "pw_fails_complexity.json", 'w') as f:
        json.dump(complexity, f, indent=2)
    with open(session_dir / "pw_fails_blank.json", 'w') as f:
        json.dump(blank, f, indent=2)
    with open(session_dir / "pw_fails_max_age.json", 'w') as f:
        json.dump(max_age, f, indent=2)

    bad_practices = generate_bad_practices(users, user_passwords, profile)
    with open(session_dir / "pw_bad_practices.json", 'w') as f:
        json.dump(bad_practices, f, indent=2)

    reuse = generate_password_reuse(users, user_passwords)
    with open(session_dir / "pw_reuse_table.json", 'w') as f:
        json.dump(reuse, f, indent=2)

    # LM hashes (declining over time)
    lm_count = int(total_accounts * 0.05 * profile["bad_practices_multiplier"])
    lm_hashes = [{"username": u["SamAccountName"]} for u in random.sample(users, min(lm_count, len(users)))]
    with open(session_dir / "pw_lm_hashes.json", 'w') as f:
        json.dump(lm_hashes, f, indent=2)

    # Pie charts
    pie_data = {
        "labels": ["Cracked", "Uncracked"],
        "data": [cracked_count, total_accounts - cracked_count],
    }
    with open(session_dir / "pw_account_pie.json", 'w') as f:
        json.dump(pie_data, f, indent=2)
    with open(session_dir / "pw_ntlm_hash_pie.json", 'w') as f:
        json.dump(pie_data, f, indent=2)

    # Session metadata
    session_id = session_dir.name
    metadata = {
        "session_id": session_id,
        "name": f"{COMPANY_NAME} - {project_desc}",
        "created_at": session_date.isoformat(),
        "updated_at": session_date.isoformat(),
        "created_by": "admin",
        "company_name": COMPANY_NAME,
        "project_description": project_desc,
        "source_files": {"add_json": "generated_ADD.json"},
        "source_hash": generate_ntlm_hash(f"source_{session_id}"),
        "total_accounts": total_accounts,
        "cracked_accounts": cracked_count,
        "crack_rate": profile["crack_rate"] * 100,
        "notes": "Generated historical test session for trend analysis",
        "aaia_generated": False,
        "aaia_timestamp": "",
    }
    with open(session_dir / "session_meta.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    # Analysis options
    options = {
        "company_name": COMPANY_NAME,
        "project_description": project_desc,
        "policy_min_pw_len": "12",
        "policy_max_pw_age": "90",
        "policy_complexity_req": "3",
    }
    with open(session_dir / "analysis_options.json", 'w') as f:
        json.dump(options, f, indent=2)


def main():
    """Main function to generate all test data."""
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent
    sessions_dir = project_dir / "data" / "sessions"
    test_data_dir = project_dir / "testData"

    print("=" * 60)
    print("Historical Trend Analysis Test Data Generator")
    print("=" * 60)

    # Load master potfile for real password examples
    potfile_path = project_dir / "data" / "master.potfile"
    potfile_entries = load_master_potfile(str(potfile_path))
    all_passwords = [p[1] for p in potfile_entries if p[1]]
    print(f"\nLoaded {len(all_passwords)} passwords from master potfile")

    # Generate expanded ADD JSON
    print("\nGenerating expanded ADD JSON (~250 accounts)...")
    add_data = generate_expanded_add_json(250, seed=42)
    print(f"  Created {len(add_data['Users'])} user accounts")

    # Save expanded ADD JSON
    expanded_add_path = test_data_dir / "example_ADD_expanded.json"
    test_data_dir.mkdir(parents=True, exist_ok=True)
    with open(expanded_add_path, 'w') as f:
        json.dump(add_data, f, indent=2)
    print(f"  Saved to: {expanded_add_path}")

    # Create sessions directory
    sessions_dir.mkdir(parents=True, exist_ok=True)

    # Generate 4 historical sessions
    now = datetime.now()
    session_configs = [
        ("year_ago", now - timedelta(days=365), "Q4 2024 Annual Assessment", 100),
        ("9_months", now - timedelta(days=270), "Q1 2025 Quarterly Review", 200),
        ("6_months", now - timedelta(days=180), "Q2 2025 Mid-Year Assessment", 300),
        ("3_months", now - timedelta(days=90), "Q3 2025 Quarterly Review", 400),
    ]

    print("\nGenerating historical sessions:")
    for profile_name, session_date, project_desc, seed in session_configs:
        profile = IMPROVEMENT_PROFILES[profile_name]
        session_id = f"trend_test_{profile_name}"
        session_dir = sessions_dir / session_id

        print(f"\n  {profile_name}:")
        print(f"    Session ID: {session_id}")
        print(f"    Date: {session_date.strftime('%Y-%m-%d')}")
        print(f"    Crack Rate: {profile['crack_rate'] * 100:.0f}%")
        print(f"    Avg Password Length: {profile['avg_password_length']}")

        create_session_files(
            session_dir, add_data, profile, session_date,
            project_desc, all_passwords, seed
        )
        print(f"    Created session files in: {session_dir}")

    print("\n" + "=" * 60)
    print("Test data generation complete!")
    print("\nTo test trend analysis:")
    print("  1. Start the HM1K application")
    print("  2. Navigate to a report page")
    print("  3. Click 'Trend Analysis' in the navigation")
    print("  4. Select 'DemoCorp' sessions to compare")
    print("=" * 60)


if __name__ == "__main__":
    main()
