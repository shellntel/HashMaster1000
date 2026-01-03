"""
password_history.py - Password History Analysis Module for Hash Master 1000

Analyzes historical password data to detect predictable rotation patterns
and password evolution. Supports both pwdump _history format and ADD JSON
HistoricalNTHashes format.

Detection Capabilities:
- Incrementing numbers: Password1 → Password2 → Password3
- Season rotation: Summer2023 → Fall2023 → Winter2024
- Special character rotation: Welcome1! → Welcome1@ → Welcome1#
- Base word persistence: same root word across multiple changes
- Password reversion: returning to previously used passwords
- Year increment patterns: Company2023 → Company2024
- Leet-speak progression: Password → P4ssword → P4ssw0rd
- Hash reuse detection: works even without cracked passwords
"""

import re
from dataclasses import dataclass, field
from typing import Any
from difflib import SequenceMatcher
from collections import Counter


# Pattern detection constants
SEASON_WORDS = [
    "spring", "summer", "fall", "autumn", "winter",
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
    "january", "february", "march", "april", "june",
    "july", "august", "september", "october", "november", "december",
    "q1", "q2", "q3", "q4"
]

SPECIAL_CHARS = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=']

LEET_SPEAK_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'l': ['1'],
    'b': ['8'],
    'g': ['9'],
}

# Reverse leet map for detection
REVERSE_LEET_MAP = {}
for letter, replacements in LEET_SPEAK_MAP.items():
    for rep in replacements:
        if rep not in REVERSE_LEET_MAP:
            REVERSE_LEET_MAP[rep] = []
        REVERSE_LEET_MAP[rep].append(letter)


@dataclass
class PasswordHistoryEntry:
    """Represents a single password in a user's history."""
    hash: str
    password: str | None = None  # None if not cracked
    position: int = 0  # 0 = current, 1 = most recent history, etc.


@dataclass
class PatternMatch:
    """Represents a detected pattern in password history."""
    pattern_type: str  # e.g., "incrementing_number", "season_rotation"
    description: str
    confidence: float  # 0.0 to 1.0
    examples: list[str] = field(default_factory=list)
    passwords_involved: list[str] = field(default_factory=list)


@dataclass
class UserHistoryAnalysis:
    """Analysis results for a single user's password history."""
    username: str
    total_historical: int
    cracked_historical: int
    current_password: str | None
    current_cracked: bool
    historical_passwords: list[str]  # Cracked passwords in order (oldest to newest)
    historical_hashes: list[str] = field(default_factory=list)  # All hashes for hash-based detection
    # Full history entries with both hash and password for display
    full_history: list[dict[str, Any]] = field(default_factory=list)
    patterns_detected: list[PatternMatch] = field(default_factory=list)
    predictability_score: float = 0.0  # 0.0 = unpredictable, 1.0 = highly predictable
    password_reuse_detected: bool = False
    reused_passwords: list[str] = field(default_factory=list)
    # Hash reuse detection (works even without cracked passwords)
    hash_reuse_detected: bool = False
    hash_reuse_count: int = 0  # Number of extra occurrences (if hash appears 3x, count is 2)
    consecutive_hash_duplicates: bool = False  # Same hash twice in a row (dangerous!)
    consecutive_duplicate_count: int = 0  # Max streak of consecutive same hashes


@dataclass
class HistoryAnalysisResult:
    """Aggregate results of password history analysis."""
    total_users_analyzed: int = 0
    users_with_history: int = 0
    users_with_cracked_history: int = 0
    users_with_patterns: int = 0

    # Pattern statistics
    pattern_counts: dict[str, int] = field(default_factory=dict)

    # User-level findings
    user_analyses: list[UserHistoryAnalysis] = field(default_factory=list)

    # Top findings for summary
    top_predictable_users: list[UserHistoryAnalysis] = field(default_factory=list)
    pattern_examples: dict[str, list[dict]] = field(default_factory=dict)

    # Hash reuse stats (detected by hash, works without cracking)
    users_with_hash_reuse: int = 0
    users_with_consecutive_duplicates: int = 0  # Same hash twice in a row


def extract_pwdump_history(
    pwdump_lines: list[dict[str, Any]],
    cracked_hashes: dict[str, str]
) -> dict[str, list[PasswordHistoryEntry]]:
    """
    Extract password history from pwdump format with _history suffixes.

    Looks for entries like:
        username_history0, username_history1, etc.

    Args:
        pwdump_lines: List of parsed pwdump line dictionaries
        cracked_hashes: Dict mapping NTLM hashes to cracked passwords

    Returns:
        Dict mapping base username to list of PasswordHistoryEntry objects
    """
    history_pattern = re.compile(r'^(.+)_history(\d+)$', re.IGNORECASE)

    # Group entries by base username
    base_users: dict[str, dict[str, Any]] = {}  # username -> {hash, rid, etc.}
    history_entries: dict[str, list[tuple[int, str]]] = {}  # username -> [(position, hash)]

    for line in pwdump_lines:
        if not line.get('is_valid', True) or not line.get('included', True):
            continue

        username = line.get('username', '')
        ntlm_hash = line.get('ntlm_hash', '')

        if not username or not ntlm_hash:
            continue

        # Check if this is a history entry
        match = history_pattern.match(username)
        if match:
            base_name = match.group(1)
            position = int(match.group(2))

            if base_name not in history_entries:
                history_entries[base_name] = []
            history_entries[base_name].append((position, ntlm_hash))
        else:
            # This is a current/base entry
            base_users[username] = {
                'hash': ntlm_hash,
                'data': line
            }

    # Build history for each user
    result: dict[str, list[PasswordHistoryEntry]] = {}

    for username, user_data in base_users.items():
        entries = []

        # Add current password
        current_hash = user_data['hash']
        current_password = cracked_hashes.get(current_hash)
        entries.append(PasswordHistoryEntry(
            hash=current_hash,
            password=current_password,
            position=0
        ))

        # Add historical entries if they exist
        if username in history_entries:
            # Sort by position (oldest to most recent before current)
            history = sorted(history_entries[username], key=lambda x: x[0], reverse=True)
            for idx, (pos, hist_hash) in enumerate(history, start=1):
                hist_password = cracked_hashes.get(hist_hash)
                entries.append(PasswordHistoryEntry(
                    hash=hist_hash,
                    password=hist_password,
                    position=idx
                ))

        if len(entries) > 1:  # Only include users with history
            result[username] = entries

    return result


def extract_add_history(
    add_entries: list[dict[str, Any]],
    cracked_hashes: dict[str, str]
) -> dict[str, list[PasswordHistoryEntry]]:
    """
    Extract password history from ADD JSON format with HistoricalNTHashes.

    Args:
        add_entries: List of ADD entry dictionaries
        cracked_hashes: Dict mapping NTLM hashes to cracked passwords

    Returns:
        Dict mapping username to list of PasswordHistoryEntry objects
    """
    result: dict[str, list[PasswordHistoryEntry]] = {}

    for entry in add_entries:
        if not entry.get('included', True) or not entry.get('is_valid', True):
            continue

        username = entry.get('sam_account_name', '')
        current_hash = entry.get('ntlm_hash', '')
        historical_hashes = entry.get('historical_hashes', [])

        if not username or not current_hash:
            continue

        if not historical_hashes:
            continue

        entries = []

        # Add current password (position 0)
        current_password = cracked_hashes.get(current_hash)
        entries.append(PasswordHistoryEntry(
            hash=current_hash,
            password=current_password,
            position=0
        ))

        # Add historical entries (position 1, 2, etc.)
        # Historical hashes are typically ordered from most recent to oldest
        for idx, hist_hash in enumerate(historical_hashes, start=1):
            hist_password = cracked_hashes.get(hist_hash)
            entries.append(PasswordHistoryEntry(
                hash=hist_hash,
                password=hist_password,
                position=idx
            ))

        result[username] = entries

    return result


def detect_incrementing_number(passwords: list[str]) -> PatternMatch | None:
    """
    Detect incrementing number suffix pattern.
    e.g., Password1 → Password2 → Password3
    """
    if len(passwords) < 2:
        return None

    # Extract base and trailing number from each password
    number_pattern = re.compile(r'^(.+?)(\d+)$')
    bases_and_numbers = []

    for pwd in passwords:
        match = number_pattern.match(pwd)
        if match:
            bases_and_numbers.append((match.group(1), int(match.group(2))))
        else:
            bases_and_numbers.append((pwd, None))

    # Check for same base with incrementing numbers
    if not bases_and_numbers:
        return None

    # Group by base
    bases = [bn[0].lower() for bn in bases_and_numbers if bn[1] is not None]
    numbers = [bn[1] for bn in bases_and_numbers if bn[1] is not None]

    if len(numbers) < 2:
        return None

    # Check if bases are similar (allowing slight variations)
    base_counts = Counter(bases)
    most_common_base, count = base_counts.most_common(1)[0]

    if count < 2:
        return None

    # Get numbers for the most common base
    relevant_numbers = [bn[1] for bn in bases_and_numbers
                        if bn[0].lower() == most_common_base and bn[1] is not None]

    if len(relevant_numbers) < 2:
        return None

    # Check if numbers are sequential or incrementing
    sorted_nums = sorted(relevant_numbers)
    is_sequential = all(sorted_nums[i] + 1 == sorted_nums[i+1]
                        for i in range(len(sorted_nums)-1))

    if is_sequential:
        confidence = min(1.0, len(relevant_numbers) / 3.0)  # Max confidence at 3+ sequential
        return PatternMatch(
            pattern_type="incrementing_number",
            description=f"Incrementing number suffix: {most_common_base}N",
            confidence=confidence,
            examples=[f"{most_common_base}{n}" for n in sorted_nums[:3]],
            passwords_involved=[p for p in passwords if p.lower().startswith(most_common_base.lower())]
        )

    return None


def detect_season_rotation(passwords: list[str]) -> PatternMatch | None:
    """
    Detect season/month rotation patterns.
    e.g., Summer2023 → Fall2023 → Winter2024
    """
    if len(passwords) < 2:
        return None

    season_matches = []

    for pwd in passwords:
        pwd_lower = pwd.lower()
        for season in SEASON_WORDS:
            if season in pwd_lower:
                # Extract year if present
                year_match = re.search(r'20\d{2}', pwd)
                year = year_match.group(0) if year_match else None
                season_matches.append((pwd, season, year))
                break

    if len(season_matches) < 2:
        return None

    # Check if we have multiple seasons
    seasons_found = set(s[1] for s in season_matches)

    if len(seasons_found) >= 2:
        confidence = min(1.0, len(season_matches) / 3.0)
        return PatternMatch(
            pattern_type="season_rotation",
            description="Season/time period rotation pattern",
            confidence=confidence,
            examples=[s[0] for s in season_matches[:3]],
            passwords_involved=[s[0] for s in season_matches]
        )

    return None


def detect_special_char_rotation(passwords: list[str]) -> PatternMatch | None:
    """
    Detect special character rotation.
    e.g., Welcome1! → Welcome1@ → Welcome1#
    """
    if len(passwords) < 2:
        return None

    # Extract base (without trailing special char) and special char
    char_pattern = re.compile(r'^(.+?)([!@#$%^&*()\-_+=])$')
    bases_and_chars = []

    for pwd in passwords:
        match = char_pattern.match(pwd)
        if match:
            bases_and_chars.append((match.group(1), match.group(2), pwd))

    if len(bases_and_chars) < 2:
        return None

    # Group by base
    base_counts = Counter(bc[0].lower() for bc in bases_and_chars)

    if not base_counts:
        return None

    most_common_base, count = base_counts.most_common(1)[0]

    if count < 2:
        return None

    # Get special chars for the most common base
    relevant_chars = [bc[1] for bc in bases_and_chars if bc[0].lower() == most_common_base]

    if len(set(relevant_chars)) >= 2:  # At least 2 different special chars
        confidence = min(1.0, len(relevant_chars) / 3.0)
        examples = [bc[2] for bc in bases_and_chars if bc[0].lower() == most_common_base][:3]
        return PatternMatch(
            pattern_type="special_char_rotation",
            description=f"Special character rotation: {most_common_base}[special]",
            confidence=confidence,
            examples=examples,
            passwords_involved=[bc[2] for bc in bases_and_chars if bc[0].lower() == most_common_base]
        )

    return None


def detect_year_increment(passwords: list[str]) -> PatternMatch | None:
    """
    Detect year increment patterns.
    e.g., Company2022 → Company2023 → Company2024
    """
    if len(passwords) < 2:
        return None

    year_pattern = re.compile(r'^(.+?)(20\d{2})(.*)$')
    bases_and_years = []

    for pwd in passwords:
        match = year_pattern.match(pwd)
        if match:
            base = match.group(1) + match.group(3)  # Combine prefix and suffix
            year = int(match.group(2))
            bases_and_years.append((base.lower(), year, pwd))

    if len(bases_and_years) < 2:
        return None

    # Group by base
    base_counts = Counter(by[0] for by in bases_and_years)

    if not base_counts:
        return None

    most_common_base, count = base_counts.most_common(1)[0]

    if count < 2:
        return None

    # Get years for the most common base
    relevant = [(by[1], by[2]) for by in bases_and_years if by[0] == most_common_base]
    years = sorted(set(r[0] for r in relevant))

    if len(years) >= 2:
        # Check if years are sequential
        is_sequential = all(years[i] + 1 == years[i+1] for i in range(len(years)-1))

        if is_sequential:
            confidence = min(1.0, len(years) / 3.0)
            return PatternMatch(
                pattern_type="year_increment",
                description=f"Year increment pattern",
                confidence=confidence,
                examples=[r[1] for r in relevant[:3]],
                passwords_involved=[r[1] for r in relevant]
            )

    return None


def detect_base_word_persistence(passwords: list[str]) -> PatternMatch | None:
    """
    Detect when the same base word persists across password changes.
    Uses string similarity to find common roots.
    """
    if len(passwords) < 2:
        return None

    # Normalize passwords for comparison
    def normalize(pwd: str) -> str:
        # Remove numbers and special chars, lowercase
        return re.sub(r'[^a-zA-Z]', '', pwd).lower()

    normalized = [normalize(p) for p in passwords if normalize(p)]

    if len(normalized) < 2:
        return None

    # Find longest common substring among all passwords
    def lcs(s1: str, s2: str) -> str:
        matcher = SequenceMatcher(None, s1, s2)
        match = matcher.find_longest_match(0, len(s1), 0, len(s2))
        return s1[match.a:match.a + match.size]

    # Check similarity between consecutive passwords
    similarities = []
    for i in range(len(normalized) - 1):
        ratio = SequenceMatcher(None, normalized[i], normalized[i+1]).ratio()
        similarities.append(ratio)

    avg_similarity = sum(similarities) / len(similarities) if similarities else 0

    # Find common substring
    common = normalized[0]
    for n in normalized[1:]:
        common = lcs(common, n)
        if len(common) < 3:
            break

    if len(common) >= 4 and avg_similarity >= 0.5:
        confidence = min(1.0, avg_similarity)
        return PatternMatch(
            pattern_type="base_word_persistence",
            description=f"Common base word: '{common}'",
            confidence=confidence,
            examples=passwords[:3],
            passwords_involved=passwords
        )

    return None


def detect_leet_progression(passwords: list[str]) -> PatternMatch | None:
    """
    Detect leet-speak progression.
    e.g., Password → P4ssword → P4ssw0rd
    """
    if len(passwords) < 2:
        return None

    def unleet(pwd: str) -> str:
        """Convert leet-speak to regular letters."""
        result = pwd.lower()
        for leet_char, letters in REVERSE_LEET_MAP.items():
            result = result.replace(leet_char, letters[0])
        return result

    def count_leet_chars(pwd: str) -> int:
        """Count leet-speak substitutions in password."""
        return sum(1 for c in pwd if c in REVERSE_LEET_MAP)

    # Check if passwords have same base when unleet'd
    unleet_versions = [(p, unleet(p), count_leet_chars(p)) for p in passwords]

    # Group by unleet version
    base_counts = Counter(u[1] for u in unleet_versions)

    if not base_counts:
        return None

    most_common_base, count = base_counts.most_common(1)[0]

    if count < 2:
        return None

    # Get leet counts for the most common base
    relevant = [(u[0], u[2]) for u in unleet_versions if u[1] == most_common_base]
    leet_counts = sorted(set(r[1] for r in relevant))

    # Check if leet-speak is increasing
    if len(leet_counts) >= 2 and leet_counts[-1] > leet_counts[0]:
        confidence = min(1.0, (leet_counts[-1] - leet_counts[0]) / 3.0)
        if confidence >= 0.3:
            return PatternMatch(
                pattern_type="leet_progression",
                description="Leet-speak character substitution progression",
                confidence=confidence,
                examples=[r[0] for r in relevant[:3]],
                passwords_involved=[r[0] for r in relevant]
            )

    return None


def detect_minimal_changes(passwords: list[str]) -> PatternMatch | None:
    """
    Detect minimal character changes between passwords.
    e.g., Sunshine1 → Sunsh1ne1 → Sunsh!ne1
    """
    if len(passwords) < 2:
        return None

    minimal_change_pairs = []

    for i in range(len(passwords) - 1):
        pwd1, pwd2 = passwords[i], passwords[i+1]

        # Calculate edit distance (simple character difference count)
        if len(pwd1) == len(pwd2):
            diff_count = sum(1 for a, b in zip(pwd1, pwd2) if a != b)
            if 1 <= diff_count <= 2:
                minimal_change_pairs.append((pwd1, pwd2, diff_count))

    if len(minimal_change_pairs) >= 1:
        confidence = min(1.0, len(minimal_change_pairs) / 2.0)
        involved = set()
        for p1, p2, _ in minimal_change_pairs:
            involved.add(p1)
            involved.add(p2)

        return PatternMatch(
            pattern_type="minimal_changes",
            description="Minimal character changes between passwords",
            confidence=confidence,
            examples=[minimal_change_pairs[0][0], minimal_change_pairs[0][1]],
            passwords_involved=list(involved)
        )

    return None


def detect_password_reversion(passwords: list[str]) -> list[str]:
    """
    Detect if a user returned to a previously used password.

    Returns list of passwords that were reused.
    """
    seen = set()
    reused = []

    for pwd in passwords:
        if pwd in seen:
            reused.append(pwd)
        seen.add(pwd)

    return reused


def detect_hash_reuse_patterns(
    all_hashes: list[str],
    hash_to_password: dict[str, str | None] | None = None
) -> tuple[list[PatternMatch], dict[str, list[int]], int, int]:
    """
    Detect hash reuse patterns and convert them to PatternMatch objects.

    Returns:
        - List of PatternMatch objects for hash reuse
        - Dict mapping hash -> list of positions where it appears
        - Max consecutive streak length
        - Number of distinct hashes that were reused
    """
    if hash_to_password is None:
        hash_to_password = {}

    patterns = []
    hash_counts = Counter(all_hashes)

    # Track which positions each hash appears at
    hash_positions: dict[str, list[int]] = {}
    for idx, h in enumerate(all_hashes):
        if h not in hash_positions:
            hash_positions[h] = []
        hash_positions[h].append(idx)

    # Find consecutive duplicates and their streaks
    consecutive_streaks = []  # List of (hash, start_idx, length)
    i = 0
    while i < len(all_hashes):
        streak_start = i
        streak_hash = all_hashes[i]
        streak_len = 1
        while i + 1 < len(all_hashes) and all_hashes[i + 1] == streak_hash:
            streak_len += 1
            i += 1
        if streak_len >= 2:
            consecutive_streaks.append((streak_hash, streak_start, streak_len))
        i += 1

    max_consecutive = max((s[2] for s in consecutive_streaks), default=0)

    # Count distinct hashes that appear multiple times
    distinct_reused = sum(1 for count in hash_counts.values() if count > 1)

    # Create pattern for consecutive hash reuse (most severe)
    if consecutive_streaks:
        # Get examples - use passwords if cracked, otherwise hash labels
        examples = []
        for h, start, length in consecutive_streaks[:3]:
            pwd = hash_to_password.get(h)
            if pwd:
                examples.append(f"{pwd} ({length}x consecutive)")
            else:
                examples.append(f"Same hash {length}x consecutive")

        # Higher confidence for longer streaks and more instances
        confidence = min(1.0, 0.5 + (max_consecutive - 2) * 0.15 + len(consecutive_streaks) * 0.1)

        patterns.append(PatternMatch(
            pattern_type="consecutive_hash_reuse",
            description=f"Same password {max_consecutive}x in a row",
            confidence=confidence,
            examples=examples,
            passwords_involved=[]
        ))

    # Create pattern for non-consecutive hash reuse (password reversion)
    # Only if there's reuse that ISN'T already covered by consecutive
    non_consecutive_reuse = []
    for h, positions in hash_positions.items():
        if len(positions) >= 2:
            # Check if this is purely consecutive or has gaps
            has_gaps = False
            for j in range(len(positions) - 1):
                if positions[j + 1] - positions[j] > 1:
                    has_gaps = True
                    break
            if has_gaps:
                pwd = hash_to_password.get(h)
                non_consecutive_reuse.append((h, pwd, len(positions)))

    if non_consecutive_reuse:
        examples = []
        for h, pwd, count in non_consecutive_reuse[:3]:
            if pwd:
                examples.append(f"{pwd} (reused {count}x)")
            else:
                examples.append(f"Hash reused {count}x non-consecutively")

        confidence = min(1.0, 0.3 + len(non_consecutive_reuse) * 0.15 +
                        sum(c for _, _, c in non_consecutive_reuse) * 0.05)

        patterns.append(PatternMatch(
            pattern_type="password_reversion",
            description=f"Returned to previous password(s)",
            confidence=confidence,
            examples=examples,
            passwords_involved=[pwd for _, pwd, _ in non_consecutive_reuse if pwd]
        ))

    return patterns, hash_positions, max_consecutive, distinct_reused


def calculate_predictability_score(
    patterns: list[PatternMatch],
    reused: list[str],
    total_history_count: int = 0,
    max_consecutive_streak: int = 0,
    distinct_reused_hashes: int = 0
) -> float:
    """
    Calculate overall predictability score for a user's password history.

    Score ranges from 0.0 (unpredictable) to 1.0 (highly predictable).
    The score represents how easy it would be for an attacker to guess the
    user's NEXT password based on their observed password change patterns.

    Scoring logic:
    - 100% = ALL password changes are to the same hash (always resets to same password)
    - Patterns contribute based on type and confidence
    - Weights reflect attack difficulty: incrementing numbers (45%) are trivial to guess,
      while leet progression (15%) is harder to predict
    - Multiple patterns stack (e.g., season + year + special char = very high score)
    - Multiple distinct reused passwords = higher score (behavior pattern)

    Note: HIBP exposure is tracked separately but not included in predictability score
    since breach exposure doesn't help predict the user's NEXT password choice.

    Score interpretation:
    - 70%+ Critical: Next password is trivially guessable
    - 40-69% High: Strong patterns make guessing feasible
    - Below 40% Medium: Some patterns detected but harder to exploit
    """
    if not patterns and not reused and distinct_reused_hashes == 0:
        return 0.0

    score = 0.0

    # Check for 100% predictability: ALL entries are the same hash
    if max_consecutive_streak >= total_history_count and total_history_count >= 2:
        return 1.0  # 100% predictable - always same password

    # Pattern-based scoring - all patterns contribute
    # Weights reflect how easy it is to guess the NEXT password given the pattern
    pattern_weights = {
        "consecutive_hash_reuse": 0.55,   # Very severe - same password repeatedly
        "password_reversion": 0.35,       # Returned to old password - likely to do again
        "incrementing_number": 0.45,      # Trivial - just increment the number
        "year_increment": 0.45,           # Trivial - just increment the year
        "season_rotation": 0.40,          # Only 4 seasons (or 12 months) to try
        "special_char_rotation": 0.35,    # Limited special chars on keyboard (~10)
        "minimal_changes": 0.30,          # Small changes narrow the search space
        "base_word_persistence": 0.20,    # Same root word helps narrow guessing
        "leet_progression": 0.15,         # Harder to predict exact substitution
    }

    for pattern in patterns:
        weight = pattern_weights.get(pattern.pattern_type, 0.10)
        pattern_contribution = pattern.confidence * weight
        score += pattern_contribution

    # Multiple distinct reused passwords = more predictable behavior
    if distinct_reused_hashes > 1:
        multi_reuse_penalty = min(0.20, (distinct_reused_hashes - 1) * 0.08)
        score += multi_reuse_penalty

    # Password reuse penalty (cracked passwords showing reuse)
    if reused:
        reuse_penalty = min(0.15, len(reused) * 0.08)
        score += reuse_penalty

    # Cap at 99% if not 100% case
    return round(min(0.99, score), 2)


def analyze_user_history(
    username: str,
    history: list[PasswordHistoryEntry]
) -> UserHistoryAnalysis:
    """
    Analyze a single user's password history for patterns.

    Args:
        username: The username
        history: List of PasswordHistoryEntry objects (position 0 = current)

    Returns:
        UserHistoryAnalysis with detected patterns and predictability score
    """
    # Get cracked passwords in order (newest to oldest, excluding current)
    cracked_history = [h.password for h in history if h.position > 0 and h.password]
    current_entry = next((h for h in history if h.position == 0), None)

    current_password = current_entry.password if current_entry else None
    current_cracked = current_password is not None

    # Include current password in analysis if cracked
    all_passwords = []
    if current_cracked:
        all_passwords.append(current_password)
    all_passwords.extend(cracked_history)

    # Detect patterns
    patterns = []

    if len(all_passwords) >= 2:
        pattern_detectors = [
            detect_incrementing_number,
            detect_season_rotation,
            detect_special_char_rotation,
            detect_year_increment,
            detect_base_word_persistence,
            detect_leet_progression,
            detect_minimal_changes,
        ]

        for detector in pattern_detectors:
            result = detector(all_passwords)
            if result and result.confidence >= 0.3:
                patterns.append(result)

    # Detect password reversion (cracked passwords only)
    reused = detect_password_reversion(all_passwords)

    # Get all hashes (including current) for hash-based reuse detection
    all_hashes = [h.hash for h in sorted(history, key=lambda x: x.position)]

    # Build hash -> password mapping for pattern descriptions
    hash_to_password = {h.hash: h.password for h in history if h.password}

    # Detect hash reuse patterns (converts to PatternMatch objects)
    hash_reuse_patterns, hash_positions, max_consecutive, distinct_reused = detect_hash_reuse_patterns(
        all_hashes, hash_to_password
    )

    # Add hash reuse patterns to the pattern list
    patterns.extend(hash_reuse_patterns)

    # Track legacy fields for backwards compatibility
    hash_counts = Counter(all_hashes)
    hash_reuse_detected = any(count > 1 for count in hash_counts.values())
    hash_reuse_count = sum(count - 1 for count in hash_counts.values() if count > 1)
    consecutive_duplicates = max_consecutive >= 2
    consecutive_duplicate_count = max_consecutive

    # Calculate predictability score with all factors
    predictability = calculate_predictability_score(
        patterns=patterns,
        reused=reused,
        total_history_count=len(all_hashes),
        max_consecutive_streak=max_consecutive,
        distinct_reused_hashes=distinct_reused
    )

    # Build full history with hash info for displaying uncracked entries
    # Mark ALL entries that belong to a reused hash group (not just duplicates after first)
    full_history = []

    sorted_history = sorted(history, key=lambda x: x.position)
    for entry in sorted_history:
        hash_short = entry.hash[-8:] if entry.hash else "unknown"

        # Check if this hash appears multiple times (is part of a reuse group)
        positions_for_hash = hash_positions.get(entry.hash, [])
        is_in_reuse_group = len(positions_for_hash) > 1

        full_history.append({
            'position': entry.position,
            'password': entry.password,  # None if not cracked
            'hash_short': hash_short,
            'is_duplicate': is_in_reuse_group,  # Now marks ALL entries in reuse group
            'reuse_count': len(positions_for_hash) if is_in_reuse_group else 0
        })

    return UserHistoryAnalysis(
        username=username,
        total_historical=len([h for h in history if h.position > 0]),
        cracked_historical=len(cracked_history),
        current_password=current_password,
        current_cracked=current_cracked,
        historical_passwords=cracked_history,
        historical_hashes=all_hashes,
        full_history=full_history,  # Include all history entries for full context
        patterns_detected=patterns,
        predictability_score=predictability,
        password_reuse_detected=len(reused) > 0,
        reused_passwords=reused,
        hash_reuse_detected=hash_reuse_detected,
        hash_reuse_count=hash_reuse_count,
        consecutive_hash_duplicates=consecutive_duplicates,
        consecutive_duplicate_count=consecutive_duplicate_count
    )


def analyze_password_history(
    pwdump_data: list[dict[str, Any]] | None = None,
    add_data: list[dict[str, Any]] | None = None,
    cracked_hashes: dict[str, str] | None = None
) -> HistoryAnalysisResult:
    """
    Perform comprehensive password history analysis.

    Args:
        pwdump_data: Parsed pwdump line data (from validation result)
        add_data: Parsed ADD JSON entries (from validation result)
        cracked_hashes: Dict mapping NTLM hashes to cracked passwords

    Returns:
        HistoryAnalysisResult with aggregate statistics and findings
    """
    from app.timing_stats import get_timing_stats, TimingStats
    import time as time_module

    timing = get_timing_stats()
    start_time = time_module.time()

    if cracked_hashes is None:
        cracked_hashes = {}

    result = HistoryAnalysisResult()

    # Extract history from both sources
    all_history: dict[str, list[PasswordHistoryEntry]] = {}

    if pwdump_data:
        pwdump_history = extract_pwdump_history(pwdump_data, cracked_hashes)
        all_history.update(pwdump_history)

    if add_data:
        add_history = extract_add_history(add_data, cracked_hashes)
        # Merge, preferring ADD data if both present
        for username, history in add_history.items():
            all_history[username] = history

    result.users_with_history = len(all_history)

    # Analyze each user's history
    for username, history in all_history.items():
        result.total_users_analyzed += 1

        analysis = analyze_user_history(username, history)
        result.user_analyses.append(analysis)

        if analysis.cracked_historical > 0:
            result.users_with_cracked_history += 1

        if analysis.patterns_detected:
            result.users_with_patterns += 1

            # Count patterns
            for pattern in analysis.patterns_detected:
                pattern_type = pattern.pattern_type
                result.pattern_counts[pattern_type] = result.pattern_counts.get(pattern_type, 0) + 1

                # Store ALL examples for each pattern type (audit report needs complete data)
                if pattern_type not in result.pattern_examples:
                    result.pattern_examples[pattern_type] = []

                result.pattern_examples[pattern_type].append({
                    'username': username,
                    'examples': pattern.examples,
                    'confidence': pattern.confidence
                })

        # Track hash reuse stats
        if analysis.hash_reuse_detected:
            result.users_with_hash_reuse += 1
        if analysis.consecutive_hash_duplicates:
            result.users_with_consecutive_duplicates += 1

    # Sort users by predictability score and include ALL users with score > 0
    sorted_users = sorted(
        result.user_analyses,
        key=lambda x: x.predictability_score,
        reverse=True
    )
    result.top_predictable_users = [u for u in sorted_users if u.predictability_score > 0]

    # Record timing
    duration = time_module.time() - start_time
    item_count = len(pwdump_data) if pwdump_data else (len(add_data) if add_data else 0)
    timing.record_sample(
        operation=TimingStats.PASSWORD_HISTORY,
        duration_seconds=duration,
        item_count=item_count
    )

    return result




def history_analysis_to_dict(result: HistoryAnalysisResult) -> dict[str, Any]:
    """
    Convert HistoryAnalysisResult to a JSON-serializable dictionary.
    """
    return {
        'total_users_analyzed': result.total_users_analyzed,
        'users_with_history': result.users_with_history,
        'users_with_cracked_history': result.users_with_cracked_history,
        'users_with_patterns': result.users_with_patterns,
        'pattern_counts': result.pattern_counts,
        'pattern_examples': result.pattern_examples,
        'users_with_hash_reuse': result.users_with_hash_reuse,
        'users_with_consecutive_duplicates': result.users_with_consecutive_duplicates,
        'top_predictable_users': [
            {
                'username': u.username,
                'predictability_score': u.predictability_score,
                'total_historical': u.total_historical,
                'cracked_historical': u.cracked_historical,
                'current_password': u.current_password,
                'historical_passwords': u.historical_passwords[:5],  # Limit for display
                # Full history with hash info for displaying uncracked entries
                'full_history': u.full_history,
                'patterns': [
                    {
                        'type': p.pattern_type,
                        'description': p.description,
                        'confidence': p.confidence,
                        'examples': p.examples,
                        'passwords_involved': p.passwords_involved
                    }
                    for p in u.patterns_detected
                ],
                'password_reuse_detected': u.password_reuse_detected,
                'reused_passwords': u.reused_passwords,
                'hash_reuse_detected': u.hash_reuse_detected,
                'hash_reuse_count': u.hash_reuse_count,
                'consecutive_hash_duplicates': u.consecutive_hash_duplicates,
                'consecutive_duplicate_count': u.consecutive_duplicate_count
            }
            for u in result.top_predictable_users
        ]
    }


# Pattern type display names for UI
PATTERN_DISPLAY_NAMES = {
    'incrementing_number': 'Incrementing Number Suffix',
    'season_rotation': 'Season/Time Period Rotation',
    'special_char_rotation': 'Special Character Rotation',
    'year_increment': 'Year Increment Pattern',
    'base_word_persistence': 'Persistent Base Word',
    'leet_progression': 'Leet-speak Progression',
    'minimal_changes': 'Minimal Character Changes',
    'consecutive_hash_reuse': 'Consecutive Reuse',
    'password_reversion': 'Password Reversion',
}


def get_pattern_display_name(pattern_type: str) -> str:
    """Get human-readable display name for a pattern type."""
    return PATTERN_DISPLAY_NAMES.get(pattern_type, pattern_type.replace('_', ' ').title())
