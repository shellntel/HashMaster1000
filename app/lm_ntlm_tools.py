"""
LM-NTLM Hash Pairing Tools

Handles the workflow of:
1. Splitting LM hashes (32-char) into two 16-char halves
2. Tracking which halves belong to which user/NTLM hash
3. Combining cracked LM halves back together
4. Generating NTLM case-permutation attack files

LM Hash Background:
- LM (LAN Manager) hashes are legacy Windows password hashes
- Passwords are uppercased and split into two 7-character halves
- Each half is DES-encrypted separately, producing a 16-char hex hash
- The two halves are concatenated to form the 32-char LM hash
- Empty half hash: aad3b435b51404ee (represents empty or <7 char portion)
"""

import json
import os
import logging
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Empty LM half hash (represents no password or empty portion)
EMPTY_LM_HALF = "aad3b435b51404ee"
# Full empty LM hash (both halves empty)
EMPTY_LM_FULL = "aad3b435b51404eeaad3b435b51404ee"

import re

# Regex pattern for hashcat's $HEX[...] notation
HEX_PATTERN = re.compile(r'\$HEX\[([0-9a-fA-F]+)\]')


def decode_hex_sequences(plaintext: str) -> str:
    """
    Decode hashcat's $HEX[...] notation in a plaintext string.

    Hashcat uses $HEX[hexchars] to represent non-printable or special characters
    in cracked passwords. This function converts them back to actual bytes.

    Args:
        plaintext: String potentially containing $HEX[...] sequences

    Returns:
        Decoded string with hex sequences replaced by actual characters

    Examples:
        "LXCLQ2}$HEX[3c515a3a39]" -> "LXCLQ2}<QZ:9"
        "TEST$HEX[0d0a]END" -> "TEST\\r\\nEND" (carriage return + newline)
    """
    def hex_replace(match: re.Match) -> str:
        hex_str = match.group(1)
        try:
            # Decode hex pairs to bytes, then decode as latin-1 (preserves all bytes)
            decoded = bytes.fromhex(hex_str).decode('latin-1')
            return decoded
        except (ValueError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to decode HEX sequence '{hex_str}': {e}")
            return match.group(0)  # Return original on error

    return HEX_PATTERN.sub(hex_replace, plaintext)


@dataclass
class LMHalfMapping:
    """Mapping of a 16-char LM half to its source user/NTLM hash."""
    lm_half: str          # 16-char LM hash half (lowercase)
    position: int         # 1 = first half, 2 = second half
    full_lm: str          # Original 32-char LM hash
    username: str         # Username from pwdump
    ntlm_hash: str        # Associated NTLM hash for this user
    cracked_plaintext: Optional[str] = None  # Filled when cracked


@dataclass
class UserLMPair:
    """Tracks both LM halves for a single user.

    LM Hash Structure:
    - Passwords are padded to 14 chars with nulls, then split into two 7-char halves
    - Each half is DES-encrypted to produce a 16-char hex hash
    - If password is ≤7 chars, second half will be the empty hash (aad3b435b51404ee)
    - If first half cracks to 7 chars and second to <7, we know the ordering is correct
    """
    username: str
    full_lm: str
    ntlm_hash: str
    half1: str            # First 16-char half
    half2: str            # Second 16-char half
    half2_is_empty: bool = False  # True if half2 == empty hash (password ≤7 chars)
    plain1: Optional[str] = None  # Cracked plaintext for half1
    plain2: Optional[str] = None  # Cracked plaintext for half2
    combined_plaintext: Optional[str] = None  # Combined uppercase password
    ordering_confirmed: bool = False  # True if we've confirmed half ordering

    @property
    def both_cracked(self) -> bool:
        """Check if both halves are cracked (or second is empty)."""
        if self.half2_is_empty:
            return self.plain1 is not None
        return self.plain1 is not None and self.plain2 is not None

    @property
    def is_complete_password(self) -> bool:
        """Check if we have the complete password."""
        return self.combined_plaintext is not None

    def combine_halves(self) -> Optional[str]:
        """Combine cracked halves into full plaintext (uppercase).

        Uses length heuristics to confirm ordering:
        - If one half is 7 chars and other is <7, the 7-char half is first
        - If second half is empty hash, password is just the first half
        """
        if not self.both_cracked:
            return None

        p1 = self.plain1 or ""
        p2 = self.plain2 or ""

        # If second half is empty hash, password is just the first half
        if self.half2_is_empty:
            self.combined_plaintext = p1
            self.ordering_confirmed = True
            return self.combined_plaintext

        # Use length heuristics to confirm ordering
        len1, len2 = len(p1), len(p2)

        if len1 == 7 and len2 < 7:
            # First half is full (7 chars), second is partial - ordering confirmed
            self.combined_plaintext = p1 + p2
            self.ordering_confirmed = True
        elif len2 == 7 and len1 < 7:
            # This shouldn't happen with correct LM structure, but handle it
            # If second half is 7 chars and first is <7, something is unusual
            # Log a warning but proceed with standard ordering
            logger.warning(
                f"Unusual LM structure for {self.username}: "
                f"half1={len1} chars, half2={len2} chars. Using standard order."
            )
            self.combined_plaintext = p1 + p2
            self.ordering_confirmed = False
        elif len1 == 7 and len2 == 7:
            # Both halves are full 7 chars - password is exactly 14 chars
            self.combined_plaintext = p1 + p2
            self.ordering_confirmed = True
        else:
            # Both halves are <7 chars - unusual but possible with some hash types
            self.combined_plaintext = p1 + p2
            self.ordering_confirmed = False

        return self.combined_plaintext


@dataclass
class LMExtractionResult:
    """Result of extracting LM halves from a pwdump file."""
    # Unique LM halves to crack (excludes empty halves)
    unique_halves: list[str] = field(default_factory=list)
    # Mapping of half -> list of UserLMPair (a half may appear for multiple users)
    half_to_users: dict[str, list[int]] = field(default_factory=dict)  # half -> indices in user_pairs
    # All user pairs with LM hashes
    user_pairs: list[UserLMPair] = field(default_factory=list)
    # Stats
    total_users_with_lm: int = 0
    total_unique_halves: int = 0
    empty_halves_skipped: int = 0

    def to_dict(self) -> dict:
        """Serialize for JSON storage."""
        return {
            "unique_halves": self.unique_halves,
            "half_to_users": self.half_to_users,
            "user_pairs": [
                {
                    "username": p.username,
                    "full_lm": p.full_lm,
                    "ntlm_hash": p.ntlm_hash,
                    "half1": p.half1,
                    "half2": p.half2,
                    "half2_is_empty": p.half2_is_empty,
                    "plain1": p.plain1,
                    "plain2": p.plain2,
                    "combined_plaintext": p.combined_plaintext,
                    "ordering_confirmed": p.ordering_confirmed,
                }
                for p in self.user_pairs
            ],
            "total_users_with_lm": self.total_users_with_lm,
            "total_unique_halves": self.total_unique_halves,
            "empty_halves_skipped": self.empty_halves_skipped,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LMExtractionResult":
        """Deserialize from JSON."""
        result = cls()
        result.unique_halves = data.get("unique_halves", [])
        result.half_to_users = data.get("half_to_users", {})
        result.user_pairs = [
            UserLMPair(
                username=p["username"],
                full_lm=p["full_lm"],
                ntlm_hash=p["ntlm_hash"],
                half1=p["half1"],
                half2=p["half2"],
                half2_is_empty=p.get("half2_is_empty", False),
                plain1=p.get("plain1"),
                plain2=p.get("plain2"),
                combined_plaintext=p.get("combined_plaintext"),
                ordering_confirmed=p.get("ordering_confirmed", False),
            )
            for p in data.get("user_pairs", [])
        ]
        result.total_users_with_lm = data.get("total_users_with_lm", 0)
        result.total_unique_halves = data.get("total_unique_halves", 0)
        result.empty_halves_skipped = data.get("empty_halves_skipped", 0)
        return result


def split_lm_hash(lm_hash: str) -> tuple[str, str]:
    """
    Split a 32-char LM hash into two 16-char halves.

    Args:
        lm_hash: 32-character hex LM hash

    Returns:
        Tuple of (first_half, second_half), both lowercase
    """
    lm_hash = lm_hash.lower().strip()
    if len(lm_hash) != 32:
        raise ValueError(f"LM hash must be 32 characters, got {len(lm_hash)}")
    return lm_hash[:16], lm_hash[16:]


def extract_lm_halves_from_pwdump(pwdump_content: str) -> LMExtractionResult:
    """
    Extract LM hash halves from pwdump content.

    Parses pwdump format (user:rid:lm:ntlm:::) and extracts:
    - All unique 16-char LM halves (excluding empty halves)
    - Mapping of halves to users for result correlation

    Args:
        pwdump_content: Raw pwdump file content

    Returns:
        LMExtractionResult with halves and mappings
    """
    result = LMExtractionResult()
    seen_halves: set[str] = set()

    for line in pwdump_content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Parse pwdump format: user:rid:lm:ntlm:::
        parts = line.split(":")
        if len(parts) < 4:
            continue

        username = parts[0]
        lm_hash = parts[2].lower().strip()
        ntlm_hash = parts[3].lower().strip()

        # Skip if no LM hash or it's the empty marker
        if not lm_hash or len(lm_hash) != 32:
            continue
        if lm_hash == EMPTY_LM_FULL:
            continue

        # Split into halves
        half1, half2 = split_lm_hash(lm_hash)

        # Check if second half is empty (password is ≤7 chars)
        half2_is_empty = (half2 == EMPTY_LM_HALF)

        # Create user pair
        pair = UserLMPair(
            username=username,
            full_lm=lm_hash,
            ntlm_hash=ntlm_hash,
            half1=half1,
            half2=half2,
            half2_is_empty=half2_is_empty,
        )
        pair_idx = len(result.user_pairs)
        result.user_pairs.append(pair)
        result.total_users_with_lm += 1

        # Track unique halves and their user mappings
        for i, half in enumerate([half1, half2], start=1):
            if half == EMPTY_LM_HALF:
                result.empty_halves_skipped += 1
                continue

            if half not in seen_halves:
                seen_halves.add(half)
                result.unique_halves.append(half)
                result.half_to_users[half] = []

            result.half_to_users[half].append(pair_idx)

    result.total_unique_halves = len(result.unique_halves)
    return result


def generate_lm_hashfile(extraction: LMExtractionResult) -> str:
    """
    Generate a hash file for hashcat mode 3000 (LM halves).

    Args:
        extraction: LMExtractionResult from extract_lm_halves_from_pwdump

    Returns:
        String content for hashcat input file (one hash per line)
    """
    return "\n".join(extraction.unique_halves)


def process_lm_potfile(potfile_content: str, extraction: LMExtractionResult) -> LMExtractionResult:
    """
    Process cracked LM halves from potfile and update extraction result.

    Matches cracked hashes to users and combines halves where both are cracked.

    Args:
        potfile_content: Raw potfile content (hash:plaintext per line)
        extraction: LMExtractionResult with half mappings

    Returns:
        Updated LMExtractionResult with cracked plaintexts
    """
    # Parse potfile
    cracked: dict[str, str] = {}
    for line in potfile_content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Split on first colon (password may contain colons)
        if ":" not in line:
            continue
        hash_part, plaintext = line.split(":", 1)
        cracked[hash_part.lower().strip()] = plaintext

    # Update user pairs with cracked plaintexts
    for pair in extraction.user_pairs:
        if pair.half1 in cracked:
            pair.plain1 = cracked[pair.half1]
        if pair.half2 in cracked:
            pair.plain2 = cracked[pair.half2]

        # Combine if both cracked
        if pair.both_cracked:
            pair.combine_halves()

    return extraction


def get_combined_plaintexts(extraction: LMExtractionResult) -> list[dict]:
    """
    Get all users with combined LM plaintexts ready for NTLM attack.

    Returns:
        List of dicts with username, ntlm_hash, and combined_plaintext
    """
    return [
        {
            "username": pair.username,
            "ntlm_hash": pair.ntlm_hash,
            "combined_plaintext": pair.combined_plaintext,
        }
        for pair in extraction.user_pairs
        if pair.is_complete_password
    ]


def generate_ntlm_attack_files(
    extraction: LMExtractionResult,
    output_dir: str,
) -> dict[str, str]:
    """
    Generate files for NTLM case-permutation attack.

    Creates:
    - ntlm_hashes.txt: NTLM hashes to crack (unique hashes only)
    - lm_plaintexts.txt: Combined uppercase plaintexts for wordlist attack

    For hashcat, use:
        hashcat -m 1000 -a 0 ntlm_hashes.txt lm_plaintexts.txt -r toggle_rules.rule

    Args:
        extraction: LMExtractionResult with combined plaintexts
        output_dir: Directory to write output files

    Returns:
        Dict with paths to generated files
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Filter to only users with combined plaintexts
    ready_users = [p for p in extraction.user_pairs if p.is_complete_password]

    # Collect unique NTLM hashes (avoid duplicates since hashcat only needs each hash once)
    unique_ntlm_hashes = set()
    for pair in ready_users:
        unique_ntlm_hashes.add(pair.ntlm_hash)

    # Generate hash file (unique NTLM hashes only)
    hash_file = output_path / "ntlm_hashes.txt"
    with open(hash_file, "w") as f:
        for ntlm_hash in sorted(unique_ntlm_hashes):
            f.write(f"{ntlm_hash}\n")

    # Generate wordlist (uppercase plaintexts from LM)
    # - Decode any $HEX[...] sequences from hashcat output
    # - Include both orderings (p1+p2 and p2+p1) when ordering is uncertain
    # - Use a set to avoid duplicates in the wordlist
    # - IMPORTANT: Write with latin-1 encoding to preserve extended ASCII chars
    wordlist_file = output_path / "lm_plaintexts.txt"
    hex_decoded_count = 0
    alternate_orderings_added = 0
    seen_plaintexts: set[str] = set()

    # Use latin-1 encoding to match hashcat's expected format for extended ASCII
    with open(wordlist_file, "w", encoding="latin-1", errors="replace") as f:
        for pair in ready_users:
            plaintext = pair.combined_plaintext or ""

            # Decode HEX sequences if present
            if "$HEX[" in plaintext:
                plaintext = decode_hex_sequences(plaintext)
                hex_decoded_count += 1

            # Add the primary ordering if not seen
            if plaintext and plaintext not in seen_plaintexts:
                seen_plaintexts.add(plaintext)
                f.write(f"{plaintext}\n")

            # If ordering is not confirmed and we have two non-empty halves,
            # add the reversed ordering as well
            if not pair.ordering_confirmed and pair.plain1 and pair.plain2:
                p1 = pair.plain1
                p2 = pair.plain2

                # Decode HEX in individual halves if present
                if "$HEX[" in p1:
                    p1 = decode_hex_sequences(p1)
                if "$HEX[" in p2:
                    p2 = decode_hex_sequences(p2)

                # Create reversed ordering: p2 + p1
                reversed_plaintext = p2 + p1

                if reversed_plaintext and reversed_plaintext not in seen_plaintexts:
                    seen_plaintexts.add(reversed_plaintext)
                    f.write(f"{reversed_plaintext}\n")
                    alternate_orderings_added += 1

    if hex_decoded_count > 0:
        logger.info(f"Decoded $HEX sequences in {hex_decoded_count} plaintexts")
    if alternate_orderings_added > 0:
        logger.info(f"Added {alternate_orderings_added} alternate orderings for uncertain cases")

    # Generate user mapping for result correlation
    mapping_file = output_path / "user_mapping.json"
    with open(mapping_file, "w") as f:
        json.dump(
            [
                {
                    "username": p.username,
                    "ntlm_hash": p.ntlm_hash,
                    "lm_plaintext": p.combined_plaintext,
                    "plain1": p.plain1,
                    "plain2": p.plain2 if not p.half2_is_empty else None,
                    "password_length": len(p.combined_plaintext or ""),
                    "short_password": p.half2_is_empty,
                    "ordering_confirmed": p.ordering_confirmed,
                }
                for p in ready_users
            ],
            f,
            indent=2,
        )

    logger.info(
        f"Generated NTLM attack files: {len(unique_ntlm_hashes)} unique hashes, "
        f"{len(seen_plaintexts)} wordlist entries for {len(ready_users)} users"
    )

    return {
        "hash_file": str(hash_file),
        "wordlist_file": str(wordlist_file),
        "mapping_file": str(mapping_file),
        "user_count": len(ready_users),
        "unique_hashes": len(unique_ntlm_hashes),
        "wordlist_entries": len(seen_plaintexts),
        "alternate_orderings": alternate_orderings_added,
        "hex_decoded": hex_decoded_count,
    }


def save_extraction_result(extraction: LMExtractionResult, filepath: str) -> None:
    """Save extraction result to JSON file."""
    with open(filepath, "w") as f:
        json.dump(extraction.to_dict(), f, indent=2)


def load_extraction_result(filepath: str) -> LMExtractionResult:
    """Load extraction result from JSON file."""
    with open(filepath, "r") as f:
        return LMExtractionResult.from_dict(json.load(f))


def get_cracking_stats(extraction: LMExtractionResult) -> dict:
    """
    Get statistics about LM cracking progress.

    Returns:
        Dict with cracking statistics
    """
    total_pairs = len(extraction.user_pairs)
    both_cracked = sum(1 for p in extraction.user_pairs if p.both_cracked)
    half1_only = sum(1 for p in extraction.user_pairs if p.plain1 and not p.plain2 and not p.half2_is_empty)
    half2_only = sum(1 for p in extraction.user_pairs if p.plain2 and not p.plain1)
    neither = sum(1 for p in extraction.user_pairs if not p.plain1 and not p.plain2 and not p.half2_is_empty)

    # Count users with short passwords (≤7 chars, only need half1)
    short_passwords = sum(1 for p in extraction.user_pairs if p.half2_is_empty)
    short_passwords_cracked = sum(1 for p in extraction.user_pairs if p.half2_is_empty and p.plain1)

    # Count users with ordering confirmed
    ordering_confirmed = sum(1 for p in extraction.user_pairs if p.ordering_confirmed)

    # Count unique halves cracked
    cracked_halves = set()
    for pair in extraction.user_pairs:
        if pair.plain1:
            cracked_halves.add(pair.half1)
        if pair.plain2 and not pair.half2_is_empty:
            cracked_halves.add(pair.half2)

    return {
        "total_users_with_lm": total_pairs,
        "total_unique_halves": extraction.total_unique_halves,
        "unique_halves_cracked": len(cracked_halves),
        "users_both_halves_cracked": both_cracked,
        "users_half1_only": half1_only,
        "users_half2_only": half2_only,
        "users_neither_cracked": neither,
        "users_short_password": short_passwords,
        "users_short_password_cracked": short_passwords_cracked,
        "ordering_confirmed_count": ordering_confirmed,
        "ready_for_ntlm_attack": both_cracked,
    }
