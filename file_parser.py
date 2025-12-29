"""
file_parser.py - File parsing and validation module for Hash Master 1000

Supports parsing of pwdump/ntds files and hashcat potfiles with detailed
line-by-line validation and error reporting.

Formats supported:
- Standard pwdump: user::lm_hash:ntlm_hash:::
- With RID: user:RID:lm_hash:ntlm_hash:::
- dcsync: user:RID:lm_hash:ntlm_hash::: (status=Disabled)
"""

import re
import binascii
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple, List
import json

from hash_types import identify_hash_type, get_most_likely_type, is_ntlm_hash, HashType
from domain_utils import extract_domain_from_username, analyze_domains, DomainInfo, NO_DOMAIN


# Constants
HASH_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')

# Privileged AD Groups and RIDs for security analysis
PRIVILEGED_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
}

# Tier 0 groups (highest privilege)
TIER0_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
}

# Well-known privileged RIDs
PRIVILEGED_RIDS = {
    500,   # Built-in Administrator
    502,   # krbtgt (Kerberos service account)
}
STATUS_PATTERN = re.compile(r'\s*\(status=(\w+)\)\s*$')
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
BLANK_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


class FileFormat(Enum):
    """Detected file format for a parsed line."""
    STANDARD = "standard"  # No status suffix
    DCSYNC = "dcsync"      # Has (status=...) suffix
    UNKNOWN = "unknown"    # Could not determine format


class ErrorSeverity(Enum):
    """Severity level for validation errors."""
    FATAL = "fatal"      # Line cannot be processed
    WARNING = "warning"  # Line can be processed with caveats
    INFO = "info"        # Informational message


class PwdumpErrorCode:
    """Error codes for pwdump file validation."""
    WRONG_FIELD_COUNT = "WRONG_FIELD_COUNT"
    INVALID_LM_HASH = "INVALID_LM_HASH"
    INVALID_NTLM_HASH = "INVALID_NTLM_HASH"
    EMPTY_USERNAME = "EMPTY_USERNAME"
    EMPTY_LINE = "EMPTY_LINE"


class PotfileErrorCode:
    """Error codes for potfile validation."""
    WRONG_FIELD_COUNT = "WRONG_FIELD_COUNT"
    INVALID_HASH_FORMAT = "INVALID_HASH_FORMAT"
    NON_NTLM_HASH = "NON_NTLM_HASH"
    EMPTY_LINE = "EMPTY_LINE"


@dataclass
class ValidationError:
    """Represents a single validation issue with a line."""
    severity: ErrorSeverity
    code: str
    message: str
    field_index: Optional[int] = None


@dataclass
class ParsedLine:
    """Represents a single parsed line from a pwdump file."""
    line_number: int
    raw_line: str
    format_detected: FileFormat = FileFormat.UNKNOWN

    # Parsed fields
    username: Optional[str] = None
    rid: Optional[int] = None
    lm_hash: Optional[str] = None
    ntlm_hash: Optional[str] = None
    status: Optional[str] = None  # "Enabled", "Disabled", or None
    domain: Optional[str] = None  # Extracted domain from username (e.g., "CORP" from "CORP\\user")

    # Validation state
    is_valid: bool = True
    errors: list[ValidationError] = field(default_factory=list)

    # User selection for include/exclude
    included: bool = True


@dataclass
class PotfileEntry:
    """Represents a single entry from a potfile."""
    line_number: int
    raw_line: str
    ntlm_hash: Optional[str] = None
    password: Optional[str] = None
    is_valid: bool = True
    is_ntlm: bool = True  # Whether the hash is NTLM format
    detected_type: Optional[str] = None  # Detected hash type name
    detected_mode: Optional[int] = None  # Hashcat mode number
    errors: list[ValidationError] = field(default_factory=list)
    included: bool = True


@dataclass
class ValidationResult:
    """Complete validation results for a pwdump file."""
    filepath: str
    total_lines: int
    valid_lines: int
    warning_lines: int
    error_lines: int
    lines: list[ParsedLine]
    formats_detected: dict[str, int] = field(default_factory=dict)
    error_summary: dict[str, int] = field(default_factory=dict)
    domain_info: Optional[DomainInfo] = None  # Domain statistics for the file

    @property
    def has_fatal_errors(self) -> bool:
        """Check if any included line has fatal errors."""
        return any(
            any(e.severity == ErrorSeverity.FATAL for e in line.errors)
            for line in self.lines
            if line.included
        )

    @property
    def processable_lines(self) -> list[ParsedLine]:
        """Get lines that are valid and included."""
        return [l for l in self.lines if l.included and l.is_valid]


@dataclass
class PotfileValidationResult:
    """Complete validation results for a potfile."""
    filepath: str
    total_lines: int
    valid_lines: int
    error_lines: int
    ntlm_count: int = 0  # Count of valid NTLM hashes
    non_ntlm_count: int = 0  # Count of non-NTLM hashes (will be ignored)
    entries: list[PotfileEntry] = field(default_factory=list)
    error_summary: dict[str, int] = field(default_factory=dict)
    hash_type_summary: dict[str, dict] = field(default_factory=dict)  # Hash types found

    @property
    def processable_entries(self) -> list[PotfileEntry]:
        """Get entries that are valid NTLM and included."""
        return [e for e in self.entries if e.included and e.is_valid and e.is_ntlm]

    @property
    def has_non_ntlm_hashes(self) -> bool:
        """Check if potfile contains non-NTLM hashes."""
        return self.non_ntlm_count > 0


def is_valid_hash(hash_value: str) -> bool:
    """
    Validate that a string is a valid 32-character hex hash.

    Args:
        hash_value: The hash string to validate

    Returns:
        True if valid 32-char hex, False otherwise
    """
    if not hash_value:
        return False
    return bool(HASH_PATTERN.match(hash_value))


def validate_hash(hash_value: str, allow_empty: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validate a hash string and return detailed result.

    Args:
        hash_value: The hash string to validate
        allow_empty: If True, empty strings are considered valid

    Returns:
        Tuple of (is_valid, error_message or None)
    """
    if not hash_value:
        if allow_empty:
            return (True, None)
        return (False, "Hash is empty")

    if not HASH_PATTERN.match(hash_value):
        return (False, f"Invalid hash format: expected 32 hex characters, got {len(hash_value)} chars")

    return (True, None)


def extract_status_suffix(line: str) -> Tuple[str, Optional[str]]:
    """
    Check for and extract status suffix from a line.

    Args:
        line: The raw line to check

    Returns:
        Tuple of (line_without_suffix, status_value or None)
    """
    match = STATUS_PATTERN.search(line)
    if match:
        status = match.group(1)
        line_without_suffix = line[:match.start()]
        return (line_without_suffix, status)
    return (line, None)


def extract_rid(field_value: str) -> Optional[int]:
    """
    Extract RID from a field if it's numeric.

    Args:
        field_value: The field value to check

    Returns:
        Integer RID if field is numeric, None otherwise
    """
    if field_value and field_value.isdigit():
        return int(field_value)
    return None


def parse_pwdump_line(line_number: int, raw_line: str) -> ParsedLine:
    """
    Parse a single pwdump line into a ParsedLine object.

    Supports both standard pwdump and dcsync formats.

    Args:
        line_number: 1-based line number in the file
        raw_line: The raw line content

    Returns:
        ParsedLine object with parsed data and validation results
    """
    result = ParsedLine(
        line_number=line_number,
        raw_line=raw_line
    )

    # Handle empty lines
    stripped = raw_line.strip()
    if not stripped:
        result.is_valid = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.WARNING,
            code=PwdumpErrorCode.EMPTY_LINE,
            message="Empty line - will be skipped"
        ))
        return result

    # Check for and extract status suffix
    line_to_parse, status = extract_status_suffix(stripped)
    if status:
        result.status = status
        result.format_detected = FileFormat.DCSYNC
    else:
        result.format_detected = FileFormat.STANDARD

    # Split by colon
    parts = line_to_parse.split(':')

    # Validate field count
    if len(parts) != 7:
        result.is_valid = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=PwdumpErrorCode.WRONG_FIELD_COUNT,
            message=f"Expected 7 colon-separated fields, got {len(parts)}"
        ))
        return result

    # Parse username (field 0) and extract domain if present
    result.username = parts[0]
    if not result.username:
        result.is_valid = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=PwdumpErrorCode.EMPTY_USERNAME,
            message="Username field is empty",
            field_index=0
        ))
    else:
        # Extract domain from username (e.g., "CORP\\user" -> domain="CORP")
        domain, _ = extract_domain_from_username(result.username)
        result.domain = domain

    # Parse RID (field 1) - optional, extract if numeric
    result.rid = extract_rid(parts[1])

    # Validate LM hash (field 2) - can be empty
    result.lm_hash = parts[2]
    if result.lm_hash:
        lm_valid, lm_error = validate_hash(parts[2], allow_empty=True)
        if not lm_valid:
            result.errors.append(ValidationError(
                severity=ErrorSeverity.WARNING,
                code=PwdumpErrorCode.INVALID_LM_HASH,
                message=lm_error,
                field_index=2
            ))

    # Validate NTLM hash (field 3) - required
    result.ntlm_hash = parts[3]
    ntlm_valid, ntlm_error = validate_hash(parts[3])
    if not ntlm_valid:
        result.is_valid = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=PwdumpErrorCode.INVALID_NTLM_HASH,
            message=ntlm_error,
            field_index=3
        ))

    return result


def validate_pwdump_file(filepath: str) -> ValidationResult:
    """
    Validate an entire pwdump file and return detailed results.

    Args:
        filepath: Path to the pwdump file

    Returns:
        ValidationResult with all parsed lines and summary statistics
    """
    lines: list[ParsedLine] = []
    formats_detected: dict[str, int] = {f.value: 0 for f in FileFormat}
    error_summary: dict[str, int] = {}

    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, raw_line in enumerate(f, start=1):
            parsed = parse_pwdump_line(line_num, raw_line)
            lines.append(parsed)

            # Track format distribution
            formats_detected[parsed.format_detected.value] += 1

            # Track error distribution
            for error in parsed.errors:
                error_summary[error.code] = error_summary.get(error.code, 0) + 1

    valid_lines = sum(1 for l in lines if l.is_valid)
    warning_lines = sum(1 for l in lines if l.errors and l.is_valid)
    error_lines = sum(1 for l in lines if not l.is_valid)

    # Build domain statistics from valid lines
    valid_usernames = [l.username for l in lines if l.is_valid and l.username]
    domain_info = analyze_domains(valid_usernames)

    return ValidationResult(
        filepath=filepath,
        total_lines=len(lines),
        valid_lines=valid_lines,
        warning_lines=warning_lines,
        error_lines=error_lines,
        lines=lines,
        formats_detected=formats_detected,
        error_summary=error_summary,
        domain_info=domain_info
    )


def parse_potfile_line(line_number: int, raw_line: str) -> PotfileEntry:
    """
    Parse a single potfile line and identify hash type.

    Format: hash:password
    Note: Password may contain colons, so we only split on first colon.
    Identifies hash type and flags non-NTLM hashes.

    Args:
        line_number: 1-based line number in the file
        raw_line: The raw line content

    Returns:
        PotfileEntry object with parsed data and validation results
    """
    result = PotfileEntry(
        line_number=line_number,
        raw_line=raw_line
    )

    stripped = raw_line.strip()
    if not stripped:
        result.is_valid = False
        result.is_ntlm = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.WARNING,
            code=PotfileErrorCode.EMPTY_LINE,
            message="Empty line - will be skipped"
        ))
        return result

    # Skip comment lines
    if stripped.startswith('#'):
        result.is_valid = False
        result.is_ntlm = False
        result.included = False  # Auto-exclude comments
        result.errors.append(ValidationError(
            severity=ErrorSeverity.INFO,
            code="COMMENT_LINE",
            message="Comment line - will be skipped"
        ))
        return result

    # Split only on first colon (password may contain colons)
    parts = stripped.split(':', 1)

    if len(parts) != 2:
        result.is_valid = False
        result.is_ntlm = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=PotfileErrorCode.WRONG_FIELD_COUNT,
            message="Expected format 'hash:password'"
        ))
        return result

    hash_value = parts[0]
    result.ntlm_hash = hash_value
    result.password = parts[1]

    # Identify the hash type
    hash_type = get_most_likely_type(hash_value)

    if hash_type:
        result.detected_type = hash_type.name
        result.detected_mode = hash_type.mode

        # Check if it's NTLM (mode 1000) or could be NTLM (32-char hex)
        if hash_type.mode == 1000:
            # Confirmed NTLM
            result.is_ntlm = True
        elif is_ntlm_hash(hash_value):
            # 32-char hex could be NTLM or MD5 - assume NTLM for potfile context
            result.is_ntlm = True
            # If detected as MD5 but could be NTLM, prefer NTLM in this context
            if hash_type.mode == 0:  # MD5
                result.detected_type = "NTLM or MD5"
                result.detected_mode = 1000
        else:
            # Non-NTLM hash type
            result.is_ntlm = False
            result.is_valid = True  # Still valid, just not NTLM
            result.included = False  # Auto-exclude non-NTLM
            result.errors.append(ValidationError(
                severity=ErrorSeverity.INFO,
                code=PotfileErrorCode.NON_NTLM_HASH,
                message=f"Non-NTLM hash detected ({hash_type.name}, mode {hash_type.mode}) - will be ignored"
            ))
    else:
        # Unknown hash format
        result.is_ntlm = False
        result.is_valid = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.WARNING,
            code=PotfileErrorCode.INVALID_HASH_FORMAT,
            message="Unknown hash format - will be skipped"
        ))

    return result


def validate_potfile(filepath: str) -> PotfileValidationResult:
    """
    Validate an entire potfile and return detailed results.

    Identifies hash types and categorizes NTLM vs non-NTLM hashes.

    Args:
        filepath: Path to the potfile

    Returns:
        PotfileValidationResult with all parsed entries and summary statistics
    """
    entries: list[PotfileEntry] = []
    error_summary: dict[str, int] = {}
    hash_type_summary: dict[str, dict] = {}
    ntlm_count = 0
    non_ntlm_count = 0

    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, raw_line in enumerate(f, start=1):
            parsed = parse_potfile_line(line_num, raw_line)
            entries.append(parsed)

            # Track errors
            for error in parsed.errors:
                error_summary[error.code] = error_summary.get(error.code, 0) + 1

            # Track hash types
            if parsed.detected_type:
                type_key = parsed.detected_type.lower().replace(" ", "_").replace("/", "_")
                if type_key not in hash_type_summary:
                    hash_type_summary[type_key] = {
                        "name": parsed.detected_type,
                        "mode": parsed.detected_mode,
                        "count": 0,
                        "is_ntlm": parsed.is_ntlm
                    }
                hash_type_summary[type_key]["count"] += 1

            # Count NTLM vs non-NTLM
            if parsed.is_ntlm and parsed.is_valid:
                ntlm_count += 1
            elif parsed.is_valid and not parsed.is_ntlm:
                non_ntlm_count += 1

    valid_lines = sum(1 for e in entries if e.is_valid)
    error_lines = sum(1 for e in entries if not e.is_valid)

    return PotfileValidationResult(
        filepath=filepath,
        total_lines=len(entries),
        valid_lines=valid_lines,
        error_lines=error_lines,
        ntlm_count=ntlm_count,
        non_ntlm_count=non_ntlm_count,
        entries=entries,
        error_summary=error_summary,
        hash_type_summary=hash_type_summary
    )


def merge_potfile_entries(
    master_path: str,
    new_entries: list[PotfileEntry],
    create_if_missing: bool = True
) -> tuple[int, int, int]:
    """
    Merge new NTLM potfile entries into a master potfile.

    Only valid, included NTLM hashes are merged. Duplicate hashes (already in master)
    are skipped to avoid overwriting existing entries.

    Args:
        master_path: Path to the master potfile
        new_entries: List of PotfileEntry objects to merge
        create_if_missing: Create master file if it doesn't exist

    Returns:
        Tuple of (entries_added, entries_skipped_duplicate, total_in_master)
    """
    import os
    import fcntl
    import logging

    logger = logging.getLogger(__name__)

    # Filter to only valid, included NTLM entries
    ntlm_entries = [
        e for e in new_entries
        if e.is_valid and e.included and e.is_ntlm and e.ntlm_hash
    ]

    if not ntlm_entries and not os.path.exists(master_path):
        # Nothing to merge and no master exists yet
        return (0, 0, 0)

    # Ensure directory exists
    master_dir = os.path.dirname(master_path)
    if master_dir and not os.path.exists(master_dir):
        os.makedirs(master_dir, exist_ok=True)

    # Read existing hashes from master (if it exists)
    existing_hashes: set[str] = set()
    if os.path.exists(master_path):
        try:
            with open(master_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ':' in line:
                        hash_part = line.split(':', 1)[0].upper()
                        existing_hashes.add(hash_part)
        except Exception as e:
            logger.error(f"Error reading master potfile: {e}")
            # Continue anyway - we'll try to append

    entries_added = 0
    entries_skipped = 0

    # Append new entries to master file with file locking
    if ntlm_entries:
        try:
            with open(master_path, 'a', encoding='utf-8') as f:
                # Use file locking to prevent race conditions
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    for entry in ntlm_entries:
                        hash_upper = entry.ntlm_hash.upper()
                        if hash_upper not in existing_hashes:
                            # Write in standard potfile format: hash:password
                            password = entry.password or ""
                            f.write(f"{entry.ntlm_hash}:{password}\n")
                            existing_hashes.add(hash_upper)
                            entries_added += 1
                        else:
                            entries_skipped += 1
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Error writing to master potfile: {e}")
            raise

    total_in_master = len(existing_hashes)

    logger.info(
        f"Master potfile merge: {entries_added} added, "
        f"{entries_skipped} skipped (duplicate), {total_in_master} total"
    )

    return (entries_added, entries_skipped, total_in_master)


def get_potfile_entry_count(potfile_path: str) -> int:
    """
    Get the number of valid entries in a potfile.

    Args:
        potfile_path: Path to the potfile

    Returns:
        Number of valid hash:password entries, or 0 if file doesn't exist
    """
    import os

    if not os.path.exists(potfile_path):
        return 0

    count = 0
    try:
        with open(potfile_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    count += 1
    except Exception:
        return 0

    return count


def decode_hex_password(password: Optional[str]) -> Optional[str]:
    """
    Decode $HEX[] encoded passwords from hashcat.

    Args:
        password: The password string, possibly $HEX[] encoded

    Returns:
        Decoded password string, or None if input is None
    """
    if password is None:
        return None
    if password.startswith("$HEX[") and password.endswith("]"):
        hex_string = password[5:-1]
        try:
            return binascii.unhexlify(hex_string).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return password  # Return original if decode fails
    return password


def is_computer_account(username: str) -> bool:
    """
    Check if an account name represents a computer account.

    Computer accounts in Active Directory end with a $ character.
    They are typically all uppercase but we check case-insensitively.

    Args:
        username: The account name to check

    Returns:
        True if this appears to be a computer account
    """
    return username.endswith('$')


def build_account_data(
    pwdump_result: ValidationResult,
    potfile_result: PotfileValidationResult,
    ignore_disabled: bool = False,
    ignore_computer_accounts: bool = False
) -> dict[str, dict[str, Optional[str | int | bool]]]:
    """
    Build account_data dictionary from validated results.

    Only includes lines marked as 'included' by user.
    This replaces the process_files() logic in HashMaster1000.py.

    Args:
        pwdump_result: Validated pwdump file results
        potfile_result: Validated potfile results
        ignore_disabled: If True, skip accounts with status=Disabled
        ignore_computer_accounts: If True, skip accounts ending with $

    Returns:
        Dictionary mapping account names to account data
    """
    # Build hash->password lookup from potfile
    cracked_hashes: dict[str, str] = {BLANK_NTLM_HASH: ""}  # Blank password
    for entry in potfile_result.entries:
        if entry.included and entry.is_valid and entry.ntlm_hash:
            cracked_hashes[entry.ntlm_hash] = entry.password or ""

    account_data: dict[str, dict[str, Optional[str | int | bool]]] = {}

    for line in pwdump_result.lines:
        if not (line.included and line.is_valid):
            continue

        if not line.username:
            continue

        # Skip computer accounts if requested
        if ignore_computer_accounts and is_computer_account(line.username):
            continue

        # Skip disabled accounts if requested (only if status info is available)
        if ignore_disabled and line.status == "Disabled":
            continue

        account_entry: dict[str, Optional[str | int | bool]] = {
            "lm_hash": line.lm_hash,
            "ntlm_hash": line.ntlm_hash,
            "cracked_pw": None,
            "locked": None,
            "disabled": line.status == "Disabled" if line.status else None,
            "last_pw_change": None,
            "rid": line.rid,
        }

        # Check if NTLM hash is cracked
        if line.ntlm_hash and line.ntlm_hash in cracked_hashes:
            cracked_value = cracked_hashes[line.ntlm_hash]
            account_entry["cracked_pw"] = decode_hex_password(cracked_value)

        account_data[line.username] = account_entry

    return account_data


def build_account_data_with_cache(
    pwdump_result: ValidationResult,
    cracked_hashes: dict[str, str],
    ignore_disabled: bool = False,
    ignore_computer_accounts: bool = False
) -> dict[str, dict[str, Optional[str | int | bool]]]:
    """
    Build account_data dictionary using a pre-built cracked_hashes lookup.

    This is an optimized version of build_account_data() that accepts the
    cracked_hashes dictionary directly from the potfile cache, avoiding
    the need to iterate through 620K+ PotfileEntry objects.

    Args:
        pwdump_result: Validated pwdump file results
        cracked_hashes: Pre-built hash->password lookup dict from cache
        ignore_disabled: If True, skip accounts with status=Disabled
        ignore_computer_accounts: If True, skip accounts ending with $

    Returns:
        Dictionary mapping account names to account data
    """
    # Ensure blank password hash is included
    if BLANK_NTLM_HASH not in cracked_hashes:
        cracked_hashes = {BLANK_NTLM_HASH: "", **cracked_hashes}

    account_data: dict[str, dict[str, Optional[str | int | bool]]] = {}

    for line in pwdump_result.lines:
        if not (line.included and line.is_valid):
            continue

        if not line.username:
            continue

        # Skip computer accounts if requested
        if ignore_computer_accounts and is_computer_account(line.username):
            continue

        # Skip disabled accounts if requested (only if status info is available)
        if ignore_disabled and line.status == "Disabled":
            continue

        account_entry: dict[str, Optional[str | int | bool]] = {
            "lm_hash": line.lm_hash,
            "ntlm_hash": line.ntlm_hash,
            "cracked_pw": None,
            "locked": None,
            "disabled": line.status == "Disabled" if line.status else None,
            "last_pw_change": None,
            "rid": line.rid,
        }

        # Check if NTLM hash is cracked
        if line.ntlm_hash and line.ntlm_hash in cracked_hashes:
            cracked_value = cracked_hashes[line.ntlm_hash]
            account_entry["cracked_pw"] = decode_hex_password(cracked_value)

        account_data[line.username] = account_entry

    return account_data


# Serialization helpers for Flask session storage

def validation_result_to_dict(result: ValidationResult) -> dict:
    """
    Convert ValidationResult to JSON-serializable dict for session storage.

    Args:
        result: The ValidationResult to serialize

    Returns:
        Dictionary suitable for JSON serialization
    """
    return {
        "filepath": result.filepath,
        "total_lines": result.total_lines,
        "valid_lines": result.valid_lines,
        "warning_lines": result.warning_lines,
        "error_lines": result.error_lines,
        "formats_detected": result.formats_detected,
        "error_summary": result.error_summary,
        "domain_info": result.domain_info.to_dict() if result.domain_info else None,
        "lines": [
            {
                "line_number": l.line_number,
                "raw_line": l.raw_line,
                "format_detected": l.format_detected.value,
                "username": l.username,
                "rid": l.rid,
                "lm_hash": l.lm_hash,
                "ntlm_hash": l.ntlm_hash,
                "status": l.status,
                "domain": l.domain,
                "is_valid": l.is_valid,
                "included": l.included,
                "errors": [
                    {
                        "severity": e.severity.value,
                        "code": e.code,
                        "message": e.message,
                        "field_index": e.field_index
                    }
                    for e in l.errors
                ]
            }
            for l in result.lines
        ]
    }


def dict_to_validation_result(data: dict) -> ValidationResult:
    """
    Reconstruct ValidationResult from session dict.

    Args:
        data: The dictionary from session storage

    Returns:
        Reconstructed ValidationResult object
    """
    lines = []
    for l in data["lines"]:
        parsed_line = ParsedLine(
            line_number=l["line_number"],
            raw_line=l["raw_line"],
            format_detected=FileFormat(l["format_detected"]),
            username=l["username"],
            rid=l["rid"],
            lm_hash=l["lm_hash"],
            ntlm_hash=l["ntlm_hash"],
            status=l["status"],
            domain=l.get("domain"),  # May not exist in older sessions
            is_valid=l["is_valid"],
            included=l["included"],
            errors=[
                ValidationError(
                    severity=ErrorSeverity(e["severity"]),
                    code=e["code"],
                    message=e["message"],
                    field_index=e["field_index"]
                )
                for e in l["errors"]
            ]
        )
        lines.append(parsed_line)

    # Reconstruct domain_info if present
    domain_info = None
    if data.get("domain_info"):
        domain_info = DomainInfo.from_dict(data["domain_info"])

    return ValidationResult(
        filepath=data["filepath"],
        total_lines=data["total_lines"],
        valid_lines=data["valid_lines"],
        warning_lines=data["warning_lines"],
        error_lines=data["error_lines"],
        lines=lines,
        formats_detected=data["formats_detected"],
        error_summary=data["error_summary"],
        domain_info=domain_info
    )


def potfile_result_to_dict(result: PotfileValidationResult) -> dict:
    """
    Convert PotfileValidationResult to JSON-serializable dict.

    Args:
        result: The PotfileValidationResult to serialize

    Returns:
        Dictionary suitable for JSON serialization
    """
    return {
        "filepath": result.filepath,
        "total_lines": result.total_lines,
        "valid_lines": result.valid_lines,
        "error_lines": result.error_lines,
        "ntlm_count": result.ntlm_count,
        "non_ntlm_count": result.non_ntlm_count,
        "error_summary": result.error_summary,
        "hash_type_summary": result.hash_type_summary,
        "entries": [
            {
                "line_number": e.line_number,
                "raw_line": e.raw_line,
                "ntlm_hash": e.ntlm_hash,
                "password": e.password,
                "is_valid": e.is_valid,
                "is_ntlm": e.is_ntlm,
                "detected_type": e.detected_type,
                "detected_mode": e.detected_mode,
                "included": e.included,
                "errors": [
                    {
                        "severity": err.severity.value,
                        "code": err.code,
                        "message": err.message,
                        "field_index": err.field_index
                    }
                    for err in e.errors
                ]
            }
            for e in result.entries
        ]
    }


def dict_to_potfile_result(data: dict) -> PotfileValidationResult:
    """
    Reconstruct PotfileValidationResult from session dict.

    Args:
        data: The dictionary from session storage

    Returns:
        Reconstructed PotfileValidationResult object
    """
    entries = []
    for e in data["entries"]:
        entry = PotfileEntry(
            line_number=e["line_number"],
            raw_line=e["raw_line"],
            ntlm_hash=e["ntlm_hash"],
            password=e["password"],
            is_valid=e["is_valid"],
            is_ntlm=e.get("is_ntlm", True),  # Default to True for backwards compatibility
            detected_type=e.get("detected_type"),
            detected_mode=e.get("detected_mode"),
            included=e["included"],
            errors=[
                ValidationError(
                    severity=ErrorSeverity(err["severity"]),
                    code=err["code"],
                    message=err["message"],
                    field_index=err["field_index"]
                )
                for err in e["errors"]
            ]
        )
        entries.append(entry)

    return PotfileValidationResult(
        filepath=data["filepath"],
        total_lines=data["total_lines"],
        valid_lines=data["valid_lines"],
        error_lines=data["error_lines"],
        ntlm_count=data.get("ntlm_count", 0),
        non_ntlm_count=data.get("non_ntlm_count", 0),
        entries=entries,
        error_summary=data["error_summary"],
        hash_type_summary=data.get("hash_type_summary", {})
    )


def get_potfile_hash_type_message(result: PotfileValidationResult) -> Optional[str]:
    """
    Generate a user-friendly message about hash types found in a potfile.

    Args:
        result: The potfile validation result

    Returns:
        A message string if non-NTLM hashes were found, None otherwise
    """
    if not result.has_non_ntlm_hashes:
        return None

    # Build list of non-NTLM hash types found
    non_ntlm_types = []
    for type_key, info in result.hash_type_summary.items():
        if not info.get("is_ntlm", True):
            non_ntlm_types.append(f"{info['name']} ({info['count']})")

    if not non_ntlm_types:
        return None

    type_list = ", ".join(non_ntlm_types)
    return (
        f"{result.non_ntlm_count} non-NTLM hash(es) will be ignored: {type_list}. "
        f"{result.ntlm_count} NTLM hash(es) will be used for analysis."
    )


def get_potfile_summary(result: PotfileValidationResult) -> dict:
    """
    Generate a summary of potfile contents for display to users.

    Args:
        result: The potfile validation result

    Returns:
        Dictionary with summary information
    """
    return {
        "total_lines": result.total_lines,
        "valid_entries": result.valid_lines,
        "ntlm_hashes": result.ntlm_count,
        "non_ntlm_hashes": result.non_ntlm_count,
        "error_lines": result.error_lines,
        "hash_types_found": [
            {
                "name": info["name"],
                "mode": info["mode"],
                "count": info["count"],
                "usable": info.get("is_ntlm", False)
            }
            for info in result.hash_type_summary.values()
        ],
        "has_non_ntlm_warning": result.has_non_ntlm_hashes,
        "warning_message": get_potfile_hash_type_message(result)
    }


# =============================================================================
# ADD (Active Directory Dumper) JSON Format Support
# =============================================================================

class ADDErrorCode:
    """Error codes for ADD JSON file validation."""
    INVALID_JSON = "INVALID_JSON"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_HASH_FORMAT = "INVALID_HASH_FORMAT"
    EMPTY_USERS = "EMPTY_USERS"


def is_add_json_file(filepath: str) -> bool:
    """
    Detect if a file is ADD JSON format by checking for characteristic fields.

    ADD JSON files have:
    - Valid JSON structure
    - "Users" array field
    - Domain policy fields like "Name", "PullDate", "MinPasswordLength"

    Args:
        filepath: Path to file to check

    Returns:
        True if file appears to be ADD JSON format, False otherwise
    """
    # First check file extension as a quick filter
    if not filepath.lower().endswith('.json'):
        return False

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Read first 4KB to detect format without loading entire file
            content = f.read(4096)

        # Try to parse as JSON
        # For detection, we need to load enough to see the structure
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check for characteristic ADD JSON fields
        # Must have "Users" array - this is the defining characteristic
        if not isinstance(data.get("Users"), list):
            return False

        # Should also have at least some domain policy fields
        add_indicators = ["Name", "PullDate", "MinPasswordLength", "MaxPwdAge",
                         "PwdHistoryLength", "LockoutThreshold"]
        matches = sum(1 for field in add_indicators if field in data)

        # If we have Users array and at least 2 domain policy fields, it's ADD JSON
        return matches >= 2

    except (json.JSONDecodeError, IOError, OSError):
        return False


@dataclass
class DomainPolicy:
    """Domain password policy from ADD JSON."""
    domain_name: str
    pull_date: str
    min_password_length: int
    max_password_age: int  # days
    pwd_history_length: int
    pwd_properties: int
    lockout_duration: int  # minutes
    lockout_observation_window: int  # minutes
    lockout_threshold: int

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "domain_name": self.domain_name,
            "pull_date": self.pull_date,
            "min_password_length": self.min_password_length,
            "max_password_age": self.max_password_age,
            "pwd_history_length": self.pwd_history_length,
            "pwd_properties": self.pwd_properties,
            "lockout_duration": self.lockout_duration,
            "lockout_observation_window": self.lockout_observation_window,
            "lockout_threshold": self.lockout_threshold,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'DomainPolicy':
        """Reconstruct from dict."""
        return cls(
            domain_name=data["domain_name"],
            pull_date=data["pull_date"],
            min_password_length=data["min_password_length"],
            max_password_age=data["max_password_age"],
            pwd_history_length=data["pwd_history_length"],
            pwd_properties=data["pwd_properties"],
            lockout_duration=data["lockout_duration"],
            lockout_observation_window=data["lockout_observation_window"],
            lockout_threshold=data["lockout_threshold"],
        )


@dataclass
class ADDAccountEntry:
    """Extended account data from ADD JSON format."""
    # Identity
    sam_account_name: str
    logon_name: str  # domain\user format
    object_sid: str
    rid: int

    # NTLM hashes
    ntlm_hash: Optional[str]
    lm_hash: Optional[str]
    historical_hashes: List[str]  # Previous NTLM hashes

    # Group membership
    member_of: List[str]
    primary_group_id: int

    # Account status
    user_account_control: List[str]  # Flags like "NORMAL_ACCOUNT", "ACCOUNT_DISABLED"
    is_disabled: bool
    pwd_last_set: Optional[str]

    # Privilege detection (computed)
    is_privileged: bool = False
    privilege_level: str = "standard"  # "standard", "elevated", "tier0"
    privilege_groups: List[str] = field(default_factory=list)

    # Descriptive fields
    display_name: str = ""
    description: str = ""
    cn: str = ""

    # Validation
    is_valid: bool = True
    errors: List[ValidationError] = field(default_factory=list)
    included: bool = True

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "sam_account_name": self.sam_account_name,
            "logon_name": self.logon_name,
            "object_sid": self.object_sid,
            "rid": self.rid,
            "ntlm_hash": self.ntlm_hash,
            "lm_hash": self.lm_hash,
            "historical_hashes": self.historical_hashes,
            "member_of": self.member_of,
            "primary_group_id": self.primary_group_id,
            "user_account_control": self.user_account_control,
            "is_disabled": self.is_disabled,
            "pwd_last_set": self.pwd_last_set,
            "is_privileged": self.is_privileged,
            "privilege_level": self.privilege_level,
            "privilege_groups": self.privilege_groups,
            "display_name": self.display_name,
            "description": self.description,
            "cn": self.cn,
            "is_valid": self.is_valid,
            "included": self.included,
            "errors": [
                {
                    "severity": e.severity.value,
                    "code": e.code,
                    "message": e.message,
                    "field_index": e.field_index
                }
                for e in self.errors
            ]
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ADDAccountEntry':
        """Reconstruct from dict."""
        errors = [
            ValidationError(
                severity=ErrorSeverity(e["severity"]),
                code=e["code"],
                message=e["message"],
                field_index=e.get("field_index")
            )
            for e in data.get("errors", [])
        ]
        return cls(
            sam_account_name=data["sam_account_name"],
            logon_name=data["logon_name"],
            object_sid=data["object_sid"],
            rid=data["rid"],
            ntlm_hash=data.get("ntlm_hash"),
            lm_hash=data.get("lm_hash"),
            historical_hashes=data.get("historical_hashes", []),
            member_of=data.get("member_of", []),
            primary_group_id=data.get("primary_group_id", 0),
            user_account_control=data.get("user_account_control", []),
            is_disabled=data.get("is_disabled", False),
            pwd_last_set=data.get("pwd_last_set"),
            is_privileged=data.get("is_privileged", False),
            privilege_level=data.get("privilege_level", "standard"),
            privilege_groups=data.get("privilege_groups", []),
            display_name=data.get("display_name", ""),
            description=data.get("description", ""),
            cn=data.get("cn", ""),
            is_valid=data.get("is_valid", True),
            included=data.get("included", True),
            errors=errors
        )


@dataclass
class ADDValidationResult:
    """Complete validation results for ADD JSON file."""
    filepath: str
    domain_policy: Optional[DomainPolicy]
    total_users: int
    valid_users: int
    error_users: int

    # Privilege analysis
    privileged_count: int
    tier0_count: int  # Domain Admins, Enterprise Admins, etc.
    elevated_count: int  # Other privileged groups

    entries: List[ADDAccountEntry]
    errors: List[ValidationError] = field(default_factory=list)

    # Historical hash stats
    users_with_history: int = 0
    total_historical_hashes: int = 0

    # Domain stats
    unique_domains: List[str] = field(default_factory=list)

    # Raw user data for advanced analysis (Kerberoast, etc.)
    raw_users: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def domain_count(self) -> int:
        """Get count of unique domains."""
        return len(self.unique_domains) if self.unique_domains else 1

    @property
    def processable_entries(self) -> List[ADDAccountEntry]:
        """Get entries that are valid and included."""
        return [e for e in self.entries if e.included and e.is_valid]

    @property
    def has_errors(self) -> bool:
        """Check if there are any validation errors."""
        return len(self.errors) > 0 or self.error_users > 0


def extract_rid_from_sid(object_sid: str) -> Optional[int]:
    """
    Extract RID from ObjectSid string.

    Args:
        object_sid: SID like "S-1-5-21-3339965682-2664943134-2984951395-500"

    Returns:
        RID integer (e.g., 500) or None if invalid
    """
    if not object_sid or not object_sid.startswith("S-1-5-21-"):
        return None
    parts = object_sid.split("-")
    if len(parts) >= 8:
        try:
            return int(parts[-1])
        except ValueError:
            return None
    return None


def detect_privilege_level(
    member_of: List[str],
    rid: Optional[int],
    user_account_control: List[str] = None
) -> Tuple[str, List[str]]:
    """
    Detect privilege level based on group membership and RID.

    Args:
        member_of: List of group names the user is a member of
        rid: User's RID (e.g., 500 for Administrator)
        user_account_control: UAC flags (optional, for future use)

    Returns:
        Tuple of (privilege_level, list of matching privileged groups)
        privilege_level: "tier0", "elevated", or "standard"
    """
    matching_groups = [g for g in member_of if g in PRIVILEGED_GROUPS]

    # Tier 0: Domain Admins, Enterprise Admins, Schema Admins, or RID 500/502
    if any(g in TIER0_GROUPS for g in matching_groups) or (rid and rid in PRIVILEGED_RIDS):
        return ("tier0", matching_groups)

    # Elevated: Other privileged groups
    if matching_groups:
        return ("elevated", matching_groups)

    return ("standard", [])


def parse_add_ntlm_hash(hash_field: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse NTLMHash field from ADD JSON.

    The format can vary:
    - Single NTLM hash: "31d6cfe0d16ae931b73c59d7e0c089c0"
    - LM:NTLM format: "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    - NTLM:LM format (some tools): "31d6cfe0d16ae931b73c59d7e0c089c0:aad3b435b51404ee"

    The function detects the format by checking for the empty LM hash marker.

    Args:
        hash_field: The NTLMHash field value

    Returns:
        Tuple of (lm_hash, ntlm_hash)
    """
    if not hash_field:
        return (None, None)

    if ":" in hash_field:
        parts = hash_field.split(":")
        if len(parts) >= 2:
            hash1 = parts[0].strip() if parts[0] else None
            hash2 = parts[1].strip() if parts[1] else None

            # Validate both are proper 32-char hex hashes
            hash1_valid = hash1 and is_valid_hash(hash1)
            hash2_valid = hash2 and is_valid_hash(hash2)

            if hash1_valid and hash2_valid:
                # Both are valid hashes - determine which is LM and which is NTLM
                # The empty LM hash is a strong indicator of position
                if hash1 == EMPTY_LM_HASH:
                    # Format is LM:NTLM (hash1 is the empty LM)
                    return (hash1, hash2)
                elif hash2 == EMPTY_LM_HASH:
                    # Format is NTLM:LM (hash2 is the empty LM)
                    return (hash2, hash1)
                else:
                    # Neither is the empty LM hash - assume LM:NTLM order
                    # (standard pwdump format)
                    return (hash1, hash2)
            elif hash1_valid and not hash2_valid:
                # Only first hash is valid - treat as NTLM
                return (None, hash1)
            elif hash2_valid and not hash1_valid:
                # Only second hash is valid - treat as NTLM
                return (None, hash2)

    # Single hash - assume NTLM
    if is_valid_hash(hash_field):
        return (None, hash_field)

    return (None, None)


def parse_add_json(filepath: str) -> ADDValidationResult:
    """
    Parse ADD JSON format and return structured results.

    Args:
        filepath: Path to ADD JSON file

    Returns:
        ADDValidationResult with domain policy and all user entries
    """
    entries: List[ADDAccountEntry] = []
    errors: List[ValidationError] = []
    domain_policy: Optional[DomainPolicy] = None
    users_with_history = 0
    total_historical_hashes = 0
    privileged_count = 0
    tier0_count = 0
    elevated_count = 0
    domains_seen: set = set()

    # Load and parse JSON
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=ADDErrorCode.INVALID_JSON,
            message=f"Invalid JSON: {str(e)}"
        ))
        return ADDValidationResult(
            filepath=filepath,
            domain_policy=None,
            total_users=0,
            valid_users=0,
            error_users=0,
            privileged_count=0,
            tier0_count=0,
            elevated_count=0,
            entries=[],
            errors=errors
        )
    except Exception as e:
        errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=ADDErrorCode.INVALID_JSON,
            message=f"Error reading file: {str(e)}"
        ))
        return ADDValidationResult(
            filepath=filepath,
            domain_policy=None,
            total_users=0,
            valid_users=0,
            error_users=0,
            privileged_count=0,
            tier0_count=0,
            elevated_count=0,
            entries=[],
            errors=errors
        )

    # Extract domain policy
    try:
        # Parse MaxPwdAge - AD uses ~10675199 days to represent "never expires"
        # This corresponds to the FILETIME value when set to 0 (never expire)
        raw_max_pwd_age = data.get("MaxPwdAge", 0)
        try:
            if isinstance(raw_max_pwd_age, (int, float)):
                max_pwd_age = int(raw_max_pwd_age)
            else:
                # Handle string with possible decimal (e.g., "10675199.116730064")
                max_pwd_age = int(float(str(raw_max_pwd_age)))
        except (ValueError, TypeError):
            max_pwd_age = 0  # Default to "never expires" if parsing fails

        # If max_pwd_age exceeds 999 (AD's max configurable value), treat as "never expires" (0)
        if max_pwd_age > 999:
            max_pwd_age = 0

        domain_policy = DomainPolicy(
            domain_name=data.get("Name", "Unknown"),
            pull_date=data.get("PullDate", "Unknown"),
            min_password_length=int(data.get("MinPasswordLength", 0)),
            max_password_age=max_pwd_age,
            pwd_history_length=int(data.get("PwdHistoryLength", 0)),
            pwd_properties=int(data.get("PwdProperties", 0)),
            lockout_duration=int(data.get("LockoutDuration", 0)),
            lockout_observation_window=int(data.get("LockoutObservationWindow", 0)),
            lockout_threshold=int(data.get("LockoutThreshold", 0)),
        )
    except (KeyError, ValueError, TypeError) as e:
        errors.append(ValidationError(
            severity=ErrorSeverity.WARNING,
            code=ADDErrorCode.MISSING_REQUIRED_FIELD,
            message=f"Could not parse domain policy: {str(e)}"
        ))

    # Extract users
    users = data.get("Users", [])
    if not users:
        errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=ADDErrorCode.EMPTY_USERS,
            message="No users found in ADD JSON file"
        ))
        return ADDValidationResult(
            filepath=filepath,
            domain_policy=domain_policy,
            total_users=0,
            valid_users=0,
            error_users=0,
            privileged_count=0,
            tier0_count=0,
            elevated_count=0,
            entries=[],
            errors=errors
        )

    valid_users = 0
    error_users = 0

    for user in users:
        entry_errors: List[ValidationError] = []
        is_valid = True

        # Parse required fields
        sam_account_name = user.get("SamAccountName", "")
        if not sam_account_name:
            entry_errors.append(ValidationError(
                severity=ErrorSeverity.FATAL,
                code=ADDErrorCode.MISSING_REQUIRED_FIELD,
                message="Missing SamAccountName"
            ))
            is_valid = False

        # Parse SID and extract RID
        object_sid = user.get("ObjectSid", "")
        rid = extract_rid_from_sid(object_sid)
        if rid is None and object_sid:
            # Try to get from explicit RID field if available
            rid = user.get("RID")

        # Parse hash field
        lm_hash, ntlm_hash = parse_add_ntlm_hash(user.get("NTLMHash", ""))

        # Also check for separate LMHash field (some ADD exports have this)
        explicit_lm_hash = user.get("LMHash", "")
        if explicit_lm_hash and is_valid_hash(explicit_lm_hash):
            # Use explicit LMHash field if present and valid
            lm_hash = explicit_lm_hash

        if not ntlm_hash:
            entry_errors.append(ValidationError(
                severity=ErrorSeverity.WARNING,
                code=ADDErrorCode.INVALID_HASH_FORMAT,
                message="No valid NTLM hash found"
            ))

        # Parse historical hashes
        historical_hashes = []
        for hist_hash in user.get("HistoricalNTHashes", []):
            if hist_hash and is_valid_hash(hist_hash):
                historical_hashes.append(hist_hash)
        if historical_hashes:
            users_with_history += 1
            total_historical_hashes += len(historical_hashes)

        # Parse group membership
        member_of = user.get("MemberOf", [])
        if isinstance(member_of, str):
            member_of = [member_of] if member_of else []

        # Parse UAC flags
        user_account_control = user.get("UserAccountControl", [])
        if isinstance(user_account_control, str):
            user_account_control = [user_account_control] if user_account_control else []
        is_disabled = "ACCOUNT_DISABLED" in user_account_control

        # Detect privilege level
        privilege_level, privilege_groups = detect_privilege_level(member_of, rid, user_account_control)
        is_privileged = privilege_level != "standard"

        if is_privileged:
            privileged_count += 1
            if privilege_level == "tier0":
                tier0_count += 1
            else:
                elevated_count += 1

        # Extract domain from LogonName (format: DOMAIN\user)
        logon_name = user.get("LogonName", sam_account_name)
        if "\\" in logon_name:
            domain_part = logon_name.split("\\")[0].upper()
            if domain_part:
                domains_seen.add(domain_part)

        # Create entry
        entry = ADDAccountEntry(
            sam_account_name=sam_account_name,
            logon_name=logon_name,
            object_sid=object_sid,
            rid=rid if rid else 0,
            ntlm_hash=ntlm_hash,
            lm_hash=lm_hash,
            historical_hashes=historical_hashes,
            member_of=member_of,
            primary_group_id=user.get("PrimaryGroupId", 0),
            user_account_control=user_account_control,
            is_disabled=is_disabled,
            pwd_last_set=user.get("PwdLastSet"),
            is_privileged=is_privileged,
            privilege_level=privilege_level,
            privilege_groups=privilege_groups,
            display_name=user.get("DisplayName", ""),
            description=user.get("Description", ""),
            cn=user.get("CN", ""),
            is_valid=is_valid,
            errors=entry_errors,
            included=True
        )
        entries.append(entry)

        if is_valid:
            valid_users += 1
        else:
            error_users += 1

    return ADDValidationResult(
        filepath=filepath,
        domain_policy=domain_policy,
        total_users=len(entries),
        valid_users=valid_users,
        error_users=error_users,
        privileged_count=privileged_count,
        tier0_count=tier0_count,
        elevated_count=elevated_count,
        entries=entries,
        errors=errors,
        users_with_history=users_with_history,
        total_historical_hashes=total_historical_hashes,
        unique_domains=sorted(list(domains_seen)),
        raw_users=users  # Preserve raw user dicts for Kerberoast analysis
    )


def add_to_account_data(
    add_result: ADDValidationResult,
    potfile_result: Optional[PotfileValidationResult],
    ignore_disabled: bool = False,
    ignore_computer_accounts: bool = False
) -> Tuple[dict, dict]:
    """
    Convert ADD data to account_data format compatible with existing analysis.

    Args:
        add_result: Validated ADD JSON results
        potfile_result: Validated potfile results (optional)
        ignore_disabled: If True, skip disabled accounts
        ignore_computer_accounts: If True, skip computer accounts

    Returns:
        Tuple of (account_data, privileged_findings)
        - account_data: Standard format for HashMaster1000 analysis
        - privileged_findings: Enhanced data for privileged account report
    """
    # Build hash->password lookup from potfile
    cracked_hashes: dict[str, str] = {BLANK_NTLM_HASH: ""}
    if potfile_result:
        for entry in potfile_result.entries:
            if entry.included and entry.is_valid and entry.ntlm_hash:
                cracked_hashes[entry.ntlm_hash] = entry.password or ""

    account_data: dict = {}
    privileged_findings = {
        "tier0": [],
        "elevated": [],
        "summary": {
            "total_privileged": 0,
            "tier0_count": 0,
            "elevated_count": 0,
            "cracked_privileged": 0,
            "cracked_tier0": 0,
        }
    }

    for entry in add_result.entries:
        if not entry.included or not entry.is_valid:
            continue

        # Skip computer accounts if requested
        if ignore_computer_accounts and is_computer_account(entry.sam_account_name):
            continue

        # Skip disabled accounts if requested
        if ignore_disabled and entry.is_disabled:
            continue

        # Check if current hash is cracked
        cracked_pw = None
        if entry.ntlm_hash and entry.ntlm_hash in cracked_hashes:
            cracked_value = cracked_hashes[entry.ntlm_hash]
            if cracked_value is not None:
                cracked_pw = decode_hex_password(cracked_value)

        # Build standard account_data entry
        account_entry = {
            "lm_hash": entry.lm_hash,
            "ntlm_hash": entry.ntlm_hash,
            "cracked_pw": cracked_pw,
            "locked": None,
            "disabled": entry.is_disabled,
            "last_pw_change": entry.pwd_last_set,
            "rid": entry.rid,
            # Extended fields from ADD
            "is_privileged": entry.is_privileged,
            "privilege_level": entry.privilege_level,
            "privilege_groups": entry.privilege_groups,
            "member_of": entry.member_of,
            "historical_hashes": entry.historical_hashes,
        }

        account_data[entry.sam_account_name] = account_entry

        # Track privileged account findings
        if entry.is_privileged:
            privileged_findings["summary"]["total_privileged"] += 1
            priv_entry = {
                "username": entry.sam_account_name,
                "rid": entry.rid,
                "groups": entry.privilege_groups,
                "cracked": cracked_pw is not None,
                "password": cracked_pw if cracked_pw else None,
                "disabled": entry.is_disabled,
            }

            if entry.privilege_level == "tier0":
                privileged_findings["tier0"].append(priv_entry)
                privileged_findings["summary"]["tier0_count"] += 1
                if cracked_pw is not None:
                    privileged_findings["summary"]["cracked_tier0"] += 1
                    privileged_findings["summary"]["cracked_privileged"] += 1
            else:
                privileged_findings["elevated"].append(priv_entry)
                privileged_findings["summary"]["elevated_count"] += 1
                if cracked_pw is not None:
                    privileged_findings["summary"]["cracked_privileged"] += 1

    return account_data, privileged_findings


def analyze_historical_hashes(
    add_result: ADDValidationResult,
    cracked_hashes: dict[str, str]
) -> dict:
    """
    Analyze historical hashes for password reuse.

    Args:
        add_result: Validated ADD JSON results
        cracked_hashes: Dict mapping NTLM hashes to cracked passwords

    Returns:
        Dictionary with historical hash analysis results
    """
    results = {
        "users_analyzed": 0,
        "users_with_history": 0,
        "historical_passwords_cracked": 0,
        "password_reuse_violations": [],
        "history_compliance_failures": [],
    }

    for entry in add_result.entries:
        if not entry.included or not entry.is_valid:
            continue

        results["users_analyzed"] += 1

        if not entry.historical_hashes:
            continue

        results["users_with_history"] += 1

        # Check current password
        current_cracked = entry.ntlm_hash and entry.ntlm_hash in cracked_hashes
        current_password = cracked_hashes.get(entry.ntlm_hash) if current_cracked else None

        # Check historical hashes
        historical_cracked = []
        for hist_hash in entry.historical_hashes:
            if hist_hash in cracked_hashes:
                historical_cracked.append(cracked_hashes[hist_hash])
                results["historical_passwords_cracked"] += 1

        # Check for password reuse (current password was used before)
        if current_password and current_password in historical_cracked:
            results["password_reuse_violations"].append({
                "username": entry.sam_account_name,
                "current_password": current_password,
                "previous_passwords": historical_cracked,
                "violation_type": "current_reused_from_history"
            })

        # Check for history compliance failures (same password used multiple times in history)
        password_counts = {}
        for pw in historical_cracked:
            password_counts[pw] = password_counts.get(pw, 0) + 1
        for pw, count in password_counts.items():
            if count > 1:
                results["history_compliance_failures"].append({
                    "username": entry.sam_account_name,
                    "reused_password": pw,
                    "reuse_count": count
                })

    return results


def detect_privilege_password_sharing(
    add_result: ADDValidationResult,
    cracked_hashes: dict[str, str]
) -> List[dict]:
    """
    Detect when privileged accounts share passwords with standard accounts.

    Args:
        add_result: Validated ADD JSON results
        cracked_hashes: Dict mapping NTLM hashes to cracked passwords

    Returns:
        List of password sharing findings
    """
    findings = []

    # Build hash->accounts mapping
    hash_to_accounts: dict[str, List[ADDAccountEntry]] = {}
    for entry in add_result.entries:
        if not entry.included or not entry.is_valid or not entry.ntlm_hash:
            continue
        if entry.ntlm_hash not in hash_to_accounts:
            hash_to_accounts[entry.ntlm_hash] = []
        hash_to_accounts[entry.ntlm_hash].append(entry)

    # Find hashes shared between privileged and standard accounts
    for ntlm_hash, accounts in hash_to_accounts.items():
        if len(accounts) < 2:
            continue

        privileged = [a for a in accounts if a.is_privileged]
        standard = [a for a in accounts if not a.is_privileged]

        if privileged and standard:
            for priv_account in privileged:
                finding = {
                    "finding_type": "privilege_to_standard_sharing",
                    "severity": "critical",
                    "privileged_account": priv_account.sam_account_name,
                    "privilege_level": priv_account.privilege_level,
                    "privilege_groups": priv_account.privilege_groups,
                    "standard_accounts": [a.sam_account_name for a in standard],
                    "shared_hash": ntlm_hash,
                    "password_cracked": ntlm_hash in cracked_hashes,
                    "password": cracked_hashes.get(ntlm_hash) if ntlm_hash in cracked_hashes else None,
                }
                findings.append(finding)

    return findings


def add_result_to_dict(result: ADDValidationResult) -> dict:
    """
    Convert ADDValidationResult to JSON-serializable dict for session storage.

    Args:
        result: The ADDValidationResult to serialize

    Returns:
        Dictionary suitable for JSON serialization
    """
    return {
        "filepath": result.filepath,
        "domain_policy": result.domain_policy.to_dict() if result.domain_policy else None,
        "total_users": result.total_users,
        "valid_users": result.valid_users,
        "error_users": result.error_users,
        "privileged_count": result.privileged_count,
        "tier0_count": result.tier0_count,
        "elevated_count": result.elevated_count,
        "users_with_history": result.users_with_history,
        "total_historical_hashes": result.total_historical_hashes,
        "unique_domains": result.unique_domains,
        "entries": [e.to_dict() for e in result.entries],
        "errors": [
            {
                "severity": e.severity.value,
                "code": e.code,
                "message": e.message,
                "field_index": e.field_index
            }
            for e in result.errors
        ],
        "raw_users": result.raw_users  # Preserve for Kerberoast analysis
    }


def dict_to_add_result(data: dict) -> ADDValidationResult:
    """
    Reconstruct ADDValidationResult from session dict.

    Args:
        data: The dictionary from session storage

    Returns:
        Reconstructed ADDValidationResult object
    """
    domain_policy = None
    if data.get("domain_policy"):
        domain_policy = DomainPolicy.from_dict(data["domain_policy"])

    entries = [ADDAccountEntry.from_dict(e) for e in data.get("entries", [])]

    errors = [
        ValidationError(
            severity=ErrorSeverity(e["severity"]),
            code=e["code"],
            message=e["message"],
            field_index=e.get("field_index")
        )
        for e in data.get("errors", [])
    ]

    return ADDValidationResult(
        filepath=data["filepath"],
        domain_policy=domain_policy,
        total_users=data["total_users"],
        valid_users=data["valid_users"],
        error_users=data["error_users"],
        privileged_count=data["privileged_count"],
        tier0_count=data["tier0_count"],
        elevated_count=data.get("elevated_count", data["privileged_count"] - data["tier0_count"]),
        entries=entries,
        errors=errors,
        users_with_history=data.get("users_with_history", 0),
        total_historical_hashes=data.get("total_historical_hashes", 0),
        unique_domains=data.get("unique_domains", []),
        raw_users=data.get("raw_users", [])  # Restore for Kerberoast analysis
    )
