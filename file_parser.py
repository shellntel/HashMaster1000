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
from typing import Optional, Tuple, List

from hash_types import identify_hash_type, get_most_likely_type, is_ntlm_hash, HashType


# Constants
HASH_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
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

    # Parse username (field 0)
    result.username = parts[0]
    if not result.username:
        result.is_valid = False
        result.errors.append(ValidationError(
            severity=ErrorSeverity.FATAL,
            code=PwdumpErrorCode.EMPTY_USERNAME,
            message="Username field is empty",
            field_index=0
        ))

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

    return ValidationResult(
        filepath=filepath,
        total_lines=len(lines),
        valid_lines=valid_lines,
        warning_lines=warning_lines,
        error_lines=error_lines,
        lines=lines,
        formats_detected=formats_detected,
        error_summary=error_summary
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


def decode_hex_password(password: str) -> str:
    """
    Decode $HEX[] encoded passwords from hashcat.

    Args:
        password: The password string, possibly $HEX[] encoded

    Returns:
        Decoded password string
    """
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

    return ValidationResult(
        filepath=data["filepath"],
        total_lines=data["total_lines"],
        valid_lines=data["valid_lines"],
        warning_lines=data["warning_lines"],
        error_lines=data["error_lines"],
        lines=lines,
        formats_detected=data["formats_detected"],
        error_summary=data["error_summary"]
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
