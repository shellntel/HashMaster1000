# Hash Master 1000 - Application Package
# This package contains the core application modules

from .file_parser import (
    validate_pwdump_file,
    validate_potfile,
    parse_pwdump_line,
    parse_potfile_line,
    build_account_data,
)
from .session_manager import get_session_manager, SessionManager, SessionMetadata
from .password_analysis_tools import crack_stats, substring_analysis, dictionary_analysis
from .hibp_checker import check_hashes_hibp, check_hashes_local, get_local_db_status
from .timing_stats import get_timing_stats, TimingStats

__all__ = [
    # File parsing
    "validate_pwdump_file",
    "validate_potfile",
    "parse_pwdump_line",
    "parse_potfile_line",
    "build_account_data",
    # Session management
    "get_session_manager",
    "SessionManager",
    "SessionMetadata",
    # Password analysis
    "crack_stats",
    "substring_analysis",
    "dictionary_analysis",
    # HIBP
    "check_hashes_hibp",
    "check_hashes_local",
    "get_local_db_status",
    # Timing
    "get_timing_stats",
    "TimingStats",
]
