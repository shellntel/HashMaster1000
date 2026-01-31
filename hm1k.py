import os
import re
import subprocess
import sys
import time
import json
import logging
import bcrypt
import zipfile
import io
from pathlib import Path
from dotenv import load_dotenv
from flask_compress import Compress
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    send_file,
    send_from_directory,
    abort,
    make_response,
    Response,
    session,
)
from flask.wrappers import Response as FlaskResponse
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# werkzeug.security not used - using bcrypt directly for password verification
from datetime import datetime, timedelta, timezone
from typing import Any, cast
# Import file parser module for validation
from app import file_parser
# Import session manager for multi-session support
from app.session_manager import get_session_manager, SessionMetadata
# Import domain utilities for domain filtering
from app.domain_utils import filter_accounts_by_domain, detect_cross_domain_password_reuse
# Import password history analysis module
from app import password_history
# Import potfile cache for efficient master potfile operations
from app.potfile_cache import get_master_cache, build_cracked_hashes_fast, get_cracked_hashes_direct
# Import LM-NTLM pairing tools for LM hash cracking workflow
from app import lm_ntlm_tools
# Import LM->NTLM multi-step workflow manager
from app.lm_ntlm_workflow import LMtoNTLMWorkflow, WorkflowStep
from app.job_templates import JobTemplateManager, JobTemplate, JobSequence, JobSequenceStep
from app.performance_tracker import (
    PerformanceTracker, BenchmarkResult, JobPerformanceMetrics, GPUMetrics, BENCHMARK_HASH_MODES
)
from app.resource_manager import ResourceManager, Resource
from app.potfile_manager import PotfileManager
from app.mask_manager import MaskManager, Mask, MaskGroup, format_keyspace, format_duration
from agent_state_db import get_agent_db, AgentStateDB

# Helper function to ensure SECRET_KEY exists in .env file
def _ensure_secret_key() -> None:
    """
    Checks if SECRET_KEY is set in the .env file.
    If not, generates a new one and appends it to the .env file.
    """
    import secrets

    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

    # First, check if .env file exists and contains SECRET_KEY
    secret_key_exists = False
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    # Check for SECRET_KEY= that's not commented out
                    stripped = line.strip()
                    if stripped.startswith("SECRET_KEY=") and not stripped.startswith("#"):
                        # Check if it has a value (not just SECRET_KEY= or SECRET_KEY="")
                        value = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                        if value and value != "your-secret-key-here":
                            secret_key_exists = True
                            break
        except IOError:
            pass

    if not secret_key_exists:
        # Generate a new secret key
        new_key = secrets.token_hex(32)
        print(f"\n--> No SECRET_KEY found in .env file. Generating new key...")

        try:
            # Append to .env file (create if doesn't exist)
            with open(env_path, "a", encoding="utf-8") as f:
                f.write(f'\nSECRET_KEY="{new_key}"\n')
            print(f"--> SECRET_KEY has been added to {env_path}")
        except IOError as e:
            raise ValueError(f"Could not write SECRET_KEY to .env file: {e}")

# Ensure SECRET_KEY exists before loading environment
_ensure_secret_key()

# Load environment variables at module level so they're available for route handlers
# Use override=True to ensure .env file values take precedence over any cached env vars
load_dotenv(override=True)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")

# Default file paths (optional - pre-populates form fields)
DEFAULT_PWDUMP_PATH = os.getenv("DEFAULT_PWDUMP_PATH", "")
DEFAULT_POTFILE_PATH = os.getenv("DEFAULT_POTFILE_PATH", "")
DEFAULT_ADD_JSON_PATH = os.getenv("DEFAULT_ADD_JSON_PATH", "")

# Master Potfile configuration
MASTER_POTFILE_ENABLED = os.getenv("MASTER_POTFILE_ENABLED", "false").lower() == "true"
MASTER_POTFILE_PATH = os.getenv("MASTER_POTFILE_PATH", "data/master.potfile")

# Advanced Options (experimental tools) configuration - DEPRECATED, use roles instead
# Kept for backwards compatibility, will be removed in future version
ADVANCED_OPTIONS_ENABLED = os.getenv("ADVANCED_OPTIONS_ENABLED", "false").lower() == "true"

# Multi-user mode configuration
MULTI_USER_ENABLED = os.getenv("MULTI_USER_ENABLED", "false").lower() == "true"
MULTI_USER_FILE = os.getenv("MULTI_USER_FILE", "data/users.json")

# Master potfile access for regular users (only applies when MULTI_USER_ENABLED)
MASTER_POTFILE_USER_ACCESS = os.getenv("MASTER_POTFILE_USER_ACCESS", "true").lower() == "true"

# Local file browser security - allowed paths (comma-separated)
LOCAL_FILE_ALLOWED_PATHS = [
    p.strip() for p in os.getenv("LOCAL_FILE_ALLOWED_PATHS", "/home/").split(",")
    if p.strip()
]


def validate_libraries() -> None:
    """Validate that all required libraries are installed."""
    required_libraries = {
        "Flask": "flask",
        "flask-login": "flask_login",
        "bcrypt": "bcrypt",
        "nltk": "nltk",
        "python-dotenv": "dotenv",
    }

    missing_libraries = []

    # Check each library for availability
    for install_name, import_name in required_libraries.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_libraries.append(install_name)

    if missing_libraries:
        print("\nError: The following required libraries are missing:")
        for lib in missing_libraries:
            print(f"  - {lib}")
        print("\nPlease install them using the following command:")
        print(f"  pip install {' '.join(missing_libraries)}")
        sys.exit(1)

    print("\n--> All required libraries are installed.")


def validate_files() -> None:
    """
    Validate the existence of critical files required for the application.
    Create a .env file from env.example if necessary.
    Create a new self-signed SSL certificate if necessary.
    """
    env_file = ".env"
    env_example_file = "env.example"
    cert_file = "cert.pem"
    key_file = "key.pem"

    # Handle .env file
    if not os.path.exists(env_file):
        if os.path.exists(env_example_file):
            print(
                f"The required {env_file} is missing. Let's create one from {env_example_file}."
            )
            print("Press <Enter> to accept default values.")
            with open(env_example_file, "r") as example:
                lines = example.readlines()

            env_values = {}
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):  # Ignore comments and empty lines
                    key, value = line.split("=", 1)
                    user_input = input(f"{key} [{value}]: ").strip()
                    env_values[key] = user_input if user_input else value

            # Save the new .env file
            with open(env_file, "w") as env:
                for key, value in env_values.items():
                    env.write(f"{key}={value}\n")
            print(f"\n{env_file} has been created.")
        else:
            print(
                f"\nError: {env_file} is missing, and {env_example_file} does not exist."
            )
            sys.exit(1)

    # Handle SSL certificate files
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"\nSSL certificate files ({cert_file}, {key_file}) are missing.")
        print("Attempting to generate SSL certificates using generate_cert.py...")

        try:
            subprocess.run([sys.executable, "generate_cert.py"], check=True)
        except FileNotFoundError:
            print(
                "\nError: generate_cert.py script is missing. Cannot generate SSL certificates."
            )
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"\nError: Failed to generate SSL certificates. {e}")
            sys.exit(1)

        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print(
                f"\nError: SSL certificate files ({cert_file}, {key_file}) could not be generated."
            )
            sys.exit(1)

    print("\n--> All required files are in place.")


def validate_permissions() -> None:
    """
    Validate that all required directories are writable and files are accessible.
    This prevents permission-related failures during operation.
    """
    issues: list[str] = []

    # Directories that must exist and be writable
    required_dirs = [
        ("uploads", "File uploads"),
        ("flask_session", "Flask session storage"),
        ("data", "Application data"),
    ]

    for dir_path, description in required_dirs:
        abs_path = os.path.abspath(dir_path)
        if not os.path.exists(abs_path):
            try:
                os.makedirs(abs_path, exist_ok=True)
                print(f"--> Created {description} directory: {abs_path}")
            except Exception as e:
                issues.append(f"{description} directory missing and cannot create: {abs_path} ({e})")
                continue

        if not os.path.isdir(abs_path):
            issues.append(f"{description} path is not a directory: {abs_path}")
            continue

        if not os.access(abs_path, os.W_OK):
            issues.append(f"{description} directory not writable: {abs_path}")

    # Check master potfile if enabled
    master_potfile_enabled = os.getenv("MASTER_POTFILE_ENABLED", "false").lower() == "true"
    master_potfile_path = os.getenv("MASTER_POTFILE_PATH", "data/master.potfile")

    if master_potfile_enabled:
        abs_potfile = os.path.abspath(master_potfile_path)
        potfile_dir = os.path.dirname(abs_potfile)

        # Ensure potfile directory exists
        if not os.path.exists(potfile_dir):
            try:
                os.makedirs(potfile_dir, exist_ok=True)
            except Exception as e:
                issues.append(f"Master potfile directory cannot be created: {potfile_dir} ({e})")

        # Check if potfile exists and is writable, or if directory is writable
        if os.path.exists(abs_potfile):
            if not os.access(abs_potfile, os.W_OK):
                issues.append(f"Master potfile not writable: {abs_potfile}")
        elif potfile_dir and not os.access(potfile_dir, os.W_OK):
            issues.append(f"Master potfile directory not writable (cannot create potfile): {potfile_dir}")

    # Check SSL certificate files are readable
    for cert_file in ["cert.pem", "key.pem"]:
        if os.path.exists(cert_file) and not os.access(cert_file, os.R_OK):
            issues.append(f"SSL certificate not readable: {cert_file}")

    # Report results
    if issues:
        print("\n" + "=" * 60)
        print("PERMISSION AUDIT FAILED")
        print("=" * 60)
        print("\nThe following permission issues were detected:\n")
        for issue in issues:
            print(f"  - {issue}")
        print("\nPlease fix these permission issues before starting Hash Master.")
        print("Typical fixes:")
        print("  - sudo chown -R $USER:$USER uploads/ flask_session/ data/")
        print("  - chmod 755 uploads/ flask_session/ data/")
        print("=" * 60 + "\n")
        sys.exit(1)

    print("\n--> Permission audit passed: all directories are writable.")


def is_safe_redirect_url(target: str) -> bool:
    """
    Check if the redirect URL is safe (relative to this application).
    Prevents open redirect attacks.
    """
    if not target:
        return False
    # Parse the target URL
    parsed = urlparse(target)
    # Only allow relative URLs (no scheme or netloc)
    return not parsed.netloc and not parsed.scheme


def is_allowed_path(path: str) -> bool:
    """
    Check if the given path is within allowed directories for local file access.
    Uses LOCAL_FILE_ALLOWED_PATHS from .env to determine allowed directories.

    Security: This restricts local file browsing to configured directories only,
    preventing access to sensitive system files like /etc/passwd, /etc/shadow, etc.
    """
    try:
        # Resolve to absolute path, following symlinks to prevent traversal attacks
        abs_path = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
        # Check if path starts with any allowed prefix
        return any(abs_path.startswith(allowed) for allowed in LOCAL_FILE_ALLOWED_PATHS)
    except Exception:
        return False


class User(UserMixin):
    def __init__(
        self,
        username: str,
        password_hash: str | None = None,
        role: str = "superadmin",
        can_view_passwords: bool = True,
        force_password_change: bool = False,
    ):
        self.username = username
        self.password_hash = password_hash
        self._role = role
        self._can_view_passwords = can_view_passwords
        self._force_password_change = force_password_change

    @property
    def id(self) -> str:
        # Use username as the unique identifier
        return self.username

    @property
    def role(self) -> str:
        """Get user role. In single-user mode, always returns 'superadmin'."""
        if not MULTI_USER_ENABLED:
            return "superadmin"
        return self._role

    @property
    def can_view_passwords(self) -> bool:
        """Check if user can view clear-text passwords."""
        if not MULTI_USER_ENABLED:
            return True
        return self._can_view_passwords

    @property
    def force_password_change(self) -> bool:
        """Check if user must change password on next action."""
        if not MULTI_USER_ENABLED:
            return False
        return self._force_password_change

    @property
    def is_superadmin(self) -> bool:
        """Check if user is a superadmin."""
        return self.role == "superadmin"

    @property
    def is_admin(self) -> bool:
        """Check if user is an admin or superadmin."""
        return self.role in ("admin", "superadmin")

    @property
    def can_access_advanced(self) -> bool:
        """Check if user can access advanced pages."""
        return self.is_admin

    @property
    def can_manage_users(self) -> bool:
        """Check if user can manage other users."""
        return self.is_superadmin


# Function to properly handle boolean arguments
def parse_boolean_field(field_name: str) -> bool:
    values = request.form.getlist(field_name)
    if not values or not all(isinstance(v, str) for v in values):
        return False
    return values[-1].lower() == "true"


# Function to validate pwdump file before attempting analysis
def validate_pwdump_file(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) != 7:
                    return False  # Invalid format
        return True
    except Exception as e:
        logging.error(f"Error validating pwdump file {filepath}: {e}")
        return False


# Function to validate potfile file before attempting analysis
def validate_potfile(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) != 2:
                    return False  # Invalid format
        return True
    except Exception as e:
        logging.error(f"Error validating potfile {filepath}: {e}")
        return False


def _apply_duplicate_handling(
    pwdump_result: "file_parser.ValidationResult",
    duplicate_handling: dict
) -> None:
    """
    Apply duplicate handling by marking lines to exclude.

    Args:
        pwdump_result: The validation result to modify in place
        duplicate_handling: Dict with 'method' and 'manual_selections' keys
    """
    method = duplicate_handling.get("method", "first")
    manual_selections = duplicate_handling.get("manual_selections", {})

    for dup_info in pwdump_result.duplicate_accounts:
        account_lower = dup_info.account_name.lower()

        # Determine which line to keep
        if method == "manual":
            # Check for manual selection (case-insensitive lookup)
            keep_line = None
            for key, val in manual_selections.items():
                if key.lower() == account_lower:
                    keep_line = val
                    break
            # Fall back to first if no manual selection
            if keep_line is None:
                keep_line = dup_info.first_line
        elif method == "last":
            keep_line = dup_info.last_line
        else:  # "first" is default
            keep_line = dup_info.first_line

        # Mark other occurrences as excluded
        for line in pwdump_result.lines:
            if (line.username and
                line.username.lower() == account_lower and
                line.line_number != keep_line):
                line.included = False


app = Flask(__name__, static_folder="static", template_folder="templates")
Compress(app)  # Enable gzip/brotli compression for static assets

# Apply ProxyFix to correctly handle X-Forwarded-For headers from nginx
# This ensures request.remote_addr returns the real client IP, not 127.0.0.1
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Track app start time for health endpoint
_app_start_time = time.time()

# Track active user sessions (username -> last_activity_timestamp)
# Updated on each authenticated request via @before_request
_user_activity: dict[str, float] = {}

# File-based tracking for multi-worker consistency
_SHARED_STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'state')
os.makedirs(_SHARED_STATE_DIR, exist_ok=True)

# Import fcntl for file locking (Unix only, but we only run on Linux)
try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False


def _get_sse_connections_file() -> str:
    """Get path to file tracking SSE connections."""
    return os.path.join(_SHARED_STATE_DIR, 'sse_connections.json')


def _get_user_activity_file() -> str:
    """Get path to file tracking user activity."""
    return os.path.join(_SHARED_STATE_DIR, 'user_activity.json')


def _read_json_with_lock(filepath: str) -> dict:
    """Read JSON file with file locking to prevent race conditions."""
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r') as f:
            if _HAS_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
            try:
                return json.load(f)
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except (json.JSONDecodeError, ValueError):
        # File is corrupted, return empty dict
        return {}


def _write_json_with_lock(filepath: str, data: dict, timeout_ms: int = 100) -> bool:
    """Write JSON file with file locking to prevent race conditions.

    Returns True if write succeeded, False if lock couldn't be acquired.
    """
    # Use a lock file to coordinate between processes
    lockfile = filepath + '.lock'
    try:
        with open(lockfile, 'w') as lock:
            if _HAS_FCNTL:
                # Use non-blocking lock with retry
                import time as _time
                start = _time.monotonic()
                while True:
                    try:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if (_time.monotonic() - start) * 1000 > timeout_ms:
                            return False
                        _time.sleep(0.01)  # 10ms retry interval
            try:
                # Re-read the file under lock to get latest data
                existing = {}
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            existing = json.load(f)
                    except (json.JSONDecodeError, ValueError):
                        existing = {}
                # Merge the new data with existing
                existing.update(data)
                # Write atomically using temp file
                tmpfile = filepath + '.tmp'
                with open(tmpfile, 'w') as f:
                    json.dump(existing, f)
                os.replace(tmpfile, filepath)
                return True
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        return False


def _track_sse_connection(agent_id: str, connected: bool) -> None:
    """Track SSE connection state in shared file."""
    filepath = _get_sse_connections_file()
    lockfile = filepath + '.lock'
    try:
        with open(lockfile, 'w') as lock:
            if _HAS_FCNTL:
                # Use non-blocking lock - skip if can't acquire immediately
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return
            try:
                connections = {}
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            connections = json.load(f)
                    except (json.JSONDecodeError, ValueError):
                        connections = {}

                if connected:
                    connections[agent_id] = {
                        'connected_at': time.time(),
                        'worker_pid': os.getpid()
                    }
                else:
                    connections.pop(agent_id, None)

                tmpfile = filepath + '.tmp'
                with open(tmpfile, 'w') as f:
                    json.dump(connections, f)
                os.replace(tmpfile, filepath)
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logging.warning(f"Failed to track SSE connection: {e}")


def _get_sse_connections() -> dict[str, dict]:
    """Get all active SSE connections from shared file."""
    filepath = _get_sse_connections_file()
    try:
        connections = _read_json_with_lock(filepath)
        # Clean up stale connections (older than 2 minutes without heartbeat)
        now = time.time()
        active = {
            k: v for k, v in connections.items()
            if now - v.get('connected_at', 0) < 120
        }
        # Don't write cleanup here - let the heartbeat handle it
        return active
    except Exception as e:
        logging.warning(f"Failed to read SSE connections: {e}")
    return {}


def _track_user_activity_shared(username: str) -> None:
    """Track user activity in shared file for multi-worker consistency."""
    filepath = _get_user_activity_file()
    lockfile = filepath + '.lock'
    try:
        with open(lockfile, 'w') as lock:
            if _HAS_FCNTL:
                # Use non-blocking lock - skip if can't acquire immediately
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    # Another process has the lock, skip this update
                    return
            try:
                activity = {}
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            activity = json.load(f)
                    except (json.JSONDecodeError, ValueError):
                        activity = {}

                activity[username] = time.time()

                tmpfile = filepath + '.tmp'
                with open(tmpfile, 'w') as f:
                    json.dump(activity, f)
                os.replace(tmpfile, filepath)
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logging.warning(f"Failed to track user activity: {e}")


def _get_user_activity_shared() -> dict[str, float]:
    """Get user activity from shared file."""
    filepath = _get_user_activity_file()
    try:
        return _read_json_with_lock(filepath)
    except Exception as e:
        logging.warning(f"Failed to read user activity: {e}")
    return {}

# Configure logging to show INFO level messages
# This ensures agent commands, benchmark status, etc. are visible in logs
# Use file-based logging for multi-worker support
from logging.handlers import RotatingFileHandler

_LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'hm1k.log')
_LOG_FORMAT = '[%(asctime)s] %(levelname)s: %(message)s'
_LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Ensure logs directory exists
os.makedirs(os.path.dirname(_LOG_FILE_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt=_LOG_DATE_FORMAT
)

# Add rotating file handler for persistent logs across all workers
_file_handler = RotatingFileHandler(
    _LOG_FILE_PATH,
    maxBytes=10 * 1024 * 1024,  # 10 MB per file
    backupCount=5,  # Keep 5 backup files
    encoding='utf-8'
)
_file_handler.setLevel(logging.INFO)
_file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _LOG_DATE_FORMAT))
logging.getLogger().addHandler(_file_handler)


def _read_log_file(limit: int = 500, level: str | None = None,
                   search: str | None = None) -> tuple[list[dict], int]:
    """
    Read and parse log entries from the log file.

    Returns:
        Tuple of (filtered log entries, total line count in file)
    """
    import re

    log_pattern = re.compile(
        r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (\w+): (.*)$'
    )

    entries = []
    total_lines = 0

    try:
        if not os.path.exists(_LOG_FILE_PATH):
            return [], 0

        # Read file in reverse order (newest first) efficiently
        with open(_LOG_FILE_PATH, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        total_lines = len(lines)

        # Process lines in reverse (newest first)
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue

            match = log_pattern.match(line)
            if match:
                timestamp_str, log_level, message = match.groups()

                # Filter by level if specified
                if level and log_level.upper() != level.upper():
                    continue

                # Filter by search term if specified
                if search:
                    search_lower = search.lower()
                    if search_lower not in message.lower():
                        continue

                # Parse timestamp
                try:
                    timestamp = datetime.strptime(timestamp_str, _LOG_DATE_FORMAT)
                    timestamp_iso = timestamp.isoformat()
                except ValueError:
                    timestamp_iso = timestamp_str

                entries.append({
                    'timestamp': timestamp_iso,
                    'level': log_level.upper(),
                    'message': message,
                })

                if len(entries) >= limit:
                    break

    except Exception as e:
        logging.error(f"Error reading log file: {e}")

    return entries, total_lines


def _clear_log_file() -> bool:
    """Clear the log file contents."""
    try:
        # Truncate the file
        with open(_LOG_FILE_PATH, 'w', encoding='utf-8') as f:
            pass
        logging.info("Log file cleared by user")
        return True
    except Exception as e:
        logging.error(f"Error clearing log file: {e}")
        return False

# Validate and set SECRET_KEY immediately - required for WSGI imports
# The _ensure_secret_key() function should have already generated one if missing
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    raise ValueError(
        "SECRET_KEY could not be loaded. Check that your .env file exists and is readable."
    )
app.secret_key = _secret_key

# Custom Jinja filter for basename
@app.template_filter('basename')
def basename_filter(path: str | None) -> str:
    """Jinja filter to get basename of a path."""
    return os.path.basename(path) if path else ''

# Custom Jinja test for checking if username ends with $ (computer account)
@app.template_test('computer_account')
def is_computer_account(username: str | None) -> bool:
    """Jinja test to check if a username is a computer account (ends with $)."""
    return bool(username and username.endswith('$'))

# Custom Jinja test for checking if username is a password history entry (_historyN suffix)
@app.template_test('history_account')
def is_history_account(username: str | None) -> bool:
    """Jinja test to check if a username is a password history entry (ends with _historyN)."""
    import re
    return bool(username and re.search(r'_history\d+$', username, re.IGNORECASE))

# Advanced Mode pages - used to avoid circular return URLs
ADVANCED_MODE_PATHS = {
    '/hidden', '/hiddenpages', '/api/ai/report/test', '/api/ai/benchmark',
    '/api/ai/servers/manage', '/hibp/download', '/timing/stats', '/agents/jobs',
    '/agents/wordlists', '/agents/rules', '/users', '/users/create', '/system/logs'
}


def get_advanced_mode_return_url() -> str:
    """
    Get a safe return URL for exiting Advanced Mode pages.

    Checks the HTTP Referer header and validates it's:
    - From the same origin (internal URL)
    - Not another Advanced Mode page (to avoid circular navigation)

    Returns "/" as the default if no valid return URL is found.
    """
    referer = request.headers.get('Referer', '')

    if not referer:
        return "/"

    try:
        from urllib.parse import urlparse
        parsed = urlparse(referer)

        # Only accept same-origin URLs (no scheme/host or matching host)
        request_host = request.host.split(':')[0]  # Remove port
        referer_host = parsed.netloc.split(':')[0] if parsed.netloc else ''

        if referer_host and referer_host != request_host:
            return "/"

        # Get the path
        path = parsed.path or "/"

        # Don't return to another Advanced Mode page or user edit pages
        if any(path.startswith(adv_path) for adv_path in ADVANCED_MODE_PATHS):
            return "/"

        # Don't return to login/logout/change-password
        if path in {'/login', '/logout', '/change-password'}:
            return "/"

        return path
    except Exception:
        return "/"


# Context processor to make global variables available to all templates
@app.context_processor
def inject_global_settings() -> dict[str, Any]:
    """Inject global settings into all templates."""
    # Determine if advanced options should be shown
    # In single-user mode: use the env flag (backwards compatibility)
    # In multi-user mode: based on user role
    if MULTI_USER_ENABLED and current_user.is_authenticated:
        show_advanced = current_user.can_access_advanced
    else:
        show_advanced = ADVANCED_OPTIONS_ENABLED

    return {
        'advanced_options_enabled': show_advanced,
        'multi_user_enabled': MULTI_USER_ENABLED,
    }

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    hours=8
)  # Session expiration can be adjusted here
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["UPLOAD_FOLDER"] = "uploads"

# Configure server-side sessions (filesystem-based)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "flask_session"
app.config["SESSION_PERMANENT"] = True
Session(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter for brute force protection
# Uses in-memory storage by default (resets on app restart)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],  # No global limits, only per-route
    storage_uri="memory://",
)


@app.errorhandler(429)
def ratelimit_handler(e: Exception) -> tuple[str, int]:
    """Handle rate limit exceeded errors."""
    client_ip = request.remote_addr or "unknown"
    logging.warning(f"Rate limit exceeded: ip={client_ip} path={request.path}")
    return render_template(
        "message.html",
        message="Too many login attempts. Please wait a minute before trying again.",
        message_type="error-message",
        status_code=429,
        referrer="Login",
        referrer_url=url_for("login"),
    ), 429


@app.before_request
def track_user_activity() -> None:
    """Track last activity time for authenticated users."""
    if current_user.is_authenticated:
        _user_activity[current_user.id] = time.time()
        # Also update shared file for multi-worker consistency
        _track_user_activity_shared(current_user.id)


# =============================================================================
# Request Timing and Health Monitoring
# =============================================================================

# Track active requests per worker for health monitoring
import threading
import os as _os
_request_tracking = {
    "active_requests": {},  # request_id -> {path, started_at, thread_id}
    "lock": threading.Lock(),
    "worker_pid": _os.getpid(),
    "slow_request_threshold_seconds": 30,  # Log warning for requests > 30s
    "very_slow_request_threshold_seconds": 300,  # Log error for requests > 5min
}


@app.before_request
def track_request_start() -> None:
    """Track when each request starts for timing and health monitoring."""
    from flask import g
    import uuid
    g.request_id = str(uuid.uuid4())[:8]
    g.request_start_time = time.time()

    with _request_tracking["lock"]:
        _request_tracking["active_requests"][g.request_id] = {
            "path": request.path,
            "method": request.method,
            "started_at": g.request_start_time,
            "thread_id": threading.current_thread().ident,
        }


@app.after_request
def track_request_end(response):
    """Log request timing and clean up tracking."""
    from flask import g

    if hasattr(g, 'request_id'):
        duration = time.time() - g.request_start_time

        # Clean up tracking
        with _request_tracking["lock"]:
            _request_tracking["active_requests"].pop(g.request_id, None)

        # Log slow requests
        threshold = _request_tracking["slow_request_threshold_seconds"]
        very_slow = _request_tracking["very_slow_request_threshold_seconds"]

        if duration > very_slow:
            logging.error(
                f"VERY SLOW REQUEST [{g.request_id}]: {request.method} {request.path} "
                f"took {duration:.2f}s (threshold: {very_slow}s)"
            )
        elif duration > threshold:
            logging.warning(
                f"Slow request [{g.request_id}]: {request.method} {request.path} "
                f"took {duration:.2f}s (threshold: {threshold}s)"
            )

    return response


@app.teardown_request
def cleanup_request_tracking(exception=None):
    """Ensure request tracking is cleaned up even on errors."""
    from flask import g
    if hasattr(g, 'request_id'):
        with _request_tracking["lock"]:
            _request_tracking["active_requests"].pop(g.request_id, None)


# Ensure the upload and data folders exists
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])
if not os.path.exists("data"):
    os.makedirs("data")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = (
    "login"  # Redirect users to the login page if not authenticated
)
login_manager.login_message = (
    "Please log in to access this page."  # Redirects too fast to be seen?
)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """Load user by ID (username)."""
    # Always check superadmin from .env first
    if user_id == ADMIN_USERNAME:
        return User(
            username=ADMIN_USERNAME,
            role="superadmin",
            can_view_passwords=True,
            force_password_change=False,
        )

    # In multi-user mode, also check the user store
    if MULTI_USER_ENABLED:
        from app.user_store import get_user_store
        user_store = get_user_store()
        user_data = user_store.get_user(user_id)
        if user_data:
            return User(
                username=user_data.username,
                password_hash=user_data.password_hash,
                role=user_data.role,
                can_view_passwords=user_data.can_view_passwords,
                force_password_change=user_data.force_password_change,
            )

    return None


@login_manager.unauthorized_handler
def unauthorized() -> Response | str:
    """Custom unauthorized handler that returns JSON for API calls."""
    # Check if this is an API/AJAX request
    if request.path.startswith('/api/') or request.is_json or request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({
            "error": "Authentication required",
            "message": "Please log in to access this resource."
        }), 401
    # For regular page requests, redirect to login
    return redirect(url_for('login', next=request.url))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])  # Rate limit login attempts by IP
def login() -> FlaskResponse:
    if current_user.is_authenticated:  # If already logged in, redirect to index
        # Check if user needs to change password
        if current_user.force_password_change:
            return cast(FlaskResponse, redirect(url_for("change_password")))
        return cast(FlaskResponse, redirect(url_for("index")))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        client_ip = request.remote_addr or "unknown"

        # Input validation
        if not username or not password:
            return make_response(
                render_template(
                    "message.html",
                    message="Invalid Input: A valid username and password are required.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Login",
                    referrer_url=url_for("login"),
                ),
            )

        # Try to authenticate
        authenticated_user = None

        # Check superadmin from .env first
        if username == ADMIN_USERNAME and bcrypt.checkpw(
            password.encode("utf-8"), ADMIN_PASSWORD_HASH.encode("utf-8")
        ):
            authenticated_user = User(
                username=ADMIN_USERNAME,
                password_hash=ADMIN_PASSWORD_HASH,
                role="superadmin",
                can_view_passwords=True,
                force_password_change=False,
            )

        # In multi-user mode, also check user store
        elif MULTI_USER_ENABLED:
            from app.user_store import get_user_store
            user_store = get_user_store()
            if user_store.verify_password(username.lower(), password):
                user_data = user_store.get_user(username.lower())
                if user_data:
                    authenticated_user = User(
                        username=user_data.username,
                        password_hash=user_data.password_hash,
                        role=user_data.role,
                        can_view_passwords=user_data.can_view_passwords,
                        force_password_change=user_data.force_password_change,
                    )

        if authenticated_user:
            login_user(authenticated_user)

            # Check if password change is required
            if authenticated_user.force_password_change:
                return cast(FlaskResponse, redirect(url_for("change_password")))

            # Redirect to the 'next' parameter or index (with open redirect protection)
            next_page = request.args.get("next")
            if next_page and is_safe_redirect_url(next_page):
                return cast(FlaskResponse, redirect(next_page))
            return cast(FlaskResponse, redirect(url_for("index")))

        # Authentication failed - log attempt and add delay
        logging.warning(
            f"Failed login attempt: username='{username}' ip={client_ip}"
        )
        time.sleep(1)  # 1 second delay to slow down brute force attacks

        return make_response(
            render_template(
                "message.html",
                message="Invalid Credentials: Please enter a valid username and password.",
                message_type="error-message",
                status_code=401,
                referrer="Login",
                referrer_url=url_for("login"),
            ),
        )

    # Render the login page for GET requests
    return make_response(render_template("login.html"))


@app.route("/logout", methods=["POST"])
@login_required
def logout() -> Response:
    logout_user()
    # Clear Flask session (including session_id for multi-user mode)
    session.clear()
    return cast(FlaskResponse, redirect(url_for("login")))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password() -> FlaskResponse:
    """Allow user to change their password."""
    # Superadmin from .env cannot change password here
    if current_user.username == ADMIN_USERNAME:
        return make_response(
            render_template(
                "message.html",
                message="Superadmin password can only be changed in the .env file.",
                message_type="error-message",
                status_code=403,
                referrer="Home",
                referrer_url=url_for("index"),
            )
        )

    if not MULTI_USER_ENABLED:
        return cast(FlaskResponse, redirect(url_for("index")))

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            return make_response(
                render_template(
                    "change_password.html",
                    error="All fields are required.",
                    force_change=current_user.force_password_change,
                )
            )

        if new_password != confirm_password:
            return make_response(
                render_template(
                    "change_password.html",
                    error="New passwords do not match.",
                    force_change=current_user.force_password_change,
                )
            )

        if len(new_password) < 8:
            return make_response(
                render_template(
                    "change_password.html",
                    error="Password must be at least 8 characters.",
                    force_change=current_user.force_password_change,
                )
            )

        # Verify current password
        from app.user_store import get_user_store
        user_store = get_user_store()
        if not user_store.verify_password(current_user.username, current_password):
            return make_response(
                render_template(
                    "change_password.html",
                    error="Current password is incorrect.",
                    force_change=current_user.force_password_change,
                )
            )

        # Change password
        success, message = user_store.change_password(current_user.username, new_password)
        if success:
            return cast(FlaskResponse, redirect(url_for("index")))
        else:
            return make_response(
                render_template(
                    "change_password.html",
                    error=message,
                    force_change=current_user.force_password_change,
                )
            )

    # GET request - show form
    return make_response(
        render_template(
            "change_password.html",
            force_change=current_user.force_password_change,
        )
    )


# =============================================================================
# User Management Routes (Multi-User Mode Only)
# =============================================================================

@app.route("/users")
@login_required
def users_list() -> FlaskResponse:
    """List all users (superadmin only)."""
    if not MULTI_USER_ENABLED:
        return cast(FlaskResponse, redirect(url_for("index")))

    if not current_user.can_manage_users:
        return make_response(
            render_template(
                "message.html",
                message="Access Denied: You do not have permission to manage users.",
                message_type="error-message",
                status_code=403,
                referrer="Home",
                referrer_url=url_for("index"),
            )
        )

    from app.user_store import get_user_store
    user_store = get_user_store()
    users = user_store.list_users()

    return make_response(
        render_template(
            "users.html",
            users=users,
            superadmin_username=ADMIN_USERNAME,
        )
    )


@app.route("/users/create", methods=["GET", "POST"])
@login_required
def users_create() -> FlaskResponse:
    """Create a new user (superadmin only)."""
    if not MULTI_USER_ENABLED:
        return cast(FlaskResponse, redirect(url_for("index")))

    if not current_user.can_manage_users:
        return make_response(
            render_template(
                "message.html",
                message="Access Denied: You do not have permission to create users.",
                message_type="error-message",
                status_code=403,
                referrer="Home",
                referrer_url=url_for("index"),
            )
        )

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "user")
        can_view_passwords = request.form.get("can_view_passwords") == "on"

        from app.user_store import get_user_store
        user_store = get_user_store()

        # Prevent creating user with superadmin username
        if username.lower() == ADMIN_USERNAME.lower():
            return make_response(
                render_template(
                    "users_create.html",
                    error="Cannot create user with the superadmin username.",
                )
            )

        success, message = user_store.create_user(
            username=username,
            password=password,
            role=role,
            can_view_passwords=can_view_passwords,
            created_by=current_user.username,
        )

        if success:
            return cast(FlaskResponse, redirect(url_for("users_list")))
        else:
            return make_response(
                render_template(
                    "users_create.html",
                    error=message,
                    username=username,
                    role=role,
                    can_view_passwords=can_view_passwords,
                )
            )

    # GET request - show form
    return make_response(render_template("users_create.html"))


@app.route("/users/<username>/edit", methods=["GET", "POST"])
@login_required
def users_edit(username: str) -> FlaskResponse:
    """Edit a user (superadmin only)."""
    if not MULTI_USER_ENABLED:
        return cast(FlaskResponse, redirect(url_for("index")))

    if not current_user.can_manage_users:
        return make_response(
            render_template(
                "message.html",
                message="Access Denied: You do not have permission to edit users.",
                message_type="error-message",
                status_code=403,
                referrer="Home",
                referrer_url=url_for("index"),
            )
        )

    from app.user_store import get_user_store
    user_store = get_user_store()
    user_data = user_store.get_user(username)

    if not user_data:
        return make_response(
            render_template(
                "message.html",
                message=f"User '{username}' not found.",
                message_type="error-message",
                status_code=404,
                referrer="Users",
                referrer_url=url_for("users_list"),
            )
        )

    if request.method == "POST":
        role = request.form.get("role", "user")
        can_view_passwords = request.form.get("can_view_passwords") == "on"

        success, message = user_store.update_user(
            username=username,
            role=role,
            can_view_passwords=can_view_passwords,
        )

        if success:
            return cast(FlaskResponse, redirect(url_for("users_list")))
        else:
            return make_response(
                render_template(
                    "users_edit.html",
                    user=user_data,
                    error=message,
                )
            )

    # GET request - show form
    return make_response(render_template("users_edit.html", user=user_data))


@app.route("/users/<username>/reset-password", methods=["POST"])
@login_required
def users_reset_password(username: str) -> FlaskResponse:
    """Reset a user's password (superadmin only)."""
    if not MULTI_USER_ENABLED:
        return jsonify({"error": "Multi-user mode is not enabled"}), 400

    if not current_user.can_manage_users:
        return jsonify({"error": "Access denied"}), 403

    new_password = request.form.get("new_password", "").strip()
    if not new_password:
        return jsonify({"error": "Password is required"}), 400

    from app.user_store import get_user_store
    user_store = get_user_store()

    # Change password and force password change on next login
    success, message = user_store.change_password(username, new_password)
    if success:
        # Force password change on next login
        user_store.update_user(username, force_password_change=True)
        return jsonify({"success": True, "message": "Password reset successfully"})
    else:
        return jsonify({"error": message}), 400


@app.route("/users/<username>/delete", methods=["POST"])
@login_required
def users_delete(username: str) -> FlaskResponse:
    """Delete a user (superadmin only)."""
    if not MULTI_USER_ENABLED:
        return jsonify({"error": "Multi-user mode is not enabled"}), 400

    if not current_user.can_manage_users:
        return jsonify({"error": "Access denied"}), 403

    # Prevent deleting superadmin
    if username.lower() == ADMIN_USERNAME.lower():
        return jsonify({"error": "Cannot delete the superadmin user"}), 400

    from app.user_store import get_user_store
    user_store = get_user_store()

    success, message = user_store.delete_user(username)
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"error": message}), 400


@app.route("/")
@login_required
def index() -> str:
    import time as time_module
    from app.timing_stats import get_timing_stats, TimingStats

    # Get step parameter (defaults to 1 if not provided)
    # Step 3 is used when continuing from validation review to configuration
    initial_step = request.args.get("step", 1, type=int)
    input_method = request.args.get("input_method", "")

    # Only pass validation data when going directly to step 3
    # (coming from validation review with Continue to Configuration)
    pwdump_validation = None
    potfile_validation = None
    add_validation = None
    analysis_options = None

    # Track timing for Step 3 configuration loading
    timing = get_timing_stats()
    config_start = None
    item_count = 0

    if initial_step == 3:
        config_start = time_module.time()
        timing.start_timer(TimingStats.CONFIG_LOAD)

        # Load session data (instant - Flask sessions are already in memory)
        pwdump_validation = session.get("pwdump_validation")
        potfile_validation = session.get("potfile_validation")
        add_validation = session.get("add_validation")
        analysis_options = session.get("analysis_options")

        # Count items for throughput calculation
        if pwdump_validation:
            item_count = pwdump_validation.get("total_lines", 0)
        elif add_validation:
            item_count = add_validation.get("total_users", 0)

    # Get master potfile entry count if enabled (this can be slow for large potfiles)
    master_potfile_count = 0
    if MASTER_POTFILE_ENABLED:
        potfile_count_start = time_module.time()
        master_potfile_count = file_parser.get_potfile_entry_count(MASTER_POTFILE_PATH)
        potfile_count_duration = time_module.time() - potfile_count_start

        # Record master potfile count timing (only for Step 3)
        if initial_step == 3:
            timing.record_sample(
                operation=TimingStats.MASTER_POTFILE_COUNT,
                duration_seconds=potfile_count_duration,
                item_count=master_potfile_count
            )

    # Render template (this is where the heavy work happens for Step 3)
    if initial_step == 3:
        render_start = time_module.time()

    result = render_template(
        "index.html",
        initial_step=initial_step,
        input_method=input_method,
        pwdump_validation=pwdump_validation,
        potfile_validation=potfile_validation,
        add_validation=add_validation,
        analysis_options=analysis_options,
        default_pwdump_path=DEFAULT_PWDUMP_PATH,
        default_potfile_path=DEFAULT_POTFILE_PATH,
        default_add_json_path=DEFAULT_ADD_JSON_PATH,
        master_potfile_enabled=MASTER_POTFILE_ENABLED,
        master_potfile_count=master_potfile_count,
    )

    # Record Step 3 timing
    if initial_step == 3 and config_start:
        render_duration = time_module.time() - render_start
        timing.record_sample(
            operation=TimingStats.CONFIG_RENDER,
            duration_seconds=render_duration,
            item_count=item_count
        )
        timing.stop_timer(TimingStats.CONFIG_LOAD, item_count=item_count)

    return result


@app.route("/favicon.ico")
def favicon() -> Response:
    return send_from_directory(
        "static", "favicon.ico", mimetype="image/vnd.microsoft.icon"
    )


@app.route("/readme")
def readme() -> Response:
    return send_file("README.md", mimetype="text/markdown")


@app.route("/LICENSE")
def license() -> Response:
    return send_file("LICENSE", mimetype="text/markdown")


# ============================================================================
# Master Potfile Helper Functions
# ============================================================================

def extract_hashes_from_pwdump(pwdump_result: "file_parser.ValidationResult") -> set[str]:
    """
    Extract unique NTLM hashes from a validated pwdump result.

    Args:
        pwdump_result: Validated pwdump file results

    Returns:
        Set of lowercase NTLM hashes
    """
    hashes = set()
    for line in pwdump_result.lines:
        if line.included and line.is_valid and line.ntlm_hash:
            hashes.add(line.ntlm_hash.lower())
    return hashes


def extract_hashes_from_add(add_result: "file_parser.ADDValidationResult") -> set[str]:
    """
    Extract unique NTLM hashes from a validated ADD result.

    Args:
        add_result: Validated ADD file results

    Returns:
        Set of lowercase NTLM hashes
    """
    hashes = set()
    for entry in add_result.entries:
        if entry.included and entry.is_valid:
            # Current hash
            if entry.ntlm_hash:
                hashes.add(entry.ntlm_hash.lower())
            # Historical hashes
            for hist in entry.historical_hashes:
                if hist:
                    hashes.add(hist.lower())
    return hashes


def handle_master_potfile_merge(
    potfile_result: "file_parser.PotfileValidationResult",
    pwdump_hashes: set[str] = None
) -> tuple:
    """
    Handle master potfile merge logic when MASTER_POTFILE_ENABLED is true.

    Uses cached potfile for efficient merge and validation operations.
    With 620K+ hashes, this avoids reading the file twice per operation.

    When pwdump_hashes is provided, the returned potfile result is filtered
    to only include hashes that match the pwdump accounts. This dramatically
    reduces session storage (620K entries -> only matching entries).

    Args:
        potfile_result: The validated potfile result from user's upload
        pwdump_hashes: Optional set of NTLM hashes from pwdump (lowercase).
                      If provided, filters result to only matching hashes.

    Returns:
        Tuple of (final_potfile_result, merge_stats_dict)
        - final_potfile_result: Either master potfile result or original user result
        - merge_stats_dict: Dict with 'added', 'skipped', 'total' keys (or None if disabled)
    """
    if not MASTER_POTFILE_ENABLED:
        return (potfile_result, None)

    merge_stats = None

    try:
        # Use cached merge - avoids reading file for deduplication
        cache = get_master_cache()
        added, skipped, total = cache.merge_entries(
            MASTER_POTFILE_PATH,
            potfile_result.entries
        )
        merge_stats = {
            "added": added,
            "skipped": skipped,
            "total": total,
            "user_ntlm_count": potfile_result.ntlm_count,
        }

        # Create PotfileValidationResult - use filtered version if pwdump_hashes provided
        if pwdump_hashes:
            # Session-optimized: only include hashes that match pwdump accounts
            master_result = cache.to_filtered_validation_result(
                MASTER_POTFILE_PATH,
                pwdump_hashes,
                additional_entries=potfile_result.entries  # Include user's potfile entries
            )
            logging.info(
                f"Master potfile merge complete: {added} added, {skipped} skipped, "
                f"{total} total in master, {master_result.ntlm_count} matching session hashes"
            )
        else:
            # Full result (legacy behavior)
            master_result = cache.to_validation_result(MASTER_POTFILE_PATH)
            logging.info(
                f"Master potfile merge complete: {added} added, {skipped} skipped, "
                f"{master_result.ntlm_count} total NTLM hashes in master"
            )
        return (master_result, merge_stats)

    except Exception as e:
        logging.error(f"Error during master potfile merge: {e}")
        # Fall back to user's potfile on error
        merge_stats = {
            "added": 0,
            "skipped": 0,
            "total": 0,
            "error": str(e),
            "user_ntlm_count": potfile_result.ntlm_count,
        }
        return (potfile_result, merge_stats)


def load_master_potfile_only(pwdump_hashes: set[str] = None) -> tuple:
    """
    Load master potfile when user skips providing their own potfile.

    Uses cached potfile for fast loading of 620K+ hash files.

    Args:
        pwdump_hashes: Optional set of NTLM hashes from pwdump (lowercase).
                      If provided, filters result to only matching hashes.

    Returns:
        Tuple of (potfile_result, merge_stats_dict)
    """
    if not MASTER_POTFILE_ENABLED or not os.path.exists(MASTER_POTFILE_PATH):
        return (None, None)

    try:
        # Use cache for fast loading
        cache = get_master_cache()

        if pwdump_hashes:
            # Session-optimized: only include hashes that match pwdump accounts
            master_result = cache.to_filtered_validation_result(
                MASTER_POTFILE_PATH,
                pwdump_hashes
            )
        else:
            master_result = cache.to_validation_result(MASTER_POTFILE_PATH)

        merge_stats = {
            "added": 0,
            "skipped": 0,
            "total": cache.get_stats()["ntlm_count"] if cache.get_stats() else 0,
            "user_ntlm_count": 0,
            "master_only": True,
            "session_hashes": master_result.ntlm_count,
        }
        return (master_result, merge_stats)
    except Exception as e:
        logging.error(f"Error loading master potfile: {e}")
        return (None, {"error": str(e)})


# ============================================================================
# New Validation Flow Endpoints
# ============================================================================

@app.route("/validate", methods=["POST"])
@login_required
def validate_files_endpoint() -> Response:
    """
    Step 1 of validation flow: Validate uploaded files and store results in session.
    If there are issues, redirect to validation review page.
    If files are clean, proceed directly to processing.
    """
    import time as time_module
    from app.timing_stats import get_timing_stats, TimingStats
    timing = get_timing_stats()
    validation_start = time_module.time()
    timing.start_timer(TimingStats.VALIDATION_TOTAL)

    try:
        # Retrieve file uploads
        pwdump_file = request.files.get("pwdump_file")
        potfile = request.files.get("potfile")
        use_master = request.form.get("use_master_potfile", "false").lower() == "true"

        # Pwdump file is always required
        if not pwdump_file:
            logging.error("Missing pwdump file upload.")
            return Response(
                render_template(
                    "message.html",
                    message="A valid pwdump/NTDS/ADD JSON file upload is required.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Potfile is required unless using master potfile
        if not potfile and not use_master:
            logging.error("Missing potfile upload and not using master.")
            return Response(
                render_template(
                    "message.html",
                    message="A potfile is required. Either upload a potfile or use the master potfile.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Check if master potfile is available when requested
        if use_master and (not MASTER_POTFILE_ENABLED or not os.path.exists(MASTER_POTFILE_PATH)):
            logging.error("Master potfile requested but not available.")
            return Response(
                render_template(
                    "message.html",
                    message="Master potfile is not available. Please upload a potfile instead.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Use secure_filename to prevent path traversal attacks
        pwdump_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(pwdump_file.filename))
        potfile_path = None
        if potfile and potfile.filename:
            potfile_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(potfile.filename))

        # Save files
        try:
            pwdump_file.save(pwdump_path)
            if potfile_path:
                potfile.save(potfile_path)
        except Exception as e:
            return Response(
                render_template(
                    "message.html",
                    message=f"Error saving files: {e}",
                    status_code=500,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=500,
            )

        # Check if the pwdump file is actually ADD JSON format
        is_add_json = file_parser.is_add_json_file(pwdump_path)

        if is_add_json:
            # Parse as ADD JSON format
            add_result = file_parser.parse_add_json(pwdump_path)

            # Extract hashes for session-optimized potfile filtering
            add_hashes = extract_hashes_from_add(add_result)

            if use_master:
                # Use master potfile only (no user potfile)
                final_potfile_result, merge_stats = load_master_potfile_only(add_hashes)
                if not final_potfile_result:
                    return Response(
                        render_template(
                            "message.html",
                            message="Failed to load master potfile.",
                            message_type="error-message",
                            status_code=500,
                            referrer="Start",
                            referrer_url=url_for("index"),
                        ),
                        status=500,
                    )
            else:
                # Validate user's potfile and merge with master if enabled
                potfile_result = file_parser.validate_potfile(potfile_path)
                final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, add_hashes)

            # Store ADD validation results in session
            session["add_validation"] = file_parser.add_result_to_dict(add_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path if potfile_path else MASTER_POTFILE_PATH
            session["input_format"] = "add_json"
            session["use_master_potfile"] = use_master
            if merge_stats:
                session["master_potfile_merge"] = merge_stats

            # Store form options for later processing (includes company/project info)
            session["analysis_options"] = {
                "company_name": request.form.get("company_name", "").strip(),
                "project_description": request.form.get("project_description", "").strip(),
                "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
                "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
                "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
                "substring_min_len": request.form.get("substring_min_len", "4"),
                "substring_max_len": request.form.get("substring_max_len", "20"),
                "substring_freq_threshold": request.form.get("substring_freq_threshold", "5"),
                "substring_disp_nest": str(parse_boolean_field("substring_disp_nest")).lower(),
                "substring_normalize": str(parse_boolean_field("substring_normalize")).lower(),
                "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
                "dictionary_disp_nest": str(parse_boolean_field("dictionary_disp_nest")).lower(),
                "ignore_blank_passwords": str(parse_boolean_field("ignore_blank_passwords")).lower(),
            }

            # Redirect to ADD JSON validation review page
            return cast(FlaskResponse, redirect(url_for("validation_review_add")))
        else:
            # Standard pwdump format
            pwdump_result = file_parser.validate_pwdump_file(pwdump_path)
            item_count = pwdump_result.total_lines

            # Extract hashes for session-optimized potfile filtering
            hash_extract_start = time_module.time()
            pwdump_hashes = extract_hashes_from_pwdump(pwdump_result)
            hash_extract_duration = time_module.time() - hash_extract_start
            timing.record_sample(
                operation=TimingStats.HASH_EXTRACTION,
                duration_seconds=hash_extract_duration,
                item_count=len(pwdump_hashes)
            )

            if use_master:
                # Use master potfile only (no user potfile)
                merge_start = time_module.time()
                final_potfile_result, merge_stats = load_master_potfile_only(pwdump_hashes)
                merge_duration = time_module.time() - merge_start
                if not final_potfile_result:
                    return Response(
                        render_template(
                            "message.html",
                            message="Failed to load master potfile.",
                            message_type="error-message",
                            status_code=500,
                            referrer="Start",
                            referrer_url=url_for("index"),
                        ),
                        status=500,
                    )
                if merge_stats:
                    timing.record_sample(
                        operation=TimingStats.MASTER_POTFILE_MERGE,
                        duration_seconds=merge_duration,
                        item_count=merge_stats.get("total", 0)
                    )
            else:
                # Validate user's potfile and merge with master if enabled
                potfile_result = file_parser.validate_potfile(potfile_path)
                merge_start = time_module.time()
                final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, pwdump_hashes)
                merge_duration = time_module.time() - merge_start
                if merge_stats:
                    timing.record_sample(
                        operation=TimingStats.MASTER_POTFILE_MERGE,
                        duration_seconds=merge_duration,
                        item_count=merge_stats.get("total", 0)
                    )

            # Store validation results in session
            session["pwdump_validation"] = file_parser.validation_result_to_dict(pwdump_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path if potfile_path else MASTER_POTFILE_PATH
            session["input_format"] = "pwdump"
            session["use_master_potfile"] = use_master
            if merge_stats:
                session["master_potfile_merge"] = merge_stats

            # Store form options for later processing (includes company/project info)
            session["analysis_options"] = {
                "company_name": request.form.get("company_name", "").strip(),
                "project_description": request.form.get("project_description", "").strip(),
                "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
                "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
                "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
                "substring_min_len": request.form.get("substring_min_len", "4"),
                "substring_max_len": request.form.get("substring_max_len", "20"),
                "substring_freq_threshold": request.form.get("substring_freq_threshold", "5"),
                "substring_disp_nest": str(parse_boolean_field("substring_disp_nest")).lower(),
                "substring_normalize": str(parse_boolean_field("substring_normalize")).lower(),
                "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
                "dictionary_disp_nest": str(parse_boolean_field("dictionary_disp_nest")).lower(),
                "ignore_blank_passwords": str(parse_boolean_field("ignore_blank_passwords")).lower(),
            }

            # Stop total validation timer
            timing.stop_timer(TimingStats.VALIDATION_TOTAL, item_count=item_count)

            # Redirect to validation review page (Step 2)
            return cast(FlaskResponse, redirect(url_for("validation_review")))

    except Exception as e:
        logging.error(f"Validation error: {e}")
        return Response(
            render_template(
                "message.html",
                message=f"Error validating files: {str(e)}",
                message_type="error-message",
                status_code=500,
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            status=500,
        )


@app.route("/validate_local", methods=["POST"])
@login_required
def validate_local_files() -> Response:
    """
    Validate local server files and redirect to validation review.
    Similar to validate_files_endpoint but for local file paths instead of uploads.

    Security: Access is restricted to paths under /home/ only.
    """
    import time as time_module
    from app.timing_stats import get_timing_stats, TimingStats
    timing = get_timing_stats()
    validation_start = time_module.time()
    timing.start_timer(TimingStats.VALIDATION_TOTAL)

    try:
        pwdump_path = request.form.get("pwdump_path", "").strip()
        potfile_path = request.form.get("potfile_path", "").strip()
        use_master = request.form.get("use_master_potfile", "false").lower() == "true"

        # Pwdump path is always required
        if not pwdump_path:
            return Response(
                render_template(
                    "message.html",
                    message="A pwdump/NTDS/ADD JSON file path is required.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Potfile path is required unless using master potfile
        if not potfile_path and not use_master:
            return Response(
                render_template(
                    "message.html",
                    message="A potfile path is required. Either provide a path or use the master potfile.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Check if master potfile is available when requested
        if use_master and (not MASTER_POTFILE_ENABLED or not os.path.exists(MASTER_POTFILE_PATH)):
            return Response(
                render_template(
                    "message.html",
                    message="Master potfile is not available. Please provide a potfile path instead.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Security: Validate that paths are within allowed directories
        if not is_allowed_path(pwdump_path):
            return Response(
                render_template(
                    "message.html",
                    message="Access denied. File access is restricted to /home/ directories only.",
                    message_type="error-message",
                    status_code=403,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=403,
            )

        if potfile_path and not use_master and not is_allowed_path(potfile_path):
            return Response(
                render_template(
                    "message.html",
                    message="Access denied. File access is restricted to /home/ directories only.",
                    message_type="error-message",
                    status_code=403,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=403,
            )

        # Check if files exist
        if not os.path.isfile(pwdump_path):
            return Response(
                render_template(
                    "message.html",
                    message=f"Pwdump file not found: {pwdump_path}",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        if potfile_path and not use_master and not os.path.isfile(potfile_path):
            return Response(
                render_template(
                    "message.html",
                    message=f"Potfile not found: {potfile_path}",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Check if the pwdump file is actually ADD JSON format
        is_add_json = file_parser.is_add_json_file(pwdump_path)

        if is_add_json:
            # Parse as ADD JSON format
            add_result = file_parser.parse_add_json(pwdump_path)

            # Extract hashes for session-optimized potfile filtering
            add_hashes = extract_hashes_from_add(add_result)

            if use_master:
                # Use master potfile only (no user potfile)
                final_potfile_result, merge_stats = load_master_potfile_only(add_hashes)
                if not final_potfile_result:
                    return Response(
                        render_template(
                            "message.html",
                            message="Failed to load master potfile.",
                            message_type="error-message",
                            status_code=500,
                            referrer="Start",
                            referrer_url=url_for("index"),
                        ),
                        status=500,
                    )
                if merge_stats:
                    session["master_potfile_merge"] = merge_stats
            else:
                # Validate user's potfile and merge with master if enabled
                potfile_result = file_parser.validate_potfile(potfile_path)
                if MASTER_POTFILE_ENABLED:
                    final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, add_hashes)
                    session["master_potfile_merge"] = merge_stats
                else:
                    final_potfile_result = potfile_result

            # Store ADD validation results in session
            session["add_validation"] = file_parser.add_result_to_dict(add_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path if potfile_path else MASTER_POTFILE_PATH
            session["input_format"] = "add_json"
            session["use_master_potfile"] = use_master

            # Store form options for later processing (includes company/project info)
            session["analysis_options"] = {
                "company_name": request.form.get("company_name", "").strip(),
                "project_description": request.form.get("project_description", "").strip(),
                "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
                "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
                "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
                "substring_min_len": request.form.get("substring_min_len", "4"),
                "substring_max_len": request.form.get("substring_max_len", "20"),
                "substring_freq_threshold": request.form.get("substring_freq_threshold", "5"),
                "substring_disp_nest": str(parse_boolean_field("substring_disp_nest")).lower(),
                "substring_normalize": str(parse_boolean_field("substring_normalize")).lower(),
                "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
                "dictionary_disp_nest": str(parse_boolean_field("dictionary_disp_nest")).lower(),
                "ignore_blank_passwords": str(parse_boolean_field("ignore_blank_passwords")).lower(),
            }

            # Redirect to ADD JSON validation review page
            return cast(FlaskResponse, redirect(url_for("validation_review_add")))
        else:
            # Standard pwdump format
            pwdump_result = file_parser.validate_pwdump_file(pwdump_path)
            item_count = pwdump_result.total_lines

            # Extract hashes for session-optimized potfile filtering
            hash_extract_start = time_module.time()
            pwdump_hashes = extract_hashes_from_pwdump(pwdump_result)
            hash_extract_duration = time_module.time() - hash_extract_start
            timing.record_sample(
                operation=TimingStats.HASH_EXTRACTION,
                duration_seconds=hash_extract_duration,
                item_count=len(pwdump_hashes)
            )

            if use_master:
                # Use master potfile only (no user potfile)
                merge_start = time_module.time()
                final_potfile_result, merge_stats = load_master_potfile_only(pwdump_hashes)
                merge_duration = time_module.time() - merge_start
                if not final_potfile_result:
                    return Response(
                        render_template(
                            "message.html",
                            message="Failed to load master potfile.",
                            message_type="error-message",
                            status_code=500,
                            referrer="Start",
                            referrer_url=url_for("index"),
                        ),
                        status=500,
                    )
                if merge_stats:
                    timing.record_sample(
                        operation=TimingStats.MASTER_POTFILE_MERGE,
                        duration_seconds=merge_duration,
                        item_count=merge_stats.get("total", 0)
                    )
                    session["master_potfile_merge"] = merge_stats
            else:
                # Validate user's potfile and merge with master if enabled
                potfile_result = file_parser.validate_potfile(potfile_path)
                if MASTER_POTFILE_ENABLED:
                    merge_start = time_module.time()
                    final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, pwdump_hashes)
                    merge_duration = time_module.time() - merge_start
                    timing.record_sample(
                        operation=TimingStats.MASTER_POTFILE_MERGE,
                        duration_seconds=merge_duration,
                        item_count=merge_stats.get("total", 0) if merge_stats else 0
                    )
                    session["master_potfile_merge"] = merge_stats
                else:
                    final_potfile_result = potfile_result

            # Store validation results in session
            session["pwdump_validation"] = file_parser.validation_result_to_dict(pwdump_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path if potfile_path else MASTER_POTFILE_PATH
            session["input_format"] = "pwdump"
            session["use_master_potfile"] = use_master

            # Store form options for later processing (includes company/project info)
            session["analysis_options"] = {
                "company_name": request.form.get("company_name", "").strip(),
                "project_description": request.form.get("project_description", "").strip(),
                "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
                "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
                "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
                "substring_min_len": request.form.get("substring_min_len", "4"),
                "substring_max_len": request.form.get("substring_max_len", "20"),
                "substring_freq_threshold": request.form.get("substring_freq_threshold", "5"),
                "substring_disp_nest": str(parse_boolean_field("substring_disp_nest")).lower(),
                "substring_normalize": str(parse_boolean_field("substring_normalize")).lower(),
                "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
                "dictionary_disp_nest": str(parse_boolean_field("dictionary_disp_nest")).lower(),
                "ignore_blank_passwords": str(parse_boolean_field("ignore_blank_passwords")).lower(),
            }

            # Stop total validation timer and redirect
            timing.stop_timer(TimingStats.VALIDATION_TOTAL, item_count=item_count)

            # Redirect to validation review page
            return cast(FlaskResponse, redirect(url_for("validation_review")))

    except Exception as e:
        logging.error(f"Local file validation error: {e}")
        return Response(
            render_template(
                "message.html",
                message=f"Error validating local files: {str(e)}",
                message_type="error-message",
                status_code=500,
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            status=500,
        )


@app.route("/validation_review")
@login_required
def validation_review() -> Response:
    """
    Display validation results and allow user to include/exclude lines.
    Can display results for one or both files.
    """
    import time as time_module
    from app.timing_stats import get_timing_stats, TimingStats

    pwdump_data = session.get("pwdump_validation")
    potfile_data = session.get("potfile_validation")
    master_merge_stats = session.get("master_potfile_merge")

    # Need at least one file to show review
    if not pwdump_data and not potfile_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    # Time the template rendering
    timing = get_timing_stats()
    render_start = time_module.time()

    result = make_response(render_template(
        "validate.html",
        pwdump=pwdump_data,
        potfile=potfile_data,
        master_potfile_enabled=MASTER_POTFILE_ENABLED,
        master_potfile_merge=master_merge_stats
    ))

    render_duration = time_module.time() - render_start
    item_count = pwdump_data.get("total_lines", 0) if pwdump_data else 0
    timing.record_sample(
        operation=TimingStats.VALIDATION_RENDER,
        duration_seconds=render_duration,
        item_count=item_count
    )

    return result


@app.route("/clear_and_restart", methods=["GET", "POST"])
@login_required
def clear_and_restart() -> Response:
    """
    Clear validation session data and redirect to a fresh Step 1.
    Used when user wants to start over with new files.
    Note: Accepts both GET and POST for usability (links and buttons).
    """
    # Clear validation-related session data
    session.pop("pwdump_validation", None)
    session.pop("potfile_validation", None)
    session.pop("pwdump_path", None)
    session.pop("potfile_path", None)
    session.modified = True

    return cast(FlaskResponse, redirect(url_for("index")))


@app.route("/validate_single", methods=["POST"])
@login_required
def validate_single_file() -> Response:
    """
    AJAX endpoint to validate a single file (pwdump or potfile) without processing.
    Returns validation results as JSON for display in the UI.
    """
    try:
        file_type = request.form.get("file_type")  # "pwdump" or "potfile"
        uploaded_file = request.files.get("file")

        if not file_type or not uploaded_file:
            return jsonify({"error": "Missing file_type or file"}), 400

        # Save file (keep it for potential validation review)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{file_type}_{secure_filename(uploaded_file.filename)}")
        uploaded_file.save(file_path)

        if file_type == "pwdump":
            # Check if the file is ADD JSON format
            if file_parser.is_add_json_file(file_path):
                # Parse as ADD JSON
                add_result = file_parser.parse_add_json(file_path)
                result_dict = file_parser.add_result_to_dict(add_result)

                # Store in session for validation review access
                session["add_validation"] = result_dict
                session["pwdump_path"] = file_path
                session["input_format"] = "add_json"
                session.modified = True

                return jsonify({
                    "success": True,
                    "file_type": "add_json",
                    "filename": uploaded_file.filename,
                    "total_lines": add_result.total_users,
                    "valid_lines": add_result.valid_users,
                    "warning_lines": 0,
                    "error_lines": add_result.error_users,
                    "formats_detected": {"add_json": add_result.total_users},
                    "status_coverage": 0,
                    "lines_with_status": 0,
                    "domain_name": add_result.domain_policy.domain_name if add_result.domain_policy else "Unknown",
                    "unique_domains": add_result.unique_domains,
                    "tier0_count": add_result.tier0_count,
                    "elevated_count": add_result.elevated_count,
                    "privileged_count": add_result.privileged_count,
                    "users_with_history": add_result.users_with_history,
                    "total_historical_hashes": add_result.total_historical_hashes,
                    "problem_lines": [
                        {
                            "line_number": i + 1,
                            "username": entry.sam_account_name,
                            "status": "disabled" if entry.is_disabled else "enabled",
                            "is_valid": entry.is_valid,
                            "errors": [{"severity": e.severity.value, "message": e.message} for e in entry.errors],
                            "raw_line": f"{entry.sam_account_name} ({entry.logon_name})"
                        }
                        for i, entry in enumerate(add_result.entries) if entry.errors
                    ]
                })
            else:
                # Standard pwdump format
                result = file_parser.validate_pwdump_file(file_path)
                result_dict = file_parser.validation_result_to_dict(result)

                # Store in session for validation review access
                session["pwdump_validation"] = result_dict
                session["pwdump_path"] = file_path
                session["input_format"] = "pwdump"
                session.modified = True

                # Calculate status coverage
                lines_with_status = sum(1 for line in result.lines if line.status is not None and line.is_valid)
                valid_lines = result.valid_lines
                status_coverage = (lines_with_status / valid_lines * 100) if valid_lines > 0 else 0

                return jsonify({
                    "success": True,
                    "file_type": "pwdump",
                    "filename": uploaded_file.filename,
                    "total_lines": result.total_lines,
                    "valid_lines": result.valid_lines,
                    "warning_lines": result.warning_lines,
                    "error_lines": result.error_lines,
                    "formats_detected": result.formats_detected,
                    "status_coverage": round(status_coverage, 1),
                    "lines_with_status": lines_with_status,
                    "problem_lines": [
                        {
                            "line_number": line.line_number,
                            "username": line.username,
                            "status": line.status,
                            "is_valid": line.is_valid,
                            "errors": [{"severity": e.severity.value, "message": e.message} for e in line.errors],
                            "raw_line": line.raw_line[:80] + ("..." if len(line.raw_line) > 80 else "")
                        }
                        for line in result.lines if line.errors
                    ]
                })
        else:  # potfile
            result = file_parser.validate_potfile(file_path)
            result_dict = file_parser.potfile_result_to_dict(result)

            # Store in session for validation review access
            session["potfile_validation"] = result_dict
            session["potfile_path"] = file_path
            session.modified = True

            return jsonify({
                "success": True,
                "file_type": "potfile",
                "filename": uploaded_file.filename,
                "total_lines": result.total_lines,
                "valid_lines": result.valid_lines,
                "error_lines": result.error_lines,
                "ntlm_count": result.ntlm_count,
                "non_ntlm_count": result.non_ntlm_count,
                "hash_type_summary": {
                    mode: {"name": info["name"], "count": info["count"], "is_ntlm": info["is_ntlm"]}
                    for mode, info in result.hash_type_summary.items()
                } if result.hash_type_summary else {},
                "problem_entries": [
                    {
                        "line_number": entry.line_number,
                        "is_valid": entry.is_valid,
                        "errors": [{"severity": e.severity.value, "message": e.message} for e in entry.errors],
                        "raw_line": entry.raw_line[:80] + ("..." if len(entry.raw_line) > 80 else "")
                    }
                    for entry in result.entries if entry.errors
                ]
            })

    except Exception as e:
        logging.error(f"Single file validation error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/update_selections", methods=["POST"])
@login_required
def update_selections() -> Response:
    """
    AJAX endpoint to update line include/exclude selections.
    """
    data = request.get_json()
    file_type = data.get("file_type")  # "pwdump" or "potfile"
    line_number = data.get("line_number")
    included = data.get("included")

    session_key = f"{file_type}_validation"
    validation_data = session.get(session_key)

    if validation_data:
        key_name = "lines" if file_type == "pwdump" else "entries"
        for line in validation_data[key_name]:
            if line["line_number"] == line_number:
                line["included"] = included
                break
        session[session_key] = validation_data
        session.modified = True

    return jsonify({"status": "ok"})


@app.route("/api/duplicate_handling", methods=["POST"])
@login_required
def save_duplicate_handling() -> Response:
    """
    Save user's duplicate handling preference to session.

    Stores:
    - method: "first", "last", or "manual"
    - manual_selections: dict mapping account names to line numbers to keep
    """
    data = request.get_json()
    handling = data.get("handling", "first")
    manual_selections = data.get("manual_selections", {})

    session["duplicate_handling"] = {
        "method": handling,
        "manual_selections": manual_selections
    }
    session.modified = True

    return jsonify({"success": True})


@app.route("/process_validated", methods=["GET", "POST"])
@login_required
def process_validated() -> Response:
    """
    Process validated files with user's include/exclude decisions.
    Accepts options from form data (POST) or falls back to session data.
    Creates a new analysis session to store results.
    """
    import time as time_module
    from app.timing_stats import get_timing_stats
    report_start_time = time_module.time()

    pwdump_data = session.get("pwdump_validation")
    potfile_data = session.get("potfile_validation")

    # Get options from form data if POST, otherwise from session
    # Preserve company_name and project_description from session (set in Step 1) if not in form
    existing_options = session.get("analysis_options", {})
    if request.method == "POST" and request.form:
        options = {
            "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
            "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
            "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
            "substring_min_len": request.form.get("substring_min_len", "4"),
            "substring_max_len": request.form.get("substring_max_len", "20"),
            "substring_freq_threshold": request.form.get("substring_freq_threshold", "5"),
            "substring_disp_nest": str(parse_boolean_field("substring_disp_nest")).lower(),
            "substring_normalize": str(parse_boolean_field("substring_normalize")).lower(),
            "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
            "dictionary_disp_nest": str(parse_boolean_field("dictionary_disp_nest")).lower(),
            "ignore_disabled_accounts": str(parse_boolean_field("ignore_disabled_accounts")).lower(),
            "ignore_computer_accounts": str(parse_boolean_field("ignore_computer_accounts")).lower(),
            "ignore_blank_passwords": str(parse_boolean_field("ignore_blank_passwords")).lower(),
            "include_history_in_reports": str(parse_boolean_field("include_history_in_reports")).lower(),
            "custom_keywords": request.form.get("custom_keywords", ""),
            "domain_filter": request.form.get("domain_filter", "all"),
            # Preserve company_name/project_description from session if not in form (validate.html doesn't have these)
            "company_name": request.form.get("company_name", "").strip() or existing_options.get("company_name", ""),
            "project_description": request.form.get("project_description", "").strip() or existing_options.get("project_description", ""),
            # Mark as pwdump session for filter editing support
            "input_format": "pwdump",
        }
        # Store in session for consistency
        session["analysis_options"] = options
    else:
        options = existing_options
        # Ensure input_format is set for pwdump sessions
        if "input_format" not in options:
            options["input_format"] = "pwdump"
    pwdump_path = session.get("pwdump_path")
    potfile_path = session.get("potfile_path")

    if not pwdump_data or not potfile_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    try:
        # Reconstruct pwdump validation result from session
        pwdump_result = file_parser.dict_to_validation_result(pwdump_data)

        # Apply duplicate handling if duplicates were detected
        if pwdump_result.has_duplicates:
            duplicate_handling = session.get("duplicate_handling", {"method": "first"})
            _apply_duplicate_handling(pwdump_result, duplicate_handling)

        # Optimization: If using master potfile, use cached dict directly
        # This avoids creating 620K+ PotfileEntry objects
        cracked_hashes = None
        if MASTER_POTFILE_ENABLED:
            cracked_hashes = get_cracked_hashes_direct(MASTER_POTFILE_PATH)

        # Determine if password history entries should be included in main analysis
        # Default is to exclude them (only analyze in Password History Pattern Analysis)
        include_history = options.get("include_history_in_reports", "false") == "true"

        if cracked_hashes is not None:
            # Use optimized path - direct cache access
            account_data = file_parser.build_account_data_with_cache(
                pwdump_result,
                cracked_hashes,
                ignore_disabled=options.get("ignore_disabled_accounts", "false") == "true",
                ignore_computer_accounts=options.get("ignore_computer_accounts", "false") == "true",
                ignore_history_accounts=not include_history,
            )
        else:
            # Fall back to standard path for non-master potfiles
            potfile_result = file_parser.dict_to_potfile_result(potfile_data)
            account_data = file_parser.build_account_data(
                pwdump_result,
                potfile_result,
                ignore_disabled=options.get("ignore_disabled_accounts", "false") == "true",
                ignore_computer_accounts=options.get("ignore_computer_accounts", "false") == "true",
                ignore_history_accounts=not include_history,
            )

        # Apply domain filter if specified
        domain_filter = options.get("domain_filter", "all")
        if domain_filter and domain_filter.lower() != "all":
            account_data = filter_accounts_by_domain(account_data, domain_filter)
            app.logger.info(f"Applied domain filter '{domain_filter}', {len(account_data)} accounts remaining")

        if not account_data:
            return Response(
                render_template(
                    "message.html",
                    message="No valid accounts to process after filtering.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Import analysis tools
        from app import password_analysis_tools

        # Run analysis
        stats_report = password_analysis_tools.crack_stats(
            account_data,
            int(options.get("policy_min_pw_len", "8")),
            int(options.get("policy_complexity_req", "3")),
            ignore_blank_passwords=options.get("ignore_blank_passwords", "false") == "true",
            max_pw_age=int(options.get("policy_max_pw_age", "90")),
        )

        # Convert stats to array format
        key_order = [
            "Cracked Accounts: ",
            "Uncracked Accounts: ",
            "Total Accounts Analyzed: ",
            "Percent of Accounts Cracked: ",
            "Cracked NTLM Hashes: ",
            "Uncracked NTLM Hashes: ",
            "Unique NTLM Hashes Analyzed: ",
            "Percent of NTLM Hashes Cracked: ",
            "Total LANMan Hashes: ",
            "Shortest Cracked Password: ",
            "Longest Cracked Password: ",
            "Average Password Length: ",
        ]
        stats_table = [{"key": key, "value": stats_report["cracking_stats"][key]} for key in key_order]

        # Create list of cracked passwords (for dictionary analysis)
        cracked_passwords = [
            account["cracked_pw"]
            for account in account_data.values()
            if account.get("cracked_pw")
        ]

        # Create list of account/password entries (for substring analysis)
        account_password_entries = [
            {"account": username, "password": account["cracked_pw"]}
            for username, account in account_data.items()
            if account.get("cracked_pw")
        ]

        # Run substring analysis
        substrings = password_analysis_tools.substring_analysis(
            account_password_entries,
            int(options.get("substring_min_len", "4")),
            int(options.get("substring_max_len", "20")),
            int(options.get("substring_freq_threshold", "5")),
            options.get("substring_normalize", "false") == "true",
            options.get("substring_disp_nest", "false") == "true",
        )

        # Run dictionary analysis
        detailed_results, english_words = password_analysis_tools.dictionary_analysis(
            cracked_passwords,
            int(options.get("dictionary_min_len", "4")),
            options.get("dictionary_disp_nest", "false") == "true",
        )

        # Parse custom keywords from form (newlines and commas supported)
        custom_keywords_raw = options.get("custom_keywords", "").strip()
        custom_keywords = []
        if custom_keywords_raw:
            # Split by newlines and commas, then strip whitespace
            for line in custom_keywords_raw.replace(",", "\n").split("\n"):
                keyword = line.strip()
                if keyword:
                    custom_keywords.append(keyword)

        # Run bad practices analysis (pass account entries for username-in-password detection)
        bad_practices = password_analysis_tools.bad_practices_analysis(
            cracked_passwords, custom_keywords, account_password_entries
        )

        # Check password reuse using in-memory account_data (avoids re-reading file)
        pw_reuse_table = password_analysis_tools.check_pw_reuse_from_account_data(account_data)

        # Build cracked_hashes lookup from potfile (uses cache for master potfile)
        # Note: cracked_hashes may already be set from the optimized path above
        if cracked_hashes is None:
            # Need to build from potfile_result (non-master potfile case)
            cracked_hashes = build_cracked_hashes_fast(potfile_result)
        # Ensure blank hash is included for history analysis (in-place update avoids dict copy)
        if file_parser.BLANK_NTLM_HASH not in cracked_hashes:
            cracked_hashes[file_parser.BLANK_NTLM_HASH] = ""

        # Run password history pattern analysis (for pwdump with _history entries)
        pwdump_lines_data = [
            {
                'username': line.username,
                'ntlm_hash': line.ntlm_hash,
                'is_valid': line.is_valid,
                'included': line.included
            }
            for line in pwdump_result.lines if line.username
        ]
        history_pattern_analysis = password_history.analyze_password_history(
            pwdump_data=pwdump_lines_data,
            cracked_hashes=cracked_hashes
        )
        history_pattern_results = password_history.history_analysis_to_dict(history_pattern_analysis)

        # Create a new session for this analysis
        session_mgr = get_session_manager()

        # Get company/project info from options, or generate defaults
        company_name = options.get("company_name", "")
        project_description = options.get("project_description", "")
        if not company_name:
            company_name = "Unknown"
        if not project_description:
            # Auto-generate from pwdump filename
            pwdump_filename = os.path.basename(pwdump_path) if pwdump_path else "unknown"
            project_description = f"Analysis - {pwdump_filename}"

        # Compute source hash for staleness detection
        source_hash = session_mgr.compute_source_hash(account_data=list(account_data.values()))

        # Create the session
        analysis_session = session_mgr.create_session(
            name="",  # Auto-generated from company + project
            username=current_user.id,
            source_files={
                "pwdump": os.path.basename(pwdump_path) if pwdump_path else "",
                "potfile": os.path.basename(potfile_path) if potfile_path else ""
            },
            source_hash=source_hash,
            company_name=company_name,
            project_description=project_description
        )

        # Set as current session
        session_mgr.set_current_session(analysis_session.session_id, current_user.id)

        # Save all data files to the session folder
        session_mgr.save_session_data("cracking_stats_table.json", stats_table, analysis_session.session_id)
        session_mgr.save_session_data("pw_account_pie.json", stats_report["pw_account_pie"], analysis_session.session_id)
        session_mgr.save_session_data("pw_ntlm_hash_pie.json", stats_report["pw_ntlm_hash_pie"], analysis_session.session_id)
        session_mgr.save_session_data("pw_length_distribution.json", stats_report["pw_length_distribution"], analysis_session.session_id)
        session_mgr.save_session_data("pw_top_passwords.json", stats_report["pw_top_passwords"], analysis_session.session_id)
        session_mgr.save_session_data("pw_substrings.json", substrings, analysis_session.session_id)
        session_mgr.save_session_data("pw_dict_words.json", english_words, analysis_session.session_id)
        session_mgr.save_session_data("pw_reuse_table.json", pw_reuse_table, analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_min_length.json", stats_report["pw_fails_min_length"], analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_complexity.json", stats_report["pw_fails_complexity"], analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_blank.json", stats_report["pw_fails_blank"], analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_max_age.json", stats_report["pw_fails_max_age"], analysis_session.session_id)
        session_mgr.save_session_data("pw_lm_hashes.json", stats_report["pw_lm_hashes"], analysis_session.session_id)
        session_mgr.save_session_data("pw_bad_practices.json", bad_practices, analysis_session.session_id)
        session_mgr.save_session_data("account_data.json", account_data, analysis_session.session_id)
        session_mgr.save_session_data("analysis_options.json", options, analysis_session.session_id)
        session_mgr.save_session_data("password_history_patterns.json", history_pattern_results, analysis_session.session_id)

        # Calculate stale logins (days since last login exceeding 90 days)
        stale_logins = password_analysis_tools.stale_login_analysis(
            account_data, max_days=90
        )
        session_mgr.save_session_data("stale_logins.json", stale_logins, analysis_session.session_id)

        # Generate all cracked accounts list
        cracked_accounts_list = _generate_cracked_accounts_list(account_data)
        session_mgr.save_session_data("pw_cracked_accounts.json", cracked_accounts_list, analysis_session.session_id)

        # Save validation data for domain filter changes later
        session_mgr.save_session_data("pwdump_validation.json", pwdump_data, analysis_session.session_id)
        session_mgr.save_session_data("potfile_validation.json", potfile_data, analysis_session.session_id)

        # Save domain info for domain filter dropdown in settings
        if pwdump_data.get("domain_info"):
            session_mgr.save_session_data("domain_info.json", pwdump_data["domain_info"], analysis_session.session_id)

        # Update session with statistics
        cracked_count = sum(1 for acc in account_data.values() if acc.get("cracked_pw"))
        total_count = len(account_data)
        crack_rate = (cracked_count / total_count * 100) if total_count > 0 else 0.0
        session_mgr.update_session(
            analysis_session.session_id,
            total_accounts=total_count,
            cracked_accounts=cracked_count,
            crack_rate=round(crack_rate, 2)
        )

        # Run automatic HIBP check if local database is available
        session_dir = session_mgr.get_session_dir(analysis_session.session_id)
        hibp_results = run_automatic_hibp_check(account_data, session_dir)
        if hibp_results:
            print(f"--> HIBP breach check: {hibp_results['total_found']}/{hibp_results['total_checked']} passwords found in breaches ({hibp_results['found_percentage']}%)")

        # Clean up Flask session
        session.pop("pwdump_validation", None)
        session.pop("potfile_validation", None)
        session.pop("pwdump_path", None)
        session.pop("potfile_path", None)
        session.pop("analysis_options", None)

        # Record timing for report generation
        report_duration = time_module.time() - report_start_time
        timing = get_timing_stats()
        timing.record_sample(
            operation="report_generation",
            duration_seconds=report_duration,
            item_count=total_count
        )

        print(f"\nPassword and hash analysis complete. Session created: {analysis_session.name} ({analysis_session.session_id})\n")
        print(f"Report generation took {report_duration:.2f}s for {total_count} accounts")
        return cast(FlaskResponse, redirect(url_for("report")))

    except Exception as e:
        logging.error(f"Error processing validated files: {e}")
        return Response(
            render_template(
                "message.html",
                message=f"Error processing files: {str(e)}",
                message_type="error-message",
                status_code=500,
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            status=500,
        )


@app.route("/report")
@login_required
def report() -> str:
    return render_template("report.html")


@app.route("/sessions")
@login_required
def sessions_page() -> str:
    """Session management page with sorting, grouping, and bulk operations."""
    return render_template("sessions.html", advanced_options_enabled=ADVANCED_OPTIONS_ENABLED, return_url=get_advanced_mode_return_url())


@app.route("/hiddenpages")
@app.route("/hidden")
@login_required
def hidden_pages_index() -> str:
    """Index page for hidden/development pages and tools."""
    from app.ollama_tools import get_ollama_config, get_cached_server_status

    # Get Ollama config (instant - no network calls)
    config = get_ollama_config()
    ollama_enabled = config.enabled if config else False

    # Use cached server status if available (instant), otherwise JS will fetch async
    cached_status = get_cached_server_status() if ollama_enabled else None
    servers = cached_status.get("servers", []) if cached_status else []

    return render_template(
        'hidden_index.html',
        ollama_enabled=ollama_enabled,
        servers=servers,
        servers_from_cache=cached_status is not None,
        return_url=get_advanced_mode_return_url()
    )


@app.route("/hibp/download")
@login_required
def hibp_download_page() -> str:
    """HIBP database download management page."""
    return render_template('hibp_download.html', return_url=get_advanced_mode_return_url())


@app.route("/timing/stats")
@login_required
def timing_stats_page() -> str:
    """Timing statistics page."""
    return render_template('timing_stats.html', return_url=get_advanced_mode_return_url())


@app.route("/system/health")
@login_required
def system_health_page() -> str:
    """System health monitoring dashboard."""
    return render_template('system_health.html', return_url=get_advanced_mode_return_url())


@app.route("/api/system/health/detailed")
@login_required
def system_health_detailed() -> Response:
    """
    Detailed system health information for the dashboard.
    Includes worker status, active requests, and system metrics.
    """
    import os

    # Count connected agents from shared file (multi-worker consistent)
    sse_connections = _get_sse_connections()
    connected_agents = len(sse_connections)

    # Get agent stats from database
    db = _get_db()
    agent_stats = db.get_agent_stats()
    total_agents = agent_stats['total_agents']
    active_jobs = agent_stats['active_jobs']

    # Get potfile stats if available (use cached count to avoid slow load)
    potfile_count = 0
    if MASTER_POTFILE_ENABLED:
        try:
            cache = get_master_cache()
            if cache and cache._cache:
                potfile_count = cache._cache.ntlm_count
        except Exception:
            pass

    # Worker info
    workers_configured = 12
    threads_configured = 2
    try:
        import importlib.util
        gunicorn_conf_path = os.path.join(os.path.dirname(__file__), "gunicorn.conf.py")
        if os.path.exists(gunicorn_conf_path):
            spec = importlib.util.spec_from_file_location("gunicorn_conf", gunicorn_conf_path)
            if spec and spec.loader:
                gunicorn_conf = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(gunicorn_conf)
                workers_configured = getattr(gunicorn_conf, "workers", 12)
                threads_configured = getattr(gunicorn_conf, "threads", 2)
    except Exception:
        pass

    # Active user sessions from shared file (multi-worker consistent)
    now = time.time()
    session_timeout = 3600
    shared_activity = _get_user_activity_shared()
    active_users = [
        username for username, last_seen in shared_activity.items()
        if (now - last_seen) < session_timeout
    ]

    # Session count
    session_count = 0
    try:
        session_dir = app.config.get("SESSION_FILE_DIR", "flask_session")
        if os.path.isdir(session_dir):
            for fname in os.listdir(session_dir):
                fpath = os.path.join(session_dir, fname)
                if os.path.isfile(fpath):
                    mtime = os.path.getmtime(fpath)
                    if (now - mtime) < session_timeout:
                        session_count += 1
    except Exception:
        pass

    return jsonify({
        "status": "healthy",
        "version": "2.0.0",
        "uptime_seconds": int(time.time() - _app_start_time),
        "workers": {
            "configured": workers_configured,
            "threads_per_worker": threads_configured,
            "total_capacity": workers_configured * threads_configured,
            "current_pid": os.getpid(),
        },
        "users": {
            "active_sessions": session_count,
            "logged_in": sorted(active_users),
        },
        "agents": {
            "total": total_agents,
            "connected": connected_agents,
            "active_jobs": active_jobs,
        },
        "potfile": {
            "entries": potfile_count,
        },
        "requests": _get_active_requests_summary(),
        "server_time": datetime.now().isoformat(),
    })


@app.route("/system/logs")
@login_required
def system_logs_page() -> str:
    """System logs viewer page."""
    return render_template('system_logs.html', return_url=get_advanced_mode_return_url())


@app.route("/api/system/logs")
@login_required
def api_system_logs() -> Response:
    """
    Get application logs from the log file.

    Query params:
        - limit: Maximum number of entries to return (default: 500, max: 2000)
        - level: Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        - search: Filter by search term in message or logger name
    """
    limit = min(int(request.args.get('limit', 500)), 2000)
    level = request.args.get('level')
    search = request.args.get('search')

    logs, total_lines = _read_log_file(limit=limit, level=level, search=search)

    # Get file size info
    file_size = 0
    try:
        if os.path.exists(_LOG_FILE_PATH):
            file_size = os.path.getsize(_LOG_FILE_PATH)
    except Exception:
        pass

    return jsonify({
        "logs": logs,
        "total_lines": total_lines,
        "file_size_bytes": file_size,
        "file_size_mb": round(file_size / (1024 * 1024), 2),
        "filtered_count": len(logs),
    })


@app.route("/api/system/logs/clear", methods=["POST"])
@login_required
def api_system_logs_clear() -> Response:
    """Clear the log file."""
    if _clear_log_file():
        return jsonify({"success": True, "message": "Log file cleared"})
    else:
        return jsonify({"success": False, "message": "Failed to clear log file"}), 500


@app.route("/api/timing/status")
@login_required
def api_timing_status() -> Response:
    """Get timing statistics status."""
    from app.timing_stats import get_timing_stats
    timing = get_timing_stats()
    return jsonify(timing.get_status())


@app.route("/api/timing/clear", methods=["POST"])
@login_required
def api_timing_clear() -> Response:
    """Clear all timing statistics."""
    from app.timing_stats import get_timing_stats
    timing = get_timing_stats()
    timing.clear_stats()
    return jsonify({"success": True})


@app.route("/api/timing/estimate")
@login_required
def api_timing_estimate() -> Response:
    """
    Get time estimates for processing operations.

    Query params:
        - phase: Operation phase ('report_generation', 'validation', etc.)
        - hash_count: Number of hashes/accounts to process
        - account_count: Number of accounts (alternative to hash_count)
        - cracked_count: Number of cracked passwords
        - unique_hashes: Number of unique hashes (optional)
        - hibp_enabled: Whether HIBP check is enabled (true/false)
        - hibp_mode: HIBP mode (sqlite, binary_search, api)
    """
    from app.timing_stats import get_timing_stats

    timing = get_timing_stats()

    # Support simple phase-based estimation
    phase = request.args.get('phase')
    hash_count = request.args.get('hash_count', 0, type=int)

    if phase and hash_count > 0:
        # Simple operation estimation based on phase
        operation_map = {
            'report_generation': 'report_generation',
            'validation': 'pwdump_validation',
        }
        operation = operation_map.get(phase, phase)
        estimate = timing.estimate_duration(operation, hash_count)

        if estimate:
            return jsonify({
                "operation": operation,
                "item_count": hash_count,
                "estimated_total_seconds": estimate,
                "confidence": "medium" if timing._operations.get(operation, None) else "low"
            })
        else:
            # No historical data yet - provide a rough estimate based on typical performance
            # Rough estimate: ~1000 accounts per second for report generation
            rough_estimate = hash_count / 1000.0 if hash_count > 0 else 0
            return jsonify({
                "operation": operation,
                "item_count": hash_count,
                "estimated_total_seconds": max(rough_estimate, 2.0),  # At least 2 seconds
                "confidence": "low",
                "note": "Estimate based on default assumptions - no historical data available yet"
            })

    # Fall back to detailed phase processing estimates
    account_count = request.args.get('account_count', hash_count, type=int)
    cracked_count = request.args.get('cracked_count', 0, type=int)
    unique_hashes = request.args.get('unique_hashes', type=int)
    hibp_enabled = request.args.get('hibp_enabled', 'false').lower() == 'true'
    hibp_mode = request.args.get('hibp_mode')

    estimates = timing.estimate_processing_phase(
        account_count=account_count,
        cracked_count=cracked_count,
        hibp_enabled=hibp_enabled,
        hibp_mode=hibp_mode,
        unique_hash_count=unique_hashes,
    )

    return jsonify(estimates)


@app.route("/api/timing/systems")
@login_required
def api_timing_systems() -> Response:
    """Get system comparison data across all systems that have run the app."""
    from app.timing_stats import get_timing_stats

    timing = get_timing_stats()
    systems = timing.get_systems_comparison()
    return jsonify({"systems": systems})


# Helper function to load session data with fallback to legacy paths
def _load_session_json(filename: str) -> dict | None:
    """
    Load JSON data from the current session folder.
    Falls back to legacy data/ folder if no session is active.
    Returns None if file doesn't exist.
    """
    session_mgr = get_session_manager()
    data = session_mgr.load_session_data(filename)
    return data


def _generate_cracked_accounts_list(account_data: dict) -> list[dict]:
    """
    Generate a list of all cracked accounts with password, age, and status.

    Args:
        account_data: Dictionary of account data from analysis

    Returns:
        List of dicts with account, password, password_age, and status
    """
    from datetime import date, datetime

    today = date.today()
    cracked_accounts = []

    for account_name, account in account_data.items():
        cracked_pw = account.get("cracked_pw")
        if not cracked_pw:
            continue

        # Calculate password age
        pw_age = None
        last_pw_change = account.get("last_pw_change")
        if last_pw_change and last_pw_change not in ("0", ""):
            try:
                pw_change_date = None
                if isinstance(last_pw_change, str):
                    for fmt in ["%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y"]:
                        try:
                            pw_change_date = datetime.strptime(last_pw_change, fmt).date()
                            break
                        except ValueError:
                            continue
                if pw_change_date:
                    pw_age = (today - pw_change_date).days
            except (ValueError, TypeError):
                pass

        # Determine status
        is_disabled = account.get("disabled")
        status = "Disabled" if is_disabled else "Enabled"

        cracked_accounts.append({
            "account": account_name,
            "password": cracked_pw,
            "password_age": pw_age,
            "status": status,
        })

    # Sort by account name
    cracked_accounts.sort(key=lambda x: x["account"].lower())

    return cracked_accounts


# Endpoint for Project Statistics Table
@app.route("/cracking_stats_table")
@login_required
def cracking_stats_table() -> Response:
    data = _load_session_json("cracking_stats_table.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Breach Statistics Table
@app.route("/breach_stats")
@login_required
def breach_stats() -> Response:
    data = _load_session_json("breach_stats.json")
    if data is None:
        return jsonify({"error": "No breach data available"}), 404
    return jsonify(data)


# Endpoint for Cracked Accounts Pie Chart data
@app.route("/pw_account_pie")
@login_required
def pw_account_pie() -> Response:
    data = _load_session_json("pw_account_pie.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Cracked Hashes Pie Chart data
@app.route("/pw_ntlm_hash_pie")
@login_required
def pw_ntlm_hash_pie() -> Response:
    data = _load_session_json("pw_ntlm_hash_pie.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for analysis options (includes domain filter)
@app.route("/analysis_options.json")
@login_required
def analysis_options_json() -> Response:
    data = _load_session_json("analysis_options.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for master potfile status (for header indicator)
@app.route("/api/master_potfile/status")
@login_required
def master_potfile_status() -> Response:
    """Return master potfile status and count for header display."""
    if not MASTER_POTFILE_ENABLED:
        return jsonify({
            "enabled": False,
            "count": 0
        })

    # Load cache (will reload if file mtime changed, e.g., from agent merges)
    cache = get_master_cache()
    cached_potfile = cache.load(MASTER_POTFILE_PATH)
    count = cached_potfile.total_entries if cached_potfile else 0

    return jsonify({
        "enabled": True,
        "count": count
    })


# Endpoint to use master potfile instead of uploading one
@app.route("/api/use_master_potfile", methods=["POST"])
@login_required
def use_master_potfile() -> Response:
    """
    Return master potfile validation data for use instead of uploading a potfile.
    This allows users to skip providing a potfile when master potfile is available.
    """
    if not MASTER_POTFILE_ENABLED:
        return jsonify({"error": "Master potfile is not enabled"}), 400

    if not os.path.exists(MASTER_POTFILE_PATH):
        return jsonify({"error": "Master potfile not found"}), 404

    try:
        # Load cached master potfile
        cache = get_master_cache()
        cached_potfile = cache.load(MASTER_POTFILE_PATH)

        if not cached_potfile:
            return jsonify({"error": "Failed to load master potfile"}), 500

        return jsonify({
            "valid": True,
            "file_path": MASTER_POTFILE_PATH,
            "ntlm_count": cached_potfile.ntlm_count,
            "total_lines": cached_potfile.total_entries,
            "use_master": True
        })

    except Exception as e:
        logging.error(f"Error loading master potfile: {e}")
        return jsonify({"error": str(e)}), 500


# Endpoint for Password Length Distribution Bar Chart data
@app.route("/pw_length_distribution")
@login_required
def pw_length_distribution() -> Response:
    data = _load_session_json("pw_length_distribution.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Top X Cracked Passwords Bar Chart data
@app.route("/pw_top_passwords")
@login_required
def pw_top_passwords() -> Response:
    data = _load_session_json("pw_top_passwords.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Top X Substrings Bar Chart data
@app.route("/pw_substrings")
@login_required
def pw_substrings() -> Response:
    data = _load_session_json("pw_substrings.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Top X Dictionary Words Bar Chart data
@app.route("/pw_dict_words")
@login_required
def pw_dict_words() -> Response:
    data = _load_session_json("pw_dict_words.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Password Reuse Table data
@app.route("/pw_reuse_table")
@login_required
def pw_reuse_table() -> Response:
    data = _load_session_json("pw_reuse_table.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Password Fails Min Length
@app.route("/pw_fails_min_length")
@login_required
def pw_min_len_table() -> Response:
    data = _load_session_json("pw_fails_min_length.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Password Fails Complexity
@app.route("/pw_fails_complexity")
@login_required
def pw_complexity_table() -> Response:
    data = _load_session_json("pw_fails_complexity.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Password Fails Blank
@app.route("/pw_fails_blank")
@login_required
def pw_blank_table() -> Response:
    data = _load_session_json("pw_fails_blank.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Password Fails Max Age
@app.route("/pw_fails_max_age")
@login_required
def pw_max_age_table() -> Response:
    data = _load_session_json("pw_fails_max_age.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Stale Logins (Days Since Last Login)
@app.route("/stale_logins")
@login_required
def stale_logins_table() -> Response:
    data = _load_session_json("stale_logins.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Accounts with LM Hashes
@app.route("/pw_lm_hashes")
@login_required
def pw_lm_hashes_table() -> Response:
    data = _load_session_json("pw_lm_hashes.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Bad Practices Analysis
@app.route("/pw_bad_practices")
@login_required
def pw_bad_practices() -> Response:
    data = _load_session_json("pw_bad_practices.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for All Cracked Accounts Table
@app.route("/pw_cracked_accounts")
@login_required
def pw_cracked_accounts() -> Response:
    data = _load_session_json("pw_cracked_accounts.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Password History Pattern Analysis
@app.route("/password_history_patterns.json")
@login_required
def password_history_patterns() -> Response:
    data = _load_session_json("password_history_patterns.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


@app.route("/api/password_history/summary")
@login_required
def password_history_summary() -> Response:
    """Get password history summary without full user list for fast initial page load."""
    data = _load_session_json("password_history_patterns.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404

    # Return summary without the large top_predictable_users array
    summary = {
        "total_users_analyzed": data.get("total_users_analyzed", 0),
        "users_with_history": data.get("users_with_history", 0),
        "users_with_cracked_history": data.get("users_with_cracked_history", 0),
        "users_with_patterns": data.get("users_with_patterns", 0),
        "pattern_counts": data.get("pattern_counts", {}),
        "users_with_hash_reuse": data.get("users_with_hash_reuse", 0),
        "users_with_consecutive_duplicates": data.get("users_with_consecutive_duplicates", 0),
        "predictable_users_count": len(data.get("top_predictable_users", []))
    }
    return jsonify(summary)


@app.route("/api/password_history/paginated")
@login_required
def password_history_paginated() -> Response:
    """
    Get paginated password history results for DataTables server-side processing.

    Query parameters (DataTables server-side):
    - draw: DataTables draw counter
    - start: Starting record index
    - length: Number of records to return
    - search[value]: Global search term
    - order[0][column]: Column index to sort by
    - order[0][dir]: Sort direction (asc/desc)
    """
    data = _load_session_json("password_history_patterns.json")
    if data is None:
        return jsonify({
            "draw": int(request.args.get("draw", 1)),
            "recordsTotal": 0,
            "recordsFiltered": 0,
            "data": []
        })

    users = data.get("top_predictable_users", [])

    # Get DataTables parameters
    draw = int(request.args.get("draw", 1))
    start = int(request.args.get("start", 0))
    length = int(request.args.get("length", 10))
    search_value = request.args.get("search[value]", "").lower()
    order_column = int(request.args.get("order[0][column]", 1))  # Default: predictability_score
    order_dir = request.args.get("order[0][dir]", "desc")

    # Column mapping for sorting (0=expand icon, 1=username, 2=score, 3=patterns, 4=evolution)
    column_map = {
        0: "username",
        1: "predictability_score",
        2: "patterns",
        3: "full_history"
    }
    sort_key = column_map.get(order_column, "predictability_score")

    records_total = len(users)

    # Apply search filter
    if search_value:
        filtered_users = []
        for user in users:
            username_match = search_value in user.get("username", "").lower()
            # Search in patterns
            pattern_match = any(
                search_value in p.get("type", "").lower()
                for p in user.get("patterns", [])
            )
            # Search in passwords
            password_match = any(
                search_value in str(entry.get("password", "")).lower()
                for entry in user.get("full_history", [])
                if entry.get("password")
            )
            if username_match or pattern_match or password_match:
                filtered_users.append(user)
        users = filtered_users

    records_filtered = len(users)

    # Sort results
    reverse = order_dir == "desc"
    try:
        if sort_key == "predictability_score":
            users.sort(key=lambda x: x.get("predictability_score", 0), reverse=reverse)
        elif sort_key == "username":
            users.sort(key=lambda x: x.get("username", "").lower(), reverse=reverse)
        elif sort_key == "patterns":
            users.sort(key=lambda x: len(x.get("patterns", [])), reverse=reverse)
        elif sort_key == "full_history":
            users.sort(key=lambda x: len(x.get("full_history", [])), reverse=reverse)
    except (TypeError, AttributeError):
        pass

    # Paginate
    paginated = users[start:start + length]

    # Format response for DataTables - send the full user objects
    # The client-side rendering will format them properly
    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": paginated
    })


# Endpoint for Privileged Accounts (ADD JSON)
@app.route("/privileged_accounts.json")
@login_required
def privileged_accounts() -> Response:
    data = _load_session_json("privileged_accounts.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Password Sharing Findings (ADD JSON)
@app.route("/password_sharing_findings.json")
@login_required
def password_sharing_findings() -> Response:
    data = _load_session_json("password_sharing_findings.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
    return jsonify(data)


# Endpoint for Kerberoast Exposure Report (ADD JSON)
@app.route("/kerberoast_report.json")
@login_required
def kerberoast_report() -> Response:
    """Return Kerberoast exposure analysis report for the current session."""
    data = _load_session_json("kerberoast_report.json")
    if data is None:
        return jsonify({"error": "No Kerberoast data available. This report requires ADD JSON input with SPNs."}), 404
    return jsonify(data)


# Endpoint for AS-REP Roasting Exposure Report (ADD JSON)
@app.route("/asrep_report.json")
@login_required
def asrep_report() -> Response:
    """Return AS-REP roasting exposure analysis report for the current session."""
    data = _load_session_json("asrep_report.json")
    if data is None:
        return jsonify({"error": "No AS-REP data available. This report requires ADD JSON input with DONT_REQ_PREAUTH accounts."}), 404
    return jsonify(data)


# Endpoint for AD Description Analysis Report (ADD JSON)
@app.route("/description_analysis_report.json")
@login_required
def description_analysis_report() -> Response:
    """Return AD description analysis report for the current session."""
    data = _load_session_json("description_analysis_report.json")
    if data is None:
        return jsonify({"error": "No description analysis data available. This report requires ADD JSON input."}), 404
    return jsonify(data)


# Endpoint for Group Membership Report (ADD JSON)
@app.route("/group_membership_report.json")
@login_required
def group_membership_report() -> Response:
    """Return group membership analysis report for the current session."""
    data = _load_session_json("group_membership_report.json")
    if data is None:
        return jsonify({"error": "No group membership data available. This report requires ADD JSON input with group memberships."}), 404
    return jsonify(data)


@app.route("/api/groups/list")
@login_required
def api_groups_list() -> Response:
    """
    Return list of all unique AD groups from the current session.

    Used for the Group Membership Analysis dropdown selector.
    """
    data = _load_session_json("group_analysis_data.json")
    if data is None:
        return jsonify({
            "error": "No group data available. This feature requires ADD JSON input with group memberships.",
            "groups": [],
            "total_groups": 0
        }), 404
    return jsonify({
        "groups": data.get("groups", []),
        "total_groups": data.get("total_groups", 0),
        "total_accounts_with_groups": data.get("total_accounts_with_groups", 0)
    })


@app.route("/api/groups/<path:group_name>/members")
@login_required
def api_group_members(group_name: str) -> Response:
    """
    Return all accounts that are members of the specified AD group.

    Args:
        group_name: The name of the AD group (URL encoded)

    Returns:
        JSON with list of member accounts including:
        - sam_account_name
        - privilege_level
        - is_enabled
        - is_cracked
        - password (if cracked)
    """
    from urllib.parse import unquote

    # URL decode the group name
    decoded_group_name = unquote(group_name)

    data = _load_session_json("group_analysis_data.json")
    if data is None:
        return jsonify({
            "error": "No group data available. This feature requires ADD JSON input with group memberships.",
            "members": [],
            "group_name": decoded_group_name
        }), 404

    accounts = data.get("accounts", [])

    # Filter accounts that are members of the specified group
    members = []
    for acc in accounts:
        if decoded_group_name in acc.get("member_of", []):
            members.append({
                "sam_account_name": acc["sam_account_name"],
                "privilege_level": acc.get("privilege_level", "standard"),
                "privilege_groups": acc.get("privilege_groups", []),
                "is_enabled": acc.get("is_enabled", True),
                "is_cracked": acc.get("is_cracked", False),
                "password": acc.get("password", ""),
                "group_count": len(acc.get("member_of", [])),
            })

    # Sort by privilege level (tier0 first), then by cracked status, then by name
    privilege_order = {"tier0": 0, "elevated": 1, "standard": 2}
    members.sort(key=lambda x: (
        privilege_order.get(x["privilege_level"], 3),
        not x["is_cracked"],  # Cracked first
        x["sam_account_name"].lower()
    ))

    # Calculate summary stats
    cracked_count = sum(1 for m in members if m["is_cracked"])
    enabled_count = sum(1 for m in members if m["is_enabled"])
    tier0_count = sum(1 for m in members if m["privilege_level"] == "tier0")
    elevated_count = sum(1 for m in members if m["privilege_level"] == "elevated")

    return jsonify({
        "group_name": decoded_group_name,
        "members": members,
        "total_members": len(members),
        "summary": {
            "cracked_count": cracked_count,
            "cracked_percentage": round(cracked_count / len(members) * 100, 1) if members else 0,
            "enabled_count": enabled_count,
            "tier0_count": tier0_count,
            "elevated_count": elevated_count,
            "standard_count": len(members) - tier0_count - elevated_count,
        }
    })


# ============================================================================
# HIBP (Have I Been Pwned) Integration Endpoints
# ============================================================================

@app.route("/api/hibp/status")
@login_required
def hibp_status() -> Response:
    """
    Get the status of HIBP integration including local database availability.

    Returns information about:
    - Whether a local database is configured and loaded
    - API availability
    - Recommended check method
    """
    from app.hibp_checker import (
        get_local_db_status,
        validate_local_db_path,
        load_local_hibp_database,
        test_hibp_connection
    )

    # Check local database configuration
    local_db_path = os.environ.get("HIBP_LOCAL_DB_PATH", "").strip()
    local_db_status = get_local_db_status()

    local_db_info = {
        "configured": bool(local_db_path),
        "path": local_db_path if local_db_path else None,
        "loaded": local_db_status["loaded"],
        "hash_count": local_db_status["hash_count"],
        "file_date": local_db_status.get("file_date"),
        "mode": local_db_status.get("mode"),  # "sqlite" or "binary_search"
        "valid": False,
        "message": ""
    }

    # If path is configured but not loaded, validate and try to load it
    if local_db_path and not local_db_status["loaded"]:
        is_valid, message, info = validate_local_db_path(local_db_path)
        local_db_info["valid"] = is_valid
        local_db_info["message"] = message
        if is_valid:
            local_db_info["estimated_entries"] = info.get("estimated_entries", 0)
            local_db_info["file_size_gb"] = info.get("file_size_gb", 0)
    elif local_db_status["loaded"]:
        local_db_info["valid"] = True
        local_db_info["message"] = f"Database loaded with {local_db_status['hash_count']:,} hashes"

    # Determine available check methods
    check_methods = []
    if local_db_status["loaded"]:
        check_methods.append({
            "id": "local",
            "name": "Local Database",
            "description": f"Fast offline check against {local_db_status['hash_count']:,} known breached hashes",
            "recommended": True,
            "requires_consent": False
        })

    check_methods.append({
        "id": "api",
        "name": "HIBP API",
        "description": "Check against latest Have I Been Pwned database (requires internet)",
        "recommended": not local_db_status["loaded"],
        "requires_consent": True
    })

    return jsonify({
        "local_database": local_db_info,
        "check_methods": check_methods,
        "default_method": "local" if local_db_status["loaded"] else "api"
    })


@app.route("/api/hibp/load-local-db", methods=["POST"])
@login_required
def hibp_load_local_db() -> Response:
    """
    Load or reload the local HIBP database.

    This can take a while for large databases (typically 20-60 seconds for the full HIBP NTLM database).
    """
    from app.hibp_checker import load_local_hibp_database

    local_db_path = os.environ.get("HIBP_LOCAL_DB_PATH", "").strip()

    if not local_db_path:
        return jsonify({
            "success": False,
            "message": "No local database path configured. Set HIBP_LOCAL_DB_PATH in your .env file."
        }), 400

    data = request.get_json() or {}
    force_reload = data.get("force_reload", False)

    success, message, hash_count = load_local_hibp_database(local_db_path, force_reload=force_reload)

    return jsonify({
        "success": success,
        "message": message,
        "hash_count": hash_count
    })


@app.route("/api/hibp/test")
@login_required
def hibp_test_connection() -> Response:
    """Test connectivity to the HIBP Pwned Passwords API."""
    from app.hibp_checker import test_hibp_connection

    success, message = test_hibp_connection()
    return jsonify({
        "success": success,
        "message": message
    })


def _generate_breach_stats(hibp_results: dict, session_dir: str):
    """
    Generate breach statistics table from HIBP results.

    Creates breach_stats.json with key/value pairs for the Breach Statistics table.
    """
    try:
        # Extract data from HIBP results
        total_checked = hibp_results.get("total_checked", 0)
        results = hibp_results.get("results", [])

        # Count different categories
        breached_hashes = set()
        cracked_hashes = set()
        cracked_and_breached_hashes = set()
        all_hashes = set()
        breached_accounts = 0
        cracked_and_breached_accounts = 0

        for result in results:
            ntlm_hash = result.get("ntlm_hash")
            if ntlm_hash:
                all_hashes.add(ntlm_hash.upper())

            is_breached = result.get("found_in_breach", False)
            has_cracked_pw = result.get("cracked_pw") is not None

            if is_breached:
                breached_accounts += 1
                if ntlm_hash:
                    breached_hashes.add(ntlm_hash.upper())

            if has_cracked_pw and ntlm_hash:
                cracked_hashes.add(ntlm_hash.upper())

            if is_breached and has_cracked_pw:
                cracked_and_breached_accounts += 1
                if ntlm_hash:
                    cracked_and_breached_hashes.add(ntlm_hash.upper())

        unique_breached_hashes = len(breached_hashes)
        unique_all_hashes = len(all_hashes)
        cracked_pwds_in_breach = cracked_and_breached_accounts

        # Calculate percentages
        hash_breach_rate = f"{(unique_breached_hashes / unique_all_hashes * 100):.1f}%" if unique_all_hashes > 0 else "0.0%"
        account_breach_rate = f"{(breached_accounts / len(results) * 100):.1f}%" if len(results) > 0 else "0.0%"

        # Create breach stats table in same format as cracking_stats_table.json
        breach_stats = [
            {"key": "Accts. w/ Breached Pw: ", "value": cracked_pwds_in_breach},
            {"key": "Hashes in Breach: ", "value": unique_breached_hashes},
            {"key": "Hash Breach Rate: ", "value": hash_breach_rate},
            {"key": "Account Breach Rate: ", "value": account_breach_rate}
        ]

        # Save to session directory
        breach_stats_path = os.path.join(session_dir, "breach_stats.json")
        with open(breach_stats_path, "w") as f:
            json.dump(breach_stats, f, indent=2)

        logging.info(f"Generated breach statistics: {cracked_pwds_in_breach} cracked passwords in breach, {unique_breached_hashes} unique hashes in breach")

    except Exception as e:
        logging.error(f"Failed to generate breach statistics: {e}")


def _run_hibp_check_background(session_dir: str, method: str, account_list: list,
                                username_to_password: dict, username_to_status: dict,
                                local_db_hash_count: int = 0):
    """
    Run HIBP check in background thread.

    This function runs the actual HIBP check and saves results to files.
    It's designed to be called from a background thread.
    """
    from app.hibp_checker import check_hashes_hibp, check_hashes_local

    progress_path = os.path.join(session_dir, "hibp_progress.json")
    hibp_results_path = os.path.join(session_dir, "hibp_results.json")

    # Calculate unique prefixes for progress estimation (API mode)
    unique_prefixes = len(set(acct["ntlm_hash"][:5].upper() for acct in account_list
                              if acct.get("ntlm_hash") and len(acct["ntlm_hash"]) >= 5))

    # Track start time for duration estimates
    import time as _time
    check_start_time = _time.time()

    def save_progress(checked: int, total: int, found: int = 0, status: str = "running"):
        """Save progress to file for frontend polling."""
        try:
            progress_data = {
                "checked": checked,
                "total": total,
                "found": found,
                "percentage": round((checked / total) * 100, 1) if total > 0 else 0,
                "status": status,
                "start_time": check_start_time,
                "mode": method,
            }
            with open(progress_path, "w") as f:
                json.dump(progress_data, f)
        except Exception as e:
            logging.error(f"Failed to save HIBP progress: {e}")

    # Initialize progress with estimate (will be updated by callback with actual total)
    estimated_prefixes = unique_prefixes if method == "api" else len(account_list)
    save_progress(0, estimated_prefixes, 0, "running")
    logging.info(f"HIBP check starting: estimated {estimated_prefixes} prefixes for {len(account_list)} accounts")

    try:
        if method == "local":
            results = check_hashes_local(account_list, progress_callback=lambda c, t: save_progress(c, t))
            data_source = "local"
            data_source_info = f"Local database ({local_db_hash_count:,} hashes)"
        else:
            results = check_hashes_hibp(account_list, progress_callback=lambda c, t: save_progress(c, t))
            data_source = "api"
            data_source_info = "Have I Been Pwned API"

        results_dict = results.to_dict()

        # Add data source information
        results_dict["data_source"] = data_source
        results_dict["data_source_info"] = data_source_info

        # Add cracked passwords and account status to results
        for result in results_dict.get("results", []):
            result["cracked_pw"] = username_to_password.get(result["username"])
            result["account_status"] = username_to_status.get(result["username"], "unknown")
        for result in results_dict.get("top_breached", []):
            result["cracked_pw"] = username_to_password.get(result["username"])
            result["account_status"] = username_to_status.get(result["username"], "unknown")

        # Add hash-level statistics
        all_results = results_dict.get("results", [])
        unique_hashes = set(r["ntlm_hash"].upper() for r in all_results if r.get("ntlm_hash"))
        breached_hashes = set(r["ntlm_hash"].upper() for r in all_results if r.get("found_in_breach", False) and r.get("ntlm_hash"))

        results_dict["total_unique_hashes"] = len(unique_hashes)
        results_dict["unique_hashes_in_breach"] = len(breached_hashes)
        results_dict["unique_hashes_not_in_breach"] = len(unique_hashes) - len(breached_hashes)
        results_dict["total_accounts"] = len(all_results)

        # Save results to session
        with open(hibp_results_path, "w") as f:
            json.dump(results_dict, f, indent=2)

        # Generate breach statistics table
        _generate_breach_stats(results_dict, session_dir)

        # Mark progress as complete
        total_checked = results_dict.get("total_checked", estimated_prefixes)
        save_progress(total_checked, total_checked, results_dict.get("total_found", 0), "complete")

        logging.info(f"HIBP background check complete: {results_dict.get('total_found', 0)}/{results_dict.get('total_checked', 0)} found")

    except Exception as e:
        logging.error(f"HIBP background check failed: {e}")
        # Mark progress as error
        try:
            with open(progress_path, "w") as f:
                json.dump({"status": "error", "error": str(e)}, f)
        except Exception:
            pass


@app.route("/api/hibp/check", methods=["POST"])
@login_required
def hibp_check_hashes() -> Response:
    """
    Check account hashes against the HIBP Pwned Passwords database.

    This endpoint starts the check in a background thread and returns immediately.
    The frontend should poll /api/hibp/progress to monitor status.

    Supports two modes:
    1. Local mode (method="local"): Uses local HIBP database - fast, no internet required
    2. API mode (method="api"): Uses HIBP API with k-Anonymity - requires consent

    Request JSON:
        - method: str (optional) - "local" or "api" (defaults to "local" if available)
        - consent: bool (required for API mode) - User must explicitly consent

    Returns:
        JSON with status "started" immediately, or error if validation fails
    """
    import threading
    from app.hibp_checker import get_local_db_status

    data = request.get_json() or {}

    # Determine which method to use
    local_db_status = get_local_db_status()
    method = data.get("method", "local" if local_db_status["loaded"] else "api")

    # Validate method selection
    if method == "local" and not local_db_status["loaded"]:
        return jsonify({
            "error": "Local database not available",
            "message": "The local HIBP database is not loaded. Use method='api' or load the database first."
        }), 400

    if method == "api" and not data.get("consent"):
        return jsonify({
            "error": "User consent required",
            "message": "You must explicitly consent to send partial hash data to the Have I Been Pwned API. Only the first 5 characters of each hash are sent (k-Anonymity model)."
        }), 400

    # Load account data from session
    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    account_data_path = os.path.join(session_dir, "account_data.json")

    if not os.path.exists(account_data_path):
        return jsonify({"error": "No account data available. Please process a pwdump file first."}), 404

    try:
        with open(account_data_path, "r") as f:
            account_data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed to load account data: {str(e)}"}), 500

    if not account_data:
        return jsonify({"error": "Account data is empty"}), 400

    # Convert account_data dict to list format expected by HIBP checker
    BLANK_PASSWORD_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
    account_list = []
    username_to_password = {}
    username_to_status = {}

    for username, acct_data in account_data.items():
        if isinstance(acct_data, dict) and acct_data.get("ntlm_hash"):
            if acct_data["ntlm_hash"].lower() == BLANK_PASSWORD_HASH:
                continue
            account_list.append({
                "username": username,
                "ntlm_hash": acct_data["ntlm_hash"]
            })
            username_to_password[username] = acct_data.get("cracked_pw")
            disabled = acct_data.get("disabled")
            if disabled is True:
                username_to_status[username] = "disabled"
            elif disabled is False:
                username_to_status[username] = "enabled"
            else:
                username_to_status[username] = "unknown"

    if not account_list:
        return jsonify({"error": "No valid NTLM hashes found in account data"}), 400

    # Initialize progress file
    progress_path = os.path.join(session_dir, "hibp_progress.json")
    unique_prefixes = len(set(acct["ntlm_hash"][:5].upper() for acct in account_list
                              if acct.get("ntlm_hash") and len(acct["ntlm_hash"]) >= 5))
    total_items = unique_prefixes if method == "api" else len(account_list)

    with open(progress_path, "w") as f:
        json.dump({
            "checked": 0,
            "total": total_items,
            "found": 0,
            "percentage": 0,
            "status": "starting"
        }, f)

    # Start background thread
    thread = threading.Thread(
        target=_run_hibp_check_background,
        args=(session_dir, method, account_list, username_to_password, username_to_status,
              local_db_status.get("hash_count", 0)),
        daemon=True
    )
    thread.start()

    return jsonify({
        "status": "started",
        "method": method,
        "total_accounts": len(account_list),
        "total_api_calls": total_items,
        "message": f"HIBP check started in background. Poll /api/hibp/progress for status."
    })


@app.route("/api/hibp/progress")
@login_required
def hibp_progress() -> Response:
    """Get current HIBP check progress for polling."""
    from app.timing_stats import get_timing_stats, get_processing_message, format_duration

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    progress_path = os.path.join(session_dir, "hibp_progress.json")

    if not os.path.exists(progress_path):
        return jsonify({"status": "idle"})

    try:
        with open(progress_path, "r") as f:
            progress = json.load(f)

        # Add time estimate and fun message for running status
        if progress.get("status") == "running":
            timing = get_timing_stats()
            checked = progress.get("checked", 0)
            total = progress.get("total", 0)
            mode = progress.get("mode", "sqlite")

            # Calculate elapsed and estimate remaining
            start_time = progress.get("start_time")
            if start_time and checked > 0:
                import time
                elapsed = time.time() - start_time
                rate = checked / elapsed if elapsed > 0 else 0
                remaining = (total - checked) / rate if rate > 0 else 0

                progress["elapsed_seconds"] = round(elapsed, 1)
                progress["elapsed_formatted"] = format_duration(elapsed)
                progress["remaining_seconds"] = round(remaining, 1)
                progress["remaining_formatted"] = format_duration(remaining)
                progress["rate"] = round(rate, 1)

            # Add a fun processing message
            message_index = (checked // 10000) % 18 if checked else 0
            progress["message"] = get_processing_message(message_index)

        return jsonify(progress)
    except Exception:
        return jsonify({"status": "idle"})


@app.route("/hibp_results.json")
@login_required
def hibp_results() -> Response:
    """Get cached HIBP check results."""
    data = _load_session_json("hibp_results.json")
    if data is None:
        return jsonify({"error": "No HIBP results available. Run a check first."}), 404
    return jsonify(data)


@app.route("/api/hibp/results/paginated")
@login_required
def hibp_results_paginated() -> Response:
    """
    Get paginated HIBP results for DataTables server-side processing.

    Query parameters (DataTables server-side):
    - draw: DataTables draw counter
    - start: Starting record index
    - length: Number of records to return
    - search[value]: Global search term
    - order[0][column]: Column index to sort by
    - order[0][dir]: Sort direction (asc/desc)
    - filter: Optional filter ('breached' or 'all')
    """
    data = _load_session_json("hibp_results.json")
    if data is None:
        return jsonify({
            "draw": int(request.args.get("draw", 1)),
            "recordsTotal": 0,
            "recordsFiltered": 0,
            "data": []
        })

    results = data.get("results", [])

    # Get DataTables parameters
    draw = int(request.args.get("draw", 1))
    start = int(request.args.get("start", 0))
    length = int(request.args.get("length", 10))
    search_value = request.args.get("search[value]", "").lower()
    order_column = int(request.args.get("order[0][column]", 3))  # Default: breach_count
    order_dir = request.args.get("order[0][dir]", "desc")
    filter_type = request.args.get("filter", "breached")  # Default to breached only

    # Column mapping for sorting
    column_map = {
        0: "username",
        1: "account_status",
        2: "cracked_pw",
        3: "breach_count"
    }
    sort_key = column_map.get(order_column, "breach_count")

    # Filter results
    if filter_type == "breached":
        filtered_results = [r for r in results if r.get("found_in_breach")]
    else:
        filtered_results = results

    records_total = len(filtered_results)

    # Apply search filter
    if search_value:
        filtered_results = [
            r for r in filtered_results
            if search_value in r.get("username", "").lower()
            or search_value in str(r.get("cracked_pw", "")).lower()
            or search_value in r.get("account_status", "").lower()
        ]

    records_filtered = len(filtered_results)

    # Sort results
    reverse = order_dir == "desc"
    try:
        filtered_results.sort(
            key=lambda x: (x.get(sort_key) or 0) if sort_key == "breach_count" else (x.get(sort_key) or "").lower(),
            reverse=reverse
        )
    except (TypeError, AttributeError):
        pass  # Skip sorting if data types are inconsistent

    # Paginate
    paginated = filtered_results[start:start + length]

    # Format response for DataTables
    response_data = []
    for item in paginated:
        response_data.append({
            "username": item.get("username", ""),
            "account_status": item.get("account_status", "unknown"),
            "cracked_pw": item.get("cracked_pw", ""),
            "breach_count": item.get("breach_count", 0)
        })

    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": response_data
    })


@app.route("/api/hibp/summary")
@login_required
def hibp_summary() -> Response:
    """Get HIBP summary data only (without full results array) for fast initial page load."""
    data = _load_session_json("hibp_results.json")
    if data is None:
        return jsonify({"error": "No HIBP results available."}), 404

    # Return only summary fields, not the large results array
    summary = {
        "total_checked": data.get("total_checked", 0),
        "total_found": data.get("total_found", 0),
        "found_percentage": data.get("found_percentage", 0),
        "check_duration_seconds": data.get("check_duration_seconds", 0),
        "data_source": data.get("data_source", "unknown"),
        "data_source_info": data.get("data_source_info", ""),
        "has_results": bool(data.get("results")),
        "result_count": len(data.get("results", [])),
        "total_unique_hashes": data.get("total_unique_hashes", 0),
        "unique_hashes_in_breach": data.get("unique_hashes_in_breach", 0),
        "unique_hashes_not_in_breach": data.get("unique_hashes_not_in_breach", 0),
        "total_accounts": data.get("total_accounts", 0)
    }
    return jsonify(summary)


# ============================================================================
# HIBP Database Download Endpoints
# ============================================================================

@app.route("/api/hibp/download/info")
@login_required
def hibp_download_info() -> Response:
    """Get information about HIBP database download, including estimates and attribution."""
    from app.hibp_downloader import estimate_download, get_download_status, get_conversion_status, get_sqlite_db_info
    from app.hibp_checker import get_local_db_status

    # Get current local database status
    local_db_status = get_local_db_status()

    # Get download estimates
    estimates = estimate_download()

    # Get any active download status
    download_status = get_download_status()

    # Get conversion status
    conversion_status = get_conversion_status()

    # Default output path
    default_output = os.path.join("data", "pwnedpasswords-ntlm.txt")
    configured_path = os.environ.get("HIBP_LOCAL_DB_PATH", "")

    # Check for SQLite version of configured path
    sqlite_info = None
    text_file_exists = False
    text_file_size_gb = None
    text_file_path = None
    text_file_date = None
    if configured_path:
        # Check if text file exists (either directly configured or alongside SQLite)
        if configured_path.endswith('.txt') and os.path.exists(configured_path):
            text_file_exists = True
            text_file_path = configured_path
            text_file_size_gb = round(os.path.getsize(configured_path) / (1024**3), 1)
            text_file_date = datetime.fromtimestamp(os.path.getmtime(configured_path)).isoformat()
        elif configured_path.endswith('.db'):
            # Check if text file exists alongside SQLite db
            txt_path = os.path.splitext(configured_path)[0] + ".txt"
            if os.path.exists(txt_path):
                text_file_exists = True
                text_file_path = txt_path
                text_file_size_gb = round(os.path.getsize(txt_path) / (1024**3), 1)
                text_file_date = datetime.fromtimestamp(os.path.getmtime(txt_path)).isoformat()

        sqlite_path = os.path.splitext(configured_path)[0] + ".db"
        if os.path.exists(sqlite_path):
            sqlite_info = get_sqlite_db_info(sqlite_path)

    return jsonify({
        "local_database": local_db_status,
        "estimates": estimates,
        "download_status": download_status,
        "conversion_status": conversion_status,
        "sqlite_info": sqlite_info,
        "text_file_exists": text_file_exists,
        "text_file_size_gb": text_file_size_gb,
        "text_file_path": text_file_path,
        "text_file_date": text_file_date,
        "default_output_path": default_output,
        "configured_path": configured_path
    })


@app.route("/api/hibp/download/start", methods=["POST"])
@login_required
def hibp_download_start() -> Response:
    """
    Start downloading the HIBP NTLM database.

    This downloads all 1,048,576 hash prefixes from the HIBP API and
    combines them into a single sorted file for local lookups.

    Request JSON (optional):
        - output_dir: Directory to save file (default: "data")
        - output_filename: Filename (default: "pwnedpasswords-ntlm.txt")
        - parallelism: Number of concurrent downloads (default: 20)

    Returns immediately with status. Poll /api/hibp/download/status for progress.
    """
    from app.hibp_downloader import start_download

    data = request.get_json() or {}

    output_dir = data.get("output_dir", "data")
    output_filename = data.get("output_filename", "pwnedpasswords-ntlm.txt")
    parallelism = min(max(int(data.get("parallelism", 20)), 1), 100)  # Clamp 1-100

    started = start_download(
        output_dir=output_dir,
        output_filename=output_filename,
        parallelism=parallelism
    )

    if started:
        return jsonify({
            "success": True,
            "message": "HIBP database download started",
            "output_path": os.path.join(output_dir, output_filename),
            "parallelism": parallelism
        })
    else:
        return jsonify({
            "success": False,
            "message": "A download is already in progress"
        }), 409


@app.route("/api/hibp/download/status")
@login_required
def hibp_download_status() -> Response:
    """Get the current status of an active or completed HIBP download."""
    from app.hibp_downloader import get_download_status

    return jsonify(get_download_status())


@app.route("/api/hibp/download/cancel", methods=["POST"])
@login_required
def hibp_download_cancel() -> Response:
    """Cancel an active HIBP database download."""
    from app.hibp_downloader import cancel_download

    cancelled = cancel_download()

    if cancelled:
        return jsonify({
            "success": True,
            "message": "Download cancellation requested"
        })
    else:
        return jsonify({
            "success": False,
            "message": "No active download to cancel"
        }), 400


@app.route("/api/hibp/convert/start", methods=["POST"])
@login_required
def hibp_convert_start() -> Response:
    """
    Start converting a HIBP text file to SQLite database.

    This converts the text file to SQLite for faster indexed lookups.
    The conversion runs in a background thread.

    Request JSON:
        - text_file_path: Path to the HIBP text file (required)
        - db_output_path: Output path for SQLite database (optional, defaults to .db extension)

    Returns immediately with status. Poll /api/hibp/convert/status for progress.
    """
    from app.hibp_downloader import start_conversion_background, get_conversion_status

    data = request.get_json() or {}

    text_file_path = data.get("text_file_path", "").strip()

    if not text_file_path:
        # Try to use configured HIBP path
        text_file_path = os.environ.get("HIBP_LOCAL_DB_PATH", "").strip()

    if not text_file_path:
        return jsonify({
            "success": False,
            "message": "No text file path provided. Set text_file_path in request or HIBP_LOCAL_DB_PATH in .env"
        }), 400

    if not os.path.exists(text_file_path):
        return jsonify({
            "success": False,
            "message": f"Text file not found: {text_file_path}"
        }), 404

    # Check if already a SQLite database
    if text_file_path.endswith('.db'):
        return jsonify({
            "success": False,
            "message": "Path is already a SQLite database"
        }), 400

    db_output_path = data.get("db_output_path")
    if not db_output_path:
        # Default: same location with .db extension
        db_output_path = os.path.splitext(text_file_path)[0] + ".db"

    # Check if output already exists
    if os.path.exists(db_output_path):
        return jsonify({
            "success": False,
            "message": f"SQLite database already exists: {db_output_path}. Delete it first to reconvert."
        }), 409

    started = start_conversion_background(text_file_path, db_output_path)

    if started:
        return jsonify({
            "success": True,
            "message": "SQLite conversion started",
            "input_path": text_file_path,
            "output_path": db_output_path
        })
    else:
        return jsonify({
            "success": False,
            "message": "A conversion is already in progress"
        }), 409


@app.route("/api/hibp/convert/status")
@login_required
def hibp_convert_status() -> Response:
    """Get the current status of an active or completed SQLite conversion."""
    from app.hibp_downloader import get_conversion_status

    return jsonify(get_conversion_status())


@app.route("/api/hibp/convert/cancel", methods=["POST"])
@login_required
def hibp_convert_cancel() -> Response:
    """Cancel an active SQLite conversion."""
    from app.hibp_downloader import cancel_conversion

    cancelled = cancel_conversion()

    if cancelled:
        return jsonify({
            "success": True,
            "message": "Conversion cancellation requested"
        })
    else:
        return jsonify({
            "success": False,
            "message": "No active conversion to cancel"
        }), 400


@app.route("/api/hibp/text-file/delete", methods=["POST"])
@login_required
def hibp_delete_text_file() -> Response:
    """
    Delete the HIBP text file to save disk space after SQLite conversion.

    Only allows deletion when:
    - A SQLite database is actively loaded
    - The text file exists
    """
    from app.hibp_checker import get_local_db_status

    # Get current local database status
    local_db_status = get_local_db_status()

    # Only allow deletion if SQLite is active
    if local_db_status.get("mode") != "sqlite":
        return jsonify({
            "success": False,
            "message": "Cannot delete text file: SQLite database is not active. Ensure SQLite conversion is complete and the app has been restarted."
        }), 400

    # Find the text file path
    configured_path = os.environ.get("HIBP_LOCAL_DB_PATH", "")
    text_file_path = None

    if configured_path:
        if configured_path.endswith('.txt') and os.path.exists(configured_path):
            text_file_path = configured_path
        elif configured_path.endswith('.db'):
            txt_path = os.path.splitext(configured_path)[0] + ".txt"
            if os.path.exists(txt_path):
                text_file_path = txt_path

    if not text_file_path or not os.path.exists(text_file_path):
        return jsonify({
            "success": False,
            "message": "Text file not found"
        }), 404

    # Get file size before deletion
    file_size_bytes = os.path.getsize(text_file_path)
    file_size_gb = round(file_size_bytes / (1024**3), 1)

    try:
        os.remove(text_file_path)
        return jsonify({
            "success": True,
            "message": f"Text file deleted successfully",
            "freed_bytes": file_size_bytes,
            "freed_gb": file_size_gb,
            "deleted_path": text_file_path
        })
    except OSError as e:
        return jsonify({
            "success": False,
            "message": f"Failed to delete file: {str(e)}"
        }), 500


def run_automatic_hibp_check(account_data: dict, session_dir: str) -> dict | None:
    """
    Run HIBP check automatically during analysis pipeline if local database is available.

    This function checks passwords against the local HIBP database without requiring
    user consent (since no data leaves the system). Returns the results dict or None
    if no local database is available.
    """
    from app.hibp_checker import check_hashes_local, get_local_db_status

    local_db_status = get_local_db_status()
    if not local_db_status["loaded"]:
        # No local database available - skip automatic check
        return None

    # Build account list for HIBP check
    BLANK_PASSWORD_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
    account_list = []
    username_to_password = {}
    username_to_status = {}

    for username, acct_data in account_data.items():
        if isinstance(acct_data, dict) and acct_data.get("ntlm_hash"):
            # Skip blank password hashes
            if acct_data["ntlm_hash"].lower() == BLANK_PASSWORD_HASH:
                continue
            account_list.append({
                "username": username,
                "ntlm_hash": acct_data["ntlm_hash"]
            })
            username_to_password[username] = acct_data.get("cracked_pw")
            # Store account status if available (disabled is a boolean)
            disabled = acct_data.get("disabled")
            if disabled is True:
                username_to_status[username] = "disabled"
            elif disabled is False:
                username_to_status[username] = "enabled"
            else:
                username_to_status[username] = "unknown"

    if not account_list:
        return None

    try:
        # Run local HIBP check
        results = check_hashes_local(account_list)
        results_dict = results.to_dict()

        # Add data source information
        results_dict["data_source"] = "local"
        results_dict["data_source_info"] = f"Local database ({local_db_status['hash_count']:,} hashes)"
        results_dict["automatic"] = True  # Mark as automatic check

        # Add cracked passwords and account status to results
        for result in results_dict.get("results", []):
            result["cracked_pw"] = username_to_password.get(result["username"])
            result["account_status"] = username_to_status.get(result["username"], "unknown")
        for result in results_dict.get("top_breached", []):
            result["cracked_pw"] = username_to_password.get(result["username"])
            result["account_status"] = username_to_status.get(result["username"], "unknown")

        # Add hash-level statistics
        all_results = results_dict.get("results", [])
        unique_hashes = set(r["ntlm_hash"].upper() for r in all_results if r.get("ntlm_hash"))
        breached_hashes = set(r["ntlm_hash"].upper() for r in all_results if r.get("found_in_breach", False) and r.get("ntlm_hash"))

        results_dict["total_unique_hashes"] = len(unique_hashes)
        results_dict["unique_hashes_in_breach"] = len(breached_hashes)
        results_dict["unique_hashes_not_in_breach"] = len(unique_hashes) - len(breached_hashes)
        results_dict["total_accounts"] = len(all_results)

        # Save results to session
        hibp_results_path = os.path.join(session_dir, "hibp_results.json")
        with open(hibp_results_path, "w") as f:
            json.dump(results_dict, f, indent=2)

        # Generate breach statistics table
        _generate_breach_stats(results_dict, session_dir)

        logging.info(f"Automatic HIBP check complete: {results_dict['total_found']}/{results_dict['total_checked']} found in breaches")
        return results_dict

    except Exception as e:
        logging.error(f"Automatic HIBP check failed: {e}")
        return None


# Endpoint for Downloading JSON Files
@app.route("/download/<filename>")
@login_required
def download_file(filename: str) -> Response:
    try:
        if not filename.endswith(".json"):
            abort(403)  # Forbidden
        # Get path from current session
        session_mgr = get_session_manager()
        session_dir = session_mgr.get_session_dir()
        return send_from_directory(session_dir, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)  # File not found


@app.route("/list_json_files", methods=["GET"])
@login_required
def list_json_files() -> Response:
    try:
        session_mgr = get_session_manager()
        session_dir = session_mgr.get_session_dir()
        files = [f for f in os.listdir(session_dir) if f.endswith(".json")]
        return jsonify(files)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/download-all-images", methods=["POST"])
@login_required
def download_all_images() -> Response:
    """
    Endpoint to create a zip file containing all chart/table SVG images.
    Receives SVG data from the frontend and packages them into a downloadable zip.
    """
    try:
        data = request.get_json()
        if not data or "images" not in data:
            return jsonify({"error": "No image data provided"}), 400

        images = data["images"]
        if not images:
            return jsonify({"error": "No images to download"}), 400

        # Create zip file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for image in images:
                filename = image.get("filename", "image.svg")
                content = image.get("content", "")
                if filename and content:
                    # Ensure filename is safe
                    safe_filename = secure_filename(filename)
                    if not safe_filename.endswith(".svg"):
                        safe_filename += ".svg"
                    zip_file.writestr(safe_filename, content)

        zip_buffer.seek(0)

        # Get session name for zip filename
        session_mgr = get_session_manager()
        current_session = session_mgr.get_current_session()
        session_name = current_session.get("name", "report") if current_session else "report"
        # Sanitize session name for filename
        safe_session_name = re.sub(r"[^\w\-]", "_", session_name)
        zip_filename = f"{safe_session_name}_images.zip"

        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name=zip_filename,
        )

    except Exception as e:
        logging.error(f"Error creating images zip: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/validate_single_local", methods=["POST"])
@login_required
def validate_single_local_file() -> Response:
    """
    AJAX endpoint to validate a single local file (pwdump or potfile) by path.
    Returns validation results as JSON for display in the UI.

    Security: Access is restricted to paths under /home/ only.
    """
    try:
        data = request.get_json()
        file_type = data.get("file_type")  # "pwdump" or "potfile"
        file_path = data.get("file_path", "").strip()

        if not file_type or not file_path:
            return jsonify({"error": "Missing file_type or file_path"}), 400

        # Security: Validate that path is within allowed directories
        if not is_allowed_path(file_path):
            return jsonify({"error": "Access denied. File access is restricted to /home/ directories only."}), 403

        # Check if file exists
        if not os.path.isfile(file_path):
            return jsonify({"error": f"File not found: {file_path}"}), 404

        filename = os.path.basename(file_path)

        if file_type == "pwdump":
            # Check if the file is ADD JSON format
            if file_parser.is_add_json_file(file_path):
                # Parse as ADD JSON
                add_result = file_parser.parse_add_json(file_path)
                result_dict = file_parser.add_result_to_dict(add_result)

                # Store in session for validation review access
                session["add_validation"] = result_dict
                session["pwdump_path"] = file_path
                session["input_format"] = "add_json"
                session.modified = True

                return jsonify({
                    "success": True,
                    "file_type": "add_json",
                    "filename": filename,
                    "total_lines": add_result.total_users,
                    "valid_lines": add_result.valid_users,
                    "warning_lines": 0,
                    "error_lines": add_result.error_users,
                    "formats_detected": {"add_json": add_result.total_users},
                    "status_coverage": 0,
                    "lines_with_status": 0,
                    "domain_name": add_result.domain_policy.domain_name if add_result.domain_policy else "Unknown",
                    "unique_domains": add_result.unique_domains,
                    "tier0_count": add_result.tier0_count,
                    "elevated_count": add_result.elevated_count,
                    "privileged_count": add_result.privileged_count,
                    "users_with_history": add_result.users_with_history,
                    "total_historical_hashes": add_result.total_historical_hashes,
                    "problem_lines": [
                        {
                            "line_number": i + 1,
                            "username": entry.sam_account_name,
                            "status": "disabled" if entry.is_disabled else "enabled",
                            "is_valid": entry.is_valid,
                            "errors": [{"severity": e.severity.value, "message": e.message} for e in entry.errors],
                            "raw_line": f"{entry.sam_account_name} ({entry.logon_name})"
                        }
                        for i, entry in enumerate(add_result.entries) if entry.errors
                    ]
                })
            else:
                # Standard pwdump format
                result = file_parser.validate_pwdump_file(file_path)
                result_dict = file_parser.validation_result_to_dict(result)

                # Store in session for validation review access
                session["pwdump_validation"] = result_dict
                session["pwdump_path"] = file_path
                session["input_format"] = "pwdump"
                session.modified = True

                # Calculate status coverage
                lines_with_status = sum(1 for line in result.lines if line.status is not None and line.is_valid)
                valid_lines = result.valid_lines
                status_coverage = (lines_with_status / valid_lines * 100) if valid_lines > 0 else 0

                return jsonify({
                    "success": True,
                    "file_type": "pwdump",
                    "filename": filename,
                    "total_lines": result.total_lines,
                    "valid_lines": result.valid_lines,
                    "warning_lines": result.warning_lines,
                    "error_lines": result.error_lines,
                    "formats_detected": result.formats_detected,
                    "status_coverage": round(status_coverage, 1),
                    "lines_with_status": lines_with_status,
                    "problem_lines": [
                        {
                            "line_number": line.line_number,
                            "username": line.username,
                            "status": line.status,
                            "is_valid": line.is_valid,
                            "errors": [{"severity": e.severity.value, "message": e.message} for e in line.errors],
                            "raw_line": line.raw_line[:80] + ("..." if len(line.raw_line) > 80 else "")
                        }
                        for line in result.lines if line.errors
                    ]
                })
        else:  # potfile
            result = file_parser.validate_potfile(file_path)
            result_dict = file_parser.potfile_result_to_dict(result)

            # Store in session for validation review access
            session["potfile_validation"] = result_dict
            session["potfile_path"] = file_path
            session.modified = True

            return jsonify({
                "success": True,
                "file_type": "potfile",
                "filename": filename,
                "total_lines": result.total_lines,
                "valid_lines": result.valid_lines,
                "error_lines": result.error_lines,
                "ntlm_count": result.ntlm_count,
                "non_ntlm_count": result.non_ntlm_count,
                "hash_type_summary": {
                    mode: {"name": info["name"], "count": info["count"], "is_ntlm": info["is_ntlm"]}
                    for mode, info in result.hash_type_summary.items()
                } if result.hash_type_summary else {},
                "problem_entries": [
                    {
                        "line_number": entry.line_number,
                        "is_valid": entry.is_valid,
                        "errors": [{"severity": e.severity.value, "message": e.message} for e in entry.errors],
                        "raw_line": entry.raw_line[:80] + ("..." if len(entry.raw_line) > 80 else "")
                    }
                    for entry in result.entries if entry.errors
                ]
            })

    except Exception as e:
        logging.error(f"Single local file validation error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# ADD (Active Directory Dumper) JSON Format Routes
# =============================================================================
# Note: ADD JSON files are now auto-detected in /validate and /validate_local
# endpoints. The validation_review_add and process_add_validated routes remain
# for displaying and processing validated ADD JSON data.
# =============================================================================

@app.route("/validation_review_add")
@login_required
def validation_review_add() -> Response:
    """
    Display ADD JSON validation results and allow user review.
    Shows domain policy, user breakdown, and privilege analysis.
    """
    add_data = session.get("add_validation")
    potfile_data = session.get("potfile_validation")
    master_merge_stats = session.get("master_potfile_merge")

    if not add_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    # Extract domain count from unique_domains list
    domain_count = len(add_data.get("unique_domains", [])) or 1

    return make_response(render_template(
        "validate_add.html",
        add_data=add_data,
        potfile=potfile_data,
        domain_count=domain_count,
        master_potfile_enabled=MASTER_POTFILE_ENABLED,
        master_potfile_merge=master_merge_stats
    ))


@app.route("/process_add_validated", methods=["GET", "POST"])
@login_required
def process_add_validated() -> Response:
    """
    Process validated ADD JSON with user's configuration.
    Generates standard reports plus privileged account reports.
    """
    import time as time_module
    from app.timing_stats import get_timing_stats
    report_start_time = time_module.time()

    add_data = session.get("add_validation")
    potfile_data = session.get("potfile_validation")
    add_json_path = session.get("add_json_path")

    if not add_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    # Get options from form data if POST, otherwise from session
    # Preserve company_name and project_description from session (set in Step 1) if not in form
    existing_options = session.get("analysis_options", {})
    if request.method == "POST" and request.form:
        options = {
            "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
            "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
            "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
            "substring_min_len": request.form.get("substring_min_len", "4"),
            "substring_max_len": request.form.get("substring_max_len", "20"),
            "substring_freq_threshold": request.form.get("substring_freq_threshold", "5"),
            "substring_disp_nest": str(parse_boolean_field("substring_disp_nest")).lower(),
            "substring_normalize": str(parse_boolean_field("substring_normalize")).lower(),
            "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
            "dictionary_disp_nest": str(parse_boolean_field("dictionary_disp_nest")).lower(),
            "ignore_disabled_accounts": str(parse_boolean_field("ignore_disabled_accounts")).lower(),
            "ignore_computer_accounts": str(parse_boolean_field("ignore_computer_accounts")).lower(),
            "ignore_blank_passwords": str(parse_boolean_field("ignore_blank_passwords")).lower(),
            "include_history_in_reports": str(parse_boolean_field("include_history_in_reports")).lower(),
            "custom_keywords": request.form.get("custom_keywords", ""),
            # Preserve company_name/project_description from session if not in form (validate.html doesn't have these)
            "company_name": request.form.get("company_name", "").strip() or existing_options.get("company_name", ""),
            "project_description": request.form.get("project_description", "").strip() or existing_options.get("project_description", ""),
            # Mark as ADD JSON session for filter editing support
            "input_format": "add_json",
        }
        session["analysis_options"] = options
    else:
        options = existing_options
        # Ensure input_format is set for ADD JSON sessions
        if "input_format" not in options:
            options["input_format"] = "add_json"

    try:
        # Reconstruct validation results from session
        add_result = file_parser.dict_to_add_result(add_data)
        potfile_result = None
        if potfile_data:
            potfile_result = file_parser.dict_to_potfile_result(potfile_data)

        # Determine if historical password entries should be included in main analysis
        # Default is to exclude them (only analyze in Password History Pattern Analysis)
        include_history = options.get("include_history_in_reports", "false") == "true"

        # Convert ADD data to account_data format
        account_data, privileged_findings = file_parser.add_to_account_data(
            add_result,
            potfile_result,
            ignore_disabled=options.get("ignore_disabled_accounts", "false") == "true",
            ignore_computer_accounts=options.get("ignore_computer_accounts", "false") == "true",
            include_historical=include_history,
        )

        if not account_data:
            return Response(
                render_template(
                    "message.html",
                    message="No valid accounts to process after filtering.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Build cracked hashes lookup for additional analysis (uses cache for master potfile)
        if potfile_result:
            cracked_hashes = build_cracked_hashes_fast(potfile_result)
        else:
            cracked_hashes = {file_parser.BLANK_NTLM_HASH: ""}

        # Run historical hash analysis (basic reuse checking)
        historical_analysis = file_parser.analyze_historical_hashes(add_result, cracked_hashes)

        # Run password history pattern analysis (advanced pattern detection)
        add_entries_data = [entry.to_dict() for entry in add_result.entries if entry.included and entry.is_valid]
        history_pattern_analysis = password_history.analyze_password_history(
            add_data=add_entries_data,
            cracked_hashes=cracked_hashes
        )
        history_pattern_results = password_history.history_analysis_to_dict(history_pattern_analysis)

        # Run password sharing detection
        password_sharing = file_parser.detect_privilege_password_sharing(add_result, cracked_hashes)

        # Import analysis tools
        from app import password_analysis_tools

        # Run standard analysis
        stats_report = password_analysis_tools.crack_stats(
            account_data,
            int(options.get("policy_min_pw_len", "8")),
            int(options.get("policy_complexity_req", "3")),
            ignore_blank_passwords=options.get("ignore_blank_passwords", "false") == "true",
            max_pw_age=int(options.get("policy_max_pw_age", "90")),
        )

        # Convert stats to array format
        key_order = [
            "Cracked Accounts: ",
            "Uncracked Accounts: ",
            "Total Accounts Analyzed: ",
            "Percent of Accounts Cracked: ",
            "Cracked NTLM Hashes: ",
            "Uncracked NTLM Hashes: ",
            "Unique NTLM Hashes Analyzed: ",
            "Percent of NTLM Hashes Cracked: ",
            "Total LANMan Hashes: ",
            "Shortest Cracked Password: ",
            "Longest Cracked Password: ",
            "Average Password Length: ",
        ]
        stats_table = [{"key": key, "value": stats_report["cracking_stats"][key]} for key in key_order]

        # Create list of cracked passwords (for dictionary analysis)
        cracked_passwords = [
            account["cracked_pw"]
            for account in account_data.values()
            if account.get("cracked_pw")
        ]

        # Create list of account/password entries (for substring analysis)
        account_password_entries = [
            {"account": username, "password": account["cracked_pw"]}
            for username, account in account_data.items()
            if account.get("cracked_pw")
        ]

        # Run substring analysis
        substrings = password_analysis_tools.substring_analysis(
            account_password_entries,
            int(options.get("substring_min_len", "4")),
            int(options.get("substring_max_len", "20")),
            int(options.get("substring_freq_threshold", "5")),
            options.get("substring_normalize", "false") == "true",
            options.get("substring_disp_nest", "false") == "true",
        )

        # Run dictionary analysis
        detailed_results, english_words = password_analysis_tools.dictionary_analysis(
            cracked_passwords,
            int(options.get("dictionary_min_len", "4")),
            options.get("dictionary_disp_nest", "false") == "true",
        )

        # Parse custom keywords
        custom_keywords_raw = options.get("custom_keywords", "").strip()
        custom_keywords = []
        if custom_keywords_raw:
            for line in custom_keywords_raw.replace(",", "\n").split("\n"):
                keyword = line.strip()
                if keyword:
                    custom_keywords.append(keyword)

        # Run bad practices analysis (pass account entries for username-in-password detection)
        bad_practices = password_analysis_tools.bad_practices_analysis(
            cracked_passwords, custom_keywords, account_password_entries
        )

        # Create a new session for this analysis
        session_mgr = get_session_manager()

        # Get company/project info from options, or generate defaults
        company_name = options.get("company_name", "")
        project_description = options.get("project_description", "")
        if not company_name:
            # Try to use domain name from ADD data
            domain_name = add_result.domain_policy.domain_name if add_result.domain_policy else None
            company_name = domain_name if domain_name else "Unknown"
        if not project_description:
            project_description = "ADD Analysis"

        # Compute source hash for staleness detection
        source_hash = session_mgr.compute_source_hash(account_data=list(account_data.values()))

        # Create the session
        analysis_session = session_mgr.create_session(
            name="",  # Auto-generated from company + project
            username=current_user.id,
            source_files={
                "add_json": os.path.basename(add_json_path) if add_json_path else "",
                "potfile": os.path.basename(session.get("potfile_path", "")) if session.get("potfile_path") else ""
            },
            source_hash=source_hash,
            company_name=company_name,
            project_description=project_description
        )

        # Set as current session
        session_mgr.set_current_session(analysis_session.session_id, current_user.id)

        # Save all standard data files
        session_mgr.save_session_data("cracking_stats_table.json", stats_table, analysis_session.session_id)
        session_mgr.save_session_data("pw_account_pie.json", stats_report["pw_account_pie"], analysis_session.session_id)
        session_mgr.save_session_data("pw_ntlm_hash_pie.json", stats_report["pw_ntlm_hash_pie"], analysis_session.session_id)
        session_mgr.save_session_data("pw_length_distribution.json", stats_report["pw_length_distribution"], analysis_session.session_id)
        session_mgr.save_session_data("pw_top_passwords.json", stats_report["pw_top_passwords"], analysis_session.session_id)
        session_mgr.save_session_data("pw_substrings.json", substrings, analysis_session.session_id)
        session_mgr.save_session_data("pw_dict_words.json", english_words, analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_min_length.json", stats_report["pw_fails_min_length"], analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_complexity.json", stats_report["pw_fails_complexity"], analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_blank.json", stats_report["pw_fails_blank"], analysis_session.session_id)
        session_mgr.save_session_data("pw_fails_max_age.json", stats_report["pw_fails_max_age"], analysis_session.session_id)
        session_mgr.save_session_data("pw_lm_hashes.json", stats_report["pw_lm_hashes"], analysis_session.session_id)
        session_mgr.save_session_data("pw_bad_practices.json", bad_practices, analysis_session.session_id)
        session_mgr.save_session_data("account_data.json", account_data, analysis_session.session_id)

        # Calculate stale logins (days since last login exceeding 90 days)
        stale_logins = password_analysis_tools.stale_login_analysis(
            account_data, max_days=90
        )
        session_mgr.save_session_data("stale_logins.json", stale_logins, analysis_session.session_id)

        # Generate all cracked accounts list
        cracked_accounts_list = _generate_cracked_accounts_list(account_data)
        session_mgr.save_session_data("pw_cracked_accounts.json", cracked_accounts_list, analysis_session.session_id)

        # Save ADD-specific data files
        if add_result.domain_policy:
            session_mgr.save_session_data("domain_policy.json", add_result.domain_policy.to_dict(), analysis_session.session_id)
        session_mgr.save_session_data("privileged_accounts.json", privileged_findings, analysis_session.session_id)
        session_mgr.save_session_data("historical_hash_analysis.json", historical_analysis, analysis_session.session_id)
        session_mgr.save_session_data("password_history_patterns.json", history_pattern_results, analysis_session.session_id)
        session_mgr.save_session_data("password_sharing_findings.json", {
            "critical_findings": password_sharing,
            "summary": {
                "total_sharing_violations": len(password_sharing),
                "privileged_accounts_affected": len(set(f["privileged_account"] for f in password_sharing)),
                "standard_accounts_affected": len(set(
                    acct for f in password_sharing for acct in f["standard_accounts"]
                )),
            }
        }, analysis_session.session_id)

        # Check password reuse from account_data (works with ADD JSON format)
        pw_reuse_table = password_analysis_tools.check_pw_reuse_from_account_data(account_data)
        session_mgr.save_session_data("pw_reuse_table.json", pw_reuse_table, analysis_session.session_id)
        session_mgr.save_session_data("analysis_options.json", options, analysis_session.session_id)

        # Save ADD validation data for session reload (enables editing filters after reload)
        add_validation_path = session_mgr.get_session_data_path("add_validation.json", analysis_session.session_id)
        logging.info(f"Saving add_validation.json to: {add_validation_path}")
        session_mgr.save_session_data("add_validation.json", add_data, analysis_session.session_id)
        logging.info(f"add_validation.json saved, exists: {os.path.exists(add_validation_path)}")

        # Save potfile validation data if available (for filter editing support)
        if potfile_data:
            session_mgr.save_session_data("potfile_validation.json", potfile_data, analysis_session.session_id)

        # Run Kerberoast exposure analysis if raw user data is available
        if add_result.raw_users:
            try:
                from app import kerberoast_analysis

                # Build cracked accounts dict for Kerberoast analysis
                kerberoast_cracked = {
                    username: acc.get("cracked_pw", "")
                    for username, acc in account_data.items()
                    if acc.get("cracked_pw")
                }

                # Build password reuse clusters
                reuse_clusters: dict[str, list[str]] = {}
                for item in pw_reuse_table:
                    if isinstance(item, dict) and "hash" in item and "accounts" in item:
                        hash_val = item["hash"]
                        accounts = item["accounts"]
                        if len(accounts) > 1:
                            reuse_clusters[hash_val] = accounts

                # Run Kerberoast analysis
                kerberoast_report = kerberoast_analysis.analyze_kerberoast_exposure(
                    users=add_result.raw_users,
                    cracked_accounts=kerberoast_cracked,
                    hibp_results=None,  # HIBP runs later, can be updated after
                    password_reuse_clusters=reuse_clusters,
                )

                # Save Kerberoast report
                session_mgr.save_session_data(
                    "kerberoast_report.json",
                    kerberoast_report.to_dict(),
                    analysis_session.session_id
                )

                if kerberoast_report.summary.total_kerberoastable > 0:
                    print(f"--> Kerberoast analysis: {kerberoast_report.summary.total_kerberoastable} Kerberoastable accounts, "
                          f"{kerberoast_report.summary.critical_count} Critical, "
                          f"{kerberoast_report.summary.high_count} High risk")
            except Exception as kerb_err:
                logging.warning(f"Kerberoast analysis failed: {kerb_err}")

            # Run AS-REP roasting exposure analysis
            try:
                from app import asrep_analysis

                # Reuse the cracked accounts and reuse clusters from Kerberoast analysis
                asrep_report = asrep_analysis.analyze_asrep_exposure(
                    users=add_result.raw_users,
                    cracked_accounts=kerberoast_cracked,
                    hibp_results=None,  # HIBP runs later, can be updated after
                    password_reuse_clusters=reuse_clusters,
                )

                # Save AS-REP report
                session_mgr.save_session_data(
                    "asrep_report.json",
                    asrep_report.to_dict(),
                    analysis_session.session_id
                )

                if asrep_report.summary.total_asrep_roastable > 0:
                    print(f"--> AS-REP analysis: {asrep_report.summary.total_asrep_roastable} AS-REP roastable accounts, "
                          f"{asrep_report.summary.critical_count} Critical, "
                          f"{asrep_report.summary.high_count} High risk")
            except Exception as asrep_err:
                logging.warning(f"AS-REP analysis failed: {asrep_err}")

            # Run AD Description Analysis
            try:
                from app import description_analysis

                desc_report = description_analysis.analyze_descriptions(
                    users=add_result.raw_users,
                    use_llm=False,  # Regex-only by default
                )

                # Save description analysis report
                session_mgr.save_session_data(
                    "description_analysis_report.json",
                    desc_report.to_dict(),
                    analysis_session.session_id
                )

                if desc_report.summary.accounts_with_findings > 0:
                    print(f"--> Description analysis: {desc_report.summary.accounts_with_findings} accounts with sensitive info, "
                          f"{desc_report.summary.password_disclosures} password disclosures, "
                          f"{desc_report.summary.pii_findings} PII findings")
            except Exception as desc_err:
                logging.warning(f"Description analysis failed: {desc_err}")

            # Run Group Membership analysis
            try:
                from app import group_membership_analysis

                # Convert account_data dict to list format for analysis
                account_list = []
                for username, acc in account_data.items():
                    account_list.append({
                        "sam_account_name": username,
                        "member_of": acc.get("member_of", []),
                        "privilege_level": acc.get("privilege_level", "standard"),
                        "privilege_groups": acc.get("privilege_groups", []),
                        "is_enabled": acc.get("is_enabled", True),
                        "password": acc.get("cracked_pw", "")
                    })

                group_report = group_membership_analysis.analyze_group_memberships(
                    account_data=account_list,
                    top_n=25
                )

                # Save group membership report
                session_mgr.save_session_data(
                    "group_membership_report.json",
                    group_report.to_dict(),
                    analysis_session.session_id
                )

                if group_report.top_accounts:
                    print(f"--> Group membership analysis: Top account has {group_report.summary['max_group_count']} groups, "
                          f"{group_report.summary['tier0_in_top']} Tier 0, "
                          f"{group_report.summary['elevated_in_top']} Elevated in top 25")
            except Exception as grp_err:
                logging.warning(f"Group membership analysis failed: {grp_err}")

            # Generate group analysis data for group membership explorer
            try:
                all_groups: set[str] = set()
                group_accounts_data: list[dict] = []

                for username, acc in account_data.items():
                    member_of = acc.get("member_of", [])
                    if member_of:
                        all_groups.update(member_of)
                        cracked_pw = acc.get("cracked_pw", "")
                        group_accounts_data.append({
                            "sam_account_name": username,
                            "member_of": member_of,
                            "privilege_level": acc.get("privilege_level", "standard"),
                            "privilege_groups": acc.get("privilege_groups", []),
                            "is_enabled": acc.get("is_enabled", True),
                            "is_cracked": bool(cracked_pw and cracked_pw != "[NOT CRACKED]"),
                            "password": cracked_pw if cracked_pw and cracked_pw != "[NOT CRACKED]" else "",
                        })

                # Sort groups alphabetically for dropdown
                sorted_groups = sorted(all_groups, key=str.lower)

                session_mgr.save_session_data(
                    "group_analysis_data.json",
                    {
                        "groups": sorted_groups,
                        "accounts": group_accounts_data,
                        "total_groups": len(sorted_groups),
                        "total_accounts_with_groups": len(group_accounts_data),
                    },
                    analysis_session.session_id
                )

                if sorted_groups:
                    print(f"--> Group analysis data: {len(sorted_groups)} unique groups, "
                          f"{len(group_accounts_data)} accounts with group memberships")
            except Exception as ga_err:
                logging.warning(f"Group analysis data generation failed: {ga_err}")

            # Save raw ADD data for AI freeform prompts (account descriptions, etc.)
            session_mgr.save_session_data(
                "add_data.json",
                {"Users": add_result.raw_users},
                analysis_session.session_id
            )

        # Update session with statistics
        cracked_count = sum(1 for acc in account_data.values() if acc.get("cracked_pw"))
        total_count = len(account_data)
        crack_rate = (cracked_count / total_count * 100) if total_count > 0 else 0.0
        session_mgr.update_session(
            analysis_session.session_id,
            total_accounts=total_count,
            cracked_accounts=cracked_count,
            crack_rate=round(crack_rate, 2)
        )

        # Run automatic HIBP check if local database is available
        session_dir = session_mgr.get_session_dir(analysis_session.session_id)
        hibp_results = run_automatic_hibp_check(account_data, session_dir)
        if hibp_results:
            print(f"--> HIBP breach check: {hibp_results['total_found']}/{hibp_results['total_checked']} passwords found in breaches ({hibp_results['found_percentage']}%)")

        # Clean up Flask session
        session.pop("add_validation", None)
        session.pop("add_json_path", None)
        session.pop("potfile_validation", None)
        session.pop("potfile_path", None)
        session.pop("analysis_options", None)

        # Record timing for report generation
        report_duration = time_module.time() - report_start_time
        timing = get_timing_stats()
        timing.record_sample(
            operation="report_generation",
            duration_seconds=report_duration,
            item_count=total_count
        )

        print(f"\nADD JSON analysis complete. Session created: {analysis_session.name} ({analysis_session.session_id})\n")
        print(f"Report generation took {report_duration:.2f}s for {total_count} accounts")
        return cast(FlaskResponse, redirect(url_for("report")))

    except Exception as e:
        logging.error(f"ADD JSON processing error: {e}")
        import traceback
        traceback.print_exc()
        return Response(
            render_template(
                "message.html",
                message=f"Error processing ADD JSON: {str(e)}",
                message_type="error-message",
                status_code=500,
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            status=500,
        )


@app.route("/browse_directory", methods=["POST"])
@login_required
def browse_directory() -> Response:
    """
    AJAX endpoint to browse server directories for file selection.
    Returns list of directories and files in the requested path.

    Security: Access is restricted to paths configured in LOCAL_FILE_ALLOWED_PATHS.
    """
    data = request.get_json()
    path = data.get("path", ".")

    # Default to first allowed path if no path or root path provided
    default_path = LOCAL_FILE_ALLOWED_PATHS[0] if LOCAL_FILE_ALLOWED_PATHS else "/home/"
    if not path or path in (".", "/", "~"):
        path = default_path

    # Resolve to absolute path
    try:
        abs_path = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
    except Exception:
        return jsonify({"error": "Invalid path"}), 400

    # Security: Only allow access to configured paths
    if not is_allowed_path(abs_path):
        allowed_str = ", ".join(LOCAL_FILE_ALLOWED_PATHS)
        return jsonify({"error": f"Access denied. File browsing is restricted to: {allowed_str}"}), 403

    # Check if path exists and is a directory
    if not os.path.exists(abs_path):
        return jsonify({"error": "Path does not exist"}), 404

    if not os.path.isdir(abs_path):
        return jsonify({"error": "Path is not a directory"}), 400

    try:
        entries = []
        # Add parent directory option (except for /home/ which is the boundary)
        parent = os.path.dirname(abs_path)
        if parent != abs_path and is_allowed_path(parent):
            entries.append({
                "name": "..",
                "path": parent,
                "is_dir": True,
                "size": None,
                "mtime": None
            })

        # List directory contents
        for entry in sorted(os.listdir(abs_path)):
            entry_path = os.path.join(abs_path, entry)
            try:
                stat_info = os.stat(entry_path)
                is_dir = os.path.isdir(entry_path)
                size = None if is_dir else stat_info.st_size
                mtime = stat_info.st_mtime  # Unix timestamp
                entries.append({
                    "name": entry,
                    "path": entry_path,
                    "is_dir": is_dir,
                    "size": size,
                    "mtime": mtime
                })
            except (PermissionError, OSError):
                # Skip entries we can't access
                continue

        # Sort: directories first, then files, both alphabetically (default)
        entries.sort(key=lambda x: (not x["is_dir"] if x["name"] != ".." else False, x["name"].lower()))

        return jsonify({
            "current_path": abs_path,
            "entries": entries
        })

    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Hidden AI Analysis Endpoints (Experimental)
# These endpoints are not linked in the UI and require OLLAMA_ENABLED=true
# =============================================================================

@app.route("/api/ai/status", methods=["GET"])
@login_required
def ai_status() -> Response:
    """Check Ollama AI integration status."""
    from app.ollama_tools import test_ollama_connection, get_ollama_config

    config = get_ollama_config()
    result = test_ollama_connection()

    return jsonify(result)


@app.route("/api/ai/models", methods=["GET"])
@login_required
def ai_models() -> Response:
    """Get list of available models from Ollama server."""
    from app.ollama_tools import OllamaClient, get_ollama_config

    # Get server_id from query params to support multi-server setup
    server_id = request.args.get("server_id")
    config = get_ollama_config(server_id)
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    client = OllamaClient(config)
    # Get models with details (name and size) for the UI
    models = client.list_models(include_details=True)

    return jsonify({"models": models, "server_id": server_id, "host": config.host})


@app.route("/api/ai/library", methods=["GET"])
@login_required
def ai_library_models() -> Response:
    """Get list of popular models available to pull from Ollama library."""
    from app.ollama_tools import get_available_library_models

    models = get_available_library_models()
    return jsonify({"models": models})


@app.route("/api/ai/presets", methods=["GET"])
@login_required
def ai_presets() -> Response:
    """Get analysis preset configurations."""
    from app.ollama_tools import get_analysis_presets

    presets = get_analysis_presets()
    return jsonify({"presets": presets})


@app.route("/api/ai/pull", methods=["POST"])
@login_required
def ai_pull_model() -> Response:
    """Pull (download) a model from Ollama library."""
    from app.ollama_tools import pull_model, get_ollama_config

    data = request.get_json() or {}
    server_id = data.get("server_id")  # Optional - defaults to primary server
    model_name = data.get("model")

    config = get_ollama_config(server_id)
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    if not model_name:
        return jsonify({"error": "Model name is required"}), 400

    result = pull_model(model_name, server_id=server_id)
    if result["success"]:
        return jsonify(result)
    else:
        return jsonify(result), 500


@app.route("/api/ai/delete", methods=["POST"])
@login_required
def ai_delete_model() -> Response:
    """Delete a model from the Ollama server."""
    from app.ollama_tools import delete_model, get_ollama_config

    data = request.get_json() or {}
    server_id = data.get("server_id")  # Optional - defaults to primary server
    model_name = data.get("model")

    config = get_ollama_config(server_id)
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    if not model_name:
        return jsonify({"error": "Model name is required"}), 400

    result = delete_model(model_name, server_id=server_id)
    if result["success"]:
        return jsonify(result)
    else:
        return jsonify(result), 500


@app.route("/api/ai/generate", methods=["POST"])
@login_required
def ai_generate() -> Response:
    """Send a prompt to the Ollama server."""
    import time
    from app.ollama_tools import OllamaClient, get_ollama_config

    data = request.get_json()
    if not data or "prompt" not in data:
        return jsonify({"error": "Missing 'prompt' in request body"}), 400

    if not data.get("model"):
        return jsonify({"error": "Missing 'model' in request body"}), 400

    # Support server_id for multi-server benchmarks
    server_id = data.get("server_id")
    config = get_ollama_config(server_id)
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    client = OllamaClient(config)

    start_time = time.time()
    response = client.generate(
        prompt=data["prompt"],
        model=data["model"],
        system=data.get("system"),
        temperature=data.get("temperature", 0.7)
    )
    elapsed = time.time() - start_time

    if response:
        # Format response time
        if elapsed >= 60:
            time_formatted = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
        else:
            time_formatted = f"{elapsed:.1f}s"

        return jsonify({
            "response": response,
            "content": response,  # Alias for consistency with analyze endpoint
            "response_time_seconds": elapsed,
            "response_time_formatted": time_formatted
        })
    else:
        return jsonify({"error": "Failed to generate response"}), 500


@app.route("/api/ai/executive-summary", methods=["POST"])
@login_required
def ai_executive_summary() -> Response:
    """Generate an executive summary from session data."""
    from app.ollama_tools import PasswordAnalysisAI, get_ollama_config

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    # Get data from session or request
    data = request.get_json() or {}

    model = data.get("model")
    if not model:
        return jsonify({"error": "Missing 'model' in request body"}), 400

    # Try to use session data if not provided in request
    stats = data.get("stats") or session.get("report_data", {}).get("stats", {})
    patterns = data.get("patterns") or session.get("report_data", {}).get("bad_practices", {})
    critical_findings = data.get("critical_findings", [])

    if not stats:
        return jsonify({"error": "No statistics data available"}), 400

    ai = PasswordAnalysisAI()
    summary = ai.generate_executive_summary(stats, patterns, critical_findings, model=model)

    if summary:
        return jsonify({"summary": summary})
    else:
        return jsonify({"error": "Failed to generate executive summary"}), 500


@app.route("/api/ai/analyze-patterns", methods=["POST"])
@login_required
def ai_analyze_patterns() -> Response:
    """Generate natural language pattern analysis."""
    from app.ollama_tools import PasswordAnalysisAI, get_ollama_config

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    data = request.get_json() or {}

    model = data.get("model")
    if not model:
        return jsonify({"error": "Missing 'model' in request body"}), 400

    pattern_data = data.get("patterns") or session.get("report_data", {}).get("bad_practices", {})

    if not pattern_data:
        return jsonify({"error": "No pattern data available"}), 400

    ai = PasswordAnalysisAI()
    analysis = ai.describe_patterns(pattern_data, model=model)

    if analysis:
        return jsonify({"analysis": analysis})
    else:
        return jsonify({"error": "Failed to analyze patterns"}), 500


@app.route("/api/ai/cluster-passwords", methods=["POST"])
@login_required
def ai_cluster_passwords() -> Response:
    """Categorize passwords by semantic meaning."""
    from app.ollama_tools import PasswordAnalysisAI, get_ollama_config

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    data = request.get_json() or {}

    model = data.get("model")
    if not model:
        return jsonify({"error": "Missing 'model' in request body"}), 400

    passwords = data.get("passwords", [])

    # If no passwords provided, try to get from session
    if not passwords:
        report_data = session.get("report_data", {})
        top_passwords = report_data.get("top_passwords", [])
        passwords = [p[0] for p in top_passwords if p]

    if not passwords:
        return jsonify({"error": "No passwords provided"}), 400

    sample_size = data.get("sample_size", 500)

    ai = PasswordAnalysisAI()
    result = ai.cluster_passwords_semantically(passwords, sample_size, model=model)

    if result:
        return jsonify(result)
    else:
        return jsonify({"error": "Failed to cluster passwords"}), 500


@app.route("/api/ai/attack-strategy", methods=["POST"])
@login_required
def ai_attack_strategy() -> Response:
    """Generate attack strategy recommendations."""
    from app.ollama_tools import PasswordAnalysisAI, get_ollama_config

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    data = request.get_json() or {}

    model = data.get("model")
    if not model:
        return jsonify({"error": "Missing 'model' in request body"}), 400

    patterns = data.get("patterns", {})
    stats = data.get("stats", {})
    base_words = data.get("base_words", [])
    structures = data.get("structures", [])

    ai = PasswordAnalysisAI()
    strategy = ai.recommend_attack_strategy(patterns, stats, base_words, structures, model=model)

    if strategy:
        return jsonify({"strategy": strategy})
    else:
        return jsonify({"error": "Failed to generate attack strategy"}), 500


# =============================================================================
# AI Report Section Endpoints
# =============================================================================

@app.route("/api/ai/servers", methods=["GET"])
@login_required
def ai_list_servers() -> Response:
    """Get all configured Ollama servers and their status."""
    from app.ollama_tools import test_all_servers
    return jsonify(test_all_servers())


@app.route("/api/ai/servers/<server_id>/status", methods=["GET"])
@login_required
def ai_server_status(server_id: str) -> Response:
    """Get detailed status of a specific Ollama server including running models."""
    from app.ollama_tools import test_ollama_connection, get_server_by_id, get_ollama_config, OllamaClient

    server = get_server_by_id(server_id)
    if not server:
        return jsonify({"error": f"Unknown server: {server_id}"}), 404

    # Basic connection status
    status = test_ollama_connection(host=server.host)

    # Get extended info if server is reachable
    running_models = {"models": [], "count": 0, "total_vram": 0, "busy": False}
    version = None

    if status.get("reachable"):
        config = get_ollama_config(server_id)
        client = OllamaClient(config)
        running_models = client.get_running_models()
        version = client.get_version()

    return jsonify({
        "id": server.id,
        "name": server.name,
        "host": server.host,
        "description": server.description,
        "hardware": server.hardware,
        "version": version,
        "running": running_models,
        **status
    })


@app.route("/api/ai/report/sections", methods=["GET"])
@login_required
def ai_report_sections() -> Response:
    """Get all AI report section configurations."""
    from app.ollama_tools import get_ai_report_sections
    return jsonify({"sections": get_ai_report_sections()})


def _analyze_spi_section(
    section_id: str,
    section_config: dict,
    client,
    model: str | None,
    temperature: float | None,
    server_id: str,
    server_name: str,
    start_time: float
) -> Response:
    """
    Run full SPI (Semantic Password Intelligence) analysis.

    Runs all 11 SPI category prompts and aggregates results.
    """
    import time
    from app.spi_analyzer import SPIAnalyzer, results_to_dict
    from app.spi_prompts import SPI_PREAMBLE

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()

    analyzer = SPIAnalyzer(session_dir)

    # Use provided model/temp or section defaults
    used_model = model or section_config["recommended_model"]
    used_temp = temperature if temperature is not None else section_config["temperature"]

    # Create LLM call function that uses the client
    total_prompt_tokens = 0
    total_completion_tokens = 0

    def llm_call_fn(prompt: str) -> str:
        nonlocal total_prompt_tokens, total_completion_tokens
        result = client.generate(
            prompt=prompt,
            model=used_model,
            system=SPI_PREAMBLE,
            temperature=used_temp,
            include_usage=True
        )
        if isinstance(result, dict):
            total_prompt_tokens += result.get("prompt_tokens", 0)
            total_completion_tokens += result.get("completion_tokens", 0)
            return result.get("response", "")
        return result or ""

    # Run full analysis (all categories)
    results = analyzer.run_full_analysis(llm_call_fn)

    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    elapsed_seconds = round(elapsed_time, 1)
    elapsed_formatted = f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s" if elapsed_time >= 60 else f"{elapsed_seconds}s"

    # Format results as HTML
    html_report = analyzer.format_report_html(results)

    # Also prepare JSON data for debugging/analysis
    results_dict = results_to_dict(results)

    # Build summary text
    summary_lines = [f"Analyzed {results.total_passwords:,} passwords across {len(results.categories)} categories."]
    if results.sampling_used:
        summary_lines.append(f"Sampling: {results.sampling_note}")

    # Count categories with matches
    categories_with_matches = sum(1 for cat in results.categories.values() if cat.matches)
    total_matches = sum(len(cat.matches) for cat in results.categories.values())
    summary_lines.append(f"Found {total_matches:,} total matches in {categories_with_matches} categories.")

    # Save to test_outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = used_model.replace(":", "_").replace("/", "_")
    # Use 'spi' as the filename prefix since this is SPI analysis
    filename = f"spi_{safe_model}_t{used_temp}_{timestamp}.md"

    test_output_dir = os.path.join(os.path.dirname(__file__), "test_outputs")
    os.makedirs(test_output_dir, exist_ok=True)
    filepath = os.path.join(test_output_dir, filename)

    with open(filepath, "w") as f:
        f.write(f"# SPI Analysis Test Output\n\n")
        f.write(f"- **Section:** {section_id}\n")
        f.write(f"- **Model:** {used_model}\n")
        f.write(f"- **Server:** {server_name}\n")
        f.write(f"- **Temperature:** {used_temp}\n")
        f.write(f"- **Response Time:** {elapsed_formatted} ({elapsed_seconds}s)\n")
        f.write(f"- **Tokens:** {total_prompt_tokens:,} prompt + {total_completion_tokens:,} completion = {total_prompt_tokens + total_completion_tokens:,} total\n")
        f.write(f"- **Categories Analyzed:** {len(results.categories)}\n")
        f.write(f"- **Timestamp:** {timestamp}\n")
        f.write(f"\n---\n\n## Summary\n\n")
        f.write("\n".join(summary_lines))
        f.write(f"\n\n## Results by Category\n\n")
        for cat_key, cat_result in results.categories.items():
            count, pct = results.get_category_stats(cat_key)
            f.write(f"### {cat_result.category_name}\n")
            f.write(f"- Matches: {count} ({pct:.1f}%)\n")
            if cat_result.matches:
                f.write(f"- Examples: {', '.join(cat_result.matches[:10])}\n")
            if cat_result.error:
                f.write(f"- Error: {cat_result.error}\n")
            f.write("\n")

    return jsonify({
        "section_id": section_id,
        "content": html_report,
        "summary": "\n".join(summary_lines),
        "model": used_model,
        "server_id": server_id,
        "server_name": server_name,
        "saved_to": filename,
        "response_time_seconds": elapsed_seconds,
        "response_time_formatted": elapsed_formatted,
        "prompt_tokens": total_prompt_tokens,
        "completion_tokens": total_completion_tokens,
        "total_tokens": total_prompt_tokens + total_completion_tokens,
        "categories_analyzed": len(results.categories),
        "total_matches": total_matches,
        "results_json": results_dict
    })


def _analyze_ci_section(
    section_id: str,
    section_config: dict,
    client,
    model: str | None,
    temperature: float | None,
    server_id: str,
    server_name: str,
    start_time: float
) -> Response:
    """
    Run full Company Intelligence analysis.

    Runs all 3 CI category prompts and aggregates findings.
    """
    import time
    from app.company_intel_analyzer import CIAnalyzer, results_to_dict
    from app.company_intel_prompts import CI_PREAMBLE

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()

    analyzer = CIAnalyzer(session_dir)

    # Use provided model/temp or section defaults
    used_model = model or section_config["recommended_model"]
    used_temp = temperature if temperature is not None else section_config["temperature"]

    # Create LLM call function that uses the client
    total_prompt_tokens = 0
    total_completion_tokens = 0

    def llm_call_fn(prompt: str) -> str:
        nonlocal total_prompt_tokens, total_completion_tokens
        result = client.generate(
            prompt=prompt,
            model=used_model,
            system=CI_PREAMBLE,
            temperature=used_temp,
            include_usage=True
        )
        if isinstance(result, dict):
            total_prompt_tokens += result.get("prompt_tokens", 0)
            total_completion_tokens += result.get("completion_tokens", 0)
            return result.get("response", "")
        return result or ""

    # Run full analysis (all categories)
    results = analyzer.run_full_analysis(llm_call_fn)

    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    elapsed_seconds = round(elapsed_time, 1)
    elapsed_formatted = f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s" if elapsed_time >= 60 else f"{elapsed_seconds}s"

    # Format results as HTML
    html_report = analyzer.format_report_html(results)

    # Also prepare JSON data for debugging/analysis
    results_dict = results_to_dict(results)

    # Build summary text
    summary_lines = [f"Analyzed {results.total_passwords:,} passwords and {results.total_accounts:,} accounts across {len(results.categories)} categories."]
    if results.sampling_used:
        summary_lines.append(f"Sampling: {results.sampling_note}")

    # Count total findings
    total_findings = sum(len(cat.findings) for cat in results.categories.values())
    categories_with_findings = sum(1 for cat in results.categories.values() if cat.findings)
    summary_lines.append(f"Found {total_findings} findings in {categories_with_findings} categories.")

    # Save to test_outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = used_model.replace(":", "_").replace("/", "_")
    # Use 'company-intel' as the filename prefix since this is CI analysis
    filename = f"company-intel_{safe_model}_t{used_temp}_{timestamp}.md"

    test_output_dir = os.path.join(os.path.dirname(__file__), "test_outputs")
    os.makedirs(test_output_dir, exist_ok=True)
    filepath = os.path.join(test_output_dir, filename)

    with open(filepath, "w") as f:
        f.write(f"# Company Intelligence Analysis Test Output\n\n")
        f.write(f"- **Section:** {section_id}\n")
        f.write(f"- **Model:** {used_model}\n")
        f.write(f"- **Server:** {server_name}\n")
        f.write(f"- **Temperature:** {used_temp}\n")
        f.write(f"- **Response Time:** {elapsed_formatted} ({elapsed_seconds}s)\n")
        f.write(f"- **Tokens:** {total_prompt_tokens:,} prompt + {total_completion_tokens:,} completion = {total_prompt_tokens + total_completion_tokens:,} total\n")
        f.write(f"- **Categories Analyzed:** {len(results.categories)}\n")
        f.write(f"- **Timestamp:** {timestamp}\n")
        f.write(f"\n---\n\n## Summary\n\n")
        f.write("\n".join(summary_lines))
        f.write(f"\n\n## Results by Category\n\n")
        for cat_key, cat_result in results.categories.items():
            f.write(f"### {cat_result.category_name}\n")
            f.write(f"- Findings: {len(cat_result.findings)}\n")
            for finding in cat_result.findings:
                f.write(f"  - **{finding.what}** ({finding.confidence})\n")
                if finding.evidence:
                    f.write(f"    Evidence: {', '.join(finding.evidence[:5])}\n")
            if cat_result.error:
                f.write(f"- Error: {cat_result.error}\n")
            f.write("\n")

    return jsonify({
        "section_id": section_id,
        "content": html_report,
        "summary": "\n".join(summary_lines),
        "model": used_model,
        "server_id": server_id,
        "server_name": server_name,
        "saved_to": filename,
        "response_time_seconds": elapsed_seconds,
        "response_time_formatted": elapsed_formatted,
        "prompt_tokens": total_prompt_tokens,
        "completion_tokens": total_completion_tokens,
        "total_tokens": total_prompt_tokens + total_completion_tokens,
        "categories_analyzed": len(results.categories),
        "total_findings": total_findings,
        "results_json": results_dict
    })


def _analyze_description_llm_section(
    section_id: str,
    section_config: dict,
    client,
    model: str | None,
    temperature: float | None,
    server_id: str,
    server_name: str,
    start_time: float
) -> Response:
    """
    Run full Description LLM analysis using chunked processing.

    Analyzes AD account descriptions for sensitive information:
    - Passwords and password hints
    - PII (SSN, phone, DOB, email)
    - Credentials (API keys, tokens, PINs)
    """
    import time
    from app.description_llm_analyzer import DescriptionLLMAnalyzer
    from app.description_llm_prompts import DA_PREAMBLE

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()

    # Get chunk size from config or use default
    chunk_config = section_config.get("chunk_config", {})
    chunk_size = chunk_config.get("default_chunk_size", 100)

    analyzer = DescriptionLLMAnalyzer(session_dir, chunk_size=chunk_size)

    # Check if we have users with descriptions
    users_with_desc = analyzer.get_users_with_descriptions()
    total_users = analyzer.get_total_user_count()

    if not users_with_desc:
        elapsed_time = time.time() - start_time
        return jsonify({
            "section_id": section_id,
            "content": '<div class="da-no-data"><p>No AD account data available or no accounts with descriptions found.</p></div>',
            "summary": f"No accounts with descriptions found (0 of {total_users} accounts have descriptions)",
            "model": model or section_config["recommended_model"],
            "server_id": server_id,
            "server_name": server_name,
            "response_time_seconds": round(elapsed_time, 1),
            "response_time_formatted": f"{round(elapsed_time, 1)}s",
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "categories_analyzed": 0,
            "total_findings": 0,
            "results_json": {}
        })

    # Use provided model/temp or section defaults
    used_model = model or section_config["recommended_model"]
    used_temp = temperature if temperature is not None else section_config["temperature"]

    # Create LLM call function that uses the client
    total_prompt_tokens = 0
    total_completion_tokens = 0

    def llm_call_fn(prompt: str) -> str:
        nonlocal total_prompt_tokens, total_completion_tokens
        result = client.generate(
            prompt=prompt,
            model=used_model,
            system=DA_PREAMBLE,
            temperature=used_temp,
            include_usage=True
        )
        if isinstance(result, dict):
            total_prompt_tokens += result.get("prompt_tokens", 0)
            total_completion_tokens += result.get("completion_tokens", 0)
            return result.get("response", "")
        return result or ""

    # Run full analysis (all categories)
    results = analyzer.run_full_analysis(llm_call_fn, model_name=used_model, temperature=used_temp)

    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    elapsed_seconds = round(elapsed_time, 1)
    elapsed_formatted = f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s" if elapsed_time >= 60 else f"{elapsed_seconds}s"

    # Format results as HTML
    html_report = analyzer.format_report_html(results)

    # Also prepare JSON data for debugging/analysis
    results_dict = results.to_dict()

    # Build summary text
    summary_lines = [f"Analyzed {results.accounts_analyzed:,} accounts with descriptions (of {total_users:,} total) across {len(results.category_results)} categories."]
    summary_lines.append(f"Chunk size: {results.chunk_size}, Total chunks processed: {results.total_chunks}")

    total_findings = results.total_findings
    accounts_with_findings = results.unique_accounts_with_findings
    summary_lines.append(f"Found {total_findings:,} findings in {accounts_with_findings} accounts.")

    # Save to test_outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = used_model.replace(":", "_").replace("/", "_")
    filename = f"description-analysis_{safe_model}_t{used_temp}_{timestamp}.md"

    test_output_dir = os.path.join(os.path.dirname(__file__), "test_outputs")
    os.makedirs(test_output_dir, exist_ok=True)
    filepath = os.path.join(test_output_dir, filename)

    with open(filepath, "w") as f:
        f.write(f"# Description LLM Analysis Test Output\n\n")
        f.write(f"- **Section:** {section_id}\n")
        f.write(f"- **Model:** {used_model}\n")
        f.write(f"- **Server:** {server_name}\n")
        f.write(f"- **Temperature:** {used_temp}\n")
        f.write(f"- **Response Time:** {elapsed_formatted} ({elapsed_seconds}s)\n")
        f.write(f"- **Tokens:** {total_prompt_tokens:,} prompt + {total_completion_tokens:,} completion = {total_prompt_tokens + total_completion_tokens:,} total\n")
        f.write(f"- **Accounts Analyzed:** {results.accounts_analyzed}\n")
        f.write(f"- **Chunk Size:** {results.chunk_size}\n")
        f.write(f"- **Total Chunks:** {results.total_chunks}\n")
        f.write(f"- **Categories Analyzed:** {len(results.category_results)}\n")
        f.write(f"- **Timestamp:** {timestamp}\n")
        f.write(f"\n---\n\n## Summary\n\n")
        f.write("\n".join(summary_lines))
        f.write(f"\n\n## Results by Category\n\n")
        for cat_key, cat_result in results.category_results.items():
            f.write(f"### {cat_result.category_name}\n")
            f.write(f"- Accounts with findings: {cat_result.accounts_with_findings}\n")
            f.write(f"- Total findings: {cat_result.total_findings}\n")
            f.write(f"- Chunks processed: {cat_result.chunks_processed}\n")
            if cat_result.findings:
                f.write(f"\n**Findings:**\n")
                for account in cat_result.findings[:10]:  # Limit for file size
                    if account.has_findings:
                        f.write(f"\n**{account.sam_account_name}**\n")
                        for finding in account.findings:
                            f.write(f"  - {finding.category}: {finding.value} ({finding.confidence:.0%})\n")
                            f.write(f"    Reasoning: {finding.reasoning}\n")
            if cat_result.error:
                f.write(f"- Error: {cat_result.error}\n")
            f.write("\n")

    return jsonify({
        "section_id": section_id,
        "content": html_report,
        "summary": "\n".join(summary_lines),
        "model": used_model,
        "server_id": server_id,
        "server_name": server_name,
        "saved_to": filename,
        "response_time_seconds": elapsed_seconds,
        "response_time_formatted": elapsed_formatted,
        "prompt_tokens": total_prompt_tokens,
        "completion_tokens": total_completion_tokens,
        "total_tokens": total_prompt_tokens + total_completion_tokens,
        "categories_analyzed": len(results.category_results),
        "total_findings": total_findings,
        "accounts_analyzed": results.accounts_analyzed,
        "accounts_with_findings": accounts_with_findings,
        "chunk_size": results.chunk_size,
        "total_chunks": results.total_chunks,
        "results_json": results_dict
    })


@app.route("/api/ai/report/analyze/<section_id>", methods=["POST"])
@login_required
def ai_report_analyze_section(section_id: str) -> Response:
    """
    Analyze a specific report section.

    Expects JSON body with:
    - model: (optional) Override model selection
    - temperature: (optional) Override temperature
    - server_id: (optional) Server to use (defaults to primary)
    - data: Dictionary containing section-specific data
    """
    import time
    from app.ollama_tools import AIReportAnalyzer, get_ollama_config, get_ai_report_sections, get_server_by_id, OllamaClient

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    sections = get_ai_report_sections()
    if section_id not in sections:
        return jsonify({"error": f"Unknown section: {section_id}"}), 400

    section_config = sections[section_id]
    pipeline = section_config.get("pipeline", "standard")

    request_data = request.get_json() or {}
    model = request_data.get("model")
    temperature = request_data.get("temperature")
    server_id = request_data.get("server_id", "primary")
    data = request_data.get("data", {})

    # Get server-specific config
    server = get_server_by_id(server_id)
    server_name = server.name if server else "Primary"
    server_host = server.host if server else config.host
    server_config = get_ollama_config(server_id)

    # Track response time
    start_time = time.time()

    # Create client for specific server
    client = OllamaClient(server_config)

    # Handle specialized pipelines (SPI, Company Intel, and Description LLM)
    if pipeline == "spi":
        return _analyze_spi_section(
            section_id, section_config, client, model, temperature,
            server_id, server_name, start_time
        )
    elif pipeline == "company_intel":
        return _analyze_ci_section(
            section_id, section_config, client, model, temperature,
            server_id, server_name, start_time
        )
    elif pipeline == "description_llm":
        return _analyze_description_llm_section(
            section_id, section_config, client, model, temperature,
            server_id, server_name, start_time
        )

    # Standard pipeline - use generic analyzer
    # If no data provided, load it automatically (fallback)
    if not data:
        from app.ollama_tools import get_ai_data_loader
        session_mgr = get_session_manager()
        session_dir = session_mgr.get_session_dir()
        loader = get_ai_data_loader(session_dir)
        data = loader.load_section_data(section_id)

    analyzer = AIReportAnalyzer(client=client)

    # Use the new method that returns token usage
    result_data = analyzer.generate_section_with_usage(
        section_id=section_id,
        data=data,
        model=model,
        temperature=temperature
    )

    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    elapsed_seconds = round(elapsed_time, 1)
    elapsed_formatted = f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s" if elapsed_time >= 60 else f"{elapsed_seconds}s"

    # Extract result and token info
    if result_data and isinstance(result_data, dict):
        result = result_data.get("response", "")
        prompt_tokens = result_data.get("prompt_tokens", 0)
        completion_tokens = result_data.get("completion_tokens", 0)
        total_tokens = result_data.get("total_tokens", 0)
    else:
        result = result_data if isinstance(result_data, str) else None
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0

    if result:
        # Cache the result in session
        if "ai_report_cache" not in session:
            session["ai_report_cache"] = {}

        used_model = model or sections[section_id]["recommended_model"]
        used_temp = temperature if temperature is not None else sections[section_id]["temperature"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Check if response seems off-topic (basic relevance check)
        relevance_keywords = ["password", "pattern", "security", "account", "crack", "hash", "weak", "user"]
        result_lower = result.lower()
        keyword_matches = sum(1 for kw in relevance_keywords if kw in result_lower)
        seems_off_topic = keyword_matches < 2  # Less than 2 matches = probably off-topic

        session["ai_report_cache"][section_id] = {
            "content": result,
            "model": used_model,
            "timestamp": json.dumps({"generated": True})  # Simple marker
        }
        session.modified = True

        # Auto-save to test_outputs folder
        test_output_dir = os.path.join(os.path.dirname(__file__), "test_outputs")
        os.makedirs(test_output_dir, exist_ok=True)

        # Create filename: section_model_temp_timestamp.md
        # Mark off-topic responses with _OFFTOPIC suffix
        safe_model = used_model.replace(":", "_").replace("/", "_")
        offtopic_marker = "_OFFTOPIC" if seems_off_topic else ""
        filename = f"{section_id}_{safe_model}_t{used_temp}_{timestamp}{offtopic_marker}.md"
        filepath = os.path.join(test_output_dir, filename)

        # Save with metadata header
        with open(filepath, "w") as f:
            f.write(f"# AI Test Output\n\n")
            f.write(f"- **Section:** {section_id}\n")
            f.write(f"- **Model:** {used_model}\n")
            f.write(f"- **Server:** {server_name} ({server_host})\n")
            f.write(f"- **Temperature:** {used_temp}\n")
            f.write(f"- **Response Time:** {elapsed_formatted} ({elapsed_seconds}s)\n")
            f.write(f"- **Tokens:** {prompt_tokens:,} prompt + {completion_tokens:,} completion = {total_tokens:,} total\n")
            f.write(f"- **Timestamp:** {timestamp}\n")
            if seems_off_topic:
                f.write(f"- **WARNING:** Response appears off-topic (only {keyword_matches} relevance keywords found)\n")
            f.write(f"\n---\n\n")
            f.write(result)

        response_data = {
            "section_id": section_id,
            "content": result,
            "model": used_model,
            "server_id": server_id,
            "server_name": server_name,
            "saved_to": filename,
            "response_time_seconds": elapsed_seconds,
            "response_time_formatted": elapsed_formatted,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        }

        if seems_off_topic:
            response_data["warning"] = f"Response may be off-topic - only {keyword_matches} password-related keywords detected. The model may not be suitable for this task."

        return jsonify(response_data)
    else:
        return jsonify({"error": "Failed to generate analysis", "server_id": server_id, "server_name": server_name, "response_time_seconds": elapsed_seconds, "response_time_formatted": elapsed_formatted}), 500


# ============================================================================
# AI Pipeline Endpoints (3-Phase Analysis with SSE Streaming)
# ============================================================================


@app.route("/api/ai/report/pipeline/stream", methods=["GET"])
@login_required
def ai_pipeline_stream() -> Response:
    """
    Run 3-phase pipeline with Server-Sent Events (SSE) for real-time progress.

    Query params:
    - sections: comma-separated section IDs or "all" (default: all)
    - server_id: Ollama server to use (default: primary)
    - skip_phase1: If "true", skip Phase 1 and load from cached debug files (default: false)

    Streams JSON events:
    - type: "progress" - Progress updates
    - type: "complete" - Final results
    - type: "error" - Error occurred
    """
    import time
    import glob
    from flask import Response, stream_with_context
    from app.ollama_tools import (
        AIPipelineRunner, get_ollama_config, OllamaClient,
        get_ai_data_loader, get_phase_config, AIReportAnalyzer,
        get_ai_report_sections
    )
    from app.spi_analyzer import SPIAnalyzer, results_to_dict as spi_results_to_dict
    from app.spi_prompts import get_all_category_keys as get_spi_category_keys, get_category_display_name as get_spi_category_name
    from app.company_intel_analyzer import CIAnalyzer, results_to_dict as ci_results_to_dict
    from app.company_intel_prompts import get_all_category_keys as get_ci_category_keys, get_category_display_name as get_ci_category_name

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    # Parse query params
    sections_param = request.args.get("sections", "all")
    server_id = request.args.get("server_id", "primary")
    skip_phase1 = request.args.get("skip_phase1", "false").lower() == "true"

    # SPI configuration from UI (not .env)
    spi_max_passwords = request.args.get("spi_max_passwords", "500")
    spi_intelligent_sampling = request.args.get("spi_intelligent_sampling", "true").lower() == "true"

    # CI (Company Intel) configuration from UI
    ci_max_passwords = request.args.get("ci_max_passwords", "500")
    ci_intelligent_sampling = request.args.get("ci_intelligent_sampling", "true").lower() == "true"

    # Temperature settings from UI (JSON string)
    temperatures_json = request.args.get("temperatures", "{}")
    try:
        temperatures = json.loads(temperatures_json)
    except (json.JSONDecodeError, TypeError):
        temperatures = {}

    # Determine sections to process
    all_sections = get_ai_report_sections()

    # Filter to only enabled sections (the 3 active AAIA pipelines)
    enabled_sections = [
        s for s in ["weak-habits", "company-intel", "description-analysis"]
        if s in all_sections and all_sections[s].get("enabled", True)
    ]

    if sections_param == "all":
        sections = enabled_sections
    else:
        sections = [s.strip() for s in sections_param.split(",")
                    if s.strip() in all_sections
                    and all_sections[s.strip()].get("enabled", True)]
        if not sections:
            sections = enabled_sections

    def generate():
        """Generator that yields SSE events as pipeline progresses."""
        start_time = time.time()

        # Initialize
        server_config = get_ollama_config(server_id)
        client = OllamaClient(server_config)
        # Use session-specific directories for AAIA
        session_mgr = get_session_manager()
        session_dir = session_mgr.get_session_dir()
        session_debug_dir = _get_ai_analysis_dir()
        runner = AIPipelineRunner(client=client, data_dir=session_dir, debug_dir=session_debug_dir)
        loader = get_ai_data_loader(session_dir)

        # Adjust total steps based on skip_phase1
        total_steps = len(sections) * 2 if skip_phase1 else len(sections) * 3
        step_counter = 0

        results = {}
        total_time = 0
        all_phase1_results = {}
        all_phase2_results = {}
        spi_results = {}  # Store SPI analysis results for weak-habits section

        def load_latest_phase1_file(section_id: str) -> str | None:
            """Load the most recent Phase 1 debug file for a section."""
            import glob
            ai_analysis_dir = _get_ai_analysis_dir()
            pattern = os.path.join(ai_analysis_dir, f"{section_id}_phase1_raw_*.md")
            files = glob.glob(pattern)
            if not files:
                return None
            # Sort by modification time, get newest
            latest_file = max(files, key=os.path.getmtime)
            try:
                with open(latest_file, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                logging.error(f"Failed to load {latest_file}: {e}")
                return None

        # Optimized execution order (minimize model reloads)
        # Run deepseek sections first (likely already loaded), then llama sections last
        llama_sections = [s for s in sections if get_phase_config(s).get("phase1", {}).get("model", "").startswith("llama")]
        deepseek_sections = [s for s in sections if s not in llama_sections]
        ordered_sections = deepseek_sections + llama_sections

        def send_progress(phase, section, action):
            nonlocal step_counter
            step_counter += 1
            elapsed = time.time() - start_time
            progress_data = {
                "type": "progress",
                "total_steps": total_steps,
                "current_step": step_counter,
                "current_phase": phase,
                "current_section": section,
                "current_action": action,
                "elapsed_seconds": round(elapsed, 1),
                "percent_complete": round(step_counter / total_steps * 100, 1)
            }
            return f"data: {json.dumps(progress_data)}\n\n"

        def send_substep_progress(phase: str, section: str, action: str) -> str:
            """Send progress update without incrementing step counter (for sub-steps like SPI categories)."""
            elapsed = time.time() - start_time
            progress_data = {
                "type": "progress",
                "total_steps": total_steps,
                "current_step": step_counter,  # Don't increment
                "current_phase": phase,
                "current_section": section,
                "current_action": action,
                "elapsed_seconds": round(elapsed, 1),
                "percent_complete": round(step_counter / total_steps * 100, 1)
            }
            return f"data: {json.dumps(progress_data)}\n\n"

        def send_error(error_msg):
            error_data = {
                "type": "error",
                "error": error_msg,
                "elapsed_seconds": round(time.time() - start_time, 1)
            }
            return f"data: {json.dumps(error_data)}\n\n"

        def send_step_complete(phase, section, step_time, prompt_tokens=0, completion_tokens=0, total_tokens=0, tier0_result=None):
            """Send event when a step completes with timing and token info."""
            complete_data = {
                "type": "step_complete",
                "phase": phase,
                "section": section,
                "step_time": round(step_time, 1),
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            }
            if tier0_result:
                complete_data["tier0_result"] = tier0_result  # "skipped", "fast", or "deep"
            return f"data: {json.dumps(complete_data)}\n\n"

        def send_model_loading(model_name, action="Loading"):
            """Send event when model is being loaded."""
            loading_data = {
                "type": "model_loading",
                "model": model_name,
                "action": action,
                "elapsed_seconds": round(time.time() - start_time, 1)
            }
            return f"data: {json.dumps(loading_data)}\n\n"

        try:
            # Send initial progress
            yield f"data: {json.dumps({'type': 'progress', 'total_steps': total_steps, 'current_step': 0, 'current_phase': 'initializing', 'current_section': '', 'current_action': 'Starting pipeline...', 'elapsed_seconds': 0, 'percent_complete': 0})}\n\n"

            # Track current model to detect switches
            current_model = None

            # PHASE 1: Run all initial analyses OR load from cache
            if skip_phase1:
                # Load cached Phase 1 results from debug files
                yield f"data: {json.dumps({'type': 'progress', 'total_steps': total_steps, 'current_step': 0, 'current_phase': 'phase1', 'current_section': '', 'current_action': 'Loading cached Phase 1 results...', 'elapsed_seconds': round(time.time() - start_time, 1), 'percent_complete': 0})}\n\n"

                missing_sections = []
                for section_id in ordered_sections:
                    cached_content = load_latest_phase1_file(section_id)
                    if cached_content:
                        all_phase1_results[section_id] = {
                            "content": cached_content,
                            "model": "cached",
                            "temperature": 0,
                            "time": 0,
                            "tokens": 0,
                            "prompt_tokens": 0,
                            "completion_tokens": 0,
                            "cached": True
                        }
                    else:
                        missing_sections.append(section_id)
                        all_phase1_results[section_id] = {
                            "content": "",
                            "model": "cached",
                            "temperature": 0,
                            "time": 0,
                            "tokens": 0,
                            "error": "No cached Phase 1 file found"
                        }

                if missing_sections:
                    yield send_error(f"Missing cached Phase 1 files for: {', '.join(missing_sections)}")
                    return

                # Send phase1_cached event so frontend knows Phase 1 was skipped
                yield f"data: {json.dumps({'type': 'phase1_cached', 'sections': list(ordered_sections), 'elapsed_seconds': round(time.time() - start_time, 1)})}\n\n"

            else:
                # Run Phase 1 normally
                for section_id in ordered_sections:
                    phase_config = get_phase_config(section_id)
                    phase1_model = phase_config.get("phase1", {}).get("model", "llama3.1:70b")

                    # Check if this section uses SPI pipeline
                    if phase_config.get("pipeline") == "spi":
                        # SPI Pipeline: Run 11 focused category extractions
                        yield send_progress("phase1", section_id, "Running Semantic Password Intelligence...")

                        # Ensure model is loaded
                        if current_model is None or current_model != phase1_model:
                            yield send_model_loading(phase1_model, "Loading")
                            load_start = time.time()
                            if not client.ensure_model_loaded(phase1_model, num_ctx=16384):
                                yield send_error(f"Failed to load model {phase1_model}")
                                return
                            load_time = time.time() - load_start
                            current_model = phase1_model
                            yield send_model_loading(phase1_model, f"Ready ({load_time:.1f}s)")

                        # Initialize SPI analyzer with UI-configured sampling
                        # (spi_max_passwords and spi_intelligent_sampling already parsed from request.args above)

                        # Convert max_passwords: None if 0 or empty, otherwise int
                        try:
                            max_pw = int(spi_max_passwords) if spi_max_passwords else 500
                            max_pw = None if max_pw == 0 else max_pw
                        except ValueError:
                            max_pw = 500  # Fallback to default

                        spi_analyzer = SPIAnalyzer(
                            session_dir,
                            max_passwords=max_pw,
                            intelligent_sampling=spi_intelligent_sampling
                        )
                        passwords, sampling_used, sampling_note = spi_analyzer.get_passwords_for_analysis()

                        if not passwords:
                            all_phase1_results[section_id] = {
                                "content": "No passwords available for analysis",
                                "model": phase1_model,
                                "temperature": 0.2,
                                "time": 0,
                                "tokens": 0,
                                "spi_pipeline": True
                            }
                            yield send_step_complete("phase1", section_id, 0, 0, 0, 0)
                            continue

                        # Run each SPI category
                        from app.spi_analyzer import SPIResults, SPICategoryResult
                        spi_result = SPIResults(
                            total_passwords=len(spi_analyzer._get_password_set()),
                            sampling_used=sampling_used,
                            sampling_note=sampling_note
                        )

                        category_keys = get_spi_category_keys()
                        total_spi_time = 0
                        total_spi_tokens = 0
                        total_prompt_tokens = 0
                        total_completion_tokens = 0

                        phase1_temp = phase_config.get("phase1", {}).get("temperature", 0.2)

                        for i, category_key in enumerate(category_keys):
                            category_name = get_spi_category_name(category_key)
                            # Use substep progress to avoid incrementing step counter for each category
                            yield send_substep_progress("phase1", section_id, f"Analyzing {category_name} ({i+1}/{len(category_keys)})...")

                            start = time.time()

                            # Create LLM call function that uses our client with token tracking
                            def llm_call(prompt):
                                nonlocal total_spi_tokens, total_prompt_tokens, total_completion_tokens
                                result = client.generate(
                                    prompt=prompt,
                                    model=phase1_model,
                                    temperature=phase1_temp,
                                    include_usage=True
                                )
                                if isinstance(result, dict):
                                    total_prompt_tokens += result.get("prompt_tokens", 0)
                                    total_completion_tokens += result.get("completion_tokens", 0)
                                    total_spi_tokens += result.get("total_tokens", 0)
                                    return result.get("response", "")
                                return result if result else ""

                            # Analyze this category
                            cat_result = spi_analyzer.analyze_category(
                                category_key, passwords, llm_call
                            )
                            spi_result.categories[category_key] = cat_result

                            cat_elapsed = time.time() - start
                            total_spi_time += cat_elapsed

                            # Log category result
                            match_count = len(cat_result.matches)
                            logging.info(f"SPI {category_key}: {match_count} matches in {cat_elapsed:.1f}s")

                        # Generate formatted HTML report from SPI results
                        spi_html = spi_analyzer.format_report_html(spi_result)

                        # Store SPI results for later use
                        spi_results[section_id] = spi_results_to_dict(spi_result)

                        all_phase1_results[section_id] = {
                            "content": spi_html,
                            "model": phase1_model,
                            "temperature": phase1_temp,
                            "time": total_spi_time,
                            "tokens": total_spi_tokens,
                            "prompt_tokens": total_prompt_tokens,
                            "completion_tokens": total_completion_tokens,
                            "spi_pipeline": True,
                            "spi_categories_analyzed": len(category_keys)
                        }

                        if runner.debug_mode:
                            runner._save_debug_output(section_id, "spi_results", spi_results[section_id])
                            runner._save_debug_output(section_id, "phase1_raw", spi_html)

                        total_time += total_spi_time
                        yield send_step_complete(
                            "phase1", section_id, total_spi_time,
                            total_prompt_tokens, total_completion_tokens, total_spi_tokens
                        )
                        continue

                    # Check if this section uses Company Intel pipeline
                    elif phase_config.get("pipeline") == "company_intel":
                        # Company Intel Pipeline: Run 3 focused category extractions
                        yield send_progress("phase1", section_id, "Running Company Intelligence Analysis...")

                        # Ensure model is loaded
                        if current_model is None or current_model != phase1_model:
                            yield send_model_loading(phase1_model, "Loading")
                            load_start = time.time()
                            if not client.ensure_model_loaded(phase1_model, num_ctx=16384):
                                yield send_error(f"Failed to load model {phase1_model}")
                                return
                            load_time = time.time() - load_start
                            current_model = phase1_model
                            yield send_model_loading(phase1_model, f"Ready ({load_time:.1f}s)")

                        # Initialize CI analyzer with UI-configured sampling
                        try:
                            ci_max_pw = int(ci_max_passwords) if ci_max_passwords else 500
                            ci_max_pw = None if ci_max_pw == 0 else ci_max_pw
                        except ValueError:
                            ci_max_pw = 500  # Fallback to default

                        ci_analyzer = CIAnalyzer(
                            session_dir,
                            max_passwords=ci_max_pw,
                            intelligent_sampling=ci_intelligent_sampling
                        )
                        passwords, accounts, _, _ = ci_analyzer.get_data_for_analysis()

                        if not passwords and not accounts:
                            all_phase1_results[section_id] = {
                                "content": "No data available for Company Intelligence analysis",
                                "model": phase1_model,
                                "temperature": 0.3,
                                "time": 0,
                                "tokens": 0,
                                "ci_pipeline": True
                            }
                            yield send_step_complete("phase1", section_id, 0, 0, 0, 0)
                            continue

                        # Run each CI category
                        from app.company_intel_analyzer import CIResults, CICategoryResult
                        ci_result = CIResults(
                            total_passwords=len(ci_analyzer._get_password_counts()),
                            total_accounts=len(ci_analyzer._get_account_list())
                        )

                        category_keys = get_ci_category_keys()
                        total_ci_time = 0
                        total_ci_tokens = 0
                        total_prompt_tokens = 0
                        total_completion_tokens = 0

                        phase1_temp = phase_config.get("phase1", {}).get("temperature", 0.3)

                        for i, category_key in enumerate(category_keys):
                            category_name = get_ci_category_name(category_key)
                            # Use substep progress to avoid incrementing step counter for each category
                            yield send_substep_progress("phase1", section_id, f"Analyzing {category_name} ({i+1}/{len(category_keys)})...")

                            start = time.time()

                            # Create LLM call function that uses our client with token tracking
                            def llm_call_ci(prompt):
                                nonlocal total_ci_tokens, total_prompt_tokens, total_completion_tokens
                                result = client.generate(
                                    prompt=prompt,
                                    model=phase1_model,
                                    temperature=phase1_temp,
                                    include_usage=True
                                )
                                if isinstance(result, dict):
                                    total_prompt_tokens += result.get("prompt_tokens", 0)
                                    total_completion_tokens += result.get("completion_tokens", 0)
                                    total_ci_tokens += result.get("total_tokens", 0)
                                    return result.get("response", "")
                                return result if result else ""

                            # Analyze this category
                            cat_result = ci_analyzer.analyze_category(
                                category_key, passwords, accounts, llm_call_ci
                            )
                            ci_result.categories[category_key] = cat_result

                            cat_elapsed = time.time() - start
                            total_ci_time += cat_elapsed

                            # Log category result
                            finding_count = len(cat_result.findings)
                            logging.info(f"CI {category_key}: {finding_count} findings in {cat_elapsed:.1f}s")

                        # Generate formatted markdown report from CI results
                        ci_markdown = ci_analyzer.format_report_markdown(ci_result)

                        # Store CI results for later use
                        ci_results = ci_results_to_dict(ci_result)

                        all_phase1_results[section_id] = {
                            "content": ci_markdown,
                            "model": phase1_model,
                            "temperature": phase1_temp,
                            "time": total_ci_time,
                            "tokens": total_ci_tokens,
                            "prompt_tokens": total_prompt_tokens,
                            "completion_tokens": total_completion_tokens,
                            "ci_pipeline": True,
                            "ci_categories_analyzed": len(category_keys)
                        }

                        if runner.debug_mode:
                            runner._save_debug_output(section_id, "ci_results", ci_results)
                            runner._save_debug_output(section_id, "phase1_raw", ci_markdown)

                        total_time += total_ci_time
                        yield send_step_complete(
                            "phase1", section_id, total_ci_time,
                            total_prompt_tokens, total_completion_tokens, total_ci_tokens
                        )
                        continue

                    # Check if this section uses Description LLM pipeline
                    elif phase_config.get("pipeline") == "description_llm":
                        # Description LLM Pipeline: Chunked analysis of AD account descriptions
                        yield send_progress("phase1", section_id, "Running AI Description Analysis...")

                        # Ensure model is loaded
                        if current_model is None or current_model != phase1_model:
                            yield send_model_loading(phase1_model, "Loading")
                            load_start = time.time()
                            if not client.ensure_model_loaded(phase1_model, num_ctx=16384):
                                yield send_error(f"Failed to load model {phase1_model}")
                                return
                            load_time = time.time() - load_start
                            current_model = phase1_model
                            yield send_model_loading(phase1_model, f"Ready ({load_time:.1f}s)")

                        # Initialize Description LLM analyzer
                        from app.description_llm_analyzer import DescriptionLLMAnalyzer
                        from app.description_llm_prompts import DA_PREAMBLE, get_all_category_keys as get_da_category_keys

                        # Get chunk size from request args (default 100)
                        da_chunk_size_str = request.args.get("da_chunk_size", "100")
                        try:
                            da_chunk_size = int(da_chunk_size_str) if da_chunk_size_str else 100
                        except ValueError:
                            da_chunk_size = 100

                        da_analyzer = DescriptionLLMAnalyzer(session_dir, chunk_size=da_chunk_size)
                        users_with_desc = da_analyzer.get_users_with_descriptions()

                        if not users_with_desc:
                            all_phase1_results[section_id] = {
                                "content": "No accounts with descriptions found for analysis",
                                "model": phase1_model,
                                "temperature": 0.1,
                                "time": 0,
                                "tokens": 0,
                                "da_pipeline": True
                            }
                            yield send_step_complete("phase1", section_id, 0, 0, 0, 0)
                            continue

                        # Run Description LLM analysis
                        phase1_temp = temperatures.get(section_id, phase_config.get("phase1", {}).get("temperature", 0.1))
                        total_da_time = 0
                        total_da_tokens = 0
                        total_prompt_tokens = 0
                        total_completion_tokens = 0

                        def llm_call_da(prompt):
                            nonlocal total_prompt_tokens, total_completion_tokens, total_da_tokens
                            result = client.generate(
                                prompt=prompt,
                                model=phase1_model,
                                system=DA_PREAMBLE,
                                temperature=phase1_temp,
                                include_usage=True
                            )
                            if isinstance(result, dict):
                                total_prompt_tokens += result.get("prompt_tokens", 0)
                                total_completion_tokens += result.get("completion_tokens", 0)
                                total_da_tokens += result.get("total_tokens", 0)
                                return result.get("response", "")
                            return result if result else ""

                        # Run full analysis across all categories
                        start = time.time()
                        da_results = da_analyzer.run_full_analysis(
                            llm_call_fn=llm_call_da,
                            model_name=phase1_model,
                            temperature=phase1_temp
                        )
                        total_da_time = time.time() - start

                        # Generate formatted HTML report
                        da_html = da_analyzer.format_report_html(da_results)

                        all_phase1_results[section_id] = {
                            "content": da_html,
                            "model": phase1_model,
                            "temperature": phase1_temp,
                            "time": total_da_time,
                            "tokens": total_da_tokens,
                            "prompt_tokens": total_prompt_tokens,
                            "completion_tokens": total_completion_tokens,
                            "da_pipeline": True,
                            "da_accounts_analyzed": da_results.accounts_analyzed,
                            "da_findings": da_results.total_findings,
                            "da_chunks": da_results.total_chunks
                        }

                        if runner.debug_mode:
                            runner._save_debug_output(section_id, "da_results", da_results.to_dict())
                            runner._save_debug_output(section_id, "phase1_raw", da_html)

                        total_time += total_da_time
                        yield send_step_complete(
                            "phase1", section_id, total_da_time,
                            total_prompt_tokens, total_completion_tokens, total_da_tokens
                        )
                        continue

                    # Standard pipeline: single LLM call
                    # Check if we need to switch models
                    if current_model is None or current_model != phase1_model:
                        yield send_model_loading(phase1_model, "Loading")
                        load_start = time.time()

                        # Ensure model is loaded before proceeding
                        if not client.ensure_model_loaded(phase1_model, num_ctx=16384):
                            yield send_error(f"Failed to load model {phase1_model}")
                            return

                        load_time = time.time() - load_start
                        current_model = phase1_model
                        yield send_model_loading(phase1_model, f"Ready ({load_time:.1f}s)")

                    data = loader.load_section_data(section_id)

                    yield send_progress("phase1", section_id, f"Generating {section_id}...")

                    start = time.time()
                    analyzer = AIReportAnalyzer(client=client)

                    phase1_temp = phase_config.get("phase1", {}).get("temperature", 0.3)

                    result = analyzer.generate_section_with_usage(
                        section_id=section_id,
                        data=data,
                        model=phase1_model,
                        temperature=phase1_temp
                    )

                    elapsed = time.time() - start
                    total_time += elapsed

                    if result and isinstance(result, dict):
                        all_phase1_results[section_id] = {
                            "content": result.get("response", ""),
                            "model": phase1_model,
                            "temperature": phase1_temp,
                            "time": elapsed,
                            "tokens": result.get("total_tokens", 0),
                            "prompt_tokens": result.get("prompt_tokens", 0),
                            "completion_tokens": result.get("completion_tokens", 0)
                        }

                        if runner.debug_mode and all_phase1_results[section_id]["content"]:
                            runner._save_debug_output(section_id, "phase1_raw", all_phase1_results[section_id]["content"])

                        # Send step complete event with token info
                        yield send_step_complete(
                            "phase1", section_id, elapsed,
                            result.get("prompt_tokens", 0),
                            result.get("completion_tokens", 0),
                            result.get("total_tokens", 0)
                        )
                    else:
                        all_phase1_results[section_id] = {
                            "content": "",
                            "model": phase1_model,
                            "temperature": phase1_temp,
                            "time": elapsed,
                            "tokens": 0,
                            "error": "Generation failed"
                        }
                        yield send_step_complete("phase1", section_id, elapsed, 0, 0, 0)

            # PHASE 2: Validate all sections (with Tier-0 gating)
            # Model loading is now dynamic based on Tier-0 routing decisions
            for section_id in ordered_sections:
                phase_config = get_phase_config(section_id)
                phase2_config = phase_config.get("phase2", {})

                if not phase2_config.get("enabled", True):
                    all_phase2_results[section_id] = {
                        "corrected_content": all_phase1_results.get(section_id, {}).get("content", ""),
                        "issues": [],
                        "confidence": 1.0,
                        "needs_human_review": False,
                        "skipped": True,
                        "time": 0
                    }
                    step_counter += 1
                    yield f"data: {json.dumps({'type': 'progress', 'total_steps': total_steps, 'current_step': step_counter, 'current_phase': 'phase2', 'current_section': section_id, 'current_action': f'Validated by Python', 'elapsed_seconds': round(time.time() - start_time, 1), 'percent_complete': round(step_counter / total_steps * 100, 1)})}\n\n"
                    # Send step_complete with python indicator (validation done by Python, not LLM)
                    yield send_step_complete("phase2", section_id, 0, 0, 0, 0, tier0_result="python")
                    continue

                phase1_content = all_phase1_results.get(section_id, {}).get("content", "")
                if not phase1_content:
                    all_phase2_results[section_id] = {
                        "corrected_content": "",
                        "issues": [],
                        "confidence": 0,
                        "needs_human_review": True,
                        "skipped": False,
                        "time": 0,
                        "error": "No Phase 1 content"
                    }
                    step_counter += 1
                    yield f"data: {json.dumps({'type': 'progress', 'total_steps': total_steps, 'current_step': step_counter, 'current_phase': 'phase2', 'current_section': section_id, 'current_action': f'No content to validate for {section_id}', 'elapsed_seconds': round(time.time() - start_time, 1), 'percent_complete': round(step_counter / total_steps * 100, 1)})}\n\n"
                    continue

                # Run Tier-0 prechecks (fast, deterministic)
                tier0_result = runner.tier0_validator.run_prechecks(phase1_content, section_id)

                if runner.debug_mode:
                    runner._save_debug_output(section_id, "tier0_precheck", {
                        "flags_fired": tier0_result.flags_fired,
                        "requires_llm": tier0_result.requires_llm_validation,
                        "suggested_model": tier0_result.suggested_model,
                        "skip_reason": tier0_result.skip_reason,
                        "extracted_claims_count": len(tier0_result.extracted_claims)
                    })

                if not tier0_result.requires_llm_validation:
                    # Clean content - skip LLM validation entirely
                    yield send_progress("phase2", section_id, f"Skipping validation (clean)")

                    all_phase2_results[section_id] = {
                        "corrected_content": phase1_content,
                        "issues": [],
                        "confidence": 0.95,
                        "needs_human_review": False,
                        "validation_stats": {
                            "tier0_skipped": True,
                            "skip_reason": tier0_result.skip_reason
                        },
                        "time": 0,
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                        "tier0_result": "skipped"
                    }

                    yield send_step_complete("phase2", section_id, 0, 0, 0, 0, tier0_result="skipped")
                    continue

                # Tier-0 flagged issues - determine model and run validation
                validation_model = tier0_result.suggested_model or phase2_config.get("model", "deepseek-r1:671b")
                model_label = "fast" if validation_model == "llama3.1:70b" else "deep"

                yield send_progress("phase2", section_id, f"Validating {section_id} ({model_label})...")

                # Load the appropriate model if needed
                if current_model != validation_model:
                    yield send_model_loading(validation_model, "Loading")
                    load_start = time.time()
                    if not client.ensure_model_loaded(validation_model, num_ctx=16384):
                        yield send_error(f"Failed to load model {validation_model}")
                        return
                    load_time = time.time() - load_start
                    current_model = validation_model
                    yield send_model_loading(validation_model, f"Ready ({load_time:.1f}s)")

                start = time.time()

                # For sections with extracted claims, use focused validation
                if tier0_result.extracted_claims:
                    validation = runner._run_claim_validation(
                        section_id=section_id,
                        phase1_content=phase1_content,
                        claims=tier0_result.extracted_claims,
                        model=validation_model,
                        temperature=phase2_config.get("temperature", 0.2)
                    )
                else:
                    validation = runner._run_validation_phase(
                        section_id=section_id,
                        phase1_content=phase1_content,
                        model=validation_model,
                        temperature=phase2_config.get("temperature", 0.2)
                    )

                elapsed = time.time() - start
                total_time += elapsed

                # Add Tier-0 context to validation stats
                validation_stats = validation.validation_stats.copy() if validation.validation_stats else {}
                validation_stats["tier0_flags"] = tier0_result.flags_fired
                validation_stats["tier0_model_suggestion"] = tier0_result.suggested_model
                validation_stats["actual_model_used"] = validation_model

                all_phase2_results[section_id] = {
                    "corrected_content": validation.corrected_content,
                    "issues": validation.issues,
                    "confidence": validation.confidence,
                    "needs_human_review": validation.needs_human_review,
                    "validation_stats": validation_stats,
                    "time": elapsed,
                    "prompt_tokens": getattr(validation, 'prompt_tokens', 0),
                    "completion_tokens": getattr(validation, 'completion_tokens', 0),
                    "total_tokens": getattr(validation, 'total_tokens', 0),
                    "tier0_result": model_label
                }

                if runner.debug_mode:
                    runner._save_debug_output(section_id, "phase2_validated", validation)

                # Send step complete event
                yield send_step_complete(
                    "phase2", section_id, elapsed,
                    getattr(validation, 'prompt_tokens', 0),
                    getattr(validation, 'completion_tokens', 0),
                    getattr(validation, 'total_tokens', 0),
                    tier0_result=model_label
                )

            # PHASE 3: Format all sections
            # All Phase 3 uses llama3.1:70b - ensure it's loaded once at start
            phase3_model = "llama3.1:70b"
            if current_model != phase3_model:
                yield send_model_loading(phase3_model, "Loading")
                load_start = time.time()
                if not client.ensure_model_loaded(phase3_model, num_ctx=16384):
                    yield send_error(f"Failed to load model {phase3_model}")
                    return
                load_time = time.time() - load_start
                current_model = phase3_model
                yield send_model_loading(phase3_model, f"Ready ({load_time:.1f}s)")

            for section_id in ordered_sections:
                phase_config = get_phase_config(section_id)
                phase3_config = phase_config.get("phase3", {})

                if not phase3_config.get("enabled", True):
                    final_content = all_phase2_results.get(section_id, {}).get("corrected_content", "")
                    results[section_id] = {
                        "content": final_content,
                        "needs_human_review": all_phase2_results.get(section_id, {}).get("needs_human_review", False),
                        "validation_issues": 0,
                        "validation_confidence": 1.0,
                        "timing": {
                            "phase1": all_phase1_results.get(section_id, {}).get("time", 0),
                            "phase2": all_phase2_results.get(section_id, {}).get("time", 0),
                            "phase3": 0
                        }
                    }
                    step_counter += 1
                    yield f"data: {json.dumps({'type': 'progress', 'total_steps': total_steps, 'current_step': step_counter, 'current_phase': 'phase3', 'current_section': section_id, 'current_action': f'Skipped formatting for {section_id}', 'elapsed_seconds': round(time.time() - start_time, 1), 'percent_complete': round(step_counter / total_steps * 100, 1)})}\n\n"
                    continue

                validated_content = all_phase2_results.get(section_id, {}).get("corrected_content", "")
                if not validated_content:
                    results[section_id] = {
                        "content": "",
                        "needs_human_review": True,
                        "validation_issues": 0,
                        "validation_confidence": 0,
                        "timing": {"phase1": 0, "phase2": 0, "phase3": 0},
                        "error": "No validated content"
                    }
                    step_counter += 1
                    yield f"data: {json.dumps({'type': 'progress', 'total_steps': total_steps, 'current_step': step_counter, 'current_phase': 'phase3', 'current_section': section_id, 'current_action': f'No content to format for {section_id}', 'elapsed_seconds': round(time.time() - start_time, 1), 'percent_complete': round(step_counter / total_steps * 100, 1)})}\n\n"
                    continue

                yield send_progress("phase3", section_id, f"Formatting {section_id}...")

                start = time.time()
                format_result = runner._run_formatting_phase(
                    validated_content=validated_content,
                    model=phase3_config.get("model", "llama3.1:70b"),
                    temperature=phase3_config.get("temperature", 0.15)
                )
                elapsed = time.time() - start
                total_time += elapsed

                # Extract content and tokens from result
                final_content = format_result.get("content", validated_content)
                phase3_prompt_tokens = format_result.get("prompt_tokens", 0)
                phase3_completion_tokens = format_result.get("completion_tokens", 0)
                phase3_total_tokens = format_result.get("total_tokens", 0)

                if runner.debug_mode and final_content:
                    runner._save_debug_output(section_id, "phase3_final", final_content)

                results[section_id] = {
                    "content": final_content,
                    "needs_human_review": all_phase2_results.get(section_id, {}).get("needs_human_review", False),
                    "validation_issues": len(all_phase2_results.get(section_id, {}).get("issues", [])),
                    "validation_confidence": all_phase2_results.get(section_id, {}).get("confidence", 1.0),
                    "timing": {
                        "phase1": all_phase1_results.get(section_id, {}).get("time", 0),
                        "phase2": all_phase2_results.get(section_id, {}).get("time", 0),
                        "phase3": elapsed
                    }
                }

                # Send step complete event with token info
                yield send_step_complete("phase3", section_id, elapsed, phase3_prompt_tokens, phase3_completion_tokens, phase3_total_tokens)

            # Save results to aaia_results.json
            # Include all fields needed by displayAAIAResults for proper reload
            aaia_output = {
                "results": {
                    section_id: {
                        "content": data.get("content", ""),
                        "time": str(round(sum(data.get("timing", {}).values()), 1)) + "s",
                        "needs_human_review": data.get("needs_human_review", False),
                        "validation_confidence": data.get("validation_confidence", 1.0),
                        "validation_issues": data.get("validation_issues", 0),
                        "timing": data.get("timing", {})
                    }
                    for section_id, data in results.items()
                },
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "pipeline_version": "3-phase",
                    "total_time_seconds": round(total_time, 1),
                    "server_id": server_id,
                    "sections": {
                        section_id: {
                            "model": all_phase1_results.get(section_id, {}).get("model", ""),
                            "server": server_id
                        }
                        for section_id, data in results.items()
                    }
                }
            }

            # Save to current session
            session_mgr = get_session_manager()
            session_mgr.save_session_data("aaia_results.json", aaia_output)

            # Mark AAIA as generated for this session
            current = session_mgr.get_current_session()
            if current:
                session_mgr.mark_aaia_generated(current.get("session_id"))

            # Send final complete event with results
            complete_data = {
                "type": "complete",
                "success": True,
                "results": results,
                "total_time_seconds": round(total_time, 1),
                "sections_processed": len(results),
                "any_needs_review": any(r.get("needs_human_review", False) for r in results.values())
            }
            yield f"data: {json.dumps(complete_data)}\n\n"

        except Exception as e:
            logging.error(f"Pipeline error: {e}")
            import traceback
            traceback.print_exc()
            yield send_error(str(e))

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'  # Disable nginx buffering
        }
    )


@app.route("/api/ai/report/cache", methods=["GET"])
@login_required
def ai_report_get_cache() -> Response:
    """Get cached AI report analyses from session."""
    cache = session.get("ai_report_cache", {})
    return jsonify({"cache": cache})


@app.route("/api/ai/report/cache/<section_id>", methods=["DELETE"])
@login_required
def ai_report_clear_section_cache(section_id: str) -> Response:
    """Clear cached analysis for a specific section."""
    if "ai_report_cache" in session and section_id in session["ai_report_cache"]:
        del session["ai_report_cache"][section_id]
        session.modified = True
    return jsonify({"success": True})


@app.route("/api/ai/report/cache", methods=["DELETE"])
@login_required
def ai_report_clear_all_cache() -> Response:
    """Clear all cached AI report analyses."""
    session["ai_report_cache"] = {}
    session.modified = True
    return jsonify({"success": True})


# ============================================================================
# Session Management Endpoints
# ============================================================================

@app.route("/api/sessions", methods=["GET"])
@login_required
def list_sessions() -> Response:
    """
    List sessions based on user role:
    - Superadmin: sees all sessions
    - Admin: sees own sessions + other users' non-private sessions
    - Regular user: sees only own sessions
    """
    session_mgr = get_session_manager()

    if current_user.is_superadmin:
        # Superadmin can see all sessions
        sessions = session_mgr.list_sessions(username=None)
        grouped = session_mgr.get_sessions_grouped_by_company(username=None)
    elif current_user.is_admin:
        # Admin can see own sessions + other non-private sessions
        sessions = session_mgr.list_sessions(
            username=current_user.id,
            include_non_private=True
        )
        grouped = session_mgr.get_sessions_grouped_by_company(username=None)
        # Filter grouped to match same visibility rules
        for company in list(grouped.keys()):
            grouped[company] = [
                s for s in grouped[company]
                if s.created_by == current_user.id or not s.private
            ]
            if not grouped[company]:
                del grouped[company]
    else:
        # Regular user sees only own sessions
        sessions = session_mgr.list_sessions(username=current_user.id)
        grouped = session_mgr.get_sessions_grouped_by_company(username=current_user.id)

    current = session_mgr.get_current_session()
    current_id = current.get("session_id") if current else None

    return jsonify({
        "sessions": [s.to_dict() for s in sessions],
        "sessions_by_company": {
            company: [s.to_dict() for s in company_sessions]
            for company, company_sessions in grouped.items()
        },
        "current_session_id": current_id
    })


@app.route("/api/sessions/companies", methods=["GET"])
@login_required
def get_company_suggestions() -> Response:
    """Get list of company names for autocomplete."""
    session_mgr = get_session_manager()
    partial = request.args.get("q", "")
    # Superadmin can see all companies
    username_filter = None if current_user.is_superadmin else current_user.id
    companies = session_mgr.get_company_suggestions(
        partial=partial,
        username=username_filter
    )
    return jsonify({"companies": companies})


@app.route("/api/sessions/current", methods=["GET"])
@login_required
def get_current_session_info() -> Response:
    """Get information about the current session."""
    session_mgr = get_session_manager()
    current = session_mgr.get_current_session()

    if not current:
        return jsonify({"error": "No active session"}), 404

    metadata = session_mgr.get_session(current.get("session_id"))
    if not metadata:
        return jsonify({"error": "Session not found"}), 404

    # Include staleness info
    staleness = session_mgr.check_aaia_staleness()

    return jsonify({
        "session": metadata.to_dict(),
        "aaia_staleness": staleness
    })


def _can_access_session(metadata, write_access: bool = False) -> bool:
    """
    Check if current user can access a session.

    Args:
        metadata: SessionMetadata object
        write_access: If True, check for write/delete permission (owner/superadmin only)
                      If False, check for read-only permission (includes admin for non-private)

    Returns:
        True if access is allowed
    """
    # Owner always has access
    if metadata.created_by == current_user.id:
        return True
    # Superadmin has access to everything
    if current_user.is_superadmin:
        return True
    # For write access, only owner and superadmin are allowed
    if write_access:
        return False
    # For read access, admin can access non-private sessions
    if current_user.is_admin and not metadata.private:
        return True
    return False


@app.route("/api/sessions", methods=["POST"])
@login_required
def create_session() -> Response:
    """Create a new session."""
    try:
        data = request.get_json() or {}
        name = data.get("name", "").strip()

        if not name:
            return jsonify({"error": "Session name is required"}), 400

        session_mgr = get_session_manager()
        new_session = session_mgr.create_session(
            name=name,
            username=current_user.id
        )

        return jsonify({
            "success": True,
            "session": new_session.to_dict()
        })
    except Exception as e:
        logging.error(f"Error creating session: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/<session_id>", methods=["GET"])
@login_required
def get_session_info(session_id: str) -> Response:
    """Get information about a specific session."""
    session_mgr = get_session_manager()
    metadata = session_mgr.get_session(session_id)

    if not metadata:
        return jsonify({"error": "Session not found"}), 404

    # Check read access (owner, superadmin, or admin for non-private)
    if not _can_access_session(metadata, write_access=False):
        return jsonify({"error": "Access denied"}), 403

    return jsonify({
        "session": metadata.to_dict()
    })


@app.route("/api/sessions/<session_id>", methods=["PUT"])
@login_required
def update_session_info(session_id: str) -> Response:
    """Update session metadata (name, notes)."""
    try:
        session_mgr = get_session_manager()
        metadata = session_mgr.get_session(session_id)

        if not metadata:
            return jsonify({"error": "Session not found"}), 404

        # Write access required for updates (owner or superadmin only)
        if not _can_access_session(metadata, write_access=True):
            return jsonify({"error": "Access denied"}), 403

        data = request.get_json() or {}

        # Only allow updating specific fields
        updates = {}
        if "name" in data:
            updates["name"] = data["name"].strip()
        if "notes" in data:
            updates["notes"] = data["notes"]
        if "private" in data:
            updates["private"] = bool(data["private"])

        if updates:
            updated = session_mgr.update_session(session_id, **updates)
            return jsonify({
                "success": True,
                "session": updated.to_dict() if updated else None
            })

        return jsonify({"success": True, "session": metadata.to_dict()})
    except Exception as e:
        logging.error(f"Error updating session: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/<session_id>", methods=["DELETE"])
@login_required
def delete_session_endpoint(session_id: str) -> Response:
    """Delete a session."""
    try:
        session_mgr = get_session_manager()
        metadata = session_mgr.get_session(session_id)

        if not metadata:
            return jsonify({"error": "Session not found"}), 404

        # Write access required for deletion (owner or superadmin only)
        if not _can_access_session(metadata, write_access=True):
            return jsonify({"error": "Access denied"}), 403

        success = session_mgr.delete_session(session_id)
        return jsonify({
            "success": success,
            "message": "Session deleted" if success else "Failed to delete session"
        })
    except Exception as e:
        logging.error(f"Error deleting session: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/<session_id>/switch", methods=["POST"])
@login_required
def switch_to_session(session_id: str) -> Response:
    """Switch to a different session."""
    try:
        session_mgr = get_session_manager()
        metadata = session_mgr.get_session(session_id)

        if not metadata:
            return jsonify({"error": "Session not found"}), 404

        # Check read access (owner, superadmin, or admin for non-private)
        if not _can_access_session(metadata, write_access=False):
            return jsonify({"error": "Access denied"}), 403

        success = session_mgr.set_current_session(session_id, current_user.id)

        # Load and restore analysis_options from the session
        if success:
            saved_options = session_mgr.load_session_data("analysis_options.json", session_id)
            if saved_options:
                session["analysis_options"] = saved_options

        return jsonify({
            "success": success,
            "session": metadata.to_dict() if success else None
        })
    except Exception as e:
        logging.error(f"Error switching session: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/trend-analysis", methods=["POST"])
@login_required
def analyze_session_trends() -> Response:
    """
    Analyze trends across multiple sessions.

    Request body:
        {
            "session_ids": ["abc123", "def456", ...]  // At least 2 sessions
        }

    Returns trend comparison with metrics, changes, and chart data.
    """
    try:
        from app.trend_analysis import TrendAnalyzer

        data = request.get_json() or {}
        session_ids = data.get("session_ids", [])

        if len(session_ids) < 2:
            return jsonify({
                "error": "At least 2 sessions are required for trend analysis"
            }), 400

        session_mgr = get_session_manager()

        # Verify all sessions belong to current user (or user is superadmin)
        for sid in session_ids:
            metadata = session_mgr.get_session(sid)
            if not metadata:
                return jsonify({"error": f"Session not found: {sid}"}), 404
            if metadata.created_by != current_user.id and not current_user.is_superadmin:
                return jsonify({"error": "Access denied to one or more sessions"}), 403

        # Perform trend analysis
        analyzer = TrendAnalyzer(session_mgr)
        comparison = analyzer.compare_sessions(session_ids)

        if not comparison:
            return jsonify({
                "error": "Could not analyze sessions - insufficient data"
            }), 400

        return jsonify({
            "success": True,
            "analysis": analyzer.to_dict(comparison)
        })

    except Exception as e:
        logging.error(f"Error analyzing trends: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/by-company/<company_name>", methods=["GET"])
@login_required
def get_sessions_by_company(company_name: str) -> Response:
    """Get all sessions for a specific company."""
    try:
        session_mgr = get_session_manager()
        # Superadmin can see all sessions
        username_filter = None if current_user.is_superadmin else current_user.id
        sessions = session_mgr.list_sessions_by_company(
            company_name=company_name,
            username=username_filter
        )
        return jsonify({
            "company_name": company_name,
            "sessions": [s.to_dict() for s in sessions],
            "count": len(sessions)
        })
    except Exception as e:
        logging.error(f"Error getting sessions by company: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/migrate-legacy", methods=["POST"])
@login_required
def migrate_legacy_data() -> Response:
    """
    Migrate legacy data from data/ folder to a new session.
    Useful for upgrading from pre-session installations.
    """
    try:
        data = request.get_json() or {}
        name = data.get("name", "").strip() or "Migrated Analysis"

        session_mgr = get_session_manager()

        # Check if legacy data exists
        legacy_stats = os.path.join("data", "cracking_stats_table.json")
        if not os.path.exists(legacy_stats):
            return jsonify({"error": "No legacy data found to migrate"}), 404

        # Create new session
        new_session = session_mgr.create_session(
            name=name,
            username=current_user.id
        )

        # Migrate files
        success = session_mgr.migrate_legacy_data_to_session(new_session.session_id)

        if success:
            # Set as current session
            session_mgr.set_current_session(new_session.session_id, current_user.id)

            # Try to update stats from migrated data
            stats = session_mgr.load_session_data("cracking_stats_table.json", new_session.session_id)
            if stats:
                # Parse stats from the key-value format
                stats_dict = {item["key"]: item["value"] for item in stats} if isinstance(stats, list) else {}
                total_str = stats_dict.get("Total Accounts Analyzed: ", "0")
                cracked_str = stats_dict.get("Cracked Accounts: ", "0")
                try:
                    total = int(total_str.replace(",", ""))
                    cracked = int(cracked_str.split()[0].replace(",", ""))
                    crack_rate = (cracked / total * 100) if total > 0 else 0.0
                    session_mgr.update_session(
                        new_session.session_id,
                        total_accounts=total,
                        cracked_accounts=cracked,
                        crack_rate=round(crack_rate, 2)
                    )
                except (ValueError, IndexError):
                    pass

            return jsonify({
                "success": True,
                "session": session_mgr.get_session(new_session.session_id).to_dict()
            })

        return jsonify({"error": "Migration failed"}), 500
    except Exception as e:
        logging.error(f"Error migrating legacy data: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/check-duplicate", methods=["POST"])
@login_required
def check_duplicate_session() -> Response:
    """
    Check if source files match any existing session.
    Used before processing to warn users about potential duplicates.

    Expects JSON body with either:
    - pwdump_path and potfile_path (for local files)
    - validation data in Flask session (for uploaded files)
    """
    try:
        session_mgr = get_session_manager()
        data = request.get_json() or {}

        # Try to compute source hash from provided paths or session data
        source_hash = None

        if data.get("pwdump_path") and data.get("potfile_path"):
            # Local file paths provided
            source_hash = session_mgr.compute_source_hash(
                pwdump_path=data["pwdump_path"],
                potfile_path=data["potfile_path"]
            )
        else:
            # Try to use validation data from Flask session
            pwdump_data = session.get("pwdump_validation")
            if pwdump_data and pwdump_data.get("lines"):
                # Build minimal account data for hashing
                account_data = []
                for line in pwdump_data.get("lines", []):
                    if line.get("is_valid") and line.get("username") and line.get("ntlm_hash"):
                        account_data.append({
                            "username": line["username"],
                            "ntlm_hash": line["ntlm_hash"]
                        })
                if account_data:
                    source_hash = session_mgr.compute_source_hash(account_data=account_data)

        if not source_hash:
            return jsonify({"error": "Could not compute source hash"}), 400

        # Check all user's sessions for matching hash (superadmin sees all)
        username_filter = None if current_user.is_superadmin else current_user.id
        sessions = session_mgr.list_sessions(username=username_filter)
        matching_sessions = []

        for sess in sessions:
            if sess.source_hash == source_hash:
                matching_sessions.append({
                    "session_id": sess.session_id,
                    "name": sess.name,
                    "created_at": sess.created_at,
                    "updated_at": sess.updated_at,
                    "total_accounts": sess.total_accounts,
                    "cracked_accounts": sess.cracked_accounts,
                    "crack_rate": sess.crack_rate,
                    "aaia_generated": sess.aaia_generated
                })

        return jsonify({
            "source_hash": source_hash,
            "has_duplicates": len(matching_sessions) > 0,
            "matching_sessions": matching_sessions
        })

    except Exception as e:
        logging.error(f"Error checking for duplicate sessions: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/regenerate-reports", methods=["POST"])
@login_required
def regenerate_session_reports() -> Response:
    """
    Regenerate all analysis reports for the current session.

    This first resyncs with the master potfile to pick up any newly cracked
    passwords, then reprocesses the stored account_data.json to generate any
    new or updated report files.

    Returns:
        JSON with list of regenerated reports and any errors
    """
    try:
        session_mgr = get_session_manager()
        current_session = session_mgr.get_current_session()

        if not current_session:
            return jsonify({"error": "No active session"}), 400

        # Get the session ID from the current session dict
        session_id = current_session.get("session_id")
        if not session_id:
            return jsonify({"error": "Invalid session - no session ID"}), 400

        # Load the stored account data
        account_data = session_mgr.load_session_data("account_data.json")
        if not account_data:
            return jsonify({
                "error": "No account data found in session. Please re-import your data."
            }), 400

        regenerated = []
        errors = []
        potfile_sync_stats = {"new_cracks": 0, "total_cracked": 0}

        # Step 0: Resync with master potfile to pick up newly cracked passwords
        if MASTER_POTFILE_ENABLED and os.path.exists(MASTER_POTFILE_PATH):
            try:
                from app.potfile_cache import get_master_cache
                from app.file_parser import decode_hex_password, BLANK_NTLM_HASH

                # Force reload to get latest potfile entries
                cache = get_master_cache()
                cached_potfile = cache.load(MASTER_POTFILE_PATH, force_reload=True)
                cracked_hashes = cached_potfile.hash_to_password

                # Track changes
                new_cracks = 0
                total_cracked = 0

                # Update each account's cracked_pw based on fresh potfile
                for username, acc in account_data.items():
                    ntlm_hash = acc.get("ntlm_hash")
                    if not ntlm_hash:
                        continue

                    # Check if hash is in potfile (lowercase match)
                    hash_lower = ntlm_hash.lower()
                    old_pw = acc.get("cracked_pw")
                    was_cracked = bool(old_pw and old_pw != "[NOT CRACKED]")

                    if hash_lower in cracked_hashes:
                        new_pw = decode_hex_password(cracked_hashes[hash_lower])
                        acc["cracked_pw"] = new_pw
                        total_cracked += 1
                        if not was_cracked:
                            new_cracks += 1
                    elif hash_lower == BLANK_NTLM_HASH.lower():
                        # Blank password
                        acc["cracked_pw"] = ""
                        total_cracked += 1
                        if not was_cracked:
                            new_cracks += 1

                potfile_sync_stats = {
                    "new_cracks": new_cracks,
                    "total_cracked": total_cracked,
                    "potfile_entries": cached_potfile.ntlm_count
                }

                # Save updated account_data if we found new cracks
                if new_cracks > 0:
                    session_mgr.save_session_data("account_data.json", account_data, session_id)

                    # Update session metadata with new crack statistics
                    metadata = session_mgr.get_session(session_id)
                    if metadata:
                        metadata.cracked_accounts = total_cracked
                        metadata.crack_rate = (total_cracked / metadata.total_accounts * 100) if metadata.total_accounts > 0 else 0.0
                        session_mgr.update_session(session_id, metadata)

                    regenerated.append("account_data.json (potfile resync)")

            except Exception as e:
                errors.append(f"Potfile Resync: {e}")

        # 1. Regenerate Group Membership Report (Top 25)
        try:
            from app import group_membership_analysis

            account_list = []
            for username, acc in account_data.items():
                account_list.append({
                    "sam_account_name": username,
                    "member_of": acc.get("member_of", []),
                    "privilege_level": acc.get("privilege_level", "standard"),
                    "privilege_groups": acc.get("privilege_groups", []),
                    "is_enabled": acc.get("is_enabled", True),
                    "password": acc.get("cracked_pw", "")
                })

            group_report = group_membership_analysis.analyze_group_memberships(
                account_data=account_list,
                top_n=25
            )

            session_mgr.save_session_data(
                "group_membership_report.json",
                group_report.to_dict(),
                session_id
            )
            regenerated.append("group_membership_report.json")
        except Exception as e:
            errors.append(f"Group Membership Report: {e}")

        # 2. Regenerate Group Analysis Data (for Group Explorer)
        try:
            all_groups: set[str] = set()
            group_accounts_data: list[dict] = []

            for username, acc in account_data.items():
                member_of = acc.get("member_of", [])
                if member_of:
                    all_groups.update(member_of)
                    cracked_pw = acc.get("cracked_pw", "")
                    group_accounts_data.append({
                        "sam_account_name": username,
                        "member_of": member_of,
                        "privilege_level": acc.get("privilege_level", "standard"),
                        "privilege_groups": acc.get("privilege_groups", []),
                        "is_enabled": acc.get("is_enabled", True),
                        "is_cracked": bool(cracked_pw and cracked_pw != "[NOT CRACKED]"),
                        "password": cracked_pw if cracked_pw and cracked_pw != "[NOT CRACKED]" else "",
                    })

            sorted_groups = sorted(all_groups, key=str.lower)

            session_mgr.save_session_data(
                "group_analysis_data.json",
                {
                    "groups": sorted_groups,
                    "accounts": group_accounts_data,
                    "total_groups": len(sorted_groups),
                    "total_accounts_with_groups": len(group_accounts_data),
                },
                session_id
            )
            regenerated.append("group_analysis_data.json")
        except Exception as e:
            errors.append(f"Group Analysis Data: {e}")

        # 3. Regenerate Kerberoast Report
        try:
            from app import kerberoast_analysis

            kerberoast_accounts = []
            for username, acc in account_data.items():
                if acc.get("service_principal_names"):
                    kerberoast_accounts.append({
                        "sam_account_name": username,
                        "service_principal_names": acc.get("service_principal_names", []),
                        "privilege_level": acc.get("privilege_level", "standard"),
                        "privilege_groups": acc.get("privilege_groups", []),
                        "is_enabled": acc.get("is_enabled", True),
                        "password": acc.get("cracked_pw", ""),
                        "pwd_last_set": acc.get("pwd_last_set"),
                        "description": acc.get("description", ""),
                    })

            if kerberoast_accounts:
                kerb_report = kerberoast_analysis.analyze_kerberoastable_accounts(
                    account_data=kerberoast_accounts
                )
                session_mgr.save_session_data(
                    "kerberoast_report.json",
                    kerb_report.to_dict(),
                    session_id
                )
                regenerated.append("kerberoast_report.json")
        except Exception as e:
            errors.append(f"Kerberoast Report: {e}")

        # 4. Regenerate AS-REP Report
        try:
            from app import asrep_analysis

            asrep_accounts = []
            for username, acc in account_data.items():
                if acc.get("dont_require_preauth"):
                    asrep_accounts.append({
                        "sam_account_name": username,
                        "privilege_level": acc.get("privilege_level", "standard"),
                        "privilege_groups": acc.get("privilege_groups", []),
                        "is_enabled": acc.get("is_enabled", True),
                        "password": acc.get("cracked_pw", ""),
                        "pwd_last_set": acc.get("pwd_last_set"),
                        "description": acc.get("description", ""),
                    })

            if asrep_accounts:
                asrep_report = asrep_analysis.analyze_asrep_accounts(
                    account_data=asrep_accounts
                )
                session_mgr.save_session_data(
                    "asrep_report.json",
                    asrep_report.to_dict(),
                    session_id
                )
                regenerated.append("asrep_report.json")
        except Exception as e:
            errors.append(f"AS-REP Report: {e}")

        # 5. Regenerate Description Analysis Report
        try:
            from app import description_analysis

            desc_accounts = []
            for username, acc in account_data.items():
                if acc.get("description"):
                    desc_accounts.append({
                        "sam_account_name": username,
                        "description": acc.get("description", ""),
                        "privilege_level": acc.get("privilege_level", "standard"),
                        "is_enabled": acc.get("is_enabled", True),
                        "password": acc.get("cracked_pw", ""),
                    })

            if desc_accounts:
                desc_report = description_analysis.analyze_descriptions(
                    account_data=desc_accounts
                )
                session_mgr.save_session_data(
                    "description_analysis_report.json",
                    desc_report.to_dict(),
                    session_id
                )
                regenerated.append("description_analysis_report.json")
        except Exception as e:
            errors.append(f"Description Analysis Report: {e}")

        # 6. Regenerate Privileged Accounts Report
        # Must match the structure expected by the front-end: tier0, elevated, summary
        try:
            privileged_findings = {
                "tier0": [],
                "elevated": [],
                "summary": {
                    "tier0_count": 0,
                    "elevated_count": 0,
                    "total_privileged": 0,
                    "cracked_tier0": 0,
                    "cracked_privileged": 0
                }
            }

            for username, acc in account_data.items():
                privilege_level = acc.get("privilege_level")
                if privilege_level in ("tier0", "elevated"):
                    cracked_pw = acc.get("cracked_pw", "")
                    is_cracked = bool(cracked_pw and cracked_pw != "[NOT CRACKED]")

                    priv_entry = {
                        "username": username,
                        "rid": acc.get("rid"),
                        "groups": acc.get("privilege_groups", []),
                        "cracked": is_cracked,
                        "password": cracked_pw if is_cracked else None,
                        "disabled": not acc.get("is_enabled", True),
                    }

                    privileged_findings["summary"]["total_privileged"] += 1

                    if privilege_level == "tier0":
                        privileged_findings["tier0"].append(priv_entry)
                        privileged_findings["summary"]["tier0_count"] += 1
                        if is_cracked:
                            privileged_findings["summary"]["cracked_tier0"] += 1
                            privileged_findings["summary"]["cracked_privileged"] += 1
                    else:
                        privileged_findings["elevated"].append(priv_entry)
                        privileged_findings["summary"]["elevated_count"] += 1
                        if is_cracked:
                            privileged_findings["summary"]["cracked_privileged"] += 1

            if privileged_findings["summary"]["total_privileged"] > 0:
                session_mgr.save_session_data(
                    "privileged_accounts.json",
                    privileged_findings,
                    session_id
                )
                regenerated.append("privileged_accounts.json")
        except Exception as e:
            errors.append(f"Privileged Accounts Report: {e}")

        # Build message with potfile sync info
        message_parts = []
        if potfile_sync_stats.get("new_cracks", 0) > 0:
            message_parts.append(f"Found {potfile_sync_stats['new_cracks']} newly cracked passwords")
        message_parts.append(f"Regenerated {len(regenerated)} reports")
        if errors:
            message_parts.append(f"{len(errors)} errors")

        return jsonify({
            "success": True,
            "regenerated": regenerated,
            "regenerated_count": len(regenerated),
            "errors": errors,
            "error_count": len(errors),
            "potfile_sync": potfile_sync_stats,
            "message": " | ".join(message_parts)
        })

    except Exception as e:
        logging.error(f"Error regenerating reports: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================================
# Settings API Endpoints (for report reconfiguration)
# ============================================================================

@app.route("/api/settings/current", methods=["GET"])
@login_required
def get_current_settings() -> Response:
    """Get current analysis settings from session."""
    options = session.get("analysis_options", {})

    # If no options in Flask session, try to load from the current session's saved file
    if not options:
        session_mgr = get_session_manager()
        saved_options = session_mgr.load_session_data("analysis_options.json")
        if saved_options:
            options = saved_options
            # Also restore to Flask session for future use
            session["analysis_options"] = options

    # Return default values if still no options
    if not options:
        options = {
            "policy_min_pw_len": "12",
            "policy_max_pw_age": "90",
            "policy_complexity_req": "3",
            "substring_min_len": "4",
            "substring_max_len": "30",
            "substring_freq_threshold": "5",
            "substring_disp_nest": "true",
            "substring_normalize": "false",
            "dictionary_min_len": "4",
            "dictionary_disp_nest": "true",
            "company_keywords": "",
            "ignore_blank_passwords": "false",
            "ignore_disabled_accounts": "false",
            "ignore_computer_accounts": "false",
        }

    # Map custom_keywords to company_keywords for the UI
    if "custom_keywords" in options and "company_keywords" not in options:
        options["company_keywords"] = options["custom_keywords"]

    # Include domain info if available (for domain filter dropdown)
    session_mgr = get_session_manager()
    domain_info_data = session_mgr.load_session_data("domain_info.json")
    if domain_info_data:
        options["domain_info"] = domain_info_data

    # Check if there's password history data available
    # Look for history entries in pwdump validation, ADD JSON validation, or persisted session data
    has_history = False

    # First check Flask session (for fresh analysis)
    pwdump_validation = session.get("pwdump_validation")
    add_validation = session.get("add_validation")

    if pwdump_validation and pwdump_validation.get("lines"):
        import re
        for line in pwdump_validation["lines"]:
            username = line.get("username", "")
            if username and re.search(r'_history\d+$', username, re.IGNORECASE):
                has_history = True
                break
    elif add_validation and add_validation.get("total_historical_hashes", 0) > 0:
        has_history = True

    # Also check persisted session data (for loaded sessions)
    if not has_history:
        # Check for password history patterns file (indicates history data exists)
        # This file uses "users_with_history" field for pwdump sessions
        history_patterns = session_mgr.load_session_data("password_history_patterns.json")
        if history_patterns and isinstance(history_patterns, dict):
            if history_patterns.get("users_with_history", 0) > 0 or history_patterns.get("total_history_entries", 0) > 0:
                has_history = True

        # Also check historical_hash_analysis.json (for ADD JSON sessions)
        if not has_history:
            historical_analysis = session_mgr.load_session_data("historical_hash_analysis.json")
            if historical_analysis and isinstance(historical_analysis, dict):
                # Check if there's actual history data
                if historical_analysis.get("total_historical_hashes", 0) > 0:
                    has_history = True

        # Finally check account_data for history entries (pwdump sessions)
        if not has_history:
            account_data = session_mgr.load_session_data("account_data.json")
            if account_data:
                import re
                # Check first 100 entries for _history pattern to avoid scanning entire dataset
                entries_to_check = list(account_data.keys())[:100] if isinstance(account_data, dict) else [e.get("username", "") for e in account_data[:100]]
                for username in entries_to_check:
                    if username and re.search(r'_history\d+$', str(username), re.IGNORECASE):
                        has_history = True
                        break

    options["has_history_data"] = has_history

    return jsonify(options)


@app.route("/api/settings/regenerate", methods=["POST"])
@login_required
def regenerate_with_settings() -> Response:
    """Re-run analysis with new settings on the current session's data."""
    try:
        new_settings = request.get_json()
        if not new_settings:
            return jsonify({"success": False, "error": "No settings provided"}), 400

        # Get current session data
        session_mgr = get_session_manager()
        account_data = session_mgr.load_session_data("account_data.json")

        if not account_data:
            return jsonify({"success": False, "error": "No account data found in current session"}), 400

        # Convert account_data from dict format to list format if needed
        if isinstance(account_data, dict):
            account_data_list = []
            for username, data in account_data.items():
                if isinstance(data, dict):
                    entry = {"username": username}
                    entry.update(data)
                    account_data_list.append(entry)
            account_data_for_analysis = {entry["username"]: entry for entry in account_data_list}
        else:
            account_data_for_analysis = {entry["username"]: entry for entry in account_data}

        # Check if domain filter or account filtering options are being changed
        new_domain_filter = new_settings.get("domain_filter", "all")
        new_ignore_disabled = new_settings.get("ignore_disabled_accounts", "false")
        new_ignore_computer = new_settings.get("ignore_computer_accounts", "false")
        new_ignore_blank = new_settings.get("ignore_blank_passwords", "false")
        new_include_history = new_settings.get("include_history_in_reports", "false")

        current_options = session.get("analysis_options", {})
        # If Flask session lost options, try loading from file
        if not current_options:
            current_options = session_mgr.load_session_data("analysis_options.json") or {}
            if current_options:
                session["analysis_options"] = current_options
        current_domain_filter = current_options.get("domain_filter", "all")
        current_ignore_disabled = current_options.get("ignore_disabled_accounts", "false")
        current_ignore_computer = current_options.get("ignore_computer_accounts", "false")
        current_include_history = current_options.get("include_history_in_reports", "false")

        # Check if any filter that affects account data has changed
        domain_filter_changed = new_domain_filter.lower() != current_domain_filter.lower()
        account_filter_changed = (
            new_ignore_disabled != current_ignore_disabled or
            new_ignore_computer != current_ignore_computer or
            new_include_history != current_include_history
        )

        # If domain or account filter changed, need to rebuild account_data from original validation
        if domain_filter_changed or account_filter_changed:
            # Detect session type from session metadata
            current = session_mgr.get_current_session()
            session_metadata = session_mgr.get_session(current.get("session_id")) if current else None
            is_add_json_session = session_metadata and session_metadata.source_files.get("add_json")

            app.logger.info(f"Filter change detected. Current session: {current}")
            app.logger.info(f"Is ADD JSON session: {is_add_json_session}")
            if session_metadata:
                app.logger.info(f"Source files: {session_metadata.source_files}")

            # Check for ADD JSON validation data first
            add_data = session.get("add_validation")
            app.logger.info(f"add_validation from Flask session: {'found' if add_data else 'not found'}")
            if not add_data:
                add_data = session_mgr.load_session_data("add_validation.json")
                app.logger.info(f"add_validation.json from file: {'found' if add_data else 'not found'}")
                if not add_data and current:
                    # Log the path we're looking for
                    expected_path = session_mgr.get_session_data_path("add_validation.json")
                    app.logger.info(f"Expected path: {expected_path}, exists: {os.path.exists(expected_path)}")

            if add_data:
                # ADD JSON session - rebuild account data using add_to_account_data
                add_result = file_parser.dict_to_add_result(add_data)

                # Get potfile data if available
                potfile_data = session.get("potfile_validation")
                if not potfile_data:
                    potfile_data = session_mgr.load_session_data("potfile_validation.json")

                potfile_result = None
                if potfile_data:
                    potfile_result = file_parser.dict_to_potfile_result(potfile_data)

                # Rebuild account data with new filter settings
                account_data_for_analysis, _ = file_parser.add_to_account_data(
                    add_result,
                    potfile_result,
                    ignore_disabled=new_ignore_disabled == "true",
                    ignore_computer_accounts=new_ignore_computer == "true",
                    include_historical=new_include_history == "true",
                )

                # Apply new domain filter
                if new_domain_filter and new_domain_filter.lower() != "all":
                    account_data_for_analysis = filter_accounts_by_domain(account_data_for_analysis, new_domain_filter)
                    app.logger.info(f"Applied domain filter '{new_domain_filter}', {len(account_data_for_analysis)} accounts remaining")

                if not account_data_for_analysis:
                    return jsonify({"success": False, "error": "No accounts match the selected domain filter"}), 400

                # Update the saved account data
                session_mgr.save_session_data("account_data.json", account_data_for_analysis)
            else:
                # Standard pwdump+potfile session
                # Try Flask session first, then fall back to session files
                pwdump_data = session.get("pwdump_validation")
                potfile_data = session.get("potfile_validation")

                # If not in Flask session, try loading from session files
                if not pwdump_data:
                    pwdump_data = session_mgr.load_session_data("pwdump_validation.json")
                if not potfile_data:
                    potfile_data = session_mgr.load_session_data("potfile_validation.json")

                if is_add_json_session:
                    # ADD JSON session but validation data not saved (older session)
                    # Cannot rebuild - would need to re-parse the original file
                    return jsonify({
                        "success": False,
                        "error": "Cannot change account filters for this session. This session was created before filter editing was supported. Please re-import your ADD JSON file to create a new session with filter editing support."
                    }), 400

                if pwdump_data and potfile_data:
                    # Rebuild account data with new domain filter
                    pwdump_result = file_parser.dict_to_validation_result(pwdump_data)

                    # Optimization: If using master potfile, use cached dict directly
                    cracked_hashes = None
                    if MASTER_POTFILE_ENABLED:
                        cracked_hashes = get_cracked_hashes_direct(MASTER_POTFILE_PATH)

                    if cracked_hashes is not None:
                        # Use optimized path - direct cache access
                        account_data_for_analysis = file_parser.build_account_data_with_cache(
                            pwdump_result,
                            cracked_hashes,
                            ignore_disabled=new_ignore_disabled == "true",
                            ignore_computer_accounts=new_ignore_computer == "true",
                            ignore_history_accounts=new_include_history != "true",
                        )
                    else:
                        # Fall back to standard path
                        potfile_result = file_parser.dict_to_potfile_result(potfile_data)
                        account_data_for_analysis = file_parser.build_account_data(
                            pwdump_result,
                            potfile_result,
                            ignore_disabled=new_ignore_disabled == "true",
                            ignore_computer_accounts=new_ignore_computer == "true",
                            ignore_history_accounts=new_include_history != "true",
                        )

                    # Apply new domain filter
                    if new_domain_filter and new_domain_filter.lower() != "all":
                        account_data_for_analysis = filter_accounts_by_domain(account_data_for_analysis, new_domain_filter)
                        app.logger.info(f"Applied domain filter '{new_domain_filter}', {len(account_data_for_analysis)} accounts remaining")

                    if not account_data_for_analysis:
                        return jsonify({"success": False, "error": "No accounts match the selected domain filter"}), 400

                    # Update the saved account data
                    session_mgr.save_session_data("account_data.json", account_data_for_analysis)
                else:
                    return jsonify({"success": False, "error": "Cannot change account filters - validation data not available"}), 400
        # else: account_data_for_analysis already set correctly at the beginning

        # Update session options
        options = {
            "policy_min_pw_len": new_settings.get("policy_min_pw_len", "12"),
            "policy_max_pw_age": new_settings.get("policy_max_pw_age", "90"),
            "policy_complexity_req": new_settings.get("policy_complexity_req", "3"),
            "substring_min_len": new_settings.get("substring_min_len", "4"),
            "substring_max_len": new_settings.get("substring_max_len", "30"),
            "substring_freq_threshold": new_settings.get("substring_freq_threshold", "5"),
            "substring_disp_nest": new_settings.get("substring_disp_nest", "true"),
            "substring_normalize": new_settings.get("substring_normalize", "false"),
            "dictionary_min_len": new_settings.get("dictionary_min_len", "4"),
            "dictionary_disp_nest": new_settings.get("dictionary_disp_nest", "true"),
            "custom_keywords": new_settings.get("company_keywords", ""),
            "ignore_blank_passwords": new_ignore_blank,
            "ignore_disabled_accounts": new_ignore_disabled,
            "ignore_computer_accounts": new_ignore_computer,
            "include_history_in_reports": new_include_history,
            "domain_filter": new_domain_filter,
        }
        session["analysis_options"] = options

        # Import analysis tools
        from app import password_analysis_tools

        # Re-run analysis with new settings
        stats_report = password_analysis_tools.crack_stats(
            account_data_for_analysis,
            int(options.get("policy_min_pw_len", "12")),
            int(options.get("policy_complexity_req", "3")),
            ignore_blank_passwords=options.get("ignore_blank_passwords", "false") == "true",
            max_pw_age=int(options.get("policy_max_pw_age", "90")),
        )

        # Create list of cracked passwords (for dictionary analysis)
        cracked_passwords = [
            account["cracked_pw"]
            for account in account_data_for_analysis.values()
            if account.get("cracked_pw")
        ]

        # Create list of account/password entries (for substring analysis)
        account_password_entries = [
            {"account": username, "password": account["cracked_pw"]}
            for username, account in account_data_for_analysis.items()
            if account.get("cracked_pw")
        ]

        # Re-run substring analysis
        substrings = password_analysis_tools.substring_analysis(
            account_password_entries,
            int(options.get("substring_min_len", "4")),
            int(options.get("substring_max_len", "30")),
            int(options.get("substring_freq_threshold", "5")),
            options.get("substring_normalize", "false") == "true",
            options.get("substring_disp_nest", "true") == "true",
        )

        # Re-run dictionary analysis
        detailed_results, english_words = password_analysis_tools.dictionary_analysis(
            cracked_passwords,
            int(options.get("dictionary_min_len", "4")),
            options.get("dictionary_disp_nest", "true") == "true",
        )

        # Parse custom keywords
        custom_keywords_raw = options.get("custom_keywords", "").strip()
        custom_keywords = []
        if custom_keywords_raw:
            for line in custom_keywords_raw.replace(",", "\n").split("\n"):
                keyword = line.strip()
                if keyword and len(keyword) >= 3:
                    custom_keywords.append(keyword)

        # Re-run bad practices analysis (pass account entries for username-in-password detection)
        bad_practices = password_analysis_tools.bad_practices_analysis(
            cracked_passwords, custom_keywords, account_password_entries
        )

        # Save updated results to session directory
        session_dir = session_mgr.get_session_dir()

        # Convert stats to array format
        key_order = [
            "Cracked Accounts: ",
            "Uncracked Accounts: ",
            "Total Accounts Analyzed: ",
            "Percent of Accounts Cracked: ",
            "Cracked NTLM Hashes: ",
            "Uncracked NTLM Hashes: ",
            "Unique NTLM Hashes Analyzed: ",
            "Percent of NTLM Hashes Cracked: ",
            "Total LANMan Hashes: ",
            "Shortest Cracked Password: ",
            "Longest Cracked Password: ",
            "Average Password Length: ",
        ]
        stats_table = [{"key": key, "value": stats_report["cracking_stats"][key]} for key in key_order]

        # Save all updated JSON files
        with open(os.path.join(session_dir, "cracking_stats_table.json"), "w") as f:
            json.dump(stats_table, f, indent=2)

        with open(os.path.join(session_dir, "pw_substrings.json"), "w") as f:
            json.dump(substrings, f, indent=2)

        with open(os.path.join(session_dir, "pw_dict_words.json"), "w") as f:
            json.dump(english_words, f, indent=2)

        with open(os.path.join(session_dir, "pw_bad_practices.json"), "w") as f:
            json.dump(bad_practices, f, indent=2)

        with open(os.path.join(session_dir, "pw_length_distribution.json"), "w") as f:
            json.dump(stats_report["pw_length_distribution"], f, indent=2)

        with open(os.path.join(session_dir, "pw_top_passwords.json"), "w") as f:
            json.dump(stats_report["pw_top_passwords"], f, indent=2)

        with open(os.path.join(session_dir, "pw_fails_min_length.json"), "w") as f:
            json.dump(stats_report["pw_fails_min_length"], f, indent=2)

        with open(os.path.join(session_dir, "pw_fails_complexity.json"), "w") as f:
            json.dump(stats_report["pw_fails_complexity"], f, indent=2)

        with open(os.path.join(session_dir, "pw_fails_blank.json"), "w") as f:
            json.dump(stats_report["pw_fails_blank"], f, indent=2)

        with open(os.path.join(session_dir, "pw_lm_hashes.json"), "w") as f:
            json.dump(stats_report["pw_lm_hashes"], f, indent=2)

        with open(os.path.join(session_dir, "pw_account_pie.json"), "w") as f:
            json.dump(stats_report["pw_account_pie"], f, indent=2)

        with open(os.path.join(session_dir, "pw_ntlm_hash_pie.json"), "w") as f:
            json.dump(stats_report["pw_ntlm_hash_pie"], f, indent=2)

        # Save max age violations if available
        if stats_report.get("pw_fails_max_age"):
            with open(os.path.join(session_dir, "pw_fails_max_age.json"), "w") as f:
                json.dump(stats_report["pw_fails_max_age"], f, indent=2)

        # Save updated analysis options
        with open(os.path.join(session_dir, "analysis_options.json"), "w") as f:
            json.dump(options, f, indent=2)

        # Re-run HIBP check if account filters or domain filter changed
        if domain_filter_changed or account_filter_changed:
            hibp_results = run_automatic_hibp_check(account_data_for_analysis, session_dir)
            if hibp_results:
                logging.info(f"HIBP re-check after filter change: {hibp_results['total_found']}/{hibp_results['total_checked']} found in breaches")

        # Update session timestamp
        current_session = session_mgr.get_current_session()
        if current_session:
            session_mgr.update_session(current_session["session_id"])

        logging.info(f"Report regenerated with new settings for session {session_dir}")

        return jsonify({"success": True, "message": "Report regenerated successfully"})

    except Exception as e:
        logging.error(f"Error regenerating report: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# AAIA (Advanced A.I. Analysis) Endpoints
# ============================================================================

def _get_aaia_results_path() -> str:
    """Get path to AAIA results file for current session."""
    session_mgr = get_session_manager()
    return session_mgr.get_session_data_path("aaia_results.json")


def _get_ai_analysis_dir() -> str:
    """Get path to AI analysis debug directory for current session."""
    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    return os.path.join(session_dir, "ai_analysis")


@app.route("/api/ai/aaia/results", methods=["GET"])
@login_required
def aaia_get_results() -> Response:
    """Get saved AAIA results for current session."""
    session_mgr = get_session_manager()
    data = session_mgr.load_session_data("aaia_results.json")
    if data:
        # Include session info and staleness check
        current = session_mgr.get_current_session()
        if current:
            staleness = session_mgr.check_aaia_staleness()
            data["_session_info"] = {
                "session_id": current.get("session_id"),
                "is_stale": staleness.get("is_stale", False),
                "stale_reason": staleness.get("reason", "")
            }
        return jsonify(data)
    return jsonify({"results": {}, "metadata": None})


@app.route("/api/ai/aaia/save", methods=["POST"])
@login_required
def aaia_save_results() -> Response:
    """Save AAIA results to current session folder."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        session_mgr = get_session_manager()
        session_mgr.save_session_data("aaia_results.json", data)

        # Mark AAIA as generated for this session
        current = session_mgr.get_current_session()
        if current:
            session_mgr.mark_aaia_generated(current.get("session_id"))

        return jsonify({"success": True, "message": "AAIA results saved"})
    except Exception as e:
        logging.error(f"Error saving AAIA results: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/aaia/clear", methods=["DELETE"])
@login_required
def aaia_clear_results() -> Response:
    """Clear saved AAIA results for current session."""
    try:
        aaia_path = _get_aaia_results_path()
        if os.path.exists(aaia_path):
            os.remove(aaia_path)

        # Update session metadata
        session_mgr = get_session_manager()
        current = session_mgr.get_current_session()
        if current:
            session_mgr.update_session(
                current.get("session_id"),
                aaia_generated=False,
                aaia_timestamp=""
            )

        return jsonify({"success": True, "message": "AAIA results cleared"})
    except Exception as e:
        logging.error(f"Error clearing AAIA results: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/aaia/config", methods=["GET"])
@login_required
def aaia_get_config() -> Response:
    """Get AAIA configuration with section recommendations and available servers/models."""
    from app.ollama_tools import test_all_servers, OllamaClient, get_ollama_config
    from app.ollama_prompts import AI_REPORT_SECTIONS

    # Get all servers and their status (use cache for fast response)
    servers_data = test_all_servers(use_cache=True)
    online_servers = [s for s in servers_data.get("servers", []) if s.get("reachable")]

    # Get models, running status, and version for each online server
    for server in online_servers:
        config = get_ollama_config(server["id"])
        client = OllamaClient(config)
        server["models"] = client.list_models(include_details=True)
        server["running"] = client.get_running_models()
        server["version"] = client.get_version()

    # Active AAIA sections (SPI, CI, DA)
    # Only include enabled sections
    all_aaia_sections = ["weak-habits", "company-intel", "description-analysis"]
    aaia_sections = [s for s in all_aaia_sections if AI_REPORT_SECTIONS.get(s, {}).get("enabled", True)]

    sections_config = []
    for section_id in aaia_sections:
        section_info = AI_REPORT_SECTIONS.get(section_id, {})
        recommended_model = section_info.get("recommended_model", "llama3.1:70b")

        # Parse model name and estimate size requirement
        model_size_gb = 0
        if "671b" in recommended_model.lower():
            model_size_gb = 400  # ~400GB for 671B models
        elif "405b" in recommended_model.lower():
            model_size_gb = 230  # ~230GB for 405B models
        elif "70b" in recommended_model.lower():
            model_size_gb = 40   # ~40GB for 70B models
        elif "14b" in recommended_model.lower():
            model_size_gb = 8    # ~8GB for 14B models
        elif "7b" in recommended_model.lower():
            model_size_gb = 4    # ~4GB for 7B models

        sections_config.append({
            "id": section_id,
            "title": section_info.get("title", section_id),
            "description": section_info.get("description", ""),
            "recommended_model": recommended_model,
            "temperature": section_info.get("temperature", 0.5),
            "model_size_gb": model_size_gb,
            "order": section_info.get("order", 99),
            "enabled": section_info.get("enabled", True),
            "pipeline": section_info.get("pipeline", "standard")
        })

    # Get total unique passwords for SPI sampling recommendation
    total_passwords = 0
    total_accounts = 0
    accounts_with_descriptions = 0
    try:
        session_dir = get_session_manager().get_session_dir()
        if session_dir:
            from app.spi_analyzer import SPIAnalyzer
            analyzer = SPIAnalyzer(session_dir)
            total_passwords = len(analyzer._get_password_set())

            # Get account description counts for description-analysis section
            from app.description_llm_analyzer import DescriptionLLMAnalyzer
            da_analyzer = DescriptionLLMAnalyzer(session_dir)
            total_accounts = da_analyzer.get_total_user_count()
            accounts_with_descriptions = len(da_analyzer.get_users_with_descriptions())
    except Exception as e:
        logging.warning(f"AAIA config: failed to get session data: {e}")

    return jsonify({
        "servers": online_servers,
        "sections": sorted(sections_config, key=lambda x: x["order"]),
        "total_passwords": total_passwords,
        "total_accounts": total_accounts,
        "accounts_with_descriptions": accounts_with_descriptions
    })


# =============================================================================
# Prompt Management API Endpoints
# =============================================================================


@app.route("/api/ai/prompts", methods=["GET"])
@login_required
def list_prompts() -> Response:
    """
    List all prompts with their status (custom vs default).

    Returns JSON with categories and their prompts:
    {
        "categories": {
            "main": [{"key": "WEAK_HABITS_PROMPT", "name": "...", "is_custom": false}, ...],
            "spi": [...],
            ...
        },
        "custom_counts": {"main": 0, "spi": 2, ...},
        "total_prompts": 31,
        "total_custom": 2
    }
    """
    from app.prompt_manager import get_prompt_manager

    manager = get_prompt_manager()
    all_prompts = manager.list_all_prompts()
    custom_counts = manager.get_custom_prompts_count()

    total_prompts = sum(len(prompts) for prompts in all_prompts.values())
    total_custom = sum(custom_counts.values())

    return jsonify({
        "categories": all_prompts,
        "custom_counts": custom_counts,
        "total_prompts": total_prompts,
        "total_custom": total_custom
    })


@app.route("/api/ai/prompts/<category>/<name>", methods=["GET"])
@login_required
def get_prompt(category: str, name: str) -> Response:
    """
    Get a specific prompt with full details.

    Returns JSON with:
    {
        "category": "spi",
        "name": "sports",
        "display_name": "Sports References",
        "description": "...",
        "template": "...",  # Default template
        "current_content": "...",  # Current content (custom if set)
        "is_custom": false,
        "custom_content": null,
        "variables": ["{passwords}"]
    }
    """
    from app.prompt_manager import get_prompt_manager

    manager = get_prompt_manager()

    try:
        info = manager.get_prompt_info(category, name)
        return jsonify({
            "category": category,
            "key": name,
            "display_name": info.get("name", name),
            "description": info.get("description", ""),
            "template": info.get("template", ""),
            "current_content": info.get("current_content", ""),
            "is_custom": info.get("is_custom", False),
            "custom_content": info.get("custom_content"),
            "variables": info.get("variables", [])
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/ai/prompts/<category>/<name>", methods=["PUT"])
@login_required
def save_prompt(category: str, name: str) -> Response:
    """
    Save a custom prompt.

    Request body:
    {
        "content": "Custom prompt text..."
    }

    Returns:
    {
        "success": true,
        "message": "Prompt saved",
        "validation": {...}  # Optional validation results
    }
    """
    from app.prompt_manager import get_prompt_manager

    manager = get_prompt_manager()
    data = request.get_json() or {}
    content = data.get("content", "")

    if not content:
        return jsonify({"error": "Content is required"}), 400

    try:
        # Get expected variables for validation
        expected_vars = manager.get_prompt_variables(category, name)
        validation = manager.validate_prompt(content, expected_vars)

        # Save the prompt
        manager.save_prompt(category, name, content)

        return jsonify({
            "success": True,
            "message": "Prompt saved",
            "validation": validation
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logging.error(f"Error saving prompt: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/prompts/<category>/<name>", methods=["DELETE"])
@login_required
def revert_prompt(category: str, name: str) -> Response:
    """
    Revert to default prompt (removes custom override).

    Returns:
    {
        "success": true,
        "message": "Prompt reverted to default"
    }
    """
    from app.prompt_manager import get_prompt_manager

    manager = get_prompt_manager()

    try:
        manager.revert_prompt(category, name)
        return jsonify({
            "success": True,
            "message": "Prompt reverted to default"
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logging.error(f"Error reverting prompt: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/prompts/variables", methods=["GET"])
@login_required
def get_prompt_variables_docs() -> Response:
    """
    Get variable documentation for all prompt types.

    Returns comprehensive documentation of available template variables
    and what data each one contains.
    """
    variables_docs = {
        "main_section_variables": {
            "{cracked_passwords}": "List of all cracked passwords (may be sampled for large datasets)",
            "{account_passwords}": "Passwords with associated account names (username:password pairs)",
            "{password_reuse}": "Accounts sharing the same passwords with reuse counts",
            "{length_distribution}": "Password length statistics and distribution",
            "{org_context}": "Organization name and domain info derived from the data",
            "{total_accounts}": "Total number of accounts analyzed",
            "{cracked_count}": "Number of cracked accounts",
            "{account_names}": "List of account/usernames for analysis",
            "{stats}": "Summary statistics from the password audit",
            "{policy_failures}": "List of policy compliance failures",
            "{critical_findings}": "Critical security findings from the audit",
            "{audit_stats}": "Complete cracking statistics",
            "{key_findings}": "Key findings from the analysis",
            "{current_policy}": "Current password policy settings",
            "{worst_practices}": "Worst password practices found"
        },
        "spi_variables": {
            "{passwords}": "Newline-separated list of unique passwords to analyze for semantic patterns"
        },
        "ci_variables": {
            "{passwords}": "Newline-separated list of unique passwords",
            "{accounts}": "Newline-separated list of account names for organizational analysis"
        },
        "da_variables": {
            "{accounts_data}": "Account:Description pairs for AD description analysis"
        },
        "validation_variables": {
            "{evidence_pack}": "Evidence data for validating claims",
            "{content_to_validate}": "Content to be validated"
        },
        "formatting_variables": {
            "{validated_content}": "Content to format for presentation"
        },
        "categories": {
            "main": "Main analysis prompts (weak habits, company intel, user behavior, recommendations)",
            "spi": "Semantic Password Intelligence - 11 categories for pattern detection",
            "ci": "Company Intelligence - 3 categories (identity, industry, location)",
            "da": "Description Analysis - 3 categories (passwords, PII, credentials)",
            "validation": "Phase 2 validation prompts for fact-checking",
            "formatting": "Phase 3 formatting prompts for presentation",
            "preambles": "System prompts and context-setting preambles"
        }
    }

    return jsonify(variables_docs)


@app.route("/api/ai/prompts/export", methods=["GET"])
@login_required
def export_prompts() -> Response:
    """
    Export all custom prompts as JSON.

    Returns downloadable JSON with all custom prompt overrides.
    """
    from app.prompt_manager import get_prompt_manager

    manager = get_prompt_manager()
    export_data = manager.export_custom_prompts()

    response = Response(
        export_data,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=custom_prompts.json"}
    )
    return response


@app.route("/api/ai/prompts/import", methods=["POST"])
@login_required
def import_prompts() -> Response:
    """
    Import custom prompts from JSON.

    Request body:
    {
        "prompts_json": "...",  # JSON string or parsed object
        "merge": true  # If true, merge with existing. If false, replace all.
    }

    Returns:
    {
        "success": true,
        "imported_count": 5,
        "errors": []
    }
    """
    from app.prompt_manager import get_prompt_manager

    manager = get_prompt_manager()
    data = request.get_json() or {}

    prompts_json = data.get("prompts_json", "")
    merge = data.get("merge", True)

    if not prompts_json:
        return jsonify({"error": "prompts_json is required"}), 400

    # Handle both string and dict input
    if isinstance(prompts_json, dict):
        prompts_json = json.dumps(prompts_json)

    result = manager.import_custom_prompts(prompts_json, merge=merge)

    if result["success"]:
        return jsonify(result)
    else:
        return jsonify(result), 400


@app.route("/api/ai/report/outputs", methods=["GET"])
@login_required
def ai_report_list_outputs() -> Response:
    """List saved test outputs from the test_outputs folder."""
    test_output_dir = os.path.join(os.path.dirname(__file__), "test_outputs")

    if not os.path.exists(test_output_dir):
        return jsonify({"outputs": [], "count": 0})

    outputs = []
    for filename in sorted(os.listdir(test_output_dir), reverse=True):
        if filename.endswith(".md"):
            filepath = os.path.join(test_output_dir, filename)
            stat = os.stat(filepath)
            # Parse filename: section_model_temp_timestamp.md
            parts = filename.replace(".md", "").split("_")
            outputs.append({
                "filename": filename,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "section": parts[0] if parts else "unknown"
            })

    return jsonify({
        "outputs": outputs,
        "count": len(outputs),
        "directory": "test_outputs"
    })


@app.route("/api/ai/report/outputs/<filename>", methods=["GET"])
@login_required
def ai_report_get_output(filename: str) -> Response:
    """Get contents of a specific test output file."""
    test_output_dir = os.path.join(os.path.dirname(__file__), "test_outputs")
    filepath = os.path.join(test_output_dir, filename)

    # Security check - prevent directory traversal
    if not os.path.abspath(filepath).startswith(os.path.abspath(test_output_dir)):
        return jsonify({"error": "Invalid filename"}), 400

    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404

    with open(filepath, "r") as f:
        content = f.read()

    return jsonify({
        "filename": filename,
        "content": content
    })


@app.route("/api/ai/report/data", methods=["GET"])
@login_required
def ai_report_data_summary() -> Response:
    """Get summary of available analysis data for AI reports."""
    from app.ollama_tools import get_ai_data_loader

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    loader = get_ai_data_loader(session_dir)
    summary = loader.get_data_summary()
    return jsonify(summary)


@app.route("/api/ai/report/data/<section_id>", methods=["GET"])
@login_required
def ai_report_section_data(section_id: str) -> Response:
    """
    Get pre-loaded analysis data for a specific AI report section.

    Returns the data that would be sent to the AI for this section,
    loaded from the /data JSON files or specialized analyzers.
    """
    from app.ollama_tools import get_ai_data_loader, get_ai_report_sections

    sections = get_ai_report_sections()
    if section_id not in sections:
        return jsonify({"error": f"Unknown section: {section_id}"}), 400

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    loader = get_ai_data_loader(session_dir)

    if not loader.has_analysis_data():
        return jsonify({
            "error": "No analysis data found. Run a password analysis first.",
            "has_data": False
        }), 404

    section_config = sections[section_id]
    pipeline = section_config.get("pipeline", "standard")

    # Handle specialized pipelines that use their own data loading
    if pipeline == "spi":
        # SPI uses SPIAnalyzer for data loading
        from app.spi_analyzer import SPIAnalyzer
        analyzer = SPIAnalyzer(session_dir)
        passwords, sampling_used, sampling_note = analyzer.get_passwords_for_analysis()
        total_unique = len(analyzer._get_password_set())

        data = {
            "description": "Semantic Password Intelligence sends the full list of unique passwords to the LLM for semantic categorization (sports, pop culture, profanity, etc.)",
            "total_unique_passwords": total_unique,
            "passwords_sent_to_llm": len(passwords),
            "sampling_used": sampling_used,
            "sampling_note": sampling_note if sampling_note else f"All {total_unique} unique passwords will be sent to the LLM",
            "sampling_threshold": analyzer.max_passwords,
            "sample_passwords": passwords[:50] if passwords else [],  # Show first 50 as preview
            "note": f"Showing first 50 of {len(passwords)} passwords that will be analyzed"
        }
        return jsonify({
            "section_id": section_id,
            "section_title": section_config["title"],
            "data": data,
            "data_sources": {"passwords": "Full list of unique cracked passwords (with sampling if >2000)"}
        })

    elif pipeline == "company_intel":
        # Company Intel uses CIAnalyzer for data loading
        from app.company_intel_analyzer import CIAnalyzer
        analyzer = CIAnalyzer(session_dir)
        passwords, accounts, sampling_used, sampling_note = analyzer.get_data_for_analysis()
        total_passwords = len(analyzer._get_password_counts())
        total_accounts = len(analyzer._get_account_list())

        data = {
            "description": "Company Intelligence sends passwords and account names to the LLM to infer company identity, industry, and location",
            "total_unique_passwords": total_passwords,
            "passwords_sent_to_llm": len(passwords),
            "total_unique_accounts": total_accounts,
            "accounts_sent_to_llm": len(accounts),
            "sampling_used": sampling_used,
            "sampling_note": sampling_note if sampling_note else f"All {total_passwords} passwords and {total_accounts} accounts will be sent to the LLM",
            "sampling_threshold_passwords": analyzer.max_passwords,
            "sampling_threshold_accounts": analyzer.max_accounts,
            "sample_passwords": passwords[:30] if passwords else [],  # Show first 30 as preview
            "sample_accounts": accounts[:30] if accounts else [],  # Show first 30 as preview
            "note": f"Showing first 30 of {len(passwords)} passwords and {len(accounts)} accounts that will be analyzed"
        }
        return jsonify({
            "section_id": section_id,
            "section_title": section_config["title"],
            "data": data,
            "data_sources": {
                "passwords": "Full list of unique cracked passwords (with sampling if >2000)",
                "accounts": "Full list of unique account names (with sampling if >2000)"
            }
        })

    # Standard pipeline - use generic loader
    session_data = {
        "analysis_options": session.get("analysis_options", {})
    }
    data = loader.load_section_data(section_id, session_data)

    return jsonify({
        "section_id": section_id,
        "section_title": section_config["title"],
        "data": data,
        "data_sources": section_config.get("data_sources", {})
    })


@app.route("/api/ai/report/data/all", methods=["GET"])
@login_required
def ai_report_all_section_data() -> Response:
    """
    Get pre-loaded analysis data for all AI report sections.

    Useful for initializing the test page with real data.
    """
    from app.ollama_tools import get_ai_data_loader, get_ai_report_sections

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    loader = get_ai_data_loader(session_dir)

    if not loader.has_analysis_data():
        return jsonify({
            "error": "No analysis data found. Run a password analysis first.",
            "has_data": False
        }), 404

    sections = get_ai_report_sections()
    session_data = {
        "analysis_options": session.get("analysis_options", {})
    }

    all_data = {}
    for section_id, section_config in sections.items():
        pipeline = section_config.get("pipeline", "standard")

        # Handle specialized pipelines
        if pipeline == "spi":
            from app.spi_analyzer import SPIAnalyzer
            analyzer = SPIAnalyzer(session_dir)
            passwords, sampling_used, sampling_note = analyzer.get_passwords_for_analysis()
            total_unique = len(analyzer._get_password_set())

            all_data[section_id] = {
                "description": "Semantic Password Intelligence sends the full list of unique passwords to the LLM for semantic categorization (sports, pop culture, profanity, etc.)",
                "total_unique_passwords": total_unique,
                "passwords_sent_to_llm": len(passwords),
                "sampling_used": sampling_used,
                "sampling_note": sampling_note if sampling_note else f"All {total_unique} unique passwords will be sent to the LLM",
                "sampling_threshold": analyzer.max_passwords,
                "sample_passwords": passwords[:50] if passwords else [],
                "note": f"Showing first 50 of {len(passwords)} passwords that will be analyzed"
            }

        elif pipeline == "company_intel":
            from app.company_intel_analyzer import CIAnalyzer
            analyzer = CIAnalyzer(session_dir)
            passwords, accounts, sampling_used, sampling_note = analyzer.get_data_for_analysis()
            total_passwords = len(analyzer._get_password_counts())
            total_accounts = len(analyzer._get_account_list())

            all_data[section_id] = {
                "description": "Company Intelligence sends passwords and account names to the LLM to infer company identity, industry, and location",
                "total_unique_passwords": total_passwords,
                "passwords_sent_to_llm": len(passwords),
                "total_unique_accounts": total_accounts,
                "accounts_sent_to_llm": len(accounts),
                "sampling_used": sampling_used,
                "sampling_note": sampling_note if sampling_note else f"All {total_passwords} passwords and {total_accounts} accounts will be sent to the LLM",
                "sampling_threshold_passwords": analyzer.max_passwords,
                "sampling_threshold_accounts": analyzer.max_accounts,
                "sample_passwords": passwords[:30] if passwords else [],
                "sample_accounts": accounts[:30] if accounts else [],
                "note": f"Showing first 30 of {len(passwords)} passwords and {len(accounts)} accounts that will be analyzed"
            }

        else:
            # Standard pipeline - use generic loader
            all_data[section_id] = loader.load_section_data(section_id, session_data)

    return jsonify({
        "has_data": True,
        "sections": all_data
    })


@app.route("/api/ai/report/prompt/<section_id>", methods=["GET"])
@login_required
def ai_report_section_prompt(section_id: str) -> Response:
    """
    Get the formatted prompt for a specific AI report section.

    Returns the prompt template with data filled in, so users can see
    exactly what will be sent to the AI.

    Active pipelines: spi (weak-habits), company_intel, description_llm
    """
    from app.ollama_tools import get_ai_report_sections
    from app.ollama_prompts import SYSTEM_PROMPT

    sections = get_ai_report_sections()
    if section_id not in sections:
        return jsonify({"error": f"Unknown section: {section_id}"}), 400

    section_config = sections[section_id]
    pipeline = section_config.get("pipeline", "unknown")

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()

    # Handle SPI pipeline
    if pipeline == "spi":
        from app.spi_analyzer import SPIAnalyzer
        from app.spi_prompts import get_spi_prompt, SPI_PREAMBLE, get_all_category_keys

        analyzer = SPIAnalyzer(session_dir)
        passwords, sampling_used, sampling_note = analyzer.get_passwords_for_analysis()

        if not passwords:
            return jsonify({
                "section_id": section_id,
                "system_prompt": SPI_PREAMBLE,
                "prompt_template": None,
                "formatted_prompt": None,
                "has_data": False,
                "message": "No password data available. Run a password analysis first."
            })

        # Show example prompt for first category (sports)
        example_category = "sports"
        example_prompt = get_spi_prompt(example_category, passwords)

        # Build explanation of the multi-prompt approach
        categories = get_all_category_keys()
        explanation = f"""=== SPI Multi-Prompt Approach ===

Semantic Password Intelligence runs {len(categories)} separate LLM calls, one for each category:
{', '.join(categories)}

Each prompt sends the same {len(passwords)} passwords and asks the LLM to identify matches for that specific category.

Below is an example prompt for the '{example_category}' category:

{'='*60}

{example_prompt}"""

        return jsonify({
            "section_id": section_id,
            "system_prompt": SPI_PREAMBLE,
            "prompt_template": f"SPI uses {len(categories)} category-specific prompts",
            "formatted_prompt": explanation,
            "has_data": True,
            "note": f"Showing example prompt for '{example_category}' category. All {len(categories)} categories use similar prompts with {len(passwords)} passwords."
        })

    # Handle Company Intel pipeline
    elif pipeline == "company_intel":
        from app.company_intel_analyzer import CIAnalyzer
        from app.company_intel_prompts import get_ci_prompt, CI_PREAMBLE, get_all_category_keys

        analyzer = CIAnalyzer(session_dir)
        passwords, accounts, sampling_used, sampling_note = analyzer.get_data_for_analysis()

        if not passwords and not accounts:
            return jsonify({
                "section_id": section_id,
                "system_prompt": CI_PREAMBLE,
                "prompt_template": None,
                "formatted_prompt": None,
                "has_data": False,
                "message": "No password or account data available. Run a password analysis first."
            })

        # Show example prompt for first category (company_identity)
        example_category = "company_identity"
        example_prompt = get_ci_prompt(example_category, passwords, accounts)

        # Build explanation of the multi-prompt approach
        categories = get_all_category_keys()
        explanation = f"""=== Company Intelligence Multi-Prompt Approach ===

Company Intelligence runs {len(categories)} separate LLM calls, one for each category:
{', '.join(categories)}

Each prompt sends {len(passwords)} passwords and {len(accounts)} account names, asking the LLM to extract organizational intelligence for that category.

Below is an example prompt for the '{example_category}' category:

{'='*60}

{example_prompt}"""

        return jsonify({
            "section_id": section_id,
            "system_prompt": CI_PREAMBLE,
            "prompt_template": f"CI uses {len(categories)} category-specific prompts",
            "formatted_prompt": explanation,
            "has_data": True,
            "note": f"Showing example prompt for '{example_category}' category. All {len(categories)} categories use similar prompts."
        })

    # Handle Description Analysis pipeline
    elif pipeline == "description_llm":
        from app.description_llm_analyzer import DescriptionLLMAnalyzer
        from app.description_llm_prompts import get_da_prompt, DA_PREAMBLE, get_all_category_keys

        analyzer = DescriptionLLMAnalyzer(session_dir)
        users_with_desc = analyzer.get_users_with_descriptions()

        if not users_with_desc:
            return jsonify({
                "section_id": section_id,
                "system_prompt": DA_PREAMBLE,
                "prompt_template": None,
                "formatted_prompt": None,
                "has_data": False,
                "message": "No account descriptions available. This check requires ADD JSON data with user descriptions."
            })

        # Show example prompt for first category (passwords)
        example_category = "passwords"
        # Format a sample of accounts for the example
        sample_accounts = users_with_desc[:5]
        accounts_data = "\n".join([
            f"[{u.get('SamAccountName', u.get('sam_account_name', ''))}]: {u.get('Description', u.get('description', ''))[:100]}"
            for u in sample_accounts
        ])
        example_prompt = get_da_prompt(example_category, accounts_data)

        # Build explanation
        categories = get_all_category_keys()
        explanation = f"""=== Account Description Inspector Multi-Prompt Approach ===

Description Analysis runs {len(categories)} separate LLM calls, one for each category:
{', '.join(categories)}

Each prompt sends account descriptions in chunks and asks the LLM to identify sensitive information for that category.

Found {len(users_with_desc)} accounts with descriptions.

Below is an example prompt for the '{example_category}' category (showing first 5 accounts):

{'='*60}

{example_prompt}"""

        return jsonify({
            "section_id": section_id,
            "system_prompt": DA_PREAMBLE,
            "prompt_template": f"DA uses {len(categories)} category-specific prompts",
            "formatted_prompt": explanation,
            "has_data": True,
            "note": f"Showing example prompt for '{example_category}' category with {len(users_with_desc)} accounts."
        })

    # Unknown pipeline
    return jsonify({
        "error": f"Unknown pipeline type: {pipeline}",
        "section_id": section_id,
        "has_data": False
    }), 400


@app.route("/api/ai/report/freeform", methods=["POST"])
@login_required
def ai_report_freeform_prompt() -> Response:
    """
    Execute a freeform AI prompt with data placeholders.

    Supports placeholders like:
    - {{all_passwords}} - All unique cracked passwords
    - {{sampled2k_passwords}}, {{sampled1k_passwords}}, {{sampled500_passwords}} - Sampled passwords
    - {{account_data}}, {{cracking_stats_table}}, {{pw_top_passwords}}, etc. - Report sections
    - {{account_descriptions}} - All AD account descriptions (requires ADD JSON)
    - {{account_descriptions_100}}, {{account_descriptions_500}} - Sampled account descriptions
    """
    import time
    import re
    from app.ollama_tools import OllamaClient, get_ollama_config, get_ai_data_loader

    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    prompt_template = data.get("prompt", "").strip()
    if not prompt_template:
        return jsonify({"error": "Prompt is required"}), 400

    model = data.get("model")
    if not model:
        return jsonify({"error": "Model is required"}), 400

    server_id = data.get("server_id")
    temperature = float(data.get("temperature", 0.3))

    # Get session data directory
    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    loader = get_ai_data_loader(session_dir)

    # Find all placeholders in the prompt
    placeholders = re.findall(r'\{\{(\w+)\}\}', prompt_template)

    # Build replacement data for each placeholder
    replacements = {}

    for placeholder in placeholders:
        if placeholder == "all_passwords":
            replacements[placeholder] = loader._derive_all_cracked_passwords()
        elif placeholder == "sampled2k_passwords":
            replacements[placeholder] = _get_sampled_passwords(loader, 2000)
        elif placeholder == "sampled1k_passwords":
            replacements[placeholder] = _get_sampled_passwords(loader, 1000)
        elif placeholder == "sampled500_passwords":
            replacements[placeholder] = _get_sampled_passwords(loader, 500)
        elif placeholder == "account_data":
            account_data = loader._load_json_file("account_data")
            if account_data:
                # Format as username:password pairs
                lines = []
                for username, data in list(account_data.items())[:500]:  # Limit to 500
                    pw = data.get("cracked_pw", "")
                    if pw:
                        simple_name = username.split("\\")[-1] if "\\" in username else username
                        lines.append(f"{simple_name}:{pw}")
                replacements[placeholder] = "\n".join(lines) if lines else "No account data available"
            else:
                replacements[placeholder] = "No account data available"
        elif placeholder == "cracking_stats_table":
            stats = loader._load_json_file("cracking_stats_table")
            replacements[placeholder] = json.dumps(stats, indent=2) if stats else "No cracking stats available"
        elif placeholder == "pw_top_passwords":
            top_pw = loader._load_json_file("pw_top_passwords")
            if top_pw:
                lines = [f"{pw}: {count}" for pw, count in list(top_pw.items())[:100]]
                replacements[placeholder] = "\n".join(lines)
            else:
                replacements[placeholder] = "No top passwords data available"
        elif placeholder == "pw_substrings":
            substrings = loader._load_json_file("pw_substrings")
            replacements[placeholder] = json.dumps(substrings, indent=2) if substrings else "No substring data available"
        elif placeholder == "pw_bad_practices":
            bad = loader._load_json_file("pw_bad_practices")
            replacements[placeholder] = json.dumps(bad, indent=2) if bad else "No bad practices data available"
        elif placeholder == "pw_length_analysis":
            length = loader._load_json_file("pw_length_analysis")
            replacements[placeholder] = json.dumps(length, indent=2) if length else "No length analysis data available"
        elif placeholder == "pw_character_classes":
            chars = loader._load_json_file("pw_character_classes")
            replacements[placeholder] = json.dumps(chars, indent=2) if chars else "No character class data available"
        elif placeholder == "account_descriptions":
            # Load account descriptions from ADD JSON with passwords from account_data
            # Format: account_name: password: description
            add_data = loader._load_json_file("add_data")
            account_data = loader._load_json_file("account_data")
            if add_data and "Users" in add_data:
                # Build a map of sam_name -> password from account_data
                pw_map: dict[str, str] = {}
                if account_data:
                    for username, data in account_data.items():
                        simple_name = username.split("\\")[-1] if "\\" in username else username
                        pw = data.get("cracked_pw", "")
                        if pw:
                            pw_map[simple_name.lower()] = pw
                lines = []
                for user in add_data["Users"]:
                    sam_name = user.get("SamAccountName", user.get("sam_account_name", ""))
                    description = user.get("Description", user.get("description", ""))
                    if sam_name and description and description.strip():
                        password = pw_map.get(sam_name.lower(), "")
                        lines.append(f"{sam_name}: {password}: {description}")
                replacements[placeholder] = "\n".join(lines) if lines else "No account descriptions found"
            else:
                replacements[placeholder] = "No ADD data available. Upload an ADD JSON file to use this placeholder."
        elif placeholder.startswith("account_descriptions_"):
            # Support sampled versions: account_descriptions_100, account_descriptions_500, etc.
            # Format: account_name: password: description
            try:
                limit = int(placeholder.split("_")[-1])
            except ValueError:
                limit = 100
            add_data = loader._load_json_file("add_data")
            account_data = loader._load_json_file("account_data")
            if add_data and "Users" in add_data:
                # Build a map of sam_name -> password from account_data
                pw_map: dict[str, str] = {}
                if account_data:
                    for username, data in account_data.items():
                        simple_name = username.split("\\")[-1] if "\\" in username else username
                        pw = data.get("cracked_pw", "")
                        if pw:
                            pw_map[simple_name.lower()] = pw
                lines = []
                for user in add_data["Users"]:
                    sam_name = user.get("SamAccountName", user.get("sam_account_name", ""))
                    description = user.get("Description", user.get("description", ""))
                    if sam_name and description and description.strip():
                        password = pw_map.get(sam_name.lower(), "")
                        lines.append(f"{sam_name}: {password}: {description}")
                        if len(lines) >= limit:
                            break
                if lines:
                    replacements[placeholder] = "\n".join(lines) + f"\n\n[Showing {len(lines)} accounts with descriptions]"
                else:
                    replacements[placeholder] = "No account descriptions found"
            else:
                replacements[placeholder] = "No ADD data available. Upload an ADD JSON file to use this placeholder."
        else:
            # Unknown placeholder - try loading as JSON file
            file_data = loader._load_json_file(placeholder)
            if file_data:
                replacements[placeholder] = json.dumps(file_data, indent=2)
            else:
                replacements[placeholder] = f"[Unknown placeholder: {placeholder}]"

    # Replace placeholders in prompt
    final_prompt = prompt_template
    for placeholder, value in replacements.items():
        final_prompt = final_prompt.replace(f"{{{{{placeholder}}}}}", str(value))

    # Execute the prompt
    config = get_ollama_config(server_id)
    if not config.enabled:
        return jsonify({"error": "LLM integration is not enabled"}), 400

    client = OllamaClient(config)

    start_time = time.time()
    try:
        response = client.generate(
            prompt=final_prompt,
            model=model,
            temperature=temperature,
            include_usage=True
        )
        elapsed = time.time() - start_time

        if response is None:
            return jsonify({
                "error": "Failed to get response from LLM",
                "response_time": elapsed
            }), 500

        # Handle response format
        if isinstance(response, dict):
            content = response.get("response", "")
            usage = {
                "prompt_tokens": response.get("prompt_tokens", 0),
                "completion_tokens": response.get("completion_tokens", 0),
                "total_tokens": response.get("total_tokens", 0)
            }
        else:
            content = response
            usage = {}

        # Format response time
        if elapsed >= 60:
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            response_time_formatted = f"{mins}m {secs}s"
        else:
            response_time_formatted = f"{elapsed:.1f}s"

        return jsonify({
            "content": content,
            "response_time": elapsed,
            "response_time_formatted": response_time_formatted,
            "usage": usage,
            "placeholders_replaced": list(replacements.keys()),
            "model": model,
            "temperature": temperature
        })

    except Exception as e:
        elapsed = time.time() - start_time
        return jsonify({
            "error": str(e),
            "response_time": elapsed
        }), 500


def _get_sampled_passwords(loader, max_count: int) -> str:
    """Get sampled passwords up to max_count."""
    account_data = loader._load_json_file("account_data")
    if not account_data:
        return "No password data available"

    # Count password frequencies
    password_counts = {}
    for account in account_data.values():
        pw = account.get("cracked_pw")
        if pw:
            password_counts[pw] = password_counts.get(pw, 0) + 1

    if not password_counts:
        return "No cracked passwords found"

    total_unique = len(password_counts)

    # Sort by frequency
    sorted_passwords = sorted(
        password_counts.items(),
        key=lambda x: (-x[1], x[0])
    )

    # If within limit, return all
    if total_unique <= max_count:
        lines = []
        for pw, count in sorted_passwords:
            if count > 1:
                lines.append(f"{pw} (x{count})")
            else:
                lines.append(pw)
        return "\n".join(lines)

    # Sample: prioritize reused passwords, then sample unique
    import random
    reused = [(pw, count) for pw, count in sorted_passwords if count > 1]
    unique = [(pw, count) for pw, count in sorted_passwords if count == 1]

    remaining_slots = max_count - len(reused)
    if remaining_slots > 0 and unique:
        sampled_unique = random.sample(unique, min(remaining_slots, len(unique)))
        sampled = reused + sampled_unique
    else:
        sampled = reused[:max_count]

    lines = [f"[Sampled {len(sampled)} of {total_unique} unique passwords]"]
    for pw, count in sampled:
        if count > 1:
            lines.append(f"{pw} (x{count})")
        else:
            lines.append(pw)

    return "\n".join(lines)


@app.route("/api/ai/report/test")
@login_required
def ai_report_test_page() -> str:
    """AI Report Analysis test page for experimenting with report sections."""
    from app.ollama_tools import test_all_servers, get_ai_report_sections, get_ai_data_loader

    # Get all server statuses (uses 90-min cache for fast page loads)
    servers_status = test_all_servers(use_cache=True)
    sections = get_ai_report_sections()

    # Check if real analysis data is available
    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    loader = get_ai_data_loader(session_dir)
    data_summary = loader.get_data_summary()

    # Build model list from all servers (combine unique models)
    all_models = set()
    reachable_servers = [s for s in servers_status.get("servers", []) if s.get("reachable")]
    for server in reachable_servers:
        all_models.update(server.get("available_models", []))
    all_models = sorted(all_models)

    # Sort sections by order
    sections_sorted = sorted(sections.items(), key=lambda x: x[1].get("order", 99))

    # Build recommended models dict for JS
    recommended_models = {sid: cfg["recommended_model"] for sid, cfg in sections.items()}

    return render_template(
        'ai_report_test.html',
        servers=servers_status.get("servers", []),
        sections_sorted=sections_sorted,
        data_summary=data_summary,
        all_models=all_models,
        recommended_models=recommended_models,
        return_url=get_advanced_mode_return_url()
    )


@app.route("/api/ai/servers/manage")
@login_required
def ai_servers_manage_page() -> str:
    """Multi-server Ollama management page - connectivity testing and model management."""
    from app.ollama_tools import test_all_servers, get_available_library_models

    # Get all server statuses (uses 90-min cache for fast page loads)
    servers_status = test_all_servers(use_cache=True)
    library_models = get_available_library_models()

    # Sort models for each server
    def model_sort_key(model_name):
        parts = model_name.split(":")
        name = parts[0]
        tag = parts[1] if len(parts) > 1 else ""
        size_match = re.search(r'(\d+)', tag)
        size_num = int(size_match.group(1)) if size_match else 0
        return (name.lower(), size_num, tag.lower())

    # Add sorted_models to each server
    servers = servers_status.get("servers", [])
    for server in servers:
        models_list = server.get("available_models", [])
        server["sorted_models"] = sorted(models_list, key=model_sort_key)

    return render_template(
        'ai_servers_manage.html',
        servers=servers,
        library_models=library_models,
        return_url=get_advanced_mode_return_url()
    )


@app.route("/api/ai/benchmark")
@login_required
def ai_benchmark_page() -> str:
    """AI Benchmark Suite - comprehensive model benchmarking and comparison."""
    from app.ollama_tools import test_all_servers, get_ai_report_sections

    # Get all server statuses (use cache for fast page load)
    servers_status = test_all_servers(use_cache=True)
    sections = get_ai_report_sections()

    # Check if production data exists
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    required_files = ["account_data.json", "pw_top_passwords.json", "pw_reuse_table.json"]
    data_exists = all(os.path.exists(os.path.join(data_dir, f)) for f in required_files)

    # Check if any of the required files have content
    data_has_content = False
    if data_exists:
        try:
            account_data_path = os.path.join(data_dir, "account_data.json")
            with open(account_data_path, "r") as f:
                content = json.load(f)
                data_has_content = len(content) > 0
        except:
            data_has_content = False

    # Build model options HTML from all servers
    all_models = set()
    reachable_servers = [s for s in servers_status.get("servers", []) if s.get("reachable")]
    for server in reachable_servers:
        all_models.update(server.get("available_models", []))
    all_models = sorted(all_models)

    model_options = ""
    for model in all_models:
        model_options += f'<option value="{model}">{model}</option>'

    # Build server options HTML
    server_options = ""
    for server in servers_status.get("servers", []):
        status_indicator = "✓" if server.get("reachable") else "✗"
        server_options += f'<option value="{server["id"]}" {"" if server.get("reachable") else "disabled"}>{status_indicator} {server["name"]}</option>'

    # Build server status cards (must match JavaScript refreshServers() structure)
    server_cards_html = ""
    for server in servers_status.get("servers", []):
        status_class = "online" if server.get("reachable") else "offline"
        model_count = len(server.get("available_models", []))
        hardware_info = f" | {server['hardware']}" if server.get("hardware") else ""
        error_info = f" | Error: {server['error']}" if server.get("error") else ""
        server_cards_html += f'''
        <div class="advanced-server-card {status_class}" data-server-id="{server['id']}">
            <div class="advanced-server-header">
                <div class="advanced-server-status">
                    <span class="advanced-status-dot"></span>
                    <span class="advanced-server-name">{server['name']}</span>
                </div>
            </div>
            <div class="advanced-server-host">{server['host']}</div>
            <div class="advanced-server-desc">{server['description']}{hardware_info}</div>
            <div class="advanced-server-desc" style="margin-top: 4px; color: #555;">{model_count} models available{error_info}</div>
        </div>
        '''

    # Build section options for active AAIA pipelines
    section_checkboxes = ""
    for section_id, config in sorted(sections.items(), key=lambda x: x[1].get("order", 99)):
        section_checkboxes += f'''
        <div class="test-item">
            <input type="checkbox" id="test-{section_id}" checked>
            <label for="test-{section_id}"><strong>{config["title"]}</strong> - {config["description"]}</label>
        </div>
        '''

    return render_template(
        'ai_benchmark.html',
        server_cards_html=server_cards_html,
        server_options=server_options,
        model_options=model_options,
        section_checkboxes=section_checkboxes,
        data_has_content=data_has_content,
        return_url=get_advanced_mode_return_url()
    )


@app.route("/agents/test")
@login_required
def agents_test_page() -> str:
    """Hashcat Agent Testing Page - pre-production testing interface."""
    return render_template("agents_test.html")


@app.route("/agents/jobs")
@login_required
def job_manager_page() -> str:
    """Job Manager Page - create and manage hashcat job templates and sequences."""
    return render_template("job_manager.html", return_url=get_advanced_mode_return_url())


# =============================================================================
# Hashcat Agent API
# =============================================================================

# In-memory caches (for performance - database is source of truth)
_agent_benchmarks: dict[str, dict] = {}  # agent_id -> benchmark status tracking
_job_metadata: dict[str, dict] = {}  # job_id -> job metadata (hashcat_args, etc.)
_agent_jobs: dict[str, dict] = {}  # agent_id -> current job status (fast access cache)

# Legacy compatibility - these now use the database
_agent_registry: dict[str, dict] = {}  # Kept for SSE connection tracking only
_pending_registrations: dict[str, dict] = {}  # Kept for backward compatibility


def _get_agent_data_dir() -> str:
    """Get directory for agent data persistence."""
    data_dir = os.path.join(os.path.dirname(__file__), "data", "agents")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def _get_db() -> AgentStateDB:
    """Get the agent state database instance."""
    return get_agent_db(_get_agent_data_dir())


def _load_agents() -> None:
    """Load agents from database (for backward compatibility)."""
    global _agent_registry
    try:
        _agent_registry = _get_db().get_all_agents()
    except Exception as e:
        logging.error(f"Failed to load agents from database: {e}")


def _save_agents() -> None:
    """Save agents - now a no-op since database handles persistence."""
    # Database handles persistence automatically
    pass


def _load_pending_registrations() -> None:
    """Load pending registrations from database."""
    global _pending_registrations
    try:
        _pending_registrations = _get_db().get_pending_registrations()
    except Exception as e:
        logging.error(f"Failed to load pending registrations: {e}")


def _save_pending_registrations() -> None:
    """Save pending registrations - now a no-op since database handles persistence."""
    # Database handles persistence automatically
    pass


def _generate_agent_token(agent_id: str, agent_name: str) -> str:
    """Generate a JWT token for an approved agent."""
    import jwt
    from datetime import datetime, timedelta

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise ValueError("SECRET_KEY not configured")

    payload = {
        "agent_id": agent_id,
        "name": agent_name,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=365),
    }

    return jwt.encode(payload, secret_key, algorithm="HS256")


def _get_job_metadata_file() -> str:
    """Get path to job metadata file."""
    return os.path.join(_get_agent_data_dir(), "job_metadata.json")


def _load_job_metadata() -> dict:
    """Load job metadata from disk."""
    global _job_metadata
    metadata_file = _get_job_metadata_file()
    if os.path.exists(metadata_file):
        try:
            with open(metadata_file, "r") as f:
                _job_metadata = json.load(f)
        except Exception as e:
            logging.error(f"Failed to load job metadata: {e}")
    return _job_metadata


def _save_job_metadata() -> None:
    """Save job metadata to disk."""
    metadata_file = _get_job_metadata_file()
    try:
        with open(metadata_file, "w") as f:
            json.dump(_job_metadata, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to save job metadata: {e}")


def _store_job_metadata(job_id: str, metadata: dict) -> None:
    """Store metadata for a job."""
    _load_job_metadata()
    _job_metadata[job_id] = metadata
    _save_job_metadata()


def _get_job_metadata(job_id: str) -> dict:
    """Get metadata for a job."""
    _load_job_metadata()
    return _job_metadata.get(job_id, {})


def _mark_job_stopped(job_id: str) -> None:
    """Mark a job as stopped to ignore future stale status updates."""
    try:
        _get_db().mark_job_stopped(job_id)
    except Exception as e:
        logging.error(f"Failed to mark job stopped: {e}")


def _is_job_stopped(job_id: str) -> bool:
    """Check if a job has been stopped."""
    try:
        return _get_db().is_job_stopped(job_id)
    except Exception as e:
        logging.error(f"Failed to check if job stopped: {e}")
        return False


# Legacy job queue functions - kept for backward compatibility during transition
def _get_job_queue_file() -> str:
    """Get path to job queue file (legacy - no longer used)."""
    return os.path.join(_get_agent_data_dir(), "job_queue.json")


def _queue_agent_command(agent_id: str, command: dict) -> None:
    """Add a command to an agent's queue (database-backed for multi-worker)."""
    try:
        _get_db().queue_command(agent_id, command)
    except Exception as e:
        logging.error(f"Failed to queue command: {e}")


def _pop_agent_commands(agent_id: str) -> list:
    """Pop all commands for an agent from the queue (database-backed)."""
    try:
        return _get_db().pop_commands(agent_id)
    except Exception as e:
        logging.error(f"Failed to pop commands: {e}")
        return []


def _get_agent(agent_id: str) -> dict | None:
    """Get an agent's data by ID from database."""
    try:
        agent = _get_db().get_agent(agent_id)
    except Exception as e:
        logging.error(f"Failed to get agent from database: {e}")
        return None

    if agent is None:
        return None

    # Check shared SSE connections for accurate online status
    sse_connections = _get_sse_connections()
    if agent_id in sse_connections:
        # Agent has active SSE connection - mark as online
        agent["status"] = "online"
        agent["sse_connected"] = True
    else:
        # Check if we have recent heartbeat (within 2 minutes)
        last_heartbeat = agent.get("last_heartbeat")
        if last_heartbeat:
            try:
                hb_time = datetime.fromisoformat(last_heartbeat)
                age_seconds = (datetime.now() - hb_time).total_seconds()
                if age_seconds < 120:  # 2 minutes
                    agent["status"] = "online"
                else:
                    agent["status"] = "offline"
            except Exception:
                pass

    return agent


def _get_benchmark_status_file() -> str:
    """Get path to benchmark status file."""
    return os.path.join(_get_agent_data_dir(), "benchmark_status.json")


def _load_benchmark_status() -> dict:
    """Load benchmark status from disk (for multi-worker support)."""
    status_file = _get_benchmark_status_file()
    if os.path.exists(status_file):
        try:
            with open(status_file, "r") as f:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logging.error(f"Failed to load benchmark status: {e}")
    return {}


def _save_benchmark_status(status: dict) -> None:
    """Save benchmark status to disk (for multi-worker support)."""
    status_file = _get_benchmark_status_file()
    try:
        with open(status_file, "w") as f:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                json.dump(status, f)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logging.error(f"Failed to save benchmark status: {e}")


def _set_benchmark_status(agent_id: str, status_data: dict) -> None:
    """Set benchmark status for an agent (file-backed)."""
    all_status = _load_benchmark_status()
    all_status[agent_id] = status_data
    _save_benchmark_status(all_status)


def _get_benchmark_status(agent_id: str) -> dict | None:
    """Get benchmark status for an agent (file-backed)."""
    all_status = _load_benchmark_status()
    return all_status.get(agent_id)


def _clear_benchmark_status(agent_id: str) -> None:
    """Clear benchmark status for an agent (file-backed)."""
    all_status = _load_benchmark_status()
    if agent_id in all_status:
        del all_status[agent_id]
        _save_benchmark_status(all_status)


# Load agents and pending registrations on module import
_load_agents()
_load_pending_registrations()


# =============================================================================
# Agent Registration API
# =============================================================================


@app.route("/api/agent/register", methods=["POST"])
@csrf.exempt
def agent_register() -> Response:
    """
    Agent registration endpoint.
    Agent sends registration code and info, server stores as pending.
    Admin must approve in the UI before agent can authenticate.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    registration_code = data.get("registration_code")
    hostname = data.get("hostname")
    name = data.get("name", hostname)

    if not registration_code:
        return jsonify({"error": "registration_code required"}), 400
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    # Reload from disk for multi-worker support
    _load_pending_registrations()

    # Check if this code is already registered
    if registration_code in _pending_registrations:
        existing = _pending_registrations[registration_code]
        return jsonify({
            "status": existing.get("status", "pending"),
            "message": "Registration already exists",
        })

    # Store pending registration
    _pending_registrations[registration_code] = {
        "registration_code": registration_code,
        "hostname": hostname,
        "name": name,
        "ip_address": request.remote_addr or "unknown",
        "status": "pending",
        "created_at": datetime.now().isoformat(),
        "agent_id": None,  # Will be set when approved
        "token": None,  # Will be set when approved
    }
    _save_pending_registrations()

    logging.info(f"New agent registration pending: {name} ({hostname}) with code {registration_code}")

    return jsonify({
        "status": "pending",
        "message": "Registration pending admin approval",
    })


@app.route("/api/agent/register/status", methods=["GET"])
@csrf.exempt
def agent_register_status() -> Response:
    """
    Check registration status.
    Agent polls this endpoint to see if registration was approved.
    """
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "code parameter required"}), 400

    # Reload from disk for multi-worker support
    _load_pending_registrations()

    if code not in _pending_registrations:
        return jsonify({"status": "unknown", "error": "Registration not found"}), 404

    registration = _pending_registrations[code]
    status = registration.get("status", "pending")

    response = {"status": status}

    if status == "approved":
        response["token"] = registration.get("token")
        response["agent_id"] = registration.get("agent_id")

    return jsonify(response)


@app.route("/api/agent/register/pending", methods=["GET"])
@login_required
def get_pending_registrations() -> Response:
    """Get list of pending agent registrations for admin approval."""
    _load_pending_registrations()

    # Filter to only pending registrations
    pending = [
        reg for reg in _pending_registrations.values()
        if reg.get("status") == "pending"
    ]

    # Sort by creation time, newest first
    pending.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return jsonify({"pending": pending})


@app.route("/api/agent/register/approve", methods=["POST"])
@login_required
def approve_registration() -> Response:
    """Approve a pending agent registration."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    code = data.get("code")
    if not code:
        return jsonify({"error": "code required"}), 400

    _load_pending_registrations()

    if code not in _pending_registrations:
        return jsonify({"error": "Registration not found"}), 404

    registration = _pending_registrations[code]
    if registration.get("status") != "pending":
        return jsonify({"error": f"Registration already {registration.get('status')}"}), 400

    # Generate agent ID and token
    import uuid
    agent_id = str(uuid.uuid4())
    agent_name = registration.get("name", registration.get("hostname"))

    try:
        token = _generate_agent_token(agent_id, agent_name)
    except Exception as e:
        logging.error(f"Failed to generate token: {e}")
        return jsonify({"error": f"Failed to generate token: {e}"}), 500

    # Update registration
    registration["status"] = "approved"
    registration["agent_id"] = agent_id
    registration["token"] = token
    registration["approved_at"] = datetime.now().isoformat()
    _save_pending_registrations()

    # Pre-register the agent in the database
    db = _get_db()
    db.pre_register_agent(
        agent_id=agent_id,
        name=agent_name,
        ip_address=registration.get("ip_address"),
        hostname=registration.get("hostname"),
    )

    logging.info(f"Agent registration approved: {agent_name} (ID: {agent_id})")

    return jsonify({
        "status": "approved",
        "agent_id": agent_id,
        "name": agent_name,
    })


@app.route("/api/agent/register/reject", methods=["POST"])
@login_required
def reject_registration() -> Response:
    """Reject a pending agent registration."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    code = data.get("code")
    if not code:
        return jsonify({"error": "code required"}), 400

    _load_pending_registrations()

    if code not in _pending_registrations:
        return jsonify({"error": "Registration not found"}), 404

    registration = _pending_registrations[code]
    if registration.get("status") != "pending":
        return jsonify({"error": f"Registration already {registration.get('status')}"}), 400

    # Update registration status
    registration["status"] = "rejected"
    registration["rejected_at"] = datetime.now().isoformat()
    _save_pending_registrations()

    logging.info(f"Agent registration rejected: {registration.get('name')} (code: {code})")

    return jsonify({"status": "rejected"})


@app.route("/api/agent/ping", methods=["GET"])
def agent_ping() -> Response:
    """
    Connection test endpoint for agents.
    Returns server version and whether the agent is recognized.
    """
    agent_id = request.headers.get("User-Agent", "").split("/")[-1] if "hm1k-agent" in request.headers.get("User-Agent", "") else None

    db = _get_db()
    agent_recognized = db.get_agent(agent_id) is not None if agent_id else False

    return jsonify({
        "status": "ok",
        "version": "2.0.0",
        "agent_recognized": agent_recognized,
        "server_time": datetime.now().isoformat(),
    })


# Agent download directory (relative to app root)
AGENT_FILES_DIR = os.path.join(os.path.dirname(__file__), "internal", "hm1k-agent")


@app.route("/agent/<path:filename>", methods=["GET"])
def serve_agent_file(filename: str) -> Response:
    """
    Serve agent installation files.
    No authentication required for easy curl/wget access.

    Available files:
    - /agent/install.sh - Bootstrap installer script
    - /agent/deploy.sh - Full deployment script
    - /agent/config.example.yaml - Example configuration
    - /agent/hm1k_agent-*.whl - Python wheel package
    """
    from flask import send_from_directory, abort

    # Allowed files for security (prevent directory traversal)
    allowed_files = [
        "install.sh",
        "deploy.sh",
        "config.example.yaml",
    ]

    # Also allow wheel files from dist/
    if filename.endswith(".whl"):
        dist_dir = os.path.join(AGENT_FILES_DIR, "dist")
        wheel_path = os.path.join(dist_dir, filename)
        if os.path.isfile(wheel_path):
            return send_from_directory(dist_dir, filename)
        abort(404)

    if filename not in allowed_files:
        abort(404)

    file_path = os.path.join(AGENT_FILES_DIR, filename)
    if not os.path.isfile(file_path):
        abort(404)

    return send_from_directory(AGENT_FILES_DIR, filename)


@app.route("/agent/", methods=["GET"])
def list_agent_files() -> Response:
    """List available agent files for download."""
    files = []

    # List main files
    for f in ["install.sh", "deploy.sh", "config.example.yaml"]:
        path = os.path.join(AGENT_FILES_DIR, f)
        if os.path.isfile(path):
            files.append({
                "name": f,
                "url": f"/agent/{f}",
                "size": os.path.getsize(path),
            })

    # List wheel files from dist/
    dist_dir = os.path.join(AGENT_FILES_DIR, "dist")
    if os.path.isdir(dist_dir):
        for f in os.listdir(dist_dir):
            if f.endswith(".whl"):
                path = os.path.join(dist_dir, f)
                files.append({
                    "name": f,
                    "url": f"/agent/{f}",
                    "size": os.path.getsize(path),
                })

    return jsonify({
        "files": files,
        "install_command": "curl -sSL https://192.168.8.88/agent/install.sh | sudo bash",
    })


@app.route("/api/health", methods=["GET"])
def health_check() -> Response:
    """
    Health check endpoint for monitoring.
    Returns server status, worker info, and basic metrics.
    No authentication required for external monitoring systems.
    """
    import os

    # Count connected agents from shared file (multi-worker consistent)
    sse_connections = _get_sse_connections()
    connected_agents = len(sse_connections)

    # Get agent stats from database
    db = _get_db()
    agent_stats = db.get_agent_stats()
    total_agents = agent_stats['total_agents']
    active_jobs = agent_stats['active_jobs']

    # Get potfile stats if available
    potfile_count = 0
    if MASTER_POTFILE_ENABLED:
        try:
            cache = get_master_cache()
            if cache:
                cached_potfile = cache.load(MASTER_POTFILE_PATH)
                potfile_count = cached_potfile.ntlm_count
        except Exception:
            pass

    # Worker info - read from gunicorn config or use defaults
    workers_configured = 12  # Default from gunicorn.conf.py
    threads_configured = 2
    try:
        # Try to read from gunicorn config
        import importlib.util
        gunicorn_conf_path = os.path.join(os.path.dirname(__file__), "gunicorn.conf.py")
        if os.path.exists(gunicorn_conf_path):
            spec = importlib.util.spec_from_file_location("gunicorn_conf", gunicorn_conf_path)
            if spec and spec.loader:
                gunicorn_conf = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(gunicorn_conf)
                workers_configured = getattr(gunicorn_conf, "workers", 12)
                threads_configured = getattr(gunicorn_conf, "threads", 2)
    except Exception:
        pass

    # Active user sessions from shared file (multi-worker consistent)
    now = time.time()
    session_timeout = 3600  # Consider sessions active if seen in last hour
    shared_activity = _get_user_activity_shared()
    active_users = [
        username for username, last_seen in shared_activity.items()
        if (now - last_seen) < session_timeout
    ]

    # Count Flask session files modified in last hour for session count
    session_count = 0
    try:
        session_dir = app.config.get("SESSION_FILE_DIR", "flask_session")
        if os.path.isdir(session_dir):
            for fname in os.listdir(session_dir):
                fpath = os.path.join(session_dir, fname)
                if os.path.isfile(fpath):
                    mtime = os.path.getmtime(fpath)
                    if (now - mtime) < session_timeout:
                        session_count += 1
    except Exception:
        pass

    return jsonify({
        "status": "healthy",
        "version": "2.0.0",
        "uptime_seconds": int(time.time() - _app_start_time),
        "workers": {
            "configured": workers_configured,
            "threads_per_worker": threads_configured,
            "total_capacity": workers_configured * threads_configured,
            "current_pid": os.getpid(),
        },
        "users": {
            "active_sessions": session_count,
            "logged_in": sorted(active_users),
        },
        "agents": {
            "total": total_agents,
            "connected": connected_agents,
            "active_jobs": active_jobs,
        },
        "potfile": {
            "entries": potfile_count,
        },
        "requests": _get_active_requests_summary(),
        "server_time": datetime.now().isoformat(),
    })


def _get_active_requests_summary() -> dict:
    """Get summary of currently active requests for health monitoring."""
    now = time.time()
    with _request_tracking["lock"]:
        active = _request_tracking["active_requests"]
        if not active:
            return {
                "count": 0,
                "slow_count": 0,
                "oldest_seconds": 0,
                "worker_pid": _request_tracking["worker_pid"],
            }

        durations = [(now - r["started_at"]) for r in active.values()]
        slow_threshold = _request_tracking["slow_request_threshold_seconds"]

        return {
            "count": len(active),
            "slow_count": sum(1 for d in durations if d > slow_threshold),
            "oldest_seconds": round(max(durations), 2) if durations else 0,
            "worker_pid": _request_tracking["worker_pid"],
            "details": [
                {
                    "path": r["path"],
                    "method": r["method"],
                    "duration_seconds": round(now - r["started_at"], 2),
                }
                for r in active.values()
                if (now - r["started_at"]) > slow_threshold
            ][:5],  # Only show top 5 slow requests
        }


@app.route("/api/health/liveness", methods=["GET"])
def liveness_check() -> Response:
    """
    Fast liveness check for watchdog monitoring.
    Returns immediately without loading any caches or doing heavy operations.
    Used by health check watchdog to detect unresponsive workers.
    """
    return jsonify({
        "status": "alive",
        "worker_pid": _os.getpid(),
        "active_requests": len(_request_tracking["active_requests"]),
        "timestamp": time.time(),
    })


@app.route("/api/agent/heartbeat", methods=["POST"])
@csrf.exempt
def agent_heartbeat() -> Response:
    """
    Agent heartbeat endpoint.
    Registers or updates agent status and returns any pending commands.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    state = data.get("state", {})

    # Get agent's IP address
    agent_ip = request.remote_addr or "unknown"

    # Register or update agent using database
    now = datetime.now().isoformat()
    db = _get_db()

    # Try to update existing agent first (most common case)
    if not db.update_agent_heartbeat(agent_id, state, agent_ip):
        # Agent doesn't exist - register new agent
        agent_name = state.get("name", f"Agent-{agent_id[:8]}")
        db.register_new_agent(agent_id, agent_name, state, agent_ip)
        logging.info(f"New agent registered: {agent_id} from {agent_ip}")

    # Update software status if provided
    software_data = data.get("software")
    if software_data:
        try:
            manager = _get_software_manager()
            manager.update_agent_status(
                agent_id=agent_id,
                hashcat_versions=software_data.get("hashcat_versions"),
                nvidia_driver=software_data.get("nvidia_driver"),
                amd_driver=software_data.get("amd_driver"),
            )
        except Exception as e:
            logging.warning(f"Failed to update agent software status: {e}")

    # Return any pending commands for this agent (file-backed for multi-worker)
    commands = _pop_agent_commands(agent_id)

    return jsonify({
        "status": "ok",
        "server_time": now,
        "commands": commands,
    })


@app.route("/api/agent/status", methods=["POST"])
@csrf.exempt
def agent_job_status() -> Response:
    """
    Receive job status updates from agent.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    agent_id = data.get("agent_id")
    job_id = data.get("job_id")

    if not agent_id or not job_id:
        return jsonify({"error": "agent_id and job_id required"}), 400

    # Check if this job was stopped - ignore stale updates from agent
    if _is_job_stopped(job_id):
        logging.debug(f"Ignoring stale status update for stopped job {job_id}")
        return jsonify({"status": "ok", "ignored": True, "reason": "job_stopped"})

    # Get existing agent state from database
    db = _get_db()
    agent = db.get_agent(agent_id)

    # Check if this update is newer than existing (avoid progress going backwards)
    now = datetime.now()
    now_iso = now.isoformat()
    existing_job = agent.get("current_job", {}) if agent else {}
    if existing_job and existing_job.get("job_id") == job_id:
        # Only update if progress is higher or it's been more than 5 seconds
        existing_progress = existing_job.get("progress_percent", 0)
        new_progress = data.get("progress_percent", 0)
        existing_updated = existing_job.get("updated_at", "")
        if existing_updated:
            try:
                existing_time = datetime.fromisoformat(existing_updated)
                time_diff = (now - existing_time).total_seconds()
                # Accept update if: progress increased, or 5+ seconds passed, or recovered hashes increased
                if (new_progress < existing_progress and
                    time_diff < 5 and
                    data.get("recovered_hashes", 0) <= existing_job.get("recovered_hashes", 0)):
                    # Skip this stale update
                    return jsonify({"status": "ok", "skipped": True})
            except (ValueError, TypeError):
                pass  # Can't parse timestamp, accept update

    # Store job status
    job_data = {
        "job_id": job_id,
        "status": data.get("status"),
        "progress_percent": data.get("progress_percent", 0),
        "speed_hashes_per_sec": data.get("speed_hashes_per_sec", 0),
        "recovered_hashes": data.get("recovered_hashes", 0),
        "total_hashes": data.get("total_hashes", 0),
        "eta_seconds": data.get("eta_seconds"),
        "gpu_temps": data.get("gpu_temps"),
        "gpu_utils": data.get("gpu_utils"),
        "gpu_speeds": data.get("gpu_speeds"),  # Individual GPU speeds
        "hashcat_version": data.get("hashcat_version"),  # Hashcat version in use
        "time_start": data.get("time_start"),  # Unix timestamp when hashcat started
        "updated_at": now_iso,
    }

    # Update in-memory cache for fast access
    _agent_jobs[agent_id] = job_data

    # Update agent state in database
    if agent:
        db.set_agent_job(agent_id, job_data)

    return jsonify({"status": "ok"})


@app.route("/api/agent/job/complete", methods=["POST"])
@csrf.exempt
def agent_job_complete() -> Response:
    """
    Receive job completion notification from agent.

    Handles:
    - Standard jobs: saves results
    - LM jobs: processes potfile through LM pairing logic
    - Workflow jobs: chains to next step automatically
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    agent_id = data.get("agent_id")
    job_id = data.get("job_id")
    potfile = data.get("potfile", "")
    stats = data.get("stats", {})

    if not agent_id or not job_id:
        return jsonify({"error": "agent_id and job_id required"}), 400

    # Log completion
    logging.info(f"Job {job_id} completed by agent {agent_id}")
    logging.info(f"Recovered: {stats.get('recovered', 0)}/{stats.get('total_hashes', 0)}")

    # Store results
    results_dir = os.path.join(_get_agent_data_dir(), "results")
    os.makedirs(results_dir, exist_ok=True)

    # Check if this is a workflow job (job_id pattern: workflow_id-lm or workflow_id-ntlm)
    workflow_id = None
    workflow_step = None
    if job_id.endswith("-lm"):
        workflow_id = job_id[:-3]  # Remove "-lm"
        workflow_step = "lm_brute"
    elif job_id.endswith("-ntlm"):
        workflow_id = job_id[:-5]  # Remove "-ntlm"
        workflow_step = "ntlm_toggle"

    # Handle workflow job completion
    if workflow_id:
        try:
            workflow_mgr = _get_workflow_manager()

            if workflow_step == "lm_brute":
                # LM step complete - process and potentially chain NTLM step
                state, next_job_data = workflow_mgr.on_lm_job_complete(
                    workflow_id, potfile, stats
                )

                if next_job_data:
                    # Queue the NTLM job
                    _queue_agent_command(agent_id, {
                        "type": "job:assigned",
                        "data": next_job_data
                    })
                    logging.info(
                        f"Workflow {workflow_id}: LM complete, queued NTLM toggle job"
                    )

                # Add workflow info to stats
                stats["workflow"] = {
                    "workflow_id": workflow_id,
                    "step": "lm_brute",
                    "users_both_halves_cracked": state.users_both_halves_cracked,
                    "next_step": "ntlm_toggle" if next_job_data else "completed",
                }

            elif workflow_step == "ntlm_toggle":
                # NTLM step complete - workflow done
                state = workflow_mgr.on_ntlm_job_complete(workflow_id, potfile, stats)

                stats["workflow"] = {
                    "workflow_id": workflow_id,
                    "step": "ntlm_toggle",
                    "final_passwords_recovered": state.final_passwords_recovered,
                    "next_step": "completed",
                }

                logging.info(
                    f"Workflow {workflow_id}: Complete! "
                    f"Recovered {state.final_passwords_recovered} NTLM passwords"
                )

        except Exception as e:
            logging.error(f"Failed to process workflow job: {e}")
            stats["workflow_error"] = str(e)
            # Try to mark workflow as failed
            try:
                workflow_mgr = _get_workflow_manager()
                workflow_mgr.on_job_error(workflow_id, str(e))
            except Exception:
                pass

    # Check if this was a standalone LM job by looking for mapping file
    mapping_file = os.path.join(results_dir, f"{job_id}_lm_mapping.json")
    lm_stats = None

    if os.path.exists(mapping_file) and potfile.strip() and not workflow_id:
        try:
            # Load the LM extraction mapping
            extraction = lm_ntlm_tools.load_extraction_result(mapping_file)

            # Process potfile to match cracked halves to users
            extraction = lm_ntlm_tools.process_lm_potfile(potfile, extraction)

            # Get cracking statistics
            lm_stats = lm_ntlm_tools.get_cracking_stats(extraction)

            # Save updated mapping with cracked plaintexts
            lm_ntlm_tools.save_extraction_result(extraction, mapping_file)

            # Generate NTLM attack files if any users have both halves cracked
            if lm_stats["ready_for_ntlm_attack"] > 0:
                ntlm_attack_dir = os.path.join(results_dir, f"{job_id}_ntlm_attack")
                ntlm_files = lm_ntlm_tools.generate_ntlm_attack_files(extraction, ntlm_attack_dir)
                lm_stats["ntlm_attack_files"] = ntlm_files
                logging.info(
                    f"LM job {job_id}: {lm_stats['ready_for_ntlm_attack']} users ready "
                    f"for NTLM case-permutation attack"
                )

            # Add LM stats to job stats
            stats["lm_cracking"] = lm_stats
            logging.info(
                f"LM job {job_id} stats: {lm_stats['unique_halves_cracked']}/{lm_stats['total_unique_halves']} "
                f"halves cracked, {lm_stats['users_both_halves_cracked']} users fully cracked"
            )

        except Exception as e:
            logging.error(f"Failed to process LM job results: {e}")
            stats["lm_processing_error"] = str(e)

    result_file = os.path.join(results_dir, f"{job_id}.json")
    with open(result_file, "w") as f:
        json.dump({
            "job_id": job_id,
            "agent_id": agent_id,
            "completed_at": datetime.now().isoformat(),
            "potfile": potfile,
            "stats": stats,
        }, f, indent=2)

    # Save potfile separately if not empty
    if potfile.strip():
        potfile_path = os.path.join(results_dir, f"{job_id}.potfile")
        with open(potfile_path, "w") as f:
            f.write(potfile)

        # Merge into master potfile for cross-agent sync
        try:
            potfile_mgr = _get_potfile_manager()
            merge_result = potfile_mgr.sync_from_job_potfile(job_id, potfile, agent_id)
            logging.info(
                f"Merged potfile from job {job_id}: "
                f"{merge_result['added']} new, {merge_result['duplicates']} duplicates"
            )
        except Exception as e:
            logging.error(f"Failed to merge potfile from job {job_id}: {e}")

    # Mark job as completed to ignore any stale status updates from agent
    _mark_job_stopped(job_id)

    # Clear agent's current job
    if agent_id in _agent_jobs:
        del _agent_jobs[agent_id]
    _get_db().set_agent_job(agent_id, None)

    return jsonify({"status": "ok"})


@app.route("/api/agent/job/error", methods=["POST"])
@csrf.exempt
def agent_job_error() -> Response:
    """
    Receive job error notification from agent.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    agent_id = data.get("agent_id")
    job_id = data.get("job_id")
    error = data.get("error", "Unknown error")
    logs = data.get("logs", "")

    if not agent_id or not job_id:
        return jsonify({"error": "agent_id and job_id required"}), 400

    # Log error
    logging.error(f"Job {job_id} failed on agent {agent_id}: {error}")

    # Store error details
    results_dir = os.path.join(_get_agent_data_dir(), "results")
    os.makedirs(results_dir, exist_ok=True)

    error_file = os.path.join(results_dir, f"{job_id}_error.json")
    with open(error_file, "w") as f:
        json.dump({
            "job_id": job_id,
            "agent_id": agent_id,
            "failed_at": datetime.now().isoformat(),
            "error": error,
            "logs": logs,
        }, f, indent=2)

    # Mark job as failed to ignore any stale status updates from agent
    _mark_job_stopped(job_id)

    # Clear agent's current job
    if agent_id in _agent_jobs:
        del _agent_jobs[agent_id]
    _get_db().set_agent_job(agent_id, None)

    return jsonify({"status": "ok"})


@app.route("/api/agent/history", methods=["GET"])
@login_required
def agent_job_history() -> Response:
    """
    Get job history for agents.

    Query params:
        agent_id: Optional filter by agent ID
        limit: Max number of results (default 50)
        include_potfile: Include full potfile content (default false)
    """
    agent_id = request.args.get("agent_id")
    limit = int(request.args.get("limit", 50))
    include_potfile = request.args.get("include_potfile", "").lower() == "true"

    results_dir = os.path.join(_get_agent_data_dir(), "results")
    if not os.path.exists(results_dir):
        return jsonify({"jobs": []})

    jobs = []
    for filename in os.listdir(results_dir):
        if not filename.endswith(".json"):
            continue
        # Skip error files (they end with _error.json)
        if filename.endswith("_error.json"):
            continue

        filepath = os.path.join(results_dir, filename)
        try:
            with open(filepath) as f:
                job_data = json.load(f)

            # Filter by agent_id if specified
            if agent_id and job_data.get("agent_id") != agent_id:
                continue

            # Enrich with job metadata (hashcat_args, etc.)
            job_id = job_data.get("job_id", "")
            if job_id:
                job_meta = _get_job_metadata(job_id)
                if job_meta:
                    job_data["hashcat_args"] = job_meta.get("hashcat_args", [])
                    job_data["submitted_at"] = job_meta.get("submitted_at")
                    job_data["job_metadata"] = job_meta.get("metadata", {})

            # Exclude large potfile content by default to prevent response truncation
            # The potfile can be very large (thousands of cracked passwords)
            potfile = job_data.get("potfile", "")
            if not include_potfile and potfile:
                # Replace full potfile with just the line count
                potfile_lines = len(potfile.strip().split('\n')) if potfile.strip() else 0
                job_data["potfile_lines"] = potfile_lines
                job_data["potfile"] = None  # Remove large content

            # Check for corresponding error file
            job_id = job_data.get("job_id", "")
            error_file = os.path.join(results_dir, f"{job_id}_error.json")
            if os.path.exists(error_file):
                with open(error_file) as f:
                    error_data = json.load(f)
                # Truncate large error logs
                if not include_potfile and error_data.get("logs"):
                    logs = error_data["logs"]
                    if len(logs) > 2000:
                        error_data["logs"] = logs[:2000] + "\n... (truncated)"
                job_data["error_info"] = error_data

            # Also include hashcat_logs from stats if present (useful for debugging issues)
            stats = job_data.get("stats", {})
            hashcat_logs = stats.get("hashcat_logs", "")
            if hashcat_logs:
                # Truncate if needed
                if not include_potfile and len(hashcat_logs) > 2000:
                    hashcat_logs = hashcat_logs[:2000] + "\n... (truncated)"
                job_data["hashcat_logs"] = hashcat_logs

            jobs.append(job_data)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to read job file {filename}: {e}")
            continue

    # Sort by completed_at (newest first)
    jobs.sort(key=lambda j: j.get("completed_at", ""), reverse=True)

    # Apply limit
    jobs = jobs[:limit]

    return jsonify({"jobs": jobs})


@app.route("/api/agent/job/<job_id>/potfile", methods=["GET"])
@login_required
def get_job_potfile(job_id: str) -> Response:
    """
    Get the full potfile content for a specific job.

    Returns the potfile as text/plain for download.
    """
    results_dir = os.path.join(_get_agent_data_dir(), "results")

    # First try the separate potfile
    potfile_path = os.path.join(results_dir, f"{job_id}.potfile")
    if os.path.exists(potfile_path):
        with open(potfile_path) as f:
            content = f.read()
        return Response(content, mimetype="text/plain")

    # Fall back to potfile in JSON result
    result_path = os.path.join(results_dir, f"{job_id}.json")
    if os.path.exists(result_path):
        with open(result_path) as f:
            data = json.load(f)
        potfile = data.get("potfile", "")
        return Response(potfile, mimetype="text/plain")

    return jsonify({"error": "Job not found"}), 404


@app.route("/api/agent/potfile/sync", methods=["POST"])
@csrf.exempt
def agent_potfile_sync() -> Response:
    """
    Bidirectional potfile sync endpoint for agents.

    Agent sends their new entries and receives entries from other agents.
    Uses delta sync to minimize data transfer.

    Request JSON:
        agent_id: Agent identifier
        entries: List of new hash:plaintext entries from agent
        last_position: Agent's last known position in master potfile

    Response JSON:
        status: "ok"
        new_entries: List of entries since agent's last_position
        current_position: Current end position of master potfile
        merged_count: Number of new unique entries merged from agent
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    entries = data.get("entries", [])
    last_position = data.get("last_position", 0)

    potfile_mgr = _get_potfile_manager()

    # Merge agent's entries into master potfile
    merge_result = potfile_mgr.merge_entries(entries, agent_id)

    # Get entries since agent's last known position
    new_entries, current_position = potfile_mgr.get_entries_since(last_position)

    return jsonify({
        "status": "ok",
        "new_entries": new_entries,
        "current_position": current_position,
        "merged_count": merge_result.get("added", 0),
    })


@app.route("/api/agent/potfile/full", methods=["GET"])
@csrf.exempt
def agent_potfile_full() -> Response:
    """
    Get the full master potfile content.

    Used by agents for initial sync or recovery.

    Query params:
        agent_id: Agent identifier (for tracking)

    Returns potfile as text/plain with current position in header.
    """
    agent_id = request.args.get("agent_id", "unknown")

    potfile_mgr = _get_potfile_manager()
    content, position = potfile_mgr.get_full_potfile()

    response = Response(content, mimetype="text/plain")
    response.headers["X-Potfile-Position"] = str(position)
    response.headers["X-Agent-Id"] = agent_id
    return response


@app.route("/api/agent/events", methods=["GET"])
def agent_events() -> Response:
    """
    Server-Sent Events endpoint for agent commands.
    Agents connect here to receive real-time job assignments.
    """
    # Get agent ID from authorization header or user-agent
    user_agent = request.headers.get("User-Agent", "")
    agent_id = None
    if "hm1k-agent/" in user_agent:
        agent_id = user_agent.split("hm1k-agent/")[-1]

    if not agent_id:
        return jsonify({"error": "Agent ID required"}), 400

    def generate():
        """Generate SSE events for the agent."""
        # Maximum connection lifetime (4 hours) - agent will reconnect after
        max_connection_time = 4 * 60 * 60  # 4 hours in seconds
        connection_start = time.time()

        try:
            # Send initial connection confirmation
            yield f"event: ping\ndata: {json.dumps({'connected': True, 'agent_id': agent_id})}\n\n"

            # Update agent status
            if agent_id in _agent_registry:
                _agent_registry[agent_id]["sse_connected"] = True
                _agent_registry[agent_id]["sse_connected_at"] = datetime.now().isoformat()
            # Track in shared file for multi-worker visibility
            _track_sse_connection(agent_id, True)

            # Keep connection alive with periodic pings
            last_ping = time.time()
            last_heartbeat_update = time.time()
            while True:
                # Check for pending events for this agent (file-backed for multi-worker)
                commands = _pop_agent_commands(agent_id)
                for event in commands:
                    event_type = event.get("type", "message")
                    event_data = json.dumps(event.get("data", {}))
                    yield f"event: {event_type}\ndata: {event_data}\n\n"

                # Send ping every 30 seconds to keep connection alive
                if time.time() - last_ping > 30:
                    yield f"event: ping\ndata: {json.dumps({'time': datetime.now().isoformat()})}\n\n"
                    last_ping = time.time()
                    # Refresh shared file heartbeat every 30 seconds
                    _track_sse_connection(agent_id, True)

                # Check max connection lifetime - force reconnect to allow worker recycling
                if time.time() - connection_start > max_connection_time:
                    logging.info(f"SSE connection for agent {agent_id} reached max lifetime, closing")
                    yield f"event: reconnect\ndata: {json.dumps({'reason': 'max_lifetime_reached'})}\n\n"
                    break

                time.sleep(1)
        except GeneratorExit:
            # Client disconnected or worker shutting down
            logging.info(f"SSE connection closed for agent {agent_id}")
        finally:
            # Update agent status on disconnect
            if agent_id in _agent_registry:
                _agent_registry[agent_id]["sse_connected"] = False
            # Remove from shared file
            _track_sse_connection(agent_id, False)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


@app.route("/api/agent/list", methods=["GET"])
@login_required
def list_agents() -> Response:
    """
    List all registered agents with their status.
    """
    # Reload from file to get latest state from other workers
    _load_agents()

    agents = []
    for agent_id, agent_data in _agent_registry.items():
        # Check if agent is stale (no heartbeat in 2 minutes)
        last_hb = agent_data.get("last_heartbeat")
        if last_hb:
            try:
                last_hb_time = datetime.fromisoformat(last_hb)
                if (datetime.now() - last_hb_time).total_seconds() > 120:
                    agent_data["status"] = "offline"
            except:
                pass

        # Extract hardware info from agent state
        state = agent_data.get("state", {})
        hardware_raw = state.get("hardware", {})
        hardware = {}
        if hardware_raw:
            if hardware_raw.get("cpu"):
                hardware["cpu"] = hardware_raw["cpu"].get("model", "Unknown")
            if hardware_raw.get("gpus"):
                gpus = hardware_raw["gpus"]
                num_gpus = len(gpus)
                if num_gpus == 1:
                    # Single GPU - show name and memory
                    gpu = gpus[0]
                    gpu_mem = gpu.get("memory_total_mb", 0)
                    gpu_mem_gb = round(gpu_mem / 1024) if gpu_mem else 0
                    hardware["gpu"] = f"{gpu.get('name', 'Unknown')} ({gpu_mem_gb}GB)"
                elif num_gpus > 1:
                    # Multiple GPUs - check if all same model
                    gpu_names = [g.get("name", "Unknown") for g in gpus]
                    unique_names = list(set(gpu_names))
                    if len(unique_names) == 1:
                        # All same model
                        gpu_mem = gpus[0].get("memory_total_mb", 0)
                        gpu_mem_gb = round(gpu_mem / 1024) if gpu_mem else 0
                        hardware["gpu"] = f"{num_gpus}x {unique_names[0]} ({gpu_mem_gb}GB each)"
                    else:
                        # Different models - list first 2
                        gpu_list = unique_names[:2]
                        gpu_summary = ", ".join(gpu_list)
                        if len(unique_names) > 2:
                            gpu_summary += f" +{len(unique_names) - 2} more"
                        hardware["gpu"] = f"{num_gpus} GPUs: {gpu_summary}"
            if hardware_raw.get("memory_total_mb"):
                ram_gb = round(hardware_raw["memory_total_mb"] / 1024)
                hardware["ram"] = f"{ram_gb}GB"
            # Extract disk info
            if hardware_raw.get("disk"):
                # Use root disk for summary, include all disks in detail
                root_disk = next((d for d in hardware_raw["disk"] if d.get("path") == "/"), None)
                if root_disk:
                    hardware["disk_free_gb"] = round(root_disk.get("free_gb", 0), 1)
                    hardware["disk_total_gb"] = round(root_disk.get("total_gb", 0), 1)
                    hardware["disk_used_percent"] = round(root_disk.get("used_percent", 0), 1)
                hardware["disk_details"] = hardware_raw["disk"]

        # Get agent name from state if available
        agent_name = state.get("agent_name") or agent_data.get("name") or f"Agent-{agent_id[:8]}"

        # Get current job info (use file-backed current_job from registry)
        current_job = agent_data.get("current_job")

        # Enrich current_job with metadata (hashcat_args, etc.)
        if current_job and current_job.get("job_id"):
            job_meta = _get_job_metadata(current_job["job_id"])
            if job_meta:
                current_job = dict(current_job)  # Copy to avoid modifying registry
                current_job["hashcat_args"] = job_meta.get("hashcat_args", [])
                current_job["submitted_at"] = job_meta.get("submitted_at")

        # Get agent IP and determine if local
        agent_ip = agent_data.get("ip_address", "")
        is_local = agent_ip in ("127.0.0.1", "::1", "localhost")

        # Get cached resources info
        resources_info = state.get("resources", {})
        cached_resources = resources_info.get("cached", [])

        # For local agents, show server-side resources (they share filesystem)
        if is_local and not cached_resources:
            try:
                manager = _get_resource_manager()
                server_resources = []
                total_size_mb = 0
                by_type = {"wordlists": 0, "rules": 0, "masks": 0}
                for resource_type in ["wordlists", "rules", "masks"]:
                    for r in manager.list_resources(resource_type):
                        size_mb = r.size_bytes / 1024 / 1024
                        server_resources.append({
                            "resource_id": r.resource_id,
                            "name": r.name,
                            "type": r.resource_type,
                            "size_mb": size_mb,
                        })
                        total_size_mb += size_mb
                        by_type[resource_type] += 1
                cached_resources = server_resources
                resources_info = {
                    "cache_size_mb": total_size_mb,
                    "cached_count": len(server_resources),
                    "by_type": by_type,
                    "cached": server_resources,
                    "is_server_resources": True,  # Flag to indicate these are server resources
                }
            except Exception as e:
                logging.warning(f"Failed to get server resources for local agent: {e}")

        # Get software info (hashcat version)
        software_info = state.get("software", {})
        hashcat_versions = software_info.get("hashcat_versions", [])
        current_hashcat = next((h for h in hashcat_versions if h.get("is_current")), None)
        hashcat_version = current_hashcat.get("version") if current_hashcat else None

        # Get update status if any
        update_status = state.get("update_status")

        # Get potfile info
        potfile_info = state.get("potfile", {})

        agents.append({
            "id": agent_id,
            "name": agent_name,
            "status": agent_data.get("status", "unknown"),
            "last_heartbeat": agent_data.get("last_heartbeat"),
            "first_seen": agent_data.get("first_seen"),
            "current_job": current_job,
            "sse_connected": agent_data.get("sse_connected", False),
            "hardware": hardware,
            "ip_address": agent_ip,
            "is_local": is_local,
            "version": state.get("version"),
            "hashcat_version": hashcat_version,
            "hashcat_versions": hashcat_versions,  # Full list of installed versions
            "update_status": update_status,  # Update progress/error info
            "resources": {
                "cache_size_mb": resources_info.get("cache_size_mb", 0),
                "cached_count": resources_info.get("cached_count", 0),
                "by_type": resources_info.get("by_type", {}),
                "cached": cached_resources,
                "is_server_resources": resources_info.get("is_server_resources", False),
            },
            "potfile": {
                "local_entries": potfile_info.get("local_entries", 0),
                "sync_healthy": potfile_info.get("sync_healthy", True),
            },
        })

    return jsonify({"agents": agents})


@app.route("/api/agent/<agent_id>/delete", methods=["POST"])
@login_required
def delete_agent(agent_id: str) -> Response:
    """
    Delete an agent from the registry.

    This removes all agent data including connection info and job history.
    Only administrators can delete agents.
    """
    db = _get_db()
    agent_data = db.get_agent(agent_id)

    if not agent_data:
        return jsonify({"error": "Agent not found"}), 404

    agent_name = agent_data.get("name", f"Agent-{agent_id[:8]}")

    # Don't allow deleting agents that are currently online/working
    status = agent_data.get("status", "unknown")
    if status in ("online", "working"):
        return jsonify({
            "error": f"Cannot delete agent '{agent_name}' while it is {status}. "
                     "Stop the agent first or wait for it to go offline."
        }), 400

    # Remove from database
    db.delete_agent(agent_id)

    logging.info(f"Agent deleted: {agent_name} ({agent_id})")

    return jsonify({
        "success": True,
        "message": f"Agent '{agent_name}' has been deleted"
    })


@app.route("/api/agent/<agent_id>/verify-resources", methods=["POST"])
@login_required
def verify_agent_resources(agent_id: str) -> Response:
    """
    Verify that resource files are accessible on an agent.

    For local agents (127.0.0.1), makes a direct HTTP call to the agent's
    local API. For remote agents, returns an error (not yet supported).

    Request body:
        {
            "paths": ["/path/to/wordlist.txt", "/path/to/rules.rule", ...]
        }

    Returns:
        {
            "success": true/false,
            "results": [...],
            "all_accessible": true/false
        }
    """
    db = _get_db()
    agent_data = db.get_agent(agent_id)

    if not agent_data:
        return jsonify({"error": "Agent not found"}), 404

    if agent_data.get("status") != "online":
        return jsonify({"error": "Agent is offline"}), 400

    data = request.get_json()
    if not data or "paths" not in data:
        return jsonify({"error": "Missing 'paths' in request body"}), 400

    paths = data["paths"]
    if not isinstance(paths, list) or len(paths) == 0:
        return jsonify({"error": "'paths' must be a non-empty list"}), 400

    # Check if this is a local agent
    agent_ip = agent_data.get("ip_address", "")
    is_local = agent_ip in ("127.0.0.1", "::1", "localhost")

    if is_local:
        # Make direct HTTP call to agent's local API
        import requests as http_requests

        # Default agent API port
        agent_port = 8787
        agent_url = f"http://127.0.0.1:{agent_port}/verify-resources"

        try:
            response = http_requests.post(
                agent_url,
                json={"paths": paths},
                timeout=10,
            )

            if response.status_code == 200:
                return jsonify(response.json())
            else:
                return jsonify({
                    "error": f"Agent verification failed: {response.text}",
                    "status_code": response.status_code,
                }), 502
        except http_requests.exceptions.ConnectionError:
            return jsonify({
                "error": "Cannot connect to agent's local API. Is the agent running?",
            }), 503
        except http_requests.exceptions.Timeout:
            return jsonify({
                "error": "Agent verification timed out",
            }), 504
        except Exception as e:
            return jsonify({
                "error": f"Failed to verify resources: {str(e)}",
            }), 500
    else:
        # For remote agents, verification is not yet supported
        # They use ResourceCache which downloads on demand
        return jsonify({
            "error": "Resource verification for remote agents is not yet supported. "
                     "Remote agents download resources on demand from the server.",
            "hint": "Use the Deploy button to pre-cache resources on the agent, "
                    "or the job will attempt to download them when it starts.",
        }), 501


@app.route("/api/agent/<agent_id>/job", methods=["POST"])
@login_required
def assign_job_to_agent(agent_id: str) -> Response:
    """
    Assign a job to a specific agent.

    Accepts either:
    - hash_file: path to hash file on the agent
    - hash_content: raw hash content to be saved by agent

    For LM hash jobs (mode 3000), automatically:
    - Extracts unique 16-char LM halves from pwdump content
    - Saves mapping for later result correlation
    - Sends only unique halves to the agent
    """
    db = _get_db()
    if not db.get_agent(agent_id):
        return jsonify({"error": "Agent not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    job_id = data.get("job_id", f"job-{int(time.time())}")
    hash_file = data.get("hash_file")
    hash_content = data.get("hash_content")
    hash_filename = data.get("hash_filename", "uploaded_hashes.txt")
    hashcat_args = data.get("hashcat_args", [])

    # Must have either hash_file or hash_content
    if not hash_file and not hash_content:
        return jsonify({"error": "hash_file or hash_content required"}), 400

    # Detect if this is an LM job (mode 3000)
    is_lm_job = False
    for i, arg in enumerate(hashcat_args):
        if arg == "-m" and i + 1 < len(hashcat_args) and hashcat_args[i + 1] == "3000":
            is_lm_job = True
            break
        if arg.startswith("-m") and arg[2:] == "3000":
            is_lm_job = True
            break

    # Build job metadata
    job_metadata = data.get("metadata", {})
    job_metadata["job_type"] = "lm" if is_lm_job else "standard"

    # Handle LM job preprocessing
    if is_lm_job and hash_content:
        # Extract LM halves from pwdump content
        extraction = lm_ntlm_tools.extract_lm_halves_from_pwdump(hash_content)

        if extraction.total_unique_halves > 0:
            # Save the original pwdump content and mapping for later
            results_dir = os.path.join(_get_agent_data_dir(), "results")
            os.makedirs(results_dir, exist_ok=True)

            # Save mapping for result correlation
            mapping_file = os.path.join(results_dir, f"{job_id}_lm_mapping.json")
            lm_ntlm_tools.save_extraction_result(extraction, mapping_file)

            # Save original pwdump for reference
            original_file = os.path.join(results_dir, f"{job_id}_original_pwdump.txt")
            with open(original_file, "w") as f:
                f.write(hash_content)

            # Replace hash_content with just the unique LM halves
            hash_content = lm_ntlm_tools.generate_lm_hashfile(extraction)
            hash_filename = "lm_halves.txt"

            # Add LM-specific metadata
            job_metadata["lm_extraction"] = {
                "total_users_with_lm": extraction.total_users_with_lm,
                "total_unique_halves": extraction.total_unique_halves,
                "empty_halves_skipped": extraction.empty_halves_skipped,
                "mapping_file": mapping_file,
                "original_pwdump": original_file,
            }

            logging.info(
                f"LM job {job_id}: extracted {extraction.total_unique_halves} unique halves "
                f"from {extraction.total_users_with_lm} users"
            )
        else:
            logging.warning(f"LM job {job_id}: no LM hashes found in content")

    # Build job data
    job_data = {
        "job_id": job_id,
        "hashcat_args": hashcat_args,
        "priority": data.get("priority", 0),
        "metadata": job_metadata,
    }

    if hash_content:
        # Pass content to agent - agent will save to local file
        job_data["hash_content"] = hash_content
        job_data["hash_filename"] = hash_filename
        logging.info(f"Job {job_id} with uploaded hashes ({len(hash_content)} bytes)")
    else:
        # Use existing file path on agent
        job_data["hash_file"] = hash_file

    # Queue the job assignment event for the agent (file-backed for multi-worker)
    _queue_agent_command(agent_id, {
        "type": "job:assigned",
        "data": job_data
    })

    # Store job metadata for later retrieval (includes hashcat command)
    _store_job_metadata(job_id, {
        "job_id": job_id,
        "agent_id": agent_id,
        "hashcat_args": hashcat_args,
        "submitted_at": datetime.now().isoformat(),
        "metadata": job_metadata,
    })

    logging.info(f"Job {job_id} assigned to agent {agent_id}")

    return jsonify({
        "success": True,
        "job_id": job_id,
        "agent_id": agent_id,
        "job_type": "lm" if is_lm_job else "standard",
    })


@app.route("/api/agent/<agent_id>/stop", methods=["POST"])
@login_required
def stop_agent_job(agent_id: str) -> Response:
    """
    Stop the current job on an agent.
    """
    db = _get_db()
    agent_data = db.get_agent(agent_id)

    if not agent_data:
        return jsonify({"error": "Agent not found"}), 404

    data = request.get_json() or {}
    job_id = data.get("job_id")
    reason = data.get("reason", "Stopped by server")

    # If no job_id specified, get from database current_job
    if not job_id:
        current_job = agent_data.get("current_job")
        if current_job:
            job_id = current_job.get("job_id")

    if not job_id:
        return jsonify({"error": "No active job to stop"}), 400

    # Mark job as stopped to ignore future stale status updates from agent
    _mark_job_stopped(job_id)

    # Clear current_job from database immediately
    db.set_agent_job(agent_id, None)

    # Also clear from in-memory jobs
    if agent_id in _agent_jobs:
        del _agent_jobs[agent_id]

    # Queue the stop event (database-backed for multi-worker)
    _queue_agent_command(agent_id, {
        "type": "job:stop",
        "data": {
            "job_id": job_id,
            "reason": reason,
        }
    })

    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/agent/<agent_id>/pause", methods=["POST"])
@login_required
def pause_agent_job(agent_id: str) -> Response:
    """
    Pause the current job on an agent.
    """
    db = _get_db()
    agent_data = db.get_agent(agent_id)

    if not agent_data:
        return jsonify({"error": "Agent not found"}), 404

    data = request.get_json() or {}
    job_id = data.get("job_id")

    # If no job_id specified, get from database current_job
    if not job_id:
        current_job = agent_data.get("current_job")
        if current_job:
            job_id = current_job.get("job_id")

    if not job_id:
        return jsonify({"error": "No active job to pause"}), 400

    # Queue the pause event (database-backed for multi-worker)
    _queue_agent_command(agent_id, {
        "type": "job:pause",
        "data": {
            "job_id": job_id,
        }
    })

    return jsonify({"success": True, "job_id": job_id})


# ============================================================================
# LM -> NTLM Workflow API
# ============================================================================

def _get_workflow_manager() -> LMtoNTLMWorkflow:
    """Get or create the workflow manager singleton."""
    return LMtoNTLMWorkflow(_get_agent_data_dir())


@app.route("/api/agent/workflow/create", methods=["POST"])
@login_required
def create_lm_ntlm_workflow() -> Response:
    """
    Create a new LM -> NTLM multi-step cracking workflow.

    This automatically:
    1. Extracts LM halves from the pwdump file
    2. Submits an LM brute force job
    3. When complete, combines halves and submits NTLM toggle job
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    agent_id = data.get("agent_id")
    pwdump_content = data.get("pwdump_content")
    workflow_id = data.get("workflow_id")

    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400
    if not pwdump_content:
        return jsonify({"error": "pwdump_content required"}), 400

    db = _get_db()
    if not db.get_agent(agent_id):
        return jsonify({"error": "Agent not found"}), 404

    try:
        # Create workflow and get first job data
        workflow = _get_workflow_manager()
        state, job_data = workflow.create_workflow(agent_id, pwdump_content, workflow_id)

        # Queue the LM job
        _queue_agent_command(agent_id, {
            "type": "job:assigned",
            "data": job_data
        })

        logging.info(f"Created workflow {state.workflow_id} for agent {agent_id}")

        return jsonify({
            "success": True,
            "workflow_id": state.workflow_id,
            "lm_job_id": state.lm_job_id,
            "total_users_with_lm": state.total_users_with_lm,
            "total_unique_halves": state.total_unique_halves,
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"Failed to create workflow: {e}")
        return jsonify({"error": f"Failed to create workflow: {e}"}), 500


@app.route("/api/agent/workflow/list", methods=["GET"])
@login_required
def list_workflows() -> Response:
    """List all LM -> NTLM workflows."""
    try:
        workflow = _get_workflow_manager()
        workflows = workflow.list_workflows()

        return jsonify({
            "workflows": [w.to_dict() for w in workflows]
        })
    except Exception as e:
        logging.error(f"Failed to list workflows: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/workflow/<workflow_id>", methods=["GET"])
@login_required
def get_workflow_status(workflow_id: str) -> Response:
    """Get status of a specific workflow."""
    try:
        workflow = _get_workflow_manager()
        summary = workflow.get_workflow_summary(workflow_id)

        if "error" in summary:
            return jsonify(summary), 404

        return jsonify(summary)
    except Exception as e:
        logging.error(f"Failed to get workflow status: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Job Template API
# =============================================================================

def _get_template_manager() -> JobTemplateManager:
    """Get or create the job template manager singleton."""
    return JobTemplateManager(_get_agent_data_dir())


@app.route("/api/agent/templates", methods=["GET"])
@login_required
def list_job_templates() -> Response:
    """List all job templates (builtin + custom)."""
    try:
        manager = _get_template_manager()
        templates = manager.get_all_templates()
        return jsonify({
            "templates": [t.to_dict() for t in templates]
        })
    except Exception as e:
        logging.error(f"Failed to list templates: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/templates", methods=["POST"])
@login_required
def create_job_template() -> Response:
    """Create a new custom job template."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        template = JobTemplate(
            id="",  # Will be auto-generated
            name=data.get("name", "Unnamed Template"),
            description=data.get("description", ""),
            category=data.get("category", "Custom"),
            hash_mode=data.get("hash_mode"),
            attack_mode=data.get("attack_mode", 0),
            hashcat_args=data.get("hashcat_args"),
            wordlist=data.get("wordlist"),
            rules=data.get("rules"),
            mask=data.get("mask"),
            increment=data.get("increment", False),
            increment_min=data.get("increment_min"),
            increment_max=data.get("increment_max"),
            custom_charset_1=data.get("custom_charset_1"),
            optimized_kernels=data.get("optimized_kernels", False),
            workload_profile=data.get("workload_profile", 3),
            estimated_time=data.get("estimated_time"),
        )

        manager = _get_template_manager()
        created = manager.create_template(template)

        return jsonify({
            "success": True,
            "template": created.to_dict()
        })
    except Exception as e:
        logging.error(f"Failed to create template: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/templates/<template_id>", methods=["GET"])
@login_required
def get_job_template(template_id: str) -> Response:
    """Get a specific job template."""
    try:
        manager = _get_template_manager()
        template = manager.get_template(template_id)
        if not template:
            return jsonify({"error": "Template not found"}), 404
        return jsonify(template.to_dict())
    except Exception as e:
        logging.error(f"Failed to get template: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/templates/<template_id>", methods=["DELETE"])
@login_required
def delete_job_template(template_id: str) -> Response:
    """Delete a custom job template."""
    try:
        manager = _get_template_manager()
        if manager.delete_template(template_id):
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Template not found or is builtin"}), 404
    except Exception as e:
        logging.error(f"Failed to delete template: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/sequences", methods=["GET"])
@login_required
def list_job_sequences() -> Response:
    """List all job sequences (builtin + custom)."""
    try:
        manager = _get_template_manager()
        sequences = manager.get_all_sequences()
        return jsonify({
            "sequences": [s.to_dict() for s in sequences]
        })
    except Exception as e:
        logging.error(f"Failed to list sequences: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/sequences", methods=["POST"])
@login_required
def create_job_sequence() -> Response:
    """Create a new custom job sequence."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        steps = []
        for step_data in data.get("steps", []):
            steps.append(JobSequenceStep(
                template_id=step_data.get("template_id"),
                order=step_data.get("order", 0),
                stop_on_success=step_data.get("stop_on_success", False),
                min_crack_rate=step_data.get("min_crack_rate"),
            ))

        sequence = JobSequence(
            id="",  # Will be auto-generated
            name=data.get("name", "Unnamed Sequence"),
            description=data.get("description", ""),
            steps=steps,
        )

        manager = _get_template_manager()
        created = manager.create_sequence(sequence)

        return jsonify({
            "success": True,
            "sequence": created.to_dict()
        })
    except Exception as e:
        logging.error(f"Failed to create sequence: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/sequences/<sequence_id>", methods=["GET"])
@login_required
def get_job_sequence(sequence_id: str) -> Response:
    """Get a specific job sequence with expanded template details."""
    try:
        manager = _get_template_manager()
        sequence_data = manager.get_sequence_with_templates(sequence_id)
        if not sequence_data:
            return jsonify({"error": "Sequence not found"}), 404
        return jsonify(sequence_data)
    except Exception as e:
        logging.error(f"Failed to get sequence: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/sequences/<sequence_id>", methods=["DELETE"])
@login_required
def delete_job_sequence(sequence_id: str) -> Response:
    """Delete a custom job sequence."""
    try:
        manager = _get_template_manager()
        if manager.delete_sequence(sequence_id):
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Sequence not found or is builtin"}), 404
    except Exception as e:
        logging.error(f"Failed to delete sequence: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Performance Tracking API
# =============================================================================

def _get_performance_tracker() -> PerformanceTracker:
    """Get or create the performance tracker singleton."""
    return PerformanceTracker(_get_agent_data_dir())


@app.route("/api/agent/performance/benchmark", methods=["POST"])
@csrf.exempt
def receive_benchmark_results() -> Response:
    """
    Receive benchmark results from an agent.

    Agents call this after running hashcat -b to report their speeds.
    No login required - agents authenticate via API key in future.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        agent_id = data.get("agent_id")
        if not agent_id:
            return jsonify({"error": "agent_id required"}), 400

        results = data.get("results", [])
        tracker = _get_performance_tracker()

        saved_count = 0
        for result_data in results:
            gpus = [
                GPUMetrics(
                    gpu_index=g.get("gpu_index", g.get("id", 0)),
                    gpu_name=g.get("gpu_name", g.get("name", "Unknown")),
                    speed_hs=g.get("speed_hs", g.get("speed", 0)),
                    temperature=g.get("temperature", g.get("temp")),
                    utilization=g.get("utilization", g.get("util")),
                )
                for g in result_data.get("gpus", result_data.get("devices", []))
            ]

            benchmark = BenchmarkResult(
                agent_id=agent_id,
                hash_mode=result_data.get("hash_mode"),
                total_speed_hs=result_data.get("total_speed_hs", result_data.get("total_speed", 0)),
                gpus=gpus,
                timestamp=data.get("timestamp"),
                hashcat_version=data.get("hashcat_version"),
                cuda_version=data.get("cuda_version"),
                driver_version=data.get("driver_version"),
            )
            tracker.save_benchmark(benchmark)
            saved_count += 1

        # Update benchmark status tracking (file-backed for multi-worker)
        current_status = _get_benchmark_status(agent_id)
        if current_status and current_status.get("status") == "running":
            hashcat_version = data.get("hashcat_version", "unknown")

            if current_status.get("all_versions"):
                # Multi-version benchmark - track which versions have completed
                completed_versions = set(current_status.get("completed_versions", []))
                completed_versions.add(hashcat_version)
                queued_versions = current_status.get("queued_versions", [])
                queued_version_names = {v.get("version") for v in queued_versions}

                # Calculate total completed modes across all versions
                total_completed = len(completed_versions) * len(current_status.get("hash_modes", []))

                if completed_versions >= queued_version_names:
                    # All versions completed
                    _set_benchmark_status(agent_id, {
                        "status": "completed",
                        "completed_at": datetime.now().isoformat(),
                        "completed_modes": total_completed,
                        "total_modes": current_status.get("total_modes", total_completed),
                        "all_versions": True,
                        "completed_versions": list(completed_versions),
                    })
                    logging.info(f"All benchmarks completed for agent {agent_id}: {len(completed_versions)} versions, {total_completed} total modes")
                else:
                    # Still waiting for more versions
                    _set_benchmark_status(agent_id, {
                        **current_status,
                        "completed_versions": list(completed_versions),
                        "completed_modes": total_completed,
                    })
                    logging.info(f"Benchmark progress for agent {agent_id}: {len(completed_versions)}/{len(queued_versions)} versions completed")
            else:
                # Single version benchmark
                _set_benchmark_status(agent_id, {
                    "status": "completed",
                    "completed_at": datetime.now().isoformat(),
                    "completed_modes": saved_count,
                    "total_modes": saved_count,
                })
                logging.info(f"Benchmark completed for agent {agent_id}: {saved_count} modes")

        return jsonify({
            "success": True,
            "saved": saved_count,
        })
    except Exception as e:
        logging.error(f"Failed to save benchmark results: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/performance/job", methods=["POST"])
@csrf.exempt
def receive_job_metrics() -> Response:
    """
    Receive job performance metrics from an agent.

    Agents call this after a job completes to report actual performance.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        agent_id = data.get("agent_id")
        job_id = data.get("job_id")
        if not agent_id or not job_id:
            return jsonify({"error": "agent_id and job_id required"}), 400

        gpus = [
            GPUMetrics(
                gpu_index=g.get("gpu_index", g.get("id", 0)),
                gpu_name=g.get("gpu_name", g.get("name", "Unknown")),
                speed_hs=g.get("speed_hs", g.get("speed", 0)),
                temperature=g.get("temperature", g.get("temp")),
                utilization=g.get("utilization", g.get("util")),
                memory_used_mb=g.get("memory_used_mb"),
            )
            for g in data.get("gpus", data.get("devices", []))
        ]

        metrics = JobPerformanceMetrics(
            agent_id=agent_id,
            job_id=job_id,
            hash_mode=data.get("hash_mode", 0),
            attack_mode=data.get("attack_mode", 0),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            duration_seconds=data.get("duration_seconds", 0),
            total_hashes=data.get("total_hashes", 0),
            hashes_cracked=data.get("hashes_cracked", 0),
            keyspace_total=data.get("keyspace_total", 0),
            keyspace_processed=data.get("keyspace_processed", 0),
            avg_speed_hs=data.get("avg_speed_hs", 0),
            peak_speed_hs=data.get("peak_speed_hs", data.get("avg_speed_hs", 0)),
            speed_samples=data.get("speed_samples", []),
            gpus=gpus,
            max_gpu_temp=data.get("max_gpu_temp"),
            avg_gpu_util=data.get("avg_gpu_util"),
            wordlist_path=data.get("wordlist_path"),
            wordlist_size=data.get("wordlist_size"),
            rules_used=data.get("rules_used"),
            mask_used=data.get("mask_used"),
        )

        tracker = _get_performance_tracker()
        tracker.save_job_metrics(metrics)

        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Failed to save job metrics: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/performance", methods=["GET"])
@login_required
def get_agent_performance(agent_id: str) -> Response:
    """Get performance data for a specific agent."""
    try:
        tracker = _get_performance_tracker()

        benchmarks = tracker.get_agent_benchmarks(agent_id)
        job_history = tracker.get_agent_job_history(agent_id, limit=20)
        benchmark_status = tracker.agent_needs_benchmark(agent_id)

        return jsonify({
            "agent_id": agent_id,
            "benchmark_status": benchmark_status,
            "benchmarks": [b.to_dict() for b in benchmarks],
            "recent_jobs": [j.to_dict() for j in job_history],
        })
    except Exception as e:
        logging.error(f"Failed to get agent performance: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/performance/estimate", methods=["GET"])
@login_required
def estimate_job_duration(agent_id: str) -> Response:
    """
    Estimate job duration based on historical data.

    Query params:
      - hash_mode: Target hash mode (required)
      - attack_mode: Attack mode (default: 0)
      - hash_count: Number of hashes (default: 1)
      - keyspace: Keyspace for brute force
      - wordlist_size: Wordlist size for dictionary attacks
    """
    try:
        hash_mode = request.args.get("hash_mode", type=int)
        if hash_mode is None:
            return jsonify({"error": "hash_mode required"}), 400

        attack_mode = request.args.get("attack_mode", 0, type=int)
        hash_count = request.args.get("hash_count", 1, type=int)
        keyspace = request.args.get("keyspace", type=int)
        wordlist_size = request.args.get("wordlist_size", type=int)

        tracker = _get_performance_tracker()
        estimate = tracker.estimate_job_duration(
            agent_id=agent_id,
            hash_mode=hash_mode,
            attack_mode=attack_mode,
            hash_count=hash_count,
            keyspace=keyspace,
            wordlist_size=wordlist_size,
        )

        if not estimate:
            return jsonify({
                "error": "Insufficient data for estimate",
                "recommendation": "Run benchmarks on this agent first",
            }), 404

        return jsonify(estimate)
    except Exception as e:
        logging.error(f"Failed to estimate job duration: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/benchmark/status", methods=["GET"])
@login_required
def get_agent_benchmark_status(agent_id: str) -> Response:
    """
    Check if an agent needs to run benchmarks and current benchmark run status.

    Returns recommendation for running benchmarks plus active benchmark status.
    """
    try:
        tracker = _get_performance_tracker()
        status = tracker.agent_needs_benchmark(agent_id)

        # Add active benchmark run status (file-backed for multi-worker)
        run_status = _get_benchmark_status(agent_id)
        if run_status:
            status["benchmark_run"] = {
                "status": run_status.get("status"),
                "started_at": run_status.get("started_at"),
                "completed_at": run_status.get("completed_at"),
                "completed_modes": run_status.get("completed_modes", 0),
                "total_modes": run_status.get("total_modes", 0),
            }
        else:
            status["benchmark_run"] = None

        return jsonify(status)
    except Exception as e:
        logging.error(f"Failed to get benchmark status: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/benchmark/run", methods=["POST"])
@csrf.exempt
@login_required
def trigger_agent_benchmark(agent_id: str) -> Response:
    """
    Trigger a benchmark run on an agent.

    The agent will receive the command via heartbeat and run hashcat
    benchmarks for the recommended hash modes.

    Optional JSON body:
        - hash_modes: List of hash modes to benchmark (default: recommended modes)
        - hashcat_binary: Path to specific hashcat binary to use (default: agent's configured binary)
        - all_versions: If true, benchmark all installed hashcat versions sequentially
    """
    db = _get_db()
    agent_data = db.get_agent(agent_id)

    if not agent_data:
        return jsonify({"error": "Agent not found"}), 404

    if agent_data.get("status") != "online":
        return jsonify({"error": "Agent is offline"}), 400

    # Check if agent has a current job
    if agent_data.get("current_job"):
        return jsonify({"error": "Agent is busy with a job"}), 400

    # Get optional parameters from request
    data = request.get_json() or {}
    hash_modes = data.get("hash_modes")  # None means use defaults
    hashcat_binary = data.get("hashcat_binary")  # None means use agent's configured binary
    all_versions = data.get("all_versions", False)  # Benchmark all installed versions

    # Track benchmark status (file-backed for multi-worker)
    modes_to_run = hash_modes or BENCHMARK_HASH_MODES

    if all_versions:
        # Get all installed hashcat versions from agent's software status
        state = agent_data.get("state", {})
        software = state.get("software", {})
        hashcat_versions = software.get("hashcat_versions", [])

        if not hashcat_versions:
            return jsonify({"error": "No hashcat versions found on agent"}), 400

        # Queue benchmark commands for each version
        queued_versions = []
        for version_info in hashcat_versions:
            binary_path = version_info.get("path")
            version = version_info.get("version")
            if binary_path:
                _queue_agent_command(agent_id, {
                    "type": "benchmark",
                    "data": {
                        "hash_modes": hash_modes,
                        "hashcat_binary": binary_path,
                    }
                })
                queued_versions.append({"path": binary_path, "version": version})

        _set_benchmark_status(agent_id, {
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "hash_modes": list(modes_to_run),
            "completed_modes": 0,
            "total_modes": len(modes_to_run) * len(queued_versions),
            "all_versions": True,
            "queued_versions": queued_versions,
        })

        logging.info(f"Benchmark commands queued for agent {agent_id}: {len(queued_versions)} versions")

        return jsonify({
            "success": True,
            "message": f"Benchmark commands sent for {len(queued_versions)} hashcat versions",
            "hash_modes": modes_to_run,
            "versions": queued_versions,
        })

    else:
        # Single version benchmark
        _set_benchmark_status(agent_id, {
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "hash_modes": list(modes_to_run),
            "completed_modes": 0,
            "total_modes": len(modes_to_run),
            "hashcat_binary": hashcat_binary,
        })

        # Queue the benchmark command for the agent
        _queue_agent_command(agent_id, {
            "type": "benchmark",
            "data": {
                "hash_modes": hash_modes,
                "hashcat_binary": hashcat_binary,
            }
        })

        logging.info(f"Benchmark command queued for agent {agent_id}" + (f" (binary: {hashcat_binary})" if hashcat_binary else ""))

        return jsonify({
            "success": True,
            "message": f"Benchmark command sent to agent {agent_id}",
            "hash_modes": modes_to_run,
            "hashcat_binary": hashcat_binary,
        })


@app.route("/api/performance/summary", methods=["GET"])
@login_required
def get_performance_summary() -> Response:
    """Get performance summary for all agents."""
    try:
        tracker = _get_performance_tracker()
        summaries = tracker.get_all_agents_summary()
        return jsonify({
            "agents": summaries,
            "recommended_hash_modes": BENCHMARK_HASH_MODES,
        })
    except Exception as e:
        logging.error(f"Failed to get performance summary: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Resource Management API (Wordlists, Rules, Masks)
# =============================================================================

def _get_resource_manager() -> ResourceManager:
    """Get or create the resource manager singleton."""
    return ResourceManager(_get_agent_data_dir())


def _get_potfile_manager() -> PotfileManager:
    """Get or create the potfile manager singleton."""
    return PotfileManager(_get_agent_data_dir(), MASTER_POTFILE_PATH)


@app.route("/agents/wordlists")
@login_required
def wordlists_page() -> str:
    """Wordlist management page."""
    return render_template("wordlists.html", return_url=get_advanced_mode_return_url())


@app.route("/agents/rules")
@login_required
def rules_page() -> str:
    """Rules management page."""
    return render_template("rules.html", return_url=get_advanced_mode_return_url())


def _get_mask_manager() -> MaskManager:
    """Get or create the mask manager singleton."""
    return MaskManager(_get_agent_data_dir(), _get_performance_tracker())


@app.route("/agents/masks")
@login_required
def masks_page() -> str:
    """Masks management page."""
    return render_template("masks.html", return_url=get_advanced_mode_return_url())


@app.route("/api/resources", methods=["GET"])
@login_required
def list_resources() -> Response:
    """List all resources with optional type filter."""
    try:
        resource_type = request.args.get("type")
        manager = _get_resource_manager()
        resources = manager.list_resources(resource_type=resource_type)
        return jsonify({
            "resources": [r.to_dict() for r in resources],
            "stats": manager.get_stats(),
        })
    except Exception as e:
        logging.error(f"Failed to list resources: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/<resource_type>", methods=["GET"])
@login_required
def list_resources_by_type(resource_type: str) -> Response:
    """List resources of a specific type."""
    try:
        if resource_type not in ["wordlists", "rules", "masks"]:
            return jsonify({"error": "Invalid resource type"}), 400

        manager = _get_resource_manager()
        resources = manager.list_resources(resource_type=resource_type)
        untracked = manager.get_untracked_count()
        return jsonify({
            "resources": [r.to_dict() for r in resources],
            "untracked_count": untracked.get(resource_type, 0),
        })
    except Exception as e:
        logging.error(f"Failed to list resources: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/scan", methods=["POST"])
@login_required
def scan_untracked_resources() -> Response:
    """Scan resource directories for untracked files and import them."""
    try:
        manager = _get_resource_manager()
        imported = manager.scan_untracked()
        return jsonify({
            "success": True,
            "imported_count": len(imported),
            "imported": [r.to_dict() for r in imported],
        })
    except Exception as e:
        logging.error(f"Failed to scan resources: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/migrate", methods=["POST"])
@login_required
def migrate_resource_filenames() -> Response:
    """Rename resource files that have spaces or special characters."""
    try:
        manager = _get_resource_manager()
        renamed = manager.migrate_filenames()
        return jsonify({
            "success": True,
            "renamed_count": len(renamed),
            "renamed": [{"resource_id": r[0], "old_path": r[1], "new_path": r[2]} for r in renamed],
        })
    except Exception as e:
        logging.error(f"Failed to migrate resource filenames: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/untracked", methods=["GET"])
@login_required
def get_untracked_count() -> Response:
    """Get count of untracked files in resource directories."""
    try:
        manager = _get_resource_manager()
        counts = manager.get_untracked_count()
        total = sum(counts.values())
        return jsonify({
            "total": total,
            "by_type": counts,
        })
    except Exception as e:
        logging.error(f"Failed to get untracked count: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/<resource_type>", methods=["POST"])
@login_required
def upload_resource(resource_type: str) -> Response:
    """Upload a new resource."""
    try:
        if resource_type not in ["wordlists", "rules", "masks"]:
            return jsonify({"error": "Invalid resource type"}), 400

        # Check for file upload
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "No file selected"}), 400

        # Get metadata from form
        name = request.form.get("name", file.filename)
        description = request.form.get("description", "")
        tags_str = request.form.get("tags", "")
        tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

        # Read file content
        file_content = file.read()

        # Get current user
        uploaded_by = session.get("username", "unknown")

        manager = _get_resource_manager()
        resource = manager.add_resource(
            name=name,
            resource_type=resource_type,
            file_content=file_content,
            description=description,
            uploaded_by=uploaded_by,
            tags=tags,
        )

        return jsonify({
            "success": True,
            "resource": resource.to_dict(),
        })
    except Exception as e:
        logging.error(f"Failed to upload resource: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/<resource_type>/<resource_id>", methods=["GET"])
@login_required
def get_resource(resource_type: str, resource_id: str) -> Response:
    """Get resource metadata."""
    try:
        manager = _get_resource_manager()
        resource = manager.get_resource(resource_id)
        if not resource:
            return jsonify({"error": "Resource not found"}), 404
        return jsonify(resource.to_dict())
    except Exception as e:
        logging.error(f"Failed to get resource: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/<resource_type>/<resource_id>", methods=["DELETE"])
@login_required
def delete_resource(resource_type: str, resource_id: str) -> Response:
    """Delete a resource."""
    try:
        manager = _get_resource_manager()
        if manager.delete_resource(resource_id):
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Resource not found or is builtin"}), 404
    except Exception as e:
        logging.error(f"Failed to delete resource: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/<resource_type>/<resource_id>", methods=["PATCH"])
@login_required
def update_resource(resource_type: str, resource_id: str) -> Response:
    """Update resource metadata."""
    try:
        data = request.get_json()
        manager = _get_resource_manager()
        resource = manager.update_resource(
            resource_id=resource_id,
            name=data.get("name"),
            description=data.get("description"),
            tags=data.get("tags"),
        )
        if not resource:
            return jsonify({"error": "Resource not found"}), 404
        return jsonify({
            "success": True,
            "resource": resource.to_dict(),
        })
    except Exception as e:
        logging.error(f"Failed to update resource: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/<resource_type>/<resource_id>/download", methods=["GET"])
@login_required
def download_resource(resource_type: str, resource_id: str) -> Response:
    """Download a resource file."""
    try:
        manager = _get_resource_manager()
        resource = manager.get_resource(resource_id)
        if not resource:
            return jsonify({"error": "Resource not found"}), 404

        file_path = manager.get_resource_file(resource_id)
        if not file_path:
            return jsonify({"error": "Resource file not found"}), 404

        return send_file(
            file_path,
            as_attachment=True,
            download_name=resource.name,
        )
    except Exception as e:
        logging.error(f"Failed to download resource: {e}")
        return jsonify({"error": str(e)}), 500


# Agent resource sync endpoint (no login required for agents)
@app.route("/api/agent/resources/<resource_type>", methods=["GET"])
def agent_list_resources(resource_type: str) -> Response:
    """List resources for agent sync."""
    try:
        if resource_type not in ["wordlists", "rules", "masks"]:
            return jsonify({"error": "Invalid resource type"}), 400

        manager = _get_resource_manager()
        resources = manager.list_resources(resource_type=resource_type)
        return jsonify({
            "resources": [r.to_dict() for r in resources],
        })
    except Exception as e:
        logging.error(f"Failed to list resources for agent: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/resources/<resource_type>/<resource_id>", methods=["GET"])
def agent_download_resource(resource_type: str, resource_id: str) -> Response:
    """Download a resource file for agent sync."""
    try:
        manager = _get_resource_manager()
        resource = manager.get_resource(resource_id)
        if not resource:
            return jsonify({"error": "Resource not found"}), 404

        file_path = manager.get_resource_file(resource_id)
        if not file_path:
            return jsonify({"error": "Resource file not found"}), 404

        return send_file(file_path, as_attachment=True, download_name=resource.name)
    except Exception as e:
        logging.error(f"Failed to download resource for agent: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/resources/<resource_type>/<resource_id>/meta", methods=["GET"])
def agent_get_resource_meta(resource_type: str, resource_id: str) -> Response:
    """Get resource metadata for agent sync."""
    try:
        manager = _get_resource_manager()
        resource = manager.get_resource(resource_id)
        if not resource:
            return jsonify({"error": "Resource not found"}), 404
        return jsonify(resource.to_dict())
    except Exception as e:
        logging.error(f"Failed to get resource metadata for agent: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/resources/<resource_type>/<resource_id>/compressed", methods=["GET"])
def agent_download_resource_compressed(resource_type: str, resource_id: str) -> Response:
    """
    Download compressed (.zst) version of a resource for agent sync.

    Returns 404 if compressed version doesn't exist.
    Agents should fall back to uncompressed download in that case.
    """
    try:
        manager = _get_resource_manager()
        resource = manager.get_resource(resource_id)
        if not resource:
            return jsonify({"error": "Resource not found"}), 404

        compressed_path = manager.get_compressed_file(resource_id)
        if not compressed_path:
            return jsonify({"error": "Compressed version not available"}), 404

        return send_file(
            compressed_path,
            as_attachment=True,
            download_name=resource.name + ".zst",
        )
    except Exception as e:
        logging.error(f"Failed to download compressed resource for agent: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/compression/stats", methods=["GET"])
@login_required
def get_compression_stats() -> Response:
    """Get compression statistics for all resources."""
    try:
        manager = _get_resource_manager()
        stats = manager.get_compression_stats()
        return jsonify(stats)
    except Exception as e:
        logging.error(f"Failed to get compression stats: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/compression/queue", methods=["GET"])
@login_required
def get_compression_queue() -> Response:
    """Get status of the background compression queue."""
    try:
        manager = _get_resource_manager()
        status = manager.get_compression_queue_status()
        return jsonify(status)
    except Exception as e:
        logging.error(f"Failed to get compression queue status: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/compression/queue-all", methods=["POST"])
@login_required
def queue_all_compression() -> Response:
    """
    Queue all uncompressed resources for background compression.

    This is useful for batch-compressing existing resources that were
    imported before compression was enabled.
    """
    try:
        manager = _get_resource_manager()
        result = manager.queue_all_uncompressed()
        return jsonify(result)
    except Exception as e:
        logging.error(f"Failed to queue resources for compression: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resources/<resource_type>/<resource_id>/compress", methods=["POST"])
@login_required
def compress_resource(resource_type: str, resource_id: str) -> Response:
    """
    Compress a resource file using zstd.

    This is typically run as a background task for large files.
    Returns immediately if compression is already in progress or complete.
    """
    try:
        manager = _get_resource_manager()
        resource = manager.get_resource(resource_id)
        if not resource:
            return jsonify({"error": "Resource not found"}), 404

        # Check if already compressed
        if resource.compressed_path and Path(resource.compressed_path).exists():
            return jsonify({
                "status": "already_compressed",
                "compressed_path": resource.compressed_path,
                "compressed_size": resource.compressed_size,
            })

        # Compress (this may take a while for large files)
        success = manager.compress_resource(resource_id)

        if success:
            # Reload to get updated info
            resource = manager.get_resource(resource_id)
            return jsonify({
                "status": "compressed",
                "compressed_path": resource.compressed_path,
                "compressed_size": resource.compressed_size,
                "original_size": resource.size_bytes,
                "ratio": resource.size_bytes / resource.compressed_size if resource.compressed_size else 0,
            })
        else:
            return jsonify({"error": "Compression failed"}), 500

    except Exception as e:
        logging.error(f"Failed to compress resource: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/deploy-resources", methods=["POST"])
@login_required
def deploy_resources_to_agent(agent_id: str) -> Response:
    """
    Deploy selected resources to an agent.

    Request body:
    {
        "resource_ids": ["id1", "id2"],
        "force": false  // Set to true to bypass disk space warnings
    }

    Response:
    {
        "success": true,
        "queued": 5,
        "total_size_gb": 12.5,
        "warning": "Low disk space...",  // Only if space is tight
        "requires_confirmation": true     // True if warning present and force=false
    }
    """
    db = _get_db()
    agent_data = db.get_agent(agent_id)

    if not agent_data:
        return jsonify({"error": "Agent not found"}), 404

    data = request.get_json() or {}
    resource_ids = data.get("resource_ids", [])
    force = data.get("force", False)
    include_rules = data.get("include_rules", True)  # Default to True for backward compatibility

    if not resource_ids:
        return jsonify({"error": "No resource_ids provided"}), 400

    # Get resource details and calculate total size
    manager = _get_resource_manager()
    resources = []
    total_size_bytes = 0

    for rid in resource_ids:
        resource = manager.get_resource(rid)
        if resource:
            resources.append(resource)
            total_size_bytes += resource.size_bytes

    # Optionally include all rules (they're small and commonly needed)
    added_rules_count = 0
    if include_rules:
        all_rules = manager.list_resources(resource_type="rules")
        for rule in all_rules:
            if rule.resource_id not in resource_ids:
                resources.append(rule)
                total_size_bytes += rule.size_bytes
                added_rules_count += 1

    if not resources:
        return jsonify({"error": "No valid resources found"}), 400

    total_size_gb = total_size_bytes / (1024 ** 3)

    # Get agent's available disk space (agent_data already loaded from database above)
    hardware = agent_data.get("state", {}).get("hardware", {})
    disk_info = hardware.get("disk", [])

    # Find root disk or first available disk
    root_disk = next((d for d in disk_info if d.get("path") == "/"), None)
    if not root_disk and disk_info:
        root_disk = disk_info[0]

    warning = None
    requires_confirmation = False

    if root_disk:
        free_gb = root_disk.get("free_gb", 0)
        total_gb = root_disk.get("total_gb", 1)

        # Calculate space after deployment
        space_after = free_gb - total_size_gb
        percent_used_after = ((total_gb - space_after) / total_gb) * 100 if total_gb > 0 else 100

        # Check if deployment would exceed 90% usage
        if percent_used_after > 90:
            warning = (
                f"Warning: This deployment ({total_size_gb:.1f} GB) would leave the agent "
                f"with only {space_after:.1f} GB free ({percent_used_after:.1f}% disk used). "
                f"Agent currently has {free_gb:.1f} GB free."
            )
            requires_confirmation = not force
    else:
        warning = "Warning: Unable to determine agent disk space. Proceed with caution."
        requires_confirmation = not force

    # If warning and not forced, return without deploying
    if requires_confirmation:
        return jsonify({
            "success": False,
            "warning": warning,
            "requires_confirmation": True,
            "total_size_gb": round(total_size_gb, 2),
            "resource_count": len(resources),
        })

    # Queue resource sync command to agent
    _queue_agent_command(agent_id, {
        "type": "resource:sync",
        "data": {
            "resource_ids": [r.resource_id for r in resources],
        }
    })

    return jsonify({
        "success": True,
        "queued": len(resources),
        "total_size_gb": round(total_size_gb, 2),
        "warning": warning,
        "requires_confirmation": False,
        "rules_added": added_rules_count,
    })


@app.route("/api/agent/<agent_id>/clean-resources", methods=["POST"])
@login_required
def clean_agent_resources(agent_id: str) -> Response:
    """
    Remove stale resources from an agent that no longer exist on the server.

    Response:
    {
        "success": true,
        "valid_resource_count": 50,
        "message": "Cleanup command sent to agent"
    }
    """
    db = _get_db()
    if not db.get_agent(agent_id):
        return jsonify({"error": "Agent not found"}), 404

    # Get all valid resource IDs from server
    manager = _get_resource_manager()
    valid_ids = []

    for resource_type in ["wordlists", "rules", "masks"]:
        resources = manager.list_resources(resource_type=resource_type)
        valid_ids.extend([r.resource_id for r in resources])

    # Queue resource clean command to agent
    _queue_agent_command(agent_id, {
        "type": "resource:clean",
        "data": {
            "valid_resource_ids": valid_ids,
        }
    })

    return jsonify({
        "success": True,
        "valid_resource_count": len(valid_ids),
        "message": "Cleanup command sent to agent",
    })


@app.route("/api/resources/categories", methods=["GET"])
@login_required
def get_resource_categories() -> Response:
    """
    Get resources organized by size category.

    Categories:
    - small: < 100 MB
    - medium: 100 MB - 1 GB
    - large: 1 GB - 10 GB
    - extra_large: > 10 GB
    """
    manager = _get_resource_manager()
    wordlists = manager.list_resources(resource_type="wordlists")

    # Define size thresholds (in bytes)
    SMALL_MAX = 100 * 1024 * 1024         # 100 MB
    MEDIUM_MAX = 1 * 1024 * 1024 * 1024   # 1 GB
    LARGE_MAX = 10 * 1024 * 1024 * 1024   # 10 GB

    categories = {
        "small": [],
        "medium": [],
        "large": [],
        "extra_large": [],
    }

    for wl in wordlists:
        size = wl.size_bytes
        wl_dict = wl.to_dict()
        wl_dict["size_gb"] = round(size / (1024 ** 3), 2)
        wl_dict["size_mb"] = round(size / (1024 ** 2), 1)

        if size < SMALL_MAX:
            wl_dict["category"] = "small"
            categories["small"].append(wl_dict)
        elif size < MEDIUM_MAX:
            wl_dict["category"] = "medium"
            categories["medium"].append(wl_dict)
        elif size < LARGE_MAX:
            wl_dict["category"] = "large"
            categories["large"].append(wl_dict)
        else:
            wl_dict["category"] = "extra_large"
            categories["extra_large"].append(wl_dict)

    # Sort each category by size
    for cat in categories:
        categories[cat].sort(key=lambda x: x["size_bytes"])

    # Calculate totals
    totals = {
        "small": {
            "count": len(categories["small"]),
            "total_size_gb": round(sum(w["size_bytes"] for w in categories["small"]) / (1024 ** 3), 2),
        },
        "medium": {
            "count": len(categories["medium"]),
            "total_size_gb": round(sum(w["size_bytes"] for w in categories["medium"]) / (1024 ** 3), 2),
        },
        "large": {
            "count": len(categories["large"]),
            "total_size_gb": round(sum(w["size_bytes"] for w in categories["large"]) / (1024 ** 3), 2),
        },
        "extra_large": {
            "count": len(categories["extra_large"]),
            "total_size_gb": round(sum(w["size_bytes"] for w in categories["extra_large"]) / (1024 ** 3), 2),
        },
    }

    return jsonify({
        "categories": categories,
        "totals": totals,
    })


# =============================================================================
# Masks Management API
# =============================================================================

@app.route("/api/masks", methods=["GET"])
@login_required
def list_masks() -> Response:
    """List all masks grouped by length."""
    try:
        manager = _get_mask_manager()
        grouped = manager.get_masks_by_length()
        stats = manager.get_stats()

        # Convert to serializable format
        grouped_data = {}
        for length, masks in grouped.items():
            grouped_data[str(length)] = []
            for mask in masks:
                mask_dict = mask.to_dict()
                # Add formatted values
                mask_dict["keyspace_formatted"] = format_keyspace(mask.keyspace)
                crack_time = manager.estimate_crack_time(mask.keyspace)
                mask_dict["crack_time_seconds"] = crack_time
                mask_dict["crack_time_formatted"] = format_duration(crack_time) if crack_time else "N/A"
                grouped_data[str(length)].append(mask_dict)

        return jsonify({
            "masks_by_length": grouped_data,
            "stats": {
                "mask_count": stats["mask_count"],
                "group_count": stats["group_count"],
                "fastest_ntlm_speed": stats["fastest_ntlm_speed"],
                "fastest_ntlm_speed_formatted": format_keyspace(int(stats["fastest_ntlm_speed"])) + "/s" if stats["fastest_ntlm_speed"] else "N/A",
            },
        })
    except Exception as e:
        logging.error(f"Failed to list masks: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/masks", methods=["POST"])
@login_required
def add_masks() -> Response:
    """Add one or more masks."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        manager = _get_mask_manager()
        created_by = session.get("username", "unknown")

        # Get custom charsets if provided (handle null from JS)
        custom_charsets = data.get("custom_charsets") or {}

        # Check for single mask or bulk input
        if "pattern" in data:
            # Single mask
            mask, error = manager.add_mask(
                pattern=data["pattern"],
                description=data.get("description", ""),
                tags=data.get("tags", []),
                custom_charsets=custom_charsets,
                created_by=created_by,
            )
            if mask:
                mask_dict = mask.to_dict()
                mask_dict["keyspace_formatted"] = format_keyspace(mask.keyspace)
                crack_time = manager.estimate_crack_time(mask.keyspace)
                mask_dict["crack_time_formatted"] = format_duration(crack_time) if crack_time else "N/A"
                return jsonify({"success": True, "mask": mask_dict})
            else:
                return jsonify({"error": error}), 400

        elif "file_content" in data:
            # File import with embedded charsets
            file_content = data["file_content"]
            patterns, file_charsets = manager.parse_mask_file(file_content)

            # File charsets override/merge with provided custom_charsets
            if file_charsets:
                custom_charsets = {**custom_charsets, **file_charsets}

            added, errors = manager.add_masks_bulk(
                patterns=patterns,
                custom_charsets=custom_charsets if custom_charsets else None,
                created_by=created_by,
            )

            return jsonify({
                "success": len(added) > 0,
                "added_count": len(added),
                "added": [m.to_dict() for m in added],
                "errors": errors,
                "charsets_detected": file_charsets,
            })

        elif "patterns" in data:
            # Bulk input (list of patterns)
            patterns = data["patterns"]
            if isinstance(patterns, str):
                patterns = manager.parse_mask_input(patterns)

            added, errors = manager.add_masks_bulk(
                patterns=patterns,
                custom_charsets=custom_charsets,
                created_by=created_by,
            )

            return jsonify({
                "success": len(added) > 0,
                "added_count": len(added),
                "added": [m.to_dict() for m in added],
                "errors": errors,
            })

        else:
            return jsonify({"error": "No pattern or patterns provided"}), 400

    except Exception as e:
        logging.error(f"Failed to add mask: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/masks/validate", methods=["POST"])
@login_required
def validate_mask() -> Response:
    """Validate a mask without saving."""
    try:
        data = request.get_json()
        pattern = data.get("pattern", "")
        custom_charsets = data.get("custom_charsets", {})

        manager = _get_mask_manager()
        is_valid, error = manager.validate_mask(pattern, custom_charsets)

        if is_valid:
            length = manager.calculate_mask_length(pattern)
            keyspace = manager.calculate_keyspace(pattern, custom_charsets)
            crack_time = manager.estimate_crack_time(keyspace)

            return jsonify({
                "valid": True,
                "length": length,
                "keyspace": keyspace,
                "keyspace_formatted": format_keyspace(keyspace),
                "crack_time_seconds": crack_time,
                "crack_time_formatted": format_duration(crack_time) if crack_time else "N/A",
            })
        else:
            return jsonify({"valid": False, "error": error})

    except Exception as e:
        logging.error(f"Failed to validate mask: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/masks/<mask_id>", methods=["GET"])
@login_required
def get_mask(mask_id: str) -> Response:
    """Get a mask by ID."""
    try:
        manager = _get_mask_manager()
        mask = manager.get_mask(mask_id)
        if not mask:
            return jsonify({"error": "Mask not found"}), 404

        mask_dict = mask.to_dict()
        mask_dict["keyspace_formatted"] = format_keyspace(mask.keyspace)
        crack_time = manager.estimate_crack_time(mask.keyspace)
        mask_dict["crack_time_formatted"] = format_duration(crack_time) if crack_time else "N/A"

        return jsonify(mask_dict)
    except Exception as e:
        logging.error(f"Failed to get mask: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/masks/<mask_id>", methods=["PATCH"])
@login_required
def update_mask(mask_id: str) -> Response:
    """Update mask metadata."""
    try:
        data = request.get_json()
        manager = _get_mask_manager()

        mask, error = manager.update_mask(
            mask_id=mask_id,
            description=data.get("description"),
            tags=data.get("tags"),
        )

        if mask:
            return jsonify({"success": True, "mask": mask.to_dict()})
        else:
            return jsonify({"error": error}), 404

    except Exception as e:
        logging.error(f"Failed to update mask: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/masks/<mask_id>", methods=["DELETE"])
@login_required
def delete_mask(mask_id: str) -> Response:
    """Delete a mask."""
    try:
        manager = _get_mask_manager()
        success, error = manager.delete_mask(mask_id)

        if success:
            return jsonify({"success": True})
        else:
            return jsonify({"error": error}), 404

    except Exception as e:
        logging.error(f"Failed to delete mask: {e}")
        return jsonify({"error": str(e)}), 500


# Mask Groups API

@app.route("/api/mask-groups", methods=["GET"])
@login_required
def list_mask_groups() -> Response:
    """List all mask groups."""
    try:
        manager = _get_mask_manager()
        groups = manager.list_groups()

        groups_data = []
        for group in groups:
            group_dict = group.to_dict()
            group_dict["mask_count"] = len(group.mask_ids)
            groups_data.append(group_dict)

        return jsonify({"groups": groups_data})
    except Exception as e:
        logging.error(f"Failed to list mask groups: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/mask-groups", methods=["POST"])
@login_required
def create_mask_group() -> Response:
    """Create a new mask group."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        manager = _get_mask_manager()

        # Handle null from JS
        custom_charsets = data.get("custom_charsets") or {}

        group, error = manager.create_group(
            name=data.get("name", ""),
            description=data.get("description", ""),
            mask_ids=data.get("mask_ids", []),
            custom_charsets=custom_charsets,
        )

        if group:
            return jsonify({"success": True, "group": group.to_dict()})
        else:
            return jsonify({"error": error}), 400

    except Exception as e:
        logging.error(f"Failed to create mask group: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/mask-groups/<group_id>", methods=["GET"])
@login_required
def get_mask_group(group_id: str) -> Response:
    """Get a mask group with its masks."""
    try:
        manager = _get_mask_manager()
        result = manager.get_group_with_masks(group_id)

        if not result:
            return jsonify({"error": "Group not found"}), 404

        group, masks = result
        group_dict = group.to_dict()
        group_dict["masks"] = []

        for mask in masks:
            mask_dict = mask.to_dict()
            mask_dict["keyspace_formatted"] = format_keyspace(mask.keyspace)
            crack_time = manager.estimate_crack_time(mask.keyspace)
            mask_dict["crack_time_formatted"] = format_duration(crack_time) if crack_time else "N/A"
            group_dict["masks"].append(mask_dict)

        return jsonify(group_dict)

    except Exception as e:
        logging.error(f"Failed to get mask group: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/mask-groups/<group_id>", methods=["PATCH"])
@login_required
def update_mask_group(group_id: str) -> Response:
    """Update a mask group."""
    try:
        data = request.get_json()
        manager = _get_mask_manager()

        # Only pass custom_charsets if it was explicitly provided
        custom_charsets = None
        if "custom_charsets" in data:
            custom_charsets = data.get("custom_charsets") or {}

        group, error = manager.update_group(
            group_id=group_id,
            name=data.get("name"),
            description=data.get("description"),
            mask_ids=data.get("mask_ids"),
            custom_charsets=custom_charsets,
        )

        if group:
            return jsonify({"success": True, "group": group.to_dict()})
        else:
            return jsonify({"error": error}), 400

    except Exception as e:
        logging.error(f"Failed to update mask group: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/mask-groups/<group_id>", methods=["DELETE"])
@login_required
def delete_mask_group(group_id: str) -> Response:
    """Delete a mask group."""
    try:
        manager = _get_mask_manager()
        success, error = manager.delete_group(group_id)

        if success:
            return jsonify({"success": True})
        else:
            return jsonify({"error": error}), 404

    except Exception as e:
        logging.error(f"Failed to delete mask group: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/mask-groups/<group_id>/export", methods=["GET"])
@login_required
def export_mask_group(group_id: str) -> Response:
    """Export a mask group as .hcmask file."""
    try:
        manager = _get_mask_manager()
        group = manager.get_group(group_id)

        if not group:
            return jsonify({"error": "Group not found"}), 404

        content = manager.export_group_hcmask(group_id)
        if not content:
            return jsonify({"error": "Failed to export group"}), 500

        # Create response with file download
        response = make_response(content)
        response.headers["Content-Type"] = "text/plain"
        response.headers["Content-Disposition"] = f"attachment; filename={group.name.replace(' ', '_')}.hcmask"
        return response

    except Exception as e:
        logging.error(f"Failed to export mask group: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Software Management API (Hashcat, NVIDIA Drivers, AMD Drivers)
# =============================================================================

def _get_software_manager():
    """Get or create the software manager singleton."""
    from app.software_manager import get_software_manager
    return get_software_manager(_get_agent_data_dir())


@app.route("/agents/software")
@login_required
def software_page() -> str:
    """Software management page (Hashcat & Drivers)."""
    return render_template("software.html", return_url=get_advanced_mode_return_url())


@app.route("/api/software", methods=["GET"])
@login_required
def list_all_software() -> Response:
    """List all software packages with stats."""
    try:
        manager = _get_software_manager()
        packages = manager.list_packages()
        return jsonify({
            "packages": [p.to_dict() for p in packages],
            "stats": manager.get_stats(),
        })
    except Exception as e:
        logging.error(f"Failed to list software: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/software/<software_type>", methods=["GET"])
@login_required
def list_software_by_type(software_type: str) -> Response:
    """List software packages of a specific type."""
    try:
        if software_type not in ["hashcat", "nvidia", "amd"]:
            return jsonify({"error": "Invalid software type. Must be: hashcat, nvidia, amd"}), 400

        manager = _get_software_manager()
        packages = manager.list_packages(software_type=software_type)
        current = manager.get_current(software_type)

        return jsonify({
            "packages": [p.to_dict() for p in packages],
            "current_version": current.version if current else None,
            "current_package_id": current.package_id if current else None,
        })
    except Exception as e:
        logging.error(f"Failed to list {software_type} packages: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/software/<software_type>", methods=["POST"])
@login_required
def upload_software(software_type: str) -> Response:
    """Upload a new software package."""
    try:
        if software_type not in ["hashcat", "nvidia", "amd"]:
            return jsonify({"error": "Invalid software type. Must be: hashcat, nvidia, amd"}), 400

        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        # Get optional parameters
        version = request.form.get("version")
        description = request.form.get("description", "")
        notes = request.form.get("notes", "")
        make_current = request.form.get("make_current", "false").lower() == "true"

        # Save to temp file
        temp_dir = os.path.join(os.path.dirname(__file__), "data", "temp")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, secure_filename(file.filename))
        file.save(temp_path)

        try:
            manager = _get_software_manager()
            package = manager.add_package(
                file_path=temp_path,
                software_type=software_type,
                version=version,
                description=description,
                uploaded_by=current_user.id,
                notes=notes,
                make_current=make_current,
            )
            return jsonify({
                "success": True,
                "package": package.to_dict(),
            })
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"Failed to upload software: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/software/<software_type>/<package_id>", methods=["DELETE"])
@login_required
def delete_software(software_type: str, package_id: str) -> Response:
    """Delete a software package."""
    try:
        manager = _get_software_manager()
        package = manager.get_package(package_id)

        if not package:
            return jsonify({"error": "Package not found"}), 404

        if package.software_type != software_type:
            return jsonify({"error": "Package type mismatch"}), 400

        if manager.remove_package(package_id):
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Failed to remove package"}), 500

    except Exception as e:
        logging.error(f"Failed to delete software: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/software/<software_type>/<package_id>/current", methods=["PUT"])
@login_required
def set_software_current(software_type: str, package_id: str) -> Response:
    """Mark a software package as the current version."""
    try:
        manager = _get_software_manager()
        package = manager.get_package(package_id)

        if not package:
            return jsonify({"error": "Package not found"}), 404

        if package.software_type != software_type:
            return jsonify({"error": "Package type mismatch"}), 400

        if manager.set_current(package_id):
            return jsonify({
                "success": True,
                "current_version": package.version,
            })
        else:
            return jsonify({"error": "Failed to set current version"}), 500

    except Exception as e:
        logging.error(f"Failed to set current version: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/software/<software_type>/<package_id>/download", methods=["GET"])
@login_required
def download_software(software_type: str, package_id: str) -> Response:
    """Download a software package file."""
    try:
        manager = _get_software_manager()
        package = manager.get_package(package_id)

        if not package:
            return jsonify({"error": "Package not found"}), 404

        if package.software_type != software_type:
            return jsonify({"error": "Package type mismatch"}), 400

        if not os.path.exists(package.file_path):
            return jsonify({"error": "Package file not found"}), 404

        return send_file(
            package.file_path,
            as_attachment=True,
            download_name=package.filename,
        )

    except Exception as e:
        logging.error(f"Failed to download software: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/software/<software_type>/<package_id>/download", methods=["GET"])
@csrf.exempt
def agent_download_software(software_type: str, package_id: str) -> Response:
    """
    Agent-specific software download endpoint.

    Allows agents to download software packages without user login.
    Verifies request is from a registered agent via User-Agent header.
    """
    # Verify request is from an agent
    user_agent = request.headers.get("User-Agent", "")
    if "hm1k-agent/" not in user_agent:
        return jsonify({"error": "Agent authentication required"}), 401

    agent_id = user_agent.split("hm1k-agent/")[-1]

    # Verify agent is registered
    agent = _get_agent(agent_id)
    if not agent:
        logging.warning(f"Download attempt from unknown agent: {agent_id}")
        return jsonify({"error": "Unknown agent"}), 401

    try:
        manager = _get_software_manager()
        package = manager.get_package(package_id)

        if not package:
            return jsonify({"error": "Package not found"}), 404

        if package.software_type != software_type:
            return jsonify({"error": "Package type mismatch"}), 400

        if not os.path.exists(package.file_path):
            return jsonify({"error": "Package file not found"}), 404

        logging.info(f"Agent {agent_id} downloading {software_type} package: {package_id}")

        return send_file(
            package.file_path,
            as_attachment=True,
            download_name=package.filename,
        )

    except Exception as e:
        logging.error(f"Failed to download software for agent: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/cert", methods=["GET"])
@csrf.exempt
def get_server_certificate() -> Response:
    """
    Serve the server's SSL certificate for agent trust.

    Agents fetch this during initialization to enable certificate verification
    for all subsequent HTTPS communications. This endpoint is unauthenticated
    as agents need the certificate before they can establish secure communication.
    """
    cert_path = os.path.join(os.path.dirname(__file__), "cert.pem")
    if not os.path.exists(cert_path):
        return jsonify({"error": "Server certificate not found"}), 404

    return send_file(
        cert_path,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name="hm1k-server.pem",
    )


@app.route("/api/agent/<agent_id>/software", methods=["GET"])
@login_required
def get_agent_software_status(agent_id: str) -> Response:
    """Get the software status for an agent."""
    try:
        manager = _get_software_manager()
        status = manager.get_agent_status(agent_id)

        if not status:
            return jsonify({
                "agent_id": agent_id,
                "hashcat_versions": [],
                "nvidia_driver": None,
                "amd_driver": None,
                "last_updated": None,
            })

        return jsonify(status.to_dict())

    except Exception as e:
        logging.error(f"Failed to get agent software status: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/software", methods=["POST"])
@login_required
def update_agent_software_status(agent_id: str) -> Response:
    """Update the software status for an agent (called by agent during heartbeat)."""
    try:
        data = request.get_json()
        manager = _get_software_manager()

        status = manager.update_agent_status(
            agent_id=agent_id,
            hashcat_versions=data.get("hashcat_versions"),
            nvidia_driver=data.get("nvidia_driver"),
            amd_driver=data.get("amd_driver"),
        )

        return jsonify({"success": True, "status": status.to_dict()})

    except Exception as e:
        logging.error(f"Failed to update agent software status: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/deploy/hashcat/<package_id>", methods=["POST"])
@login_required
def deploy_hashcat_to_agent(agent_id: str, package_id: str) -> Response:
    """Deploy a hashcat version to an agent."""
    try:
        manager = _get_software_manager()
        package = manager.get_package(package_id)

        if not package:
            return jsonify({"error": "Package not found"}), 404

        if package.software_type != "hashcat":
            return jsonify({"error": "Package is not a hashcat package"}), 400

        # Check if agent is online
        agent = _get_agent(agent_id)
        if not agent or agent.get("status") != "online":
            return jsonify({"error": "Agent is not online"}), 400

        # Queue deployment command
        data = request.get_json() or {}
        make_current = data.get("make_current", True)

        _queue_agent_command(agent_id, {
            "type": "software:install",
            "data": {
                "software_type": "hashcat",
                "package_id": package_id,
                "version": package.version,
                "filename": package.filename,
                "sha256": package.sha256,
                "size_bytes": package.size_bytes,
                "make_current": make_current,
                "download_url": f"/api/agent/software/hashcat/{package_id}/download",
            }
        })

        return jsonify({
            "success": True,
            "message": f"Deployment of hashcat {package.version} queued for agent {agent_id}",
            "package": package.to_dict(),
        })

    except Exception as e:
        logging.error(f"Failed to deploy hashcat to agent: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/hashcat/set-current", methods=["POST"])
@login_required
def set_agent_hashcat_version(agent_id: str) -> Response:
    """
    Set the current hashcat version for an agent.

    This updates the agent's config to use the specified hashcat binary path.
    Used after deployment or to switch between installed versions.

    Request body:
        {"binary": "/opt/hashcat/hashcat-7.1.2/hashcat"}
        or
        {"version": "7.1.2"}  (will use /opt/hashcat/hashcat-{version}/hashcat)
    """
    try:
        data = request.get_json() or {}
        binary = data.get("binary")
        version = data.get("version")

        if not binary and not version:
            return jsonify({"error": "Must specify 'binary' path or 'version'"}), 400

        if not binary and version:
            binary = f"/opt/hashcat/hashcat-{version}/hashcat"

        # Check if agent is online
        agent = _get_agent(agent_id)
        if not agent or agent.get("status") != "online":
            return jsonify({"error": "Agent is not online"}), 400

        # Queue command to update agent config
        _queue_agent_command(agent_id, {
            "type": "config:update",
            "data": {
                "section": "hashcat",
                "updates": {
                    "binary": binary
                }
            }
        })

        return jsonify({
            "success": True,
            "message": f"Hashcat config update queued for agent {agent_id}",
            "binary": binary,
        })

    except Exception as e:
        logging.error(f"Failed to set agent hashcat version: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/deploy/driver/<driver_type>/<package_id>", methods=["POST"])
@login_required
def deploy_driver_to_agent(agent_id: str, driver_type: str, package_id: str) -> Response:
    """Deploy a GPU driver to an agent."""
    try:
        if driver_type not in ["nvidia", "amd"]:
            return jsonify({"error": "Invalid driver type. Must be: nvidia, amd"}), 400

        manager = _get_software_manager()
        package = manager.get_package(package_id)

        if not package:
            return jsonify({"error": "Package not found"}), 404

        if package.software_type != driver_type:
            return jsonify({"error": f"Package is not a {driver_type} driver package"}), 400

        # Check if agent is online
        agent = _get_agent(agent_id)
        if not agent or agent.get("status") != "online":
            return jsonify({"error": "Agent is not online"}), 400

        # Queue deployment command
        _queue_agent_command(agent_id, {
            "type": "software:install",
            "data": {
                "software_type": driver_type,
                "package_id": package_id,
                "version": package.version,
                "filename": package.filename,
                "sha256": package.sha256,
                "size_bytes": package.size_bytes,
                "download_url": f"/api/agent/software/{driver_type}/{package_id}/download",
            }
        })

        return jsonify({
            "success": True,
            "message": f"Deployment of {driver_type} driver {package.version} queued for agent {agent_id}",
            "package": package.to_dict(),
        })

    except Exception as e:
        logging.error(f"Failed to deploy driver to agent: {e}")
        return jsonify({"error": str(e)}), 500


# Agent wheel distribution endpoints
AGENT_WHEEL_DIR = os.path.join(os.path.dirname(__file__), "internal", "hm1k-agent", "dist")


@app.route("/api/agent/wheel/info", methods=["GET"])
@login_required
def get_agent_wheel_info() -> Response:
    """Get information about the available agent wheel package."""
    try:
        if not os.path.isdir(AGENT_WHEEL_DIR):
            return jsonify({"error": "Agent wheel directory not found"}), 404

        # Find the latest wheel file
        wheel_files = [f for f in os.listdir(AGENT_WHEEL_DIR) if f.endswith(".whl")]
        if not wheel_files:
            return jsonify({"error": "No agent wheel files found"}), 404

        # Get the most recent wheel
        wheel_files.sort(key=lambda f: os.path.getmtime(os.path.join(AGENT_WHEEL_DIR, f)), reverse=True)
        wheel_file = wheel_files[0]
        wheel_path = os.path.join(AGENT_WHEEL_DIR, wheel_file)

        # Parse version from filename (hm1k_agent-0.1.0-py3-none-any.whl)
        import re
        version_match = re.search(r"hm1k_agent-([^-]+)-", wheel_file)
        version = version_match.group(1) if version_match else "unknown"

        # Calculate SHA256
        import hashlib
        sha256 = hashlib.sha256()
        with open(wheel_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return jsonify({
            "filename": wheel_file,
            "version": version,
            "size_bytes": os.path.getsize(wheel_path),
            "sha256": sha256.hexdigest(),
            "modified": datetime.fromtimestamp(os.path.getmtime(wheel_path)).isoformat(),
            "download_url": "/api/agent/wheel/download",
        })

    except Exception as e:
        logging.error(f"Failed to get agent wheel info: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/wheel/download", methods=["GET"])
@csrf.exempt  # Allow agents to download without CSRF token
def download_agent_wheel() -> Response:
    """Download the agent wheel package."""
    try:
        if not os.path.isdir(AGENT_WHEEL_DIR):
            return jsonify({"error": "Agent wheel directory not found"}), 404

        # Find the latest wheel file
        wheel_files = [f for f in os.listdir(AGENT_WHEEL_DIR) if f.endswith(".whl")]
        if not wheel_files:
            return jsonify({"error": "No agent wheel files found"}), 404

        # Get the most recent wheel
        wheel_files.sort(key=lambda f: os.path.getmtime(os.path.join(AGENT_WHEEL_DIR, f)), reverse=True)
        wheel_file = wheel_files[0]

        return send_from_directory(
            AGENT_WHEEL_DIR,
            wheel_file,
            as_attachment=True,
            download_name=wheel_file,
        )

    except Exception as e:
        logging.error(f"Failed to serve agent wheel: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<agent_id>/update", methods=["POST"])
@login_required
def trigger_agent_update(agent_id: str) -> Response:
    """Trigger an agent to update itself to the latest version."""
    try:
        db = _get_db()
        agent = db.get_agent(agent_id)

        if not agent:
            return jsonify({"error": "Agent not found"}), 404

        if agent.get("status") not in ("online", "idle"):
            return jsonify({"error": "Agent is not online"}), 400

        # Get wheel info
        if not os.path.isdir(AGENT_WHEEL_DIR):
            return jsonify({"error": "Agent wheel not available on server"}), 404

        wheel_files = [f for f in os.listdir(AGENT_WHEEL_DIR) if f.endswith(".whl")]
        if not wheel_files:
            return jsonify({"error": "No agent wheel files found"}), 404

        wheel_files.sort(key=lambda f: os.path.getmtime(os.path.join(AGENT_WHEEL_DIR, f)), reverse=True)
        wheel_file = wheel_files[0]
        wheel_path = os.path.join(AGENT_WHEEL_DIR, wheel_file)

        # Calculate SHA256
        import hashlib
        sha256 = hashlib.sha256()
        with open(wheel_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        # Parse version
        import re
        version_match = re.search(r"hm1k_agent-([^-]+)-", wheel_file)
        version = version_match.group(1) if version_match else "unknown"

        # Queue update command
        _queue_agent_command(agent_id, {
            "type": "agent:update",
            "data": {
                "download_url": "/api/agent/wheel/download",
                "filename": wheel_file,
                "version": version,
                "sha256": sha256.hexdigest(),
                "size_bytes": os.path.getsize(wheel_path),
            }
        })

        # Set initial update status
        update_status = {
            "status": "queued",
            "version": version,
            "message": f"Update to v{version} queued",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        state = agent.get("state", {})
        state["update_status"] = update_status
        db.update_agent_state(agent_id, state)

        agent_name = agent.get("state", {}).get("agent_name") or agent.get("name", agent_id[:8])
        logging.info(f"Agent update queued for {agent_name} ({agent_id})")

        return jsonify({
            "success": True,
            "message": f"Update to version {version} queued for agent {agent_name}",
            "version": version,
        })

    except Exception as e:
        logging.error(f"Failed to trigger agent update: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/update/status", methods=["POST"])
@csrf.exempt
def agent_update_status() -> Response:
    """
    Receive agent update status reports.

    Called by agents during the update process to report progress or errors.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    agent_id = data.get("agent_id")
    version = data.get("version")
    status = data.get("status")  # downloading, installed, restarting, error
    message = data.get("message")
    error = data.get("error")

    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    db = _get_db()
    agent = db.get_agent(agent_id)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    # Store update status in agent state
    update_status = {
        "version": version,
        "status": status,
        "message": message,
        "error": error,
        "timestamp": datetime.now().isoformat(),
    }

    # Update the agent's update_status field
    state = agent.get("state", {})
    state["update_status"] = update_status
    db.update_agent_state(agent_id, state)

    agent_name = state.get("agent_name") or agent.get("name", agent_id[:8])

    if status == "error":
        logging.warning(f"Agent update failed for {agent_name}: {error or message}")
    else:
        logging.info(f"Agent update status for {agent_name}: {status} - {message}")

    return jsonify({"status": "ok"})


# Comparison results storage directory
COMPARISON_RESULTS_DIR = os.path.join(os.path.dirname(__file__), "benchmark_results")


@app.route("/api/ai/benchmark/comparison/save", methods=["POST"])
@login_required
def save_comparison_results() -> Response:
    """Save model comparison benchmark results to a file."""
    # Ensure directory exists
    os.makedirs(COMPARISON_RESULTS_DIR, exist_ok=True)

    data = request.get_json()
    comparison_id = data.get("comparison_id", f"compare_{int(time.time())}")

    # Build result data
    result_data = {
        "id": comparison_id,
        "timestamp": data.get("timestamp", datetime.now().isoformat()),
        "server_id": data.get("server_id"),
        "temperature": data.get("temperature"),
        "prompt": data.get("prompt"),
        "preset": data.get("preset", "custom"),
        "results": data.get("results", []),
        "models": [r.get("model") for r in data.get("results", [])],
    }

    # Save to file
    filename = f"{comparison_id}.json"
    filepath = os.path.join(COMPARISON_RESULTS_DIR, filename)

    with open(filepath, "w") as f:
        json.dump(result_data, f, indent=2)

    return jsonify({"success": True, "saved_to": filename})


@app.route("/api/ai/benchmark/comparison/history", methods=["GET"])
@login_required
def get_comparison_history() -> Response:
    """Get list of saved comparison results."""
    os.makedirs(COMPARISON_RESULTS_DIR, exist_ok=True)

    comparisons = []
    for filename in os.listdir(COMPARISON_RESULTS_DIR):
        if filename.endswith(".json") and filename.startswith("compare_"):
            filepath = os.path.join(COMPARISON_RESULTS_DIR, filename)
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                    comparisons.append({
                        "id": data.get("id", filename.replace(".json", "")),
                        "timestamp": data.get("timestamp"),
                        "models": data.get("models", []),
                        "prompt": data.get("prompt", "")[:100],
                        "preset": data.get("preset", "custom"),
                        "server_id": data.get("server_id"),
                    })
            except Exception as e:
                logging.error(f"Error loading comparison file {filename}: {e}")

    # Sort by timestamp descending
    comparisons.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return jsonify({"comparisons": comparisons})


@app.route("/api/ai/benchmark/comparison/<comparison_id>", methods=["GET"])
@login_required
def get_comparison_result(comparison_id: str) -> Response:
    """Get a specific comparison result."""
    filename = f"{comparison_id}.json"
    filepath = os.path.join(COMPARISON_RESULTS_DIR, filename)

    if not os.path.exists(filepath):
        return jsonify({"error": "Comparison not found"}), 404

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/benchmark/comparison/<comparison_id>", methods=["DELETE"])
@login_required
def delete_comparison_result(comparison_id: str) -> Response:
    """Delete a comparison result."""
    filename = f"{comparison_id}.json"
    filepath = os.path.join(COMPARISON_RESULTS_DIR, filename)

    if not os.path.exists(filepath):
        return jsonify({"error": "Comparison not found"}), 404

    try:
        os.remove(filepath)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# Module-Level Initialization (runs on import for both Flask dev server and Gunicorn)
# ============================================================================

# Initialize local HIBP database if configured (uses binary search - no memory loading)
# This runs at module import time, so it executes in every Gunicorn worker process
hibp_local_db_path = os.getenv("HIBP_LOCAL_DB_PATH", "").strip()
if hibp_local_db_path:
    from app.hibp_checker import init_local_hibp_database, get_local_db_status
    import time as _hibp_time
    # Normalize path for cross-platform compatibility
    hibp_local_db_path = os.path.normpath(hibp_local_db_path)
    if os.path.exists(hibp_local_db_path):
        _hibp_start = _hibp_time.time()
        _success, _message, _estimated_entries = init_local_hibp_database(hibp_local_db_path)
        _hibp_duration = _hibp_time.time() - _hibp_start
        if _success:
            _db_status = get_local_db_status()
            # Log to stderr so it appears in Gunicorn error log
            import sys
            print(f"[HM1K] Local HIBP database ready: ~{_estimated_entries:,} hashes ({_db_status.get('mode', 'unknown')} mode, {_hibp_duration:.2f}s)", file=sys.stderr)
        else:
            import sys
            print(f"[HM1K] Warning: Could not initialize local HIBP database: {_message}", file=sys.stderr)
    else:
        import sys
        print(f"[HM1K] Warning: HIBP database file does not exist: {hibp_local_db_path}", file=sys.stderr)


if __name__ == "__main__":
    import time as _time
    from app.timing_stats import get_timing_stats
    from app.hibp_checker import get_local_db_status

    timing = get_timing_stats()
    timing.start_startup_timing()

    # Validate libraries and files before starting the app
    validate_libraries()
    validate_files()
    validate_permissions()

    # Validate required environment variables (SECRET_KEY already validated at module level)
    if not ADMIN_USERNAME:
        raise ValueError(
            "Environment variable ADMIN_USERNAME must be set in a local .env file."
        )

    if not ADMIN_PASSWORD_HASH:
        raise ValueError(
            "Environment variable ADMIN_PASSWORD_HASH must be set in a local .env file."
        )

    # HIBP database initialization moved to module level (runs for both Flask dev server and Gunicorn)
    # Show status message for Flask dev server (Gunicorn workers already logged this)
    _hibp_local_db_path = os.getenv("HIBP_LOCAL_DB_PATH", "").strip()
    if _hibp_local_db_path:
        _db_status = get_local_db_status()
        if _db_status["loaded"]:
            print(f"\n--> Local HIBP database ready: ~{_db_status['hash_count']:,} hashes ({_db_status.get('mode', 'unknown')} mode)")
        else:
            print(f"\n--> Warning: Local HIBP database configured but not loaded")
    else:
        print("\n--> No local HIBP database configured (HIBP_LOCAL_DB_PATH not set)")

    # Preload master potfile cache at startup for instant first request
    if MASTER_POTFILE_ENABLED:
        print(f"\n--> Master potfile enabled, checking: {MASTER_POTFILE_PATH}")
        # Normalize path for cross-platform compatibility
        master_path_normalized = os.path.normpath(MASTER_POTFILE_PATH)
        if os.path.exists(master_path_normalized):
            print(f"--> Loading master potfile cache: {master_path_normalized}")
            potfile_start = _time.time()
            cache = get_master_cache()
            cache.load(master_path_normalized)
            potfile_duration = _time.time() - potfile_start
            stats = cache.get_stats()
            if stats:
                timing.record_potfile_load(potfile_duration, stats['ntlm_count'])
                print(f"--> Master potfile cache ready: {stats['ntlm_count']:,} hashes ({potfile_duration:.2f}s)")
        else:
            print(f"--> Warning: Master potfile not found at: {master_path_normalized}")
    else:
        print("\n--> Master potfile disabled (MASTER_POTFILE_ENABLED not set to true)")

    # Record startup completion
    startup = timing.finish_startup_timing()
    if startup:
        print(f"\n--> Startup complete in {startup.total_startup_seconds:.2f}s")

    # Start Flask application with threading for better performance
    # Threading allows handling multiple concurrent requests (important for report page)
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"), debug=False, threaded=True)
