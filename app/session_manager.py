"""
Session Manager for HM1K

Manages analysis sessions to allow users to save, recall, and switch between
different password audit projects. Each session contains:
- All analysis JSON files (pw_*.json, cracking_stats_table.json, etc.)
- AAIA results (aaia_results.json, ai_analysis/ folder)
- Session metadata (name, timestamp, user, source file info)

Sessions are stored in data/sessions/<session_id>/ folders.
The current active session is tracked per-user in Flask session storage.
"""

import os
import json
import shutil
import hashlib
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Any

# Import Flask session for per-user session tracking
try:
    from flask import session as flask_session, has_request_context
    FLASK_SESSION_AVAILABLE = True
except ImportError:
    FLASK_SESSION_AVAILABLE = False
    flask_session = None
    has_request_context = lambda: False


@dataclass
class SessionMetadata:
    """Metadata for a saved session."""
    session_id: str
    name: str  # Display name (auto-generated from company_name + project_description)
    created_at: str  # ISO timestamp
    updated_at: str  # ISO timestamp
    created_by: str  # Username who created the session

    # Company and project identification (for trend analysis grouping)
    company_name: str = ""  # Required for trend analysis - e.g., "ACME Corporation"
    project_description: str = ""  # Required for trend analysis - e.g., "Q4 2024 Annual Pentest"

    # Source file information
    source_files: dict[str, str] = field(default_factory=dict)  # {pwdump: filename, potfile: filename}
    source_hash: str = ""  # Hash of source data for staleness detection

    # Statistics snapshot
    total_accounts: int = 0
    cracked_accounts: int = 0
    crack_rate: float = 0.0

    # AAIA state
    aaia_generated: bool = False
    aaia_timestamp: str = ""

    # Optional notes
    notes: str = ""

    # Privacy setting - if True, only owner and superadmin can see this session
    private: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'SessionMetadata':
        """
        Create SessionMetadata from a dictionary, handling backward compatibility.

        Old sessions may not have company_name or project_description fields.
        Migrate them by parsing the existing name field.
        """
        # Handle backward compatibility for old sessions without new fields
        if 'company_name' not in data:
            data['company_name'] = ""
        if 'project_description' not in data:
            data['project_description'] = ""
        if 'private' not in data:
            data['private'] = False

        # If we have a name but no company/project, try to infer from name
        if data.get('name') and not data.get('company_name'):
            # Old sessions had names like "Analysis - filename.ntds"
            # Mark them as needing migration
            data['company_name'] = "Unknown"
            data['project_description'] = data.get('name', '')
        return cls(**data)


class SessionManager:
    """
    Manages analysis sessions for HM1K.

    Session folder structure:
    data/
      sessions/
        <session_id>/
          session_meta.json
          cracking_stats_table.json
          account_data.json
          pw_*.json
          aaia_results.json
          ai_analysis/
            *.md, *.json
      current_session.json  # {session_id: "abc123", user: "admin"}
    """

    BASE_DIR = "data"
    SESSIONS_DIR = "data/sessions"
    CURRENT_SESSION_FILE = "data/current_session.json"

    # Files that belong to a session (analysis outputs)
    SESSION_FILES = [
        "cracking_stats_table.json",
        "account_data.json",
        "pw_account_pie.json",
        "pw_ntlm_hash_pie.json",
        "pw_length_distribution.json",
        "pw_top_passwords.json",
        "pw_substrings.json",
        "pw_dict_words.json",
        "pw_reuse_table.json",
        "pw_fails_min_length.json",
        "pw_fails_complexity.json",
        "pw_fails_blank.json",
        "pw_fails_max_age.json",
        "pw_lm_hashes.json",
        "pw_bad_practices.json",
        "aaia_results.json",
    ]

    # Directories that belong to a session
    SESSION_DIRS = [
        "ai_analysis",
    ]

    def __init__(self):
        """Initialize the session manager and ensure directories exist."""
        os.makedirs(self.SESSIONS_DIR, exist_ok=True)
        os.makedirs(self.BASE_DIR, exist_ok=True)

    def generate_session_id(self) -> str:
        """Generate a unique session ID."""
        return uuid.uuid4().hex[:12]

    def compute_source_hash(self, pwdump_path: str | None = None,
                           potfile_path: str | None = None,
                           account_data: list[dict] | None = None) -> str:
        """
        Compute a hash of the source data to detect staleness.

        Can use either file paths or processed account_data.
        """
        hasher = hashlib.sha256()

        if account_data:
            # Hash based on account data (more reliable)
            # Handle both formats:
            # - List of dicts: [{"username": "x", "ntlm_hash": "y"}, ...]
            # - Dict with usernames as keys: {"username": {"ntlm_hash": "y", ...}, ...}
            if isinstance(account_data, dict):
                # Convert dict format to list for consistent hashing
                for username in sorted(account_data.keys()):
                    data = account_data[username]
                    ntlm_hash = data.get("ntlm_hash", "") if isinstance(data, dict) else ""
                    hasher.update(username.encode())
                    hasher.update(ntlm_hash.encode())
            else:
                # List format - use sorted usernames + hashes for consistency
                for account in sorted(account_data, key=lambda x: x.get("username") or ""):
                    username = account.get("username") or ""
                    ntlm_hash = account.get("ntlm_hash") or ""
                    hasher.update(username.encode())
                    hasher.update(ntlm_hash.encode())
        else:
            # Hash based on file contents
            for path in [pwdump_path, potfile_path]:
                if path and os.path.exists(path):
                    with open(path, 'rb') as f:
                        hasher.update(f.read())

        return hasher.hexdigest()[:16]

    def create_session(self, name: str, username: str,
                      source_files: dict[str, str] | None = None,
                      source_hash: str = "",
                      company_name: str = "",
                      project_description: str = "") -> SessionMetadata:
        """
        Create a new session.

        Args:
            name: Display name (auto-generated from company_name + project_description if not provided)
            username: Username of the creator
            source_files: Dict with pwdump and potfile filenames
            source_hash: Hash of source data
            company_name: Company name for trend analysis grouping (e.g., "ACME Corporation")
            project_description: Project description (e.g., "Q4 2024 Annual Pentest")

        Returns:
            SessionMetadata for the new session
        """
        session_id = self.generate_session_id()
        now = datetime.now().isoformat()

        # Auto-generate display name from company + project if both provided
        if company_name and project_description and not name:
            name = f"{company_name} - {project_description}"
        elif not name:
            name = "Unnamed Session"

        metadata = SessionMetadata(
            session_id=session_id,
            name=name,
            created_at=now,
            updated_at=now,
            created_by=username,
            company_name=company_name,
            project_description=project_description,
            source_files=source_files or {},
            source_hash=source_hash
        )

        # Create session directory
        session_dir = os.path.join(self.SESSIONS_DIR, session_id)
        os.makedirs(session_dir, exist_ok=True)

        # Create ai_analysis subdirectory
        os.makedirs(os.path.join(session_dir, "ai_analysis"), exist_ok=True)

        # Save metadata
        self._save_session_metadata(metadata)

        return metadata

    def get_session(self, session_id: str) -> SessionMetadata | None:
        """Get metadata for a specific session."""
        meta_path = os.path.join(self.SESSIONS_DIR, session_id, "session_meta.json")
        if not os.path.exists(meta_path):
            return None

        with open(meta_path, 'r') as f:
            data = json.load(f)

        return SessionMetadata.from_dict(data)

    def list_sessions(self, username: str | None = None,
                      include_non_private: bool = False) -> list[SessionMetadata]:
        """
        List all sessions with flexible filtering.

        Args:
            username: If provided, filter by creator (unless include_non_private is True)
            include_non_private: If True, also include sessions from other users
                                 that are not marked as private (for admin users)

        Returns sessions sorted by updated_at (most recent first).

        Permission model:
        - username=None: Returns ALL sessions (superadmin mode)
        - username + include_non_private=False: Returns only user's own sessions
        - username + include_non_private=True: Returns user's sessions + other non-private sessions
        """
        sessions = []

        if not os.path.exists(self.SESSIONS_DIR):
            return sessions

        for session_id in os.listdir(self.SESSIONS_DIR):
            session_dir = os.path.join(self.SESSIONS_DIR, session_id)
            if not os.path.isdir(session_dir):
                continue

            metadata = self.get_session(session_id)
            if metadata:
                if username is None:
                    # Superadmin mode - return all sessions
                    sessions.append(metadata)
                elif metadata.created_by == username:
                    # User's own session - always include
                    sessions.append(metadata)
                elif include_non_private and not metadata.private:
                    # Admin mode - include other users' non-private sessions
                    sessions.append(metadata)

        # Sort by updated_at descending
        sessions.sort(key=lambda s: s.updated_at, reverse=True)
        return sessions

    def list_companies(self, username: str | None = None) -> list[str]:
        """
        Get a list of distinct company names from all sessions.

        Args:
            username: Optional filter by session creator

        Returns:
            Sorted list of unique company names (excluding empty/Unknown)
        """
        sessions = self.list_sessions(username=username)
        companies = set()
        for session in sessions:
            if session.company_name and session.company_name != "Unknown":
                companies.add(session.company_name)
        return sorted(companies)

    def list_sessions_by_company(self, company_name: str,
                                  username: str | None = None) -> list[SessionMetadata]:
        """
        Get all sessions for a specific company.

        Args:
            company_name: Company name to filter by
            username: Optional filter by session creator

        Returns:
            Sessions for that company, sorted by created_at (oldest first for trend analysis)
        """
        sessions = self.list_sessions(username=username)
        company_sessions = [s for s in sessions if s.company_name == company_name]
        # Sort by created_at ascending (oldest first) for trend analysis
        company_sessions.sort(key=lambda s: s.created_at)
        return company_sessions

    def get_sessions_grouped_by_company(self,
                                        username: str | None = None) -> dict[str, list[SessionMetadata]]:
        """
        Get all sessions grouped by company name.

        Args:
            username: Optional filter by session creator

        Returns:
            Dict mapping company_name -> list of sessions (sorted by date)
        """
        sessions = self.list_sessions(username=username)
        grouped: dict[str, list[SessionMetadata]] = {}

        for session in sessions:
            company = session.company_name or "Unknown"
            if company not in grouped:
                grouped[company] = []
            grouped[company].append(session)

        # Sort each company's sessions by created_at ascending
        for company in grouped:
            grouped[company].sort(key=lambda s: s.created_at)

        return grouped

    def get_company_suggestions(self, partial: str = "",
                                 username: str | None = None) -> list[str]:
        """
        Get company name suggestions for autocomplete.

        Args:
            partial: Partial company name to filter by (case-insensitive)
            username: Optional filter by session creator

        Returns:
            List of matching company names, sorted alphabetically
        """
        companies = self.list_companies(username=username)
        if not partial:
            return companies

        partial_lower = partial.lower()
        return [c for c in companies if partial_lower in c.lower()]

    def update_session(self, session_id: str, **updates) -> SessionMetadata | None:
        """
        Update session metadata.

        Accepts keyword arguments matching SessionMetadata fields.
        Always updates updated_at timestamp.
        """
        metadata = self.get_session(session_id)
        if not metadata:
            return None

        # Update fields
        for key, value in updates.items():
            if hasattr(metadata, key):
                setattr(metadata, key, value)

        metadata.updated_at = datetime.now().isoformat()
        self._save_session_metadata(metadata)

        return metadata

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session and all its data.

        Returns True if successful, False if session not found.
        """
        session_dir = os.path.join(self.SESSIONS_DIR, session_id)
        if not os.path.exists(session_dir):
            return False

        # Check if this is the current session
        current = self.get_current_session()
        if current and current.get("session_id") == session_id:
            self.clear_current_session()

        # Delete the entire session directory
        shutil.rmtree(session_dir)
        return True

    def get_current_session(self) -> dict[str, str] | None:
        """
        Get the current active session info for the current user.

        Returns dict with session_id and user, or None if no active session.

        Uses Flask session storage for per-user tracking when available.
        Falls back to global file for backward compatibility.
        """
        # Use Flask session if available (per-user isolation)
        if FLASK_SESSION_AVAILABLE and has_request_context():
            session_id = flask_session.get('current_session_id')
            username = flask_session.get('current_session_user')
            set_at = flask_session.get('current_session_set_at')

            if session_id:
                # Verify session still exists
                if self.get_session(session_id):
                    return {
                        "session_id": session_id,
                        "user": username or "unknown",
                        "set_at": set_at or datetime.now().isoformat()
                    }
                else:
                    # Session was deleted, clear from Flask session
                    flask_session.pop('current_session_id', None)
                    flask_session.pop('current_session_user', None)
                    flask_session.pop('current_session_set_at', None)
                    return None

            return None

        # Fallback to global file (legacy/non-HTTP contexts)
        if not os.path.exists(self.CURRENT_SESSION_FILE):
            return None

        try:
            with open(self.CURRENT_SESSION_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def set_current_session(self, session_id: str, username: str) -> bool:
        """
        Set the current active session for the current user.

        Returns False if session doesn't exist.

        Uses Flask session storage for per-user tracking when available.
        Falls back to global file for backward compatibility.
        """
        if not self.get_session(session_id):
            return False

        # Use Flask session if available (per-user isolation)
        if FLASK_SESSION_AVAILABLE and has_request_context():
            flask_session['current_session_id'] = session_id
            flask_session['current_session_user'] = username
            flask_session['current_session_set_at'] = datetime.now().isoformat()
            flask_session.modified = True  # Ensure session is saved
            return True

        # Fallback to global file (legacy/non-HTTP contexts)
        try:
            with open(self.CURRENT_SESSION_FILE, 'w') as f:
                json.dump({
                    "session_id": session_id,
                    "user": username,
                    "set_at": datetime.now().isoformat()
                }, f, indent=2)
            return True
        except IOError:
            return False

    def clear_current_session(self):
        """
        Clear the current session pointer for the current user.

        Uses Flask session storage when available, falls back to global file.
        """
        # Clear from Flask session if available
        if FLASK_SESSION_AVAILABLE and has_request_context():
            flask_session.pop('current_session_id', None)
            flask_session.pop('current_session_user', None)
            flask_session.pop('current_session_set_at', None)
            flask_session.modified = True

        # Also clear global file (for backward compatibility)
        if os.path.exists(self.CURRENT_SESSION_FILE):
            try:
                os.remove(self.CURRENT_SESSION_FILE)
            except OSError:
                pass  # Ignore if file can't be removed

    def get_session_data_path(self, filename: str, session_id: str | None = None) -> str:
        """
        Get the path to a data file, either in the current session or specified session.

        For backward compatibility, if no session is active, returns the legacy
        data/ path.

        Args:
            filename: Name of the data file (e.g., "cracking_stats_table.json")
            session_id: Optional session ID (uses current session if not provided)

        Returns:
            Full path to the data file
        """
        if session_id is None:
            current = self.get_current_session()
            session_id = current.get("session_id") if current else None

        if session_id:
            return os.path.join(self.SESSIONS_DIR, session_id, filename)
        else:
            # Legacy fallback - read from base data/ folder
            return os.path.join(self.BASE_DIR, filename)

    def get_session_dir(self, session_id: str | None = None) -> str:
        """
        Get the directory path for a session.

        Args:
            session_id: Optional session ID (uses current session if not provided)

        Returns:
            Full path to the session directory, or base data/ if no session
        """
        if session_id is None:
            current = self.get_current_session()
            session_id = current.get("session_id") if current else None

        if session_id:
            return os.path.join(self.SESSIONS_DIR, session_id)
        else:
            return self.BASE_DIR

    def save_session_data(self, filename: str, data: Any,
                         session_id: str | None = None) -> str:
        """
        Save data to a session file.

        Args:
            filename: Name of the file (e.g., "cracking_stats_table.json")
            data: Data to save (will be JSON serialized)
            session_id: Optional session ID (uses current session if not provided)

        Returns:
            Path where data was saved
        """
        path = self.get_session_data_path(filename, session_id)

        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

        return path

    def load_session_data(self, filename: str,
                         session_id: str | None = None) -> Any | None:
        """
        Load data from a session file.

        Args:
            filename: Name of the file
            session_id: Optional session ID (uses current session if not provided)

        Returns:
            Loaded data, or None if file doesn't exist
        """
        path = self.get_session_data_path(filename, session_id)

        if not os.path.exists(path):
            return None

        with open(path, 'r') as f:
            return json.load(f)

    def migrate_legacy_data_to_session(self, session_id: str) -> bool:
        """
        Migrate data from the legacy data/ folder to a session folder.

        Used when creating a session from existing analysis.

        Args:
            session_id: Target session ID

        Returns:
            True if migration successful
        """
        session_dir = os.path.join(self.SESSIONS_DIR, session_id)
        if not os.path.exists(session_dir):
            os.makedirs(session_dir, exist_ok=True)

        # Copy files
        for filename in self.SESSION_FILES:
            src = os.path.join(self.BASE_DIR, filename)
            dst = os.path.join(session_dir, filename)
            if os.path.exists(src):
                shutil.copy2(src, dst)

        # Copy directories
        for dirname in self.SESSION_DIRS:
            src = os.path.join(self.BASE_DIR, dirname)
            dst = os.path.join(session_dir, dirname)
            if os.path.exists(src) and os.path.isdir(src):
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)

        return True

    def check_aaia_staleness(self, session_id: str | None = None) -> dict[str, Any]:
        """
        Check if AAIA results are stale (source data has changed).

        Args:
            session_id: Optional session ID (uses current session if not provided)

        Returns:
            Dict with:
            - is_stale: bool
            - reason: str (if stale)
            - aaia_timestamp: str (when AAIA was generated)
            - data_timestamp: str (when source data was last modified)
        """
        metadata = None
        if session_id:
            metadata = self.get_session(session_id)
        else:
            current = self.get_current_session()
            if current:
                metadata = self.get_session(current.get("session_id"))

        result = {
            "is_stale": False,
            "reason": "",
            "aaia_exists": False,
            "aaia_timestamp": "",
            "session_id": metadata.session_id if metadata else None
        }

        if not metadata:
            result["reason"] = "No active session"
            return result

        # Check if AAIA exists
        aaia_path = self.get_session_data_path("aaia_results.json", metadata.session_id)
        if not os.path.exists(aaia_path):
            result["reason"] = "No AAIA results"
            return result

        result["aaia_exists"] = True
        result["aaia_timestamp"] = metadata.aaia_timestamp

        # Check if source hash matches
        if metadata.source_hash:
            # Load account data and recompute hash
            account_data = self.load_session_data("account_data.json", metadata.session_id)
            if account_data:
                current_hash = self.compute_source_hash(account_data=account_data)
                if current_hash != metadata.source_hash:
                    result["is_stale"] = True
                    result["reason"] = "Source data has changed since AAIA was generated"

        return result

    def update_session_stats(self, session_id: str) -> SessionMetadata | None:
        """
        Update session statistics from cracking_stats_table.json.

        Called after analysis completes.
        """
        stats = self.load_session_data("cracking_stats_table.json", session_id)
        if not stats:
            return None

        return self.update_session(
            session_id,
            total_accounts=stats.get("total_accounts", 0),
            cracked_accounts=stats.get("cracked_accounts", 0),
            crack_rate=stats.get("crack_rate", 0.0)
        )

    def mark_aaia_generated(self, session_id: str) -> SessionMetadata | None:
        """Mark that AAIA has been generated for this session."""
        return self.update_session(
            session_id,
            aaia_generated=True,
            aaia_timestamp=datetime.now().isoformat()
        )

    def _save_session_metadata(self, metadata: SessionMetadata):
        """Save session metadata to file."""
        meta_path = os.path.join(self.SESSIONS_DIR, metadata.session_id, "session_meta.json")
        os.makedirs(os.path.dirname(meta_path), exist_ok=True)

        with open(meta_path, 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)


# Singleton instance
_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Get the singleton SessionManager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
