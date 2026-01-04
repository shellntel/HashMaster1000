"""
User store module for multi-user support.

Manages user accounts stored in a JSON file with the following schema:
{
    "username": {
        "password_hash": "$2b$12$...",
        "role": "admin",  # "admin" or "user"
        "can_view_passwords": true,
        "force_password_change": false,
        "created_at": "2026-01-03T10:30:00Z",
        "created_by": "superadmin"
    }
}

The superadmin account is always defined in .env and never stored in users.json.
"""

import json
import os
import fcntl
import bcrypt
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, asdict


# Default path for user store
DEFAULT_USER_STORE_PATH = "data/users.json"


@dataclass
class UserData:
    """User data structure."""
    username: str
    password_hash: str
    role: str  # "admin" or "user"
    can_view_passwords: bool = True
    force_password_change: bool = False
    created_at: str = ""
    created_by: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage (excludes username as it's the key)."""
        return {
            "password_hash": self.password_hash,
            "role": self.role,
            "can_view_passwords": self.can_view_passwords,
            "force_password_change": self.force_password_change,
            "created_at": self.created_at,
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, username: str, data: dict) -> "UserData":
        """Create UserData from dictionary."""
        return cls(
            username=username,
            password_hash=data.get("password_hash", ""),
            role=data.get("role", "user"),
            can_view_passwords=data.get("can_view_passwords", True),
            force_password_change=data.get("force_password_change", False),
            created_at=data.get("created_at", ""),
            created_by=data.get("created_by", ""),
        )


class UserStore:
    """Thread-safe user store backed by JSON file."""

    def __init__(self, path: str = DEFAULT_USER_STORE_PATH):
        self.path = path
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure the directory for the user store exists."""
        directory = os.path.dirname(self.path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

    def _read_store(self) -> dict:
        """Read the user store from disk with file locking."""
        if not os.path.exists(self.path):
            return {}

        try:
            with open(self.path, "r") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    content = f.read()
                    if not content.strip():
                        return {}
                    return json.loads(content)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (json.JSONDecodeError, IOError) as e:
            # Log error but return empty dict to allow superadmin fallback
            print(f"Warning: Could not read user store: {e}")
            return {}

    def _write_store(self, data: dict) -> bool:
        """Write the user store to disk with file locking and atomic write."""
        temp_path = self.path + ".tmp"
        backup_path = self.path + ".bak"

        try:
            # Write to temp file first
            with open(temp_path, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(data, f, indent=2)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Set restrictive permissions (owner read/write only)
            os.chmod(temp_path, 0o600)

            # Backup existing file if it exists
            if os.path.exists(self.path):
                if os.path.exists(backup_path):
                    os.remove(backup_path)
                os.rename(self.path, backup_path)

            # Atomic rename
            os.rename(temp_path, self.path)
            return True

        except IOError as e:
            print(f"Error writing user store: {e}")
            # Clean up temp file if it exists
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False

    def get_user(self, username: str) -> Optional[UserData]:
        """Get a user by username."""
        store = self._read_store()
        if username in store:
            return UserData.from_dict(username, store[username])
        return None

    def list_users(self) -> list[UserData]:
        """List all users."""
        store = self._read_store()
        return [UserData.from_dict(username, data) for username, data in store.items()]

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "user",
        can_view_passwords: bool = True,
        created_by: str = "superadmin",
    ) -> tuple[bool, str]:
        """
        Create a new user.

        Returns (success, message) tuple.
        """
        # Validate username
        if not username or not username.strip():
            return False, "Username cannot be empty"

        username = username.strip().lower()

        if not username.isalnum() and "_" not in username and "-" not in username:
            return False, "Username can only contain letters, numbers, underscores, and hyphens"

        if len(username) < 2:
            return False, "Username must be at least 2 characters"

        if len(username) > 50:
            return False, "Username must be 50 characters or less"

        # Validate password
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters"

        # Validate role
        if role not in ("admin", "user"):
            return False, "Role must be 'admin' or 'user'"

        store = self._read_store()

        if username in store:
            return False, f"User '{username}' already exists"

        # Hash password
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        # Create user data
        user_data = UserData(
            username=username,
            password_hash=password_hash,
            role=role,
            can_view_passwords=can_view_passwords,
            force_password_change=True,  # Force password change on first login
            created_at=datetime.utcnow().isoformat() + "Z",
            created_by=created_by,
        )

        store[username] = user_data.to_dict()

        if self._write_store(store):
            return True, f"User '{username}' created successfully"
        else:
            return False, "Failed to save user store"

    def delete_user(self, username: str) -> tuple[bool, str]:
        """
        Delete a user.

        Returns (success, message) tuple.
        """
        store = self._read_store()

        if username not in store:
            return False, f"User '{username}' not found"

        del store[username]

        if self._write_store(store):
            return True, f"User '{username}' deleted successfully"
        else:
            return False, "Failed to save user store"

    def update_user(
        self,
        username: str,
        role: Optional[str] = None,
        can_view_passwords: Optional[bool] = None,
        force_password_change: Optional[bool] = None,
    ) -> tuple[bool, str]:
        """
        Update user attributes.

        Returns (success, message) tuple.
        """
        store = self._read_store()

        if username not in store:
            return False, f"User '{username}' not found"

        if role is not None:
            if role not in ("admin", "user"):
                return False, "Role must be 'admin' or 'user'"
            store[username]["role"] = role

        if can_view_passwords is not None:
            store[username]["can_view_passwords"] = can_view_passwords

        if force_password_change is not None:
            store[username]["force_password_change"] = force_password_change

        if self._write_store(store):
            return True, f"User '{username}' updated successfully"
        else:
            return False, "Failed to save user store"

    def change_password(self, username: str, new_password: str) -> tuple[bool, str]:
        """
        Change a user's password.

        Returns (success, message) tuple.
        """
        if not new_password or len(new_password) < 8:
            return False, "Password must be at least 8 characters"

        store = self._read_store()

        if username not in store:
            return False, f"User '{username}' not found"

        # Hash new password
        password_hash = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        store[username]["password_hash"] = password_hash
        store[username]["force_password_change"] = False

        if self._write_store(store):
            return True, "Password changed successfully"
        else:
            return False, "Failed to save user store"

    def verify_password(self, username: str, password: str) -> bool:
        """Verify a user's password."""
        user = self.get_user(username)
        if not user:
            return False

        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                user.password_hash.encode("utf-8")
            )
        except Exception:
            return False

    def user_count(self) -> int:
        """Get the number of users in the store."""
        store = self._read_store()
        return len(store)


# Global user store instance
_user_store: Optional[UserStore] = None


def get_user_store() -> UserStore:
    """Get the global user store instance."""
    global _user_store
    if _user_store is None:
        path = os.getenv("MULTI_USER_FILE", DEFAULT_USER_STORE_PATH)
        _user_store = UserStore(path)
    return _user_store


def init_user_store(path: Optional[str] = None) -> UserStore:
    """Initialize the global user store with a specific path."""
    global _user_store
    if path:
        _user_store = UserStore(path)
    else:
        _user_store = UserStore(os.getenv("MULTI_USER_FILE", DEFAULT_USER_STORE_PATH))
    return _user_store
