import os
import re
import subprocess
import sys
import time
import json
import logging
import bcrypt
from dotenv import load_dotenv
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
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_session import Session
# werkzeug.security not used - using bcrypt directly for password verification
from datetime import datetime, timedelta
from typing import Any, cast
# Import file parser module for validation
import file_parser
# Import session manager for multi-session support
from session_manager import get_session_manager, SessionMetadata
# Import domain utilities for domain filtering
from domain_utils import filter_accounts_by_domain, detect_cross_domain_password_reuse
# Import password history analysis module
import password_history
# Import potfile cache for efficient master potfile operations
from potfile_cache import get_master_cache, build_cracked_hashes_fast, get_cracked_hashes_direct

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

# Advanced Options (experimental tools) configuration
ADVANCED_OPTIONS_ENABLED = os.getenv("ADVANCED_OPTIONS_ENABLED", "false").lower() == "true"


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


class User(UserMixin):
    def __init__(self, username: str, password_hash: str | None = None):
        self.username = username
        self.password_hash = password_hash

    @property
    def id(self) -> str:
        # Use username as the unique identifier
        return self.username


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


app = Flask(__name__, static_folder="static", template_folder="templates")

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

# Context processor to make global variables available to all templates
@app.context_processor
def inject_global_settings() -> dict[str, Any]:
    """Inject global settings into all templates."""
    return {
        'advanced_options_enabled': ADVANCED_OPTIONS_ENABLED
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
    # Return the admin user if the ID matches
    if user_id == ADMIN_USERNAME:
        return User(username=ADMIN_USERNAME)
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
def login() -> FlaskResponse:
    if current_user.is_authenticated:  # If already logged in, redirect to index
        return cast(FlaskResponse, redirect(url_for("index")))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

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
                # status=400, # Removed because it doesn't fit the make_response class
            )

        # Authenticate against the .env credentials
        if username == ADMIN_USERNAME and bcrypt.checkpw(
            password.encode("utf-8"), ADMIN_PASSWORD_HASH.encode("utf-8")
        ):

            user = User(username=ADMIN_USERNAME, password_hash=ADMIN_PASSWORD_HASH)
            login_user(user)

            # Redirect to the 'next' parameter or index (with open redirect protection)
            next_page = request.args.get("next")
            if next_page and is_safe_redirect_url(next_page):
                return cast(FlaskResponse, redirect(next_page))
            return cast(FlaskResponse, redirect(url_for("index")))

        # If authentication fails
        return make_response(
            render_template(
                "message.html",
                message="Invalid Credentials: Please enter a valid username and password.",
                message_type="error-message",
                status_code=401,
                referrer="Login",
                referrer_url=url_for("login"),
            ),
            # status=401, # Not allowed in make_response class
        )

    # Render the login page for GET requests
    return make_response(render_template("login.html"))


@app.route("/logout", methods=["POST"])
@login_required
def logout() -> Response:
    logout_user()
    return cast(FlaskResponse, redirect(url_for("login")))


@app.route("/")
@login_required
def index() -> str:
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
    if initial_step == 3:
        pwdump_validation = session.get("pwdump_validation")
        potfile_validation = session.get("potfile_validation")
        add_validation = session.get("add_validation")
        analysis_options = session.get("analysis_options")

    # Get master potfile entry count if enabled
    master_potfile_count = 0
    if MASTER_POTFILE_ENABLED:
        master_potfile_count = file_parser.get_potfile_entry_count(MASTER_POTFILE_PATH)

    return render_template(
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


@app.route("/favicon.ico")
def favicon() -> Response:
    return send_from_directory(
        "static", "favicon.ico", mimetype="image/vnd.microsoft.icon"
    )


@app.route("/readme")
def readme() -> Response:
    return send_file("readme.md", mimetype="text/markdown")


@app.route("/LICENSE")
def license() -> Response:
    return send_file("LICENSE", mimetype="text/markdown")


@app.route("/upload", methods=["POST"])
@login_required
def upload_files() -> Response:
    try:
        # Retrieve file uploads
        pwdump_file = request.files.get("pwdump_file")
        potfile = request.files.get("potfile")

        if not pwdump_file or not potfile:
            logging.error("Missing file uploads.")
            return Response(
                render_template(
                    "message.html",
                    message="Valid pwdump and potfile (both) uploads are required.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        pwdump_path = os.path.join(app.config["UPLOAD_FOLDER"], pwdump_file.filename)
        potfile_path = os.path.join(app.config["UPLOAD_FOLDER"], potfile.filename)

        # Save pwdump and potfile files to the upload folder for validation
        try:
            pwdump_file.save(pwdump_path)
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

        # Validate pwdump file
        if not validate_pwdump_file(pwdump_path):
            logging.error(f"Invalid pwdump file: {pwdump_path}")
            os.remove(pwdump_path)
            os.remove(potfile_path)
            return Response(
                render_template(
                    "message.html",
                    message="The uploaded pwdump file is invalid. Please upload a valid pwdump file.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Validate potfile
        if not validate_potfile(potfile_path):
            logging.error(f"Invalid potfile: {potfile_path}")
            os.remove(pwdump_path)
            os.remove(potfile_path)
            return Response(
                render_template(
                    "message.html",
                    message="The uploaded potfile is invalid. Please upload a valid potfile.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        # Collect form data for options
        options: Dict[str, Union[str, bool]] = {
            "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
            "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
            "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
            "substring_min_len": request.form.get("substring_min_len", "4"),
            "substring_max_len": request.form.get("substring_max_len", "20"),
            "substring_freq_threshold": request.form.get(
                "substring_freq_threshold", "5"
            ),
            "substring_disp_nest": parse_boolean_field("substring_disp_nest"),
            "substring_normalize": parse_boolean_field("substring_normalize"),
            "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
            "dictionary_disp_nest": parse_boolean_field("dictionary_disp_nest"),
            "ignore_blank_passwords": parse_boolean_field("ignore_blank_passwords"),
        }

        # Prepare command-line arguments
        cmd_args = [
            sys.executable,
            "HashMaster1000.py",
            pwdump_path,
            potfile_path,
            "--policy_min_pw_len",
            str(options["policy_min_pw_len"]),
            "--policy_max_pw_age",
            str(options["policy_max_pw_age"]),
            "--policy_complexity_req",
            str(options["policy_complexity_req"]),
            "--substring_min_len",
            str(options["substring_min_len"]),
            "--substring_max_len",
            str(options["substring_max_len"]),
            "--substring_freq_threshold",
            str(options["substring_freq_threshold"]),
            "--substring_disp_nest",
            str(options["substring_disp_nest"]).lower(),
            "--substring_normalize",
            str(options["substring_normalize"]).lower(),
            "--dictionary_min_len",
            str(options["dictionary_min_len"]),
            "--dictionary_disp_nest",
            str(options["dictionary_disp_nest"]).lower(),
            "--ignore_blank_passwords",
            str(options["ignore_blank_passwords"]).lower(),
        ]
        print(f"\nStep 1: Parse inputs")
        print(f"Running command: {cmd_args}")

        # Execute the script with command-line arguments
        result = subprocess.run(cmd_args, capture_output=True, text=True, check=True)
        print("\nHashMaster1000.py ran with the following messages:")
        print(result.stdout)
        print(
            f"\nPassword and hash analysis complete.\n\nStep 3: Load Report Charts and Tables\n"
        )
        return cast(FlaskResponse, redirect(url_for("report")))

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing HashMaster1000.py: {e.stderr}")
        return Response(
            render_template(
                "message.html",
                message="Error processing files. Please check your input files.",
                message_type="error-message",
                status_code=500,
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            status=500,
        )

    except Exception as e:
        logging.error(f"Unexpected error during upload: {e}")
        return Response(
            render_template(
                "message.html",
                message="An unexpected error occurred. Please try again later.",
                message_type="error-message",
                status_code=500,
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            status=500,
        )


@app.route("/local_files", methods=["POST"])
@login_required
def local_files() -> FlaskResponse:
    pwdump_path = request.form["pwdump_path"]
    potfile_path = request.form["potfile_path"]

    # Check if the provided paths are valid files
    if not os.path.isfile(pwdump_path) or not os.path.isfile(potfile_path):
        return make_response(
            render_template(
                "message.html",
                message=f"One or both file paths are invalid. Please check and try again.\n"
                f"pwdump_path={pwdump_path}\n"
                f"potfile_path={potfile_path}",
                message_type="error-message",
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            400,  # Status code for bad request
        )

    # Validate pwdump file
    if not validate_pwdump_file(pwdump_path):
        return make_response(
            render_template(
                "message.html",
                message="The provided pwdump file is invalid. Please provide a valid pwdump file.",
                message_type="error-message",
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            400,
        )

    # Validate potfile
    if not validate_potfile(potfile_path):
        return make_response(
            render_template(
                "message.html",
                message="The provided potfile is invalid. Please provide a valid potfile.",
                message_type="error-message",
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            400,
        )

    # Collect form data for options
    options = {
        "policy_min_pw_len": request.form.get("policy_min_pw_len", "12"),
        "policy_max_pw_age": request.form.get("policy_max_pw_age", "90"),
        "policy_complexity_req": request.form.get("policy_complexity_req", "3"),
        "substring_min_len": request.form.get("substring_min_len", "4"),
        "substring_max_len": request.form.get("substring_max_len", "20"),
        "substring_freq_threshold": request.form.get("substring_freq_threshold", "5"),
        "substring_disp_nest": parse_boolean_field("substring_disp_nest"),
        "substring_normalize": parse_boolean_field("substring_normalize"),
        "dictionary_min_len": request.form.get("dictionary_min_len", "4"),
        "dictionary_disp_nest": parse_boolean_field("dictionary_disp_nest"),
        "ignore_blank_passwords": parse_boolean_field("ignore_blank_passwords"),
    }

    # Prepare command-line arguments
    cmd_args = [
        sys.executable,
        "HashMaster1000.py",
        pwdump_path,
        potfile_path,
        "--policy_min_pw_len",
        str(options["policy_min_pw_len"]),
        "--policy_max_pw_age",
        str(options["policy_max_pw_age"]),
        "--policy_complexity_req",
        str(options["policy_complexity_req"]),
        "--substring_min_len",
        str(options["substring_min_len"]),
        "--substring_max_len",
        str(options["substring_max_len"]),
        "--substring_freq_threshold",
        str(options["substring_freq_threshold"]),
        "--substring_disp_nest",
        str(options["substring_disp_nest"]).lower(),
        "--substring_normalize",
        str(options["substring_normalize"]).lower(),
        "--dictionary_min_len",
        str(options["dictionary_min_len"]),
        "--dictionary_disp_nest",
        str(options["dictionary_disp_nest"]).lower(),
        "--ignore_blank_passwords",
        str(options["ignore_blank_passwords"]).lower(),
    ]

    print(f"\nStep 1: Parse inputs")
    print(f"Running command: {cmd_args}")

    # Execute the script with command-line arguments
    try:
        result = subprocess.run(cmd_args, check=True)
        print("\nHashMaster1000.py ran with the following messages:")
        print(result.stdout)
        print(
            f"\nPassword and hash analysis complete.\n\nStep 3: Load Report Charts and Tables\n"
        )
    except subprocess.CalledProcessError as e:
        return make_response(
            render_template(
                "message.html",
                message=f"Error processing files: {e.stderr}",
                message_type="error-message",
                referrer="Start",
                referrer_url=url_for("index"),
            ),
            500,  # Status code for server error
        )

    return cast(FlaskResponse, redirect(url_for("report")))


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
    try:
        # Retrieve file uploads
        pwdump_file = request.files.get("pwdump_file")
        potfile = request.files.get("potfile")

        if not pwdump_file or not potfile:
            logging.error("Missing file uploads.")
            return Response(
                render_template(
                    "message.html",
                    message="Valid pwdump and potfile (both) uploads are required.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
            )

        pwdump_path = os.path.join(app.config["UPLOAD_FOLDER"], pwdump_file.filename)
        potfile_path = os.path.join(app.config["UPLOAD_FOLDER"], potfile.filename)

        # Save files
        try:
            pwdump_file.save(pwdump_path)
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
            potfile_result = file_parser.validate_potfile(potfile_path)

            # Extract hashes for session-optimized potfile filtering
            add_hashes = extract_hashes_from_add(add_result)

            # Handle master potfile merge if enabled (with session filtering)
            final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, add_hashes)

            # Store ADD validation results in session
            session["add_validation"] = file_parser.add_result_to_dict(add_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path
            session["input_format"] = "add_json"
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
            potfile_result = file_parser.validate_potfile(potfile_path)

            # Extract hashes for session-optimized potfile filtering
            pwdump_hashes = extract_hashes_from_pwdump(pwdump_result)

            # Handle master potfile merge if enabled (with session filtering)
            final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, pwdump_hashes)

            # Store validation results in session
            session["pwdump_validation"] = file_parser.validation_result_to_dict(pwdump_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path
            session["input_format"] = "pwdump"
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
    """
    try:
        pwdump_path = request.form.get("pwdump_path", "").strip()
        potfile_path = request.form.get("potfile_path", "").strip()

        if not pwdump_path or not potfile_path:
            return Response(
                render_template(
                    "message.html",
                    message="Both pwdump and potfile paths are required.",
                    message_type="error-message",
                    status_code=400,
                    referrer="Start",
                    referrer_url=url_for("index"),
                ),
                status=400,
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

        if not os.path.isfile(potfile_path):
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
            potfile_result = file_parser.validate_potfile(potfile_path)

            # Extract hashes for session-optimized potfile filtering
            add_hashes = extract_hashes_from_add(add_result)

            # Handle master potfile merge if enabled (with session filtering)
            if MASTER_POTFILE_ENABLED:
                final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, add_hashes)
                session["master_potfile_merge"] = merge_stats
            else:
                final_potfile_result = potfile_result

            # Store ADD validation results in session
            session["add_validation"] = file_parser.add_result_to_dict(add_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path
            session["input_format"] = "add_json"

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
            potfile_result = file_parser.validate_potfile(potfile_path)

            # Extract hashes for session-optimized potfile filtering
            pwdump_hashes = extract_hashes_from_pwdump(pwdump_result)

            # Handle master potfile merge if enabled (with session filtering)
            if MASTER_POTFILE_ENABLED:
                final_potfile_result, merge_stats = handle_master_potfile_merge(potfile_result, pwdump_hashes)
                session["master_potfile_merge"] = merge_stats
            else:
                final_potfile_result = potfile_result

            # Store validation results in session
            session["pwdump_validation"] = file_parser.validation_result_to_dict(pwdump_result)
            session["potfile_validation"] = file_parser.potfile_result_to_dict(final_potfile_result)
            session["pwdump_path"] = pwdump_path
            session["potfile_path"] = potfile_path
            session["input_format"] = "pwdump"

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
    pwdump_data = session.get("pwdump_validation")
    potfile_data = session.get("potfile_validation")
    master_merge_stats = session.get("master_potfile_merge")

    # Need at least one file to show review
    if not pwdump_data and not potfile_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    return make_response(render_template(
        "validate.html",
        pwdump=pwdump_data,
        potfile=potfile_data,
        master_potfile_enabled=MASTER_POTFILE_ENABLED,
        master_potfile_merge=master_merge_stats
    ))


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
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{file_type}_{uploaded_file.filename}")
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


@app.route("/process_validated", methods=["GET", "POST"])
@login_required
def process_validated() -> Response:
    """
    Process validated files with user's include/exclude decisions.
    Accepts options from form data (POST) or falls back to session data.
    Creates a new analysis session to store results.
    """
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
            "custom_keywords": request.form.get("custom_keywords", ""),
            "domain_filter": request.form.get("domain_filter", "all"),
            # Preserve company_name/project_description from session if not in form (validate.html doesn't have these)
            "company_name": request.form.get("company_name", "").strip() or existing_options.get("company_name", ""),
            "project_description": request.form.get("project_description", "").strip() or existing_options.get("project_description", ""),
        }
        # Store in session for consistency
        session["analysis_options"] = options
    else:
        options = existing_options
    pwdump_path = session.get("pwdump_path")
    potfile_path = session.get("potfile_path")

    if not pwdump_data or not potfile_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    try:
        # Reconstruct pwdump validation result from session
        pwdump_result = file_parser.dict_to_validation_result(pwdump_data)

        # Optimization: If using master potfile, use cached dict directly
        # This avoids creating 620K+ PotfileEntry objects
        cracked_hashes = None
        if MASTER_POTFILE_ENABLED:
            cracked_hashes = get_cracked_hashes_direct(MASTER_POTFILE_PATH)

        if cracked_hashes is not None:
            # Use optimized path - direct cache access
            account_data = file_parser.build_account_data_with_cache(
                pwdump_result,
                cracked_hashes,
                ignore_disabled=options.get("ignore_disabled_accounts", "false") == "true",
                ignore_computer_accounts=options.get("ignore_computer_accounts", "false") == "true",
            )
        else:
            # Fall back to standard path for non-master potfiles
            potfile_result = file_parser.dict_to_potfile_result(potfile_data)
            account_data = file_parser.build_account_data(
                pwdump_result,
                potfile_result,
                ignore_disabled=options.get("ignore_disabled_accounts", "false") == "true",
                ignore_computer_accounts=options.get("ignore_computer_accounts", "false") == "true",
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
        import password_analysis_tools

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

        # Run bad practices analysis
        bad_practices = password_analysis_tools.bad_practices_analysis(
            cracked_passwords, custom_keywords
        )

        # Check password reuse (needs original file path)
        pw_reuse_table = password_analysis_tools.check_pw_reuse(pwdump_path)

        # Build cracked_hashes lookup from potfile (uses cache for master potfile)
        # Note: cracked_hashes may already be set from the optimized path above
        if cracked_hashes is None:
            # Need to build from potfile_result (non-master potfile case)
            cracked_hashes = build_cracked_hashes_fast(potfile_result)
        # Ensure blank hash is included for history analysis
        if file_parser.BLANK_NTLM_HASH not in cracked_hashes:
            cracked_hashes = {file_parser.BLANK_NTLM_HASH: "", **cracked_hashes}

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

        print(f"\nPassword and hash analysis complete. Session created: {analysis_session.name} ({analysis_session.session_id})\n")
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
    return render_template("sessions.html", advanced_options_enabled=ADVANCED_OPTIONS_ENABLED)


@app.route("/hiddenpages")
@app.route("/hidden")
@login_required
def hidden_pages_index() -> str:
    """Index page for hidden/development pages and tools."""
    from ollama_tools import test_all_servers, get_ollama_config

    # Get Ollama status for display
    config = get_ollama_config()
    ollama_enabled = config.enabled if config else False
    servers_status = test_all_servers() if ollama_enabled else {"servers": []}

    return render_template(
        'hidden_index.html',
        ollama_enabled=ollama_enabled,
        servers=servers_status.get("servers", [])
    )


@app.route("/hibp/download")
@login_required
def hibp_download_page() -> str:
    """HIBP database download management page."""
    return render_template('hibp_download.html')


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


# Endpoint for Project Statistics Table
@app.route("/cracking_stats_table")
@login_required
def cracking_stats_table() -> Response:
    data = _load_session_json("cracking_stats_table.json")
    if data is None:
        return jsonify({"error": "No data available"}), 404
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

    # Use cache for fast count lookup
    cache = get_master_cache()
    stats = cache.get_stats()
    if stats:
        count = stats["ntlm_count"]
    else:
        # Cache not loaded yet, load it
        cache.load(MASTER_POTFILE_PATH)
        stats = cache.get_stats()
        count = stats["ntlm_count"] if stats else 0

    return jsonify({
        "enabled": True,
        "count": count
    })


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
    from hibp_checker import (
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
    from hibp_checker import load_local_hibp_database

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
    from hibp_checker import test_hibp_connection

    success, message = test_hibp_connection()
    return jsonify({
        "success": success,
        "message": message
    })


def _run_hibp_check_background(session_dir: str, method: str, account_list: list,
                                username_to_password: dict, username_to_status: dict,
                                local_db_hash_count: int = 0):
    """
    Run HIBP check in background thread.

    This function runs the actual HIBP check and saves results to files.
    It's designed to be called from a background thread.
    """
    from hibp_checker import check_hashes_hibp, check_hashes_local

    progress_path = os.path.join(session_dir, "hibp_progress.json")
    hibp_results_path = os.path.join(session_dir, "hibp_results.json")

    # Calculate unique prefixes for progress estimation (API mode)
    unique_prefixes = len(set(acct["ntlm_hash"][:5].upper() for acct in account_list
                              if acct.get("ntlm_hash") and len(acct["ntlm_hash"]) >= 5))

    def save_progress(checked: int, total: int, found: int = 0, status: str = "running"):
        """Save progress to file for frontend polling."""
        try:
            progress_data = {
                "checked": checked,
                "total": total,
                "found": found,
                "percentage": round((checked / total) * 100, 1) if total > 0 else 0,
                "status": status
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

        # Save results to session
        with open(hibp_results_path, "w") as f:
            json.dump(results_dict, f, indent=2)

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
    from hibp_checker import get_local_db_status

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
    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    progress_path = os.path.join(session_dir, "hibp_progress.json")

    if not os.path.exists(progress_path):
        return jsonify({"status": "idle"})

    try:
        with open(progress_path, "r") as f:
            progress = json.load(f)
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
        "result_count": len(data.get("results", []))
    }
    return jsonify(summary)


# ============================================================================
# HIBP Database Download Endpoints
# ============================================================================

@app.route("/api/hibp/download/info")
@login_required
def hibp_download_info() -> Response:
    """Get information about HIBP database download, including estimates and attribution."""
    from hibp_downloader import estimate_download, get_download_status
    from hibp_checker import get_local_db_status

    # Get current local database status
    local_db_status = get_local_db_status()

    # Get download estimates
    estimates = estimate_download()

    # Get any active download status
    download_status = get_download_status()

    # Default output path
    default_output = os.path.join("data", "pwnedpasswords-ntlm.txt")

    return jsonify({
        "local_database": local_db_status,
        "estimates": estimates,
        "download_status": download_status,
        "default_output_path": default_output,
        "configured_path": os.environ.get("HIBP_LOCAL_DB_PATH", "")
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
    from hibp_downloader import start_download

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
    from hibp_downloader import get_download_status

    return jsonify(get_download_status())


@app.route("/api/hibp/download/cancel", methods=["POST"])
@login_required
def hibp_download_cancel() -> Response:
    """Cancel an active HIBP database download."""
    from hibp_downloader import cancel_download

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


def run_automatic_hibp_check(account_data: dict, session_dir: str) -> dict | None:
    """
    Run HIBP check automatically during analysis pipeline if local database is available.

    This function checks passwords against the local HIBP database without requiring
    user consent (since no data leaves the system). Returns the results dict or None
    if no local database is available.
    """
    from hibp_checker import check_hashes_local, get_local_db_status

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

        # Save results to session
        hibp_results_path = os.path.join(session_dir, "hibp_results.json")
        with open(hibp_results_path, "w") as f:
            json.dump(results_dict, f, indent=2)

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


@app.route("/validate_single_local", methods=["POST"])
@login_required
def validate_single_local_file() -> Response:
    """
    AJAX endpoint to validate a single local file (pwdump or potfile) by path.
    Returns validation results as JSON for display in the UI.
    """
    try:
        data = request.get_json()
        file_type = data.get("file_type")  # "pwdump" or "potfile"
        file_path = data.get("file_path", "").strip()

        if not file_type or not file_path:
            return jsonify({"error": "Missing file_type or file_path"}), 400

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
            "custom_keywords": request.form.get("custom_keywords", ""),
            # Preserve company_name/project_description from session if not in form (validate.html doesn't have these)
            "company_name": request.form.get("company_name", "").strip() or existing_options.get("company_name", ""),
            "project_description": request.form.get("project_description", "").strip() or existing_options.get("project_description", ""),
        }
        session["analysis_options"] = options
    else:
        options = existing_options

    try:
        # Reconstruct validation results from session
        add_result = file_parser.dict_to_add_result(add_data)
        potfile_result = None
        if potfile_data:
            potfile_result = file_parser.dict_to_potfile_result(potfile_data)

        # Convert ADD data to account_data format
        account_data, privileged_findings = file_parser.add_to_account_data(
            add_result,
            potfile_result,
            ignore_disabled=options.get("ignore_disabled_accounts", "false") == "true",
            ignore_computer_accounts=options.get("ignore_computer_accounts", "false") == "true",
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
        import password_analysis_tools

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

        # Run bad practices analysis
        bad_practices = password_analysis_tools.bad_practices_analysis(
            cracked_passwords, custom_keywords
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

        # Run Kerberoast exposure analysis if raw user data is available
        if add_result.raw_users:
            try:
                import kerberoast_analysis

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
                import asrep_analysis

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

        print(f"\nADD JSON analysis complete. Session created: {analysis_session.name} ({analysis_session.session_id})\n")
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
    """
    data = request.get_json()
    path = data.get("path", ".")

    # Resolve to absolute path
    try:
        abs_path = os.path.abspath(os.path.expanduser(path))
    except Exception:
        return jsonify({"error": "Invalid path"}), 400

    # Check if path exists and is a directory
    if not os.path.exists(abs_path):
        return jsonify({"error": "Path does not exist"}), 404

    if not os.path.isdir(abs_path):
        return jsonify({"error": "Path is not a directory"}), 400

    try:
        entries = []
        # Add parent directory option (except for root)
        parent = os.path.dirname(abs_path)
        if parent != abs_path:  # Not at root
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
    from ollama_tools import test_ollama_connection, get_ollama_config

    config = get_ollama_config()
    result = test_ollama_connection()

    return jsonify(result)


@app.route("/api/ai/models", methods=["GET"])
@login_required
def ai_models() -> Response:
    """Get list of available models from Ollama server."""
    from ollama_tools import OllamaClient, get_ollama_config

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
    from ollama_tools import get_available_library_models

    models = get_available_library_models()
    return jsonify({"models": models})


@app.route("/api/ai/presets", methods=["GET"])
@login_required
def ai_presets() -> Response:
    """Get analysis preset configurations."""
    from ollama_tools import get_analysis_presets

    presets = get_analysis_presets()
    return jsonify({"presets": presets})


@app.route("/api/ai/pull", methods=["POST"])
@login_required
def ai_pull_model() -> Response:
    """Pull (download) a model from Ollama library."""
    from ollama_tools import pull_model, get_ollama_config

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
    from ollama_tools import delete_model, get_ollama_config

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
    from ollama_tools import OllamaClient, get_ollama_config

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
    from ollama_tools import PasswordAnalysisAI, get_ollama_config

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
    from ollama_tools import PasswordAnalysisAI, get_ollama_config

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
    from ollama_tools import PasswordAnalysisAI, get_ollama_config

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
    from ollama_tools import PasswordAnalysisAI, get_ollama_config

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
    from ollama_tools import test_all_servers
    return jsonify(test_all_servers())


@app.route("/api/ai/servers/<server_id>/status", methods=["GET"])
@login_required
def ai_server_status(server_id: str) -> Response:
    """Get detailed status of a specific Ollama server including running models."""
    from ollama_tools import test_ollama_connection, get_server_by_id, get_ollama_config, OllamaClient

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
    from ollama_tools import get_ai_report_sections
    return jsonify({"sections": get_ai_report_sections()})


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
    from ollama_tools import AIReportAnalyzer, get_ollama_config, get_ai_report_sections, get_server_by_id, OllamaClient

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    sections = get_ai_report_sections()
    if section_id not in sections:
        return jsonify({"error": f"Unknown section: {section_id}"}), 400

    request_data = request.get_json() or {}
    model = request_data.get("model")
    temperature = request_data.get("temperature")
    server_id = request_data.get("server_id", "primary")
    data = request_data.get("data", {})

    # If no data provided, load it automatically (fallback)
    if not data:
        from ollama_tools import get_ai_data_loader
        session_mgr = get_session_manager()
        session_dir = session_mgr.get_session_dir()
        loader = get_ai_data_loader(session_dir)
        data = loader.load_section_data(section_id)

    # Get server-specific config
    server = get_server_by_id(server_id)
    server_name = server.name if server else "Primary"
    server_host = server.host if server else config.host
    server_config = get_ollama_config(server_id)

    # Track response time
    start_time = time.time()

    # Create client for specific server
    client = OllamaClient(server_config)
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
    from ollama_tools import (
        AIPipelineRunner, get_ollama_config, OllamaClient,
        get_ai_data_loader, get_phase_config, AIReportAnalyzer,
        get_ai_report_sections
    )

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    # Parse query params
    sections_param = request.args.get("sections", "all")
    server_id = request.args.get("server_id", "primary")
    skip_phase1 = request.args.get("skip_phase1", "false").lower() == "true"

    # Determine sections to process
    all_sections = get_ai_report_sections()
    if sections_param == "all":
        sections = ["weak-habits", "company-intel", "user-behavior", "recommendations"]
    else:
        sections = [s.strip() for s in sections_param.split(",") if s.strip() in all_sections and s.strip() != "full-report"]
        if not sections:
            sections = ["weak-habits", "company-intel", "user-behavior", "recommendations"]

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
        llama_sections = [s for s in sections if get_phase_config(s).get("phase1", {}).get("model", "").startswith("llama")]
        deepseek_sections = [s for s in sections if s not in llama_sections]
        ordered_sections = llama_sections + deepseek_sections

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
                    yield f"data: {json.dumps({'type': 'progress', 'total_steps': total_steps, 'current_step': step_counter, 'current_phase': 'phase2', 'current_section': section_id, 'current_action': f'Skipped validation for {section_id}', 'elapsed_seconds': round(time.time() - start_time, 1), 'percent_complete': round(step_counter / total_steps * 100, 1)})}\n\n"
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

                # For user-behavior with extracted claims, use focused validation
                if section_id == "user-behavior" and tier0_result.extracted_claims:
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
            aaia_output = {
                "results": {
                    section_id: {
                        "content": data.get("content", ""),
                        "time": str(round(sum(data.get("timing", {}).values()), 1)) + "s"
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
                            "needs_human_review": data.get("needs_human_review", False),
                            "validation_confidence": data.get("validation_confidence", 1.0),
                            "timing": data.get("timing", {})
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
    """List all sessions for the current user."""
    session_mgr = get_session_manager()
    sessions = session_mgr.list_sessions(username=current_user.id)
    current = session_mgr.get_current_session()
    current_id = current.get("session_id") if current else None

    # Also include sessions grouped by company for trend analysis UI
    grouped = session_mgr.get_sessions_grouped_by_company(username=current_user.id)

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
    companies = session_mgr.get_company_suggestions(
        partial=partial,
        username=current_user.id
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

    # Only allow access to own sessions
    if metadata.created_by != current_user.id:
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

        # Only allow update of own sessions
        if metadata.created_by != current_user.id:
            return jsonify({"error": "Access denied"}), 403

        data = request.get_json() or {}

        # Only allow updating specific fields
        updates = {}
        if "name" in data:
            updates["name"] = data["name"].strip()
        if "notes" in data:
            updates["notes"] = data["notes"]

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

        # Only allow deletion of own sessions
        if metadata.created_by != current_user.id:
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

        # Only allow switching to own sessions
        if metadata.created_by != current_user.id:
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
        from trend_analysis import TrendAnalyzer

        data = request.get_json() or {}
        session_ids = data.get("session_ids", [])

        if len(session_ids) < 2:
            return jsonify({
                "error": "At least 2 sessions are required for trend analysis"
            }), 400

        session_mgr = get_session_manager()

        # Verify all sessions belong to current user
        for sid in session_ids:
            metadata = session_mgr.get_session(sid)
            if not metadata:
                return jsonify({"error": f"Session not found: {sid}"}), 404
            if metadata.created_by != current_user.id:
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
        sessions = session_mgr.list_sessions_by_company(
            company_name=company_name,
            username=current_user.id
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

        # Check all user's sessions for matching hash
        sessions = session_mgr.list_sessions(username=current_user.id)
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

        current_options = session.get("analysis_options", {})
        current_domain_filter = current_options.get("domain_filter", "all")
        current_ignore_disabled = current_options.get("ignore_disabled_accounts", "false")
        current_ignore_computer = current_options.get("ignore_computer_accounts", "false")

        # Check if any filter that affects account data has changed
        domain_filter_changed = new_domain_filter.lower() != current_domain_filter.lower()
        account_filter_changed = (
            new_ignore_disabled != current_ignore_disabled or
            new_ignore_computer != current_ignore_computer
        )

        # If domain or account filter changed, need to rebuild account_data from original validation
        if domain_filter_changed or account_filter_changed:
            # Domain filter change requires re-processing from validation data
            # Try Flask session first, then fall back to session files
            pwdump_data = session.get("pwdump_validation")
            potfile_data = session.get("potfile_validation")

            # If not in Flask session, try loading from session files
            if not pwdump_data:
                pwdump_data = session_mgr.load_session_data("pwdump_validation.json")
            if not potfile_data:
                potfile_data = session_mgr.load_session_data("potfile_validation.json")

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
                    )
                else:
                    # Fall back to standard path
                    potfile_result = file_parser.dict_to_potfile_result(potfile_data)
                    account_data_for_analysis = file_parser.build_account_data(
                        pwdump_result,
                        potfile_result,
                        ignore_disabled=new_ignore_disabled == "true",
                        ignore_computer_accounts=new_ignore_computer == "true",
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
        else:
            account_data_for_analysis = account_data if isinstance(account_data, dict) else {entry["username"]: entry for entry in account_data}

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
            "domain_filter": new_domain_filter,
        }
        session["analysis_options"] = options

        # Import analysis tools
        import password_analysis_tools

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

        # Re-run bad practices analysis
        bad_practices = password_analysis_tools.bad_practices_analysis(
            cracked_passwords, custom_keywords
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
    from ollama_tools import test_all_servers, OllamaClient, get_ollama_config
    from ollama_prompts import AI_REPORT_SECTIONS

    # Get all servers and their status
    servers_data = test_all_servers()
    online_servers = [s for s in servers_data.get("servers", []) if s.get("reachable")]

    # Get models, running status, and version for each online server
    for server in online_servers:
        config = get_ollama_config(server["id"])
        client = OllamaClient(config)
        server["models"] = client.list_models(include_details=True)
        server["running"] = client.get_running_models()
        server["version"] = client.get_version()

    # AAIA sections (excluding risk-assessment and full-report for now)
    aaia_sections = ["weak-habits", "company-intel", "user-behavior", "recommendations"]

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
            "order": section_info.get("order", 99)
        })

    return jsonify({
        "servers": online_servers,
        "sections": sorted(sections_config, key=lambda x: x["order"])
    })


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
    from ollama_tools import get_ai_data_loader

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
    loaded from the /data JSON files.
    """
    from ollama_tools import get_ai_data_loader, get_ai_report_sections

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

    # Load section data with session info for policy settings
    session_data = {
        "analysis_options": session.get("analysis_options", {})
    }
    data = loader.load_section_data(section_id, session_data)

    return jsonify({
        "section_id": section_id,
        "section_title": sections[section_id]["title"],
        "data": data,
        "data_sources": sections[section_id].get("data_sources", {})
    })


@app.route("/api/ai/report/data/all", methods=["GET"])
@login_required
def ai_report_all_section_data() -> Response:
    """
    Get pre-loaded analysis data for all AI report sections.

    Useful for initializing the test page with real data.
    """
    from ollama_tools import get_ai_data_loader, get_ai_report_sections

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
    for section_id in sections:
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
    """
    from ollama_tools import get_ai_data_loader, get_ai_report_sections
    from ollama_prompts import (
        SYSTEM_PROMPT, WEAK_HABITS_PROMPT, COMPANY_INTEL_PROMPT,
        USER_BEHAVIOR_PROMPT, RISK_ASSESSMENT_PROMPT, RECOMMENDATIONS_PROMPT,
        EXECUTIVE_SUMMARY_PROMPT
    )

    # Map section IDs to their prompt templates
    PROMPTS = {
        "weak-habits": WEAK_HABITS_PROMPT,
        "company-intel": COMPANY_INTEL_PROMPT,
        "user-behavior": USER_BEHAVIOR_PROMPT,
        "risk-assessment": RISK_ASSESSMENT_PROMPT,
        "recommendations": RECOMMENDATIONS_PROMPT,
        "executive-summary": EXECUTIVE_SUMMARY_PROMPT
    }

    sections = get_ai_report_sections()
    if section_id not in sections:
        return jsonify({"error": f"Unknown section: {section_id}"}), 400

    prompt_template = PROMPTS.get(section_id)
    if not prompt_template:
        return jsonify({"error": f"No prompt template for section: {section_id}"}), 400

    session_mgr = get_session_manager()
    session_dir = session_mgr.get_session_dir()
    loader = get_ai_data_loader(session_dir)

    # Load section data
    session_data = {
        "analysis_options": session.get("analysis_options", {})
    }

    if loader.has_analysis_data():
        data = loader.load_section_data(section_id, session_data)
    else:
        # Return template with placeholder indicators
        return jsonify({
            "section_id": section_id,
            "system_prompt": SYSTEM_PROMPT,
            "prompt_template": prompt_template,
            "formatted_prompt": None,
            "has_data": False,
            "message": "No analysis data available. Run a password analysis to see the formatted prompt."
        })

    # Format the prompt with actual data
    try:
        formatted_prompt = prompt_template.format(**data)
    except KeyError as e:
        formatted_prompt = f"Error formatting prompt: missing key {e}\n\nTemplate:\n{prompt_template}"

    return jsonify({
        "section_id": section_id,
        "system_prompt": SYSTEM_PROMPT,
        "prompt_template": prompt_template,
        "formatted_prompt": formatted_prompt,
        "has_data": True
    })


@app.route("/api/ai/report/test")
@login_required
def ai_report_test_page() -> str:
    """AI Report Analysis test page for experimenting with report sections."""
    from ollama_tools import test_all_servers, get_ai_report_sections, get_ai_data_loader

    # Get all server statuses
    servers_status = test_all_servers()
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
        recommended_models=recommended_models
    )


@app.route("/api/ai/servers/manage")
@login_required
def ai_servers_manage_page() -> str:
    """Multi-server Ollama management page - connectivity testing and model management."""
    from ollama_tools import test_all_servers, get_available_library_models

    # Get all server statuses
    servers_status = test_all_servers()
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
        library_models=library_models
    )


@app.route("/api/ai/benchmark")
@login_required
def ai_benchmark_page() -> str:
    """AI Benchmark Suite - comprehensive model benchmarking and comparison."""
    from ollama_tools import test_all_servers, get_ai_report_sections

    # Get all server statuses
    servers_status = test_all_servers()
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

    # Build server status cards
    server_cards_html = ""
    for server in servers_status.get("servers", []):
        status_class = "ok" if server.get("reachable") else "error"
        model_count = len(server.get("available_models", []))
        hardware_info = f" | {server['hardware']}" if server.get("hardware") else ""
        error_info = f" | Error: {server['error']}" if server.get("error") else ""
        server_cards_html += f'''
        <div class="server-card {status_class}" data-server-id="{server['id']}">
            <div class="server-header">
                <span class="server-status-dot"></span>
                <strong>{server['name']}</strong>
            </div>
            <div class="server-details">
                <div class="server-host">{server['host']}</div>
                <div class="server-info">{server['description']}{hardware_info}</div>
                <div class="server-models">{model_count} models available{error_info}</div>
            </div>
        </div>
        '''

    # Build section options (exclude full-report)
    section_checkboxes = ""
    for section_id, config in sorted(sections.items(), key=lambda x: x[1].get("order", 99)):
        if section_id == "full-report":
            continue
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
        data_has_content=data_has_content
    )


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


if __name__ == "__main__":
    # Validate libraries and files before starting the app
    validate_libraries()
    validate_files()

    # Validate required environment variables
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise ValueError(
            "Environment variable SECRET_KEY must be set in the .env file."
        )
    app.secret_key = secret_key

    if not ADMIN_USERNAME:
        raise ValueError(
            "Environment variable ADMIN_USERNAME must be set in a local .env file."
        )

    if not ADMIN_PASSWORD_HASH:
        raise ValueError(
            "Environment variable ADMIN_PASSWORD_HASH must be set in a local .env file."
        )

    # Initialize local HIBP database if configured (uses binary search - no memory loading)
    hibp_local_db_path = os.getenv("HIBP_LOCAL_DB_PATH", "").strip()
    if hibp_local_db_path:
        from hibp_checker import init_local_hibp_database
        print(f"\n--> Checking local HIBP database at: {hibp_local_db_path}")
        success, message, estimated_entries = init_local_hibp_database(hibp_local_db_path)
        if success:
            print(f"--> Local HIBP database ready: ~{estimated_entries:,} hashes (binary search, no memory loading)")
        else:
            print(f"--> Warning: Could not initialize local HIBP database: {message}")
    else:
        print("\n--> No local HIBP database configured (HIBP_LOCAL_DB_PATH not set)")

    # Preload master potfile cache at startup for instant first request
    if MASTER_POTFILE_ENABLED and os.path.exists(MASTER_POTFILE_PATH):
        print(f"\n--> Loading master potfile cache: {MASTER_POTFILE_PATH}")
        cache = get_master_cache()
        cache.load(MASTER_POTFILE_PATH)
        stats = cache.get_stats()
        if stats:
            print(f"--> Master potfile cache ready: {stats['ntlm_count']:,} hashes")

    # Start Flask application with threading for better performance
    # Threading allows handling multiple concurrent requests (important for report page)
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"), debug=False, threaded=True)
