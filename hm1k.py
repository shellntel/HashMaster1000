import os
import subprocess
import sys
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
from typing import Dict, Union, Optional, cast
# Import file parser module for validation
import file_parser

# Load environment variables at module level so they're available for route handlers
# Use override=True to ensure .env file values take precedence over any cached env vars
load_dotenv(override=True)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")


def validate_libraries():
    # Define required libraries and their import names
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


def validate_files():
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
    def __init__(self, username: str, password_hash: Optional[str] = None):
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
def basename_filter(path: Optional[str]) -> str:
    """Jinja filter to get basename of a path."""
    return os.path.basename(path) if path else ''

# Custom Jinja test for checking if username ends with $ (computer account)
@app.template_test('computer_account')
def is_computer_account(username: Optional[str]) -> bool:
    """Jinja test to check if a username is a computer account (ends with $)."""
    return bool(username and username.endswith('$'))

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
def load_user(user_id: str) -> Optional[User]:
    # Return the admin user if the ID matches
    if user_id == ADMIN_USERNAME:
        return User(username=ADMIN_USERNAME)
    return None


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

    # Only pass validation data when going directly to step 3
    # (coming from validation review with Continue to Configuration)
    pwdump_validation = None
    potfile_validation = None
    if initial_step == 3:
        pwdump_validation = session.get("pwdump_validation")
        potfile_validation = session.get("potfile_validation")

    return render_template(
        "index.html",
        initial_step=initial_step,
        pwdump_validation=pwdump_validation,
        potfile_validation=potfile_validation
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

        # Run detailed validation using file_parser module
        pwdump_result = file_parser.validate_pwdump_file(pwdump_path)
        potfile_result = file_parser.validate_potfile(potfile_path)

        # Store validation results in session
        session["pwdump_validation"] = file_parser.validation_result_to_dict(pwdump_result)
        session["potfile_validation"] = file_parser.potfile_result_to_dict(potfile_result)
        session["pwdump_path"] = pwdump_path
        session["potfile_path"] = potfile_path

        # Store form options for later processing
        session["analysis_options"] = {
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

        # Always redirect to validation review page (Step 2) so users can see
        # exactly what data will be processed before configuring analysis options
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

        # Run detailed validation using file_parser module
        pwdump_result = file_parser.validate_pwdump_file(pwdump_path)
        potfile_result = file_parser.validate_potfile(potfile_path)

        # Store validation results in session
        session["pwdump_validation"] = file_parser.validation_result_to_dict(pwdump_result)
        session["potfile_validation"] = file_parser.potfile_result_to_dict(potfile_result)
        session["pwdump_path"] = pwdump_path
        session["potfile_path"] = potfile_path

        # Store form options for later processing
        session["analysis_options"] = {
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

    # Need at least one file to show review
    if not pwdump_data and not potfile_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    return make_response(render_template(
        "validate.html",
        pwdump=pwdump_data,
        potfile=potfile_data
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
            result = file_parser.validate_pwdump_file(file_path)
            result_dict = file_parser.validation_result_to_dict(result)

            # Store in session for validation review access
            session["pwdump_validation"] = result_dict
            session["pwdump_path"] = file_path
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
    """
    pwdump_data = session.get("pwdump_validation")
    potfile_data = session.get("potfile_validation")

    # Get options from form data if POST, otherwise from session
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
        }
        # Store in session for consistency
        session["analysis_options"] = options
    else:
        options = session.get("analysis_options", {})
    pwdump_path = session.get("pwdump_path")
    potfile_path = session.get("potfile_path")

    if not pwdump_data or not potfile_data:
        return cast(FlaskResponse, redirect(url_for("index")))

    try:
        # Reconstruct validation results from session
        pwdump_result = file_parser.dict_to_validation_result(pwdump_data)
        potfile_result = file_parser.dict_to_potfile_result(potfile_data)

        # Build account data using only included lines
        account_data = file_parser.build_account_data(
            pwdump_result,
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

        # Import analysis tools
        import password_analysis_tools

        # Run analysis
        stats_report = password_analysis_tools.crack_stats(
            account_data,
            int(options.get("policy_min_pw_len", "8")),
            int(options.get("policy_complexity_req", "3")),
            ignore_blank_passwords=options.get("ignore_blank_passwords", "false") == "true",
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

        # Create list of cracked passwords
        cracked_passwords = [
            account["cracked_pw"]
            for account in account_data.values()
            if account.get("cracked_pw")
        ]

        # Run substring analysis
        substrings = password_analysis_tools.substring_analysis(
            cracked_passwords,
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

        # Write JSON files
        with open("data/cracking_stats_table.json", "w") as f:
            json.dump(stats_table, f, indent=4)
        with open("data/pw_account_pie.json", "w") as f:
            json.dump(stats_report["pw_account_pie"], f)
        with open("data/pw_ntlm_hash_pie.json", "w") as f:
            json.dump(stats_report["pw_ntlm_hash_pie"], f)
        with open("data/pw_length_distribution.json", "w") as f:
            json.dump(stats_report["pw_length_distribution"], f)
        with open("data/pw_top_passwords.json", "w") as f:
            json.dump(stats_report["pw_top_passwords"], f)
        with open("data/pw_substrings.json", "w") as f:
            json.dump(substrings, f, indent=4)
        with open("data/pw_dict_words.json", "w") as f:
            json.dump(english_words, f, indent=4)
        with open("data/pw_reuse_table.json", "w") as f:
            json.dump(pw_reuse_table, f)
        with open("data/pw_fails_min_length.json", "w") as f:
            json.dump(stats_report["pw_fails_min_length"], f)
        with open("data/pw_fails_complexity.json", "w") as f:
            json.dump(stats_report["pw_fails_complexity"], f)
        with open("data/pw_fails_blank.json", "w") as f:
            json.dump(stats_report["pw_fails_blank"], f)
        with open("data/pw_fails_max_age.json", "w") as f:
            json.dump(stats_report["pw_fails_max_age"], f)
        with open("data/pw_lm_hashes.json", "w") as f:
            json.dump(stats_report["pw_lm_hashes"], f)
        with open("data/pw_bad_practices.json", "w") as f:
            json.dump(bad_practices, f)
        with open("data/account_data.json", "w") as f:
            json.dump(account_data, f)

        # Clean up session
        session.pop("pwdump_validation", None)
        session.pop("potfile_validation", None)
        session.pop("pwdump_path", None)
        session.pop("potfile_path", None)
        session.pop("analysis_options", None)

        print("\nPassword and hash analysis complete via validation flow.\n")
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


# Endpoint for Project Statistics Table
@app.route("/cracking_stats_table")
@login_required
def cracking_stats_table() -> Response:
    with open("data/cracking_stats_table.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Cracked Accounts Pie Chart data
@app.route("/pw_account_pie")
@login_required
def pw_account_pie() -> Response:
    with open("data/pw_account_pie.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Cracked Hashes Pie Chart data
@app.route("/pw_ntlm_hash_pie")
@login_required
def pw_ntlm_hash_pie() -> Response:
    with open("data/pw_ntlm_hash_pie.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Length Distribution Bar Chart data
@app.route("/pw_length_distribution")
@login_required
def pw_length_distribution() -> Response:
    with open("data/pw_length_distribution.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Top X Cracked Passwords Bar Chart data
@app.route("/pw_top_passwords")
@login_required
def pw_top_passwords() -> Response:
    with open("data/pw_top_passwords.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Top X Substrings Bar Chart data
@app.route("/pw_substrings")
@login_required
def pw_substrings() -> Response:
    with open("data/pw_substrings.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Top X Dictionary Words Bar Chart data
@app.route("/pw_dict_words")
@login_required
def pw_dict_words() -> Response:
    with open("data/pw_dict_words.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Reuse Table data
@app.route("/pw_reuse_table")
@login_required
def pw_reuse_table() -> Response:
    with open("data/pw_reuse_table.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Min Length
@app.route("/pw_fails_min_length")
@login_required
def pw_min_len_table() -> Response:
    with open("data/pw_fails_min_length.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Complexity
@app.route("/pw_fails_complexity")
@login_required
def pw_complexity_table() -> Response:
    with open("data/pw_fails_complexity.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Blank
@app.route("/pw_fails_blank")
@login_required
def pw_blank_table() -> Response:
    with open("data/pw_fails_blank.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Max Age
@app.route("/pw_fails_max_age")
@login_required
def pw_max_age_table() -> Response:
    with open("data/pw_fails_max_age.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Accounts with LM Hashes
@app.route("/pw_lm_hashes")
@login_required
def pw_lm_hashes_table() -> Response:
    with open("data/pw_lm_hashes.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Bad Practices Analysis
@app.route("/pw_bad_practices")
@login_required
def pw_bad_practices() -> Response:
    with open("data/pw_bad_practices.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Downloading JSON Files
JSON_FOLDER = os.path.join(os.getcwd(), "data")


@app.route("/download/<filename>")
@login_required
def download_file(filename: str) -> Response:
    try:
        if not filename.endswith(".json"):
            abort(403)  # Forbidden
        return send_from_directory(JSON_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)  # File not found


@app.route("/list_json_files", methods=["GET"])
@login_required
def list_json_files() -> Response:
    try:
        files = [f for f in os.listdir(JSON_FOLDER) if f.endswith(".json")]
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
            result = file_parser.validate_pwdump_file(file_path)
            result_dict = file_parser.validation_result_to_dict(result)

            # Store in session for validation review access
            session["pwdump_validation"] = result_dict
            session["pwdump_path"] = file_path
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
                "size": None
            })

        # List directory contents
        for entry in sorted(os.listdir(abs_path)):
            entry_path = os.path.join(abs_path, entry)
            try:
                is_dir = os.path.isdir(entry_path)
                size = None if is_dir else os.path.getsize(entry_path)
                entries.append({
                    "name": entry,
                    "path": entry_path,
                    "is_dir": is_dir,
                    "size": size
                })
            except (PermissionError, OSError):
                # Skip entries we can't access
                continue

        # Sort: directories first, then files, both alphabetically
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
def ai_status():
    """Check Ollama AI integration status."""
    from ollama_tools import test_ollama_connection, get_ollama_config

    config = get_ollama_config()
    result = test_ollama_connection()

    return jsonify(result)


@app.route("/api/ai/models", methods=["GET"])
@login_required
def ai_models():
    """Get list of available models from Ollama server."""
    from ollama_tools import OllamaClient, get_ollama_config

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    client = OllamaClient(config)
    models = client.list_models()

    return jsonify({"models": models})


@app.route("/api/ai/library", methods=["GET"])
@login_required
def ai_library_models():
    """Get list of popular models available to pull from Ollama library."""
    from ollama_tools import get_available_library_models

    models = get_available_library_models()
    return jsonify({"models": models})


@app.route("/api/ai/presets", methods=["GET"])
@login_required
def ai_presets():
    """Get analysis preset configurations."""
    from ollama_tools import get_analysis_presets

    presets = get_analysis_presets()
    return jsonify({"presets": presets})


@app.route("/api/ai/pull", methods=["POST"])
@login_required
def ai_pull_model():
    """Pull (download) a model from Ollama library."""
    from ollama_tools import pull_model, get_ollama_config

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    data = request.get_json() or {}
    model_name = data.get("model")

    if not model_name:
        return jsonify({"error": "Model name is required"}), 400

    result = pull_model(model_name)
    if result["success"]:
        return jsonify(result)
    else:
        return jsonify(result), 500


@app.route("/api/ai/delete", methods=["POST"])
@login_required
def ai_delete_model():
    """Delete a model from the Ollama server."""
    from ollama_tools import delete_model, get_ollama_config

    config = get_ollama_config()
    if not config.enabled:
        return jsonify({"error": "Ollama integration is not enabled"}), 400

    data = request.get_json() or {}
    model_name = data.get("model")

    if not model_name:
        return jsonify({"error": "Model name is required"}), 400

    result = delete_model(model_name)
    if result["success"]:
        return jsonify(result)
    else:
        return jsonify(result), 500


@app.route("/api/ai/generate", methods=["POST"])
@login_required
def ai_generate():
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
def ai_executive_summary():
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
def ai_analyze_patterns():
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
def ai_cluster_passwords():
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
def ai_attack_strategy():
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
def ai_list_servers():
    """Get all configured Ollama servers and their status."""
    from ollama_tools import test_all_servers
    return jsonify(test_all_servers())


@app.route("/api/ai/servers/<server_id>/status", methods=["GET"])
@login_required
def ai_server_status(server_id):
    """Get status of a specific Ollama server."""
    from ollama_tools import test_ollama_connection, get_server_by_id
    server = get_server_by_id(server_id)
    if not server:
        return jsonify({"error": f"Unknown server: {server_id}"}), 404

    status = test_ollama_connection(host=server.host)
    return jsonify({
        "id": server.id,
        "name": server.name,
        "host": server.host,
        "description": server.description,
        "hardware": server.hardware,
        **status
    })


@app.route("/api/ai/report/sections", methods=["GET"])
@login_required
def ai_report_sections():
    """Get all AI report section configurations."""
    from ollama_tools import get_ai_report_sections
    return jsonify({"sections": get_ai_report_sections()})


@app.route("/api/ai/report/analyze/<section_id>", methods=["POST"])
@login_required
def ai_report_analyze_section(section_id):
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
    result = analyzer.generate_section(
        section_id=section_id,
        data=data,
        model=model,
        temperature=temperature
    )

    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    elapsed_seconds = round(elapsed_time, 1)
    elapsed_formatted = f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s" if elapsed_time >= 60 else f"{elapsed_seconds}s"

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
            "response_time_formatted": elapsed_formatted
        }

        if seems_off_topic:
            response_data["warning"] = f"Response may be off-topic - only {keyword_matches} password-related keywords detected. The model may not be suitable for this task."

        return jsonify(response_data)
    else:
        return jsonify({"error": "Failed to generate analysis", "server_id": server_id, "server_name": server_name, "response_time_seconds": elapsed_seconds, "response_time_formatted": elapsed_formatted}), 500


@app.route("/api/ai/report/cache", methods=["GET"])
@login_required
def ai_report_get_cache():
    """Get cached AI report analyses from session."""
    cache = session.get("ai_report_cache", {})
    return jsonify({"cache": cache})


@app.route("/api/ai/report/cache/<section_id>", methods=["DELETE"])
@login_required
def ai_report_clear_section_cache(section_id):
    """Clear cached analysis for a specific section."""
    if "ai_report_cache" in session and section_id in session["ai_report_cache"]:
        del session["ai_report_cache"][section_id]
        session.modified = True
    return jsonify({"success": True})


@app.route("/api/ai/report/cache", methods=["DELETE"])
@login_required
def ai_report_clear_all_cache():
    """Clear all cached AI report analyses."""
    session["ai_report_cache"] = {}
    session.modified = True
    return jsonify({"success": True})


@app.route("/api/ai/report/outputs", methods=["GET"])
@login_required
def ai_report_list_outputs():
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
def ai_report_get_output(filename):
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
def ai_report_data_summary():
    """Get summary of available analysis data for AI reports."""
    from ollama_tools import get_ai_data_loader

    loader = get_ai_data_loader()
    summary = loader.get_data_summary()
    return jsonify(summary)


@app.route("/api/ai/report/data/<section_id>", methods=["GET"])
@login_required
def ai_report_section_data(section_id):
    """
    Get pre-loaded analysis data for a specific AI report section.

    Returns the data that would be sent to the AI for this section,
    loaded from the /data JSON files.
    """
    from ollama_tools import get_ai_data_loader, get_ai_report_sections

    sections = get_ai_report_sections()
    if section_id not in sections:
        return jsonify({"error": f"Unknown section: {section_id}"}), 400

    loader = get_ai_data_loader()

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
def ai_report_all_section_data():
    """
    Get pre-loaded analysis data for all AI report sections.

    Useful for initializing the test page with real data.
    """
    from ollama_tools import get_ai_data_loader, get_ai_report_sections

    loader = get_ai_data_loader()

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
def ai_report_section_prompt(section_id):
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

    loader = get_ai_data_loader()

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
def ai_report_test_page():
    """AI Report Analysis test page for experimenting with report sections."""
    from ollama_tools import test_ollama_connection, test_all_servers, get_ai_report_sections, get_ai_data_loader

    # Get all server statuses
    servers_status = test_all_servers()
    sections = get_ai_report_sections()

    # Check if real analysis data is available
    loader = get_ai_data_loader()
    data_summary = loader.get_data_summary()

    # Build model options HTML from all servers (combine unique models)
    all_models = set()
    reachable_servers = [s for s in servers_status.get("servers", []) if s.get("reachable")]
    for server in reachable_servers:
        all_models.update(server.get("available_models", []))
    all_models = sorted(all_models)

    model_options = ""
    for model in all_models:
        model_options += f'<option value="{model}">{model}</option>'

    # Build benchmark model options (only models available on ALL reachable servers)
    if len(reachable_servers) >= 2:
        benchmark_models = set(reachable_servers[0].get("available_models", []))
        for server in reachable_servers[1:]:
            benchmark_models &= set(server.get("available_models", []))
        benchmark_models = sorted(benchmark_models)
    else:
        benchmark_models = all_models  # Fall back to all models if < 2 servers

    benchmark_model_options = ""
    for model in benchmark_models:
        benchmark_model_options += f'<option value="{model}">{model}</option>'

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
            <button onclick="refreshServerStatus('{server['id']}')" class="secondary refresh-btn">↻</button>
        </div>
        '''

    # Build sections HTML with data source info
    sections_html = ""
    for section_id, config in sorted(sections.items(), key=lambda x: x[1].get("order", 99)):
        data_sources = config.get("data_sources", {})
        sources_list = ", ".join(data_sources.keys())
        sections_html += f'''
        <div class="report-section" id="section-{section_id}">
            <div class="section-header">
                <div class="section-info">
                    <h3>{config["title"]}</h3>
                    <p class="section-desc">{config["description"]}</p>
                    <p class="section-sources">Data: {sources_list}</p>
                </div>
                <div class="section-controls">
                    <select id="server-{section_id}" class="server-select">
                        {server_options}
                    </select>
                    <select id="model-{section_id}" class="model-select">
                        {model_options}
                    </select>
                    <input type="range" id="temp-{section_id}" min="0" max="1" step="0.1" value="{config["temperature"]}" class="temp-slider">
                    <span id="temp-value-{section_id}" class="temp-value">{config["temperature"]}</span>
                    <button onclick="analyzeSection('{section_id}')" class="analyze-btn">Analyze</button>
                    <button onclick="clearSection('{section_id}')" class="secondary clear-btn">Clear</button>
                </div>
            </div>
            <div class="section-data-preview" id="data-preview-{section_id}">
                <button onclick="toggleDataPreview('{section_id}')" class="secondary toggle-data-btn">Show Data</button>
                <button onclick="togglePromptPreview('{section_id}')" class="secondary toggle-prompt-btn">Show Prompt</button>
                <div class="data-preview-content" id="data-content-{section_id}" style="display:none;">
                    <pre>Loading...</pre>
                </div>
                <div class="prompt-preview-content" id="prompt-content-{section_id}" style="display:none;">
                    <pre>Loading...</pre>
                </div>
            </div>
            <div class="section-content" id="content-{section_id}">
                <span class="placeholder">Click "Analyze" to generate this section</span>
            </div>
        </div>
        '''

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>HM1K AI Report Analysis</title>
        <style>
            body { font-family: system-ui, sans-serif; max-width: 1400px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #eee; }
            h1 { color: #00d4ff; margin-bottom: 5px; }
            h2 { color: #00d4ff; margin-top: 0; }
            h3 { color: #00d4ff; margin: 0; }
            .subtitle { color: #888; margin-bottom: 20px; }
            .status { padding: 15px; border-radius: 8px; margin-bottom: 15px; }
            .status.ok { background: #1e3a1e; border: 1px solid #4caf50; }
            .status.error { background: #3a1e1e; border: 1px solid #f44336; }
            .status.warning { background: #3a3a1e; border: 1px solid #ff9800; }
            .nav-links { margin-bottom: 20px; }
            .nav-links a { color: #00d4ff; margin-right: 20px; }
            .report-section { background: #16213e; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }
            .section-header { padding: 15px 20px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
            .section-info { flex: 1; min-width: 250px; }
            .section-desc { color: #888; font-size: 0.9em; margin: 5px 0 0 0; }
            .section-sources { color: #666; font-size: 0.8em; margin: 3px 0 0 0; }
            .section-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
            .section-content { padding: 20px; min-height: 100px; }
            .section-content .placeholder { color: #666; font-style: italic; }
            .section-content .analysis { white-space: pre-wrap; line-height: 1.6; }
            .section-data-preview { padding: 10px 20px; background: #0f0f1a; border-bottom: 1px solid #333; display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-start; }
            .section-data-preview .toggle-data-btn, .section-data-preview .toggle-prompt-btn { font-size: 0.85em; padding: 4px 10px; }
            .data-preview-content, .prompt-preview-content { margin-top: 10px; width: 100%; }
            .data-preview-content pre, .prompt-preview-content pre { margin: 0; white-space: pre-wrap; font-size: 0.8em; color: #888; max-height: 400px; overflow-y: auto; background: #0a0a15; padding: 10px; border-radius: 4px; }
            .prompt-preview-content pre { color: #a8d8a8; }
            .prompt-preview-content .system-prompt { color: #d8a8d8; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px dashed #444; }
            .prompt-preview-content .prompt-label { color: #00d4ff; font-weight: bold; margin-bottom: 5px; display: block; }
            button { background: #00d4ff; color: #000; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; }
            button:hover { background: #00b8e6; }
            button:disabled { background: #555; cursor: not-allowed; }
            button.secondary { background: #555; color: #fff; }
            button.secondary:hover { background: #666; }
            button.danger { background: #f44336; color: #fff; }
            button.success { background: #4caf50; color: #fff; }
            select { background: #0f0f1a; color: #eee; border: 1px solid #333; padding: 6px 10px; border-radius: 4px; font-size: 13px; }
            .model-select { min-width: 180px; }
            .temp-slider { width: 80px; }
            .temp-value { color: #00d4ff; font-weight: bold; min-width: 30px; }
            .loading { color: #00d4ff; }
            .timer { display: inline-block; color: #ff9800; font-weight: bold; font-family: monospace; font-size: 1.1em; }
            .response-time { color: #4caf50; font-weight: bold; }
            .response-time-info { margin-top: 10px; padding: 8px 12px; background: #1e3a1e; border: 1px solid #4caf50; border-radius: 4px; color: #4caf50; font-size: 0.9em; }
            .error { color: #f44336; }
            .data-section { background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .data-mode-toggle { display: flex; gap: 10px; margin-bottom: 15px; align-items: center; }
            .data-mode-toggle label { color: #888; }
            .data-stats { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 15px; }
            .data-stat { background: #0f0f1a; padding: 10px 15px; border-radius: 6px; }
            .data-stat .label { color: #888; font-size: 0.85em; }
            .data-stat .value { color: #00d4ff; font-size: 1.2em; font-weight: bold; }
            .files-list { display: flex; flex-wrap: wrap; gap: 8px; }
            .file-tag { background: #1e3a1e; color: #4caf50; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }
            .file-tag.missing { background: #3a1e1e; color: #f44336; }
            textarea { width: 100%; background: #0f0f1a; color: #eee; border: 1px solid #333; border-radius: 4px; padding: 10px; font-family: monospace; box-sizing: border-box; resize: vertical; }
            .data-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
            .data-field label { display: block; color: #888; margin-bottom: 5px; font-size: 0.9em; }
            .hidden { display: none !important; }
            .save-notice { margin-top: 10px; padding: 8px 12px; background: #1e3a1e; border: 1px solid #4caf50; border-radius: 4px; color: #4caf50; font-size: 0.85em; }
            .offtopic-warning { margin-bottom: 15px; padding: 12px 15px; background: #3a2a1e; border: 1px solid #ff9800; border-radius: 4px; color: #ff9800; font-size: 0.9em; }
            .outputs-section { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
            .outputs-section h3 { color: #00d4ff; margin: 0 0 15px 0; }
            .outputs-list { max-height: 300px; overflow-y: auto; }
            .output-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #0f0f1a; border-radius: 4px; margin-bottom: 8px; }
            .output-item:hover { background: #1a1a2e; }
            .output-filename { color: #00d4ff; font-family: monospace; font-size: 0.85em; cursor: pointer; }
            .output-meta { color: #666; font-size: 0.8em; }
            .output-actions button { padding: 4px 8px; font-size: 0.8em; margin-left: 8px; }
            /* Server status styles */
            .servers-section { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
            .servers-section h3 { color: #00d4ff; margin: 0 0 15px 0; }
            .servers-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
            .server-card { background: #0f0f1a; border-radius: 8px; padding: 15px; position: relative; border: 2px solid #333; }
            .server-card.ok { border-color: #4caf50; }
            .server-card.error { border-color: #f44336; opacity: 0.7; }
            .server-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
            .server-status-dot { width: 12px; height: 12px; border-radius: 50%; }
            .server-card.ok .server-status-dot { background: #4caf50; box-shadow: 0 0 8px #4caf50; }
            .server-card.error .server-status-dot { background: #f44336; }
            .server-details { font-size: 0.85em; }
            .server-host { color: #00d4ff; font-family: monospace; }
            .server-info { color: #888; margin: 5px 0; }
            .server-models { color: #666; }
            .server-card .refresh-btn { position: absolute; top: 10px; right: 10px; padding: 4px 8px; font-size: 0.8em; }
            .server-select { min-width: 140px; }
            /* Benchmark styles */
            .benchmark-section { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
            .benchmark-section h3 { color: #00d4ff; margin: 0 0 15px 0; }
            .benchmark-controls { display: flex; gap: 15px; align-items: center; flex-wrap: wrap; margin-bottom: 15px; }
            .benchmark-results { margin-top: 15px; }
            .benchmark-result { background: #0f0f1a; border-radius: 8px; padding: 15px; margin-bottom: 10px; }
            .benchmark-result h4 { color: #00d4ff; margin: 0 0 10px 0; }
            .benchmark-bar { height: 24px; background: #333; border-radius: 4px; overflow: hidden; margin: 5px 0; }
            .benchmark-bar-fill { height: 100%; background: linear-gradient(90deg, #00d4ff, #4caf50); display: flex; align-items: center; justify-content: flex-end; padding-right: 10px; color: #000; font-weight: bold; font-size: 0.8em; }
            /* Benchmark test items */
            .test-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 8px; }
            .test-item { display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: #0f0f1a; border-radius: 6px; border: 1px solid #333; }
            .test-item:hover { border-color: #00d4ff; }
            .test-item input[type="checkbox"] { width: 18px; height: 18px; cursor: pointer; }
            .test-item label { cursor: pointer; flex: 1; }
            .test-item label strong { color: #00d4ff; }
            /* Matrix run styles */
            .matrix-section { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #4caf50; }
            .matrix-section h3 { color: #4caf50; margin: 0 0 15px 0; }
            .matrix-controls { display: flex; gap: 15px; align-items: center; flex-wrap: wrap; margin-bottom: 15px; }
            .matrix-progress { margin-top: 15px; }
            .matrix-progress-bar { height: 30px; background: #333; border-radius: 4px; overflow: hidden; margin: 10px 0; }
            .matrix-progress-fill { height: 100%; background: linear-gradient(90deg, #4caf50, #00d4ff); transition: width 0.3s; display: flex; align-items: center; justify-content: center; color: #000; font-weight: bold; }
            .matrix-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; margin-top: 15px; }
            .matrix-item { background: #0f0f1a; border-radius: 8px; padding: 12px; border: 1px solid #333; }
            .matrix-item.running { border-color: #00d4ff; animation: pulse 1s infinite; }
            .matrix-item.complete { border-color: #4caf50; }
            .matrix-item.error { border-color: #f44336; }
            .matrix-item-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
            .matrix-item-title { font-weight: bold; color: #00d4ff; }
            .matrix-item-status { font-size: 0.9em; }
            .matrix-item-time { color: #888; font-size: 0.85em; }
            @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        </style>
    </head>
    <body>
        <h1>AI Report Analysis</h1>
        <p class="subtitle">Test and refine AI-generated report sections</p>

        <div class="nav-links">
            <a href="/api/ai/test">&larr; Back to AI Test Console</a>
            <a href="/report">View Main Report</a>
        </div>

        <div class="servers-section">
            <h3>Ollama Servers</h3>
            <div class="servers-grid" id="servers-grid">
                """ + server_cards_html + """
            </div>
        </div>

        <div class="benchmark-section">
            <h3>Benchmark Tests</h3>
            <p style="color: #888; margin-bottom: 15px;">Run predefined tests against a single server to evaluate model performance with real-world prompts.</p>
            <div class="benchmark-controls">
                <label style="color: #888;">Server:</label>
                <select id="benchmark-server" class="server-select">
                    """ + server_options + """
                </select>
                <label style="color: #888; margin-left: 15px;">Model:</label>
                <select id="benchmark-model" class="model-select">
                    """ + model_options + """
                </select>
            </div>
            <div class="benchmark-tests" style="margin-top: 15px;">
                <h4 style="color: #888; margin-bottom: 10px;">Available Tests</h4>
                <div class="test-list">
                    <div class="test-item">
                        <input type="checkbox" id="test-weak-habits" checked>
                        <label for="test-weak-habits"><strong>Weak Password Habits</strong> - Pattern analysis with real password data</label>
                    </div>
                    <div class="test-item">
                        <input type="checkbox" id="test-company-intel" checked>
                        <label for="test-company-intel"><strong>Company Intelligence</strong> - OSINT from passwords and accounts</label>
                    </div>
                    <div class="test-item">
                        <input type="checkbox" id="test-user-behavior" checked>
                        <label for="test-user-behavior"><strong>User Behavior</strong> - Psychological analysis</label>
                    </div>
                    <div class="test-item">
                        <input type="checkbox" id="test-risk-assessment">
                        <label for="test-risk-assessment"><strong>Risk Assessment</strong> - Business risk quantification</label>
                    </div>
                    <div class="test-item">
                        <input type="checkbox" id="test-recommendations">
                        <label for="test-recommendations"><strong>Recommendations</strong> - Prioritized security actions</label>
                    </div>
                    <div class="test-item">
                        <input type="checkbox" id="test-reasoning">
                        <label for="test-reasoning"><strong>Reasoning Test</strong> - Logic and deduction challenge</label>
                    </div>
                    <div class="test-item">
                        <input type="checkbox" id="test-summarization">
                        <label for="test-summarization"><strong>Summarization</strong> - Condense long text accurately</label>
                    </div>
                </div>
                <div style="margin-top: 15px;">
                    <label style="color: #888;">Temperature:</label>
                    <input type="range" id="benchmark-temp" min="0" max="1" step="0.1" value="0.3" style="width: 100px;">
                    <span id="benchmark-temp-value" style="color: #00d4ff; font-weight: bold;">0.3</span>
                    <button onclick="runBenchmarkTests()" id="benchmark-btn" style="margin-left: 20px;">Run Selected Tests</button>
                    <button onclick="stopBenchmark()" id="benchmark-stop-btn" class="danger" style="display: none;">Stop</button>
                    <span id="benchmark-status" style="color: #888; margin-left: 15px;"></span>
                </div>
            </div>
            <div id="benchmark-progress" style="display: none; margin-top: 15px;">
                <div class="matrix-progress-bar">
                    <div class="matrix-progress-fill" id="benchmark-progress-fill" style="width: 0%;">0%</div>
                </div>
            </div>
            <div id="benchmark-results" style="margin-top: 15px;"></div>
        </div>

        <div class="matrix-section">
            <h3>Full Matrix Run (All Sections x All Models)</h3>
            <p style="color: #888; margin-bottom: 15px;">Run every report section against every available model on a single server. Sit back and relax while it runs!</p>
            <div class="matrix-controls">
                <label style="color: #888;">Server:</label>
                <select id="matrix-server" class="server-select">
                    """ + server_options + """
                </select>
                <label style="color: #888; margin-left: 15px;">Temperature:</label>
                <input type="range" id="matrix-temp" min="0" max="1" step="0.1" value="0.5" style="width: 100px;">
                <span id="matrix-temp-value" style="color: #00d4ff; font-weight: bold;">0.5</span>
                <button onclick="runMatrix()" id="matrix-btn" style="background: #4caf50;">Run Full Matrix</button>
                <button onclick="stopMatrix()" id="matrix-stop-btn" class="danger" style="display: none;">Stop</button>
            </div>
            <div id="matrix-status" style="color: #888; margin-top: 10px;"></div>
            <div id="matrix-progress" class="matrix-progress" style="display: none;">
                <div class="matrix-progress-bar">
                    <div class="matrix-progress-fill" id="matrix-progress-fill" style="width: 0%;">0%</div>
                </div>
            </div>
            <div id="matrix-results" class="matrix-grid"></div>
        </div>

        <div class="status """ + ("ok" if data_summary["has_data"] else "warning") + """" id="data-status">
            <strong>Analysis Data:</strong>
            """ + (f"Loaded - {data_summary['stats'].get('total_accounts', 0)} accounts, {data_summary['stats'].get('cracked_accounts', 0)} cracked ({data_summary['stats'].get('crack_percent', '0%')})" if data_summary["has_data"] else "No analysis data found. Run a password analysis first, or use sample data below.") + """
            <div class="files-list" style="margin-top: 10px;">
                """ + "".join([f'<span class="file-tag">{f}</span>' for f in data_summary.get("files_found", [])]) + """
                """ + "".join([f'<span class="file-tag missing">{f} (missing)</span>' for f in data_summary.get("files_missing", [])]) + """
            </div>
        </div>

        <div class="data-section">
            <div class="data-mode-toggle">
                <label><input type="radio" name="data-mode" value="auto" """ + ("checked" if data_summary["has_data"] else "") + """ onchange="setDataMode('auto')"> Use Analysis Data</label>
                <label><input type="radio" name="data-mode" value="manual" """ + ("" if data_summary["has_data"] else "checked") + """ onchange="setDataMode('manual')"> Use Sample/Custom Data</label>
                <button onclick="loadRealData()" class="secondary" style="margin-left: auto;">Reload Analysis Data</button>
            </div>

            <div id="manual-data-section" class=\"""" + ("hidden" if data_summary["has_data"] else "") + """\">
                <h3 style="color: #888; margin-bottom: 15px;">Sample Data (editable)</h3>
                <div class="data-grid">
                    <div class="data-field">
                        <label>Top Passwords (JSON: {"password": count})</label>
                        <textarea id="data-top-passwords" rows="6">{"Summer2024": 45, "Welcome1!": 38, "Password123": 32, "Company2024!": 28, "Winter2023": 25, "qwerty123": 22, "Baseball1": 18, "Football!": 15}</textarea>
                    </div>
                    <div class="data-field">
                        <label>Password Samples (one per line)</label>
                        <textarea id="data-password-samples" rows="6">Summer2024
Welcome1!
Password123
Company2024!
JohnSmith1
Yankees2024
Chicago99!
Packers!23</textarea>
                    </div>
                    <div class="data-field">
                        <label>Top Substrings (JSON array)</label>
                        <textarea id="data-substrings" rows="6">[{"substring": "2024", "count": 234}, {"substring": "2023", "count": 189}, {"substring": "pass", "count": 156}, {"substring": "summer", "count": 89}, {"substring": "welcome", "count": 67}]</textarea>
                    </div>
                    <div class="data-field">
                        <label>Bad Practices (JSON)</label>
                        <textarea id="data-bad-practices" rows="6">{"Season+Year": {"count": 234, "examples": {"Summer2024": 12, "Winter2023": 8}}, "Common Words": {"count": 456, "examples": {"Password": 45, "Welcome": 38}}, "Keyboard Patterns": {"count": 89, "examples": {"qwerty": 22, "123456": 15}}}</textarea>
                    </div>
                </div>
            </div>

            <div id="auto-data-section" class=\"""" + ("" if data_summary["has_data"] else "hidden") + """\">
                <div class="data-stats">
                    <div class="data-stat">
                        <div class="label">Total Accounts</div>
                        <div class="value" id="stat-total">""" + str(data_summary['stats'].get('total_accounts', 0)) + """</div>
                    </div>
                    <div class="data-stat">
                        <div class="label">Cracked</div>
                        <div class="value" id="stat-cracked">""" + str(data_summary['stats'].get('cracked_accounts', 0)) + """</div>
                    </div>
                    <div class="data-stat">
                        <div class="label">Crack Rate</div>
                        <div class="value" id="stat-percent">""" + str(data_summary['stats'].get('crack_percent', '0%')) + """</div>
                    </div>
                </div>
                <p style="color: #888; font-size: 0.9em;">Data is automatically loaded from your most recent analysis. Click "Show Data" on each section to preview what will be sent to the AI.</p>
            </div>
        </div>

        <div class="outputs-section">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <h3 style="margin: 0;">Saved Test Outputs</h3>
                <button onclick="toggleOutputsList()" class="secondary" id="toggle-outputs-btn">Show Outputs</button>
            </div>
            <div id="outputs-list" style="display: none;">
                <p style="color: #888; font-size: 0.9em; margin-bottom: 10px;">All test runs are automatically saved to <code>test_outputs/</code> for comparison.</p>
                <div id="outputs-content">
                    <span class="placeholder">Loading...</span>
                </div>
            </div>
        </div>

        <h2>Report Sections</h2>
        """ + sections_html + """

        <script>
            // State
            let dataMode = '""" + ("auto" if data_summary["has_data"] else "manual") + """';
            let analysisData = null;  // Cached real data

            // Initialize temperature sliders
            document.querySelectorAll('.temp-slider').forEach(slider => {
                slider.addEventListener('input', function() {
                    const sectionId = this.id.replace('temp-', '');
                    document.getElementById('temp-value-' + sectionId).textContent = this.value;
                });
            });

            // Set recommended models on load
            const recommendedModels = """ + json.dumps({sid: cfg["recommended_model"] for sid, cfg in sections.items()}) + """;
            Object.entries(recommendedModels).forEach(([sectionId, model]) => {
                const select = document.getElementById('model-' + sectionId);
                if (select) {
                    const options = Array.from(select.options);
                    const match = options.find(opt => opt.value.includes(model.split(':')[0]));
                    if (match) select.value = match.value;
                }
            });

            function setDataMode(mode) {
                dataMode = mode;
                document.getElementById('manual-data-section').classList.toggle('hidden', mode === 'auto');
                document.getElementById('auto-data-section').classList.toggle('hidden', mode === 'manual');
            }

            async function loadRealData() {
                try {
                    const resp = await fetch('/api/ai/report/data/all');
                    const data = await resp.json();
                    if (data.has_data) {
                        analysisData = data.sections;
                        alert('Analysis data loaded successfully!');
                        // Update stats display
                        const summaryResp = await fetch('/api/ai/report/data');
                        const summary = await summaryResp.json();
                        if (summary.stats) {
                            document.getElementById('stat-total').textContent = summary.stats.total_accounts || 0;
                            document.getElementById('stat-cracked').textContent = summary.stats.cracked_accounts || 0;
                            document.getElementById('stat-percent').textContent = summary.stats.crack_percent || '0%';
                        }
                        // Switch to auto mode
                        document.querySelector('input[name="data-mode"][value="auto"]').checked = true;
                        setDataMode('auto');
                    } else {
                        alert('No analysis data available: ' + (data.error || 'Unknown error'));
                    }
                } catch (e) {
                    alert('Failed to load data: ' + e.message);
                }
            }

            async function toggleDataPreview(sectionId) {
                const contentDiv = document.getElementById('data-content-' + sectionId);
                const promptDiv = document.getElementById('prompt-content-' + sectionId);
                const isVisible = contentDiv.style.display !== 'none';

                // Hide prompt preview when showing data
                if (promptDiv) promptDiv.style.display = 'none';

                if (isVisible) {
                    contentDiv.style.display = 'none';
                    return;
                }

                contentDiv.style.display = 'block';
                contentDiv.innerHTML = '<pre>Loading...</pre>';

                try {
                    const data = await getSectionData(sectionId);
                    contentDiv.innerHTML = '<pre>' + escapeHtml(JSON.stringify(data, null, 2)) + '</pre>';
                } catch (e) {
                    contentDiv.innerHTML = '<pre class="error">Error: ' + e.message + '</pre>';
                }
            }

            async function togglePromptPreview(sectionId) {
                const promptDiv = document.getElementById('prompt-content-' + sectionId);
                const dataDiv = document.getElementById('data-content-' + sectionId);
                const isVisible = promptDiv.style.display !== 'none';

                // Hide data preview when showing prompt
                if (dataDiv) dataDiv.style.display = 'none';

                if (isVisible) {
                    promptDiv.style.display = 'none';
                    return;
                }

                promptDiv.style.display = 'block';
                promptDiv.innerHTML = '<pre>Loading prompt...</pre>';

                try {
                    const resp = await fetch('/api/ai/report/prompt/' + sectionId);
                    const result = await resp.json();

                    if (result.error) {
                        promptDiv.innerHTML = '<pre class="error">Error: ' + result.error + '</pre>';
                        return;
                    }

                    let html = '<div class="prompt-label">System Prompt:</div>';
                    html += '<pre class="system-prompt">' + escapeHtml(result.system_prompt) + '</pre>';

                    if (result.formatted_prompt) {
                        html += '<div class="prompt-label">User Prompt (with data):</div>';
                        html += '<pre>' + escapeHtml(result.formatted_prompt) + '</pre>';
                    } else if (result.prompt_template) {
                        html += '<div class="prompt-label">Prompt Template (no data loaded):</div>';
                        html += '<pre>' + escapeHtml(result.prompt_template) + '</pre>';
                        if (result.message) {
                            html += '<p style="color: #ff9800; margin-top: 10px;">' + escapeHtml(result.message) + '</p>';
                        }
                    }

                    promptDiv.innerHTML = html;
                } catch (e) {
                    promptDiv.innerHTML = '<pre class="error">Error: ' + e.message + '</pre>';
                }
            }

            async function getSectionData(sectionId) {
                if (dataMode === 'auto') {
                    // Use real data from server
                    if (analysisData && analysisData[sectionId]) {
                        return analysisData[sectionId];
                    }
                    // Fetch from server
                    const resp = await fetch('/api/ai/report/data/' + sectionId);
                    const result = await resp.json();
                    if (result.error) throw new Error(result.error);
                    return result.data;
                } else {
                    // Use manual/sample data
                    return getManualTestData();
                }
            }

            function getManualTestData() {
                return {
                    top_passwords: JSON.parse(document.getElementById('data-top-passwords').value || '{}'),
                    password_samples: document.getElementById('data-password-samples').value.split('\\n').filter(p => p.trim()),
                    top_substrings: JSON.parse(document.getElementById('data-substrings').value || '[]'),
                    bad_practices: JSON.parse(document.getElementById('data-bad-practices').value || '{}'),
                    dictionary_words: [{"word": "password", "count": 156}, {"word": "welcome", "count": 67}],
                    custom_terms: ["Company", "Corp"],
                    semantic_categories: JSON.parse(document.getElementById('data-bad-practices').value || '{}'),
                    length_distribution: {"8": 234, "9": 456, "10": 321, "11": 189, "12": 145},
                    stats: {"Total Accounts Analyzed": 5000, "Cracked Accounts": 3350, "Percent of Accounts Cracked": "67%"},
                    policy_failures: {"Minimum Length": 234, "Complexity Requirements": 456, "Blank Passwords": 12},
                    critical_findings: ["67% of passwords cracked", "234 passwords under minimum length"],
                    key_findings: ["High crack rate", "Weak patterns prevalent"],
                    current_policy: {"min_length": 12, "complexity": "3 of 4 categories", "max_age": 90},
                    worst_practices: ["Season+Year pattern", "Company name in password"]
                };
            }

            // Timer tracking
            let activeTimers = {};

            function formatTime(seconds) {
                if (seconds < 60) {
                    return seconds + 's';
                }
                const mins = Math.floor(seconds / 60);
                const secs = seconds % 60;
                return mins + 'm ' + secs + 's';
            }

            function startTimer(sectionId) {
                const contentDiv = document.getElementById('content-' + sectionId);
                let seconds = 0;

                // Clear any existing timer
                if (activeTimers[sectionId]) {
                    clearInterval(activeTimers[sectionId]);
                }

                activeTimers[sectionId] = setInterval(() => {
                    seconds++;
                    const timerSpan = contentDiv.querySelector('.timer');
                    if (timerSpan) {
                        timerSpan.textContent = formatTime(seconds);
                    }
                }, 1000);

                return () => {
                    clearInterval(activeTimers[sectionId]);
                    delete activeTimers[sectionId];
                };
            }

            async function analyzeSection(sectionId) {
                const contentDiv = document.getElementById('content-' + sectionId);
                const serverId = document.getElementById('server-' + sectionId).value;
                const model = document.getElementById('model-' + sectionId).value;
                const temperature = parseFloat(document.getElementById('temp-' + sectionId).value);

                if (!model) {
                    alert('Please select a model');
                    return;
                }

                // Get server name for display
                const serverSelect = document.getElementById('server-' + sectionId);
                const serverName = serverSelect.options[serverSelect.selectedIndex].text.replace(/^[✓✗] /, '');

                // Show loading with live timer
                contentDiv.innerHTML = '<span class="loading">Analyzing with ' + escapeHtml(model) + ' on ' + escapeHtml(serverName) + ' (temp: ' + temperature + ')...</span> <span class="timer">0s</span>';

                // Start the timer
                const stopTimer = startTimer(sectionId);

                try {
                    const sectionData = await getSectionData(sectionId);
                    const resp = await fetch('/api/ai/report/analyze/' + sectionId, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            model: model,
                            temperature: temperature,
                            server_id: serverId,
                            data: sectionData
                        })
                    });
                    stopTimer();
                    const data = await resp.json();
                    if (data.content) {
                        let html = '';
                        if (data.warning) {
                            html += '<div class="offtopic-warning">\u26a0\ufe0f ' + escapeHtml(data.warning) + '</div>';
                        }
                        html += '<div class="analysis">' + escapeHtml(data.content) + '</div>';
                        // Show response time with server info
                        if (data.response_time_formatted) {
                            html += '<div class="response-time-info">\u23f1\ufe0f Response time: <span class="response-time">' + escapeHtml(data.response_time_formatted) + '</span>';
                            html += ' | Server: ' + escapeHtml(data.server_name || serverId);
                            if (data.saved_to) {
                                html += ' | Saved to: test_outputs/' + escapeHtml(data.saved_to);
                            }
                            html += '</div>';
                        } else if (data.saved_to) {
                            html += '<div class="save-notice">Saved to: test_outputs/' + escapeHtml(data.saved_to) + '</div>';
                        }
                        contentDiv.innerHTML = html;
                        // Refresh outputs list if visible
                        if (document.getElementById('outputs-list').style.display !== 'none') {
                            loadOutputsList();
                        }
                    } else {
                        let errorHtml = '<span class="error">Error: ' + (data.error || 'Unknown error') + '</span>';
                        if (data.response_time_formatted) {
                            errorHtml += ' <span style="color: #888;">(after ' + escapeHtml(data.response_time_formatted) + ' on ' + escapeHtml(data.server_name || serverId) + ')</span>';
                        }
                        contentDiv.innerHTML = errorHtml;
                    }
                } catch (e) {
                    stopTimer();
                    contentDiv.innerHTML = '<span class="error">Error: ' + e.message + '</span>';
                }
            }

            async function clearSection(sectionId) {
                const contentDiv = document.getElementById('content-' + sectionId);
                contentDiv.innerHTML = '<span class="placeholder">Click "Analyze" to generate this section</span>';
                await fetch('/api/ai/report/cache/' + sectionId, { method: 'DELETE' });
            }

            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            async function loadCache() {
                try {
                    const resp = await fetch('/api/ai/report/cache');
                    const data = await resp.json();
                    Object.entries(data.cache || {}).forEach(([sectionId, cached]) => {
                        const contentDiv = document.getElementById('content-' + sectionId);
                        if (contentDiv && cached.content) {
                            contentDiv.innerHTML = '<div class="analysis">' + escapeHtml(cached.content) + '</div>';
                        }
                    });
                } catch (e) {
                    console.error('Failed to load cache:', e);
                }
            }

            // Pre-load real data if available
            async function init() {
                await loadCache();
                if (dataMode === 'auto') {
                    try {
                        const resp = await fetch('/api/ai/report/data/all');
                        const data = await resp.json();
                        if (data.has_data) {
                            analysisData = data.sections;
                        }
                    } catch (e) {
                        console.error('Failed to pre-load data:', e);
                    }
                }
            }

            async function toggleOutputsList() {
                const listDiv = document.getElementById('outputs-list');
                const btn = document.getElementById('toggle-outputs-btn');
                const isVisible = listDiv.style.display !== 'none';

                if (isVisible) {
                    listDiv.style.display = 'none';
                    btn.textContent = 'Show Outputs';
                } else {
                    listDiv.style.display = 'block';
                    btn.textContent = 'Hide Outputs';
                    await loadOutputsList();
                }
            }

            async function loadOutputsList() {
                const contentDiv = document.getElementById('outputs-content');
                contentDiv.innerHTML = '<span class="placeholder">Loading...</span>';

                try {
                    const resp = await fetch('/api/ai/report/outputs');
                    const data = await resp.json();

                    if (data.outputs && data.outputs.length > 0) {
                        let html = '<div class="outputs-list">';
                        data.outputs.forEach(output => {
                            html += `
                                <div class="output-item">
                                    <div>
                                        <span class="output-filename" onclick="viewOutput('${escapeHtml(output.filename)}')">${escapeHtml(output.filename)}</span>
                                        <div class="output-meta">${output.modified} | ${Math.round(output.size / 1024)}KB</div>
                                    </div>
                                    <div class="output-actions">
                                        <button onclick="viewOutput('${escapeHtml(output.filename)}')" class="secondary">View</button>
                                    </div>
                                </div>
                            `;
                        });
                        html += '</div>';
                        html += '<p style="color: #666; font-size: 0.8em; margin-top: 10px;">' + data.count + ' saved outputs</p>';
                        contentDiv.innerHTML = html;
                    } else {
                        contentDiv.innerHTML = '<span class="placeholder">No saved outputs yet. Run an analysis to generate outputs.</span>';
                    }
                } catch (e) {
                    contentDiv.innerHTML = '<span class="error">Error loading outputs: ' + e.message + '</span>';
                }
            }

            async function viewOutput(filename) {
                try {
                    const resp = await fetch('/api/ai/report/outputs/' + encodeURIComponent(filename));
                    const data = await resp.json();

                    if (data.content) {
                        // Open in new window/tab with formatted content
                        const win = window.open('', '_blank');
                        win.document.write('<html><head><title>' + escapeHtml(filename) + '</title>');
                        win.document.write('<style>body { font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #eee; } pre { white-space: pre-wrap; background: #0f0f1a; padding: 20px; border-radius: 8px; overflow-x: auto; } h1 { color: #00d4ff; } code { background: #0f0f1a; padding: 2px 6px; border-radius: 4px; }</style>');
                        win.document.write('</head><body>');
                        win.document.write('<h1>' + escapeHtml(filename) + '</h1>');
                        win.document.write('<pre>' + escapeHtml(data.content) + '</pre>');
                        win.document.write('</body></html>');
                        win.document.close();
                    } else {
                        alert('Error: ' + (data.error || 'Failed to load file'));
                    }
                } catch (e) {
                    alert('Error viewing output: ' + e.message);
                }
            }

            // Server status refresh
            async function refreshServerStatus(serverId) {
                const card = document.querySelector(`.server-card[data-server-id="${serverId}"]`);
                if (!card) return;

                card.style.opacity = '0.5';
                try {
                    const resp = await fetch('/api/ai/servers/' + serverId + '/status');
                    const data = await resp.json();

                    card.classList.remove('ok', 'error');
                    card.classList.add(data.reachable ? 'ok' : 'error');

                    const modelsDiv = card.querySelector('.server-models');
                    if (modelsDiv) {
                        const modelCount = (data.available_models || []).length;
                        modelsDiv.textContent = data.reachable
                            ? modelCount + ' models available'
                            : 'Error: ' + (data.error || 'Unreachable');
                    }
                } catch (e) {
                    console.error('Failed to refresh server status:', e);
                }
                card.style.opacity = '1';
            }

            // Benchmark functionality
            let benchmarkResults = [];
            let benchmarkRunning = false;
            let benchmarkStopped = false;

            // Benchmark temperature slider
            document.getElementById('benchmark-temp').addEventListener('input', function() {
                document.getElementById('benchmark-temp-value').textContent = this.value;
            });

            // Define benchmark tests
            const BENCHMARK_TESTS = {
                'weak-habits': {
                    name: 'Weak Password Habits',
                    type: 'section',
                    description: 'Pattern analysis with real password data'
                },
                'company-intel': {
                    name: 'Company Intelligence',
                    type: 'section',
                    description: 'OSINT from passwords and accounts'
                },
                'user-behavior': {
                    name: 'User Behavior',
                    type: 'section',
                    description: 'Psychological analysis'
                },
                'risk-assessment': {
                    name: 'Risk Assessment',
                    type: 'section',
                    description: 'Business risk quantification'
                },
                'recommendations': {
                    name: 'Recommendations',
                    type: 'section',
                    description: 'Prioritized security actions'
                },
                'reasoning': {
                    name: 'Reasoning Test',
                    type: 'custom',
                    description: 'Logic and deduction challenge',
                    prompt: `Solve this logic puzzle step by step:

Three IT administrators - Alice, Bob, and Charlie - each manage a different system (Active Directory, Azure, and Linux servers) and use different password managers (Bitwarden, 1Password, and KeePass).

Clues:
1. Alice doesn't manage Active Directory
2. The person who uses Bitwarden manages Linux servers
3. Charlie uses 1Password
4. Bob doesn't manage Azure
5. The person who manages Active Directory uses KeePass

Questions:
1. Which system does each person manage?
2. Which password manager does each person use?
3. Explain your reasoning process.

Provide a clear, structured answer with your step-by-step logic.`
                },
                'summarization': {
                    name: 'Summarization Test',
                    type: 'custom',
                    description: 'Condense long text accurately',
                    prompt: `Summarize the following security audit findings in exactly 3 bullet points, capturing the most critical issues:

During the comprehensive password security assessment of the organization's Active Directory environment, we discovered several critical vulnerabilities that require immediate attention. The analysis covered 847 user accounts across three domains, with a password cracking success rate of 67.2% using standard dictionary and rule-based attacks executed over a 48-hour period.

The most alarming finding was the widespread use of company-related terms in passwords. Over 40% of cracked passwords contained variations of the company name "TechCorp", project codes like "Project Phoenix" or "Initiative Blue", or product names. This pattern suggests either a failure in security awareness training or an overly permissive password policy that allows predictable constructions.

Password reuse emerged as another significant concern, with 33 accounts sharing the single password "TechCorp2024!" and 11 additional accounts using "Summer2024". This level of reuse suggests either credential sharing among team members or IT-provisioned default passwords that were never changed. Either scenario represents a serious security risk.

The technical analysis revealed that 89 accounts still have LM hashes stored, indicating legacy compatibility settings that significantly weaken the security posture. Additionally, 23 service accounts were found to have passwords that haven't been rotated in over 2 years, with 7 of those being cracked during testing.

Provide exactly 3 bullet points summarizing the most critical findings.`
                }
            };

            async function runBenchmarkTests() {
                const serverId = document.getElementById('benchmark-server').value;
                const model = document.getElementById('benchmark-model').value;
                const temperature = parseFloat(document.getElementById('benchmark-temp').value);
                const btn = document.getElementById('benchmark-btn');
                const stopBtn = document.getElementById('benchmark-stop-btn');
                const statusSpan = document.getElementById('benchmark-status');
                const progressDiv = document.getElementById('benchmark-progress');
                const progressFill = document.getElementById('benchmark-progress-fill');
                const resultsDiv = document.getElementById('benchmark-results');

                if (benchmarkRunning) return;

                // Get selected tests
                const selectedTests = [];
                for (const testId of Object.keys(BENCHMARK_TESTS)) {
                    const checkbox = document.getElementById('test-' + testId);
                    if (checkbox && checkbox.checked) {
                        selectedTests.push(testId);
                    }
                }

                if (selectedTests.length === 0) {
                    alert('Please select at least one test');
                    return;
                }

                if (!model) {
                    alert('Please select a model');
                    return;
                }

                // Verify server is reachable
                const serverResp = await fetch('/api/ai/servers/' + serverId + '/status');
                const serverData = await serverResp.json();
                if (!serverData.reachable) {
                    statusSpan.innerHTML = '<span style="color: #f44336;">Server not reachable</span>';
                    return;
                }

                // Setup UI
                benchmarkRunning = true;
                benchmarkStopped = false;
                benchmarkResults = [];
                btn.disabled = true;
                stopBtn.style.display = 'inline';
                progressDiv.style.display = 'block';
                resultsDiv.innerHTML = '';

                const startTime = Date.now();

                // Run each test
                for (let i = 0; i < selectedTests.length; i++) {
                    if (benchmarkStopped) break;

                    const testId = selectedTests[i];
                    const test = BENCHMARK_TESTS[testId];
                    statusSpan.innerHTML = `Running: <strong>${escapeHtml(test.name)}</strong> (${i + 1}/${selectedTests.length})`;

                    // Update progress
                    const pct = Math.round((i / selectedTests.length) * 100);
                    progressFill.style.width = pct + '%';
                    progressFill.textContent = pct + '%';

                    let testSeconds = 0;
                    const timerId = setInterval(() => {
                        testSeconds++;
                        statusSpan.innerHTML = `Running: <strong>${escapeHtml(test.name)}</strong> (${i + 1}/${selectedTests.length}) - ${formatTime(testSeconds)}`;
                    }, 1000);

                    try {
                        let result;
                        if (test.type === 'section') {
                            // Use the existing section analysis endpoint
                            const sectionData = await getSectionData(testId);
                            const analyzeResp = await fetch('/api/ai/report/analyze/' + testId, {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({
                                    model: model,
                                    temperature: temperature,
                                    server_id: serverId,
                                    data: sectionData
                                })
                            });
                            result = await analyzeResp.json();
                        } else {
                            // Custom prompt test - use raw generate endpoint
                            const genResp = await fetch('/api/ai/generate', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({
                                    prompt: test.prompt,
                                    model: model,
                                    temperature: temperature,
                                    server_id: serverId
                                })
                            });
                            result = await genResp.json();
                        }

                        clearInterval(timerId);
                        benchmarkResults.push({
                            testId: testId,
                            test: test,
                            time: result.response_time_seconds || testSeconds,
                            timeFormatted: result.response_time_formatted || formatTime(testSeconds),
                            success: !!result.content || !!result.response,
                            error: result.error,
                            savedTo: result.saved_to,
                            contentLength: (result.content || result.response || '').length
                        });
                    } catch (e) {
                        clearInterval(timerId);
                        benchmarkResults.push({
                            testId: testId,
                            test: test,
                            time: 0,
                            timeFormatted: 'Error',
                            success: false,
                            error: e.message,
                            contentLength: 0
                        });
                    }
                }

                // Complete
                benchmarkRunning = false;
                btn.disabled = false;
                stopBtn.style.display = 'none';
                progressFill.style.width = '100%';
                progressFill.textContent = '100%';

                const totalTime = Math.round((Date.now() - startTime) / 1000);
                const successCount = benchmarkResults.filter(r => r.success).length;
                statusSpan.innerHTML = `<span style="color: #4caf50;">Complete!</span> ${successCount}/${selectedTests.length} passed in ${formatTime(totalTime)}`;

                displayBenchmarkResults(model, serverId);
            }

            function stopBenchmark() {
                benchmarkStopped = true;
                document.getElementById('benchmark-status').innerHTML += ' <span style="color: #ff9800;">Stopping...</span>';
            }

            function displayBenchmarkResults(model, serverId) {
                const resultsDiv = document.getElementById('benchmark-results');

                // Find max time for bar scaling
                const maxTime = Math.max(...benchmarkResults.map(r => r.time || 0), 1);

                let html = '<h4 style="color: #888;">Results for ' + escapeHtml(model) + '</h4>';
                html += '<table style="width: 100%; border-collapse: collapse;">';
                html += '<tr style="border-bottom: 1px solid #333;"><th style="text-align: left; padding: 8px; color: #888;">Test</th><th style="text-align: right; padding: 8px; color: #888;">Time</th><th style="text-align: right; padding: 8px; color: #888;">Output</th><th style="width: 40%; padding: 8px;"></th></tr>';

                benchmarkResults.forEach((result) => {
                    const barWidth = result.success ? Math.max((result.time / maxTime) * 100, 5) : 100;
                    const barColor = result.success ? '#4caf50' : '#f44336';
                    const statusIcon = result.success ? '✓' : '✗';
                    const statusColor = result.success ? '#4caf50' : '#f44336';

                    html += `
                        <tr style="border-bottom: 1px solid #222;">
                            <td style="padding: 8px;">
                                <span style="color: ${statusColor}; margin-right: 8px;">${statusIcon}</span>
                                <strong style="color: #00d4ff;">${escapeHtml(result.test.name)}</strong>
                            </td>
                            <td style="padding: 8px; text-align: right; color: ${result.success ? '#4caf50' : '#f44336'}; font-weight: bold;">
                                ${escapeHtml(result.timeFormatted)}
                            </td>
                            <td style="padding: 8px; text-align: right; color: #888;">
                                ${result.success ? (result.contentLength / 1000).toFixed(1) + 'KB' : '-'}
                            </td>
                            <td style="padding: 8px;">
                                <div style="height: 20px; background: #333; border-radius: 3px; overflow: hidden;">
                                    <div style="height: 100%; width: ${barWidth}%; background: ${barColor};"></div>
                                </div>
                            </td>
                        </tr>
                    `;
                });
                html += '</table>';

                // Summary stats
                const successful = benchmarkResults.filter(r => r.success);
                if (successful.length > 0) {
                    const totalTime = successful.reduce((sum, r) => sum + r.time, 0);
                    const avgTime = totalTime / successful.length;
                    const totalOutput = successful.reduce((sum, r) => sum + r.contentLength, 0);

                    html += `
                        <div style="margin-top: 15px; padding: 12px; background: #0f0f1a; border-radius: 6px; display: flex; gap: 30px;">
                            <div><span style="color: #888;">Tests Passed:</span> <strong style="color: #4caf50;">${successful.length}/${benchmarkResults.length}</strong></div>
                            <div><span style="color: #888;">Total Time:</span> <strong>${formatTime(Math.round(totalTime))}</strong></div>
                            <div><span style="color: #888;">Avg Time:</span> <strong>${formatTime(Math.round(avgTime))}</strong></div>
                            <div><span style="color: #888;">Total Output:</span> <strong>${(totalOutput / 1000).toFixed(1)}KB</strong></div>
                        </div>
                    `;
                }

                resultsDiv.innerHTML = html;
            }

            // Matrix temperature slider
            document.getElementById('matrix-temp').addEventListener('input', function() {
                document.getElementById('matrix-temp-value').textContent = this.value;
            });

            // Full Matrix Run functionality
            let matrixRunning = false;
            let matrixStopped = false;
            let matrixResults = [];

            async function runMatrix() {
                const serverId = document.getElementById('matrix-server').value;
                const temperature = parseFloat(document.getElementById('matrix-temp').value);
                const btn = document.getElementById('matrix-btn');
                const stopBtn = document.getElementById('matrix-stop-btn');
                const statusDiv = document.getElementById('matrix-status');
                const progressDiv = document.getElementById('matrix-progress');
                const progressFill = document.getElementById('matrix-progress-fill');
                const resultsDiv = document.getElementById('matrix-results');

                if (matrixRunning) return;

                // Get server info and models
                statusDiv.innerHTML = 'Fetching server models...';
                const serverResp = await fetch('/api/ai/servers/' + serverId + '/status');
                const serverData = await serverResp.json();

                if (!serverData.reachable) {
                    statusDiv.innerHTML = '<span style="color: #f44336;">Server not reachable: ' + (serverData.error || 'Unknown error') + '</span>';
                    return;
                }

                const models = serverData.available_models || [];
                if (models.length === 0) {
                    statusDiv.innerHTML = '<span style="color: #f44336;">No models available on this server</span>';
                    return;
                }

                // Get available sections
                const sections = ['weak-habits', 'company-intel', 'user-behavior'];
                const sectionNames = {
                    'weak-habits': 'Weak Password Habits',
                    'company-intel': 'Company Intelligence',
                    'user-behavior': 'User Behavior Insights'
                };

                // Build matrix of all combinations
                const matrix = [];
                for (const section of sections) {
                    for (const model of models) {
                        matrix.push({ section, model, sectionName: sectionNames[section] });
                    }
                }

                const totalRuns = matrix.length;
                statusDiv.innerHTML = `Starting matrix run: ${sections.length} sections x ${models.length} models = <strong>${totalRuns} total runs</strong>`;

                // Setup UI
                matrixRunning = true;
                matrixStopped = false;
                matrixResults = [];
                btn.disabled = true;
                stopBtn.style.display = 'inline';
                progressDiv.style.display = 'block';
                resultsDiv.innerHTML = '';

                // Create placeholder items for each run
                matrix.forEach((item, idx) => {
                    resultsDiv.innerHTML += `
                        <div class="matrix-item" id="matrix-item-${idx}">
                            <div class="matrix-item-header">
                                <span class="matrix-item-title">${escapeHtml(item.sectionName)}</span>
                                <span class="matrix-item-status" id="matrix-status-${idx}">Pending</span>
                            </div>
                            <div style="color: #888; font-size: 0.85em;">${escapeHtml(item.model)}</div>
                            <div class="matrix-item-time" id="matrix-time-${idx}"></div>
                        </div>
                    `;
                });

                // Run each combination sequentially
                let completed = 0;
                let startTime = Date.now();

                for (let i = 0; i < matrix.length; i++) {
                    if (matrixStopped) break;

                    const item = matrix[i];
                    const itemDiv = document.getElementById('matrix-item-' + i);
                    const statusSpan = document.getElementById('matrix-status-' + i);
                    const timeDiv = document.getElementById('matrix-time-' + i);

                    itemDiv.classList.add('running');
                    statusSpan.innerHTML = '<span style="color: #00d4ff;">Running...</span>';

                    // Start timer for this item
                    let itemSeconds = 0;
                    const itemTimerId = setInterval(() => {
                        itemSeconds++;
                        timeDiv.textContent = formatTime(itemSeconds);
                    }, 1000);

                    // Get section data
                    const sectionData = await getSectionData(item.section);

                    try {
                        const analyzeResp = await fetch('/api/ai/report/analyze/' + item.section, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                model: item.model,
                                temperature: temperature,
                                server_id: serverId,
                                data: sectionData
                            })
                        });

                        clearInterval(itemTimerId);
                        const result = await analyzeResp.json();

                        itemDiv.classList.remove('running');
                        if (result.content) {
                            itemDiv.classList.add('complete');
                            statusSpan.innerHTML = '<span style="color: #4caf50;">✓ Complete</span>';
                            timeDiv.textContent = result.response_time_formatted || formatTime(itemSeconds);
                            if (result.saved_to) {
                                timeDiv.innerHTML += ' <span style="color: #666;">→ ' + escapeHtml(result.saved_to) + '</span>';
                            }
                            matrixResults.push({ ...item, success: true, time: result.response_time_seconds, savedTo: result.saved_to });
                        } else {
                            itemDiv.classList.add('error');
                            statusSpan.innerHTML = '<span style="color: #f44336;">✗ Failed</span>';
                            timeDiv.textContent = result.error || 'Unknown error';
                            matrixResults.push({ ...item, success: false, error: result.error });
                        }
                    } catch (e) {
                        clearInterval(itemTimerId);
                        itemDiv.classList.remove('running');
                        itemDiv.classList.add('error');
                        statusSpan.innerHTML = '<span style="color: #f44336;">✗ Error</span>';
                        timeDiv.textContent = e.message;
                        matrixResults.push({ ...item, success: false, error: e.message });
                    }

                    completed++;
                    const pct = Math.round((completed / totalRuns) * 100);
                    progressFill.style.width = pct + '%';
                    progressFill.textContent = pct + '% (' + completed + '/' + totalRuns + ')';

                    // Update elapsed time
                    const elapsed = Math.round((Date.now() - startTime) / 1000);
                    const avgPerRun = elapsed / completed;
                    const remaining = Math.round(avgPerRun * (totalRuns - completed));
                    statusDiv.innerHTML = `Progress: ${completed}/${totalRuns} | Elapsed: ${formatTime(elapsed)} | Est. remaining: ${formatTime(remaining)}`;
                }

                // Complete
                matrixRunning = false;
                btn.disabled = false;
                stopBtn.style.display = 'none';

                const totalElapsed = Math.round((Date.now() - startTime) / 1000);
                const successCount = matrixResults.filter(r => r.success).length;
                statusDiv.innerHTML = `<span style="color: #4caf50;">Matrix run complete!</span> ${successCount}/${totalRuns} successful in ${formatTime(totalElapsed)}`;

                if (matrixStopped) {
                    statusDiv.innerHTML += ' <span style="color: #ff9800;">(Stopped early)</span>';
                }
            }

            function stopMatrix() {
                matrixStopped = true;
                document.getElementById('matrix-status').innerHTML += ' <span style="color: #ff9800;">Stopping after current run...</span>';
            }

            document.addEventListener('DOMContentLoaded', init);
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/ai/test")
@login_required
def ai_test_page():
    """Hidden test page for experimenting with AI features."""
    from ollama_tools import test_ollama_connection

    status = test_ollama_connection()

    # Build model options HTML
    model_options = ""
    for model in status.get("available_models", []):
        model_options += f'<option value="{model}">{model}</option>'

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>HM1K AI Test Console</title>
        <style>
            body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #eee; }
            h1 { color: #00d4ff; }
            .status { padding: 15px; border-radius: 8px; margin-bottom: 20px; }
            .status.ok { background: #1e3a1e; border: 1px solid #4caf50; }
            .status.error { background: #3a1e1e; border: 1px solid #f44336; }
            .section { background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            h2 { color: #00d4ff; margin-top: 0; }
            h3 { color: #aaa; margin-top: 20px; margin-bottom: 10px; }
            textarea { width: 100%; height: 150px; background: #0f0f1a; color: #eee; border: 1px solid #333; border-radius: 4px; padding: 10px; font-family: monospace; box-sizing: border-box; }
            button { background: #00d4ff; color: #000; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; margin-right: 10px; }
            button:hover { background: #00b8e6; }
            button:disabled { background: #555; cursor: not-allowed; }
            button.danger { background: #f44336; color: #fff; }
            button.danger:hover { background: #d32f2f; }
            button.secondary { background: #555; color: #fff; }
            button.secondary:hover { background: #666; }
            .response { background: #0f0f1a; padding: 15px; border-radius: 4px; margin-top: 15px; white-space: pre-wrap; font-family: monospace; max-height: 400px; overflow-y: auto; }
            .loading { color: #00d4ff; }
            select { background: #0f0f1a; color: #eee; border: 1px solid #333; padding: 8px 12px; border-radius: 4px; font-size: 14px; min-width: 200px; }
            input[type="text"] { background: #0f0f1a; color: #eee; border: 1px solid #333; padding: 8px 12px; border-radius: 4px; font-size: 14px; }
            label { display: block; margin-bottom: 5px; color: #888; }
            .form-group { margin-bottom: 15px; }
            .model-selector { background: #0f3460; padding: 15px; border-radius: 8px; margin-bottom: 20px; display: flex; align-items: center; gap: 15px; }
            .model-selector label { margin: 0; color: #00d4ff; font-weight: bold; }
            .model-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; margin-top: 15px; }
            .model-card { background: #0f0f1a; padding: 12px; border-radius: 6px; border: 1px solid #333; }
            .model-card.installed { border-color: #4caf50; }
            .model-card .model-name { font-weight: bold; color: #00d4ff; }
            .model-card .model-desc { color: #888; font-size: 0.9em; margin: 5px 0; }
            .model-card .model-sizes { color: #666; font-size: 0.85em; }
            .model-card .model-actions { margin-top: 10px; }
            .model-card button { padding: 6px 12px; font-size: 0.85em; }
            .installed-models { margin-bottom: 20px; }
            .installed-model { display: inline-flex; align-items: center; background: #1e3a1e; border: 1px solid #4caf50; padding: 6px 12px; border-radius: 4px; margin: 4px; }
            .installed-model .name { margin-right: 10px; }
            .installed-model button { padding: 2px 8px; font-size: 0.8em; margin: 0; }
            .preset-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; margin-top: 15px; }
            .preset-card { background: #0f0f1a; padding: 15px; border-radius: 8px; border: 1px solid #333; cursor: pointer; transition: all 0.2s; }
            .preset-card:hover { border-color: #00d4ff; transform: translateY(-2px); }
            .preset-card.active { border-color: #00d4ff; background: #1a2a4a; }
            .preset-card .preset-name { font-weight: bold; color: #00d4ff; font-size: 1.1em; }
            .preset-card .preset-desc { color: #888; font-size: 0.9em; margin: 8px 0; }
            .preset-card .preset-models { color: #666; font-size: 0.8em; }
            .preset-card .preset-tip { color: #4caf50; font-size: 0.8em; margin-top: 8px; font-style: italic; }
            .model-card .model-notes { color: #4caf50; font-size: 0.8em; margin-top: 5px; font-style: italic; }
            .model-card .model-recommended { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; }
            .model-card .rec-tag { background: #1a3a5c; color: #00d4ff; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; }
            .temp-slider { display: flex; align-items: center; gap: 10px; margin-top: 10px; }
            .temp-slider input[type="range"] { flex: 1; }
            .temp-slider .temp-value { color: #00d4ff; font-weight: bold; min-width: 40px; }
        </style>
    </head>
    <body>
        <h1>HM1K AI Test Console</h1>

        <div class="status """ + ("ok" if status["reachable"] else "error") + """">
            <strong>Ollama Status:</strong>
            """ + ("Connected" if status["reachable"] else "Not Available") + """<br>
            <strong>Host:</strong> """ + status["host"] + """<br>
            <strong>Enabled:</strong> """ + str(status["enabled"]) + """
            """ + (f"<br><strong>Error:</strong> {status['error']}" if status.get("error") else "") + """
        </div>

        <div class="model-selector">
            <label for="modelSelect">Model:</label>
            <select id="modelSelect">
                """ + model_options + """
            </select>
            <span style="color: #888; font-size: 0.9em;">Select the model to use for all requests</span>
            <button class="secondary" onclick="refreshModels()">Refresh</button>
        </div>

        <div class="section">
            <h2>Analysis Presets</h2>
            <p style="color: #888; font-size: 0.9em;">Select a preset to auto-configure model selection and temperature for your task.</p>
            <div id="presetCards" class="preset-cards">
                <span class="loading">Loading presets...</span>
            </div>
            <div class="temp-slider" style="margin-top: 15px;">
                <label style="color: #888;">Temperature:</label>
                <input type="range" id="temperatureSlider" min="0" max="1" step="0.1" value="0.7">
                <span class="temp-value" id="tempValue">0.7</span>
                <span style="color: #666; font-size: 0.85em;">(Lower = more consistent, Higher = more creative)</span>
            </div>
        </div>

        <div class="section">
            <h2>Model Management</h2>

            <h3>Installed Models</h3>
            <div id="installedModels" class="installed-models">
                <span class="loading">Loading installed models...</span>
            </div>

            <h3>Pull a Model</h3>
            <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 15px;">
                <input type="text" id="customModelName" placeholder="e.g., llama3.1:70b or mistral" style="width: 300px;">
                <button onclick="pullCustomModel()">Pull Model</button>
            </div>
            <div id="pullStatus" class="response" style="display:none;"></div>

            <h3>Available Models from Ollama Library</h3>
            <p style="color: #888; font-size: 0.9em;">Click on a size to pull that specific variant.</p>
            <div id="libraryModels" class="model-list">
                <span class="loading">Loading available models...</span>
            </div>
        </div>

        <div class="section">
            <h2>Free-form Prompt</h2>
            <div class="form-group">
                <label>System Prompt (optional):</label>
                <textarea id="systemPrompt" rows="4">You are a cybersecurity analyst specializing in password security. You recently completed an Active Directory domain password assessment by collecting (dumping) the domain hashes and then running them through hashcat doing multiple rounds of brute force guessing (up to 9 character passwords), dictionary attacks, hybrid dictionary attacks with rules (like One Rule to Rule them All) and mask attacks. Your job is to analyze the domain dump output and the hashcat output, and be prepared to answer questions about your analysis so your user can report your findings.</textarea>
            </div>
            <div class="form-group">
                <label>User Prompt:</label>
                <textarea id="userPrompt">Analyze the security implications of users choosing "Summer2024" as their password.</textarea>
            </div>
            <button onclick="sendPrompt()">Send Prompt</button>
            <div id="promptResponse" class="response" style="display:none;"></div>
        </div>

        <div class="section">
            <h2>Executive Summary Generator</h2>
            <p style="color: #888;">Uses session data if available, or provide custom JSON.</p>
            <div class="form-group">
                <label>Stats JSON (optional override):</label>
                <textarea id="summaryStats" rows="3">{"total_accounts": 5000, "cracked_accounts": 3350, "cracked_percent": 67, "unique_passwords": 2100, "avg_length": 9.2, "min_length": 4, "max_length": 24, "blank_passwords": 12}</textarea>
            </div>
            <button onclick="generateSummary()">Generate Summary</button>
            <div id="summaryResponse" class="response" style="display:none;"></div>
        </div>

        <div class="section">
            <h2>Pattern Analyzer</h2>
            <div class="form-group">
                <label>Patterns JSON:</label>
                <textarea id="patternData" rows="4">{"Password Variants": {"count": 234, "examples": {"P@ssw0rd": 45, "password123": 32}}, "Season + Year": {"count": 567, "examples": {"Summer2024": 89, "Winter2023": 45}}, "Keyboard Walks": {"count": 123, "examples": {"qwerty123": 34}}}</textarea>
            </div>
            <button onclick="analyzePatterns()">Analyze Patterns</button>
            <div id="patternResponse" class="response" style="display:none;"></div>
        </div>

        <div class="section">
            <h2>Password Clustering</h2>
            <div class="form-group">
                <label>Passwords (one per line):</label>
                <textarea id="clusterPasswords" rows="6">Summer2024
Winter2023!
GoPackers!
yankees123
JohnSmith1
password123
Welcome1!
Jesus2024
NewYork99
football!</textarea>
            </div>
            <button onclick="clusterPasswords()">Cluster Passwords</button>
            <div id="clusterResponse" class="response" style="display:none;"></div>
        </div>

        <script>
            let installedModels = [];

            function getSelectedModel() {
                return document.getElementById('modelSelect').value;
            }

            // Model Management Functions
            async function loadInstalledModels() {
                try {
                    const resp = await fetch('/api/ai/models');
                    const data = await resp.json();
                    installedModels = data.models || [];
                    renderInstalledModels();
                    updateModelSelect();
                } catch (e) {
                    document.getElementById('installedModels').innerHTML = '<span style="color: #f44336;">Error loading models: ' + e.message + '</span>';
                }
            }

            function renderInstalledModels() {
                const container = document.getElementById('installedModels');
                if (installedModels.length === 0) {
                    container.innerHTML = '<span style="color: #888;">No models installed</span>';
                    return;
                }
                container.innerHTML = installedModels.map(model =>
                    '<div class="installed-model">' +
                    '<span class="name">' + model + '</span>' +
                    '<button class="danger" onclick="deleteModel(\\'' + model + '\\')">Delete</button>' +
                    '</div>'
                ).join('');
            }

            function updateModelSelect() {
                const select = document.getElementById('modelSelect');
                const currentValue = select.value;
                select.innerHTML = installedModels.map(model =>
                    '<option value="' + model + '"' + (model === currentValue ? ' selected' : '') + '>' + model + '</option>'
                ).join('');
            }

            async function loadLibraryModels() {
                try {
                    const resp = await fetch('/api/ai/library');
                    const data = await resp.json();
                    renderLibraryModels(data.models || []);
                } catch (e) {
                    document.getElementById('libraryModels').innerHTML = '<span style="color: #f44336;">Error loading library: ' + e.message + '</span>';
                }
            }

            function renderLibraryModels(models) {
                const container = document.getElementById('libraryModels');
                container.innerHTML = models.map(model => {
                    const isInstalled = installedModels.some(m => m.startsWith(model.name));
                    const sizesHtml = model.sizes.length > 0
                        ? model.sizes.map(size =>
                            '<button class="secondary" style="padding: 4px 8px; margin: 2px;" onclick="pullModel(\\'' + model.name + ':' + size + '\\')">' + size + '</button>'
                          ).join('')
                        : '<button class="secondary" style="padding: 4px 8px; margin: 2px;" onclick="pullModel(\\'' + model.name + '\\')">Pull</button>';
                    const recommendedHtml = (model.recommended_for && model.recommended_for.length > 0)
                        ? '<div class="model-recommended">' + model.recommended_for.map(r => '<span class="rec-tag">' + r + '</span>').join('') + '</div>'
                        : '';
                    const notesHtml = model.notes ? '<div class="model-notes">' + model.notes + '</div>' : '';
                    return '<div class="model-card' + (isInstalled ? ' installed' : '') + '">' +
                        '<div class="model-name">' + model.name + (isInstalled ? ' (installed)' : '') + '</div>' +
                        '<div class="model-desc">' + model.description + '</div>' +
                        recommendedHtml +
                        notesHtml +
                        '<div class="model-actions">' + sizesHtml + '</div>' +
                        '</div>';
                }).join('');
            }

            async function pullModel(modelName) {
                const statusDiv = document.getElementById('pullStatus');
                statusDiv.style.display = 'block';
                statusDiv.innerHTML = '<span class="loading">Pulling ' + modelName + '... This may take several minutes for large models.</span>';

                try {
                    const resp = await fetch('/api/ai/pull', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ model: modelName })
                    });
                    const data = await resp.json();
                    if (data.success) {
                        statusDiv.innerHTML = '<span style="color: #4caf50;">Successfully pulled ' + modelName + '</span>';
                        await loadInstalledModels();
                        await loadLibraryModels();
                    } else {
                        statusDiv.innerHTML = '<span style="color: #f44336;">Failed to pull ' + modelName + ': ' + (data.error || 'Unknown error') + '</span>';
                    }
                } catch (e) {
                    statusDiv.innerHTML = '<span style="color: #f44336;">Error: ' + e.message + '</span>';
                }
            }

            async function pullCustomModel() {
                const modelName = document.getElementById('customModelName').value.trim();
                if (!modelName) {
                    alert('Please enter a model name');
                    return;
                }
                await pullModel(modelName);
            }

            async function deleteModel(modelName) {
                if (!confirm('Are you sure you want to delete ' + modelName + '?')) {
                    return;
                }

                const statusDiv = document.getElementById('pullStatus');
                statusDiv.style.display = 'block';
                statusDiv.innerHTML = '<span class="loading">Deleting ' + modelName + '...</span>';

                try {
                    const resp = await fetch('/api/ai/delete', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ model: modelName })
                    });
                    const data = await resp.json();
                    if (data.success) {
                        statusDiv.innerHTML = '<span style="color: #4caf50;">Successfully deleted ' + modelName + '</span>';
                        await loadInstalledModels();
                        await loadLibraryModels();
                    } else {
                        statusDiv.innerHTML = '<span style="color: #f44336;">Failed to delete ' + modelName + ': ' + (data.error || 'Unknown error') + '</span>';
                    }
                } catch (e) {
                    statusDiv.innerHTML = '<span style="color: #f44336;">Error: ' + e.message + '</span>';
                }
            }

            async function refreshModels() {
                await loadInstalledModels();
                await loadLibraryModels();
            }

            // Preset Functions
            let presets = {};
            let activePreset = null;

            async function loadPresets() {
                try {
                    const resp = await fetch('/api/ai/presets');
                    const data = await resp.json();
                    presets = data.presets || {};
                    renderPresets();
                } catch (e) {
                    document.getElementById('presetCards').innerHTML = '<span style="color: #f44336;">Error loading presets: ' + e.message + '</span>';
                }
            }

            function renderPresets() {
                const container = document.getElementById('presetCards');
                container.innerHTML = Object.entries(presets).map(([key, preset]) => {
                    const availableModels = preset.recommended_models.filter(m =>
                        installedModels.some(installed => installed.includes(m.split(':')[0]))
                    );
                    const modelsText = availableModels.length > 0
                        ? 'Available: ' + availableModels.slice(0, 3).join(', ')
                        : 'Recommended: ' + preset.recommended_models.slice(0, 2).join(', ');
                    return '<div class="preset-card' + (activePreset === key ? ' active' : '') + '" onclick="selectPreset(\\'' + key + '\\')">' +
                        '<div class="preset-name">' + preset.name + '</div>' +
                        '<div class="preset-desc">' + preset.description + '</div>' +
                        '<div class="preset-models">' + modelsText + '</div>' +
                        '<div class="preset-tip">' + preset.tips + '</div>' +
                        '</div>';
                }).join('');
            }

            function selectPreset(presetKey) {
                activePreset = presetKey;
                const preset = presets[presetKey];
                if (!preset) return;

                // Update temperature slider
                document.getElementById('temperatureSlider').value = preset.temperature;
                document.getElementById('tempValue').textContent = preset.temperature;

                // Try to select a recommended model that's installed
                const modelSelect = document.getElementById('modelSelect');
                for (const recModel of preset.recommended_models) {
                    const matchingInstalled = installedModels.find(m => m.includes(recModel.split(':')[0]));
                    if (matchingInstalled) {
                        modelSelect.value = matchingInstalled;
                        break;
                    }
                }

                // Re-render to show active state
                renderPresets();
            }

            // Temperature slider handler
            document.addEventListener('DOMContentLoaded', function() {
                const slider = document.getElementById('temperatureSlider');
                const tempValue = document.getElementById('tempValue');
                slider.addEventListener('input', function() {
                    tempValue.textContent = this.value;
                });
            });

            // Load everything on page load
            document.addEventListener('DOMContentLoaded', function() {
                loadInstalledModels().then(() => {
                    loadPresets();
                });
                loadLibraryModels();
            });

            function getTemperature() {
                return parseFloat(document.getElementById('temperatureSlider').value);
            }

            async function sendPrompt() {
                const model = getSelectedModel();
                const systemPrompt = document.getElementById('systemPrompt').value;
                const userPrompt = document.getElementById('userPrompt').value;
                const temperature = getTemperature();
                const responseDiv = document.getElementById('promptResponse');

                if (!model) {
                    alert('Please select a model');
                    return;
                }

                responseDiv.style.display = 'block';
                responseDiv.innerHTML = '<span class="loading">Generating response using ' + model + ' (temp: ' + temperature + ')...</span>';

                try {
                    const resp = await fetch('/api/ai/generate', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            model: model,
                            prompt: userPrompt,
                            system: systemPrompt,
                            temperature: temperature
                        })
                    });
                    const data = await resp.json();
                    responseDiv.textContent = data.response || data.error || 'No response';
                } catch (e) {
                    responseDiv.textContent = 'Error: ' + e.message;
                }
            }

            async function generateSummary() {
                const model = getSelectedModel();
                const statsJson = document.getElementById('summaryStats').value;
                const responseDiv = document.getElementById('summaryResponse');

                if (!model) {
                    alert('Please select a model');
                    return;
                }

                responseDiv.style.display = 'block';
                responseDiv.innerHTML = '<span class="loading">Generating executive summary using ' + model + '...</span>';

                try {
                    let body = { model: model };
                    if (statsJson.trim()) {
                        body.stats = JSON.parse(statsJson);
                    }

                    const resp = await fetch('/api/ai/executive-summary', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(body)
                    });
                    const data = await resp.json();
                    responseDiv.textContent = data.summary || data.error || 'No response';
                } catch (e) {
                    responseDiv.textContent = 'Error: ' + e.message;
                }
            }

            async function analyzePatterns() {
                const model = getSelectedModel();
                const patternJson = document.getElementById('patternData').value;
                const responseDiv = document.getElementById('patternResponse');

                if (!model) {
                    alert('Please select a model');
                    return;
                }

                responseDiv.style.display = 'block';
                responseDiv.innerHTML = '<span class="loading">Analyzing patterns using ' + model + '...</span>';

                try {
                    const resp = await fetch('/api/ai/analyze-patterns', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            model: model,
                            patterns: JSON.parse(patternJson)
                        })
                    });
                    const data = await resp.json();
                    responseDiv.textContent = data.analysis || data.error || 'No response';
                } catch (e) {
                    responseDiv.textContent = 'Error: ' + e.message;
                }
            }

            async function clusterPasswords() {
                const model = getSelectedModel();
                const passwords = document.getElementById('clusterPasswords').value.split('\\n').filter(p => p.trim());
                const responseDiv = document.getElementById('clusterResponse');

                if (!model) {
                    alert('Please select a model');
                    return;
                }

                responseDiv.style.display = 'block';
                responseDiv.innerHTML = '<span class="loading">Clustering passwords using ' + model + '...</span>';

                try {
                    const resp = await fetch('/api/ai/cluster-passwords', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ model: model, passwords: passwords })
                    });
                    const data = await resp.json();
                    responseDiv.textContent = JSON.stringify(data, null, 2);
                } catch (e) {
                    responseDiv.textContent = 'Error: ' + e.message;
                }
            }
        </script>
    </body>
    </html>
    """
    return html


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

    # Start Flask application
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"), debug=False)
