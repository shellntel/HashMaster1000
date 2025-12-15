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
from datetime import timedelta
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
