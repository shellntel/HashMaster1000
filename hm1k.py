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
)
from flask.wrappers import Response as FlaskResponse
from flask import Response as FlaskResponse
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from typing import Dict, Union, Optional, cast
from dataclasses import dataclass


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
            subprocess.run(["python3", "generate_cert.py"], check=True)
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


@dataclass
class UserData:
    username: str
    password_hash: str


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
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    hours=8
)  # Session expiration can be adjusted here
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["UPLOAD_FOLDER"] = "uploads"

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

            user = User(username=ADMIN_USERNAME, password_hash=ADMIN_PASSWORD_HASH)
            login_user(user)

            # Redirect to the 'next' parameter or index
            next_page = request.args.get("next")
            return (
                cast(FlaskResponse, redirect(next_page))
                if next_page
                else cast(FlaskResponse, redirect(url_for("index")))
            )

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
def index():
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        "static", "favicon.ico", mimetype="image/vnd.microsoft.icon"
    )


@app.route("/readme")
def readme():
    return send_file("readme.md", mimetype="text/markdown")


@app.route("/LICENSE")
def license():
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
            "python3",
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
        "python3",
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


@app.route("/report")
@login_required
def report():
    return render_template("report.html")


# Endpoint for Project Statistics Table
@app.route("/cracking_stats_table")
@login_required
def cracking_stats_table():
    with open("data/cracking_stats_table.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Cracked Accounts Pie Chart data
@app.route("/pw_account_pie")
@login_required
def pw_account_pie():
    with open("data/pw_account_pie.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Cracked Hashes Pie Chart data
@app.route("/pw_ntlm_hash_pie")
@login_required
def pw_ntlm_hash_pie():
    with open("data/pw_ntlm_hash_pie.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Length Distribution Bar Chart data
@app.route("/pw_length_distribution")
@login_required
def pw_length_distribution():
    with open("data/pw_length_distribution.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Top X Cracked Passwords Bar Chart data
@app.route("/pw_top_passwords")
@login_required
def pw_top_passwords():
    with open("data/pw_top_passwords.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Top X Substrings Bar Chart data
@app.route("/pw_substrings")
@login_required
def pw_substrings():
    with open("data/pw_substrings.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Top X Dictionary Words Bar Chart data
@app.route("/pw_dict_words")
@login_required
def pw_dict_words():
    with open("data/pw_dict_words.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Reuse Table data
@app.route("/pw_reuse_table")
@login_required
def pw_reuse_table():
    with open("data/pw_reuse_table.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Min Length
@app.route("/pw_fails_min_length")
@login_required
def pw_min_len_table():
    with open("data/pw_fails_min_length.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Complexity
@app.route("/pw_fails_complexity")
@login_required
def pw_complexity_table():
    with open("data/pw_fails_complexity.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Blank
@app.route("/pw_fails_blank")
@login_required
def pw_blank_table():
    with open("data/pw_fails_blank.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Password Fails Max Age
@app.route("/pw_fails_max_age")
@login_required
def pw_max_age_table():
    with open("data/pw_fails_max_age.json") as f:
        data = json.load(f)
    return jsonify(data)


# Endpoint for Downloading JSON Files
JSON_FOLDER = os.path.join(os.getcwd(), "data")


@app.route("/download/<filename>")
@login_required
def download_file(filename):
    try:
        if not filename.endswith(".json"):
            abort(403)  # Forbidden
        return send_from_directory(JSON_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)  # File not found


@app.route("/list_json_files", methods=["GET"])
@login_required
def list_json_files():
    try:
        files = [f for f in os.listdir(JSON_FOLDER) if f.endswith(".json")]
        return jsonify(files)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Validate libraries and files before starting the app
    validate_libraries()
    validate_files()

    load_dotenv()

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise ValueError(
            "Environment variable SECRET_KEY must be set in the .env file."
        )
    app.secret_key = secret_key

    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
    if not ADMIN_USERNAME:
        raise ValueError(
            "Environment variable ADMIN_USERNAME must be set in a local .env file."
        )

    raw_admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH")
    if not raw_admin_password_hash:
        raise ValueError(
            "Environment variable ADMIN_PASSWORD_HASH must be set in a local .env file."
        )

    ADMIN_PASSWORD_HASH: str = raw_admin_password_hash  # Explicitly set as non-None str

    # Start Flask application
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"), debug=False)
