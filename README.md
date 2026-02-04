# **Hash Master 1000**

**Windows Active Directory password audit and hash analysis tool for pentest and security assessments.** Analyze NTLM hashes extracted via DCSync, Volume Shadow Copy, or other methods (pwdump format) along with Hashcat potfiles to generate comprehensive reports on password security, policy compliance, reuse patterns, and breach exposure via HIBP integration.

---

### **Table of Contents**

1.  [Security Disclaimer](#security-disclaimer)
2.  [Introduction](#introduction)
3.  [Use Cases](#use-cases)
4.  [Project Structure](#project-structure)
5.  [Application Startup](#application-startup)
6.  [Default Login](#default-login)
7.  [Workflow Overview](#workflow-overview)
8.  [Inputs](#inputs)
9.  [File Validation](#file-validation)
10. [Configurable Settings](#configurable-settings)
11. [Output Report](#output-report)
12. [Hash Dumping Methods](#hash-dumping-methods)
13. [Session Management](#session-management)
14. [Have I Been Pwned (HIBP) Integration](#have-i-been-pwned-hibp-integration)
15. [Kerberoast Exposure Analysis](#kerberoast-exposure-analysis)
16. [AS-REP Exposure Analysis](#as-rep-exposure-analysis)
17. [Historical Trend Analysis](#historical-trend-analysis)
18. [Top 25 Group Memberships](#top-25-group-memberships)
19. [Days Since Last Login Analysis](#days-since-last-login-analysis)
20. [Advanced AI Analysis (AAIA)](#advanced-ai-analysis-aaia)
21. [AD Description Analysis](#ad-description-analysis)
22. [Advanced Mode](#advanced-mode)
23. [Environment Configuration](#environment-configuration)
24. [Licensing](#licensing)

---

## **Security Disclaimer**

Hash Master 1000 is intended as an **ad hoc tool** for password and hash analysis. It is **not designed for production environments** unless properly secured by a knowledgeable user. The default deployment lacks advanced security features, and use beyond local or controlled systems is strongly discouraged.

If production use is required:

- Replace the default Flask server with a robust web server
- Use a valid TLS certificate
- Configure appropriate firewall rules to restrict access

The authors assume no responsibility for improper or insecure deployments.

---

## **Introduction**

**Hash Master 1000** is a tool for analyzing Microsoft Windows password hashes and cracked passwords. It processes NTLM hashes in pwdump format (from tools like secretsdump, pwdump, ntdsutil, or Volume Shadow Copy extraction) along with a Hashcat potfile to generate comprehensive reports for penetration testers, auditors, and cybersecurity professionals.

For enhanced analysis capabilities, HM1K also supports **ADD JSON format** from [Active Directory Dumper](https://github.com/shellntel/ActiveDirectoryDumper), which provides rich Active Directory metadata including group memberships, privileged account detection, and historical password analysis.

Learn more: https://blog.shellntel.com/p/hash-master-1000

### **Features**

- 4-step guided wizard workflow with file validation
- Password policy compliance checks (length, complexity)
- Analysis of weak or reused passwords
- Detection of common/reused dictionary words and substrings
- Bad Practices Report with 11 detection categories (clickable bars show matching passwords)
- Company Name & Terms detection for organization-specific keyword matching
- Visualization of cracking statistics with interactive charts
- Support for mixed hash type potfiles (auto-detects and filters NTLM)
- Built-in file browser for local server files
- Account status awareness (Enabled/Disabled) from DCSync format
- Export options: PNG clipboard, SVG download, CSV download, JSON data
- **Session Management**: Save, restore, and compare multiple analysis sessions
- **ADD JSON Support**: Import rich Active Directory data with group memberships, privileged account detection, and historical password analysis
- **Have I Been Pwned (HIBP) Integration**: Check password hashes against the HIBP breach database using k-Anonymity (privacy-preserving)
- **Kerberoast Exposure Analysis**: Automated identification and risk scoring of service accounts vulnerable to Kerberoasting attacks
- **AS-REP Exposure Analysis**: Identify accounts with Kerberos pre-authentication disabled that are vulnerable to offline password cracking
- **Historical Trend Analysis**: Track password security improvements across multiple assessment sessions with visual trend charts
- **Days Since Last Login Analysis**: Identify stale accounts with no login activity over 90 days for security review
- **Advanced AI Analysis (AAIA)**: AI-powered insights using local Ollama or OpenAI-compatible API models with 3-phase pipeline
- **AD Description Analysis**: Regex and AI-powered analysis of Active Directory description fields to detect sensitive information like embedded passwords, API keys, PII, and legal hold markers

---

## **Use Cases**

1. Identify weak and reused passwords in an organization
2. Highlight accounts failing policy requirements
3. Generate reports for compliance or presentations

---

## **Project Structure**

```
hm1k/
├── hm1k.py                    # Main Flask application
├── generate_cert.py           # SSL certificate generator
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Docker build configuration
├── docker-compose.yaml        # Docker Compose configuration
├── entrypoint.sh             # Docker entrypoint script
├── env.example               # Example environment configuration
│
├── app/                      # Core application modules
│   ├── __init__.py           # Package exports
│   ├── file_parser.py        # Pwdump and potfile parsing
│   ├── session_manager.py    # Session management
│   ├── password_analysis_tools.py  # Password analysis functions
│   ├── hibp_checker.py       # HIBP breach checking
│   ├── hibp_downloader.py    # HIBP database download/conversion
│   ├── ollama_tools.py       # AI analysis integration
│   ├── ollama_prompts.py     # AI prompt templates
│   ├── timing_stats.py       # Performance timing
│   ├── trend_analysis.py     # Historical trend analysis
│   ├── kerberoast_analysis.py # Kerberoast exposure analysis
│   ├── asrep_analysis.py     # AS-REP exposure analysis
│   ├── password_history.py   # Password history analysis
│   ├── hash_types.py         # Hash type detection
│   ├── domain_utils.py       # Domain/username utilities
│   ├── potfile_cache.py      # Potfile caching
│   └── service_account.py    # Service account detection
│
├── templates/                # Jinja2 HTML templates
├── static/                   # CSS, JavaScript, images
├── scripts/                  # Utility scripts (HIBP setup, demo data, etc.)
├── tests/                    # Test and benchmark scripts
├── testData/                 # Sample test data files
├── data/                     # Runtime data (sessions, uploads)
└── docs/                     # Additional documentation
```

---

## **Application Startup**

### **Requirements**

- **Python Version:** 3.10+
- **Python dependencies:** See `requirements.txt`

### **Quick Install**

For a fast setup experience, use the included install scripts:

**Linux / macOS:**
```bash
./install.sh
```

**Windows (PowerShell):**
```powershell
.\install.ps1
```

These scripts automatically:
- Check Python version (3.10+ required)
- Create a virtual environment
- Install all dependencies
- Download required NLTK data
- Generate SSL certificates
- Create a `.env` file with secure defaults
- Create start scripts for easy launching

After installation, start the application with `./start.sh` (Linux/macOS) or `start.bat` (Windows).

### **Production Deployment**

For production server deployment with Nginx, systemd, and hashcat integration, use the production deployment script:

```bash
sudo ./scripts/deploy_production.sh
```

See `docs/MULTI_USER_DEPLOYMENT.md` for detailed multi-user deployment instructions.

### **Manual Installation**

While there are several ways that Hash Master 1000 could be run, using either Docker or a Python Virtual Environment is recommended. As stated earlier, a more persistent installation should only be done by a security professional. If you don't have Docker already installed and working, the native Python Virtual Envrionment is quick and easy.

Some Docker users prefer a zero-config environment, therefore, the application will run with a default Flask secret-key, admin username and admin password. It will also automatically create a self-signed SSL certificate in the Docker home folder when the application starts.

To override the default configuration, edit the included `env.example` file and save it as `.env` inside the local project folder. Likewise, you may configure your own SSL certificate in advance using openssl or the built-in `generate_cert.py` script. Docker will use the user created `.env`, `cert.pem` and `pub.pem` files in the project directory if they are created before building and starting the app.

#### <u>**Docker**</u>

Prerequisites: Install `docker` & `docker-compose` and add the current user to the `docker` group.

Build the docker image

```bash
docker compose build
```

Start the app

```bash
docker compose up -d
```

To stop the app

```bash
docker compose down
```

#### <u>**Virtual Environment** native Python</u>

The application runs on both Linux/macOS and Windows. Follow the instructions for your operating system below.

##### **Linux / macOS**

Prerequisites: Python 3.10+ with `venv` module (usually included with Python).

Set up a virtual environment for project isolation:

```bash
python3 -m venv .venv
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python3 hm1k.py
```

##### **Windows**

Prerequisites: Python 3.10+ from [python.org](https://www.python.org/downloads/windows/). During installation, ensure you check "Add Python to PATH".

Open PowerShell or Command Prompt and navigate to the project directory:

```powershell
cd C:\path\to\hm1k
```

Set up a virtual environment for project isolation:

```powershell
python -m venv .venv
```

Activate the virtual environment:

**PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Command Prompt:**

```cmd
.venv\Scripts\activate.bat
```

> **Note:** If you get an execution policy error in PowerShell, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the application:

```powershell
python hm1k.py
```

##### **Accessing the Application**

Once running, the application is available at:

```
https://localhost:8443
```

Accept the self-signed certificate warning in your browser to proceed.

**First-time startup:** The application automatically handles initial setup:

- Generates a SECRET_KEY if not present in the `.env` file
- Creates a self-signed SSL certificate (`cert.pem` and `key.pem`) if missing
- Copies `env.example` to `.env` if no `.env` file exists

---

## **Default Login**

Despite the security disclaimer above, it's important to prevent unauthorized users from easily accessing sensitive data. `Flask-Login` requires users to have a valid login in order to access any of the protected routes/endpoints. The weak default password used by the app is a humorous reminder that complex != secure and to always change your default passwords. :grin:

- Username: `admin`
- Password: `Winter2026##`

If you wish to change the username or password, either can be edited in the .env file. The default credentials below allow users to login as `admin` with the password `Winter2026##`. To change the password, bcrypt the password and paste the hash into the .env file.

**.env file:**

`ADMIN_USERNAME="admin"`

`ADMIN_PASSWORD_HASH="$2b$12$PzAkEQKfwFcafUK2RH08zO9Os3YFz7rq.4UqwaLHlFONDlqxncmnO"`

---

## **Workflow Overview**

Hash Master 1000 uses a guided 4-step wizard workflow to ensure data quality before analysis:

### **Step 1: Load Files**

The first step focuses on loading your source files. You have two options:

- **Upload Files**: Upload pwdump and potfile directly through the browser
- **Use Local Server Files**: Specify paths to files already on the server using the built-in file browser

For local server files, click the **Browse** button to open a file browser that lets you navigate the server's filesystem and select files. You can also manually enter file paths if you know them.

Each file must be validated before proceeding. Click the "Validate" button next to each file to check for formatting issues. The interface shows:

- A visual status indicator (pending, valid, warning, or error)
- Validation statistics (valid entries, warnings, errors)
- Format detection (Standard vs DCSync format for pwdump files)
- Hash type detection (NTLM vs non-NTLM for potfiles)

Both files must pass validation before you can continue to Step 2.

### **Step 2: Validation Review**

After initial validation, you're taken to a dedicated validation review page where you can:

- See detailed statistics about your files (valid lines, warnings, errors)
- Review any problematic lines with specific error messages
- Choose to include or exclude specific lines from analysis
- See hash type breakdown for potfiles (NTLM hashes are used, others are ignored)
- View status coverage for pwdump files (what percentage have Enabled/Disabled status)

This step ensures you have full control over what data is processed before analysis begins.

### **Step 3: Configure Analysis**

Configure the analysis options for your report:

- Substring analysis options (min/max length, frequency threshold)
- Dictionary word analysis options
- Password policy compliance settings (min length, complexity requirements)
- Account filtering options (ignore disabled accounts, ignore computer accounts)
- Blank password handling

Click "Generate Report" to process your files with the selected options.

### **Step 4: View Report**

The final step displays the comprehensive analysis report with statistics, charts, and detailed findings. From the report page, you can:

- View all analysis results
- Copy charts to clipboard as PNG
- Download charts as SVG or CSV
- Download all JSON data files
- Start over with new files

---

## **Inputs**

### **1. ADD JSON Format (Preferred)**

The preferred hash and domain input format is ADD JSON, generated with the [Active Directory Dumper (ADD)](https://github.com/shellntel/ActiveDirectoryDumper) tool from #\_shelltel. This format provides rich Active Directory metadata that enables domain based analysis features not available with standard pwdump formatted hashes from the Volume Shadow Copy Service (VSS) or DCSync extraction.

- Filename: `hm_domainoutput.json`
- Source: [Active Directory Dumper](https://github.com/shellntel/ActiveDirectoryDumpter)

#### **Why Use ADD JSON?**

ADD JSON includes comprehensive Active Directory data that enables:

- **Domain Password Policy**: Automatically imports the domain's password policy settings (min length, max age, history, lockout) for compliance checking
- **Group Memberships**: Full group membership data for each user
- **Privileged Account Detection**: Automatically identifies Tier 0 (Domain Admins, Enterprise Admins, Schema Admins, RID 500/502) and Elevated (Backup Operators, Account Operators, Server Operators) accounts
- **Historical Password Hashes**: Analyzes previous passwords to detect password reuse violations
- **Password Sharing Detection**: Alerts when privileged accounts share passwords with standard user accounts
- **Account Status**: Enabled/Disabled status for accurate reporting

#### **ADD JSON Structure**

```json
{
  "Name": "DOMAIN.LOCAL",
  "MinPasswordLength": 8,
  "MaxPwdAge": 90,
  "PwdHistoryLength": 24,
  "Users": [
    {
      "SamAccountName": "jdoe",
      "ObjectSid": "S-1-5-21-...-1234",
      "MemberOf": ["Domain Admins", "IT Staff"],
      "NTLMHash": "aad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889",
      "HistoricalNTHashes": ["abc123...", "def456..."],
      "UserAccountControl": ["NORMAL_ACCOUNT"]
    }
  ]
}
```

#### **Additional Report Sections with ADD JSON**

When using ADD JSON input, the report includes these additional sections:

1. **Cracked Privileged Account Passwords**: High-priority findings showing privileged accounts with cracked passwords
2. **Password Sharing Violations**: Alerts when a privileged account uses the same password as a standard account
3. **Tier 0 Accounts**: Complete list of Domain/Enterprise Admin accounts with crack status
4. **Elevated Accounts**: Other privileged group members with crack status
5. **Historical Password Analysis**: Identifies users reusing previous passwords

### **2. Pwdump File**

If you don't have ADD JSON output, Hash Master 1000 also supports traditional pwdump formats:

#### **Standard pwdump Format**

- Extension: `.txt` or `.ntds`
- Format: `{username}:{user_id}:{LM_hash}:{NTLM_hash}:{SID}:{comment}:{home_directory}`
- Example: `jdoe:1001:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::`

#### **DCSync Format (Recommended for pwdump)**

- Extension: `.txt` or `.ntds`
- Format: `{username}:{RID}:{LM_hash}:{NTLM_hash}:::: (status=Enabled|Disabled)`
- Example: `DOMAIN\jdoe:1001:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889::: (status=Enabled)`

The DCSync format includes account status information (Enabled/Disabled), which enables more accurate reporting. When status information is available, the report can show:

- Breakdown of enabled vs disabled accounts
- Cracked statistics filtered by account status
- More meaningful security recommendations

**Note:** Both formats can be mixed in the same file. Hash Master 1000 automatically detects the format of each line.

### **3. Hashcat Potfile**

- Extension: `.txt`, `.potfile`, or `.pot`
- Format: `{NTLM_hash}:{password}` or `{hash_with_mode}:{password}`
- Example: `66c4b0305e317b7ee0c90f7d370c885a:Password123#`

**Mixed Hash Type Support:** Potfiles may contain multiple hash types from different cracking sessions. Hash Master 1000 automatically detects and categorizes each hash type:

- NTLM hashes (32-character hex) are used for analysis
- Non-NTLM hashes (SHA1, MD5, bcrypt, etc.) are detected and ignored
- A summary of hash types is shown during validation

This allows you to use your main potfile without needing to filter out non-NTLM entries first.

**Note:** All `$HEX[...]` encoded passwords from the potfile are decoded prior to analysis and reporting.

### **File Requirements**

- Each file must have one properly formatted entry per line
- Empty lines and comment lines (starting with `#`) are automatically skipped
- Files are validated before processing to catch formatting issues early
- **Your pwdump file must not contain duplicate account names, especially with different hashes**

### **Upload vs Local Server Files**

The Step 1 interface provides a toggle between two input methods:

- **Upload Files**: Browse and upload files directly from your computer through the browser
- **Use Local Server Files**: Select files already on the server using the built-in file browser

When using local server files, you can either:

- Click the **Browse** button to open a file browser modal that lets you navigate the server's filesystem
- Manually type or paste the full path to the file

The file browser shows directories and files, their sizes, and allows easy navigation with ".." to go to parent directories.

**Note:** To assist in evaluating or testing the application, there are example pwdump and potfile files in the project's `testData/` directory.

---

## **File Validation**

Before processing, Hash Master 1000 validates both input files to ensure data quality. The validation system catches common issues early, preventing corrupted data from affecting your analysis.

### **Validation Process**

1. Click the "Validate" button next to each file after selecting it
2. The system parses each line and checks for formatting issues
3. Results are displayed with statistics and any problems found
4. Both files must pass validation before proceeding

### **Pwdump Validation Checks**

- **Field Count**: Must have exactly 7 colon-separated fields
- **Username**: Must not be empty
- **NTLM Hash**: Must be exactly 32 hexadecimal characters
- **LM Hash**: Validated if present (warnings for malformed LM hashes)
- **Format Detection**: Automatically identifies Standard vs DCSync format

### **Potfile Validation Checks**

- **Format**: Must be `hash:password` format
- **Hash Type Detection**: Automatically identifies hash types (NTLM, SHA1, MD5, bcrypt, etc.)
- **NTLM Filtering**: Only NTLM hashes (32-character hex) are used; others are flagged as "ignored"
- **Password**: Must be present (hash-only lines are flagged)
- **Hash Type Summary**: Shows breakdown of all hash types found in the file

### **Error Severity Levels**

- **Fatal**: Line cannot be processed (wrong field count, invalid hash, missing username)
- **Warning**: Line can be processed but may have issues (malformed LM hash, empty line)
- **Info**: Informational (comment lines, format detection)

### **Validation Review Page**

If issues are found, you'll be directed to a validation review page where you can:

- See all problematic lines with detailed error messages
- Choose to include or exclude specific lines from analysis
- Review the raw line content to diagnose issues
- Proceed with only the valid entries

---

## **Configurable Settings**

Configurable settings affect the analysis and reporting of cracked passwords and hash data. A thorough password analysis may require tweaking the substring and dictionary word analysis options, usually to control the number of results. Likewise, it's useful to analyze substrings and dictionary words both with and without supressing any nested strings/words. There are 5 sections of analysis options including:

1. Substring analysis options
2. Dictionary word analysis options
3. Password policy compliance options
4. Company Name & Terms detection
5. Option to treat blank passwords as uncracked

Note: The default settings should work for most basic use cases. Only the pwdump file and Hashcat potfile are required to run a report.

#### **Substring Analysis**

Substing analysis refers to identifying repeating strings of characters within passwords. The longer the repeating string of characters, the more likely that it's a common string (or perhaps word) used within the organization to make passowrds. Any intentional use of a string that exists in multiple passwords is insecure. Substring analysis enhances the more traditional discovery of English dictionary words by discovering any repeating strings, not just words.

- **Min Substring Length**: Smallest substring length to analyze (# of characters). In a large dataset with many cracked passwords, a longer minumum length is suggested to reduce the number of matches/results. Use this setting along with the Substring Frequency Threshold setting to tune the report output.
- **Max Substring Length**: Largest substring length to analyze (# of characters).
- **Substring Freq Threshold**: Minimum frequency required (# of hits). This sets how many account passwords must contain the string to be considered significant enough to be included in the report. This allows the analysis to be tuned to the size of the job. A dataset with thousands of cracked passwords is likely to identify more repeating strings, expecially if used with a low Min Substring Length setting.
- **Suppress Nested Substrings**: Whether to display substrings within larger substrings. It's common to find repeating strings within larger repeating strings and there may be use cases where you want to analyze both. This is especially useful if you intend to download the CSV or JSON file for offline analysis.
- **Analyze Substrings in Lowercase**: Normalizes passwords to lowercase before analysis. Normalizing to lowercase is standard for dictionary word analysis, but may not be ideal for substring analysis.

#### **Dictionary Word Analysis**

Dictionary analysis is just as you'd expect, Hash Master 1000 searches each password to see if it contains words from the English language dictionary. Dictionary Word Analysis uses Python's nltk as the list of English words.

- **Min Word Length**: Minimum word length to include in the analysis. Use caution including words shorter than 4 characters without Suppressing Display Nested Words as you'll likely find many nested words.
- **Suppress Nested Words**: Select whether to display words within words. For example, the password `Summertime123` includes the words: `summertime`, `summer`, `time`, `sum`, `time`, `me`. Suppressing the nested words would result in only the largest words being reported.

#### **Password Policy Compliance**

The Policy Compliance configurable settings allow the report to be customized to show violations of the effective Group Policy (or local password policy).

- **Min Password Length**: Minimum length required for a compliant password.
- **Max Password Age**: Maximum allowable days since last password change (feature coming soon).
- **Complexity Requirement**: Passwords must meet specific complexity rules (uppercase, lowercase, digit, and special character). Microsoft typically requires 3 out of 4 categories to be complex, but certain implemenations may require all 4 categories. While there is rumor of a 5th complexity category being added, selecting 5 today should cause all cracked passwords to be reported.

#### **Company Name & Terms**

This feature allows you to detect organization-specific terms in cracked passwords. Users commonly incorporate company names, acronyms, department names, product names, or other organization-specific terms into their passwords. This is a significant security risk as these terms are easily guessable by attackers who know the target organization.

Click the **Configure** button to open a modal where you can enter custom keywords:

- Enter one term per line
- Terms must be at least 3 characters long (supports short acronyms)
- Matching is case-insensitive
- Examples: company name, stock ticker, department names, product names, building names

When configured, a "Company Terms" category appears in the Bad Practices Report chart. Clicking on the bar shows all matching passwords with their occurrence counts.

#### **Ignore Blank Passwords**

This advanced option should be used with care as it will affect nearly all calculations performed. Selecting this option causes all blank passwords to be considered uncracked during analysis.

- **Do Not Treat Blank Passwords As Cracked**: Allows reports to be generated with blank passwords being calculated as uncracked rather than cracked. Use with caution!

---

## **Output Report**

The HTML report includes:

- Cracked accounts and hash statistics
- Password length distribution charts
- Reused passwords and substrings
- Password policy compliance violations
- Accounts with blank passwords

![Sample Report](static/images/sample-report.png)

The generated HTML report includes the following sections:

### **Statistics Table**

Provides a high-level overview:

- Total accounts analyzed
- Number and percentage of cracked accounts and hashes
- Shortest, longest, and average password lengths
- Number of LANMan hashes
- Number of blank passwords

### **Charts**

- **Cracked Accounts Pie Chart**: Shows cracked vs. uncracked accounts.
- **Cracked Hashes Pie Chart**: Compares cracked and uncracked hashes.
- **Password Length Distribution**: Visualizes the distribution of cracked password lengths.
- **Top Reused Cracked Passwords**: Highlights commonly reused passwords.
- **Top Substrings Used**: Displays the most frequent substrings within passwords.
- **Top Dictionary Words**: Identifies frequent dictionary words found in cracked passwords.
- **Bad Practices Report**: Interactive bar chart showing passwords matching common bad practice patterns including:

  - Password Variants (password, p@ssw0rd, passwd, etc.)
  - Season + Year combinations (Summer2024, Winter2023, etc.)
  - Keyboard walks (qwerty, asdf, 123456, etc.)
  - Common weak bases (letmein, welcome, admin, etc.)
  - Top common passwords
  - Sequential/repeated characters
  - Bible verses
  - Sports teams/mascots
  - Passwords ending with # or !
  - Leet-speak substitutions
  - Company Terms (when configured)

  **Click on any bar** to see all matching passwords with their occurrence counts in a scrollable modal.

**Note**: All charts can be copied to the clipboard as PNG, downloaded as SVG, or downloaded as CSV, using the buttons below each chart.

### **Password Reuse Table**

Displays reused NTLM hashes, their counts, and associated accounts.

### **Policy Compliance Tables**

1. **Accounts Failing Minimum Length Policy**:
   Lists accounts with passwords shorter than the required length.
2. **Accounts Failing Complexity Policy**:
   Highlights accounts with passwords that do not meet complexity requirements.
3. **Accounts With Blank Passwords**:
   Shows accounts where passwords are blank (also treated as cracked in reports).
4. **Accounts Failing Maximum Age Policy**:
   Lists accounts with expired passwords (future implementation).

### **Accounts With LM Hashes**

Displays accounts that have legacy LM (LAN Manager) hashes present. LM hashes are cryptographically weak and should be trivial to crack. The table includes:

- **Account**: The account name
- **Cracked Password**: The cracked password if available, or "Not Cracked" highlighted in orange

Accounts marked as "Not Cracked" may indicate that LM hash cracking was missed during the engagement, or the LM hash may not be valid. This helps pentesters identify accounts that may need additional cracking effort.

**Note:** At the bottom of the report page, there is a **Download All JSON Files** button. Each chart and table on the page loads a JSON object that includes the necessary data to populate the chart or table. Downloading the JSON files gives you the ability to use the raw data for other purposes outside of Hash Master 1000.

### **Important Notes**

1. **Password Cracking Data**: The analysis includes only cracked passwords. Many hashes remain uncracked, so the report represents a subset of the total accounts.
2. **Accounts vs. Hashes**: Due to password reuse, the number of cracked accounts may exceed the number of unique cracked hashes.
3. **Blank Passwords**: Accounts with blank passwords are reported as cracked. Therefore, blank passwords have a zero character length and include zero complexity categories. It is critical that accounts with blank passwords are disabled.
4. **Account Status**: When using DCSync format files with status information, the report can distinguish between enabled and disabled accounts. This provides more accurate security assessments by showing which vulnerable accounts are actively in use. If status information is incomplete (less than 100% coverage), a warning will be displayed during validation.

---

## **Hash Dumping Methods**

### **1. Using pwdump**

Standard pwdump extraction:

```bash
pwdump > hashes.txt
```

### **2. Impacket SecretsDump**

Basic extraction:

```bash
secretsdump.py -just-dc SAMDOMAIN/user:password@dc_ip
```

**To get DCSync format with account status** (recommended):

```bash
secretsdump.py -just-dc -user-status SAMDOMAIN/user:password@dc_ip
```

The `-user-status` flag includes `(status=Enabled)` or `(status=Disabled)` suffix on each line, enabling full account status analysis in Hash Master 1000.

### **3. Using AD Backups**

Extract hashes from an AD backup or snapshot using tools like `ntdsutil` or offline NTDS.dit extraction.

For detailed guidance, refer to trusted resources on Windows security and password extraction.

---

## **Session Management**

Hash Master 1000 supports multiple analysis sessions, allowing you to save, restore, and compare different password audits.

### **Session Features**

- **Named Sessions**: Give each analysis a descriptive name for easy identification
- **Session Persistence**: Sessions are automatically saved and can be restored later
- **Session Switching**: Quickly switch between different analyses from the report page
- **Duplicate Detection**: When uploading files, the system detects if you already have a session with the same data
- **Session Isolation**: Each session stores its own data files, AAIA results, and debug output

### **Session Storage**

Sessions are stored in `data/sessions/<session_id>/` with the following structure:

```
data/sessions/<session_id>/
├── account_data.json          # Raw account/password data
├── cracking_stats_table.json  # Statistics summary
├── pw_*.json                  # Various analysis files
├── aaia_results.json          # AI analysis results (if generated)
├── session_meta.json          # Session metadata
└── ai_analysis/               # AAIA debug output (if enabled)
```

---

## **Have I Been Pwned (HIBP) Integration**

Hash Master 1000 can check your password hashes against the Have I Been Pwned Pwned Passwords database to identify passwords that have appeared in known data breaches.

### **How It Works**

The HIBP integration uses the **k-Anonymity** model to protect your data:

1. Only the **first 5 characters** of each NTLM hash are sent to the HIBP API
2. The API returns all hash suffixes matching that prefix
3. The comparison happens **locally** - your full hashes never leave your system
4. No usernames, passwords, or identifying information are ever transmitted

### **Using the Breach Check**

1. Navigate to the **Breach Check** section in the report (always visible in navigation)
2. Click **Check Against Breach Database**
3. Review and accept the consent notice about connecting to an external service
4. Wait for the check to complete (typically 1-3 seconds for ~50 accounts)
5. View results showing which accounts have passwords found in breaches

### **Understanding Results**

| Column                     | Meaning                                                                                 |
| -------------------------- | --------------------------------------------------------------------------------------- |
| **Username**               | The account name                                                                        |
| **Password**               | The cracked password (blurred by default for privacy)                                   |
| **Times Seen in Breaches** | How many times this password hash has appeared across all breaches in the HIBP database |

A password appearing millions of times (e.g., 52,000,000+) indicates it's extremely common globally - passwords like "password", "123456", "admin" have counts in the millions. Even a count of 1 means the password was found in at least one breach.

### **Privacy Features**

- **Blur Toggle**: Passwords are blurred by default; click "Show Passwords" to reveal
- **Blank Password Skip**: Accounts with blank passwords are automatically excluded (no point checking those)
- **k-Anonymity**: The HIBP API never sees your full hashes
- **Consent Required**: Users must explicitly consent before any external API calls

### **Important Notes**

- **Hash Count Discrepancy**: The number of NTLM hashes checked in HIBP may be 1 less than the total shown in the report statistics, because blank passwords (hash: `31d6cfe0d16ae931b73c59d7e0c089c0`) are automatically excluded from breach checks. This is intentional - there's no value in checking whether the blank password appears in breaches.
- **Account vs Hash Counts**: Multiple accounts can share the same password hash (and thus the same password). The report displays both unique NTLM hash counts and account counts to give you a complete picture of password reuse within your organization.

### **Future: Local Database Support**

For air-gapped environments, a future update will support checking against a locally-downloaded HIBP NTLM hash database.

---

## **Kerberoast Exposure Analysis**

Hash Master 1000 includes automated Kerberoast exposure analysis when using ADD JSON input. This feature identifies accounts vulnerable to Kerberoasting attacks and calculates a comprehensive risk score based on multiple security factors.

### **What is Kerberoasting?**

Kerberoasting is an attack technique that targets Active Directory service accounts. Any account with a Service Principal Name (SPN) registered can have its Kerberos service ticket requested by any authenticated domain user. The ticket is encrypted with the account's password hash, allowing offline password cracking attempts. This makes service accounts with weak passwords high-value targets.

### **How It Works**

When ADD JSON data is processed, Hash Master 1000 automatically:

1. **Identifies Service Accounts**: Finds all accounts with ServicePrincipalNames (SPNs)
2. **Analyzes Risk Factors**: Evaluates 14 different security indicators for each account
3. **Calculates Risk Scores**: Assigns a composite risk score (0-100+) based on accumulated factors
4. **Categorizes Severity**: Groups accounts into Critical, High, Medium, and Low risk categories
5. **Generates Reports**: Creates detailed JSON output with Chart.js-compatible visualizations

### **Required ADD JSON Fields**

The following fields from the ADD JSON export enable Kerberoast analysis:

| Field                      | Purpose                                            |
| -------------------------- | -------------------------------------------------- |
| `ServicePrincipalNames`    | Array of SPNs - identifies Kerberoastable accounts |
| `RawUACValue`              | Integer bitmask for UserAccountControl flags       |
| `adminCount`               | "1" indicates protected/privileged account         |
| `supportedEncryptionTypes` | Kerberos encryption types bitmask                  |
| `allowedToDelegateTo`      | Constrained delegation targets (SPNs)              |
| `PwdLastSet`               | Password age calculation                           |

### **Risk Factor Scoring**

Each service account is evaluated against these security factors:

| Risk Factor                   | Points | Description                                      |
| ----------------------------- | ------ | ------------------------------------------------ |
| **SPN Present**               | +10    | Base score for any Kerberoastable account        |
| **Cracked Password**          | +40    | Password was cracked during assessment           |
| **HIBP Exposed**              | +35    | Password hash found in breach databases          |
| **Privileged (adminCount=1)** | +30    | Account is a protected/privileged AD account     |
| **AS-REP Roastable**          | +25    | DONT_REQ_PREAUTH flag set (no pre-auth required) |
| **Delegation Enabled**        | +25    | Unconstrained delegation configured              |
| **Password Age >3 Years**     | +20    | Password not changed in over 3 years             |
| **Reused Password Cluster**   | +20    | Password shared with other accounts              |
| **Constrained Delegation**    | +15    | Has allowedToDelegateTo entries                  |
| **Password Never Expires**    | +15    | DONT_EXPIRE_PASSWORD flag set                    |
| **Weak Encryption (DES)**     | +15    | DES encryption types enabled                     |
| **Password Age >1 Year**      | +10    | Password not changed in over 1 year              |
| **Weak Encryption (RC4)**     | +10    | RC4_HMAC encryption supported                    |
| **Account Disabled**          | -50    | Risk reduction for disabled accounts             |

### **Risk Categories**

Accounts are categorized by their total risk score:

| Category     | Score Range | Priority                       |
| ------------ | ----------- | ------------------------------ |
| **Critical** | 70+         | Immediate remediation required |
| **High**     | 50-69       | High priority remediation      |
| **Medium**   | 30-49       | Scheduled remediation          |
| **Low**      | 10-29       | Monitor and review             |

### **Example Report Output**

The analysis generates `kerberoast_report.json` containing:

```json
{
  "summary": {
    "total_service_accounts": 12,
    "enabled_with_spns": 10,
    "disabled_with_spns": 2,
    "with_cracked_passwords": 5,
    "privileged_accounts": 3,
    "with_delegation": 4,
    "asrep_roastable": 1,
    "risk_distribution": {
      "critical": 2,
      "high": 3,
      "medium": 4,
      "low": 3
    }
  },
  "accounts": [
    {
      "sam_account_name": "svc_sqlserver",
      "risk_score": 85,
      "risk_category": "critical",
      "risk_reasons": [
        "SPN_PRESENT",
        "CRACKED_PASSWORD",
        "PRIVILEGED_ADMINCOUNT",
        "PASSWORD_NEVER_EXPIRES"
      ],
      "spns": ["MSSQLSvc/sql01.domain.local:1433"],
      "is_privileged": true,
      "enabled": true,
      "supports_rc4": true,
      "supports_aes": true
    }
  ],
  "charts": {
    "risk_distribution": {...},
    "encryption_breakdown": {...},
    "delegation_types": {...}
  }
}
```

### **Security Recommendations**

Based on the analysis, prioritize remediation for:

1. **Critical Accounts**: Immediately rotate passwords, enforce AES-only encryption, review delegation settings
2. **Cracked Service Accounts**: Treat as potentially compromised; rotate passwords and audit for suspicious activity
3. **Privileged Service Accounts**: Implement Managed Service Accounts (gMSA) where possible
4. **Accounts with Delegation**: Review and minimize delegation scope; prefer constrained delegation over unconstrained
5. **Old Passwords**: Implement regular password rotation policies for service accounts

### **API Endpoint**

Access the Kerberoast analysis data via:

```
GET /kerberoast_report.json
```

Returns the full analysis report in JSON format for integration with other tools or custom reporting.

---

## **AS-REP Exposure Analysis**

Hash Master 1000 automatically identifies accounts vulnerable to AS-REP Roasting when processing ADD JSON data. AS-REP Roasting targets accounts that have Kerberos pre-authentication disabled, allowing attackers to request encrypted authentication data that can be cracked offline.

### **What is AS-REP Roasting?**

AS-REP Roasting exploits the `DONT_REQUIRE_PREAUTH` flag (UAC bit 0x400000) in Active Directory. When this flag is set, any user can request an AS-REP (Authentication Service Response) for that account without providing valid credentials. The response contains data encrypted with the account's password hash, enabling offline password cracking attempts.

### **How It Works**

When ADD JSON data is processed, Hash Master 1000 automatically:

1. **Scans All Accounts**: Checks the `RawUACValue` for the `DONT_REQ_PREAUTH` flag
2. **Identifies Vulnerable Accounts**: Lists accounts with pre-authentication disabled
3. **Correlates with Other Data**: Cross-references with cracked passwords, HIBP exposure, and privilege levels
4. **Generates Risk Assessment**: Provides severity ratings based on account characteristics

### **Report Output**

The AS-REP analysis section displays:

- **Summary Statistics**: Total accounts scanned, vulnerable accounts found
- **Risk Breakdown**: Accounts categorized by privilege level and password status
- **Account Details**: Table showing vulnerable accounts with their risk factors
- **Remediation Guidance**: Recommendations for securing affected accounts

### **API Endpoint**

```
GET /asrep_report.json
```

Returns the AS-REP analysis results in JSON format.

---

## **Historical Trend Analysis**

Track password security improvements across multiple assessment sessions for the same organization. This feature helps demonstrate ROI on security investments and identify areas that need continued focus.

### **How It Works**

Sessions are grouped by company name, allowing you to compare metrics across quarterly or annual assessments:

1. **Session Metadata**: Each session stores company name and project description
2. **Automatic Grouping**: Sessions are grouped by company for easy comparison
3. **Trend Calculation**: Metrics are compared between oldest and newest sessions
4. **Visual Charts**: Six trend charts show key metrics over time

### **Tracked Metrics**

| Metric                  | Description                               | Goal            |
| ----------------------- | ----------------------------------------- | --------------- |
| **Crack Rate**          | Percentage of passwords cracked           | Lower is better |
| **Password Reuse Rate** | Accounts sharing passwords                | Lower is better |
| **Policy Violations**   | Min length + complexity + blank passwords | Lower is better |
| **Bad Practices**       | Total bad password pattern detections     | Lower is better |
| **Total Accounts**      | Number of accounts analyzed               | Context metric  |
| **HIBP Exposed**        | Accounts with breached passwords          | Lower is better |

### **Trend Charts**

The Historical Trend Analysis section provides six visual charts:

1. **Crack Rate Over Time** - Primary security improvement indicator
2. **Password Reuse Rate Over Time** - Tracks reduction in shared passwords
3. **Total Accounts Analyzed** - Shows assessment scope consistency
4. **HIBP Exposed Accounts** - Tracks breach exposure reduction
5. **Policy Violations Over Time** - Monitors compliance improvements
6. **Bad Practices Over Time** - Tracks behavioral pattern improvements

### **Using Trend Analysis**

1. Navigate to the **Historical Trend Analysis** section in the report
2. Select your company from the dropdown (auto-detected from current session)
3. Check the sessions you want to compare (minimum 2)
4. Click **Analyze Selected Sessions**
5. Review the trend charts and comparison table

### **API Endpoint**

```
POST /api/sessions/trend-analysis
Content-Type: application/json

{"session_ids": ["session1", "session2", "session3"]}
```

Returns trend comparison data with metrics, changes, and chart-ready datasets.

---

## **Top 25 Group Memberships**

Hash Master 1000 identifies accounts with the highest number of Active Directory group memberships. Accounts with excessive group memberships often indicate over-provisioned permissions, privilege creep, or service accounts that have accumulated groups over time—all potential security risks.

### **Requirements**

This feature requires ADD JSON input, as standard pwdump files do not include group membership data.

### **How It Works**

When ADD JSON data is processed, Hash Master 1000:

1. **Extracts Group Memberships**: Reads the `MemberOf` field for each account
2. **Counts and Ranks**: Sorts accounts by total group count (descending)
3. **Classifies Privilege Levels**: Identifies Tier 0, Elevated, and Standard accounts
4. **Correlates with Crack Status**: Shows which high-membership accounts have cracked passwords

### **Privilege Level Classification**

Accounts are classified into three privilege tiers based on group membership:

| Level | Groups | Description |
|-------|--------|-------------|
| **Tier 0** | Domain Admins, Enterprise Admins, Schema Admins, RID 500/502 | Highest privilege accounts with full domain control |
| **Elevated** | Administrators, Backup Operators, Account Operators, Server Operators | Privileged accounts with significant access |
| **Standard** | All other accounts | Normal user accounts |

### **Report Output**

The Top 25 Group Memberships section displays:

- **Summary Statistics**: Max group count, average group count, counts by privilege level, cracked accounts in top 25
- **Accounts Table**: Sortable table showing account name, group count, privilege level, and crack status
- **Group Details**: Expandable view showing all groups for each account
- **CSV Export**: Download the full data for offline analysis

### **Security Implications**

High group membership counts can indicate:

- **Over-Provisioned Accounts**: Users with more access than necessary for their role
- **Service Account Sprawl**: Service accounts accumulating groups over time without cleanup
- **Privilege Creep**: Gradual accumulation of permissions as users change roles
- **Orphaned Access**: Group memberships from previous roles that were never removed

### **Recommendations**

Based on the analysis, consider:

1. **Review High-Count Accounts**: Investigate accounts with unusually high group counts
2. **Prioritize Cracked Accounts**: Accounts with both high privileges and cracked passwords are critical risks
3. **Implement Least Privilege**: Remove unnecessary group memberships
4. **Regular Access Reviews**: Schedule periodic reviews of group memberships, especially for privileged accounts

---

## **Days Since Last Login Analysis**

Hash Master 1000 identifies accounts with extended periods of inactivity based on their last login timestamp. This analysis helps identify stale, dormant, or potentially orphaned accounts that may pose security risks.

### **Requirements**

This feature requires ADD JSON input with the `LastLogonTimestamp` field populated.

### **How It Works**

When ADD JSON data is processed with login timestamps, Hash Master 1000:

1. **Calculates Login Age**: Determines days since each account's last login
2. **Filters Stale Accounts**: Identifies accounts with no login activity in over 90 days
3. **Correlates with Crack Status**: Shows which stale accounts have cracked passwords
4. **Provides Account Context**: Displays account status (Enabled/Disabled) and cracked password if available

### **Report Output**

The Days Since Last Login section displays:

- **Summary Statistics**: Total accounts analyzed, accounts with login data, stale account count
- **Stale Accounts Table**: Sortable/searchable table showing:
  - Account name
  - Days since last login
  - Account status (Enabled/Disabled)
  - Cracked password (blurred by default for privacy)
- **CSV Export**: Download the full data for offline analysis
- **Show Passwords Toggle**: Reveal blurred passwords when needed

### **Security Implications**

Stale accounts (90+ days without login) can indicate:

- **Orphaned Accounts**: Accounts belonging to former employees that were never disabled
- **Service Account Issues**: Automated accounts that may have stopped functioning
- **Shared Account Problems**: Accounts that were abandoned after being shared
- **Compliance Risks**: Accounts that should have been disabled per policy

### **Recommendations**

Based on the analysis, consider:

1. **Disable Stale Accounts**: Accounts with no recent login should be disabled pending review
2. **Prioritize Cracked Stale Accounts**: These are high-risk since attackers could use abandoned accounts
3. **Investigate Enabled Stale Accounts**: Why hasn't the user logged in? Have they left the organization?
4. **Implement Dormant Account Policies**: Automatically disable accounts after extended inactivity periods

---

## **Advanced AI Analysis (AAIA)**

Hash Master 1000 includes an optional AI-powered analysis feature that generates executive-ready insights from your password audit data.

> **⚠️ Experimental Feature Disclaimer**
>
> AAIA is an **experimental feature** that uses large language models (LLMs) to generate analysis. While the pipeline includes anti-hallucination safeguards, AI-generated content may contain:
>
> - **Inaccuracies or hallucinations** - fabricated statistics, patterns, or recommendations
> - **Misinterpretations** - incorrect conclusions drawn from the data
> - **Inconsistencies** - varying quality depending on the model used
>
> **Always verify AI-generated findings against the actual data before including them in reports or making security decisions.** The AAIA output is intended as a starting point for analysis, not as authoritative conclusions.

### **Requirements**

- **AI Backend**: Either a local/remote Ollama instance OR an OpenAI-compatible API endpoint
- **Recommended Models**: `deepseek-r1:671b` (reasoning), `llama3.1:70b` (fast), or cloud models via OpenAI API
- **Configuration**: Set `OLLAMA_ENABLED=true` in `.env`

### **OpenAI-Compatible API Support**

AAIA supports any OpenAI-compatible API endpoint, enabling use with:

- **OpenAI**: GPT-4, GPT-4o, GPT-3.5-turbo
- **OpenRouter**: Access to Claude, Gemini, Llama, Mistral, and other models
- **vLLM**: Self-hosted OpenAI-compatible server
- **LM Studio**: Local models with OpenAI API compatibility
- **Azure OpenAI**: Microsoft's hosted OpenAI models

Configure an OpenAI-compatible endpoint:

```bash
# OpenAI
OLLAMA_HOST="https://api.openai.com/v1"
OPENAI_API_KEY="sk-..."

# OpenRouter
OLLAMA_HOST="https://openrouter.ai/api/v1"
OPENAI_API_KEY="sk-or-..."

# Local vLLM/LM Studio
OLLAMA_HOST="http://localhost:8000/v1"
```

The system auto-detects API type based on response format and adjusts accordingly.

### **3-Phase Pipeline**

AAIA uses a sophisticated 3-phase pipeline to ensure accurate, well-formatted output:

| Phase                   | Purpose                                            | Model                  |
| ----------------------- | -------------------------------------------------- | ---------------------- |
| **Phase 1: Analysis**   | Generate initial insights from raw data            | Section-specific       |
| **Phase 2: Validation** | Fact-check against evidence, remove hallucinations | Dynamic (Tier-0 gated) |
| **Phase 3: Formatting** | Polish for executive presentation                  | llama3.1:70b           |

### **Report Sections**

AAIA generates four analysis sections:

1. **Password Pattern Analysis**: Discovers weak password habits and structural patterns
2. **Company Intelligence**: Infers organizational details from password choices
3. **User Behavior Insights**: Analyzes psychology and behavioral patterns
4. **Security Recommendations**: Prioritized, actionable remediation steps

### **Anti-Hallucination Measures**

The pipeline includes multiple safeguards against AI hallucination:

- Password whitelist validation ensures all examples exist in actual data
- Tier-0 gating skips validation for clean content, routes complex issues to reasoning models
- Explicit prompts warn models not to invent passwords or statistics
- Validation flags content for human review when confidence is low

### **Configuration**

Add these to your `.env` file:

```bash
OLLAMA_ENABLED=true
OLLAMA_HOST=http://localhost:11434
AI_PIPELINE_DEBUG=true  # Save debug output for each phase
```

For detailed prompt documentation, see `docs/PROMPTS.md`.

---

## **AD Description Analysis**

Hash Master 1000 includes powerful analysis of Active Directory description fields to detect sensitive information that may have been inadvertently stored in account descriptions. This feature uses both regex-based pattern matching and optional AI-powered analysis.

### **Why Analyze Descriptions?**

Active Directory description fields are often overlooked during security audits, yet they frequently contain:

- **Embedded passwords** written by administrators for convenience
- **API keys and tokens** from service account documentation
- **Personally identifiable information (PII)** like SSNs, phone numbers, and email addresses
- **Network information** including IP addresses and hostnames
- **Legal hold markers** indicating accounts involved in litigation

### **Detection Categories**

The regex-based analyzer detects the following sensitive information types:

| Category | Examples | Severity |
|----------|----------|----------|
| **Embedded Passwords** | "password: Summer2024", "pw=admin123" | Critical |
| **API Keys/Tokens** | API keys, bearer tokens, secrets | Critical |
| **SSN** | Social Security Numbers (XXX-XX-XXXX format) | Critical |
| **Credit Card** | Credit card numbers | Critical |
| **Legal Hold** | "litigation", "legal hold", "e-discovery", "subpoena" | Medium |
| **PII** | Phone numbers, email addresses, dates of birth | Medium |
| **Network Info** | IP addresses, hostnames | Low |

### **How It Works**

1. **Automatic Detection**: When ADD JSON data is processed, descriptions are automatically scanned
2. **Pattern Matching**: Regex patterns identify potential sensitive data
3. **Severity Classification**: Findings are categorized by severity (Critical, High, Medium, Low)
4. **Summary Statistics**: Dashboard shows counts by category with visual charts
5. **Searchable Interface**: When no findings exist, a search function lets you explore descriptions for custom keywords

### **AI-Powered Analysis (Optional)**

When AAIA is enabled, the Description Inspector can use AI models to detect:

- Context-sensitive password references that regex might miss
- Semantic PII patterns (names, addresses in various formats)
- Credential patterns beyond standard formats
- Organizational-specific sensitive terms

### **Viewing Results**

Navigate to the **AD Description Inspector** section in the report to see:

- **Summary Card**: Total accounts scanned, findings by category
- **Category Distribution Chart**: Visual breakdown of finding types
- **Findings Table**: Detailed list with account names, finding types, and masked values
- **Description Search**: Search accounts by description keywords when no sensitive findings exist

### **Security Recommendations**

Based on findings, prioritize:

1. **Critical Findings**: Immediately rotate any exposed passwords or API keys
2. **PII Exposure**: Review data handling policies; consider clearing descriptions
3. **Legal Hold Markers**: Ensure proper preservation procedures are followed
4. **Network Information**: Evaluate if internal topology should be documented elsewhere

---

## **Advanced Mode**

Advanced Mode provides access to development tools, diagnostics, and system configuration utilities. These pages are intended for power users and administrators who need deeper access to system internals.

### **Enabling Advanced Mode**

**Single-user mode**: Set in your `.env` file:

```bash
ADVANCED_OPTIONS_ENABLED="true"
```

**Multi-user mode**: Advanced Mode is controlled by user roles instead of the environment variable:

- **superadmin** and **admin** roles automatically have access
- **user** role does not have access to Advanced Mode

When enabled, an "Advanced" button appears in the application header.

### **Available Tools**

| Tool                         | Path                     | Description                                                                                                                          |
| ---------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| **HIBP Database Download**   | `/hibp/download`         | Download the full Have I Been Pwned NTLM database (~16GB, 850M+ hashes) for offline breach checking. Supports resume if interrupted. |
| **Ollama Server Management** | `/api/ai/servers/manage` | Multi-server connectivity testing and model management. View, pull, and delete models across all configured Ollama servers.          |
| **AI Report Lab**            | `/api/ai/report/test`    | Testing environment for AI report sections with prompt preview, temperature tuning, and output comparison.                           |
| **Benchmark Suite**          | `/api/ai/benchmark`      | Comprehensive model benchmarking with quick tests, production prompts, and full matrix performance analysis.                         |
| **Timing Statistics**        | `/timing/stats`          | Performance metrics for key operations including startup times, HIBP lookups, validation speeds, and system information.             |

### **API Endpoints**

Advanced Mode also exposes diagnostic API endpoints:

| Endpoint                  | Description                                    |
| ------------------------- | ---------------------------------------------- |
| `/api/ai/status`          | Ollama connection status and available models  |
| `/api/ai/servers`         | List all configured Ollama servers with status |
| `/api/ai/report/sections` | AI report section configurations               |
| `/api/ai/report/data`     | Available analysis data summary                |
| `/api/ai/report/outputs`  | Saved AI test outputs from Report Lab          |
| `/api/ai/aaia/config`     | AAIA configuration with server status          |
| `/api/hibp/download/info` | HIBP database status and download progress     |

### **Accessing Advanced Mode**

Navigate to `/hidden` or click the "Advanced" button in the header when enabled. The Advanced Mode index page provides quick access to all tools and shows real-time status of configured Ollama servers.

---

## **Environment Configuration**

Hash Master 1000 uses a `.env` file for configuration. Copy `env.example` to `.env` and customize:

### **Core Settings**

```bash
SECRET_KEY="your-secret-key-here"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD_HASH="your-bcrypt-hash-here"
```

### **Default File Paths (Optional)**

Pre-populate the file input fields for faster testing. Use the appropriate path format for your operating system:

**Linux/macOS:**

```bash
DEFAULT_PWDUMP_PATH="/home/user/hashes/domain.ntds"
DEFAULT_POTFILE_PATH="/home/user/hashcat/hashcat.potfile"
DEFAULT_ADD_JSON_PATH="/home/user/data/domain.json"
```

**Windows:**

```bash
DEFAULT_PWDUMP_PATH="C:\\Users\\user\\hashes\\domain.ntds"
DEFAULT_POTFILE_PATH="C:\\Users\\user\\hashcat\\hashcat.potfile"
DEFAULT_ADD_JSON_PATH="C:\\Users\\user\\data\\domain.json"
```

> **Note:** On Windows, use double backslashes (`\\`) or forward slashes (`/`) in paths.

### **Ollama AI Integration**

```bash
OLLAMA_ENABLED="true"
OLLAMA_HOST="http://localhost:11434"
OLLAMA_TIMEOUT="120"
AI_PIPELINE_DEBUG="false"
```

### **Multiple Ollama Servers**

Configure up to 3 Ollama servers for load distribution:

```bash
# Primary Server
OLLAMA_HOST="http://localhost:11434"
OLLAMA_PRIMARY_NAME="Local Server"
OLLAMA_PRIMARY_DESC="Local Ollama instance"
OLLAMA_PRIMARY_HARDWARE="CPU"

# Secondary Server (optional)
OLLAMA_SECONDARY_HOST="http://192.168.1.100:11434"
OLLAMA_SECONDARY_NAME="GPU Server"
OLLAMA_SECONDARY_HARDWARE="RTX 4090, 24GB VRAM"
```

---

## **Source**

HM1K was created by Brian Judd of SynerComm inc. It started as a side project and turned into a vibe coded passion. SynerComm is a leader in cybersecurity and penetration testing. Learn more about how Hash Master 1000 uses substring analysis to identify patterns in cracked passwords.
https://www.synercomm.com/password-security-substring-analysis/

---

## **Licensing**

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**. This allows for free use and modification, provided:

- Commercial use is prohibited.
- Attribution to the original author is maintained.

For more information, see the [LICENSE](LICENSE) file.
