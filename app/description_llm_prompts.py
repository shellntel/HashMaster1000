"""
LLM Prompt Templates for AD Description Analysis

Defines prompts for detecting sensitive information in Active Directory
user account descriptions using LLM semantic analysis.

Categories:
- passwords: Password disclosures and hints
- pii: Personally Identifiable Information (SSN, phone, DOB, email)
- credentials: Embedded credentials (API keys, tokens, PINs)
"""

# Common preamble for all description analysis prompts
DA_PREAMBLE = """You are a cybersecurity analyst specializing in Active Directory security audits.
You are analyzing user account descriptions for sensitive information that could pose security risks."""


# Category definitions with prompts
DA_CATEGORIES: dict[str, dict[str, str]] = {
    "passwords": {
        "name": "Password Disclosure",
        "description": "Passwords, credentials, or authentication hints stored in description fields",
        "look_for": """- Explicit passwords ("password is", "pwd:", "p/w:", "pass=", "password:")
- Temporary or initial password references ("temp password", "initial pwd", "default password")
- Password hints or reminders ("password hint:", "same as", "use X's password")
- Password recovery information
- Default or shared credentials mentioned
- References to password documents or storage locations""",
        "include_rules": """- Actual credential values in plaintext
- Temporary/initial password assignments
- Password hints that reveal the password pattern
- References indicating password sharing between accounts
- Default credentials that should have been changed""",
        "exclude_rules": """- Generic text mentioning "password" without an actual password (e.g., "Contact IT for password reset")
- Password policy reminders (e.g., "Must change password every 90 days")
- Application names that contain "password" (e.g., "Password Manager Admin")
- References to password systems without actual credentials""",
        "examples": """FINDING:
ACCOUNT: jsmith
CATEGORY: Password
VALUE: Welcome123! (masked: Wel********)
CONFIDENCE: 0.95
REASONING: Explicit temporary password disclosure in format "Temp password: Welcome123!"

FINDING:
ACCOUNT: newuser
CATEGORY: Password_Hint
VALUE: [same as domain admin]
CONFIDENCE: 0.85
REASONING: Password sharing disclosure - indicates reuse of privileged credentials

NOT A FINDING:
Description: "Contact helpdesk@company.com for password reset assistance"
Reasoning: This mentions password reset process, not an actual password""",
        "output_format": """ACCOUNT: [sAMAccountName]
CATEGORY: Password | Password_Hint | Default_Credential
VALUE: [the sensitive value - mask passwords after first 3 chars]
CONFIDENCE: [0.0-1.0]
REASONING: [brief explanation of why this is a finding]
---"""
    },

    "pii": {
        "name": "Personally Identifiable Information",
        "description": "PII such as SSNs, phone numbers, birth dates, or personal email addresses",
        "look_for": """- Social Security Numbers (full or partial: XXX-XX-XXXX format)
- Personal phone numbers (cell phones, home phones - not office extensions)
- Dates of birth (DOB, birthday, born on)
- Personal email addresses (not work email)
- Home addresses or personal location information
- Emergency contact details with personal information
- National ID numbers or driver's license numbers
- Financial account references""",
        "include_rules": """- Full or partial SSNs (even last 4 digits with context)
- Personal phone numbers clearly identified as personal/cell/home
- Dates explicitly identified as birth dates
- Non-work email addresses in personal context
- Home addresses or personal residential information""",
        "exclude_rules": """- Work phone numbers and office extensions
- Generic dates that aren't birth dates (hire dates, review dates)
- Corporate email addresses
- Office addresses and work locations
- Emergency contact names without personal details
- Employee ID numbers (unless they're SSNs)""",
        "examples": """FINDING:
ACCOUNT: mjohnson
CATEGORY: PII_SSN
VALUE: ***-**-6789
CONFIDENCE: 0.95
REASONING: Full SSN disclosed in format "SSN for benefits: 123-45-6789"

FINDING:
ACCOUNT: twilliams
CATEGORY: PII_DOB
VALUE: [date redacted]
CONFIDENCE: 0.90
REASONING: Date of birth explicitly stated as "DOB: 03/15/1985"

FINDING:
ACCOUNT: agarcia
CATEGORY: PII_Phone
VALUE: ***-***-4567
CONFIDENCE: 0.85
REASONING: Personal cell phone number in format "Cell: (555) 123-4567"

NOT A FINDING:
Description: "Started on 01/15/2020, reports to Jane Doe"
Reasoning: This is a hire date, not a date of birth""",
        "output_format": """ACCOUNT: [sAMAccountName]
CATEGORY: PII_SSN | PII_DOB | PII_Phone | PII_Email | PII_Address
VALUE: [masked value - show only last 4 digits for SSN/phone, redact dates]
CONFIDENCE: [0.0-1.0]
REASONING: [brief explanation]
---"""
    },

    "credentials": {
        "name": "Embedded Credentials",
        "description": "API keys, tokens, PINs, service account credentials, or authentication secrets",
        "look_for": """- API keys and secrets (patterns like sk_live_, AKIA, api_key=)
- Access tokens and bearer tokens
- PIN codes (voicemail, door access, security codes)
- Service account passwords or credentials
- Database connection strings with credentials
- Webhook URLs containing authentication tokens
- SSH keys or certificate references with sensitive data
- OAuth tokens or refresh tokens
- AWS/Azure/GCP credentials""",
        "include_rules": """- Any API key or secret with actual key value
- PIN codes for any system (voicemail, building access, etc.)
- Webhook or callback URLs containing tokens
- Connection strings with embedded passwords
- Service account credentials
- Cloud provider access keys""",
        "exclude_rules": """- Generic references to API documentation
- Instructions to "get API key from X" without the actual key
- PIN policy references without actual PINs
- Placeholder values (xxx, ****, [key here])
- Expired or revoked credential notices""",
        "examples": """FINDING:
ACCOUNT: svc_reporting
CATEGORY: API_Key
VALUE: sk_live_...xyz (first 8 and last 4 shown)
CONFIDENCE: 0.95
REASONING: Live Stripe API key disclosed in format "Stripe API: sk_live_abc123xyz789"

FINDING:
ACCOUNT: bsmith
CATEGORY: PIN
VALUE: ****
CONFIDENCE: 0.90
REASONING: Voicemail PIN disclosed in format "Voicemail PIN: 4829"

FINDING:
ACCOUNT: svc_slack
CATEGORY: Webhook_Token
VALUE: [webhook URL with token]
CONFIDENCE: 0.85
REASONING: Slack webhook URL containing authentication token

NOT A FINDING:
Description: "API access - contact DevOps team for credentials"
Reasoning: This is a process reference, not an actual credential""",
        "output_format": """ACCOUNT: [sAMAccountName]
CATEGORY: API_Key | Token | PIN | Service_Credential | Webhook_Token
VALUE: [masked - show first/last 4 chars for keys, fully mask PINs]
CONFIDENCE: [0.0-1.0]
REASONING: [brief explanation]
---"""
    }
}


def get_da_preamble() -> str:
    """Get the DA preamble, checking for custom override."""
    try:
        from .prompt_manager import get_prompt_manager
        manager = get_prompt_manager()
        preamble, is_custom = manager.get_prompt("preambles", "DA_PREAMBLE")
        return preamble
    except Exception:
        return DA_PREAMBLE


def get_da_prompt(category_key: str, accounts_data: str) -> str:
    """
    Generate the full prompt for a description analysis category.

    Args:
        category_key: Key from DA_CATEGORIES ("passwords", "pii", "credentials")
        accounts_data: Formatted string of accounts to analyze
                      Format: "[sAMAccountName]: Description text"

    Returns:
        Complete prompt string for LLM
    """
    if category_key not in DA_CATEGORIES:
        raise ValueError(f"Unknown category: {category_key}. Valid: {list(DA_CATEGORIES.keys())}")

    category = DA_CATEGORIES[category_key]

    # Use custom preamble if set
    preamble = get_da_preamble()

    prompt = f"""{preamble}

TASK: Analyze the following Active Directory account descriptions for {category["name"]}.

CATEGORY DESCRIPTION:
{category["description"]}

WHAT TO LOOK FOR:
{category["look_for"]}

WHAT TO INCLUDE:
{category["include_rules"]}

WHAT TO EXCLUDE:
{category["exclude_rules"]}

EXAMPLES:
{category["examples"]}

OUTPUT FORMAT:
For each finding, output in this exact format:
{category["output_format"]}

If no findings in this category, output exactly: NO_FINDINGS

ACCOUNTS TO ANALYZE:
{accounts_data}

FINDINGS:"""

    return prompt


def get_all_category_keys() -> list[str]:
    """Get all available category keys."""
    return list(DA_CATEGORIES.keys())


def get_category_info(category_key: str) -> dict[str, str]:
    """Get category name and description for display."""
    if category_key not in DA_CATEGORIES:
        raise ValueError(f"Unknown category: {category_key}")

    cat = DA_CATEGORIES[category_key]
    return {
        "key": category_key,
        "name": cat["name"],
        "description": cat["description"]
    }


def get_all_categories_info() -> list[dict[str, str]]:
    """Get info for all categories."""
    return [get_category_info(key) for key in DA_CATEGORIES.keys()]
