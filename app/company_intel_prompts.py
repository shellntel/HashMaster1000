"""
Company Intelligence (CI) Prompts

This module contains focused LLM prompts for extracting organizational intelligence
from password data. Each prompt targets ONE specific category.

The approach:
1. LLM extracts relevant information from passwords and account names
2. Python validates results against the data
3. Python formats the final report

Categories:
1. Company Identity - company name, abbreviations, brands, products
2. Industry Sector - what industry the organization operates in
3. Geographic Location - where the organization is located
"""

# Common preamble for all CI prompts
CI_PREAMBLE = """You are a cybersecurity analyst performing organizational reconnaissance from password audit data.
Your task is to identify information that reveals organizational identity, industry, or location.
Be thorough but precise - only include findings you are confident about."""


def get_ci_prompt(category_key: str, passwords: list[str], accounts: list[str]) -> str:
    """
    Generate the full CI prompt for a category with the password and account list.

    Args:
        category_key: The CI category identifier (e.g., 'company_identity', 'industry')
        passwords: List of unique passwords to analyze
        accounts: List of account names to analyze

    Returns:
        Complete prompt string ready for LLM
    """
    if category_key not in CI_CATEGORIES:
        raise ValueError(f"Unknown CI category: {category_key}")

    category = CI_CATEGORIES[category_key]
    password_list = "\n".join(passwords)  # Sampling handled by CIAnalyzer
    account_list = "\n".join(accounts)
    pw_count = len(passwords)
    acct_count = len(accounts)

    prompt = f"""{CI_PREAMBLE}

CATEGORY: {category['name']}
{category['description']}

DATASET CONTEXT:
You are analyzing {pw_count} unique passwords and {acct_count} account names from this organization.

WHAT TO LOOK FOR:
{category['look_for']}

CONFIDENCE LEVELS:
- HIGH: Multiple clear indicators, consistent pattern
- MEDIUM: Some indicators present, reasonable inference
- LOW: Single indicator or speculative

EXAMPLES OF GOOD FINDINGS:
{category['examples']}

OUTPUT RULES:
- Report your findings in the exact format shown below
- Include specific evidence (passwords/accounts) for each finding
- If no clear evidence exists, output exactly: NO_FINDINGS
- Do not add explanations beyond what's requested
- Assign appropriate confidence level{category.get('output_extra', '')}

PASSWORDS TO ANALYZE:
{password_list}

ACCOUNT NAMES TO ANALYZE:
{account_list}

{category['output_format']}"""

    return prompt


# CI Category Definitions
CI_CATEGORIES = {
    "company_identity": {
        "name": "Company Identity",
        "description": "Identify company name, abbreviations, brands, products, or internal project names that appear in passwords or account names.",
        "look_for": """- Company name or abbreviations (e.g., 'Acme', 'ACME2024', 'AcmeCorp')
- Product or brand names
- Internal project codenames (e.g., 'ProjectPhoenix', 'Falcon123')
- Division or department names
- Building or campus names
- Company-specific acronyms""",
        "examples": """Finding: Company name is likely 'IPC' (International Products Corp)
Evidence: Passwords containing `IPC2024`, `IPC@admin`, `Welcome2IPC`
Confidence: HIGH - Multiple passwords contain company abbreviation

Finding: Internal project name 'Phoenix'
Evidence: Passwords `ProjectPhoenix!`, `phoenix2024`, account 'phoenix-admin'
Confidence: MEDIUM - Appears in both passwords and accounts""",
        "output_format": """FINDINGS:

### Finding 1
**What:** [What you identified - company name, product, project, etc.]
**Evidence:** [List specific passwords/accounts that support this, one per line]
**Confidence:** [HIGH/MEDIUM/LOW] - [Brief justification]

### Finding 2
(continue for each finding, or output NO_FINDINGS if none)"""
    },

    "industry_sector": {
        "name": "Industry Sector",
        "description": "Identify what industry or sector this organization operates in based on domain-specific terminology in passwords and account names.",
        "look_for": """- Technology/IT terms (coding, devops, servers, cloud)
- Healthcare/Medical terms (patient, clinic, pharma, HIPAA)
- Finance/Banking terms (trading, accounts, compliance)
- Manufacturing terms (production, assembly, QC)
- Education terms (student, faculty, campus)
- Government terms (agency, federal, clearance)
- Retail/E-commerce terms (store, inventory, POS)
- Legal terms (attorney, case, litigation)
- Engineering terms (CAD, design, blueprint)""",
        "examples": """Finding: Organization is in Healthcare sector
Evidence: Passwords containing `HIPAA2024`, `Patient123`, `Clinic@dmin`
Account names: 'nurse-station', 'pharmacy-team', 'radiology-west'
Confidence: HIGH - Multiple healthcare-specific terms

Finding: Technology/Software company
Evidence: Passwords `DevOps2024!`, `K8sAdmin`, `AWSroot123`
Account names: 'jenkins-build', 'qa-automation'
Confidence: HIGH - Clear DevOps and development terminology""",
        "output_format": """FINDINGS:

### Finding 1
**Industry:** [Identified industry/sector]
**Evidence from Passwords:** [List specific passwords]
**Evidence from Accounts:** [List specific account names]
**Confidence:** [HIGH/MEDIUM/LOW] - [Brief justification]

### Finding 2
(continue for each finding, or output NO_FINDINGS if none)"""
    },

    "geographic_location": {
        "name": "Geographic Location",
        "description": "Identify where this organization is likely located based on location-related references in passwords and account names.",
        "look_for": """- City names (Chicago, London, Tokyo, Dallas)
- State/Province names (California, Texas, Ontario, Bavaria)
- Country names or codes (USA, Deutschland, UK, Brasil)
- Area codes or zip codes (212, 90210, 10001)
- Regional sports teams (Cowboys, Lakers, Yankees)
- Local landmarks or attractions (Fenway, BigBen, Hollywood)
- Regional slang or cultural references
- Time zone references (EST, PST, GMT)""",
        "examples": """Finding: Organization likely located in Texas
Evidence: Passwords `Cowboys2024!`, `Dallas#1`, `Houston99`
Account containing: 'austin-office', 'tx-datacenter'
Confidence: HIGH - Multiple Texas city references and Cowboys sports team

Finding: UK-based or has UK office
Evidence: Passwords `London2024`, `BigBen123`
Account: 'uk-sales-team'
Confidence: MEDIUM - Some UK references present""",
        "output_format": """FINDINGS:

### Finding 1
**Location:** [Identified location - city, state, region, country]
**Evidence from Passwords:** [List specific passwords]
**Evidence from Accounts:** [List specific account names]
**Confidence:** [HIGH/MEDIUM/LOW] - [Brief justification]

### Finding 2
(continue for each finding, or output NO_FINDINGS if none)"""
    }
}


# Category display order
CI_CATEGORY_ORDER = [
    "company_identity",
    "industry_sector",
    "geographic_location"
]


def get_category_display_name(category_key: str) -> str:
    """Get the display name for a category."""
    if category_key in CI_CATEGORIES:
        return CI_CATEGORIES[category_key]["name"]
    return category_key


def get_all_category_keys() -> list[str]:
    """Get all category keys in display order."""
    return CI_CATEGORY_ORDER.copy()
