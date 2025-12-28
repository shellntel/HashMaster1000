# Hash Master 1000 - Feature Roadmap

> **Internal Document** - Not for public distribution
>
> This document outlines planned features for HM1K, including both the public version and the private SynerComm fork.

---

## Table of Contents

1. [SynerComm Private Fork Features](#synercomm-private-fork-features)
2. [New Reports & Analysis](#new-reports--analysis)
3. [AI-Powered Analysis (Ollama Integration)](#ai-powered-analysis-ollama-integration)
4. [Export & Reporting Enhancements](#export--reporting-enhancements)
5. [Infrastructure & UX Improvements](#infrastructure--ux-improvements)
6. [Implementation Priority Matrix](#implementation-priority-matrix)

---

## SynerComm Private Fork Features

These features are intended for the private SynerComm pentesting team fork only.

### Master Potfile Integration

**Description:** Allow `.env` file to contain the path to Hashcat's master potfile. If a master potfile exists, it could be used in place of or in addition to the user-supplied potfile.

**Use Cases:**
- Leverage historical cracking results across engagements
- Automatically crack more hashes without re-running Hashcat
- Share cracking knowledge across team members

**Implementation Notes:**
```
# .env configuration
HASHCAT_MASTER_POTFILE=/path/to/hashcat.potfile
POTFILE_MODE=merge|replace|user_only
```

**Considerations:**
- Merge strategy: master + user potfile, deduplicate
- Privacy: ensure client data isn't cross-contaminated
- Performance: master potfiles can be very large

---

### Multi-User Support

**Description:** Allow multiple concurrent users to use HM1K simultaneously.

**Requirements:**
- Session isolation between users
- User authentication (optional, could be IP-based for internal use)
- Concurrent file uploads without collision
- Separate analysis state per session

**Implementation Options:**
1. **Session-based:** Use Flask sessions with unique session IDs
2. **User accounts:** Simple username/password with SQLite backend
3. **Token-based:** Generate unique analysis tokens per upload

**Data Model:**
```
sessions/
  ├── {session_id}/
  │   ├── pwdump.txt
  │   ├── potfile.txt
  │   ├── config.json
  │   └── results_cache.json
```

---

### Session Save & Recall

**Description:** Allow analysis sessions to be saved and recalled later.

**Features:**
- Save current session state (files, config, results)
- Name/tag sessions for easy recall
- List previous sessions with metadata
- Delete old sessions
- Export session as portable archive

**Session Metadata:**
```json
{
  "session_id": "uuid",
  "name": "ClientX Q4 2024 Assessment",
  "created": "2024-12-15T10:30:00Z",
  "last_accessed": "2024-12-15T14:22:00Z",
  "files": {
    "pwdump": "clientx_dcsync.txt",
    "potfile": "clientx_cracked.pot"
  },
  "config": { ... },
  "stats": {
    "total_accounts": 5432,
    "cracked_percent": 67.2
  }
}
```

---

## New Reports & Analysis

### Password History Analysis (PLANNED)

**Status:** Planned for implementation

**Description:** Analyze password history of users when available in pwdump data to identify rotation patterns and password evolution. Detect predictable password change patterns that weaken security.

**Data Sources:**
1. **PWDump/DCSSync Format** - History entries identified by `_history0`, `_history1`, `_history2` suffixes on account names
   ```
   jsmith:1001:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0:::
   jsmith_history0:1001:AAD3B435B51404EEAAD3B435B51404EE:A87F3A337D73085C45F9416BE5787D86:::
   jsmith_history1:1001:AAD3B435B51404EEAAD3B435B51404EE:E52CAC67419A9A224A3B108F3FA6CB6D:::
   ```

2. **ADD JSON Format** - `HistoricalNTHashes` array field
   ```json
   {
     "SamAccountName": "jsmith",
     "NTHash": "31D6CFE0D16AE931B73C59D7E0C089C0",
     "HistoricalNTHashes": [
       "A87F3A337D73085C45F9416BE5787D86",
       "E52CAC67419A9A224A3B108F3FA6CB6D"
     ]
   }
   ```

**Detection Capabilities:**
- Incremental changes: `Password1` → `Password2` → `Password3`
- Season rotation: `Summer2023` → `Fall2023` → `Winter2024`
- Minimal changes: `Welcome1!` → `Welcome1@` → `Welcome1#`
- Base word persistence: same root word across multiple changes
- Reversion: returning to a previously used password
- Year increment patterns: `Company2023` → `Company2024`

**Implementation Approach:**
1. Parse history entries from both pwdump and ADD JSON formats
2. Match history hashes against potfile to get plaintext
3. Compare consecutive passwords using string similarity algorithms
4. Categorize patterns (increment, season, special char rotation, etc.)
5. Generate predictability scores for each user

**Report Output:**
```
Password Rotation Analysis
==========================
Accounts with password history available: 1,234
Accounts with predictable rotation patterns: 234 (18.5%)

Top Rotation Patterns:
1. Incrementing number suffix (89 accounts)
   Example: jsmith - Password1, Password2, Password3, Password4

2. Season/Year rotation (45 accounts)
   Example: bthompson - Spring2022, Summer2022, Fall2022, Winter2023

3. Special character rotation (34 accounts)
   Example: mwilliams - Welcome1!, Welcome1@, Welcome1#

4. Minimal character changes (28 accounts)
   Example: djones - Sunshine1, Sunsh1ne1, Sunsh!ne1

5. Year increment only (38 accounts)
   Example: rjohnson - Company2021, Company2022, Company2023, Company2024
```

**Files to Create:**
- `password_history.py` - History parsing and pattern detection module

---

### Active Directory Domain Filtering (IMPLEMENTED)

**Status:** Implemented (December 2024)

**Description:** Dynamically filter and display results by Active Directory domain when multi-domain data is present. Enable domain-specific analysis and cross-domain password reuse detection.

**Data Sources:**
1. **PWDump Format** - Domain prefix before backslash
   ```
   CORP\jsmith:1001:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0:::
   DEV\jsmith:1002:AAD3B435B51404EEAAD3B435B51404EE:A87F3A337D73085C45F9416BE5787D86:::
   ```

2. **DCSync Format** - Domain from Distinguished Name or SAM domain
   ```
   [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
   CORP\Administrator:500:aad3b435b51404eeaad3b435b51404ee:...
   ```

3. **ADD JSON Format** - Extract from `DistinguishedName` field
   ```json
   {
     "SamAccountName": "jsmith",
     "DistinguishedName": "CN=John Smith,OU=Users,DC=corp,DC=example,DC=com"
   }
   ```
   Domain extracted: `corp.example.com`

**UI Components:**
- Domain dropdown selector in Settings modal
- Options: "All Domains", "CORP", "DEV", "(No Domain)", etc.
- Persistent filter across all report sections
- Real-time recalculation of all statistics, charts, and HIBP results

**Implementation:**
- `domain_utils.py` - Domain extraction and filtering module
- Domain info saved to `domain_info.json` in session
- Settings modal allows changing domain filter with report regeneration
- Cross-domain password reuse detection available via `detect_cross_domain_password_reuse()`

**Files:**
- `domain_utils.py` - Domain extraction, filtering, and cross-domain analysis
- `hm1k.py` - Integration in processing and regeneration endpoints
- `templates/report.html` - Domain filter UI in Settings modal

---

### Privileged Account Analysis

**Description:** Special reporting for privileged/sensitive accounts with security issues.

**Account Classification:**
- Domain Admins
- Enterprise Admins
- Schema Admins
- Account Operators
- Backup Operators
- Server Operators
- Service accounts (pattern matching: svc_*, *_svc, service*)
- Admin accounts (pattern matching: admin*, *admin, *_adm)

**Critical Findings Report:**
```
CRITICAL: Privileged Accounts at Risk
=====================================

Blank Passwords (CRITICAL):
- CORP\Administrator (Domain Admin) - BLANK PASSWORD
- CORP\svc_backup (Backup Operators) - BLANK PASSWORD

Weak Passwords (HIGH):
- CORP\admin.jsmith (Domain Admin) - "Password1"
- CORP\svc_sql (Service Account) - "Summer2024"

Reused Passwords (HIGH):
- CORP\enterprise_admin uses same password as 47 other accounts
- DEV\svc_deploy shares password with CORP\svc_deploy

Password Age Concerns (MEDIUM):
- CORP\krbtgt - password unchanged in 847 days
- CORP\Administrator - password unchanged in 423 days
```

**Integration:**
- Requires group membership data (from AD enumeration)
- Could accept supplemental file with privileged account list
- Pattern-based detection as fallback

---

### Kerberoast Exposure Analysis (IMPLEMENTED)

**Status:** Implemented (December 2024)

**Description:** Identify and assess risk for accounts vulnerable to Kerberoasting attacks. Service accounts with Service Principal Names (SPNs) can have their Kerberos tickets requested and cracked offline, making them high-value targets.

**Required ADD JSON Fields:**
- `ServicePrincipalNames` - Array of SPNs (identifies Kerberoastable accounts)
- `RawUACValue` - Integer bitmask for UserAccountControl flags
- `adminCount` - String "0" or "1" (indicates protected/privileged accounts)
- `supportedEncryptionTypes` - String bitmask for Kerberos encryption types
- `allowedToDelegateTo` - Array of delegation targets
- `PwdLastSet` - Password age timestamp
- `LastLogon` - Last activity timestamp

**Risk Factor Scoring:**

| Risk Factor | Score | Description |
|-------------|-------|-------------|
| `SPN_PRESENT` | 10 | Account has SPNs (Kerberoastable) |
| `ASREP_PREAUTH_DISABLED` | 25 | Pre-auth disabled (AS-REP roastable) |
| `PRIVILEGED_ADMINCOUNT` | 30 | High-value target (adminCount=1) |
| `PASSWORD_NEVER_EXPIRES` | 15 | Long-term exposure window |
| `PASSWORD_AGE_3Y_PLUS` | 20 | Stale password (3+ years old) |
| `PASSWORD_AGE_1Y_PLUS` | 10 | Aging password (1+ years old) |
| `DELEGATION_ENABLED` | 25 | Unconstrained delegation configured |
| `CONSTRAINED_DELEGATION_SET` | 15 | Constrained delegation with targets |
| `WEAK_ENCRYPTION_RC4` | 10 | Uses vulnerable RC4 encryption |
| `WEAK_ENCRYPTION_DES` | 15 | Uses deprecated DES encryption |
| `CRACKED_PASSWORD` | 40 | Password was cracked in this assessment |
| `HIBP_EXPOSED` | 35 | Password found in HIBP breaches |
| `REUSED_PASSWORD_CLUSTER` | 20 | Password shared with other accounts |
| `ACCOUNT_DISABLED` | -50 | Reduces risk (disabled account) |

**Risk Categories:**
- **Critical** (70+ points): Immediate action required
- **High** (50-69 points): Priority remediation
- **Medium** (30-49 points): Scheduled remediation
- **Low** (10-29 points): Monitor and address

**Report Output (`kerberoast_report.json`):**
```json
{
  "summary": {
    "total_accounts_analyzed": 1000,
    "total_service_accounts": 12,
    "total_kerberoastable": 11,
    "total_asrep_roastable": 3,
    "critical_count": 2,
    "high_count": 4,
    "medium_count": 3,
    "low_count": 2,
    "privileged_with_spn": 3,
    "cracked_with_spn": 5,
    "weak_encryption_count": 6
  },
  "assessments": [
    {
      "sam_account_name": "svc_backup",
      "risk_score": 125,
      "risk_category": "Critical",
      "risk_reasons": ["SPN_PRESENT", "PRIVILEGED_ADMINCOUNT", "PASSWORD_NEVER_EXPIRES", "PASSWORD_AGE_3Y_PLUS", "WEAK_ENCRYPTION_RC4", "CRACKED_PASSWORD"],
      "spns": ["HOST/backup.democorp.local"],
      "is_privileged": true,
      "password_cracked": true,
      "supports_rc4": true,
      "supports_aes": false
    }
  ],
  "chart_data": {
    "risk_distribution": { ... },
    "risk_factors": { ... },
    "encryption_types": { ... }
  }
}
```

**API Endpoint:**
- `GET /kerberoast_report.json` - Returns full Kerberoast analysis report

**Files:**
- `service_account.py` - Service account identification and parsing
- `kerberoast_analysis.py` - Risk scoring and report generation
- Integration in `hm1k.py` - Automatic analysis during ADD JSON processing

**Use Cases:**
- Identify high-value Kerberoasting targets for remediation
- Prioritize service account password rotations
- Detect dangerous delegation configurations
- Track service account encryption type upgrades (RC4 → AES)

---

### AS-REP Exposure Analysis (IMPLEMENTED)

**Status:** Implemented (December 2024)

**Description:** Identify and assess risk for accounts vulnerable to AS-REP roasting attacks. Accounts with Kerberos pre-authentication disabled can have their AS-REP responses captured and cracked offline without any authentication.

**Required ADD JSON Fields:**
- `RawUACValue` - Integer bitmask containing DONT_REQ_PREAUTH (0x400000) flag
- `adminCount` - String "0" or "1" (indicates protected/privileged accounts)
- `DistinguishedName` - For OU-based analysis
- `PwdLastSet` - Password age timestamp
- `LastLogon` - Last activity timestamp
- `ServicePrincipalNames` - Array (for dual Kerberoast/AS-REP vulnerability detection)

**Risk Factor Scoring:**

| Risk Factor | Score | Description |
|-------------|-------|-------------|
| `ASREP_PREAUTH_DISABLED` | 25 | Pre-authentication disabled (core vulnerability) |
| `PRIVILEGED_ADMINCOUNT` | 30 | High-value target (adminCount=1) |
| `PASSWORD_NEVER_EXPIRES` | 15 | Long-term exposure window |
| `PASSWORD_AGE_3Y_PLUS` | 20 | Stale password (3+ years old) |
| `PASSWORD_AGE_1Y_PLUS` | 10 | Aging password (1+ years old) |
| `ALSO_KERBEROASTABLE` | 15 | Dual vulnerability (has SPNs too) |
| `WEAK_ENCRYPTION_RC4` | 10 | Uses vulnerable RC4 encryption |
| `CRACKED_PASSWORD` | 40 | Password was cracked in this assessment |
| `HIBP_EXPOSED` | 35 | Password found in HIBP breaches |
| `REUSED_PASSWORD_CLUSTER` | 20 | Password shared with other accounts |
| `ACCOUNT_DISABLED` | -50 | Reduces risk (disabled account) |

**Risk Categories:**
- **Critical** (70+ points): Immediate action required
- **High** (50-69 points): Priority remediation
- **Medium** (30-49 points): Scheduled remediation
- **Low** (10-29 points): Monitor and address

**Report Output (`asrep_report.json`):**
```json
{
  "summary": {
    "total_accounts_analyzed": 1000,
    "total_asrep_roastable": 5,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 1,
    "low_count": 1,
    "privileged_asrep": 1,
    "cracked_asrep": 3,
    "also_kerberoastable": 2
  },
  "assessments": [
    {
      "sam_account_name": "legacy_app",
      "risk_score": 85,
      "risk_category": "Critical",
      "risk_reasons": ["ASREP_PREAUTH_DISABLED", "PRIVILEGED_ADMINCOUNT", "PASSWORD_AGE_3Y_PLUS", "CRACKED_PASSWORD"],
      "is_privileged": true,
      "password_cracked": true,
      "also_kerberoastable": false
    }
  ],
  "chart_data": {
    "risk_distribution": { ... },
    "risk_factors": { ... }
  }
}
```

**API Endpoint:**
- `GET /asrep_report.json` - Returns full AS-REP analysis report

**Files:**
- `asrep_analysis.py` - Risk scoring and report generation
- `service_account.py` - UAC flag parsing (shared with Kerberoast analysis)
- Integration in `hm1k.py` - Automatic analysis during ADD JSON processing

**Use Cases:**
- Identify accounts at risk of AS-REP roasting attacks
- Prioritize remediation based on account privilege and password age
- Detect accounts with dual Kerberoast + AS-REP vulnerability
- Track progress in enabling pre-authentication across the domain

---

### Historical Trend Analysis (IMPLEMENTED)

**Status:** Implemented (December 2024)

**Description:** Compare password security metrics across multiple assessment sessions for the same company. Track improvements or regressions in password hygiene over time with visual charts and percentage change calculations.

**Session Metadata:**
- `company_name` - Groups sessions by organization
- `project_description` - Describes each assessment (e.g., "Q4 2024 Annual Pentest")
- Sessions can be compared when they share the same company name

**Metrics Tracked:**

| Metric | Description | Direction |
|--------|-------------|-----------|
| Crack Rate | Percentage of passwords cracked | Lower is better |
| Password Reuse Rate | Percentage of accounts sharing passwords | Lower is better |
| Blank Passwords | Count of accounts with empty passwords | Lower is better |
| Complexity Violations | Count of passwords failing complexity rules | Lower is better |
| Min Length Violations | Count of passwords below minimum length | Lower is better |
| Total Bad Practices | Sum of all password anti-patterns | Lower is better |
| LM Hash Count | Count of legacy LM hashes present | Lower is better |
| Total Accounts | Number of accounts analyzed | Context metric |
| HIBP Exposed Accounts | Count of passwords found in breaches | Lower is better |

**Trend Visualization:**
- Line charts showing metric progression over sessions
- Color-coded percentage changes (green = improvement, red = regression)
- Session comparison table with delta calculations
- Automatic Y-axis scaling based on data range

**API Endpoint:**
- `POST /api/sessions/trend-analysis` - Compare selected sessions

**Files:**
- `trend_analysis.py` - Metric extraction and comparison logic
- Report section in `templates/report.html` - Trend visualization UI

**Use Cases:**
- Demonstrate security improvements to stakeholders
- Track effectiveness of password policy changes
- Identify areas needing additional focus
- Generate quarter-over-quarter or year-over-year comparisons

---

### Base Word + Suffix Analysis

**Description:** Identify the root words users choose and how they modify them to meet complexity requirements.

**Analysis Components:**
1. Extract base words by stripping common suffixes
2. Group passwords by base word
3. Show suffix distribution per base word
4. Calculate "base word risk" - how predictable are the variations

**Example Output:**
```
Base Word Analysis
==================

"summer" - Used by 127 accounts (2.3%)
  └── Suffixes: 2024 (34), 2023 (28), 123 (18), ! (15), 1! (12), @2024 (8), ...
  └── Predictability Score: HIGH (92% use year or simple number)

"welcome" - Used by 89 accounts (1.6%)
  └── Suffixes: 1 (23), 123 (19), ! (14), 1! (11), 2024 (9), ...
  └── Predictability Score: HIGH (87% use single digit or simple pattern)

"password" - Used by 67 accounts (1.2%)
  └── Suffixes: 1 (18), 123 (15), ! (12), 1! (8), @123 (6), ...
  └── Predictability Score: CRITICAL (100% trivially guessable)
```

---

### Password Structure Template Analysis

**Description:** Categorize passwords by their character class structure to reveal predictable patterns.

**Template Notation:**
- `U` = Uppercase letter
- `l` = Lowercase letter
- `d` = Digit
- `s` = Special character

**Example Output:**
```
Password Structure Analysis
===========================

Top 20 Password Templates (covers 78% of cracked passwords):

1. Ullllllldd    (Word + 2 digits)           - 456 passwords (8.4%)
   Examples: Summer24, Welcome19, Sunshine21

2. Ullllllldds   (Word + 2 digits + special) - 389 passwords (7.2%)
   Examples: Password12!, Summer2024@, Welcome23#

3. Ullllldddd    (Word + 4 digits/year)      - 334 passwords (6.2%)
   Examples: Summer2024, Winter2023, Spring2022

4. lllllllldd    (lowercase + 2 digits)      - 298 passwords (5.5%)
   Examples: sunshine23, football99, baseball21

5. Ulllllllddds  (Word + 3 digits + special) - 267 passwords (4.9%)
   Examples: Welcome123!, Summer123@, Monkey123#

...

Attack Recommendations:
- Mask attack: ?u?l?l?l?l?l?l?d?d would crack 14% of remaining hashes
- Mask attack: ?u?l?l?l?l?l?d?d?d?d would crack 8% of remaining hashes
```

---

### Character Position Heatmap

**Description:** Visualize which character types appear at each position in passwords.

**Visualization:**
```
Position:  1    2    3    4    5    6    7    8    9    10   11   12
           ─────────────────────────────────────────────────────────
Upper:     94%  3%   2%   1%   1%   1%   1%   1%   1%   2%   3%   5%
Lower:     4%   95%  96%  95%  94%  92%  88%  72%  45%  28%  15%  8%
Digit:     1%   1%   1%   2%   3%   5%   9%   24%  48%  62%  70%  72%
Special:   1%   1%   1%   2%   2%   2%   2%   3%   6%   8%   12%  15%
```

**Key Insights:**
- Position 1 is almost always uppercase (94%)
- Digits cluster at the end (positions 9-12)
- Special characters mainly at the very end
- Middle positions are predictably lowercase

---

### Username-Password Correlation

**Description:** Detect passwords that contain user-identifiable information.

**Detection Categories:**
1. **Username in password:** jsmith → "jsmith123"
2. **First name:** John Smith → "John2024!"
3. **Last name:** John Smith → "Smith123"
4. **Initials:** John Smith → "JS2024"
5. **Email prefix:** jsmith@corp.com → "jsmith!"
6. **Reversed:** jsmith → "htimSJ"
7. **Department/Title:** (if available from AD data)

**Example Output:**
```
Username-Password Correlation
=============================

Passwords containing username: 89 accounts (1.6%)
  - jsmith: jsmith2024!
  - bthompson: BThompson1
  - mwilliams: mwilliams@123

Passwords containing first name: 234 accounts (4.3%)
  - John Smith: John2024!
  - Mary Johnson: Mary@123
  - Robert Davis: Robert1!

Passwords containing last name: 178 accounts (3.3%)
  - John Smith: Smith2024
  - Mary Johnson: Johnson123!

Total accounts with identifiable info: 412 (7.6%)
```

---

### Shared Password Families

**Description:** Group passwords that are variations of each other to show how one compromise reveals many.

**Grouping Logic:**
- Case variations: `Summer2024` = `summer2024` = `SUMMER2024`
- Suffix variations: `Summer2024` ≈ `Summer2024!` ≈ `Summer2024@`
- Leet variations: `Summer2024` ≈ `Summ3r2024` ≈ `$ummer2024`
- Minor changes: `Summer2024` ≈ `Summer2025` ≈ `Summer2023`

**Example Output:**
```
Password Families (variations that share a common base)
=======================================================

Family: "Summer2024" - 47 accounts at risk
  ├── Summer2024 (23 accounts)
  ├── summer2024 (8 accounts)
  ├── Summer2024! (7 accounts)
  ├── SUMMER2024 (4 accounts)
  ├── Summ3r2024 (3 accounts)
  └── Summer2024@ (2 accounts)

  Risk: Cracking ANY of these reveals the pattern for ALL

Family: "Welcome1" - 34 accounts at risk
  ├── Welcome1 (12 accounts)
  ├── Welcome1! (9 accounts)
  ├── welcome1 (6 accounts)
  ├── Welcome1@ (4 accounts)
  └── W3lcome1 (3 accounts)
```

---

## AI-Powered Analysis (Ollama Integration)

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        HM1K Flask App                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  Standard   │  │   Ollama    │  │    Analysis Results     │ │
│  │  Analysis   │──│   Client    │──│    + AI Insights        │ │
│  │  Engine     │  │   Module    │  │                         │ │
│  └─────────────┘  └──────┬──────┘  └─────────────────────────┘ │
└──────────────────────────┼──────────────────────────────────────┘
                           │ REST API
                           ▼
              ┌─────────────────────────┐
              │     Ollama Server       │
              │  (localhost:11434)      │
              ├─────────────────────────┤
              │  Models:                │
              │  - llama3.2 (default)   │
              │  - mistral             │
              │  - codellama           │
              └─────────────────────────┘
```

### Configuration

```
# .env configuration
OLLAMA_ENABLED=true
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT=120
```

### AI-Powered Features

#### Executive Summary Generation

**Description:** Generate a natural language executive summary suitable for management reports.

**Prompt Engineering:**
```
You are a cybersecurity analyst writing an executive summary of a password audit.

Data provided:
- Total accounts: {total}
- Cracked: {cracked} ({percent}%)
- Top patterns found: {patterns}
- Critical findings: {critical}

Write a 3-paragraph executive summary that:
1. States the overall risk level and key statistics
2. Highlights the most concerning findings
3. Provides high-level recommendations

Use professional language suitable for C-level executives.
Avoid technical jargon. Focus on business risk.
```

**Example Output:**
```
EXECUTIVE SUMMARY

This password security assessment analyzed 5,432 Active Directory accounts
and successfully recovered 67.2% of password hashes, indicating significant
organizational risk. The high crack rate suggests that current password
policies are insufficient to protect against modern attack techniques.

Several critical findings require immediate attention. Three privileged
accounts, including a Domain Administrator, were found using blank or
trivially guessable passwords. Additionally, 18% of users employ predictable
password rotation patterns, and 23% of passwords contain easily guessable
elements such as seasons, years, or company-related terms.

We recommend immediate password resets for all privileged accounts,
implementation of a 14+ character minimum password length policy, and
deployment of a password filter to block common patterns. Employee security
awareness training should emphasize the risks of predictable password choices.
```

#### Semantic Password Clustering

**Description:** Use AI to categorize passwords by meaning and theme.

**Categories:**
- Sports-related (teams, players, sports terms)
- Family-related (names, relationships, pets)
- Pop culture (movies, TV, music, celebrities)
- Profanity/inappropriate
- Religious references
- Geographic (cities, states, countries)
- Temporal (dates, seasons, years)
- Company-related
- Random/unclassifiable

**Example Output:**
```
Semantic Password Analysis (AI-Powered)
=======================================

Category Distribution:
- Temporal (seasons, years, dates): 34%
- Personal (names, family, pets): 22%
- Sports-related: 12%
- Pop culture references: 8%
- Company/work-related: 7%
- Geographic: 5%
- Profanity: 4%
- Religious: 3%
- Unclassifiable: 5%

Insights:
- High temporal usage suggests users update passwords to meet rotation
  requirements with minimal effort
- Personal information in passwords indicates users prioritize memorability
  over security
- Company-related passwords (7%) represent targeted attack risk
```

#### Natural Language Pattern Description

**Description:** Convert detected patterns into human-readable explanations.

**Example:**
```
Pattern: Ulllllldddd with high "Summer/Winter/Spring/Fall" + "2023/2024" frequency

AI Explanation:
"Users strongly prefer seasonal words followed by the current or recent year.
This pattern is extremely predictable - an attacker knowing the current date
could generate a small wordlist (4 seasons × 5 years × common capitalizations)
that would crack approximately 23% of passwords in this dataset."
```

#### Attack Strategy Recommendations

**Description:** Generate custom Hashcat attack recommendations based on observed patterns.

**Example Output:**
```
Recommended Attack Strategy for Remaining Hashes
================================================

Based on the patterns observed in cracked passwords, we recommend:

1. PRIORITY: Season + Year Mask Attack
   hashcat -a 3 -m 1000 hashes.txt ?u?l?l?l?l?l?d?d?d?d
   Expected yield: ~15% of remaining hashes
   Time estimate: 2-4 hours

2. Custom Wordlist + Rules
   Base words identified: summer, winter, welcome, password, company-name
   Recommended rules: best64.rule, d3ad0ne.rule
   hashcat -a 0 -m 1000 hashes.txt custom_words.txt -r best64.rule
   Expected yield: ~10% of remaining hashes

3. Username Mangling
   Many passwords contain username variations
   hashcat -a 0 -m 1000 hashes.txt usernames.txt -r username_rules.rule
   Expected yield: ~5% of remaining hashes

Generated Files:
- custom_words.txt (based on observed base words)
- username_rules.rule (based on observed patterns)
- recommended_masks.hcmask
```

---

## Export & Reporting Enhancements

### Standalone HTML Report

**Description:** Generate a single-file HTML report that provides an interactive experience similar to using HM1K, but without requiring access to the application.

**Features:**
- All charts rendered as interactive Chart.js visualizations
- All data embedded as JSON in the HTML file
- Clickable charts with modals (same as live app)
- Filterable tables with search
- Print-optimized CSS
- Dark/light mode toggle
- No external dependencies (all CSS/JS inlined)

**File Structure:**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Password Audit Report - ClientX - 2024-12-15</title>
  <style>
    /* Inlined CSS - all styles */
  </style>
</head>
<body>
  <!-- Report Content -->
  <div id="report">
    <!-- Executive Summary -->
    <!-- Statistics -->
    <!-- Charts (Chart.js canvas elements) -->
    <!-- Tables -->
    <!-- Detailed Findings -->
  </div>

  <!-- Embedded Data -->
  <script>
    const reportData = {
      // All analysis results as JSON
    };
  </script>

  <!-- Inlined JavaScript -->
  <script>
    // Chart.js library (minified)
    // Report rendering logic
    // Interactivity handlers
  </script>
</body>
</html>
```

**Export Options:**
- Full interactive report (larger file, full functionality)
- Print-optimized report (smaller, static charts as images)
- Executive summary only
- Technical details only

---

### Automated Report Narrative

**Description:** Generate a complete written report narrative that summarizes all findings, suitable for inclusion in penetration test reports.

**Sections:**
1. **Overview** - Scope, methodology, summary statistics
2. **Key Findings** - Prioritized list of security issues
3. **Detailed Analysis** - Each report section with narrative
4. **Risk Assessment** - Overall risk rating with justification
5. **Recommendations** - Prioritized remediation steps
6. **Technical Appendix** - Raw data, methodology details

**Example Narrative:**
```markdown
## Password Security Assessment

### Overview

This assessment analyzed 5,432 Active Directory accounts from the CORP.EXAMPLE.COM
domain. Password hashes were extracted via DCSync and subjected to offline cracking
using industry-standard techniques including dictionary attacks, rule-based
mutations, and mask attacks.

### Key Findings

| Finding | Severity | Affected Accounts |
|---------|----------|-------------------|
| Privileged accounts with weak passwords | Critical | 3 |
| Blank passwords on enabled accounts | Critical | 12 |
| Passwords matching common patterns | High | 2,847 (52%) |
| Password reuse across accounts | High | 1,234 (23%) |
| Passwords containing company name | Medium | 389 (7%) |

### Detailed Analysis

#### Cracking Results

Of the 5,432 accounts analyzed, 3,652 (67.2%) had their passwords successfully
recovered. This crack rate significantly exceeds industry benchmarks and indicates
that current password policies provide insufficient protection against determined
attackers.

The average password length was 9.3 characters, with 34% of passwords meeting
only the minimum 8-character requirement. Only 12% of passwords exceeded 12
characters.

#### Pattern Analysis

The most common password patterns observed were:

1. **Season + Year** (23% of cracked passwords)
   Examples: Summer2024, Winter2023, Fall2024!

   This pattern is extremely predictable and can be attacked with a small,
   targeted wordlist. Users likely adopt this pattern to satisfy complexity
   requirements while maintaining memorability.

2. **Common Base Word + Numbers** (18% of cracked passwords)
   Examples: Welcome123, Password1!, Sunshine2024

   These passwords use dictionary words as a base with minimal modifications,
   making them vulnerable to rule-based attacks.

[continues...]
```

---

## Infrastructure & UX Improvements

### Performance Optimizations

- **Lazy loading:** Load chart data on-demand as user scrolls
- **Web workers:** Move heavy analysis to background threads
- **Caching:** Cache analysis results, invalidate on config change
- **Streaming:** Stream large file uploads with progress indication
- **Pagination:** Paginate large tables (password reuse, etc.)

### Enhanced File Handling

- **Drag and drop:** Drop files anywhere on the page
- **Multiple file formats:** Support various pwdump/potfile formats
- **Auto-detection:** Automatically detect file format and type
- **Validation feedback:** Real-time validation as files are uploaded
- **Large file support:** Handle 100k+ account datasets efficiently

### Accessibility & UX

- **Keyboard navigation:** Full keyboard support for all features
- **Screen reader support:** ARIA labels, semantic HTML
- **Color blind modes:** Alternative color schemes for charts
- **Responsive design:** Mobile-friendly layout
- **Print styles:** Optimized printing for all reports

---

## Completed Features

| Feature | Completed | Notes |
|---------|-----------|-------|
| AD Domain Filtering | Dec 2024 | Filter reports by domain, cross-domain reuse detection |
| Historical Trend Analysis | Dec 2024 | Compare password security metrics across sessions by company |
| AS-REP Exposure Analysis | Dec 2024 | Risk assessment for accounts with pre-auth disabled |
| Kerberoast Exposure Analysis | Dec 2024 | Risk scoring for service accounts with SPNs |
| HIBP Integration | Dec 2024 | Local database + API support |
| Multi-User Support | Dec 2024 | Session-based with authentication |
| Session Save/Recall | Dec 2024 | Persistent sessions with metadata |
| Master Potfile Integration | Dec 2024 | Cumulative hash cracking |
| Ollama AI Integration | Dec 2024 | Multi-server, multi-model support |

---

## Implementation Priority Matrix

### Phase 1: Quick Wins (1-2 weeks each)

| Feature | Effort | Value | Notes |
|---------|--------|-------|-------|
| Base Word + Suffix Analysis | Medium | High | Builds on existing substring analysis |
| Password Structure Templates | Medium | High | Straightforward pattern matching |
| Username-Password Correlation | Low | High | Simple string matching |
| Privileged Account Analysis | Medium | High | Critical for pentest reports |

### Phase 2: Core Enhancements (2-4 weeks each)

| Feature | Effort | Value | Notes |
|---------|--------|-------|-------|
| Multi-User Support | High | High | Required for team use |
| Session Save/Recall | Medium | High | Major UX improvement |
| Domain Filtering | Medium | High | Essential for large environments |
| Standalone HTML Export | High | High | Major differentiator |

### Phase 3: Advanced Features (4-8 weeks each)

| Feature | Effort | Value | Notes |
|---------|--------|-------|-------|
| Password History Analysis | High | High | Requires special data format |
| Ollama Integration | High | High | Significant differentiator |
| Automated Report Narrative | Medium | High | Depends on Ollama |
| Master Potfile Integration | Medium | Medium | SynerComm-specific |

### Phase 4: Polish & Scale (Ongoing)

| Feature | Effort | Value | Notes |
|---------|--------|-------|-------|
| Character Position Heatmap | Medium | Medium | Nice visualization |
| Shared Password Families | Medium | Medium | Complex grouping logic |
| Performance Optimizations | High | Medium | Important at scale |
| ~~Historical Trend Analysis~~ | ~~High~~ | ~~Medium~~ | ✅ Completed Dec 2024 |

---

## Technical Considerations

### Database Requirements

For multi-user and session persistence, consider:

- **SQLite:** Simple, file-based, good for single-server deployment
- **PostgreSQL:** Better for concurrent access, more features
- **Redis:** For session caching and temporary data

### Security Considerations

- Passwords in memory: minimize retention, secure cleanup
- File storage: encrypted at rest for sensitive data
- Session isolation: prevent cross-user data leakage
- Audit logging: track who accessed what data
- API authentication: secure Ollama communication

### Deployment Options

- **Docker:** Containerized deployment with all dependencies
- **Docker Compose:** Multi-container setup (app + Ollama + DB)
- **Kubernetes:** Scalable deployment for larger teams

---

## Notes & Ideas Backlog

- Integration with BloodHound for attack path visualization
- HIBP API integration to check passwords against breach databases
- Password policy simulator: "What if we required 14 characters?"
- Automated remediation suggestions per-user
- Integration with ticketing systems (Jira, ServiceNow)
- Slack/Teams notifications for critical findings
- API endpoints for CI/CD integration
- Comparison mode: side-by-side domain comparison
- Time-based analysis: when were passwords last changed?
- Geographic password patterns (if location data available)

---

*Last Updated: December 27, 2024*
