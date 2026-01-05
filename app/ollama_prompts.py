"""
Ollama Prompt Templates for HM1K

All prompts used for AI-powered password analysis are stored here for easy
editing and review. These prompts are critical for tuning the AI responses.

Usage:
    from ollama_prompts import SYSTEM_PROMPT, EXECUTIVE_SUMMARY_PROMPT, etc.
"""

# =============================================================================
# SYSTEM PROMPT
# =============================================================================
# This prompt sets the context and persona for the AI. It's sent with every
# request to establish the AI's role and expertise.

SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in password security. You recently completed an Active Directory domain password assessment by collecting (dumping) the domain hashes and then running them through hashcat doing multiple rounds of brute force guessing (up to 9 character passwords), dictionary attacks, hybrid dictionary attacks with rules (like One Rule to Rule them All) and mask attacks. Your job is to analyze the domain dump output and the hashcat output, and be prepared to answer questions about your analysis so your user can report your findings."""


# =============================================================================
# EXECUTIVE SUMMARY PROMPT
# =============================================================================
# Generates a high-level executive summary suitable for management reports.
# Variables: {total_accounts}, {cracked_accounts}, {cracked_percent},
#            {unique_passwords}, {avg_length}, {min_length}, {max_length},
#            {blank_passwords}, {patterns}, {critical_findings}

EXECUTIVE_SUMMARY_PROMPT = """Analyze this password audit data and write a concise executive summary (3-4 paragraphs).

PASSWORD AUDIT DATA:
- Total accounts: {total_accounts}
- Cracked accounts: {cracked_accounts} ({cracked_percent}%)
- Unique passwords: {unique_passwords}
- Average password length: {avg_length} characters
- Shortest password: {min_length} characters
- Longest password: {max_length} characters
- Blank passwords: {blank_passwords}

TOP PATTERNS FOUND:
{patterns}

CRITICAL FINDINGS:
{critical_findings}

Write an executive summary that:
1. Opens with the overall security posture and key risk level
2. Highlights the most concerning findings with business impact
3. Provides 3-5 high-level recommendations prioritized by impact
4. Uses professional language suitable for C-level executives
5. Avoids technical jargon - focus on business risk

Do not include headers or bullet points - write in flowing paragraphs."""


# =============================================================================
# PATTERN DESCRIPTION PROMPT
# =============================================================================
# Analyzes password patterns and explains them in plain language.
# Variables: {pattern_data}

PATTERN_DESCRIPTION_PROMPT = """Analyze these password patterns and explain what they reveal about user behavior and security risks.

PATTERN DATA:
{pattern_data}

For each significant pattern:
1. Explain what the pattern is in plain language
2. Why users likely choose this pattern
3. How an attacker could exploit this pattern
4. Specific risk to the organization

Keep explanations concise but insightful. Focus on actionable intelligence."""


# =============================================================================
# SEMANTIC CLUSTERING PROMPT
# =============================================================================
# Categorizes passwords by their meaning/theme.
# Variables: {passwords}

SEMANTIC_CLUSTERING_PROMPT = """Categorize these passwords by their semantic meaning/theme. Group them into categories like:
- Personal (names, family, pets, birthdays)
- Temporal (seasons, years, dates, months)
- Sports (teams, players, sports terms)
- Pop culture (movies, TV, music, games)
- Work-related (company terms, job titles, projects)
- Geographic (cities, states, countries)
- Religious
- Profanity/inappropriate
- Random/unclassifiable

PASSWORDS TO ANALYZE:
{passwords}

For each category found:
1. Category name
2. Count and percentage
3. Example passwords (sanitized if needed)
4. Security implication

Return as JSON:
{{
  "categories": [
    {{
      "name": "Category Name",
      "count": 123,
      "percent": 12.3,
      "examples": ["example1", "example2"],
      "risk_note": "Why this is concerning"
    }}
  ],
  "insights": "Overall observations about password themes"
}}"""


# =============================================================================
# ATTACK STRATEGY PROMPT
# =============================================================================
# Recommends attack strategies for remaining uncracked hashes.
# Variables: {patterns}, {total_hashes}, {cracked}, {cracked_percent},
#            {remaining}, {base_words}, {structures}

ATTACK_STRATEGY_PROMPT = """Based on these cracked password patterns, recommend attack strategies for the remaining uncracked hashes.

OBSERVED PATTERNS IN CRACKED PASSWORDS:
{patterns}

STATISTICS:
- Total hashes: {total_hashes}
- Cracked: {cracked} ({cracked_percent}%)
- Remaining: {remaining}

TOP BASE WORDS FOUND:
{base_words}

TOP STRUCTURES (mask format):
{structures}

Provide specific attack recommendations:
1. Hashcat mask attacks with specific masks
2. Rule-based attacks with rule suggestions
3. Custom wordlist recommendations
4. Priority order and expected yield estimates

Format as actionable commands where possible."""


# =============================================================================
# BATCH ANALYSIS PROMPTS
# =============================================================================
# Simple prompts for quick password batch analysis.

BATCH_ANALYSIS_PROMPTS = {
    "general": "Analyze these passwords and identify the most significant security concerns:\n\n{passwords}",
    "weakness": "Identify specific weaknesses in these passwords that an attacker could exploit:\n\n{passwords}",
    "theme": "What themes and patterns do you see in these passwords? What do they reveal about user behavior?\n\n{passwords}"
}


# =============================================================================
# DEFAULT TEST PAGE PROMPTS
# =============================================================================
# Default values shown in the test page UI.

DEFAULT_USER_PROMPT = "Analyze the security implications of users choosing \"Summer2024\" as their password."

DEFAULT_STATS_JSON = {
    "total_accounts": 5000,
    "cracked_accounts": 3350,
    "cracked_percent": 67,
    "unique_passwords": 2100,
    "avg_length": 9.2,
    "min_length": 4,
    "max_length": 24,
    "blank_passwords": 12
}

DEFAULT_PATTERNS_JSON = {
    "Password Variants": {"count": 234, "examples": {"P@ssw0rd": 45, "password123": 32}},
    "Season + Year": {"count": 567, "examples": {"Summer2024": 89, "Winter2023": 45}},
    "Keyboard Walks": {"count": 123, "examples": {"qwerty123": 34}}
}

DEFAULT_CLUSTER_PASSWORDS = """Summer2024
Winter2023!
GoPackers!
yankees123
JohnSmith1
password123
Welcome1!
Jesus2024
NewYork99
football!"""


# =============================================================================
# AI REPORT SECTION PROMPTS
# =============================================================================
# These prompts are used for the AI Analysis & Insights report page.
# Each section has its own prompt designed for a specific analysis goal.

# -----------------------------------------------------------------------------
# Section: Weak Password Habits
# -----------------------------------------------------------------------------
# Identifies human patterns and predictable password creation behaviors.
# This prompt sends RAW password data to the LLM for independent pattern discovery.
#
# Variables:
#   {cracked_passwords} - List of all cracked passwords (raw plaintext)
#   {account_passwords} - Account:password pairs for context (username patterns)
#   {password_reuse} - Passwords shared across multiple accounts
#   {org_context} - Organizational context (domains, account types detected)
#   {total_accounts} - Total accounts in the analysis
#   {cracked_count} - Number of passwords cracked

WEAK_HABITS_PROMPT = """You are analyzing cracked passwords from a corporate Active Directory domain password audit.

⚠️ CRITICAL: DO NOT INVENT PASSWORDS ⚠️
Every password example you use MUST appear EXACTLY in the data below. If you cite a password that is not in the data, your analysis will be rejected. When in doubt, use fewer examples rather than making up passwords.

## AUDIT STATISTICS
- Total accounts analyzed: {total_accounts}
- Passwords cracked: {cracked_count}

## ORGANIZATIONAL CONTEXT
{org_context}

## PASSWORD LENGTH DISTRIBUTION
{length_distribution}

## ALL CRACKED PASSWORDS (use ONLY these as examples)
{cracked_passwords}

## ACCOUNT-PASSWORD PAIRS
{account_passwords}

## PASSWORD REUSE
{password_reuse}

## YOUR ANALYSIS TASK

Examine these passwords and discover weak password habits. Look for:
- Structural patterns (Word+Number, Word+Symbol+Year, etc.)
- Semantic themes (names, dates, seasons, sports teams, company references, pop culture)
- Keyboard patterns (qwerty, sequential, repeated characters)
- Lazy complexity additions (ending with 1!, 123, @2024)
- Username-password relationships (ONLY if the password contains the username as a substring)
- Password reuse patterns

## STRICT RULES FOR EXAMPLES

**Rule 1: ONLY USE REAL PASSWORDS**
- Every password example MUST appear EXACTLY in "ALL CRACKED PASSWORDS" or "PASSWORD REUSE" above
- Do NOT invent passwords like `kp39a`, `qpf02`, `IPCw0rks` - these are hallucinations
- Do NOT combine parts of different passwords to create new ones
- If you cannot find 2+ real examples for a pattern, skip the pattern entirely

**Rule 2: USERNAME-PASSWORD CLAIMS**
- The username MUST appear in ACCOUNT-PASSWORD PAIRS
- The password MUST be the one associated with that username in the data
- If you cannot verify the relationship, do not include the section

**Rule 3: STATISTICS**
- ONLY cite specific counts if you counted them from the data
- If unsure, write "Not measured" - never guess

**Rule 4: DOMAIN NAMES ARE NOT PASSWORDS**
- Domain names like "electronics.org" are part of account identifiers, not passwords
- Do not list them as password examples

## OUTPUT FORMAT

Provide your analysis as a numbered list of pattern findings. For EACH pattern found, use this EXACT format (no blank lines within each pattern):

### 1. [Pattern Name]
**Description:** One sentence explaining the pattern.
**Examples:** `example1`, `example2`, `example3` (MUST be from the data above)
**Prevalence:** If you can compute it from evidence, write `N accounts (X%)` where X is out of **cracked passwords**. If you cannot compute it, write `Not measured` (do NOT guess).
**Relative Rank:** High/Medium/Low (based on how often you observe the pattern in the provided passwords, even if exact counts are not available)
**Attack Risk:** How attackers exploit this.
**Psychology:** Why users choose this.

### 2. [Next Pattern Name]
**Description:** ...
(continue for each pattern discovered)

## SUMMARY

After listing all patterns, provide a brief 2-3 sentence summary of the most critical findings.

IMPORTANT FORMATTING RULES:
- Use ### for each pattern header with a number
- Keep each pattern section compact (no extra blank lines)
- Use backticks for password examples inline
- Rank patterns from most to least prevalent (use measured prevalence when available, otherwise use Relative Rank)
- Aim for 8-12 distinct patterns
- EVERY example must come from the actual data - no invented passwords"""


# -----------------------------------------------------------------------------
# Section: Company Intelligence
# -----------------------------------------------------------------------------
# Attempts to identify company information from password patterns.
# This prompt sends RAW data to the LLM for independent discovery of company-identifying information.
#
# Variables:
#   {cracked_passwords} - All cracked passwords (raw plaintext with frequency)
#   {account_names} - All account/usernames for domain and naming pattern analysis
#   {org_context} - Basic organizational context (domains, account types)
#   {total_accounts} - Total accounts in the analysis
#   {cracked_count} - Number of passwords cracked

COMPANY_INTEL_PROMPT = """You are a cybersecurity analyst inferring organizational information from password audit data.

## AUDIT STATISTICS
- Total accounts: {total_accounts}
- Passwords cracked: {cracked_count}

## ORGANIZATIONAL CONTEXT
{org_context}

## ACCOUNT NAMES
{account_names}

## CRACKED PASSWORDS
{cracked_passwords}

## YOUR TASK

Analyze the data to identify information about this organization. Provide findings for each category below.

## OUTPUT FORMAT

Use this EXACT structure for your response:

### 1. Company Identity
**Finding:** What company name, abbreviations, brands, or products appear in the data.
**Evidence:** `example1`, `example2`, `example3` (cite specific passwords/accounts)
**Confidence:** High/Medium/Low - brief justification

### 2. Industry Sector
**Finding:** What industry this organization operates in (tech, finance, healthcare, manufacturing, education, government, retail, etc.)
**Evidence:** Industry-specific terms found in passwords/accounts.
**Confidence:** High/Medium/Low - brief justification

### 3. Geographic Location
**Finding:** Where this organization is likely located based on sports teams, city names, area codes, regional references.
**Evidence:** Specific location indicators found.
**Confidence:** High/Medium/Low - brief justification

### 4. Culture & Demographics
**Finding:** Workforce characteristics revealed by password choices (age range, interests, tenure, diversity).
**Evidence:** Years, cultural references, hobbies, or interests appearing in passwords.
**Confidence:** High/Medium/Low - brief justification

### 5. Security Posture
**Finding:** Assessment of IT maturity, security awareness, and policy enforcement.
**Evidence:** Password complexity patterns, naming conventions, or weak patterns observed.
**Confidence:** High/Medium/Low - brief justification

## SUMMARY
Provide a 2-3 sentence executive summary of key intelligence findings.

FORMATTING RULES:
- Use ### headers exactly as shown above
- Keep each section concise (3-5 lines max)
- Use backticks for specific examples
- Say "Insufficient evidence" if data doesn't support a finding
- Do not add extra sections or change the structure"""


# -----------------------------------------------------------------------------
# Section: User Behavior Insights
# -----------------------------------------------------------------------------
# Analyzes user psychology and behavior from raw password data.
# This prompt sends RAW data to the LLM for independent behavioral analysis.
#
# Variables:
#   {cracked_passwords} - All cracked passwords (raw plaintext with frequency)
#   {account_passwords} - Account:password pairs showing username relationships
#   {password_reuse} - Password reuse details across accounts
#   {org_context} - Organizational context (domains, account types)
#   {total_accounts} - Total accounts in the analysis
#   {cracked_count} - Number of passwords cracked

USER_BEHAVIOR_PROMPT = """You are a behavioral psychologist analyzing password choices to understand user psychology and decision-making.

## AUDIT STATISTICS
- Total accounts: {total_accounts}
- Passwords cracked: {cracked_count}

## ORGANIZATIONAL CONTEXT
{org_context}

## PASSWORD LENGTH DISTRIBUTION
{length_distribution}

## CRACKED PASSWORDS
{cracked_passwords}

## ACCOUNT-PASSWORD PAIRS
{account_passwords}

## PASSWORD REUSE
{password_reuse}

## YOUR TASK

Analyze what these passwords reveal about user behavior, psychology, and security culture. Provide insights that help design better security awareness programs.

## OUTPUT FORMAT

Use this EXACT structure for your response:

### 1. Memorability vs Security
**Observation:** How users balance ease of memory with security requirements.
**Examples:** `password1`, `password2`, `password3`
**Psychology:** Why users make this trade-off.
**Risk:** Security implications of this behavior.
**Recommendation:** How to address this in training.

### 2. Personal vs Professional
**Observation:** Ratio of personal (names, hobbies, dates) vs work-related passwords.
**Examples:** `password1`, `password2`, `password3`
**Psychology:** What this reveals about how users view work accounts.
**Risk:** How personal information enables attacks.
**Recommendation:** Training approach.

### 3. Minimum Effort Patterns
**Observation:** How users meet complexity requirements with minimal effort (adding 1!, 123, @2024).
**Examples:** `password1`, `password2`, `password3`
**Psychology:** Why users optimize for convenience over security.
**Risk:** How attackers exploit these patterns.
**Recommendation:** Policy or training changes.

### 4. Demographics & Culture
**Observation:** Age indicators, geographic references, cultural elements, hobbies visible in passwords.
**Examples:** `password1`, `password2`, `password3`
**Psychology:** How personal identity influences password choices.
**Risk:** How attackers use demographic profiling.
**Recommendation:** Awareness approach.

### 5. Policy Circumvention
**Observation:** Creative workarounds users employ to technically comply while staying predictable.
**Examples:** `password1`, `password2`, `password3`
**Psychology:** Adversarial relationship with security policies.
**Risk:** How circumvention undermines security controls.
**Recommendation:** Policy redesign suggestions.

### 6. Risk Awareness
**Observation:** Evidence of security awareness (or lack thereof) in password choices.
**Examples:** `password1`, `password2`, `password3`
**Psychology:** User understanding of password attacks.
**Risk:** Signs of security fatigue or apathy.
**Recommendation:** Targeted training needs.

### 7. Organizational Dynamics
**Observation:** Evidence of password sharing, IT-assigned defaults, or team patterns.
**Examples:** `password1`, `password2`, `password3`
**Psychology:** Workflow or cultural factors driving shared passwords.
**Risk:** Accountability and lateral movement risks.
**Recommendation:** Process or policy changes.

## SUMMARY
Provide 2-3 sentences summarizing the most important behavioral insights and top recommendations.

FORMATTING RULES:
- Use ### headers exactly as shown
- Keep each section concise
- Use backticks for password examples
- Every section must include Examples, Psychology, Risk, and Recommendation"""


# -----------------------------------------------------------------------------
# Section: Risk Assessment
# -----------------------------------------------------------------------------
# Quantifies the business risk of the findings.
# Variables: {stats}, {policy_failures}, {critical_findings}

RISK_ASSESSMENT_PROMPT = """Assess the business and security risk based on this password audit data.

STATISTICS:
{stats}

POLICY COMPLIANCE FAILURES:
{policy_failures}

CRITICAL FINDINGS:
{critical_findings}

Provide a risk assessment that covers:

1. **Overall Risk Rating**: Provide a rating (Critical/High/Medium/Low) with justification.

2. **Attack Surface Analysis**:
   - How quickly could an attacker crack these passwords?
   - What percentage are vulnerable to common attacks (dictionary, hybrid, mask)?
   - Estimate time-to-compromise for different attack scenarios.

3. **Credential Stuffing Risk**: Given the password patterns, how likely are these passwords reused on external sites?

4. **Lateral Movement Risk**: Once one account is compromised, how easily could an attacker move laterally using password patterns?

5. **Compliance Implications**: How do these findings impact regulatory compliance (SOX, HIPAA, PCI-DSS, etc.)?

6. **Business Impact Scenarios**: Describe 2-3 realistic attack scenarios and their potential business impact.

Be specific and quantitative where possible. This assessment will be used to justify security investments to leadership."""


# -----------------------------------------------------------------------------
# Section: Recommendations
# -----------------------------------------------------------------------------
# Provides actionable security recommendations.
# Variables: {audit_stats}, {key_findings}, {current_policy}, {worst_practices}

RECOMMENDATIONS_PROMPT = """Provide prioritized security recommendations based on password audit findings.

## AUDIT STATISTICS
{audit_stats}

## KEY FINDINGS
{key_findings}

## CURRENT POLICY
{current_policy}

## WORST PRACTICES
{worst_practices}

## IMPORTANT NOTES
- Severity labels: CRITICAL (urgent), HIGH (important), LOW (minor), INFO (awareness only)
- Account status: "ENABLED" = active risk, "disabled" = already mitigated
- Do NOT recommend actions for already-mitigated issues (e.g., don't say "disable" accounts marked as disabled)
- Focus on ENABLED accounts and active threats first

## OUTPUT FORMAT

Use this EXACT structure:

### Immediate Actions (This Week)

**1. [Action Title]**
- **Action:** Specific steps to implement
- **Mitigates:** What risk this addresses
- **Effort:** Low/Medium/High
- **Impact:** High/Medium/Low
- **Status:** Note if partially mitigated already

**2. [Action Title]**
(repeat format for 3-5 immediate actions)

### Short-Term Improvements (This Quarter)

**1. [Improvement Title]**
- **Action:** What to implement
- **Mitigates:** Risk addressed
- **Effort:** Low/Medium/High
- **Impact:** High/Medium/Low

**2. [Improvement Title]**
(repeat format for 3-5 short-term items)

### Strategic Changes (This Year)

**1. [Strategic Initiative]**
- **Action:** Long-term change to implement
- **Mitigates:** Systemic risk addressed
- **Effort:** High
- **Impact:** High
- **ROI:** Brief justification

**2. [Strategic Initiative]**
(repeat format for 2-3 strategic items)

## SUMMARY
One paragraph summarizing the top 3 priorities and expected security improvement.

FORMATTING RULES:
- Use ### for section headers, **1.** for numbered items
- Keep each recommendation concise (4-5 lines max)
- Always include Effort and Impact ratings
- Prioritize by impact-to-effort ratio within each section"""


# -----------------------------------------------------------------------------
# Section: Full Report
# -----------------------------------------------------------------------------
# Generates a comprehensive security assessment report that synthesizes all
# prior AI analyses into a cohesive, professional document.
#
# Variables:
#   {audit_stats} - Complete cracking statistics
#   {weak_habits_analysis} - Output from weak-habits section
#   {company_intel_analysis} - Output from company-intel section
#   {user_behavior_analysis} - Output from user-behavior section
#   {recommendations_analysis} - Output from recommendations section
#   {raw_data_summary} - Summary of all raw JSON data available
#   {org_context} - Organizational context derived from the data

FULL_REPORT_PROMPT = """You are a senior security consultant preparing a comprehensive Password Security Assessment Report for executive leadership and the security team. You have access to complete audit data and four specialized AI analyses that have already been performed.

Your task is to synthesize all of this information into a polished, professional report that tells a cohesive story about the organization's password security posture.

## AUDIT STATISTICS
{audit_stats}

## ORGANIZATIONAL CONTEXT
{org_context}

## PRIOR AI ANALYSES

### 1. Weak Password Habits Analysis
{weak_habits_analysis}

### 2. Company Intelligence Analysis
{company_intel_analysis}

### 3. User Behavior Insights
{user_behavior_analysis}

### 4. Security Recommendations
{recommendations_analysis}

## RAW DATA SUMMARY
{raw_data_summary}

---

## YOUR REPORT REQUIREMENTS

Generate a comprehensive, board-ready security assessment report with the following structure:

# PASSWORD SECURITY ASSESSMENT REPORT

## Executive Summary
Write 3-4 paragraphs for C-level executives that:
- Opens with the overall security posture and headline risk level
- Quantifies the business exposure (% cracked, time-to-compromise estimates)
- Highlights the 3 most critical findings with potential business impact
- Closes with a clear call-to-action and investment recommendation

## Key Findings Dashboard
Create a concise "at-a-glance" section with:
- Overall Risk Rating: [CRITICAL/HIGH/MEDIUM/LOW] with 1-sentence justification
- Crack Rate: X% of passwords compromised
- Average Time to Crack: Estimate based on patterns observed
- Top 3 Vulnerabilities: Brief bullets
- Top 3 Strengths (if any): Brief bullets

## Detailed Findings

### Password Pattern Analysis
Synthesize the weak-habits analysis into a narrative that:
- Identifies the 5 most prevalent weak patterns with percentages
- Explains WHY these patterns exist (user psychology)
- Provides specific examples (sanitized appropriately)
- Quantifies the attack surface each pattern creates

### Organizational Intelligence
Synthesize company-intel findings to show:
- What an attacker could learn about the organization from passwords alone
- Industry, location, culture, and technology stack indicators
- Insider threat indicators (if any)
- OPSEC recommendations

### User Behavior Assessment
Synthesize user-behavior findings to explain:
- The psychology driving password choices
- Cultural and demographic patterns in the workforce
- Policy circumvention behaviors and their root causes
- Recommendations for security awareness training

### Risk Analysis
Provide a thorough risk assessment covering:
- Attack scenario timelines (how quickly could a breach occur?)
- Lateral movement risk assessment
- Credential stuffing exposure estimate
- Compliance implications (NIST, SOX, HIPAA, PCI-DSS as applicable)

## Prioritized Recommendations

### Immediate Actions (0-7 Days)
List 3-5 critical actions with:
- Specific action item
- Risk mitigated
- Effort level
- Expected impact

### Short-Term Improvements (30-90 Days)
List 5-7 improvements with implementation guidance

### Strategic Initiatives (6-12 Months)
List 3-5 long-term recommendations with ROI justification

## Appendix: Technical Details
- Password length distribution analysis
- Character class usage statistics
- Pattern frequency breakdown
- Methodology notes

---

## WRITING GUIDELINES

1. **Professional Tone**: Write for a mixed audience of executives and security professionals
2. **Quantify Everything**: Use percentages, counts, and time estimates wherever possible
3. **Tell a Story**: Connect the dots between findings - don't just list facts
4. **Be Actionable**: Every finding should connect to a recommendation
5. **Avoid Redundancy**: Synthesize and consolidate - don't repeat the same finding multiple times
6. **Use Clear Structure**: Use headers, bullets, and tables for scannability
7. **Highlight What Matters**: Use emphasis for critical points
8. **Be Honest About Limitations**: Note any caveats or areas needing further investigation

This report will be used to justify security investments and may be shared with auditors. Make it comprehensive but concise - aim for quality over quantity."""


# -----------------------------------------------------------------------------
# AI Report Section Configuration
# -----------------------------------------------------------------------------
# Maps section IDs to their prompts, recommended settings, and data sources.
#
# data_sources: Maps prompt variable names to their JSON file sources
#   - "file:<filename>" = Load from /data/<filename>.json
#   - "derived:<function>" = Compute from other data (handled in code)
#   - "session:<key>" = Load from Flask session
#   - "config:<key>" = Load from analysis configuration

AI_REPORT_SECTIONS = {
    "weak-habits": {
        "title": "Semantic Password Intelligence",
        "description": "AI extracts semantic patterns (sports, pop culture, profanity, etc.) that regex cannot detect",
        "pipeline": "spi",  # Uses Semantic Password Intelligence pipeline instead of standard 3-phase
        "recommended_model": "llama3.1:70b",
        "temperature": 0.2,  # Lower temp for consistent extraction
        "order": 1,
        "data_sources": {
            # SPI uses its own data loading - these are for reference only
            "cracked_passwords": "derived:all_cracked_passwords"
        }
    },
    "company-intel": {
        "title": "Company Intelligence",
        "description": "Infers company identity, industry, and location from raw passwords and account names",
        "prompt_key": "COMPANY_INTEL_PROMPT",
        "recommended_model": "deepseek-r1:671b",
        "temperature": 0.3,  # 671B excels at inference - worth the extra time
        "order": 2,
        "data_sources": {
            # Raw data for independent AI analysis
            "cracked_passwords": "derived:all_cracked_passwords",
            "account_names": "derived:all_account_names",
            "org_context": "derived:organizational_context",
            "total_accounts": "derived:total_account_count",
            "cracked_count": "derived:cracked_account_count"
        }
    },
    "user-behavior": {
        "title": "User Behavior Insights",
        "description": "Analyzes user psychology and behavior from raw password data",
        "prompt_key": "USER_BEHAVIOR_PROMPT",
        "recommended_model": "deepseek-r1:671b",
        "temperature": 0.4,  # 671B provides significantly more insightful behavioral analysis
        "order": 3,
        "data_sources": {
            # Raw data for independent AI behavioral analysis
            "cracked_passwords": "derived:all_cracked_passwords",
            "account_passwords": "derived:account_password_pairs",
            "password_reuse": "derived:password_reuse_details",
            "length_distribution": "derived:password_length_distribution",
            "org_context": "derived:organizational_context",
            "total_accounts": "derived:total_account_count",
            "cracked_count": "derived:cracked_account_count"
        }
    },
    "recommendations": {
        "title": "Security Recommendations",
        "description": "Prioritized actionable recommendations",
        "prompt_key": "RECOMMENDATIONS_PROMPT",
        "recommended_model": "deepseek-r1:671b",
        "temperature": 0.4,  # Slightly lower for more actionable, less verbose output
        "order": 5,
        "data_sources": {
            "audit_stats": "derived:audit_stats_summary",
            "key_findings": "derived:key_findings",
            "current_policy": "session:analysis_options",
            "worst_practices": "derived:worst_practices"
        }
    },
    "full-report": {
        "title": "Full Security Assessment Report",
        "description": "Comprehensive report synthesizing all prior analyses (generate last after running other sections)",
        "prompt_key": "FULL_REPORT_PROMPT",
        "recommended_model": "deepseek-r1:671b",
        "temperature": 0.5,  # Balanced creativity for professional writing
        "order": 99,  # Always last - requires prior section outputs
        "requires_prior_analyses": True,  # Flag indicating this needs other sections first
        "data_sources": {
            # Complete audit statistics
            "audit_stats": "file:cracking_stats_table",
            # Prior AI analysis outputs (loaded from session or passed directly)
            "weak_habits_analysis": "session:ai_output_weak-habits",
            "company_intel_analysis": "session:ai_output_company-intel",
            "user_behavior_analysis": "session:ai_output_user-behavior",
            "recommendations_analysis": "session:ai_output_recommendations",
            # Raw data summary for appendix
            "raw_data_summary": "derived:raw_data_summary",
            "org_context": "derived:organizational_context"
        }
    }
}


# =============================================================================
# SECTION-SPECIFIC VALIDATION PROMPTS (Phase 2)
# =============================================================================
# Each section has specific validation rules based on what claims need checking.
# Variables: {evidence_pack}, {content_to_validate}
#
# VALIDATION PHILOSOPHY (applies to all validators):
# - Do NOT invent facts, policies, metrics, counts, or percentages
# - If a number/policy/config is not explicitly supported by evidence, mark it unsupported
# - Do NOT recommend actions for already-mitigated issues (disabled accounts, resolved findings)
# - Keep recommendations realistic for on-prem Active Directory
# - Flag outdated guidance (e.g., periodic forced password rotation without evidence of compromise)
# - Never mask or redact passwords - this is an audit report

VALIDATION_PROMPT_WEAK_HABITS = """You are validating the "Password Pattern Analysis" section of a security audit.

## EVIDENCE DATA
{evidence_pack}

## CONTENT TO VALIDATE
{content_to_validate}

## SECTION-SPECIFIC VALIDATION RULES

For Password Pattern Analysis, verify these specific claims:

1. **HALLUCINATION CHECK (CRITICAL)**: Every password example MUST exist in the PASSWORD WHITELIST in the evidence data.
   - The evidence includes a "PASSWORD WHITELIST" section - ONLY passwords in that list are valid
   - For EACH password example in the content, check if it appears in the whitelist
   - If a password is NOT in the whitelist, it is HALLUCINATED and must be REMOVED
   - Check EVERY password example, not just suspicious ones
   - Common hallucinations: `kp39a`, `qpf02`, `IPCw0rks`, `ipcftp`, `IPC@2025A`, `Bunnies7!Bunnies7!`, `Winter2468#`
   - When in doubt, REMOVE the password - it's better to have fewer examples than hallucinated ones

2. **Username-Password Relationships**: If a claim says a password is "derived from" or "related to" a username, verify BOTH conditions:
   - The username MUST exist in the evidence data (account names)
   - The password MUST contain the username or a clear substring/variation of it
   Example: username "jsmith" with password "Jsmith123!" is valid (contains "jsmith").
   INVALID examples (flag for removal):
   - Any username not found in the evidence data
   - Password that doesn't contain the username as a substring (e.g., "zhouro" + "Winter2468#")
   - Made-up or invented username-password pairs
   - Pairs where you cannot verify BOTH the username AND password exist together in the data

3. **Pattern Examples**: Verify that password examples actually match the pattern being described:
   - "Sequential keyboard patterns" should show actual keyboard walks (qwerty, asdfgh)
   - "Company references" should contain company name/abbreviation in the PASSWORD itself, NOT domain names from account names
   - "Word+Number" should show word followed by numbers
   - "Repeated characters" patterns like `Bunnies7!Bunnies7!` are likely hallucinated - verify they exist
   - EXCLUDE domain names (e.g., "electronics.org", "company.com") - these are part of account identifiers, NOT passwords

4. **Prevalence Claims**: If specific counts are given (e.g., "14 accounts"), check if evidence supports this. Allow ~20% variance. If a count cannot be verified, replace with "Not measured".

5. **Password Examples**: Keep ALL valid password examples - this is an audit report. Do NOT mask or redact. But REMOVE hallucinated passwords.

6. **Orphaned Sections**: If after validation a pattern category has only 1 example remaining, or all examples are invalid:
   - If 0 valid examples remain: Remove the entire pattern section
   - If only 1 example remains: Either find more valid examples from evidence OR merge into a related category

## WHAT TO FIX (in priority order)
1. **Hallucinated passwords** - Remove any password not found in evidence data
2. **Invented statistics** - Replace with "Not measured" or remove
3. **Username-password pairs** where the username doesn't exist in evidence OR the password doesn't contain the username
4. Examples that don't match the pattern category they're listed under
5. Domain names incorrectly listed as password examples
6. Pattern sections left with 0-1 examples after removing invalid ones

## WHAT TO PRESERVE
- All password examples (never mask these)
- Reasonable estimates (~X%, approximately)
- Pattern categories even if exact counts aren't in evidence
- Psychological insights about why users choose passwords

## OUTPUT (JSON only)
Return ONLY JSON. Be concise - do NOT reproduce content unnecessarily.

**If NO issues found:**
```json
{{"issues":[],"confidence":0.95,"needs_human_review":false}}
```

**If issues found:**
```json
{{
  "issues": [
    {{
      "rule_id": "NO_INVENTED_NUMBERS|PATTERN_INTEGRITY|OTHER",
      "severity": "high|medium|low",
      "location": "Pattern # or section name",
      "find": "exact text to replace",
      "replace": "corrected text or empty string to remove"
    }}
  ],
  "confidence": 0.8,
  "needs_human_review": false
}}
```

IMPORTANT: Only include `corrected_content` if there are complex structural changes that cannot be expressed as find/replace pairs. For simple fixes, use the find/replace approach."""


VALIDATION_PROMPT_COMPANY_INTEL = """You are validating the "Company Intelligence Assessment" section of a security audit.

## EVIDENCE DATA
{evidence_pack}

## CONTENT TO VALIDATE
{content_to_validate}

## SECTION-SPECIFIC VALIDATION RULES

For Company Intelligence, verify these specific claims:

1. **Company Name Inferences**: If claiming the company is "XYZ Corp", verify passwords actually contain "xyz", "XYZ", or related terms.

2. **Geographic Claims**: Location inferences should be supported by:
   - City/state names in passwords
   - Area codes or zip codes
   - Regional sports teams or landmarks

3. **Industry Inferences**: Industry claims should have password evidence (tech terms, medical terms, etc.)

4. **Confidence Levels**: Verify HIGH confidence claims have strong evidence (multiple passwords). MEDIUM/LOW can be more speculative.

## WHAT TO FIX
- Company name claims with no supporting password evidence
- Geographic claims that contradict the evidence
- HIGH confidence ratings on weak evidence

## WHAT TO PRESERVE
- All password examples (never mask)
- Reasonable inferences with MEDIUM/LOW confidence
- Industry speculation based on terminology patterns

## OUTPUT (JSON only)
Return ONLY JSON. Be concise - do NOT reproduce content unnecessarily.

**If NO issues found:**
```json
{{"issues":[],"confidence":0.95,"needs_human_review":false}}
```

**If issues found:**
```json
{{
  "issues": [
    {{
      "type": "unsupported_inference|wrong_confidence|contradicts_evidence",
      "severity": "high|medium|low",
      "location": "Finding name",
      "find": "exact text to replace",
      "replace": "corrected text or empty string to remove"
    }}
  ],
  "confidence": 0.8,
  "needs_human_review": false
}}
```

IMPORTANT: Only include `corrected_content` if there are complex structural changes. For simple fixes, use find/replace."""


VALIDATION_PROMPT_USER_BEHAVIOR = """You are validating the "User Behavior Insights" section of a security audit.

## EVIDENCE DATA
{evidence_pack}

## CONTENT TO VALIDATE
{content_to_validate}

## SECTION-SPECIFIC VALIDATION RULES

For User Behavior, verify these specific claims:

1. **Behavioral Claims**: Statements about user behavior should be supported by password patterns in the evidence.

2. **Risk Assessments**: Risk levels should match the severity of the behavior described.

3. **Statistical Claims**: Any percentages or counts should roughly match evidence data.

4. **Remove "Risk Prioritization Framework"**: This meta-section does not belong in the user behavior analysis. If present, remove it.

## WHAT TO FIX
- Statistical claims that are >50% off from evidence
- Risk levels that don't match the actual threat
- Any "Risk Prioritization Framework" section (remove entirely)

## WHAT TO PRESERVE
- All password examples (never mask)
- Behavioral observations supported by patterns
- Reasonable risk assessments
- Recommendations tied to observed behaviors

## OUTPUT (JSON only)
Return ONLY JSON. Be concise - do NOT reproduce content unnecessarily.

**If NO issues found:**
```json
{{"issues":[],"confidence":0.95,"needs_human_review":false}}
```

**If issues found:**
```json
{{
  "issues": [
    {{
      "type": "invented_statistic|irrelevant_section|risk_mismatch",
      "severity": "high|medium|low",
      "location": "Section name",
      "find": "exact text to replace",
      "replace": "corrected text or empty string to remove"
    }}
  ],
  "confidence": 0.8,
  "needs_human_review": false
}}
```

IMPORTANT: Only include `corrected_content` if there are complex structural changes (like removing entire sections). For simple fixes, use find/replace."""


VALIDATION_PROMPT_RECOMMENDATIONS = """You are validating the "Security Recommendations" section of a security audit.

## EVIDENCE DATA
{evidence_pack}

## CONTENT TO VALIDATE
{content_to_validate}

## SECTION-SPECIFIC VALIDATION RULES

For Recommendations, verify these specific claims:

1. **Already Mitigated**: Check if recommended actions address issues that are already fixed (disabled accounts, etc.). Do NOT recommend actions on already-mitigated items.

2. **Relevance**: Each recommendation should address a finding from the audit data.

3. **Priority/Effort Ratings**: These should be reasonable based on the recommendation scope.

4. **AD Realism**: Recommendations must be implementable in native Active Directory OR explicitly state dependencies:
   - "Enforce password uniqueness across users" is NOT native AD - must be framed as detect/remediate with third-party tooling or identity platform
   - If an action requires Entra ID, third-party tools, or cloud controls, explicitly state that dependency
   - Prefer: Group Policy, Fine-Grained Password Policies, PAM/PAW tiering, authentication policies

5. **Outdated Guidance**: Flag periodic forced password rotation as a default control. Only recommend rotation if:
   - There is evidence of compromise
   - There is a specific compliance requirement
   - Instead prioritize: longer passphrases, banned-password lists, MFA, monitoring

6. **Scope Creep**: Do not recommend cloud products/controls unless evidence explicitly includes cloud scope.

## WHAT TO FIX
- Recommendations for already-mitigated issues (remove or note as already addressed)
- Actions that aren't technically feasible in native AD (add dependency note or reframe)
- Periodic rotation recommendations without justification (reframe or remove)
- Priority ratings that don't match urgency

## WHAT TO PRESERVE
- All specific recommendations (with corrections applied)
- Priority, Effort, Impact ratings (even if you'd rate differently)
- Implementation details
- Timeline suggestions

## OUTPUT (JSON only)
Return ONLY JSON. Be concise - do NOT reproduce content unnecessarily.

**If NO issues found:**
```json
{{"issues":[],"confidence":0.95,"needs_human_review":false}}
```

**If issues found:**
```json
{{
  "issues": [
    {{
      "rule_id": "AD_REALISM|MITIGATED_ACTION|OUTDATED_GUIDANCE|SCOPE_CREEP|OTHER",
      "type": "technical_inaccuracy|not_feasible_in_ad|mitigated_action|outdated_guidance|scope_creep",
      "severity": "high|medium|low",
      "location": "Immediate/Short-Term/Strategic item #",
      "find": "exact text to replace",
      "replace": "corrected text or empty string to remove"
    }}
  ],
  "confidence": 0.8,
  "needs_human_review": false
}}
```

Set `"needs_human_review": true` if any issue has severity "high" or if you are unsure about feasibility.

IMPORTANT: Only include `corrected_content` if there are complex structural changes. For simple fixes, use find/replace."""


# Dictionary to get the right validation prompt by section ID
VALIDATION_PROMPTS = {
    "weak-habits": VALIDATION_PROMPT_WEAK_HABITS,
    "company-intel": VALIDATION_PROMPT_COMPANY_INTEL,
    "user-behavior": VALIDATION_PROMPT_USER_BEHAVIOR,
    "recommendations": VALIDATION_PROMPT_RECOMMENDATIONS
}

def get_validation_prompt(section_id: str) -> str:
    """Get the section-specific validation prompt."""
    return VALIDATION_PROMPTS.get(section_id, VALIDATION_PROMPT_WEAK_HABITS)


# =============================================================================
# SECTION-SPECIFIC FORMATTING PROMPTS (Phase 3)
# =============================================================================
# Each section has specific formatting requirements.
# Variables: {validated_content}

FORMATTING_PROMPT_WEAK_HABITS = """You are formatting the "Password Pattern Analysis" section for executive presentation.

## CONTENT TO FORMAT
{validated_content}

## FORMATTING REQUIREMENTS

1. **Structure each pattern category with**:
   - Pattern name as ### header
   - Description paragraph
   - `**Examples:**` with 5-10 password examples in backticks (e.g., `Password123`)
   - `**Prevalence:**` with percentage, count, OR "Not measured" - NEVER leave this field empty
   - `**Risk:**` brief risk statement

2. **Highlight passwords** using backticks: `actualpassword`

3. **Include 5-10 examples per pattern** when available in the content. If fewer exist, keep what's there.

4. **Prevalence handling**:
   - If a specific count is provided (e.g., "87 accounts (31.3%)"), use it as-is
   - If empty or blank, write "Not measured"
   - NEVER leave `**Prevalence:**` with no value after it

5. **NO NEW CONTENT**: Only reformat what exists. Do not add examples or statistics.

## OUTPUT

Return ONLY clean markdown. No preamble, no JSON, no "VALIDATED CONTENT" header."""


FORMATTING_PROMPT_COMPANY_INTEL = """You are formatting the "Company Intelligence Assessment" section for executive presentation.

## CONTENT TO FORMAT
{validated_content}

## FORMATTING REQUIREMENTS

1. **Structure each finding with these on SEPARATE LINES**:
   ```
   ### Finding Name

   **Finding:** [The intelligence finding]

   **Evidence:** [Password examples in backticks]

   **Confidence:** [HIGH/MEDIUM/LOW with explanation]
   ```

2. **Highlight passwords and evidence** using backticks: `IPC2024!`

3. **Each field on its own line** - Finding, Evidence, and Confidence must each start on a new line with a blank line between them.

4. **NO NEW CONTENT**: Only reformat what exists.

## OUTPUT

Return ONLY clean markdown. No preamble, no JSON, no "VALIDATED CONTENT" header."""


FORMATTING_PROMPT_USER_BEHAVIOR = """You are formatting the "User Behavior Insights" section for executive presentation.

## CONTENT TO FORMAT
{validated_content}

## FORMATTING REQUIREMENTS

1. **Structure each behavior insight with these on SEPARATE LINES**:
   ```
   ### Behavior Pattern Name

   **Observation:** [What was observed]

   **Examples:** [Password examples in backticks]

   **Risk:** [Risk level and explanation]

   **Recommendation:** [Suggested action]
   ```

2. **Each field on its own line** - Observation, Examples, Risk, and Recommendation must each start on a new line with a blank line between them.

3. **Highlight passwords** using backticks: `Summer2024!`

4. **REMOVE any "Risk Prioritization Framework" section** - this does not belong here.

5. **NO NEW CONTENT**: Only reformat what exists.

## OUTPUT

Return ONLY clean markdown. No preamble, no JSON, no "VALIDATED CONTENT" header."""


FORMATTING_PROMPT_RECOMMENDATIONS = """You are formatting the "Security Recommendations" section for executive presentation.

## CONTENT TO FORMAT
{validated_content}

## FORMATTING REQUIREMENTS

1. **Structure each recommendation with**:
   ```
   ### Recommendation Title

   **Priority:** [Critical/High/Medium/Low]
   **Effort:** [Low/Medium/High]
   **Impact:** [Description]

   [Detailed recommendation text]

   **Implementation Steps:**
   1. Step one
   2. Step two
   ```

2. **Keep Priority/Effort/Impact on separate lines** at the top of each recommendation.

3. **Preserve all existing ratings** - do not change Priority, Effort, or Impact values.

4. **NO NEW CONTENT**: Only reformat what exists.

## OUTPUT

Return ONLY clean markdown. No preamble, no JSON, no "VALIDATED CONTENT" header."""


# Dictionary to get the right formatting prompt by section ID
FORMATTING_PROMPTS = {
    "weak-habits": FORMATTING_PROMPT_WEAK_HABITS,
    "company-intel": FORMATTING_PROMPT_COMPANY_INTEL,
    "user-behavior": FORMATTING_PROMPT_USER_BEHAVIOR,
    "recommendations": FORMATTING_PROMPT_RECOMMENDATIONS
}

def get_formatting_prompt(section_id: str) -> str:
    """Get the section-specific formatting prompt."""
    return FORMATTING_PROMPTS.get(section_id, FORMATTING_PROMPT_WEAK_HABITS)


# =============================================================================
# Phase Configuration for AI Report Sections
# =============================================================================
# Defines model and temperature settings for each phase of the 3-phase pipeline.
# Phase 1: Initial analysis (section-specific model)
# Phase 2: Validation (deepseek-r1:671b for fact-checking)
# Phase 3: Formatting (llama3.1:70b for polishing)

PHASE_CONFIG = {
    "weak-habits": {
        # Uses SPI pipeline - runs 11 focused category prompts, Python validates and formats
        "pipeline": "spi",
        "phase1": {"model": "llama3.1:70b", "temperature": 0.2},  # Used for each SPI category
        "phase2": {"model": None, "temperature": None, "enabled": False},  # Python validates
        "phase3": {"model": None, "temperature": None, "enabled": False},  # Python formats
        "evidence_sources": []  # SPI generates its own evidence from validated matches
    },
    "company-intel": {
        "phase1": {"model": "deepseek-r1:671b", "temperature": 0.3},
        "phase2": {"model": "deepseek-r1:671b", "temperature": 0.2, "enabled": True},
        "phase3": {"model": "llama3.1:70b", "temperature": 0.15, "enabled": True},
        "evidence_sources": ["cracking_stats_table", "pw_top_passwords", "pw_dict_words"]
    },
    "user-behavior": {
        "phase1": {"model": "deepseek-r1:671b", "temperature": 0.4},
        "phase2": {"model": "deepseek-r1:671b", "temperature": 0.2, "enabled": True},
        "phase3": {"model": "llama3.1:70b", "temperature": 0.15, "enabled": True},
        "evidence_sources": ["cracking_stats_table", "pw_top_passwords", "pw_reuse_table", "pw_bad_practices"]
    },
    "recommendations": {
        "phase1": {"model": "deepseek-r1:671b", "temperature": 0.4},
        "phase2": {"model": "deepseek-r1:671b", "temperature": 0.2, "enabled": True},
        "phase3": {"model": "llama3.1:70b", "temperature": 0.15, "enabled": True},
        "evidence_sources": ["cracking_stats_table", "pw_lm_hashes", "pw_fails_blank", "pw_reuse_table", "pw_bad_practices"]
    },
    "full-report": {
        "phase1": {"model": "deepseek-r1:671b", "temperature": 0.5},
        "phase2": {"model": None, "temperature": None, "enabled": False},  # Skip - synthesizes already validated content
        "phase3": {"model": None, "temperature": None, "enabled": False},  # Skip - has its own formatting
        "evidence_sources": []
    }
}


def get_phase_config(section_id: str) -> dict:
    """Get the phase configuration for a specific section."""
    return PHASE_CONFIG.get(section_id, {
        "phase1": {"model": "llama3.1:70b", "temperature": 0.3},
        "phase2": {"model": "deepseek-r1:671b", "temperature": 0.2, "enabled": True},
        "phase3": {"model": "llama3.1:70b", "temperature": 0.15, "enabled": True},
        "evidence_sources": ["cracking_stats_table"]
    })
