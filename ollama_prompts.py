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

WEAK_HABITS_PROMPT = """You are analyzing cracked passwords from a corporate Active Directory domain password audit. Your goal is to independently discover weak password creation habits and patterns that make these passwords predictable and vulnerable to attack.

## AUDIT STATISTICS
- Total accounts analyzed: {total_accounts}
- Passwords cracked: {cracked_count}

## ORGANIZATIONAL CONTEXT
{org_context}

## ALL CRACKED PASSWORDS
The following is the complete list of cracked passwords from this domain. Analyze them to discover patterns:

{cracked_passwords}

## ACCOUNT-PASSWORD PAIRS (sample for username context)
These show how usernames relate to password choices:
{account_passwords}

## PASSWORD REUSE (passwords shared by multiple accounts)
{password_reuse}

---

## YOUR ANALYSIS TASK

Examine these passwords as a security analyst would. Discover and categorize ALL weak password habits you can identify. Think beyond obvious patterns - look for:

1. **Structural Patterns**: How are passwords constructed? (e.g., Word+Number, Word+Symbol+Year)

2. **Semantic Categories**: What themes appear? Consider:
   - Personal names (first names, family names, pets)
   - Temporal references (seasons, years, months, dates)
   - Geographic references (cities, states, sports teams, landmarks)
   - Company/work references (company name, products, projects, jargon)
   - Pop culture (movies, TV, music, games, celebrities)
   - Religious references
   - Sports teams and mascots
   - Hobbies and interests

3. **Keyboard and Character Patterns**:
   - Keyboard walks (qwerty, asdf, etc.)
   - Sequential characters (123, abc, etc.)
   - Repeated characters (aaa, 111)
   - Common substitutions (@ for a, 0 for o, $ for s, 3 for e)
   - Lazy complexity additions (ending with 1!, #1, 123, etc.)

4. **Policy Circumvention**: How are users meeting minimum requirements while staying predictable?

5. **Username-Password Relationships**: Are users incorporating their username or name into passwords?

6. **Shared Password Patterns**: What do the reused passwords reveal about organizational practices?

## OUTPUT FORMAT

For each pattern category you discover:
1. **Pattern Name**: Give it a clear, descriptive name
2. **Description**: Explain what the pattern is
3. **Examples**: List 3-5 specific passwords that match this pattern
4. **Count/Prevalence**: Estimate how many passwords follow this pattern
5. **Attack Vulnerability**: Explain how an attacker would exploit this pattern
6. **Why Users Choose This**: Explain the psychology behind this choice

Rank your findings from most prevalent to least prevalent. Be thorough - discover patterns that might not be obvious at first glance. Your analysis will help the organization understand the true predictability of their passwords."""


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

COMPANY_INTEL_PROMPT = """You are a cybersecurity analyst who has just completed a password audit of an Active Directory domain. Your goal is to analyze the passwords and account names to infer information about the organization - without being told anything about the company beforehand.

## AUDIT STATISTICS
- Total accounts analyzed: {total_accounts}
- Passwords cracked: {cracked_count}

## ORGANIZATIONAL CONTEXT
{org_context}

## ALL ACCOUNT NAMES
These are all the account/usernames from the domain. Analyze them for:
- Domain names that might reveal company identity
- Naming conventions (first.last, flast, etc.)
- Department or role indicators
- Service account naming patterns

{account_names}

## ALL CRACKED PASSWORDS
Analyze these passwords for company-identifying information:

{cracked_passwords}

---

## YOUR INTELLIGENCE GATHERING TASK

Examine the passwords and account names as an investigator would. Look for clues that reveal:

### 1. Company Identity
- **Company name or abbreviations** appearing in passwords or account names
- **Brand names, products, or services** the company might offer
- **Domain names** that reveal the company
- **Internal project names or codenames**
- Rate your confidence: How certain are you of the company identity?

### 2. Industry Sector
Look for industry-specific terminology:
- **Healthcare**: medical terms, patient references, HIPAA-related
- **Finance**: banking terms, trading, compliance references
- **Technology**: technical jargon, software names, coding references
- **Manufacturing**: product codes, machinery terms
- **Education**: school terms, academic references
- **Government**: agency terms, clearance references
- **Retail**: product/inventory terms, POS references
What evidence supports your industry assessment?

### 3. Geographic Location
Identify location clues:
- **Sports teams** (NFL, NBA, MLB, NHL, college teams)
- **City or state names** in passwords
- **Area codes or zip codes**
- **Regional slang or cultural references**
- **Local landmarks or attractions**
Where is this company likely located?

### 4. Company Culture & Demographics
What do the passwords reveal about:
- **Company age/founding year** (years appearing in passwords)
- **Workforce demographics** (names, cultural references)
- **Company events or milestones**
- **Internal terminology or acronyms**
- **Tech-savviness** of employees

### 5. Security Posture Indicators
Based on account naming and password patterns:
- How mature is their IT organization?
- Do they appear to have security awareness training?
- Are there signs of password policy enforcement?

## OUTPUT FORMAT

For each category above:
1. **Finding**: What you discovered
2. **Evidence**: Specific passwords/accounts that support this (cite 3-5 examples)
3. **Confidence**: Low/Medium/High with justification

Be specific with evidence. If you cannot determine something, say "Insufficient evidence" rather than guessing. Your analysis should read like an intelligence briefing."""


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

USER_BEHAVIOR_PROMPT = """You are a behavioral psychologist specializing in cybersecurity. You've been given the results of a password audit and your task is to analyze what these passwords reveal about user psychology, decision-making, and behavior patterns.

## AUDIT STATISTICS
- Total accounts analyzed: {total_accounts}
- Passwords cracked: {cracked_count}

## ORGANIZATIONAL CONTEXT
{org_context}

## ALL CRACKED PASSWORDS
Analyze these passwords for behavioral patterns:

{cracked_passwords}

## ACCOUNT-PASSWORD RELATIONSHIPS
These show how users' identities relate to their password choices:
{account_passwords}

## PASSWORD REUSE PATTERNS
These passwords are shared across multiple accounts:
{password_reuse}

---

## YOUR BEHAVIORAL ANALYSIS TASK

Examine these passwords through a behavioral psychology lens. Your goal is to understand WHY users make the choices they do, what it reveals about their mindset, and how this knowledge can improve security awareness.

Provide insights on:

### 1. Memorability vs Security Trade-off
- How are users balancing these competing needs?
- What mental shortcuts and heuristics do they use?
- What does their password construction reveal about their security priorities?

### 2. Personal vs Professional Identity
- What percentage of passwords appear personal (names, family, pets, dates, hobbies)?
- What percentage incorporate work/company elements?
- What does this ratio suggest about how users view their work accounts?

### 3. Minimum Effort Patterns
- Identify specific patterns where users do the bare minimum to meet complexity requirements
- Common additions like "1!", "123", "@2024" at the end
- What does this reveal about their motivation and understanding?

### 4. Cultural and Demographic Insights
- What do the passwords suggest about workforce demographics?
- Age indicators (generational references, pop culture from specific eras)
- Geographic/regional indicators (sports teams, local references)
- Cultural or religious elements
- Hobbies and interests prevalent in the workforce

### 5. Policy Circumvention Psychology
- How are users technically complying while undermining security?
- What creative workarounds have they developed?
- What does this adversarial stance suggest about security culture?

### 6. Risk Awareness Assessment
- Do password choices suggest users understand password attacks?
- Evidence of security awareness (or lack thereof)
- Signs of security fatigue or apathy

### 7. Social and Organizational Dynamics
- Evidence of password sharing or coordination between users
- Patterns that might indicate IT-assigned passwords
- Department or team-specific patterns

## OUTPUT FORMAT

For each insight:
1. **Observation**: What you found in the data
2. **Examples**: 3-5 specific passwords that illustrate this behavior
3. **Psychology**: Why users likely make this choice
4. **Security Implication**: How this behavior creates risk
5. **Recommendation**: How security awareness training could address this

Write in a way that helps security teams understand their users' mindset so they can design more effective security awareness programs and policies."""


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
# Variables: {key_findings}, {current_policy}, {worst_practices}

RECOMMENDATIONS_PROMPT = """Based on the password audit findings, provide prioritized security recommendations.

KEY FINDINGS:
{key_findings}

CURRENT PASSWORD POLICY:
{current_policy}

WORST PRACTICES OBSERVED:
{worst_practices}

Provide recommendations in three categories:

## Immediate Actions (This Week)
- Quick wins that can be implemented immediately
- Focus on highest-risk items
- Include specific implementation steps

## Short-Term Improvements (This Quarter)
- Policy changes and their expected impact
- Technical controls to implement
- User education initiatives

## Strategic Changes (This Year)
- Long-term architectural improvements
- Consider passwordless authentication options
- Investment recommendations with ROI justification

For each recommendation:
1. Describe the action clearly
2. Explain what risk it mitigates
3. Estimate implementation effort (Low/Medium/High)
4. Estimate impact on security posture

Prioritize recommendations by impact-to-effort ratio."""


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
#   {risk_assessment_analysis} - Output from risk-assessment section
#   {recommendations_analysis} - Output from recommendations section
#   {raw_data_summary} - Summary of all raw JSON data available
#   {org_context} - Organizational context derived from the data

FULL_REPORT_PROMPT = """You are a senior security consultant preparing a comprehensive Password Security Assessment Report for executive leadership and the security team. You have access to complete audit data and five specialized AI analyses that have already been performed.

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

### 4. Risk Assessment
{risk_assessment_analysis}

### 5. Security Recommendations
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
        "title": "Weak Password Habits",
        "description": "AI analyzes raw passwords to discover predictable patterns and weak habits",
        "prompt_key": "WEAK_HABITS_PROMPT",
        "recommended_model": "llama3.1:70b",
        "temperature": 0.3,  # Lower temp for consistent, structured analysis
        "order": 1,
        "data_sources": {
            # Raw data for independent AI analysis
            "cracked_passwords": "derived:all_cracked_passwords",
            "account_passwords": "derived:account_password_pairs",
            "password_reuse": "derived:password_reuse_details",
            "org_context": "derived:organizational_context",
            "total_accounts": "derived:total_account_count",
            "cracked_count": "derived:cracked_account_count"
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
            "org_context": "derived:organizational_context",
            "total_accounts": "derived:total_account_count",
            "cracked_count": "derived:cracked_account_count"
        }
    },
    "risk-assessment": {
        "title": "Risk Assessment",
        "description": "Quantifies business and security risk",
        "prompt_key": "RISK_ASSESSMENT_PROMPT",
        "recommended_model": "deepseek-r1:70b",
        "temperature": 0.4,
        "order": 4,
        "data_sources": {
            "stats": "file:cracking_stats_table",
            "policy_failures": "derived:policy_failures",
            "critical_findings": "derived:critical_findings"
        }
    },
    "recommendations": {
        "title": "Security Recommendations",
        "description": "Prioritized actionable recommendations",
        "prompt_key": "RECOMMENDATIONS_PROMPT",
        "recommended_model": "llama3.1:70b",
        "temperature": 0.4,  # Slightly lower for more actionable, less verbose output
        "order": 5,
        "data_sources": {
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
            "risk_assessment_analysis": "session:ai_output_risk-assessment",
            "recommendations_analysis": "session:ai_output_recommendations",
            # Raw data summary for appendix
            "raw_data_summary": "derived:raw_data_summary",
            "org_context": "derived:organizational_context"
        }
    }
}
