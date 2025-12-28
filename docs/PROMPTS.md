# HM1K Prompt Architecture

This document describes the AI prompt system used in HM1K for password audit analysis. Understanding this architecture is essential for tuning prompt behavior and debugging output quality issues.

## Overview

HM1K uses a **3-phase pipeline** for generating AI analysis reports:

```
Phase 1: Analysis     →  Phase 2: Validation  →  Phase 3: Formatting
(Generate insights)      (Fact-check)            (Polish for report)
```

Each phase has specific prompts, models, and responsibilities.

---

## Phase 1: Analysis Prompts

**Purpose:** Generate initial analysis from raw password data.

**Location:** `ollama_prompts.py` - Section-specific prompts

**Model:** Varies by section (see PHASE_CONFIG)

### Available Sections

| Section ID | Prompt | Model | Purpose |
|------------|--------|-------|---------|
| `weak-habits` | `WEAK_HABITS_PROMPT` | llama3.1:70b | Discover password patterns and weak habits |
| `company-intel` | `COMPANY_INTEL_PROMPT` | deepseek-r1:671b | Infer company identity, location, industry |
| `user-behavior` | `USER_BEHAVIOR_PROMPT` | deepseek-r1:671b | Analyze user psychology and behavior |
| `recommendations` | `RECOMMENDATIONS_PROMPT` | deepseek-r1:671b | Generate prioritized security recommendations |
| `full-report` | `FULL_REPORT_PROMPT` | deepseek-r1:671b | Synthesize all sections into executive report |

### WEAK_HABITS_PROMPT

**Input Variables:**
- `{total_accounts}` - Total accounts in audit
- `{cracked_count}` - Number cracked
- `{org_context}` - Domain names, account types detected
- `{length_distribution}` - Password length statistics
- `{cracked_passwords}` - All cracked passwords (raw)
- `{account_passwords}` - Username:password pairs
- `{password_reuse}` - Passwords shared across accounts

**Expected Output Format:**
```markdown
### 1. [Pattern Name]
**Description:** One sentence explaining the pattern.
**Examples:** `example1`, `example2`, `example3`
**Prevalence:** N accounts (X%) OR "Not measured"
**Relative Rank:** High/Medium/Low
**Attack Risk:** How attackers exploit this.
**Psychology:** Why users choose this.
```

**Anti-Hallucination Rules (Critical):**
The prompt includes prominent warnings to prevent the model from inventing passwords:
- `⚠️ CRITICAL: DO NOT INVENT PASSWORDS ⚠️` at the top
- Explicit list of known hallucinations to avoid: `kp39a`, `qpf02`, `IPCw0rks`, etc.
- Rule: "If you cannot find 2+ real examples for a pattern, skip the pattern entirely"
- Data section labeled: "ALL CRACKED PASSWORDS (use ONLY these as examples)"

**Key Behaviors:**
- Should discover 8-12 distinct patterns
- Must include actual password examples (never mask)
- Examples MUST come from the provided data - no invented passwords
- Prevalence should only be computed if evidence supports it
- "Not measured" is preferred over guessing
- Domain names (e.g., "electronics.org") are NOT passwords - they're account identifiers

### COMPANY_INTEL_PROMPT

**Input Variables:**
- `{total_accounts}`, `{cracked_count}`
- `{org_context}` - Domain/account context
- `{account_names}` - All usernames
- `{cracked_passwords}` - All cracked passwords

**Expected Output Format:**
```markdown
### 1. Company Identity
**Finding:** What company name/brands appear
**Evidence:** `password1`, `password2`
**Confidence:** High/Medium/Low - justification
```

**Key Behaviors:**
- 5 fixed sections: Company Identity, Industry, Location, Culture, Security Posture
- Confidence must match evidence strength
- "Insufficient evidence" is valid when data doesn't support inference

### USER_BEHAVIOR_PROMPT

**Input Variables:**
- Same as WEAK_HABITS plus `{password_reuse}`

**Expected Output Format:**
```markdown
### 1. Memorability vs Security
**Observation:** What was observed
**Examples:** `password1`, `password2`
**Psychology:** Why users do this
**Risk:** Security implications
**Recommendation:** Training approach
```

**Key Behaviors:**
- 7 fixed sections covering behavioral patterns
- Every section must include Examples, Psychology, Risk, Recommendation
- Focus on insights that inform security awareness training

### RECOMMENDATIONS_PROMPT

**Input Variables:**
- `{audit_stats}` - Summary statistics
- `{key_findings}` - Critical issues found
- `{current_policy}` - Password policy if known
- `{worst_practices}` - Flagged bad practices

**Expected Output Format:**
```markdown
### Immediate Actions (This Week)
**1. [Action Title]**
- **Action:** Steps to implement
- **Mitigates:** Risk addressed
- **Effort:** Low/Medium/High
- **Impact:** High/Medium/Low
```

**Key Behaviors:**
- 3 time horizons: Immediate, Short-Term, Strategic
- Must respect account status (don't recommend disabling already-disabled accounts)
- Should prioritize by impact-to-effort ratio

---

## Phase 2: Validation Prompts

**Purpose:** Fact-check Phase 1 output against evidence. Catch hallucinations and technical errors.

**Location:** `ollama_prompts.py` - `VALIDATION_PROMPT_*` and `get_validation_prompt()`

**Model:** Dynamic - determined by Tier-0 gating (see below)

### Tier-0 Gating (Pre-Validation)

Before invoking expensive LLM validation, a fast deterministic precheck runs to decide:
1. **Skip validation entirely** - if content appears clean
2. **Use fast model (llama3.1:70b)** - for simple issues
3. **Use reasoning model (deepseek-r1:671b)** - for complex issues

**Location:** `ollama_tools.py` - `Tier0Validator` class

#### Tier-0 Pattern Detection

| Pattern ID | Detects | Action |
|------------|---------|--------|
| `MASKED_PASSWORD` | `***`, `••••` patterns | Requires validation |
| `UNWANTED_SECTION` | "Risk Prioritization Framework" | Requires validation |
| `SPECIFIC_PERCENTAGE` | `\d+%` claims | Requires validation |
| `SPECIFIC_COUNT` | "N accounts/users" claims | Requires validation |
| `CLOUD_TERM` | Azure AD, Entra ID, Okta, etc. | Requires validation (recommendations) |
| `FORCED_ROTATION` | Periodic rotation language | Requires validation (recommendations) |
| `POLICY_LANGUAGE` | "policy requires", "must comply" | Requires validation (recommendations) |

#### Section-Specific Rules

| Section | Patterns Checked |
|---------|------------------|
| weak-habits | MASKED_PASSWORD, SPECIFIC_PERCENTAGE, SPECIFIC_COUNT |
| company-intel | MASKED_PASSWORD, SPECIFIC_PERCENTAGE |
| user-behavior | MASKED_PASSWORD, UNWANTED_SECTION, SPECIFIC_PERCENTAGE, SPECIFIC_COUNT |
| recommendations | CLOUD_TERM, FORCED_ROTATION, POLICY_LANGUAGE |

#### Routing Logic

```
No flags fired → Skip LLM validation (confidence: 0.95)
Simple flags only → Use llama3.1:70b (fast)
Complex flags → Use deepseek-r1:671b (reasoning)
```

### Claim Extraction (User Behavior Only)

For `user-behavior` section, instead of validating full prose, Tier-0 extracts specific claims:
- Percentage claims: "40% of users..."
- Count claims: "14 accounts..."
- Behavioral assertions: "users tend to...", "most users..."

These claims are validated as a focused list, dramatically reducing prompt size and reasoning load.

**Location:** `ollama_tools.py` - `_run_claim_validation()` method

### Validation Philosophy

All validators follow these principles (documented in code comments):

1. **No Invention:** Never invent facts, policies, metrics, counts, or percentages
2. **Evidence-Based:** If a number isn't in evidence, mark it unsupported
3. **No Mitigated Actions:** Don't recommend actions on already-fixed issues
4. **AD Realism:** Keep recommendations feasible in on-prem Active Directory
5. **No Outdated Guidance:** Flag forced password rotation without justification
6. **Preserve Passwords:** Never mask or redact - this is an audit report

### Section-Specific Validators

#### VALIDATION_PROMPT_WEAK_HABITS

**Validates:**
- **Hallucination Check (Priority #1):** Every password example must exist in the PASSWORD WHITELIST
- Username-password relationships actually match (e.g., "jsmith" → "Jsmith123!" valid, "zhouro" → "Winter2468#" invalid)
- Pattern examples match their category
- Prevalence claims are within 20% of evidence
- Password examples are preserved (never masked)
- Domain names are NOT listed as password examples

**Password Whitelist:**
The evidence pack includes a definitive list of all valid passwords extracted from:
- `pw_top_passwords.json`
- `pw_bad_practices.json`
- `pw_reuse_table.json`

Validators are instructed to check EVERY password example against this whitelist and remove any that don't appear.

**Issue Types:** `HALLUCINATION_CHECK`, `wrong_example`, `invented_statistic`, `pattern_mismatch`, `USERNAME_PASSWORD_RELATIONSHIPS`

#### VALIDATION_PROMPT_COMPANY_INTEL

**Validates:**
- Company name inferences have password evidence
- Geographic claims are supported (city names, sports teams, area codes)
- HIGH confidence claims have strong evidence (multiple passwords)

**Issue Types:** `unsupported_inference`, `wrong_confidence`, `contradicts_evidence`

#### VALIDATION_PROMPT_USER_BEHAVIOR

**Validates:**
- Behavioral claims are supported by patterns
- Risk levels match threat severity
- Statistical claims match evidence

**Special Rule:** Removes "Risk Prioritization Framework" section entirely

**Issue Types:** `invented_statistic`, `irrelevant_section`, `risk_mismatch`

#### VALIDATION_PROMPT_RECOMMENDATIONS

**Validates:**
- No recommendations for already-mitigated issues
- AD Realism checks:
  - "Enforce password uniqueness" is NOT native AD
  - Cloud/third-party dependencies must be explicit
  - Prefer: Group Policy, FGPP, PAM/PAW tiering
- No outdated guidance (forced rotation without justification)
- No scope creep to cloud without explicit scope

**Issue Types:** `already_mitigated`, `not_feasible`, `wrong_priority`, `outdated_guidance`, `scope_creep`

### Validation Output Format

Validators use a **differential output** format to minimize token usage:

**If NO issues found:**
```json
{"issues":[],"confidence":0.95,"needs_human_review":false}
```

**If issues found (find/replace format):**
```json
{
  "issues": [
    {
      "rule_id": "NO_INVENTED_NUMBERS|PATTERN_INTEGRITY|AD_REALISM|...",
      "type": "invented_statistic|example_mismatch|technical_inaccuracy|...",
      "severity": "high|medium|low",
      "location": "Section or pattern name",
      "find": "exact text to replace",
      "replace": "corrected text or empty string to remove"
    }
  ],
  "confidence": 0.8,
  "needs_human_review": false
}
```

**Key optimization:** The `corrected_content` field is only included for complex structural changes. For simple fixes, the pipeline applies find/replace patches client-side, reducing output tokens by 60-80%.

---

## Phase 3: Formatting Prompts

**Purpose:** Polish validated content into consistent, executive-ready format.

**Location:** `ollama_prompts.py` - `FORMATTING_PROMPT_*` and `get_formatting_prompt()`

**Model:** llama3.1:70b (fast, good at following format instructions)

### Formatting Rules (All Sections)

1. **No New Content:** Only reformat what exists - never add facts or statistics
2. **Preserve Passwords:** Keep all password examples, use backticks for highlighting
3. **Clean Markdown:** No JSON, no "VALIDATED CONTENT" headers, no preamble

### Section-Specific Formats

#### FORMATTING_PROMPT_WEAK_HABITS

```markdown
### Pattern Name
Description paragraph.

**Examples:** `password1`, `password2`, `password3`

**Prevalence:** N accounts (X%)

**Risk:** Brief risk statement
```

- 5-10 examples per pattern when available
- Passwords highlighted with backticks

#### FORMATTING_PROMPT_COMPANY_INTEL

```markdown
### Finding Name

**Finding:** The intelligence finding

**Evidence:** `password1`, `password2`

**Confidence:** HIGH/MEDIUM/LOW with explanation
```

- Each field on its own line with blank line between
- Finding, Evidence, Confidence always present

#### FORMATTING_PROMPT_USER_BEHAVIOR

```markdown
### Behavior Pattern Name

**Observation:** What was observed

**Examples:** `password1`, `password2`

**Risk:** Risk level and explanation

**Recommendation:** Suggested action
```

- Each field on its own line with blank line between
- Removes "Risk Prioritization Framework" if still present
- Observation, Examples, Risk, Recommendation always present

#### FORMATTING_PROMPT_RECOMMENDATIONS

```markdown
### Recommendation Title

**Priority:** Critical/High/Medium/Low
**Effort:** Low/Medium/High
**Impact:** Description

Detailed recommendation text.

**Implementation Steps:**
1. Step one
2. Step two
```

- Priority/Effort/Impact at top, on separate lines
- Never change existing ratings

---

## Phase Configuration

**Location:** `ollama_prompts.py` - `PHASE_CONFIG` and `get_phase_config()`

Each section has configuration for all 3 phases:

```python
"section-id": {
    "phase1": {"model": "model_name", "temperature": 0.3},
    "phase2": {"model": "deepseek-r1:671b", "temperature": 0.2, "enabled": True},
    "phase3": {"model": "llama3.1:70b", "temperature": 0.15, "enabled": True},
    "evidence_sources": ["source1", "source2"]
}
```

### Current Configuration

| Section | Phase 1 Model | Phase 1 Temp | Notes |
|---------|---------------|--------------|-------|
| weak-habits | llama3.1:70b | 0.3 | Faster, good pattern discovery |
| company-intel | deepseek-r1:671b | 0.3 | Better inference, worth the time |
| user-behavior | deepseek-r1:671b | 0.4 | More insightful behavioral analysis |
| recommendations | deepseek-r1:671b | 0.4 | Better actionable output |
| full-report | deepseek-r1:671b | 0.5 | Synthesis requires reasoning |

Phase 2 model is **dynamically selected** by Tier-0 gating:
- No flags → Skipped entirely
- Simple flags → llama3.1:70b (fast)
- Complex flags → deepseek-r1:671b (reasoning)

Phase 3 always uses llama3.1:70b at temperature 0.15 (formatting consistency).

---

## Data Flow

### Evidence Pack

Phase 2 validators receive an "evidence pack" built from:
- `cracking_stats_table.json` - Core statistics
- `pw_top_passwords.json` - Most common passwords
- `pw_bad_practices.json` - Flagged issues
- `pw_length_distribution.json` - Length stats
- `pw_reuse_table.json` - Password sharing
- **Password Whitelist** (weak-habits only) - Definitive list of all valid passwords

The `EvidencePackBuilder` class in `ollama_tools.py` assembles this. For the `weak-habits` section, it also builds a password whitelist by extracting all passwords from the top passwords, bad practices, and reuse table files. This whitelist is included in the evidence pack to enable systematic hallucination detection.

### Debug Output

When `AI_PIPELINE_DEBUG=true` in `.env`, each phase saves output to the **session-specific** ai_analysis folder:

```
data/sessions/<session_id>/ai_analysis/
  weak-habits_phase1_raw_YYYYMMDD_HHMMSS.md
  weak-habits_tier0_precheck_YYYYMMDD_HHMMSS.md
  weak-habits_phase2_validated_YYYYMMDD_HHMMSS.json
  weak-habits_phase3_final_YYYYMMDD_HHMMSS.md
```

**Note:** Debug output is stored per-session, not globally. This allows each analysis session to maintain its own isolated debug files.

**Tier-0 precheck output includes:**
```json
{
  "flags_fired": [["SPECIFIC_PERCENTAGE", "42%"], ...],
  "requires_llm": true,
  "suggested_model": "llama3.1:70b",
  "skip_reason": "",
  "extracted_claims_count": 5,
  "precheck_time_ms": 2
}
```

This enables:
1. Comparing Phase 1 vs Phase 3 output
2. Reviewing what validation changed
3. Understanding Tier-0 routing decisions
4. Using "Revalidate & Format" to re-run Phases 2+3 with cached Phase 1

---

## Tuning Guide

### Common Issues and Fixes

| Problem | Likely Cause | Fix |
|---------|--------------|-----|
| Invented statistics | Phase 1 hallucinating | Add "Not measured" guidance to Phase 1 prompt |
| Wrong examples in categories | Phase 2 not catching | Strengthen pattern-matching rules in validation |
| Content stripped | Phase 2 too aggressive | Add to "WHAT TO PRESERVE" list |
| Inconsistent formatting | Phase 3 not following template | Add explicit format examples |
| Outdated recommendations | Phase 2 missing checks | Add to AD Realism validation rules |

### Adding New Validation Rules

1. Add rule to the appropriate `VALIDATION_PROMPT_*`
2. Add new issue type to the `type` enum in OUTPUT FORMAT
3. Document in this file

### Changing Output Format

1. Update the appropriate `FORMATTING_PROMPT_*`
2. Include explicit markdown example of desired format
3. Test with "Revalidate & Format" using cached Phase 1

### Tuning Tier-0 Gating

To add new patterns that trigger validation:

1. Add pattern to `PROBLEM_PATTERNS` dict in `Tier0Validator`
2. Add pattern ID to appropriate section in `SECTION_RULES`
3. Decide if pattern is "simple" (fast model) or "complex" (reasoning model) in `_is_simple_fix()`

To make validation more/less aggressive:

| Goal | Change |
|------|--------|
| Skip more validations | Remove patterns from `SECTION_RULES` |
| Validate more content | Add patterns to `SECTION_RULES` |
| Use fast model more often | Add pattern IDs to `simple_rules` set |
| Use reasoning model more often | Add pattern IDs to `complex_rules` set |

### Performance Optimization

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Phase 2 still slow | Tier-0 always fires | Adjust pattern sensitivity or thresholds |
| Validation skipped incorrectly | Tier-0 patterns too narrow | Add missing problem patterns |
| Wrong model selected | Routing logic mismatch | Adjust `_is_simple_fix()` logic |
| User behavior still slow | Too many claims extracted | Reduce `CLAIM_THRESHOLD` or claim patterns |

---

## File Reference

| File | Contains |
|------|----------|
| `ollama_prompts.py` | All prompts, phase config, getter functions |
| `ollama_tools.py` | Pipeline runner, evidence builder, Tier-0 validator, API calls |
| `hm1k.py` | SSE endpoint, progress tracking, result storage |
| `session_manager.py` | Session management, data isolation per analysis |
| `data/sessions/<id>/ai_analysis/` | Debug output per session (when enabled) |
| `data/sessions/<id>/aaia_results.json` | Final report results per session |
| `data/sessions/<id>/*.json` | All analysis data files per session |

### Key Classes in `ollama_tools.py`

| Class | Purpose |
|-------|---------|
| `Tier0Validator` | Fast deterministic prechecks before LLM validation |
| `Tier0Result` | Dataclass for precheck results (flags, routing decision) |
| `EvidencePackBuilder` | Assembles evidence packs from JSON files |
| `AIPipelineRunner` | Orchestrates the 3-phase pipeline |
| `ValidationResult` | Dataclass for Phase 2 output |
| `PipelineResult` | Dataclass for full pipeline output |
