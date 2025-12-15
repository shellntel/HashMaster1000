# Hash Master 1000 - QA Test Data Reference

**Files:** `example_dcsync.txt` + `example.potfile`

This document contains the expected values for all statistics when analyzing
`example_dcsync.txt` with `example.potfile`. Use these values to verify that
Hash Master 1000's reports and calculations are correct.

**Generated:** December 2024
**Regenerate with:** `python testData/generate_dcsync_test.py`

---

## Overall Account Counts

| Metric | Value | Notes |
|--------|-------|-------|
| Total Accounts | 1050 | |
| User Accounts | 1000 | accounts NOT ending with `$` |
| Computer Accounts | 50 | accounts ending with `$` |

---

## Format Detection

| Metric | Value | Notes |
|--------|-------|-------|
| DCSynC Format Lines | 1050 | all accounts have status |
| Standard Format Lines | 0 | |
| Status Coverage | 100% | |

---

## Account Status

| Status | Count | Percentage |
|--------|-------|------------|
| Enabled | 840 | 80% |
| Disabled | 210 | 20% |

---

## Domain Distribution

| Domain | Total | Enabled | Disabled | Computer | Cracked | Blank |
|--------|-------|---------|----------|----------|---------|-------|
| example.com | 250 | 200 | 50 | 5 | 45 | 25 |
| acme.corp | 300 | 240 | 60 | 5 | 0 | 0 |
| company.net | 280 | 224 | 56 | 5 | 260 | 0 |
| contoso.com | 220 | 176 | 44 | 35 | 220 | 0 |
| **TOTALS** | **1050** | **840** | **210** | **50** | **525** | **25** |

---

## Password Analysis (when using example.potfile)

| Metric | Value | Notes |
|--------|-------|-------|
| Cracked Accounts | 525 | 50% crack rate |
| Uncracked Accounts | 525 | 50% |
| Blank Passwords | 25 | 2.4% |

> **Note:** Blank password hash = `31d6cfe0d16ae931b73c59d7e0c089c0` (empty string).
> The 25 blank passwords are counted as "cracked" because the hash maps to
> an empty password in the potfile.

---

## LM Hash Analysis

| Metric | Value | Notes |
|--------|-------|-------|
| Non-blank LM Hashes | 20 | |
| Blank LM Hash | 1030 | hash: `aad3b435b51404eeaad3b435b51404ee` |

> **Note:** Non-blank LM hashes indicate older password storage. These accounts
> have passwords stored in the legacy LM format which is significantly weaker.

---

## Shared Password Analysis

| Metric | Value | Notes |
|--------|-------|-------|
| Total Unique Hashes Used | 635 | |
| Passwords Used by >1 Acct | 25 | only 25 passwords are reused |
| Max Accounts per Password | 25 | the blank password |

### Top 10 Most Shared Passwords

| Accounts | Password |
|----------|----------|
| 25 | *(blank password)* |
| 17 | `Fall22221!` |
| 17 | `Carespring22` |
| 17 | `Winter2018!` |
| 17 | `Winter2023` |
| 17 | `password#1` |
| 17 | `Fall2022!@` |
| 16 | `Ihatepasswords!16` |
| 16 | `Coldwinter22` |
| 16 | `Redwinter22` |

---

## Password Length Distribution (cracked passwords only)

| Length | Accounts | Notes |
|--------|----------|-------|
| 0 | 25 | blank passwords |
| 8 | 2 | |
| 9 | 4 | |
| 10 | 187 | most common length |
| 11 | 98 | |
| 12 | 78 | |
| 13 | 24 | |
| 14 | 37 | |
| 15 | 17 | |
| 16 | 1 | |
| 17 | 34 | |
| 19 | 1 | |
| 20 | 1 | |
| 23 | 16 | |
| **Total** | **525** | |

---

## Filter Testing Scenarios

### Individual Filters

| Filter | Accounts Analyzed | Calculation |
|--------|-------------------|-------------|
| Ignore Disabled Accounts | 840 | 1050 - 210 disabled |
| Ignore Computer Accounts | 1000 | 1050 - 50 computer accounts |
| Ignore Blank Passwords | 1025 | 1050 - 25 blank passwords |

### All Three Filters Combined

Need to calculate overlap:
- All 25 blank passwords are in example.com
- 5 blank passwords are disabled (`line_num % 5 == 0` for lines 0,5,10,15,20)
- 1 blank password is a computer account (`WORKSTATION0000$`)
- The computer account with blank password IS disabled (line 0)

**Breakdown of 25 blank passwords:**
- 1 disabled computer account (`WORKSTATION0000$`)
- 4 disabled user accounts
- 20 enabled user accounts

**Calculation:**
```
Total removed = 210 disabled + (50-1) non-disabled computers + (25-5-1) non-disabled non-computer blanks
             = 210 + 49 + 19 = 278
Accounts analyzed with all filters: 1050 - 278 = 772
```

---

## Potfile Compatibility

The `example.potfile` contains 173 entries.

| Property | Value |
|----------|-------|
| Format | All NTLM (mode 1000) |
| Non-NTLM entries | 0 |
| Hashes used in example_dcsync.txt | 143 (including blank) |
| Hashes reused across accounts | 24 |

---

## Hash Reuse Patterns (for Substring/Dictionary Analysis)

Common password patterns in the dataset:
- Season + Year combinations (`Summer2022`, `Winter2021`, `Fall2022`, `Spring2023`)
- "Password" prefix variations (`Password1`, `Password123`, `Password#1`)
- Seasonal variations (`Summertime`, `Falltime`, `Springtime`)

These patterns should be detected by:
- **Substring Analysis:** Common character sequences
- **Dictionary Analysis:** Common word patterns

---

## Expected Validation Results (Step 2)

### Pwdump File Validation

| Result | Count | Notes |
|--------|-------|-------|
| Valid Lines | 1050 | |
| Warning Lines | 0 | no warnings expected |
| Error Lines | 0 | no errors expected |

### Format Detection

| Format | Count |
|--------|-------|
| With Status | 1050 (dcsync format) |
| Without Status | 0 (standard format) |

### Summary Cards Should Show

| Card | Value |
|------|-------|
| Computer Accounts | 50 |
| Blank Passwords | 25 |
| Disabled Accounts | 210 |

---

## Expected Configuration Page (Step 3) Filter Counts

Account Filtering section should display:
- "Ignore Disabled Accounts (210)"
- "Ignore Computer Accounts (50)"
- "Ignore Blank Passwords (25)"

---

## File Format

All lines use dcsync format:
```
domain\username:RID:LM_HASH:NTLM_HASH::: (status=Enabled|Disabled)
```

**Example lines:**
```
example.com\Joseph.Wilson:1:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Enabled)
example.com\WORKSTATION0000$:0:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
```

---

## Regenerating Test Data

To regenerate the test file with the same deterministic data:

```bash
cd /path/to/hm1k
python testData/generate_dcsync_test.py
```

This will:
1. Overwrite `testData/example_dcsync.txt`
2. Print comprehensive statistics to stdout
3. Use the same algorithm to produce identical output
