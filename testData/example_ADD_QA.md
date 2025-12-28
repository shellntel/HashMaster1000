# Hash Master 1000 - ADD JSON QA Test Data Reference

**Files:** `example_ADD.json` + `example.potfile`

This document contains the expected values for all statistics when analyzing
`example_ADD.json` with `example.potfile`. Use these values to verify that
Hash Master 1000's ADD JSON reports and calculations are correct.

**Generated:** December 2025
**Domain:** testcorp.local

---

## Domain Policy Settings

| Setting | Value | Notes |
|---------|-------|-------|
| Domain Name | testcorp.local | |
| Pull Date | 12/23/2025 | |
| Min Password Length | 12 | |
| Max Password Age | 90 days | |
| Password History Length | 24 | |
| Lockout Threshold | 5 attempts | |
| Lockout Duration | 30 minutes | |
| Lockout Observation Window | 30 minutes | |
| Password Properties | 1 | Complexity required |

---

## Overall Account Counts

| Metric | Value | Notes |
|--------|-------|-------|
| Total Accounts | 45 | |
| User Accounts | 41 | accounts NOT ending with `$` |
| Computer Accounts | 4 | accounts ending with `$` |

---

## Account Status

| Status | Count | Percentage | Notes |
|--------|-------|------------|-------|
| Enabled | 40 | 88.9% | |
| Disabled | 5 | 11.1% | Guest, krbtgt, disabled1, disabled2, disabled_admin |

### Disabled Accounts List

| Account | Type | Has Password |
|---------|------|--------------|
| Guest | Built-in | Blank |
| krbtgt | Service | Yes (uncracked) |
| disabled_admin | Former Domain Admin | Yes (cracked: Password1!) |
| disabled1 | Standard | Yes (cracked: Password1) |
| disabled2 | Standard | Yes (cracked: password1) |

---

## Privilege Level Breakdown

### Tier 0 Accounts (Highest Privilege)

| Account | RID | Groups | Status | Password Cracked |
|---------|-----|--------|--------|------------------|
| Administrator | 500 | Domain Admins, Enterprise Admins, Schema Admins, Administrators | Enabled | Yes: `password` |
| krbtgt | 502 | Denied RODC Password Replication Group | Disabled | No |
| ccammilleri_admin | 1101 | Domain Admins, Administrators | Enabled | Yes: `Winteriscoming!` |
| mwebb_admin | 1102 | Domain Admins, Administrators | Enabled | Yes: `Summertime2023` |
| jsantos_admin | 1103 | Enterprise Admins, Domain Admins | Enabled | No |
| disabled_admin | 1603 | Domain Admins, Administrators | Disabled | Yes: `Password1!` |

**Tier 0 Summary:**
- Total: 6 accounts
- Enabled: 4
- Disabled: 2 (krbtgt, disabled_admin)
- Cracked: 4 (Administrator, ccammilleri_admin, mwebb_admin, disabled_admin)

### Elevated Accounts

| Account | Groups | Status | Password Cracked |
|---------|--------|--------|------------------|
| rchen_admin | Backup Operators | Enabled | Yes: `Ihatepasswords1!` |
| svc_backup | Backup Operators | Enabled | No (hash: 2a2a2a...) |
| svc_veeam | Backup Operators | Enabled | No (same hash as svc_backup) |

**Elevated Summary:**
- Total: 3 accounts
- Enabled: 3
- Disabled: 0
- Cracked: 1

### Standard Accounts

- Total: 36 accounts (41 users - 6 tier0 - 3 elevated + 4 computer accounts = 36)
- Note: Computer accounts are typically considered standard/non-privileged

---

## Password Analysis (using example.potfile)

### Cracking Statistics

| Metric | Value | Notes |
|--------|-------|-------|
| Total User Accounts | 41 | Excluding computer accounts |
| Cracked Accounts | 31 | |
| Uncracked Accounts | 10 | |
| Crack Rate | 75.6% | |
| Blank Passwords | 3 | Guest (disabled), blankpw1, blankpw2 |

> **Note:** Blank password hash = `31d6cfe0d16ae931b73c59d7e0c089c0` (empty string).
> Guest account is disabled but has blank password.
> blankpw1 and blankpw2 are enabled with blank passwords.

### Accounts with Blank Passwords

| Account | Status | Notes |
|---------|--------|-------|
| Guest | Disabled | Built-in guest account |
| blankpw1 | Enabled | Security risk |
| blankpw2 | Enabled | Security risk |

### Uncracked Accounts (10 total)

| Account | Notes |
|---------|-------|
| krbtgt | Tier 0 - disabled |
| jsantos_admin | Tier 0 - Enterprise Admin |
| svc_backup | Elevated - Backup Operators (shares hash with svc_veeam) |
| svc_veeam | Elevated - Backup Operators (shares hash with svc_backup) |
| uncracked1 | Standard |
| uncracked2 | Standard |
| uncracked3 | Standard |

---

## Admin/User Pair Password Sharing (CRITICAL FINDINGS)

These are cases where an admin account shares a password with its standard user counterpart:

| Admin Account | User Account | Password | Level |
|---------------|--------------|----------|-------|
| ccammilleri_admin | ccammilleri | Winteriscoming! | Tier 0 |
| mwebb_admin | mwebb | Summertime2023 | Tier 0 |
| jsantos_admin | jsantos | (uncracked - same hash) | Tier 0 |
| rchen_admin | rchen | Ihatepasswords1! | Elevated |

---

## Service Account Password Sharing

### SQL Services (3 accounts, same cracked password)

| Account | Password | Hash |
|---------|----------|------|
| svc_sql | Springfield1! | 09fb5dda3f095a3e0c7f024f38dd267e |
| svc_sqlrs | Springfield1! | 09fb5dda3f095a3e0c7f024f38dd267e |
| svc_sqlagent | Springfield1! | 09fb5dda3f095a3e0c7f024f38dd267e |

### IIS Services (2 accounts, same cracked password)

| Account | Password | Hash |
|---------|----------|------|
| svc_iis | Springfield23 | 427fbae0cd25256f4c2931740993032d |
| svc_iisadmin | Springfield23 | 427fbae0cd25256f4c2931740993032d |

### Backup Services (2 accounts, same UNCRACKED password)

| Account | Password | Hash |
|---------|----------|------|
| svc_backup | (uncracked) | 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a |
| svc_veeam | (uncracked) | 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a |

### SCCM Services (2 accounts, same cracked password)

| Account | Password | Hash |
|---------|----------|------|
| svc_sccm | 2Manypasswords | 43b80e99dd98fd05c1205299d0c9f7b1 |
| svc_sccmna | 2Manypasswords | 43b80e99dd98fd05c1205299d0c9f7b1 |

### Standalone Service Accounts

| Account | Password | Hash |
|---------|----------|------|
| svc_sharepoint | Springvale3 | 431073161988600bbb0a7f227cc4c58b |

---

## Shared Password Analysis

### Passwords Used by Multiple Accounts

| Hash | Password | Accounts | Count |
|------|----------|----------|-------|
| 31d6cfe0d16ae931b73c59d7e0c089c0 | (blank) | Guest, blankpw1, blankpw2 | 3 |
| e2e3e4693a5ac4c963ddc0ce9ffaf110 | Winteriscoming! | ccammilleri_admin, ccammilleri | 2 |
| 01fda8996358026baa397fe2c34b8e31 | Summertime2023 | mwebb_admin, mwebb | 2 |
| 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f | (uncracked) | jsantos_admin, jsantos | 2 |
| bfc1e1e00991f2ad57cd8cb928884eb9 | Ihatepasswords1! | rchen_admin, rchen | 2 |
| 09fb5dda3f095a3e0c7f024f38dd267e | Springfield1! | svc_sql, svc_sqlrs, svc_sqlagent | 3 |
| 427fbae0cd25256f4c2931740993032d | Springfield23 | svc_iis, svc_iisadmin | 2 |
| 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a | (uncracked) | svc_backup, svc_veeam | 2 |
| 43b80e99dd98fd05c1205299d0c9f7b1 | 2Manypasswords | svc_sccm, svc_sccmna | 2 |
| 5835048ce94ad0564e29a924a03510ef | password1 | disabled2, shortpw | 2 |

### Critical: Privileged Account Password Sharing

| Finding | Severity |
|---------|----------|
| ccammilleri_admin (Tier 0) shares password with ccammilleri (standard user) | CRITICAL |
| mwebb_admin (Tier 0) shares password with mwebb (standard user) | CRITICAL |
| jsantos_admin (Tier 0) shares password with jsantos (uncracked but same hash) | CRITICAL |
| rchen_admin (Elevated) shares password with rchen (standard user) | HIGH |
| Administrator uses trivial password `password` | CRITICAL |

---

## Historical Password Analysis

### Accounts with Password History

| Account | Current Hash Cracked | Historical Hashes | Cracked Historical |
|---------|---------------------|-------------------|-------------------|
| Administrator | Yes (password) | 2 | Yes: Password1, password1 |
| ccammilleri_admin | Yes (Winteriscoming!) | 1 | Yes: Winter2022 |
| arichardson | Yes (Summer2022!) | 1 | Yes: Summer2022 |
| ewatson | Yes (Falltime2022) | 1 | Yes: Winter2018! |
| dmiller | Yes (Carespring5000) | 2 | Yes: Summer2022, Winter2022 |
| reuseuser | Yes (Winter2022) | 3 | Yes: Winter2021, Winter2022, Winter2023 |
| histuser | Yes (Summer2022) | 4 | Yes: Summer2022!, Summer2023, Winter2018!, Winter2023 |

**Historical Hash Statistics:**
- Accounts with history: 7
- Total historical hashes: 14
- Cracked historical hashes: 14 (100%)

### Password Reuse Violations

| Account | Violation |
|---------|-----------|
| reuseuser | Current password `Winter2022` matches a historical password |

---

## Password Policy Compliance

### Fails Minimum Length (12 characters)

| Account | Password | Length |
|---------|----------|--------|
| Administrator | password | 8 |
| disabled2 | password1 | 9 |
| shortpw | password1 | 9 |

**Total failing minimum length:** 3 accounts

### Fails Max Password Age (90 days)

Based on PwdLastSet dates older than 90 days from pull date (12/23/2025):

| Account | PwdLastSet | Days Old |
|---------|------------|----------|
| oldpw | 03/01/2024 | ~663 days |
| svc_sql | 01/15/2020 | ~1,803 days |
| svc_sqlrs | 01/15/2020 | ~1,803 days |
| svc_sqlagent | 01/15/2020 | ~1,803 days |
| svc_iis | 02/01/2020 | ~1,786 days |
| svc_iisadmin | 02/01/2020 | ~1,786 days |
| svc_backup | 03/01/2020 | ~1,757 days |
| svc_veeam | 03/01/2020 | ~1,757 days |
| svc_sccm | 04/01/2020 | ~1,726 days |
| svc_sccmna | 04/01/2020 | ~1,726 days |
| svc_sharepoint | 05/01/2020 | ~1,696 days |

> Note: Service accounts have DONT_EXPIRE_PASSWORD flag set, so they may not be subject to policy.

---

## Computer Accounts

| Account | Type | Domain Group |
|---------|------|--------------|
| WORKSTATION01$ | Workstation | Domain Computers |
| WORKSTATION02$ | Workstation | Domain Computers |
| SERVER01$ | Server | Domain Computers |
| DC01$ | Domain Controller | Domain Controllers |

---

## Service Accounts

| Account | Groups | Password Expires | Cracked |
|---------|--------|------------------|---------|
| svc_sql | SQL Admins | Never | Yes: Springfield1! |
| svc_sqlrs | SQL Admins | Never | Yes: Springfield1! |
| svc_sqlagent | SQL Admins | Never | Yes: Springfield1! |
| svc_iis | Domain Users | Never | Yes: Springfield23 |
| svc_iisadmin | Domain Users | Never | Yes: Springfield23 |
| svc_backup | Backup Operators | Never | No |
| svc_veeam | Backup Operators | Never | No |
| svc_sccm | Domain Users | Never | Yes: 2Manypasswords |
| svc_sccmna | Domain Users | Never | Yes: 2Manypasswords |
| svc_sharepoint | Domain Users | Never | Yes: Springvale3 |

---

## Expected Validation Results (Step 2)

### ADD JSON Validation

| Result | Value | Notes |
|--------|-------|-------|
| Valid Format | Yes | |
| Domain Name | testcorp.local | |
| User Count | 45 | |
| Error Users | 0 | no errors expected |

### Summary Cards Should Show

| Card | Value |
|------|-------|
| Total Users | 45 |
| Valid Users | 45 |
| Tier 0 Accounts | 6 |
| Elevated Accounts | 3 |
| Computer Accounts | 4 |
| Users with History | 7 |
| Historical Hashes | 14 |

---

## Expected Report Page Statistics

### Cracked Privileged Account Passwords Section

Should show 5 entries (Tier 0 + Elevated with cracked passwords):

| Account | Level | Password |
|---------|-------|----------|
| Administrator | Tier 0 | password |
| ccammilleri_admin | Tier 0 | Winteriscoming! |
| mwebb_admin | Tier 0 | Summertime2023 |
| disabled_admin | Tier 0 | Password1! |
| rchen_admin | Elevated | Ihatepasswords1! |

### Privileged Accounts Summary Table

| Level | Total | Enabled | Cracked |
|-------|-------|---------|---------|
| Tier 0 | 6 | 4 | 4 |
| Elevated | 3 | 3 | 1 |

---

## Filter Testing Scenarios

### Individual Filters

| Filter | Accounts Analyzed | Calculation |
|--------|-------------------|-------------|
| Ignore Disabled Accounts | 40 | 45 - 5 disabled |
| Ignore Computer Accounts | 41 | 45 - 4 computer accounts |
| Ignore Blank Passwords | 42 | 45 - 3 blank passwords |

### All Three Filters Combined

**Breakdown of overlapping accounts:**
- Guest is both disabled AND has blank password
- No computer accounts have blank passwords
- No computer accounts are disabled

**Calculation:**
```
Total removed = 5 disabled + 4 computers + 3 blank - 1 overlap (Guest)
             = 5 + 4 + 3 - 1 = 11
Accounts analyzed with all filters: 45 - 11 = 34
```

---

## Password Pattern Analysis (Dictionary/Substring Hits)

### Seasonal Passwords

| Pattern | Accounts |
|---------|----------|
| Summer | arichardson, histuser, dmiller, svc_sql (Springfield), svc_iis (Springfield) |
| Winter | ccammilleri_admin, ewatson, reuseuser, mwebb_admin (Summertime) |
| Fall | ewatson (Falltime), oldpw |
| Spring | svc_sql, svc_sqlrs, svc_sqlagent (Springfield), svc_iis, svc_iisadmin (Springfield), svc_sharepoint (Springvale) |

### Common Words/Phrases

| Pattern | Accounts |
|---------|----------|
| password | Administrator, disabled1, disabled2, shortpw, svc_sccm (2Manypasswords), rchen (Ihatepasswords) |
| 2022/2023 | Multiple accounts with year patterns |

---

## Test Scenarios Checklist

- [ ] Domain policy displays correctly in validation step
- [ ] Tier 0 accounts correctly identified (6 total)
- [ ] Elevated accounts correctly identified (3 total)
- [ ] Admin/User password sharing detected (4 pairs)
- [ ] Service account password sharing detected (SQL: 3, IIS: 2, Backup: 2, SCCM: 2)
- [ ] Historical hash analysis shows 7 users with history
- [ ] Password reuse violations detected (reuseuser)
- [ ] Blank passwords identified (3 accounts)
- [ ] Disabled accounts filtered correctly (5 accounts)
- [ ] Computer accounts filtered correctly (4 accounts)
- [ ] Password length violations detected (3 accounts < 12 chars)
- [ ] Cracked privileged accounts table populates with 5 entries
- [ ] Password blur toggle works on privileged accounts table
- [ ] Shared password analysis shows correct counts
- [ ] Service accounts identified with DONT_EXPIRE_PASSWORD flag
- [ ] Privileged-to-standard password sharing alerts work (critical findings)

---

## Hash Reference Table

Key hashes used in this test file:

| NTLM Hash | Password | Used By |
|-----------|----------|---------|
| 8846f7eaee8fb117ad06bdd830b7586c | password | Administrator |
| 31d6cfe0d16ae931b73c59d7e0c089c0 | (blank) | Guest, blankpw1, blankpw2 |
| e2e3e4693a5ac4c963ddc0ce9ffaf110 | Winteriscoming! | ccammilleri_admin, ccammilleri |
| 01fda8996358026baa397fe2c34b8e31 | Summertime2023 | mwebb_admin, mwebb |
| 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f | (uncracked) | jsantos_admin, jsantos |
| bfc1e1e00991f2ad57cd8cb928884eb9 | Ihatepasswords1! | rchen_admin, rchen |
| 09fb5dda3f095a3e0c7f024f38dd267e | Springfield1! | svc_sql, svc_sqlrs, svc_sqlagent |
| 427fbae0cd25256f4c2931740993032d | Springfield23 | svc_iis, svc_iisadmin |
| 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a | (uncracked) | svc_backup, svc_veeam |
| 43b80e99dd98fd05c1205299d0c9f7b1 | 2Manypasswords | svc_sccm, svc_sccmna |
| 431073161988600bbb0a7f227cc4c58b | Springvale3 | svc_sharepoint |
| 7facdc498ed1680c4fd1448319a8c04f | Password1! | disabled_admin |
| 64f12cddaa88057e06a81b54e73b949b | Password1 | disabled1 |
| 5835048ce94ad0564e29a924a03510ef | password1 | disabled2, shortpw |
| 7978dc8a66d8e480d9a86041f8409560 | Winter2022 | reuseuser |
| a3d7d25665f1146b56192b850fd57a93 | Summer2022 | histuser |
| ed300c710c12eb947f54c6f37e75d00e | (uncracked) | krbtgt |
