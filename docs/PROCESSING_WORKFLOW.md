# HashMaster1000 Processing Workflow

This document describes each step of the file processing workflow from file upload through report generation, including potential performance impacts for large datasets.

## Overview

The workflow consists of four main phases:
1. **File Upload & Validation** - Parse and validate input files
2. **Validation Review** - User reviews/filters entries
3. **Configuration & Processing** - Run analysis algorithms
4. **Report Generation** - Save results and render report

---

## Phase 1: File Upload & Validation

**Endpoint:** `POST /validate`
**Location:** `hm1k.py:863-1003`

### Step 1.1: File Upload
- Files are uploaded and saved to temporary storage
- **Time:** Negligible (disk I/O only)

### Step 1.2: Format Detection
- `file_parser.is_add_json_file()` checks if pwdump file is ADD JSON format
- Reads first 4KB to detect JSON structure
- **Time:** Negligible

### Step 1.3: Pwdump/ADD Validation

#### For Pwdump Files:
- `file_parser.validate_pwdump_file()` parses all lines
- Creates `ParsedLine` object for each line with:
  - Username, RID, LM hash, NTLM hash extraction
  - Format detection (pwdump, secretsdump, etc.)
  - Domain extraction from username
  - Error detection and categorization
- **Time:** O(n) where n = number of lines
- **Impact:** ~600K lines = 2-3 seconds

#### For ADD JSON Files:
- `file_parser.parse_add_json()` loads entire JSON
- Extracts user entries with NTLM hashes, historical hashes
- Analyzes privileges, domain info, UAC flags
- **Time:** O(m) where m = number of users
- **Impact:** Depends on JSON size and user count

### Step 1.4: Potfile Validation
- `file_parser.validate_potfile()` parses all lines
- For each line:
  - Split on first colon (hash:password)
  - **Hash type detection** via `get_most_likely_type()`
    - Iterates through 99 hash type patterns
    - Regex matching for each pattern
  - Categorizes as NTLM vs non-NTLM
- **Time:** O(p * h) where p = potfile lines, h = hash type patterns (99)
- **Impact:** ~750K lines = 3-5 seconds (dominated by hash type detection)

**OPTIMIZATION:** For master potfile (pre-validated NTLM-only), hash type detection is skipped entirely since we control its contents.

### Step 1.5: Hash Extraction
- Extract unique hashes from validated data for potfile matching
- `extract_hashes_from_pwdump()` or `extract_hashes_from_add()`
- **Time:** O(n) additional iteration
- **Impact:** ~600K lines = <1 second

### Step 1.6: Master Potfile Merge
- If master potfile enabled, merge new NTLM entries
- Uses cache for fast lookups
- **Time:** O(1) for cache hit, O(p) for cache miss/rebuild
- **Impact:** Cache hit is instant; cache miss = 1-2 seconds

### Step 1.7: Session Storage
- `validation_result_to_dict()` serializes all `ParsedLine` objects to JSON
- Stored in Flask session for validation review step
- **Time:** O(n) serialization
- **Impact:** ~600K objects = 3-5 seconds (JSON encoding overhead)

**Total Phase 1 Time:** 10-15 seconds for 600K pwdump + 750K potfile

---

## Phase 2: Validation Review

**Endpoint:** `GET /validation_review`
**Location:** `hm1k.py:1158-1199`

### Step 2.1: Load Session Data
- Validation results loaded from session storage
- **Time:** Depends on session backend (file/memory)

### Step 2.2: User Interaction
- User can include/exclude individual lines
- `update_selections()` endpoint updates session data
- **Time:** Per-interaction, negligible

### Step 2.3: Optional Re-validation
- `POST /validate_single` can re-parse individual files
- **Note:** This re-parses the entire file, not incremental
- **Time:** Same as initial validation for that file

**Total Phase 2 Time:** User-dependent (interactive)

---

## Phase 3: Configuration & Processing

**Endpoint:** `POST /process_validated`
**Location:** `hm1k.py:1366-1620`

### Step 3.1: Reconstruct Validation Results
- `dict_to_validation_result()` recreates `ValidationResult` from session
- **Time:** O(n) object creation
- **Impact:** ~600K lines = 2-3 seconds

### Step 3.2: Build Cracked Hashes Lookup

#### With Master Potfile (Optimized Path):
- `get_cracked_hashes_direct()` returns cached dict
- **Time:** O(1) cache access
- **Impact:** Instant

#### Without Master Potfile:
- `dict_to_potfile_result()` recreates ~750K `PotfileEntry` objects
- `build_cracked_hashes_fast()` iterates to build lookup dict
- **Time:** O(p) object creation + iteration
- **Impact:** 3-5 seconds

### Step 3.3: Build Account Data
- `build_account_data()` or `build_account_data_with_cache()`
- Matches pwdump accounts with cracked passwords
- Applies ignore_disabled/ignore_computer filters
- **Time:** O(n) where n = pwdump accounts
- **Impact:** ~600K accounts = 1-2 seconds

### Step 3.4: Domain Filtering (Optional)
- `filter_accounts_by_domain()` if domain filter specified
- **Time:** O(n) iteration
- **Impact:** <1 second

### Step 3.5: Statistical Analysis - `crack_stats()`
**Location:** `password_analysis_tools.py:304-516`

This is the **most expensive analysis function** due to multiple iterations:

| Operation | Lines | Iterations | Purpose |
|-----------|-------|------------|---------|
| `check_blank()` | 325-327 | 1x | Find blank passwords |
| Count cracked | 331-336 | 1x | Count accounts with passwords |
| Unique NTLM hashes | 346-351 | 1x | Build unique hash set |
| Cracked NTLM hashes | 354-367 | 1x | Build cracked hash set |
| Check blank in hashes | 363-367 | 1x | Check for blank hash |
| `lm_count()` | 374 | 1x | Count LM hashes |
| Password lengths | 392-399 | 1x | Build length list |
| Min length failures | 428-442 | 1x | Find short passwords |
| `get_non_compliant_accounts()` | 445 | 1x | Check complexity |
| `check_max_age()` | 457 | 1x | Check password age |
| Top passwords | 469-482 | 1x | Count password frequency |
| `get_lm_accounts()` | 485 | 1x | Get LM hash accounts |

**Total:** ~12 iterations over account_data
**Time:** O(12n) = O(n)
**Impact:** ~600K accounts × 12 passes = 5-10 seconds

**FUTURE OPTIMIZATION:** Consolidate into single-pass analysis to reduce to O(n).

### Step 3.6: Substring Analysis
**Location:** `password_analysis_tools.py:518-614`

- For each cracked password, generate all substrings of length [min, max]
- Build account→substring mapping
- Filter by frequency threshold
- Suppress nested substrings
- **Time:** O(c × L²) where c = cracked passwords, L = avg password length
- **Impact:** ~300K cracked passwords × avg 10 chars = 2-5 seconds

### Step 3.7: Dictionary Analysis
**Location:** `password_analysis_tools.py:617-692`

- Load English dictionary (~234K words, cached after first load)
- For each password, find dictionary word matches
- **Time:** O(c × W × L) where W = dictionary size
- **Impact:** 2-5 seconds (dictionary is cached)

### Step 3.8: Bad Practices Analysis
**Location:** `password_analysis_tools.py:695-1037`

- Check passwords against 13 bad practice categories
- Pattern matching for each category
- **Time:** O(c × P) where P = number of patterns (~50)
- **Impact:** 2-3 seconds

### Step 3.9: Password Reuse Check
**Location:** `password_analysis_tools.py:119-135` or `137-173`

#### Current Implementation (File-based):
- `check_pw_reuse(pwdump_path)` re-reads file from disk
- **Time:** O(n) file I/O + parsing
- **Impact:** 1-2 seconds (redundant disk read)

#### Optimized Implementation (Memory-based):
- `check_pw_reuse_from_account_data(account_data)` uses in-memory data
- **Time:** O(n) iteration only
- **Impact:** <1 second (no disk I/O)

**OPTIMIZATION APPLIED:** Use `check_pw_reuse_from_account_data()` instead.

### Step 3.10: Password History Analysis
**Location:** `password_history.py:915-993`

- Extract history entries from pwdump (_history suffixes) or ADD JSON
- Detect patterns: incrementing numbers, seasons, year rotation, etc.
- **Time:** O(u × h) where u = users with history, h = history depth
- **Impact:** Usually <1 second (few users have history data)

### Step 3.11: Create Analysis Session
- `session_manager.create_session()` creates new session folder
- Compute source hash for staleness detection
- **Time:** Negligible

### Step 3.12: Save Session Data Files
- 20+ `save_session_data()` calls write JSON files
- Files include: stats, charts, account_data, validation data
- **Time:** O(total_data_size) disk I/O
- **Impact:** 2-5 seconds (sequential writes)

**FUTURE OPTIMIZATION:** Batch/parallel file writes.

**Total Phase 3 Time:** 20-40 seconds for 600K accounts

---

## Phase 4: Report Generation

**Endpoint:** `GET /report`
**Location:** `hm1k.py:1712-1896`

### Step 4.1: Load Session Data
- Load pre-computed JSON files from session folder
- **Time:** O(file_sizes) disk I/O
- **Impact:** <1 second per file

### Step 4.2: Render Template
- Jinja2 template rendering with data
- **Time:** Negligible

### Step 4.3: Client-Side Rendering
- Chart.js renders visualizations
- DataTables loads table data
- **Time:** Client-dependent

**Total Phase 4 Time:** 1-3 seconds server-side

---

## Performance Summary

| Phase | Operation | Time (600K accounts) |
|-------|-----------|---------------------|
| 1 | Pwdump validation | 2-3s |
| 1 | Potfile validation | 3-5s |
| 1 | Session serialization | 3-5s |
| 3 | Reconstruct validation | 2-3s |
| 3 | Build account data | 1-2s |
| 3 | `crack_stats()` | 5-10s |
| 3 | Substring analysis | 2-5s |
| 3 | Dictionary analysis | 2-5s |
| 3 | Bad practices | 2-3s |
| 3 | Password reuse | <1s (optimized) |
| 3 | Save session files | 2-5s |
| **Total** | | **~25-45s** |

---

## Optimization History

### Applied Optimizations

1. **Master Potfile Cache** (`potfile_cache.py`)
   - Caches hash→password lookup dict
   - Skips `PotfileEntry` object creation for cached potfiles
   - **Savings:** 3-5 seconds

2. **Skip Hash Type Detection for Master Potfile**
   - Master potfile is NTLM-only by design
   - No need for 99-pattern hash type detection
   - **Savings:** 3-5 seconds on potfile validation

3. **Use `check_pw_reuse_from_account_data()`**
   - Eliminates redundant file re-read
   - Uses in-memory account_data
   - **Savings:** 1-2 seconds

4. **In-place Blank Hash Addition**
   - Changed `{BLANK_HASH: "", **cracked_hashes}` to `cracked_hashes[BLANK_HASH] = ""`
   - Avoids copying 750K dict
   - **Savings:** <1 second

### Future Optimization Opportunities

1. **Single-Pass `crack_stats()`**
   - Consolidate 12 iterations into one pass
   - **Potential savings:** 3-5 seconds

2. **Parallel JSON File Writes**
   - Use thread pool for independent file writes
   - **Potential savings:** 1-2 seconds

3. **Streaming Validation**
   - Process files in chunks with progress updates
   - **UX improvement:** Better feedback during long operations

4. **Reduced Session Serialization**
   - Store only necessary fields in session
   - Don't serialize raw_line for every entry
   - **Potential savings:** 2-3 seconds

---

## Appendix: Key Functions Reference

| Function | File | Purpose |
|----------|------|---------|
| `validate_pwdump_file()` | file_parser.py:350-394 | Parse pwdump format |
| `validate_potfile()` | file_parser.py:556-614 | Parse potfile (with ntlm_only option) |
| `parse_potfile_line_ntlm_only()` | file_parser.py:397-452 | Fast NTLM-only potfile line parser |
| `get_most_likely_type()` | hash_types.py:865-900 | Identify hash type (99 patterns) |
| `validation_result_to_dict()` | file_parser.py:845-889 | Serialize for session |
| `dict_to_validation_result()` | file_parser.py:892-943 | Deserialize from session |
| `build_account_data()` | file_parser.py:738-841 | Match accounts with passwords |
| `crack_stats()` | password_analysis_tools.py:304-516 | Statistical analysis |
| `substring_analysis()` | password_analysis_tools.py:518-614 | Find common substrings |
| `dictionary_analysis()` | password_analysis_tools.py:617-692 | Find dictionary words |
| `bad_practices_analysis()` | password_analysis_tools.py:695-1037 | Detect weak patterns |
| `check_pw_reuse_from_account_data()` | password_analysis_tools.py:137-173 | Find shared passwords |
| `get_cracked_hashes_direct()` | potfile_cache.py | Cached potfile lookup |
