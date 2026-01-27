# Hash Master 1000 - Feature Roadmap

> **Internal Document** - Not for public distribution
>
> This document outlines planned features for HM1K, including both the public version and the private SynerComm fork.

---

## Table of Contents

1. [SynerComm Private Fork Features](#synercomm-private-fork-features)
2. [Hashcat Management & Cracking](#hashcat-management--cracking)
3. [New Reports & Analysis](#new-reports--analysis)
4. [AI-Powered Analysis (Ollama Integration)](#ai-powered-analysis-ollama-integration)
5. [Export & Reporting Enhancements](#export--reporting-enhancements)
6. [Infrastructure & UX Improvements](#infrastructure--ux-improvements)
7. [Implementation Priority Matrix](#implementation-priority-matrix)

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

## Hashcat Management & Cracking

**Status:** Planned

Hash Master 1000 will expand to include integrated hashcat cracking capabilities, allowing users to manage the entire password auditing lifecycle from hash extraction through cracking to analysis—all within a single unified interface.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    HASH MASTER 1000 SERVER                               │
│  (Can run standalone on cracking hardware OR as team server)            │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────────────┐ │
│  │  Web UI      │  │  Job Queue   │  │  Agent Manager                 │ │
│  │  (Gunicorn)  │──│  Manager     │──│  (coordinates remote agents)   │ │
│  └──────────────┘  └──────────────┘  └────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
           │                                      │
           │ (Standalone Mode)                    │ (Server Mode)
           ▼                                      ▼
┌──────────────────────┐          ┌──────────────────────────────────────┐
│  Local Hashcat       │          │  Remote Hashcat Agents               │
│  Agent               │          │  ┌────────────┐  ┌────────────┐      │
│  (screen session)    │          │  │ Cracker 1  │  │ Cracker 2  │ ... │
└──────────────────────┘          │  │ (4x 4090)  │  │ (8x A100)  │      │
                                  │  └────────────┘  └────────────┘      │
                                  └──────────────────────────────────────┘
```

### Deployment Modes

#### Standalone/Local Mode

Hash Master runs directly on a machine with hashcat and GPU hardware. The local hashcat agent runs on the same system. Ideal for:
- Single-user setups
- Dedicated cracking workstations
- Air-gapped environments

#### Team Server Mode

Hash Master runs on a central server (potentially without GPUs) and coordinates hashcat agents running on dedicated cracking servers. Features:
- Centralized job management
- Multi-user access via web UI
- Distributed cracking across multiple servers
- Job queue with priorities

---

### Hashcat Agent

**Description:** Lightweight agents that run on cracking servers to execute hashcat jobs and report status back to Hash Master.

#### Agent Responsibilities

| Function | Description |
|----------|-------------|
| Job Execution | Start hashcat with specified parameters in a screen session |
| Status Monitoring | Periodically send 's' key to hashcat to capture status |
| Progress Reporting | Report speed, progress, ETA, and recovered hashes to server |
| Error Detection | Detect hashcat errors, crashes, and GPU issues |
| Availability Check | Verify hashcat is not running and GPUs are available before starting |
| Potfile Collection | Collect and transmit cracked hashes after job completion |
| Session Management | Stop, pause, and resume hashcat sessions |

#### Agent Implementation

```
┌─────────────────────────────────────────────────────────────┐
│                    HASHCAT AGENT                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │  Agent Daemon   │──│  Screen Session │                   │
│  │  (Python)       │  │  (hashcat)      │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
│           │                    │                            │
│           │ send 's' ──────────│ (status output)            │
│           │ send 'q' ──────────│ (quit gracefully)          │
│           │                    │                            │
│  ┌────────▼────────────────────▼────────┐                   │
│  │  Status Parser                        │                   │
│  │  - Speed (H/s)                        │                   │
│  │  - Progress (%)                       │                   │
│  │  - ETA                                │                   │
│  │  - Recovered hashes                   │                   │
│  │  - GPU temps/utilization              │                   │
│  └───────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

#### Agent Deployment

The hashcat agent is distributed as a **single Python package** (`hm1k-agent`) designed to run as a systemd service on cracking servers.

**Installation:**
```bash
# Install the agent package
pip install hm1k-agent

# Initialize the agent (creates config, systemd unit, directories)
hm1k-agent init

# Start the agent service
sudo systemctl enable --now hm1k-agent
```

**Initialization Wizard (`hm1k-agent init`):**
1. Prompts for server URL and optional pre-shared token
2. Detects hashcat binary location (or prompts for path)
3. Discovers GPU hardware via `nvidia-smi` or `hashcat -I`
4. Creates config file at `/etc/hm1k-agent/config.yaml`
5. Sets up working directories with appropriate permissions
6. Generates systemd unit file at `/etc/systemd/system/hm1k-agent.service`
7. Optionally starts in discovery mode for server-side registration

**Package Commands:**
```bash
hm1k-agent init           # Initial setup wizard
hm1k-agent status         # Show agent status, connection state, current job
hm1k-agent test-connection # Verify server connectivity
hm1k-agent register       # Manually trigger registration with server
hm1k-agent logs           # Tail the agent log
hm1k-agent benchmark      # Run hashcat benchmark, report to server
```

#### Agent Authentication

Agents authenticate using **per-agent tokens** with optional **discovery mode** for easy registration.

**Authentication Flow:**
```
┌─────────────────┐                      ┌─────────────────┐
│  Cracking       │                      │  Hash Master    │
│  Server         │                      │  Server         │
└────────┬────────┘                      └────────┬────────┘
         │                                        │
         │ 1. hm1k-agent init (no token)          │
         │ ──────────────────────────────────────>│
         │                                        │
         │ 2. Agent generates one-time code       │
         │    Displays: "Register code: ABC123"   │
         │                                        │
         │ 3. Admin enters code in HM1K UI        │
         │ <──────────────────────────────────────│
         │                                        │
         │ 4. Server sends permanent token        │
         │ <──────────────────────────────────────│
         │                                        │
         │ 5. Agent stores token, begins normal   │
         │    operation with authenticated API    │
         │ ──────────────────────────────────────>│
         │                                        │
```

**Discovery Mode:**
- Agent starts without a token and generates a short-lived registration code
- Admin sees pending agents in the HM1K UI and enters the code to approve
- Server issues a permanent JWT token to the agent
- Token stored securely in agent config file

**Pre-Shared Token Mode:**
- Admin generates a token in HM1K UI before deploying agent
- Token passed to `hm1k-agent init --token <token>`
- Agent immediately authenticated, no discovery step needed

**Token Security:**
- Tokens are JWTs with agent ID claim, signed by server
- Tokens can be revoked from HM1K UI
- Failed auth attempts logged and rate-limited
- Tokens have no expiration (revocation-based invalidation)

#### Agent Communication Protocol

Agents use a **hybrid REST + Server-Sent Events (SSE)** communication model for efficient, real-time coordination.

**Communication Architecture:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        COMMUNICATION FLOW                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Agent → Server (REST API):                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ POST /api/agent/heartbeat     - Health check + status update    │   │
│  │ POST /api/agent/status        - Job progress (every 10-15s)     │   │
│  │ POST /api/agent/job/complete  - Job finished + results          │   │
│  │ POST /api/agent/job/error     - Job failed + error details      │   │
│  │ GET  /api/agent/resources/*   - Pull wordlists, rules, masks    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Server → Agent (SSE Stream):                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ GET /api/agent/events (persistent connection)                    │   │
│  │                                                                  │   │
│  │ Event types:                                                     │   │
│  │   job:assigned    - New job assigned to this agent               │   │
│  │   job:pause       - Pause current job                            │   │
│  │   job:resume      - Resume paused job                            │   │
│  │   job:stop        - Stop and cancel current job                  │   │
│  │   resource:sync   - New resource available, trigger pull         │   │
│  │   config:update   - Agent config changed (e.g., polling rate)    │   │
│  │   ping            - Keep-alive (every 30s)                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Adaptive Polling Intervals:**

| State | Heartbeat Interval | Status Update Interval |
|-------|-------------------|------------------------|
| Idle (no job) | 60 seconds | N/A |
| Job Running | 60 seconds | 10-15 seconds |
| Job Completing | 60 seconds | 5 seconds (final updates) |
| Disconnected | Exponential backoff (5s → 300s max) | Queued locally |

**Why SSE Instead of WebSockets:**
- Simpler to implement and debug
- Works through proxies and firewalls more reliably
- Auto-reconnects on connection drop
- Sufficient for server→agent commands (low frequency)
- REST handles high-frequency agent→server updates

#### Resource Synchronization

Resources (wordlists, rules, masks) are managed on the server and **pulled by agents on demand**.

**Resource Management Model:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        RESOURCE SYNC FLOW                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Server (Master):                     Agent (Cache):                    │
│  ┌─────────────────────────────┐     ┌─────────────────────────────┐   │
│  │ /data/wordlists/            │     │ /var/lib/hm1k-agent/cache/  │   │
│  │   rockyou.txt (139 MB)      │────>│   rockyou.txt (139 MB)      │   │
│  │   common_pass.txt (12 MB)   │     │   common_pass.txt (12 MB)   │   │
│  │                             │     │                             │   │
│  │ /data/rules/                │     │ /rules/                     │   │
│  │   best64.rule               │────>│   best64.rule               │   │
│  │   d3ad0ne.rule              │     │   d3ad0ne.rule              │   │
│  └─────────────────────────────┘     └─────────────────────────────┘   │
│                                                                         │
│  Sync triggers:                                                         │
│  1. Job assigned referencing resource not in cache                      │
│  2. Server sends resource:sync SSE event (new/updated resource)         │
│  3. Agent startup (verify cache integrity)                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Resource API:**
```
GET /api/agent/resources/wordlists              # List available wordlists
GET /api/agent/resources/wordlists/{name}       # Download wordlist
GET /api/agent/resources/wordlists/{name}/meta  # Get hash, size, modified date
GET /api/agent/resources/rules                  # List available rules
GET /api/agent/resources/rules/{name}           # Download rule file
GET /api/agent/resources/masks                  # List available masks
```

**Cache Management:**
- Agent maintains local cache with configurable max size (default: 50GB)
- LRU eviction when cache full
- SHA256 verification on download
- Resume support for large file downloads
- Compressed transfer for text files (gzip)

#### Offline Resilience

Agents are designed to **continue operating** when the server becomes unreachable.

**Offline Behavior:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        OFFLINE OPERATION                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Server Connection Lost:                                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. Agent detects connection failure (heartbeat timeout)         │   │
│  │ 2. Current job CONTINUES running (never auto-stop)              │   │
│  │ 3. Status updates queued locally in SQLite buffer               │   │
│  │ 4. Reconnection attempts with exponential backoff               │   │
│  │    (5s, 10s, 20s, 40s, 80s, 160s, 300s max)                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Job Completion While Offline:                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. Job finishes, results stored locally                         │   │
│  │    - Potfile saved to /var/lib/hm1k-agent/pending/              │   │
│  │    - Job completion record queued                               │   │
│  │ 2. Agent enters idle state, continues reconnection attempts     │   │
│  │ 3. On reconnection:                                             │   │
│  │    - Upload pending potfile results                             │   │
│  │    - Sync buffered status updates                               │   │
│  │    - Request next job assignment                                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Local Buffer (SQLite):                                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Table: pending_updates                                          │   │
│  │   - id, timestamp, event_type, payload (JSON)                   │   │
│  │ Max buffer size: 10,000 events (~50MB)                          │   │
│  │ Oldest events dropped if buffer full (status updates only)      │   │
│  │ Job results NEVER dropped (critical data)                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Resilience Guarantees:**
- Jobs never auto-terminate due to server disconnect
- Cracked passwords never lost (local storage + upload on reconnect)
- Status history preserved for post-reconnection sync
- Agent state persists across restarts (systemd + SQLite)

#### File Transfer Security

Hash files and potfiles contain sensitive data and are transferred securely.

**Transfer Security Model:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FILE TRANSFER                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Sensitive Files (HTTPS + Encryption):                                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Server → Agent:                                                  │   │
│  │   - Hash files for cracking jobs                                 │   │
│  │   - Encrypted with job-specific key (AES-256-GCM)               │   │
│  │   - Key delivered via separate authenticated request             │   │
│  │                                                                  │   │
│  │ Agent → Server:                                                  │   │
│  │   - Potfiles (cracked results)                                   │   │
│  │   - Encrypted with session key                                   │   │
│  │   - Chunked upload with resume support                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Non-Sensitive Files (HTTPS only):                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ - Wordlists (public data)                                        │   │
│  │ - Rule files (public data)                                       │   │
│  │ - Mask files (public data)                                       │   │
│  │ - Status updates (not sensitive)                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Transfer Features:                                                     │
│  - Chunked upload/download for large files                             │
│  - Resume support (Content-Range headers)                              │
│  - SHA256 integrity verification                                       │
│  - Automatic retry on failure (3 attempts)                             │
│  - Bandwidth throttling option                                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Agent Configuration File

```yaml
# /etc/hm1k-agent/config.yaml
# Generated by: hm1k-agent init
# Do not edit while agent is running

server:
  url: "https://hashmaster.internal:8443"
  token: "eyJhbGciOiJIUzI1NiIs..."    # JWT token (managed by agent)
  verify_ssl: true                     # Set false for self-signed certs

agent:
  id: "cracker-01"                     # Unique agent identifier
  name: "Primary Cracker"              # Human-friendly name
  description: "4x RTX 4090 system"    # Optional description

hashcat:
  binary: "/usr/bin/hashcat"           # Path to hashcat binary
  workdir: "/var/lib/hm1k-agent/sessions"  # Session working directory
  extra_args: ""                       # Additional hashcat arguments

resources:
  cache_dir: "/var/lib/hm1k-agent/cache"
  max_cache_size_gb: 50                # LRU eviction above this

timing:
  heartbeat_interval: 60               # Seconds between heartbeats
  status_interval: 15                  # Seconds between status updates (during job)
  reconnect_max_interval: 300          # Max seconds between reconnect attempts

logging:
  level: "INFO"                        # DEBUG, INFO, WARNING, ERROR
  file: "/var/log/hm1k-agent/agent.log"
  max_size_mb: 100                     # Rotate at this size
  backup_count: 5                      # Keep this many old logs
```

#### Agent Privileges

Agents run with **standard user privileges** (no root/sudo required):
- Hashcat binary accessible to agent user
- Write access to working directory for potfiles and session files
- Read access to wordlists, rules, and hash files

---

### Workflow Integration

#### Modified Step 1: Hash Input Options

The existing Step 1 (file upload) will be extended with a new option:

```
Step 1: Provide Hash Data
═════════════════════════

○ Upload PWDump/DCSync File
○ Upload ADD JSON File
○ Upload Potfile (existing cracked hashes)
● Start Cracking Session → [Configure Cracking Jobs]

    ┌─────────────────────────────────────────────────────────┐
    │  When you select "Start Cracking Session":              │
    │                                                         │
    │  1. Upload your hash file (PWDump, DCSync, or ADD)     │
    │  2. Configure cracking job series                       │
    │  3. Monitor cracking progress                           │
    │  4. When complete, proceed to Step 2 with results      │
    └─────────────────────────────────────────────────────────┘
```

#### LM Hash Detection Alert

When valid, non-blank LM hashes are detected in the uploaded file:

```
┌─────────────────────────────────────────────────────────────┐
│  ⚠️  LM Hashes Detected                                     │
│                                                             │
│  This hash file contains 234 accounts with valid LM hashes. │
│  LM hashes are significantly weaker than NTLM and should    │
│  be cracked as part of your session.                        │
│                                                             │
│  [Include LM Cracking Jobs]  [Skip LM Hashes]               │
└─────────────────────────────────────────────────────────────┘
```

---

### LM → NTLM Workflow (100% Recovery)

**Status:** ✅ COMPLETED (January 2026)

**Description:** Automated two-step workflow that achieves **100% password recovery** for any account with a valid LM hash. Exploits the inherent weakness of LM hashes to guarantee NTLM password recovery.

#### Why This Works

LM hashes have fundamental weaknesses that guarantee crackability:

| Weakness | Impact |
|----------|--------|
| Max 14 characters | Finite keyspace |
| Converted to UPPERCASE | No case to guess |
| Split into 7-char halves | Each half cracked independently |
| Limited charset | ?u?d?s covers all possibilities |

Since LM hashes are always crackable, and we know the password is ≤14 chars, we can recover the original case-sensitive password by trying all 2^14 = 16,384 case permutations against the NTLM hash.

#### Workflow Process

```
┌─────────────────────────────────────────────────────────────────┐
│  INPUT: Pwdump file with LM + NTLM hashes                       │
│  user:1001:aabbcc...1122:99887766...ccbbaa:::                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: Extract & Crack LM Halves                              │
│  ─────────────────────────────────────────────────────────────  │
│  • Split 32-char LM hash into two 16-char halves                │
│  • Skip empty halves (aad3b435b51404ee)                         │
│  • Brute force with hashcat -m 3000 -a 3 ?u?d?s (1-7 chars)     │
│  • Result: 100% crack rate (guaranteed - finite keyspace)       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: Combine Halves                                         │
│  ─────────────────────────────────────────────────────────────  │
│  • Join cracked halves: "MYPASSW" + "ORD1234" = "MYPASSWORD1234"│
│  • Handle $HEX[...] encoded special characters                  │
│  • Use latin-1 encoding for extended ASCII preservation         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Apply Toggle Rules to NTLM                             │
│  ─────────────────────────────────────────────────────────────  │
│  • Generate 16,384 toggle rules (2^14 case combinations)        │
│  • hashcat -m 1000 -a 0 ntlm.txt wordlist.txt -r toggle.rule    │
│  • One combination MUST match the NTLM hash                     │
│  • Result: 100% crack rate (original case recovered)            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  OUTPUT: Case-sensitive passwords for all LM-enabled accounts   │
│  Example: "MyPassword1234" (original case recovered)            │
└─────────────────────────────────────────────────────────────────┘
```

#### Performance Results

| Metric | Value |
|--------|-------|
| LM Halves Cracked | 100% (3,572/3,572) |
| NTLM Passwords Recovered | 100% (2,151/2,151 unique hashes) |
| LM Brute Force Time | ~3 minutes |
| NTLM Toggle Time | ~10 seconds |
| **Total Time** | **~3 minutes** |

#### Technical Implementation

**Toggle Rules Generation:**
```python
# Generate all 2^14 = 16,384 case combinations
# T0-T9 = toggle positions 0-9
# TA-TD = toggle positions 10-13
for bits in range(2 ** 14):
    rule = " ".join(f"T{pos}" for pos in range(14) if bits & (1 << pos))
```

**Critical Encoding Requirements:**
- Decode `$HEX[...]` sequences as latin-1 bytes
- Write wordlist with `encoding="latin-1"`
- Read wordlist with `encoding="latin-1"`
- Preserve encoding through JSON transfer to agent

#### UI Access

Available at: `/agents/test` → "LM → NTLM Workflow" section

```
┌─────────────────────────────────────────────────────────────┐
│  🔗 LM → NTLM Workflow                          [↻ Refresh] │
├─────────────────────────────────────────────────────────────┤
│  Multi-step automated cracking:                             │
│  Upload a pwdump file with LM hashes. The workflow will:    │
│  1. Extract and crack LM hash halves (brute force)          │
│  2. Combine cracked halves into uppercase plaintexts        │
│  3. Use toggle rules to recover case-sensitive NTLM         │
├─────────────────────────────────────────────────────────────┤
│  Agent: [hashmaster-01 ▼]                                   │
│  Pwdump File: [Click to select file]                        │
│                                                             │
│  [🚀 Start LM → NTLM Workflow]                              │
└─────────────────────────────────────────────────────────────┘
```

---

### Cracking Job Configuration

#### Preset Job Series

Users can select from pre-configured cracking "playlists" or build custom series:

```
Cracking Job Configuration
══════════════════════════

Select Preset Series:
┌─────────────────────────────────────────────────────────────┐
│  ○ Quick Crack (30 min - 1 hour)                           │
│    Common wordlists + rules, basic masks                    │
│                                                             │
│  ○ Standard Crack (4-8 hours)                              │
│    Extended wordlists, multiple rule sets, common masks     │
│                                                             │
│  ○ Thorough Crack (24-48 hours)                            │
│    Full wordlist library, exhaustive rules, brute force    │
│                                                             │
│  ● Custom Series → [Build Custom Job Series]               │
└─────────────────────────────────────────────────────────────┘
```

#### À La Carte Job Builder

```
Build Custom Cracking Series
════════════════════════════

Available Job Types:                    Your Series:
┌──────────────────────────┐           ┌──────────────────────────┐
│ Dictionary Attacks       │           │ 1. rockyou + best64      │
│  ├─ rockyou.txt         │    →      │ 2. common_passwords +    │
│  ├─ common_passwords    │           │    d3ad0ne               │
│  ├─ enterprise_words    │           │ 3. Mask: ?u?l?l?l?l?d?d  │
│  └─ [custom wordlists]  │           │ 4. Potfile + best64      │
│                          │           │    (2 rounds)            │
│ Rule Files               │           │ 5. Mask: Company?d?d?d?d │
│  ├─ best64.rule         │           └──────────────────────────┘
│  ├─ d3ad0ne.rule        │
│  ├─ dive.rule           │           Estimated Time: 6-8 hours
│  └─ [custom rules]      │
│                          │           ┌─────────────────────────┐
│ Mask Attacks             │           │ Potfile + Rules Rounds: │
│  ├─ ?u?l?l?l?l?d?d      │           │  [▼ 2 rounds         ]  │
│  ├─ ?u?l?l?l?l?d?d?d?d  │           │                         │
│  ├─ [saved masks]        │           │ After other jobs finish,│
│  └─ [custom mask]        │           │ use session potfile as  │
│                          │           │ wordlist with rules to  │
│ Hybrid Attacks           │           │ find password variants. │
│  └─ [configure...]       │           └─────────────────────────┘
└──────────────────────────┘
```

#### Potfile-as-Wordlist Feature

**Key Innovation:** Use cracked passwords from the current session as a wordlist for subsequent attacks.

```
Potfile + Rules Configuration
═════════════════════════════

When initial cracking jobs complete, use the recovered passwords
as a wordlist with rule mutations to discover password variants.

How it works:
1. Initial jobs crack passwords like "Summer2024"
2. Potfile wordlist + rules generates: "Summer2024!", "Summer2025",
   "summer2024", "Summ3r2024", etc.
3. These variants crack more hashes, expanding the potfile
4. Repeat for N rounds

Number of Potfile + Rules rounds: [▼ 2]

Rule files to apply:
☑ best64.rule
☑ d3ad0ne.rule
☐ dive.rule (adds significant time)
☐ [custom rules]
```

---

### Job Queue Management

#### Queue Dashboard

```
Cracking Job Queue
══════════════════

Active Jobs:                                           Server Status:
┌─────────────────────────────────────────────────┐   ┌──────────────┐
│ ▶ Job #142 - CORP.LOCAL (NTLM)                  │   │ Cracker-1    │
│   rockyou + best64                              │   │ ████████ 89% │
│   Progress: 67% | Speed: 45.2 GH/s | ETA: 2h15m │   │ 4x RTX 4090  │
│   Recovered: 1,234 / 5,432                      │   │ Temp: 72°C   │
│   [Pause] [Stop] [Priority ▲▼]                  │   └──────────────┘
├─────────────────────────────────────────────────┤   ┌──────────────┐
│ ⏸ Job #143 - DEV.LOCAL (NTLM)                   │   │ Cracker-2    │
│   Paused by admin (Job #145 priority override)  │   │ ░░░░░░░░ 0%  │
│   [Resume] [Cancel]                              │   │ 8x A100      │
└─────────────────────────────────────────────────┘   │ Available    │
                                                      └──────────────┘
Queued Jobs:
┌─────────────────────────────────────────────────┐
│ ⏳ Job #144 - CORP.LOCAL (NTLM) - common + dive │
│    Queued behind Job #142                        │
│    Estimated start: ~2h15m                       │
│                                                 │
│ ⏳ Job #145 - CLIENT-URGENT (NTLM) [PRIORITY]   │
│    Admin override - will start next             │
└─────────────────────────────────────────────────┘
```

#### Shared Cracking Time

When multiple users have jobs queued, enable optional "time sharing":

```
┌─────────────────────────────────────────────────────────────┐
│  Shared Cracking Time                                        │
│                                                             │
│  Your job is #3 in queue. Estimated wait: 8 hours           │
│                                                             │
│  ☑ Enable Shared Cracking Time                              │
│                                                             │
│  When enabled:                                              │
│  • Your job will start sooner on available servers          │
│  • Jobs run in round-robin across servers                   │
│  • Both jobs take longer but each sees results faster       │
│                                                             │
│  Other users with shared time enabled: 2                    │
│  Estimated time to first results: 45 min (vs 8h wait)       │
└─────────────────────────────────────────────────────────────┘
```

#### Admin Queue Override

Administrators can:
- Pause any running job
- Reprioritize queue order
- Start urgent jobs immediately
- Assign jobs to specific servers

---

### Resource Management Pages

#### Wordlist Management

```
Wordlist Library
════════════════

System Wordlists:                    Custom Wordlists:
┌────────────────────────────────┐  ┌────────────────────────────────┐
│ Name            Size    Lines  │  │ Name            Size    Lines  │
├────────────────────────────────┤  ├────────────────────────────────┤
│ rockyou.txt     139 MB  14.3M  │  │ company_terms   2.3 KB  156    │
│ common_pass     12 MB   1.2M   │  │ client_custom   45 KB   3,421  │
│ enterprise      234 MB  28.7M  │  │ industry_terms  890 KB  67,234 │
│ leaked_2024     1.2 GB  156M   │  │                                │
└────────────────────────────────┘  └────────────────────────────────┘

[Upload New Wordlist]  [Create from Potfile]  [Download from URL]
```

#### Rule File Management

```
Rule Library
════════════

System Rules:                        Custom Rules:
┌────────────────────────────────┐  ┌────────────────────────────────┐
│ Name            Rules  Est.Time│  │ Name            Rules  Est.Time│
├────────────────────────────────┤  ├────────────────────────────────┤
│ best64.rule     64     Fast    │  │ company_mangle  234    Medium  │
│ d3ad0ne.rule    34k    Medium  │  │ season_year     48     Fast    │
│ dive.rule       99k    Slow    │  │ keyboard_walk   156    Fast    │
│ toggles.rule    4k     Fast    │  │                                │
│ leetspeak.rule  128    Fast    │  │                                │
└────────────────────────────────┘  └────────────────────────────────┘

[Upload New Rule File]  [Create Rule File]  [Test Rules]
```

#### Mask Management

```
Saved Masks
═══════════

Common Masks:                        Custom Masks:
┌────────────────────────────────┐  ┌────────────────────────────────┐
│ Pattern              Keyspace  │  │ Pattern              Keyspace  │
├────────────────────────────────┤  ├────────────────────────────────┤
│ ?u?l?l?l?l?l?d?d    ~170B     │  │ Company?d?d?d?d      10,000   │
│ ?u?l?l?l?l?l?l?d?d  ~4.4T     │  │ ?u?l?l?l?l?s?d?d?d?d ~590B   │
│ ?u?l?l?l?l?d?d?d?d  ~4.5B     │  │ Season?d?d?d?d       40,000   │
│ ?d?d?d?d?d?d?d?d    100M      │  │                                │
└────────────────────────────────┘  └────────────────────────────────┘

[Create New Mask]  [Import .hcmask File]
```

#### Job Template Management

```
Crack Job Templates
═══════════════════

System Templates:                    Custom Templates:
┌────────────────────────────────┐  ┌────────────────────────────────┐
│ Name              Attack Type  │  │ Name              Attack Type  │
├────────────────────────────────┤  ├────────────────────────────────┤
│ rockyou_best64    Dict+Rules   │  │ client_custom     Dict+Rules   │
│ common_d3ad0ne    Dict+Rules   │  │ season_brute      Mask         │
│ mask_8char        Mask         │  │ potfile_expand    Dict+Rules   │
│ hybrid_word_num   Hybrid       │  │                                │
└────────────────────────────────┘  └────────────────────────────────┘

[Create Job Template]  [Import Template]

Job Series (Presets):
┌────────────────────────────────────────────────────────────────────┐
│ Name              Jobs  Est. Time  Description                      │
├────────────────────────────────────────────────────────────────────┤
│ Quick Crack       5     30-60 min  Basic wordlists + common masks   │
│ Standard Crack    12    4-8 hours  Extended coverage                │
│ Thorough Crack    25    24-48 hr   Exhaustive cracking              │
│ LM Quick          3     15 min     LM-specific attacks              │
└────────────────────────────────────────────────────────────────────┘

[Create Job Series]  [Edit Series]
```

---

### Server Health & Status

#### Server Dashboard

```
Hashcat Server Status
═════════════════════

┌─────────────────────────────────────────────────────────────────────┐
│  CRACKER-1 (Primary)                                    ● Online    │
├─────────────────────────────────────────────────────────────────────┤
│  System Information:                                                │
│  ├─ OS: Ubuntu 22.04.3 LTS (kernel 6.2.0-39-generic)               │
│  ├─ CPU: AMD EPYC 7763 64-Core @ 2.45 GHz                          │
│  ├─ RAM: 256 GB (45 GB used)                                       │
│  ├─ Storage: 2x NVMe 2TB RAID-0 (1.2 TB free)                      │
│  └─ Uptime: 45 days, 12:34:56                                      │
│                                                                     │
│  Hashcat:                                                           │
│  ├─ Version: 6.2.6                                                 │
│  ├─ Status: Running Job #142                                       │
│  └─ Session: corp_ntlm_rockyou                                     │
│                                                                     │
│  GPU Status (nvidia-smi):                                          │
│  ┌────────┬──────────┬──────────┬───────────┬────────────────────┐ │
│  │ GPU    │ Temp     │ Power    │ Memory    │ Utilization        │ │
│  ├────────┼──────────┼──────────┼───────────┼────────────────────┤ │
│  │ GPU 0  │ 72°C     │ 320W     │ 22/24 GB  │ ████████████ 98%   │ │
│  │ GPU 1  │ 70°C     │ 315W     │ 22/24 GB  │ ████████████ 97%   │ │
│  │ GPU 2  │ 73°C     │ 322W     │ 22/24 GB  │ ████████████ 99%   │ │
│  │ GPU 3  │ 71°C     │ 318W     │ 22/24 GB  │ ████████████ 98%   │ │
│  └────────┴──────────┴──────────┴───────────┴────────────────────┘ │
│                                                                     │
│  NVIDIA Driver: 545.23.08  |  CUDA: 12.3                           │
│                                                                     │
│  [View Full nvidia-smi]  [View hashcat Status]  [Restart Agent]    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  CRACKER-2 (Secondary)                                  ● Online    │
├─────────────────────────────────────────────────────────────────────┤
│  System Information:                                                │
│  ├─ OS: Rocky Linux 9.3                                            │
│  ├─ CPU: 2x Intel Xeon Gold 6248R @ 3.0 GHz (48 cores)            │
│  ├─ RAM: 512 GB (128 GB used)                                      │
│  ├─ Storage: 4x NVMe 4TB RAID-10 (6.8 TB free)                    │
│  └─ Uptime: 123 days, 08:15:42                                     │
│                                                                     │
│  Hashcat:                                                           │
│  ├─ Version: 6.2.6                                                 │
│  ├─ Status: Idle (Ready for jobs)                                  │
│  └─ Session: None                                                  │
│                                                                     │
│  GPU Status (nvidia-smi):                                          │
│  ┌────────┬──────────┬──────────┬───────────┬────────────────────┐ │
│  │ GPU    │ Temp     │ Power    │ Memory    │ Utilization        │ │
│  ├────────┼──────────┼──────────┼───────────┼────────────────────┤ │
│  │ GPU 0  │ 32°C     │ 45W      │ 2/80 GB   │ ░░░░░░░░░░░░ 0%    │ │
│  │ GPU 1  │ 31°C     │ 44W      │ 2/80 GB   │ ░░░░░░░░░░░░ 0%    │ │
│  │  ...   │  ...     │  ...     │   ...     │       ...          │ │
│  │ GPU 7  │ 33°C     │ 46W      │ 2/80 GB   │ ░░░░░░░░░░░░ 0%    │ │
│  └────────┴──────────┴──────────┴───────────┴────────────────────┘ │
│                                                                     │
│  NVIDIA Driver: 545.23.08  |  CUDA: 12.3                           │
│                                                                     │
│  [View Full nvidia-smi]  [View Logs]  [Restart Agent]              │
└─────────────────────────────────────────────────────────────────────┘
```

#### Health Checks

The server status page monitors:

| Check | Description | Alert Threshold |
|-------|-------------|-----------------|
| Agent Heartbeat | Agent communication status | > 60s since last heartbeat |
| GPU Temperature | Individual GPU temps | > 85°C warning, > 90°C critical |
| GPU Memory | VRAM utilization | > 95% warning |
| Disk Space | Available storage | < 10% warning, < 5% critical |
| hashcat Version | Installed version | Mismatch with server |
| NVIDIA Driver | Driver version | Out of date warning |
| CUDA Version | CUDA toolkit version | Compatibility check |
| Job Errors | Recent job failures | Any failure in last hour |

---

### Hash File Validation

Reuse existing HM1K validation functions before sending hashes to hashcat:

```python
# Existing validation from hm1k.py
validate_pwdump_file()    # PWDump/DCSync format validation
validate_add_json()       # ADD JSON format validation
extract_ntlm_hashes()     # NTLM hash extraction (scripts/extract_ntlm_hashes.py)
extract_lm_hashes()       # LM hash extraction
```

#### Validation Flow

```
Hash File Upload
      │
      ▼
┌─────────────────┐
│ Format Detection│ (PWDump, DCSync, ADD JSON)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Validation      │ (structure, hash format, character validation)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Hash Extraction │
│ - NTLM hashes   │ → ntlm_hashes.txt (for hashcat -m 1000)
│ - LM hashes     │ → lm_hashes.txt (for hashcat -m 3000)
│ - Blank removal │ (optionally exclude blank hashes)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ LM Hash Alert   │ (if non-blank LM hashes detected)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Ready for       │
│ Cracking Config │
└─────────────────┘
```

---

### Configuration

#### Environment Variables

```bash
# .env configuration for hashcat management

# =============================================================================
# Hashcat Management Configuration
# =============================================================================

# Enable hashcat cracking features
HASHCAT_ENABLED="true"

# Deployment mode: "standalone" or "server"
# standalone: Hash Master runs on cracking hardware with local agent
# server: Hash Master coordinates remote agents on dedicated crackers
HASHCAT_MODE="server"

# Local hashcat binary path (standalone mode)
HASHCAT_BINARY="/usr/bin/hashcat"

# Session directory for hashcat working files
HASHCAT_SESSION_DIR="/data/hashcat/sessions"

# Potfile directory
HASHCAT_POTFILE_DIR="/data/hashcat/potfiles"

# =============================================================================
# Hashcat Agent Configuration
# =============================================================================

# Agent communication
HASHCAT_AGENT_PORT="8444"
HASHCAT_AGENT_SECRET="your-secure-agent-secret"

# Configured cracking servers (server mode)
# Format: name|host|port|description
HASHCAT_SERVER_1="Cracker-1|192.168.1.100|8444|4x RTX 4090"
HASHCAT_SERVER_2="Cracker-2|192.168.1.101|8444|8x A100"

# Status polling interval (seconds)
HASHCAT_STATUS_INTERVAL="30"

# =============================================================================
# Resource Paths
# =============================================================================

# Wordlist directory
HASHCAT_WORDLIST_DIR="/data/wordlists"

# Rule file directory
HASHCAT_RULES_DIR="/data/rules"

# Mask file directory
HASHCAT_MASKS_DIR="/data/masks"
```

---

### API Endpoints

#### Job Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/hashcat/jobs` | GET | List all jobs (queued, active, completed) |
| `/api/hashcat/jobs` | POST | Create new cracking job |
| `/api/hashcat/jobs/{id}` | GET | Get job details and status |
| `/api/hashcat/jobs/{id}/pause` | POST | Pause running job |
| `/api/hashcat/jobs/{id}/resume` | POST | Resume paused job |
| `/api/hashcat/jobs/{id}/stop` | POST | Stop and cancel job |
| `/api/hashcat/jobs/{id}/priority` | PUT | Change job priority |
| `/api/hashcat/jobs/{id}/potfile` | GET | Download job potfile |

#### Server Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/hashcat/servers` | GET | List all configured servers |
| `/api/hashcat/servers/{id}/status` | GET | Get server health and status |
| `/api/hashcat/servers/{id}/nvidia-smi` | GET | Get full nvidia-smi output |
| `/api/hashcat/servers/{id}/restart-agent` | POST | Restart agent on server |

#### Resource Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/hashcat/wordlists` | GET/POST | List/upload wordlists |
| `/api/hashcat/rules` | GET/POST | List/upload rule files |
| `/api/hashcat/masks` | GET/POST | List/create masks |
| `/api/hashcat/templates` | GET/POST/PUT/DELETE | Manage job templates |
| `/api/hashcat/series` | GET/POST/PUT/DELETE | Manage job series |

---

### Implementation Phases

#### Phase 1: Foundation

- [x] Hashcat agent core (--status-json parsing, subprocess management)
- [x] Agent-server communication protocol (REST + SSE)
- [x] Basic job creation and execution
- [x] Status monitoring and reporting
- [x] **LM → NTLM Workflow (100% recovery)** ✅
- [ ] Local/standalone mode support

#### Phase 2: Job Management

- [x] Job queue with priorities
- [ ] Multi-job series execution
- [ ] Potfile-as-wordlist feature
- [ ] Job templates and presets
- [ ] Admin queue override

#### Phase 3: Multi-Server

- [x] Remote agent deployment (hm1k-agent package + systemd)
- [ ] Multi-server job distribution
- [ ] Shared cracking time feature
- [x] Server health monitoring (heartbeat + status)
- [ ] nvidia-smi integration

#### Phase 4: Resource Management

- [ ] Wordlist management UI
- [ ] Rule file management UI
- [ ] Mask management UI
- [ ] Job template editor
- [ ] Job series builder

#### Phase 5: Integration

- [ ] Step 1 workflow integration
- [ ] Hash file validation pipeline
- [ ] LM hash detection alerts
- [ ] Automatic transition to Step 2
- [ ] Session potfile integration with HM1K analysis

---

## New Reports & Analysis

### Password History Analysis (IMPLEMENTED)

**Status:** Implemented (December 2024)

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
- Hash reuse detection (works without cracking): consecutive and non-consecutive
- Leet-speak progression: `Password` → `P4ssword` → `P4ssw0rd`

**Predictability Scoring:**

The predictability score (0-100%) represents how easy it would be for an attacker to guess the user's NEXT password based on observed patterns.

| Pattern Type | Weight | Rationale |
|-------------|--------|-----------|
| Consecutive Hash Reuse | 55% | Same password repeatedly - very likely to continue |
| Incrementing Number | 45% | Trivial to guess next (just add 1) |
| Year Increment | 45% | Trivial to guess next year |
| Season Rotation | 40% | Only 4 seasons to try |
| Password Reversion | 35% | Returns to old passwords - behavioral pattern |
| Special Char Rotation | 35% | Limited special chars (~10 common ones) |
| Minimal Changes | 30% | Small changes narrow the search space |
| Base Word Persistence | 20% | Same root helps narrow guessing |
| Leet Progression | 15% | Harder to predict exact substitution |

**Score Interpretation:**
- **100%**: All password changes are to the same hash (always same password)
- **70%+** (Critical): Next password is trivially guessable
- **40-69%** (High): Strong patterns make guessing feasible
- **Below 40%** (Medium): Some patterns detected but harder to exploit

Multiple patterns stack - a user with season rotation + year increment + special char rotation will score very high.

**Implementation Approach:**
1. Parse history entries from both pwdump and ADD JSON formats
2. Match history hashes against potfile to get plaintext
3. Detect patterns using specialized detectors for each pattern type
4. Hash-based reuse detection works even without cracking
5. Calculate predictability score based on pattern weights and confidence
6. Display color-coded results: red (reuse), orange (patterns), white (no issues)

**Files:**
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

### Account Description Sensitive Data Analysis (PLANNED)

**Status:** Planned for implementation

**Description:** Scan Active Directory account description fields for sensitive information disclosures. Administrators often store passwords, hints, or other sensitive data in account descriptions, creating security risks.

**Required ADD JSON Fields:**
- `Description` - Account description field
- `SamAccountName` - For account identification
- `adminCount` - To flag privileged accounts with sensitive descriptions

**Detection Patterns:**

| Pattern Type | Examples | Risk Level |
|-------------|----------|------------|
| Plaintext passwords | "password: Welcome1!", "pwd=Summer2024" | Critical |
| Password hints | "same as username", "birthday + year" | High |
| Default credentials | "default password", "initial pw: changeme" | Critical |
| Temporary passwords | "temp pw until reset", "onboarding: Company1" | High |
| Service account secrets | "API key:", "connection string:" | Critical |
| PII/Contact info | SSN patterns, phone numbers with context | Medium |
| Reset instructions | "reset to FirstnameYear", "standard format" | Medium |

**Detection Techniques:**
1. **Keyword matching** - Common password-related terms (password, pwd, pass, credential, secret, key)
2. **Pattern recognition** - Strings that look like passwords (mixed case + numbers + special chars)
3. **Contextual analysis** - Phrases indicating credential storage ("is set to", "equals", "=")
4. **Entropy analysis** - High-entropy strings that may be secrets
5. **Format detection** - Connection strings, API keys, tokens

**Risk Scoring:**
- **Critical**: Actual credentials or secrets found
- **High**: Strong password hints or temporary credential references
- **Medium**: Vague hints or suspicious patterns
- **Low**: Potentially sensitive but ambiguous

**Report Output (`description_analysis.json`):**
```json
{
  "summary": {
    "total_accounts_analyzed": 5000,
    "accounts_with_descriptions": 1234,
    "sensitive_findings": 45,
    "critical_count": 12,
    "high_count": 18,
    "medium_count": 15
  },
  "findings": [
    {
      "sam_account_name": "svc_backup",
      "description": "Service account - password: Backup2024!",
      "risk_level": "Critical",
      "detection_type": "plaintext_password",
      "extracted_secret": "Backup2024!",
      "is_privileged": true,
      "matched_patterns": ["password:", "plaintext credential"]
    }
  ],
  "statistics": {
    "by_risk_level": {"Critical": 12, "High": 18, "Medium": 15},
    "by_detection_type": {"plaintext_password": 8, "password_hint": 15, ...},
    "privileged_accounts_affected": 5
  }
}
```

**UI Components:**
- Dedicated report section with findings table
- Risk-level color coding (red/orange/yellow)
- Masked display of extracted secrets (click to reveal)
- Filter by risk level and detection type
- Export findings for remediation tracking

**Files to Create:**
- `description_analysis.py` - Pattern matching and analysis module

**Use Cases:**
- Identify accounts with exposed credentials in descriptions
- Audit service accounts for hardcoded secrets
- Find password hints that weaken security
- Prioritize remediation based on account privilege level
- Compliance reporting for credential management policies

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

#### Free-form Prompt Lab (PLANNED)

**Status:** Planned for AI Report Lab page

**Description:** Allow users to write custom prompts with access to session data via template variables. This enables ad-hoc analysis questions without requiring code changes.

**Location:** AI Report Lab page (`/api/ai/report/test`)

**Features:**
- Free-form text input for custom prompts
- Template variable injection from current session data
- Server/model selection (same as existing Report Lab)
- Temperature control
- Save/load custom prompts for reuse

**Available Template Variables:**
| Variable | Description |
|----------|-------------|
| `{cracked_passwords_unique}` | List of unique cracked passwords |
| `{cracked_passwords_all}` | All cracked passwords with counts |
| `{account_names}` | List of account names |
| `{domain_name}` | Current domain name |
| `{company_name}` | Company name from session |
| `{total_accounts}` | Total account count |
| `{cracked_count}` | Number of cracked accounts |
| `{crack_rate}` | Crack percentage |
| `{password_lengths}` | Distribution of password lengths |
| `{top_passwords}` | Most common passwords |

**Example Prompts:**
```
How many passwords in {cracked_passwords_unique} contain city or state names?
List them grouped by geographic location.
```

```
Analyze {cracked_passwords_unique} for passwords that appear to reference
the company name "{company_name}" or variations of it.
```

```
Given these {cracked_count} cracked passwords from {total_accounts} accounts,
identify any passwords that suggest insider knowledge or specific roles
(like "admin", "backup", "sql", etc).
```

**Use Cases:**
- Ad-hoc analysis questions during assessments
- Testing new analysis ideas before building formal features
- Client-specific queries (e.g., "Find passwords mentioning [client product]")
- Research and exploration of password patterns

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
| Password History Analysis | Dec 2024 | Pattern detection, predictability scoring, hash reuse detection |
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

### Performance Optimizations

- **Integer Account ID Mapping for Set Operations**: In functions like `substring_analysis`, store account IDs as integers instead of strings. Map account strings → integer IDs once at the start, store sets of ints instead of sets of strings. This reduces memory footprint and speeds up set operations (add, intersection, subset checks) since integer hashing and comparison is faster than string operations.

### Feature Ideas

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

*Last Updated: January 16, 2026*
