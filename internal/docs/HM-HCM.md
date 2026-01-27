# HM-HCM: Hash Master Hashcat Central Management

Internal documentation for the distributed hashcat cracking system integrated into Hash Master 1000.

## Overview

HM-HCM enables centralized management of multiple hashcat cracking servers from the Hash Master 1000 web interface. It provides:

- **Distributed job dispatch** - Send cracking jobs to GPU-equipped servers
- **Real-time monitoring** - SSE-based live status updates
- **Resource management** - Centralized wordlist and rule storage
- **Offline resilience** - Agents buffer results when server is unreachable
- **Potfile synchronization** - Cracked hashes sync back to master server

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     HM1K Server (192.168.8.88)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │   Web UI     │  │  REST API    │  │   SSE Event Stream    │  │
│  │ /agents/jobs │  │ /api/agent/* │  │ /api/agent/events     │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  Resources   │  │   Potfile    │  │    Job Templates      │  │
│  │   Manager    │  │   Manager    │  │      & Sequences      │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
        ┌───────────────────┐  ┌───────────────────┐
        │   Cracking Agent  │  │   Cracking Agent  │
        │   192.168.8.24    │  │   192.168.8.229   │
        │   ┌───────────┐   │  │   ┌───────────┐   │
        │   │  hashcat  │   │  │   │  hashcat  │   │
        │   │  RTX 4090 │   │  │   │  RTX 4090 │   │
        │   └───────────┘   │  │   └───────────┘   │
        └───────────────────┘  └───────────────────┘
```

## Components

### Server-Side (hm1k.py)

#### Web UI Pages
- `/agents/jobs` - Job manager dashboard (create, monitor, control jobs)
- `/agents/wordlists` - Wordlist resource management
- `/agents/rules` - Rule file management

#### REST API Endpoints

**Agent Communication:**
- `POST /api/agent/heartbeat` - Agent keepalive with hardware stats
- `POST /api/agent/status` - Job progress updates
- `POST /api/agent/job/complete` - Job completion with results
- `POST /api/agent/job/error` - Error reporting
- `GET /api/agent/events` - SSE event stream for real-time updates

**Job Control:**
- `GET /api/agent/list` - List all connected agents
- `POST /api/agent/<agent_id>/job` - Submit job to specific agent
- `POST /api/agent/<agent_id>/stop` - Stop running job
- `POST /api/agent/<agent_id>/pause` - Pause/resume job

**Resources:**
- `GET /api/agent/resources/<type>` - List wordlists/rules
- `GET /api/agent/resources/<type>/<id>` - Download resource file

**Potfile Sync:**
- `POST /api/agent/potfile/sync` - Sync cracked hashes from agent
- `GET /api/agent/potfile/full` - Get complete master potfile
- `GET /api/agent/job/<job_id>/potfile` - Get job-specific results

**Templates & Sequences:**
- `GET/POST /api/agent/templates` - Manage job templates
- `GET/POST /api/agent/sequences` - Manage job sequences

**Performance:**
- `POST /api/agent/performance/benchmark` - Record benchmark results
- `GET /api/agent/<agent_id>/performance` - Get agent performance history
- `POST /api/agent/<agent_id>/benchmark/run` - Trigger benchmark on agent

#### Agent Distribution
- `GET /agent/install.sh` - Bootstrap installer script
- `GET /agent/deploy.sh` - Full deployment script
- `GET /agent/*.whl` - Python wheel package

### Agent-Side (internal/hm1k-agent/)

The agent is a Python daemon that runs on cracking servers.

#### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| `Agent` | agent.py | Main daemon orchestrator |
| `APIClient` | api_client.py | REST communication with server |
| `SSEListener` | sse_listener.py | Real-time event subscription |
| `HashcatRunner` | hashcat_runner.py | Hashcat process management |
| `JobManager` | job_manager.py | Job lifecycle and state |
| `ResourceCache` | resource_cache.py | Local wordlist/rule cache |
| `OfflineBuffer` | offline_buffer.py | Result buffering when offline |
| `PotfileSync` | potfile_sync.py | Potfile synchronization |
| `LocalAPIServer` | local_api.py | Health checks (port 8787) |
| `Config` | config.py | YAML configuration handling |

#### Installation

On the HM1K server, the agent is available for download:

```bash
# One-liner bootstrap install
curl -sSLk https://192.168.8.88/agent/install.sh | sudo bash

# Or download and run manually
wget --no-check-certificate https://192.168.8.88/agent/install.sh
chmod +x install.sh
sudo ./install.sh
```

#### Configuration

Agent config is stored at `/etc/hm1k-agent/config.yaml`:

```yaml
server:
  url: "https://192.168.8.88"
  token: ""  # Set during registration
  verify_ssl: true

agent:
  name: ""  # Defaults to hostname
  tags:
    - "datacenter-1"
    - "gpu-rtx4090"

hashcat:
  binary: "/opt/hashcat/current/hashcat"
  workdir: "/var/lib/hm1k-agent/hashcat"
  devices: []  # Empty = all GPUs
  workload_profile: 3
  optimized_kernels: true
```

#### Service Management

```bash
# Enable and start
sudo systemctl enable --now hm1k-agent

# Check status
sudo systemctl status hm1k-agent

# View logs
journalctl -u hm1k-agent -f

# Local health check
curl http://127.0.0.1:8787/health
```

## Job Templates

Built-in templates are defined in `app/job_templates.py`:

| Category | Templates |
|----------|-----------|
| Wordlist | rockyou, rockyou + best64, common passwords |
| Rules | OneRuleToRuleThemAll, d3adhob0, dive |
| Brute Force | Numeric PIN, alphanumeric masks |
| Hybrid | Wordlist + mask append/prepend |
| Hash-Specific | NTLM optimized, WPA-specific |

Custom templates can be created via the web UI or API.

## Job Sequences

Sequences allow chaining multiple jobs to run in order:

```json
{
  "name": "Standard AD Audit",
  "description": "Common attacks for AD password audits",
  "template_ids": [
    "rockyou-basic",
    "rockyou-best64",
    "one-rule-all",
    "numeric-8"
  ]
}
```

## Resource Management

### Wordlists

Stored in `{HM1K_DATA_DIR}/resources/wordlists/`:
- Uploaded via web UI at `/agents/wordlists`
- Synced to agents on-demand (cached locally)
- SHA256 verified for integrity

### Rules

Stored in `{HM1K_DATA_DIR}/resources/rules/`:
- Managed via `/agents/rules`
- Common rules can be pre-loaded

## Potfile Synchronization

Cracked hashes flow from agents to the master potfile:

1. Agent cracks hashes during job
2. Results stored in job-specific potfile
3. Agent syncs new cracks to server via `/api/agent/potfile/sync`
4. Server merges into master potfile
5. Master potfile available for future password lookups

## Offline Resilience

When the server is unreachable:

1. Agent continues running active jobs
2. Status updates buffered to `{DATA_DIR}/offline_buffer/`
3. Cracked results stored locally
4. On reconnect, buffer is flushed to server
5. SSE reconnection with exponential backoff

## Security Considerations

- Agent authentication via JWT tokens
- SSL/TLS for all communication
- API endpoints require valid agent token
- Resources served only to authenticated agents
- Local API server binds to localhost only

## Files

### Server-Side
```
hm1k.py                      # Main Flask app with agent routes
app/job_templates.py         # Job template definitions
app/resource_manager.py      # Wordlist/rule storage
app/potfile_manager.py       # Master potfile management
app/performance_tracker.py   # Benchmark data storage
templates/job_manager.html   # Job management UI
templates/wordlists.html     # Wordlist management UI
templates/rules.html         # Rules management UI
```

### Agent-Side
```
internal/hm1k-agent/
├── deploy.sh                # Deployment script
├── install.sh               # Bootstrap installer
├── config.example.yaml      # Example configuration
├── pyproject.toml           # Python package definition
└── src/hm1k_agent/
    ├── agent.py             # Main daemon
    ├── api_client.py        # REST client
    ├── sse_listener.py      # SSE subscription
    ├── hashcat_runner.py    # Hashcat process wrapper
    ├── job_manager.py       # Job state machine
    ├── resource_cache.py    # Local resource cache
    ├── offline_buffer.py    # Offline message queue
    ├── potfile_sync.py      # Potfile management
    ├── local_api.py         # Health check server
    ├── hardware.py          # GPU detection
    ├── config.py            # Configuration loader
    ├── init_wizard.py       # Interactive setup
    ├── auth.py              # Token management
    └── cli.py               # CLI interface
```

## Environment Variables

Server-side configuration in `.env`:

```bash
# Enable hashcat management features
HM1K_AGENTS_ENABLED=true

# Agent JWT secret (generate unique value)
HM1K_AGENT_JWT_SECRET=your-secret-key

# Resource storage location
HM1K_DATA_DIR=/opt/hm1k/data

# Master potfile path (optional, defaults to data_dir/potfile/)
HM1K_MASTER_POTFILE=/opt/hm1k/data/potfile/master.potfile
```

## Status

**Current State:** Internal/Experimental

This feature set is under active development and may be included in a future Hash Master 1000 3.0 release. Currently deployed for internal use only.
