# HM1K Agent

**Hashcat cracking agent for Hash Master 1000**

A lightweight Python agent that runs on cracking servers to execute hashcat jobs and report status back to the Hash Master 1000 server.

## Features

- Executes hashcat jobs with full parameter control
- Real-time status reporting via `--status-json`
- Offline resilience - jobs continue if server disconnects
- Pull-based resource synchronization (wordlists, rules)
- JWT-based authentication with discovery mode
- Systemd service integration

## Requirements

- Python 3.9+
- Hashcat 6.0+ (with `--status-json` support)
- Linux (Ubuntu 20.04+, Debian 10+, RHEL 8+)
- Network connectivity to HM1K server

## Installation

```bash
# Install from PyPI (when published)
pip install hm1k-agent

# Or install from source
pip install .
```

## Quick Start

```bash
# Initialize the agent (interactive wizard)
hm1k-agent init

# Check agent status
hm1k-agent status

# Test server connectivity
hm1k-agent test-connection

# View logs
hm1k-agent logs
```

## Configuration

The agent stores its configuration in `/etc/hm1k-agent/config.yaml`:

```yaml
server:
  url: "https://192.168.8.88"
  token: "..."  # JWT token (managed by agent)
  verify_ssl: false  # Set to true if using CA-signed certificates

agent:
  id: "cracker-01"
  name: "Primary Cracker"
  description: "RTX 4080 system"

hashcat:
  binary: "/opt/hashcat/current/hashcat"  # or /usr/bin/hashcat
  workdir: "/var/lib/hm1k-agent/hashcat"

resources:
  cache_dir: "/var/lib/hm1k-agent/cache"
  max_cache_size_gb: 50
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      HM1K AGENT                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   CLI        │    │  API Client  │    │ SSE Listener │  │
│  │  (click)     │    │  (requests)  │    │ (sseclient)  │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘  │
│         │                   │                   │           │
│         ▼                   ▼                   ▼           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Agent Core                        │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ Job Manager │  │ Hashcat     │  │ Resource    │  │   │
│  │  │             │  │ Runner      │  │ Cache       │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  │                                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ Config      │  │ Auth        │  │ Offline     │  │   │
│  │  │ Manager     │  │ Manager     │  │ Buffer      │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│                   ┌────────────────┐                        │
│                   │    Hashcat     │                        │
│                   │  (subprocess)  │                        │
│                   └────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Communication Protocol

### Agent → Server (REST)

| Endpoint | Purpose |
|----------|---------|
| `POST /api/agent/heartbeat` | Health check + status |
| `POST /api/agent/status` | Job progress updates |
| `POST /api/agent/job/complete` | Job finished + results |
| `POST /api/agent/job/error` | Job failed + error details |
| `GET /api/agent/resources/*` | Pull wordlists, rules |

### Server → Agent (SSE)

| Event | Purpose |
|-------|---------|
| `job:assigned` | New job for this agent |
| `job:pause` | Pause current job |
| `job:resume` | Resume paused job |
| `job:stop` | Stop and cancel job |
| `resource:sync` | New resource available |
| `ping` | Keep-alive |

## Systemd Service

After running `hm1k-agent init`, a systemd service is created:

```bash
# Enable and start
sudo systemctl enable --now hm1k-agent

# Check status
sudo systemctl status hm1k-agent

# View logs
sudo journalctl -u hm1k-agent -f
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/
ruff check src/

# Type checking
mypy src/
```

## License

This project is part of Hash Master 1000 and is licensed under CC BY-NC 4.0.
