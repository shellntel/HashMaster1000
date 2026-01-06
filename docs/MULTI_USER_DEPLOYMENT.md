# Multi-User Deployment Guide

This guide explains how to deploy Hash Master 1000 for concurrent multi-user access.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Web Browsers                        │
│  (User A: Firefox)   (User B: Chrome)               │
└───────────────┬──────────────┬──────────────────────┘
                │ HTTPS:8443   │ HTTPS:8443
                ▼              ▼
┌─────────────────────────────────────────────────────┐
│              Gunicorn (4 workers)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐│
│  │ Worker 1 │ │ Worker 2 │ │ Worker 3 │ │Worker 4 ││
│  │ 2 threads│ │ 2 threads│ │ 2 threads│ │2 threads││
│  └──────────┘ └──────────┘ └──────────┘ └─────────┘│
│  = 8 concurrent requests capacity                    │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│           Hash Master 1000 Flask App                 │
│                                                       │
│  Per-User Session Isolation:                         │
│  - User A → Flask session → Session abc123           │
│  - User B → Flask session → Session def456           │
│                                                       │
│  data/sessions/                                       │
│    ├── abc123/  (User A's analysis)                  │
│    └── def456/  (User B's analysis)                  │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- Python 3.11+
- Virtual environment with dependencies installed
- SSL certificates (cert.pem, key.pem)
- `.env` file configured with `MULTI_USER_ENABLED="true"`

## Quick Start (Development/Testing)

For quick testing with 2-3 concurrent users:

### Linux/macOS (Gunicorn)

```bash
# Activate virtual environment
source .venv/bin/activate

# Install Gunicorn
pip install gunicorn

# Run with Gunicorn (8 workers, 2 threads each = 16 concurrent)
gunicorn -c gunicorn.conf.py hm1k:app
```

### Windows (Waitress)

```powershell
# Activate virtual environment
.venv\Scripts\activate

# Install Waitress
pip install waitress

# Run with Waitress (8 threads = 8 concurrent)
python waitress_server.py
```

Access at: `https://localhost:8443`

## Production Deployment (systemd)

For production use with automatic startup and restart:

### 1. Install Gunicorn

```bash
source .venv/bin/activate
pip install gunicorn
```

### 2. Update paths in service file

Edit `docs/systemd/hm1k.service` and change:
- `User=njoyzrd` → Your username
- `Group=njoyzrd` → Your group
- `WorkingDirectory=...` → Your HM1K installation path
- `Environment="PATH=..."` → Your virtualenv path
- `ExecStart=...` → Your virtualenv gunicorn path

### 3. Install systemd service

```bash
# Copy service file to systemd
sudo cp docs/systemd/hm1k.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable hm1k

# Start service
sudo systemctl start hm1k

# Check status
sudo systemctl status hm1k
```

### 4. View logs

```bash
# Systemd journal
sudo journalctl -u hm1k -f

# Application logs
tail -f logs/gunicorn_access.log
tail -f logs/gunicorn_error.log
```

### 5. Manage service

```bash
# Restart
sudo systemctl restart hm1k

# Stop
sudo systemctl stop hm1k

# Disable (prevent auto-start)
sudo systemctl disable hm1k
```

## Configuration Tuning

### Adjust Workers Based on CPU Cores

Edit `gunicorn.conf.py`:

```python
# Option 1: Auto-calculate (default)
workers = multiprocessing.cpu_count() * 2 + 1

# Option 2: Fixed number for predictable capacity
workers = 4  # For 2-5 concurrent users
workers = 8  # For 5-10 concurrent users
```

### Adjust Timeout for AAIA Analysis

Long-running AAIA analyses may need extended timeout:

```python
# gunicorn.conf.py
timeout = 900  # 15 minutes (default)
timeout = 1800  # 30 minutes (for very large models)
```

### Thread Count

More threads = more concurrent requests per worker:

```python
# gunicorn.conf.py
threads = 2  # Conservative (default)
threads = 4  # Higher concurrency (more RAM usage)
```

**Total Capacity:** `workers × threads` concurrent requests

Examples:
- 4 workers × 2 threads = 8 concurrent users
- 8 workers × 2 threads = 16 concurrent users
- 4 workers × 4 threads = 16 concurrent users

## User Isolation

Each user gets their own:

1. **Flask Session** - Stored in `flask_session/` directory
   - Contains current session ID
   - Session cookie ties user to their data

2. **Session Directory** - `data/sessions/<session_id>/`
   - All analysis files
   - AAIA results
   - HIBP results

3. **Login Session** - Flask-Login tracks authentication
   - Username
   - Role (admin/user)
   - Permissions

## Testing Multi-User Access

### Test Scenario 1: Two Users, Different Sessions

1. **User A (Browser 1):**
   - Login as `admin`
   - Upload pwdump1.txt
   - Run analysis → Creates session `abc123`

2. **User B (Browser 2):**
   - Login as `pentester`
   - Upload pwdump2.txt
   - Run analysis → Creates session `def456`

3. **Verify Isolation:**
   - User A sees only their pwdump1 results
   - User B sees only their pwdump2 results
   - Sessions are completely independent

### Test Scenario 2: Two Users, Same Dataset

1. **User A:**
   - Uploads shared dataset
   - Runs AAIA with SPI + Company Intel

2. **User B:**
   - Uploads same dataset (or accesses shared session)
   - Runs AAIA with different model configurations

Both analyses run concurrently without interference.

## Performance Considerations

### Memory Usage

Each worker process loads the full Flask app:
- Base memory: ~200 MB per worker
- Active analysis: +500 MB - 2 GB (depends on dataset size)
- AAIA with large models: +2-8 GB (model context)

**Example:** 4 workers with typical usage = ~4-8 GB RAM

### CPU Usage

- Standard analysis: Low CPU (mostly I/O)
- HIBP API checks: Moderate (network-bound)
- AAIA analysis: **High CPU** (LLM inference on Ollama server)

**Note:** AAIA CPU load is on the **Ollama server**, not the HM1K server.

### Concurrent AAIA Limitations

If multiple users run AAIA simultaneously:
- Requests queue at the Ollama server
- Each user's AAIA will take longer
- Consider multiple Ollama servers for heavy usage

## Troubleshooting

### Workers timing out during AAIA

**Symptom:** `[CRITICAL] WORKER TIMEOUT` in logs

**Solution:** Increase timeout in `gunicorn.conf.py`:
```python
timeout = 1800  # 30 minutes
```

### High memory usage

**Symptom:** System running out of RAM

**Solution:** Reduce workers or use memory limits:
```python
workers = 2  # Fewer workers
max_requests = 500  # Restart workers more often
```

### Session data not persisting

**Symptom:** Users lose session when workers restart

**Solution:** Ensure `SESSION_TYPE = "filesystem"` in `hm1k.py`:
```python
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "flask_session"
```

### Users seeing each other's data

**Symptom:** User A sees User B's results

**Diagnosis:** Check that per-user session isolation is working:
```bash
# Check Flask session storage
ls -la flask_session/

# Check session manager is using Flask sessions
grep -A 10 "get_current_session" app/session_manager.py
```

Should see Flask session storage logic, not global file.

## Security Considerations

### SSL/HTTPS

Always use HTTPS in production:
- Self-signed cert OK for internal use
- Let's Encrypt recommended for internet-facing

### Firewall

Restrict access to trusted networks:
```bash
# Allow only local network
sudo ufw allow from 192.168.1.0/24 to any port 8443

# Or specific IPs
sudo ufw allow from 192.168.1.100 to any port 8443
```

### User Management

- Limit admin accounts
- Use strong passwords (enforced in UI)
- Regular user accounts can't access Advanced Mode
- Session isolation prevents data leakage

## Monitoring

### Check Service Status

```bash
# Is it running?
sudo systemctl status hm1k

# Recent logs
sudo journalctl -u hm1k --since "10 minutes ago"

# Follow logs in real-time
sudo journalctl -u hm1k -f
```

### Monitor Resource Usage

```bash
# CPU and memory per worker
ps aux | grep gunicorn

# Total resource usage
htop  # Filter by 'hm1k' or 'gunicorn'
```

### Access Logs

```bash
# Who's accessing the app?
tail -f logs/gunicorn_access.log

# Recent errors
tail -f logs/gunicorn_error.log
```

## Windows Production Deployment

For Windows production deployments, use Waitress with NSSM (Non-Sucking Service Manager) to run as a Windows service:

### 1. Install NSSM

Download from: https://nssm.cc/download

### 2. Install HM1K as Windows Service

```powershell
# Install the service
nssm install hm1k "F:\apps\hm1k-internal\hm1k\Scripts\python.exe" "F:\apps\hm1k-internal\waitress_server.py"

# Set working directory
nssm set hm1k AppDirectory "F:\apps\hm1k-internal"

# Set startup type (auto-start on boot)
nssm set hm1k Start SERVICE_AUTO_START

# Start the service
nssm start hm1k
```

### 3. Manage Service

```powershell
# Check status
nssm status hm1k

# Stop service
nssm stop hm1k

# Restart service
nssm restart hm1k

# Remove service
nssm remove hm1k confirm
```

### 4. View Logs

Waitress logs to console, which NSSM redirects to:
- `C:\Windows\System32\config\systemprofile\AppData\Local\NSSM\hm1k\logs\`

Or configure custom log paths:
```powershell
nssm set hm1k AppStdout "F:\apps\hm1k-internal\logs\waitress_output.log"
nssm set hm1k AppStderr "F:\apps\hm1k-internal\logs\waitress_error.log"
```

## Scaling Beyond 10 Users

For larger deployments (>10 concurrent users):

### Option 1: Nginx Reverse Proxy

```
Internet → Nginx (SSL, load balancing, static files)
            ↓
          Gunicorn/Waitress (HM1K)
```

Benefits:
- Better SSL performance
- Serve static files faster
- Rate limiting
- Multiple backend instances

### Option 2: Multiple Ollama Servers

Distribute AAIA load:
- Configure 2-3 Ollama servers in `.env`
- HM1K automatically distributes requests

### Option 3: Database Backend

Replace filesystem sessions with Redis/PostgreSQL:
- Better concurrent access
- Session sharing across multiple HM1K instances
- Required for horizontal scaling

## Support

For issues or questions:
- Check logs: `logs/gunicorn_error.log`
- GitHub Issues: [Your repo URL]
- Internal team contact: [Your contact]

---

*Last Updated: January 2026*
