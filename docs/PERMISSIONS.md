# File Permissions Reference

This document defines the expected file ownership and permissions for HM1K deployments.

## HM1K Server (`/opt/hm1k`)

### Deployment User: `audit`
### Service User: `hm1k`

| Path | Owner | Group | Mode | Notes |
|------|-------|-------|------|-------|
| `/opt/hm1k/` | audit | audit | 775 | Application root |
| `/opt/hm1k/*.py` | audit | audit | 664 | Python source files |
| `/opt/hm1k/static/` | audit | audit | 755 | Static assets directory |
| `/opt/hm1k/static/**/*` (files) | audit | audit | 644 | Must be world-readable |
| `/opt/hm1k/static/**/*` (dirs) | audit | audit | 755 | Must be world-executable |
| `/opt/hm1k/templates/` | audit | audit | 755 | Jinja templates |
| `/opt/hm1k/templates/*` | audit | audit | 644 | Must be world-readable |
| `/opt/hm1k/key.pem` | audit | audit | 640 | SSL private key (restricted) |
| `/opt/hm1k/cert.pem` | audit | audit | 644 | SSL certificate |
| `/opt/hm1k/.env` | audit | audit | 640 | Environment config (restricted) |
| `/opt/hm1k/data/` | hm1k | hm1k | 755 | Runtime data (service writes) |
| `/opt/hm1k/logs/` | hm1k | hm1k | 755 | Log files (service writes) |
| `/opt/hm1k/flask_session/` | hm1k | hm1k | 755 | Session storage (service writes) |
| `/opt/hm1k/uploads/` | hm1k | hm1k | 755 | User uploads (service writes) |

### Common Issues
- **403 on static files**: Static files need 644 permissions (world-readable)
- **Service can't write logs**: `logs/` directory must be owned by `hm1k:hm1k`
- **Session errors**: `flask_session/` must be owned by `hm1k:hm1k`

---

## HM1K Agent (`/opt/hm1k-agent`)

### Service User: `hm1k-agent`

| Path | Owner | Group | Mode | Notes |
|------|-------|-------|------|-------|
| `/opt/hm1k-agent/` | root | root | 755 | Agent root (can be root) |
| `/opt/hm1k-agent/venv/` | hm1k-agent | hm1k-agent | 755 | **CRITICAL: Must be owned by service user for self-updates** |
| `/opt/hm1k-agent/venv/**/*` | hm1k-agent | hm1k-agent | - | Entire venv tree |
| `/etc/hm1k-agent/` | hm1k-agent | hm1k-agent | 755 | Config directory |
| `/etc/hm1k-agent/config.yaml` | hm1k-agent | hm1k-agent | 640 | Agent config (contains token) |
| `/var/log/hm1k-agent/` | hm1k-agent | hm1k-agent | 755 | Log directory |
| `/var/cache/hm1k-agent/` | hm1k-agent | hm1k-agent | 755 | Resource cache |

### Common Issues
- **Agent can't self-update**: venv owned by root instead of hm1k-agent
- **Permission denied on pip install**: Same as above
- **Can't write logs**: Log directory permissions

---

## Verification Commands

### Server Permissions Audit
```bash
# Check static file permissions (should be 644)
find /opt/hm1k/static -type f ! -perm 644 -ls

# Check static directory permissions (should be 755)
find /opt/hm1k/static -type d ! -perm 755 -ls

# Check runtime directory ownership (should be hm1k:hm1k)
ls -la /opt/hm1k/ | grep -E "^d.*hm1k.*hm1k.*(data|logs|flask_session|uploads)"

# Check key.pem permissions (should be 640 or more restrictive)
ls -la /opt/hm1k/key.pem
```

### Agent Permissions Audit
```bash
# Check venv ownership (should be hm1k-agent:hm1k-agent)
ls -la /opt/hm1k-agent/venv/

# Find files in venv NOT owned by hm1k-agent
find /opt/hm1k-agent/venv -! -user hm1k-agent -ls

# Check config permissions
ls -la /etc/hm1k-agent/
```

---

## Fix Commands

### Server
```bash
# Fix static file permissions
find /opt/hm1k/static -type f -exec chmod 644 {} \;
find /opt/hm1k/static -type d -exec chmod 755 {} \;
find /opt/hm1k/templates -type f -exec chmod 644 {} \;

# Fix runtime directory ownership
sudo chown -R hm1k:hm1k /opt/hm1k/data
sudo chown -R hm1k:hm1k /opt/hm1k/logs
sudo chown -R hm1k:hm1k /opt/hm1k/flask_session
sudo chown -R hm1k:hm1k /opt/hm1k/uploads

# Fix key permissions
chmod 640 /opt/hm1k/key.pem
chmod 640 /opt/hm1k/.env
```

### Agent
```bash
# Fix venv ownership (CRITICAL for self-updates)
sudo chown -R hm1k-agent:hm1k-agent /opt/hm1k-agent/venv

# Fix config ownership
sudo chown -R hm1k-agent:hm1k-agent /etc/hm1k-agent
sudo chmod 640 /etc/hm1k-agent/config.yaml

# Fix log directory
sudo chown -R hm1k-agent:hm1k-agent /var/log/hm1k-agent
```
