# HM1K Production Deployment with Nginx

This guide covers deploying Hash Master 1000 with nginx as a reverse proxy for production environments.

## Architecture

```
┌─────────────┐     HTTPS      ┌─────────────┐      HTTP       ┌──────────────┐
│   Browser   │ ──────────────▶│    Nginx    │ ──────────────▶│   Gunicorn   │
│             │     :443       │  (SSL term) │   127.0.0.1    │   (8 workers)│
└─────────────┘                │             │     :8000      │              │
                               │  - SSL/TLS  │                │  - Flask app │
                               │  - HTTP/2   │                │  - 2 threads │
                               │  - Gzip     │                └──────────────┘
                               │  - Static   │
                               └─────────────┘
```

## Prerequisites

- Ubuntu 22.04+ or similar Linux distribution
- Root/sudo access
- SSL certificate (self-signed, internal CA, or public CA)
- Python 3.10+ with venv

## Step 1: Create Application User

```bash
# Create dedicated user with no login shell
sudo useradd -r -s /sbin/nologin -d /opt/hm1k hm1k

# Create application directory
sudo mkdir -p /opt/hm1k
sudo chown hm1k:hm1k /opt/hm1k
```

## Step 2: Deploy Application

```bash
# Clone or copy application files to /opt/hm1k
# Example with rsync:
sudo rsync -av --exclude='.git' --exclude='.venv' --exclude='__pycache__' \
    /path/to/hm1k/ /opt/hm1k/

# Create and set up virtual environment
sudo -u hm1k python3 -m venv /opt/hm1k/.venv
sudo -u hm1k /opt/hm1k/.venv/bin/pip install --upgrade pip
sudo -u hm1k /opt/hm1k/.venv/bin/pip install -r /opt/hm1k/requirements.txt

# Create required directories
sudo -u hm1k mkdir -p /opt/hm1k/data /opt/hm1k/logs /opt/hm1k/flask_session

# Set permissions
sudo chown -R hm1k:hm1k /opt/hm1k
sudo chmod 750 /opt/hm1k
```

## Step 3: Configure Application

```bash
# Create .env file (copy from example or create new)
sudo -u hm1k bash -c 'cat > /opt/hm1k/.env << EOF
FLASK_ENV=production
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b\"YOUR_PASSWORD\", bcrypt.gensalt()).decode())")
EOF'

# Secure the .env file
sudo chmod 600 /opt/hm1k/.env
```

## Step 4: Install and Configure Nginx

```bash
# Install nginx
sudo apt update
sudo apt install -y nginx

# Copy the nginx configuration
sudo cp /opt/hm1k/docs/nginx/hm1k.conf /etc/nginx/sites-available/hm1k

# Edit the configuration for your environment
sudo nano /etc/nginx/sites-available/hm1k
# Update:
#   - server_name (your hostname)
#   - ssl_certificate (path to your cert)
#   - ssl_certificate_key (path to your key)

# Enable the site
sudo ln -sf /etc/nginx/sites-available/hm1k /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm -f /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

## Step 5: Install SSL Certificate

For internally signed certificates:
```bash
# Copy certificate files
sudo cp your_cert.crt /etc/ssl/certs/hm1k.crt
sudo cp your_cert.key /etc/ssl/private/hm1k.key

# Set permissions
sudo chmod 644 /etc/ssl/certs/hm1k.crt
sudo chmod 600 /etc/ssl/private/hm1k.key
```

For self-signed (development/testing only):
```bash
# Generate self-signed certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/hm1k.key \
    -out /etc/ssl/certs/hm1k.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=hm1k.local"
```

## Step 6: Install systemd Service

```bash
# Copy the production service file
sudo cp /opt/hm1k/docs/systemd/hm1k-production.service /etc/systemd/system/hm1k.service

# Reload systemd
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable hm1k
sudo systemctl start hm1k

# Check status
sudo systemctl status hm1k
```

## Step 7: Configure Firewall

```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Verify rules
sudo ufw status
```

## Verification

1. **Check services are running:**
   ```bash
   sudo systemctl status nginx
   sudo systemctl status hm1k
   ```

2. **Check listening ports:**
   ```bash
   sudo ss -tlnp | grep -E ':(80|443|8000)'
   ```

3. **Test local connectivity:**
   ```bash
   curl -k https://localhost/health
   ```

4. **Check logs:**
   ```bash
   # Nginx logs
   sudo tail -f /var/log/nginx/hm1k_error.log

   # Gunicorn logs
   sudo tail -f /opt/hm1k/logs/gunicorn_error.log

   # Systemd journal
   sudo journalctl -u hm1k -f
   ```

## Troubleshooting

### 502 Bad Gateway
- Check if Gunicorn is running: `systemctl status hm1k`
- Check Gunicorn is listening: `ss -tlnp | grep 8000`
- Check Gunicorn logs: `tail /opt/hm1k/logs/gunicorn_error.log`

### 403 Forbidden
- Check file permissions: `ls -la /opt/hm1k/static/`
- Verify nginx user can read static files

### SSL Certificate Errors
- Verify certificate paths in nginx config
- Check certificate validity: `openssl x509 -in /etc/ssl/certs/hm1k.crt -noout -dates`

### Slow Response / Timeouts
- AAIA analysis can take up to 15 minutes
- Verify timeout settings in nginx and Gunicorn configs
- Check system resources: `htop`, `free -h`

## Maintenance

### Restart Services
```bash
sudo systemctl restart hm1k
sudo systemctl reload nginx
```

### Update Application
```bash
# Stop service
sudo systemctl stop hm1k

# Update files
sudo rsync -av --exclude='.git' --exclude='.venv' /path/to/updated/hm1k/ /opt/hm1k/

# Update dependencies if needed
sudo -u hm1k /opt/hm1k/.venv/bin/pip install -r /opt/hm1k/requirements.txt

# Start service
sudo systemctl start hm1k
```

### Rotate Logs
Logs are rotated by logrotate. Config at `/etc/logrotate.d/hm1k`:
```
/opt/hm1k/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 hm1k hm1k
    postrotate
        systemctl reload hm1k > /dev/null 2>&1 || true
    endscript
}
```

## Security Notes

- The Gunicorn server only listens on localhost (127.0.0.1)
- All external traffic goes through nginx with SSL/TLS
- Security headers are set by nginx
- The application runs as an unprivileged user
- Systemd security hardening is enabled
