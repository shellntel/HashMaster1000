#!/bin/sh

# Step 1: Check for the .env file and generate dynamically if needed
if [ ! -f /home/app/.env ]; then
    echo "No .env file found. Generating .env with secure defaults..."
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    cat > /home/app/.env << EOF
# Hash Master 1000 Configuration
SECRET_KEY="${SECRET_KEY}"
ADMIN_USERNAME="admin"
# Default password: Winter2026##
ADMIN_PASSWORD_HASH="\$2b\$12\$PzAkEQKfwFcafUK2RH08zO9Os3YFz7rq.4UqwaLHlFONDlqxncmnO"
EOF
    echo "Created .env with default credentials (admin / Winter2026##)"
else
    echo ".env file already exists. Skipping creation."
fi

# Step 2: Check for the certificate files
if [ ! -f /home/app/cert.pem ] || [ ! -f /home/app/key.pem ]; then
    echo "Missing cert.pem or key.pem. Generating certificates..."
    python3 /home/app/generate_cert.py
else
    echo "Certificate files already exist. Skipping generation."
fi

# Step 3: Create required directories
echo "Ensuring required directories exist..."
mkdir -p /home/app/data /home/app/upload

# Step 4: Start the application
echo "Starting the application..."
exec python3 /home/app/hm1k.py
