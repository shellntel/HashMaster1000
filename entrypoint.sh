#!/bin/sh

# Step 1: Check for the .env file
if [ ! -f /home/app/.env ]; then
    echo "No .env file found. Copying env.example to .env..."
    cp /home/app/env.example /home/app/.env
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
