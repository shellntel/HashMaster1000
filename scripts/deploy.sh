#!/bin/bash
# HM1K Deployment Script
# Safe to run repeatedly - never overwrites .env or data/

set -e

REMOTE_HOST="hashmaster"
STAGING_DIR="/tmp/hm1k_deploy"
PROD_DIR="/opt/hm1k"

echo "=== HM1K Deployment ==="

# Step 1: Sync to staging (excluding sensitive files)
echo "Syncing to staging directory..."
rsync -avz --delete \
    --exclude '.git' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'venv' \
    --exclude '.venv' \
    --exclude 'node_modules' \
    --exclude '*.db' \
    --exclude 'data/' \
    --exclude 'internal/' \
    --exclude '.env' \
    --exclude '*.pem' \
    --exclude 'cert.pem' \
    --exclude 'key.pem' \
    "$(dirname "$0")/../" \
    "${REMOTE_HOST}:${STAGING_DIR}/"

# Step 2: Remove .env from staging if it exists (safety check)
echo "Ensuring .env is not in staging..."
ssh "${REMOTE_HOST}" "rm -f ${STAGING_DIR}/.env ${STAGING_DIR}/cert.pem ${STAGING_DIR}/key.pem"

# Step 3: Copy to production (excluding .env and data)
echo "Deploying to production..."
ssh "${REMOTE_HOST}" "sudo rsync -av \
    --exclude '.env' \
    --exclude 'data/' \
    --exclude 'cert.pem' \
    --exclude 'key.pem' \
    ${STAGING_DIR}/ ${PROD_DIR}/"

# Step 4: Fix ownership
echo "Fixing permissions..."
ssh "${REMOTE_HOST}" "sudo chown -R hm1k:hm1k ${PROD_DIR}"

# Step 5: Restart service
echo "Restarting service..."
ssh "${REMOTE_HOST}" "sudo systemctl restart hm1k"

# Step 6: Verify
echo "Verifying..."
ssh "${REMOTE_HOST}" "sudo systemctl is-active hm1k && echo 'Service is running'"

echo "=== Deployment Complete ==="
