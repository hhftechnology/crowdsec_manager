#!/bin/bash
# Setup script to create and fix permissions for crowdsec-manager directories

set -e

# Configuration
TARGET_UID=${1:-1000}
TARGET_GID=${2:-1000}

# Directories to create
DIRS=(
    "./data"
    "./logs"
    "./backups"
    "./config"
)

echo "Setting up directories with ownership $TARGET_UID:$TARGET_GID..."

for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Creating directory: $dir"
        mkdir -p "$dir"
    fi

    echo "Setting ownership for $dir"
    chown -R "$TARGET_UID:$TARGET_GID" "$dir"
    chmod -R 755 "$dir"
done

echo ""
echo "✓ Setup complete!"
echo ""
echo "You can now start the container:"
echo "  docker compose up -d crowdsec-manager"
echo ""
echo "If using a different user in docker-compose.yml (e.g., user: \"988:988\"),"
echo "run this script with those values:"
echo "  sudo ./setup-permissions.sh 988 988"
