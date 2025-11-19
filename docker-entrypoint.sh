#!/bin/sh
set -e

# Directories that need to be writable
DIRS="/app/backups /app/logs /app/config /app/data"

# Determine target user (if running with docker-compose user: override)
# If not specified, default to appuser (1000:1000)
TARGET_UID=${TARGET_UID:-1000}
TARGET_GID=${TARGET_GID:-1000}

# If we're running as root, fix permissions and drop privileges
if [ "$(id -u)" = "0" ]; then
    echo "Running as root, fixing permissions for user $TARGET_UID:$TARGET_GID..."

    # Ensure directories exist
    for dir in $DIRS; do
        if [ ! -d "$dir" ]; then
            echo "Creating directory: $dir"
            mkdir -p "$dir"
        fi
        # Fix ownership
        chown -R $TARGET_UID:$TARGET_GID "$dir" 2>/dev/null || {
            echo "WARNING: Could not change ownership of $dir (mounted volume?)"
            echo "Please ensure host directory permissions: chown -R $TARGET_UID:$TARGET_GID <host-path>"
        }
    done

    # Drop privileges and execute command as target user
    echo "Dropping privileges to user $TARGET_UID:$TARGET_GID..."
    exec su-exec $TARGET_UID:$TARGET_GID "$@"
else
    # Not running as root - just ensure directories exist and check permissions
    echo "Running as user $(id -u):$(id -g)..."

    for dir in $DIRS; do
        if [ ! -d "$dir" ]; then
            echo "Creating directory: $dir"
            mkdir -p "$dir" 2>/dev/null || echo "WARNING: Cannot create $dir"
        fi

        # Test write permissions
        if ! touch "$dir/.write_test" 2>/dev/null; then
            echo "ERROR: Directory $dir is not writable!"
            echo "Please fix permissions on host: chown -R $(id -u):$(id -g) <host-path-for-$dir>"
            exit 1
        else
            rm -f "$dir/.write_test"
        fi
    done

    # Execute command as current user
    exec "$@"
fi
