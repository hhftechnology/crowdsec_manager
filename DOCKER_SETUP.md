# Docker Setup Guide for CrowdSec Manager

## Understanding User Permissions

The CrowdSec Manager container needs write access to several directories for logs, backups, configuration, and the database. There are two approaches to handle user permissions:

## Approach 1: Let Container Handle Permissions (Recommended)

Remove the `user:` directive from your `docker-compose.yml` and let the container handle user management via the entrypoint script.

### Configuration

In your `docker-compose.yml`, do **NOT** specify a `user:` line under `crowdsec-manager` service:

```yaml
services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:dev
    container_name: crowdsec-manager
    restart: unless-stopped
    # DO NOT set user: here - let the entrypoint handle it
    environment:
      - PORT=8080
      # ... other environment variables ...
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./backups:/app/backups
      - ./config:/app/config
```

The container will:
1. Start as root
2. Create necessary directories
3. Fix permissions automatically
4. Drop privileges to user 1000:1000 (appuser)
5. Run the application safely

### Start the Container

```bash
docker compose up -d crowdsec-manager
```

That's it! The entrypoint script handles everything.

---

## Approach 2: Fixed User ID (For Production)

If you need to run as a specific user (e.g., user 988 in production), you need to prepare the host directories first.

### Step 1: Set Up Host Permissions

Run the setup script to create directories with correct ownership:

```bash
# For user 988:988
sudo ./setup-permissions.sh 988 988

# For user 1000:1000 (default)
sudo ./setup-permissions.sh 1000 1000
```

### Step 2: Configure docker-compose.yml

Specify the user in your `docker-compose.yml`:

```yaml
services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:dev
    container_name: crowdsec-manager
    user: "988:988"  # Match the user you set up
    environment:
      - PORT=8080
      # ... other environment variables ...
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./backups:/app/backups
      - ./config:/app/config
```

### Step 3: Start the Container

```bash
docker compose up -d crowdsec-manager
```

---

## Troubleshooting

### Error: "Directory /app/data is not writable"

This means the container user doesn't have write permissions to the mounted volumes.

**Solution:**

1. Check which user the container is running as:
   ```bash
   docker compose exec crowdsec-manager id
   ```

2. Fix host directory permissions:
   ```bash
   # Replace 988:988 with the user ID from step 1
   sudo chown -R 988:988 ./data ./logs ./backups ./config
   ```

3. Restart the container:
   ```bash
   docker compose restart crowdsec-manager
   ```

### Error: "unable to open database file: no such file or directory"

This is the same as the writable directory error above. Follow the same solution.

### Permission Denied on Docker Socket

If you get permission errors accessing the Docker socket:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Or run the setup script with sudo
sudo ./setup-permissions.sh 988 988
```

---

## Production Deployment Checklist

- [ ] Decide on approach 1 (automatic) or approach 2 (fixed user)
- [ ] If using approach 2, run `setup-permissions.sh` with correct UID/GID
- [ ] Verify host directories exist: `./data`, `./logs`, `./backups`, `./config`
- [ ] Check directory ownership: `ls -la`
- [ ] Start container: `docker compose up -d crowdsec-manager`
- [ ] Check logs: `docker compose logs -f crowdsec-manager`
- [ ] Verify database creation: `ls -la ./data/settings.db`

---

## Security Notes

- **Approach 1** (recommended): Container starts as root briefly to fix permissions, then drops to unprivileged user 1000
- **Approach 2**: Container runs as specified user from start, but requires manual permission setup
- Both approaches result in the application running as a non-root user
- The Docker socket is mounted read-only for safety
