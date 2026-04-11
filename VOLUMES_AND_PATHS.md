# Volumes and Paths Guide

This document explains the directory structure, volume mappings, and file locations for the CrowdSec Manager stack.

## Directory Structure

We recommend the following directory structure on your host machine:

```text
project-root/
├── docker-compose.yml
├── .env                    # Optional environment variables
├── data/                   # Application database (settings.db)
├── logs/                   # Centralized logs
│   └── app/                # CrowdSec Manager logs
└── config/                 # Configuration files
    └── crowdsec/           # CrowdSec configuration
        └── acquis.yaml
```

## Volume Mappings

In your `docker-compose.yml`, use these mapped volumes. We use **relative paths** (`./`) to keep things portable.

### CrowdSec Manager Service

```yaml
volumes:
  # Docker Socket (Required for container management)
  - /var/run/docker.sock:/var/run/docker.sock

  # Configuration (Read/Write)
  - ./config:/app/config

  # Application Logs (Write)
  - ./logs/app:/app/logs

  # Database (Read/Write)
  - ./data:/app/data
```

## User Permissions

### Running as Root (Default)
If you run `docker-compose` as root, directories will be created with root permissions. This generally works out of the box but is less secure.

### Running as Non-Root User (Recommended)
If you run as a non-root user (e.g., `ubuntu` or `ec2-user`), you must ensure the user has permissions to write to the mapped directories.

**Setup Script:**

```bash
# 1. Create directories
mkdir -p data logs/app config/crowdsec

# 2. Set ownership (replace $USER with your username)
sudo chown -R $USER:$USER data logs config

# 3. Set permissions
chmod -R 755 data logs config
```

**Docker Group:**
Ensure your user is in the `docker` group:
```bash
sudo usermod -aG docker $USER
# Log out and log back in for changes to take effect
```

### CrowdSec Acquisition (`acquis.yaml`)

1.  **Location**: `./config/crowdsec/acquis.yaml`
2.  **Purpose**: Defines which logs CrowdSec should read.
3.  **Mapping**: Mapped to `/etc/crowdsec/acquis.yaml` in the CrowdSec container.

## Troubleshooting

**"Permission Denied" Errors:**
If you see permission errors in the logs:
1.  Check ownership: `ls -la logs/`
2.  Fix ownership: `sudo chown -R 1000:1000 logs/` (assuming container runs as UID 1000)

**"File Not Found" Errors:**
1.  Ensure you are running `docker-compose` from the directory containing your `docker-compose.yml`.
2.  Verify the file exists on the host at the relative path specified.
