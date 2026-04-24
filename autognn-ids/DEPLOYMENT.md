# AutoGNN-IDS Deployment Guide

## Portable Service Configuration

The updated `autognn-ids.service` file is now **portable and flexible**, allowing installation on any server and customization for different deployment scenarios.

---

## Installation Paths

### Option 1: System-Wide Installation (Recommended for Production)

```bash
# Install to standard location
sudo mkdir -p /opt/autognn-ids
sudo git clone <repo> /opt/autognn-ids
cd /opt/autognn-ids
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Copy systemd service
sudo cp autognn-ids.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable autognn-ids
sudo systemctl start autognn-ids
```

### Option 2: User Installation (Development/Testing)

```bash
# Install to home directory
mkdir -p ~/autognn-ids
git clone <repo> ~/autognn-ids
cd ~/autognn-ids
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Create user config
mkdir -p ~/.autognn-ids
cp autognn-ids.conf.example ~/.autognn-ids/autognn-ids.conf
sed -i 's|/opt/autognn-ids|~/autognn-ids|g' ~/.autognn-ids/autognn-ids.conf

# Install service
sudo cp autognn-ids.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start autognn-ids
```

### Option 3: Custom Installation Path

```bash
# Install to custom location
mkdir -p /srv/ids/autognn-ids
git clone <repo> /srv/ids/autognn-ids
cd /srv/ids/autognn-ids

# Create system-wide config
sudo mkdir -p /etc/autognn-ids
sudo tee /etc/autognn-ids/autognn-ids.conf > /dev/null <<EOF
AUTOGNN_INSTALL_DIR=/srv/ids/autognn-ids
AUTOGNN_USE_SAMPLE=false
EOF

# Install service
sudo cp autognn-ids.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start autognn-ids
```

---

## Configuration Files

### System-Wide Config (Priority 1)
```bash
/etc/autognn-ids/autognn-ids.conf
```
- Requires root to edit
- Applies to all users
- Persists across updates

### Per-User Config (Priority 2)
```bash
~/.autognn-ids/autognn-ids.conf
```
- No root required
- User-specific settings
- Good for personal/dev deployments

### Example Config
```bash
cp autognn-ids.conf.example /etc/autognn-ids/autognn-ids.conf
sudo nano /etc/autognn-ids/autognn-ids.conf
```

---

## Running as Non-Root User

For added security, run AutoGNN-IDS as an unprivileged user:

### 1. Create Service User

```bash
sudo useradd -r -s /bin/false autognn
sudo chown -R autognn:autognn /opt/autognn-ids
```

### 2. Override Service Settings

```bash
sudo systemctl edit autognn-ids
```

Add/modify:
```ini
[Service]
User=autognn
Group=autognn
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
```

### 3. Restart Service

```bash
sudo systemctl daemon-reload
sudo systemctl restart autognn-ids
```

**Note:** Running as non-root user requires `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities for packet sniffing. Without these, the service will fall back to log-based discovery (if available).

---

## Environment Variables

Override settings without editing config files:

```bash
# One-time override
AUTOGNN_INSTALL_DIR=/home/user/autognn-ids systemctl restart autognn-ids

# Or set permanently in shell profile
export AUTOGNN_INSTALL_DIR=/home/user/autognn-ids
export AUTOGNN_USE_SAMPLE=false
systemctl restart autognn-ids

# View current environment
systemctl show -p Environment autognn-ids
```

---

## Customization Examples

### Example 1: Multi-Server Deployment

**Server 1 (Production):**
```bash
# /etc/autognn-ids/autognn-ids.conf
AUTOGNN_INSTALL_DIR=/opt/autognn-ids
AUTOGNN_USE_SAMPLE=false
AUTOGNN_DATA_DIR=/mnt/storage/autognn-ids/data
AUTOGNN_MODEL_DIR=/mnt/storage/autognn-ids/models
```

**Server 2 (Staging):**
```bash
# /etc/autognn-ids/autognn-ids.conf
AUTOGNN_INSTALL_DIR=/opt/autognn-ids-staging
AUTOGNN_USE_SAMPLE=true
AUTOGNN_DATA_DIR=/mnt/storage/autognn-ids-staging/data
```

### Example 2: Docker Container

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y python3 python3-venv

# Copy AutoGNN-IDS
COPY autognn-ids /app/autognn-ids
WORKDIR /app/autognn-ids

# Setup venv
RUN python3 -m venv .venv && \
    .venv/bin/pip install -r requirements.txt

# Config via environment
ENV AUTOGNN_INSTALL_DIR=/app/autognn-ids
ENV AUTOGNN_USE_SAMPLE=false

# Run
CMD [".venv/bin/python", "main.py"]
```

### Example 3: Kubernetes Deployment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: autognn-ids-config
data:
  autognn-ids.conf: |
    AUTOGNN_INSTALL_DIR=/opt/autognn-ids
    AUTOGNN_USE_SAMPLE=false
    AUTOGNN_BRIDGE_INTERFACES=eth0,eth1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autognn-ids
spec:
  containers:
  - name: autognn-ids
    image: autognn-ids:latest
    env:
    - name: AUTOGNN_INSTALL_DIR
      value: /opt/autognn-ids
    volumeMounts:
    - name: config
      mountPath: /etc/autognn-ids
    - name: data
      mountPath: /opt/autognn-ids/data
    securityContext:
      capabilities:
        add:
        - NET_RAW
        - NET_ADMIN
  volumes:
  - name: config
    configMap:
      name: autognn-ids-config
  - name: data
    persistentVolumeClaim:
      claimName: autognn-data
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status autognn-ids

# View detailed logs
sudo journalctl -u autognn-ids -n 50

# Check for config errors
sudo systemctl cat autognn-ids
```

### Permission Denied Errors

```bash
# Verify installation directory ownership
ls -la /opt/autognn-ids

# Fix permissions if needed
sudo chown -R root:root /opt/autognn-ids
# Or for user installation:
sudo chown -R $(whoami) ~/autognn-ids
```

### Python Not Found

The service now auto-detects:
1. Venv python: `${AUTOGNN_INSTALL_DIR}/.venv/bin/python`
2. System python: `python3`

If still failing:
```bash
# Verify venv exists
ls -la /opt/autognn-ids/.venv/bin/python

# Or install system python
sudo apt-get install python3
```

### Packet Sniffing Requires Root

```bash
# Check current user/capabilities
id
getcap /path/to/python

# Grant capabilities
sudo setcap cap_net_raw,cap_net_admin=ep /opt/autognn-ids/.venv/bin/python
```

---

## Uninstallation

```bash
# Stop service
sudo systemctl stop autognn-ids

# Disable auto-start
sudo systemctl disable autognn-ids

# Remove systemd service
sudo rm /etc/systemd/system/autognn-ids.service
sudo systemctl daemon-reload

# Remove installation (if desired)
sudo rm -rf /opt/autognn-ids

# Remove config (if desired)
sudo rm -rf /etc/autognn-ids
```

---

## Summary

The new portable configuration allows AutoGNN-IDS to:

✅ Run on any server at any installation path  
✅ Support system-wide and per-user deployments  
✅ Auto-detect venv or fall back to system python  
✅ Configure via files or environment variables  
✅ Run as root or unprivileged user (with capabilities)  
✅ Work in containers, VMs, and Kubernetes  
✅ Support GNS3 bridge mode deployments  

Simply set `AUTOGNN_INSTALL_DIR` to your installation path and enjoy flexible, portable deployment! 🚀
