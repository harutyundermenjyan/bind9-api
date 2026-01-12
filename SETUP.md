# BIND9 REST API - Setup Guide

Complete guide for installing and configuring the BIND9 REST API.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [BIND9 Configuration](#bind9-configuration)
4. [API Configuration](#api-configuration)
5. [Systemd Service](#systemd-service)
6. [Testing](#testing)
7. [HTTPS Setup](#https-setup)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Python | 3.11+ | `python3 --version` |
| BIND9 | 9.x | `named -v` |
| rndc | - | `rndc status` |
| nsupdate | - | `which nsupdate` |

### Install Prerequisites (Ubuntu/Debian)

```bash
apt update
apt install -y bind9 bind9utils python3 python3-venv python3-pip git
```

---

## Installation

### 1. Clone Repository

```bash
cd /opt
git clone https://github.com/harutyundermenjyan/bind9-api.git
cd bind9-api
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Generate API Keys

```bash
# Generate a secure API key (SAVE THIS!)
python3 -c "import secrets; print('API_KEY:', secrets.token_urlsafe(32))"

# Generate JWT secret key
python3 -c "import secrets; print('SECRET_KEY:', secrets.token_urlsafe(32))"
```

---

## BIND9 Configuration

### 1. Create Required Directories

```bash
# Create directories
mkdir -p /etc/bind/keys
mkdir -p /var/lib/bind
mkdir -p /var/log/bind

# Set ownership
chown -R bind:bind /etc/bind/keys
chown -R bind:bind /var/lib/bind
chown -R bind:bind /var/log/bind
chmod 755 /var/lib/bind /var/log/bind
```

### 2. Generate RNDC Key

```bash
# Generate RNDC key (for server control)
rndc-confgen -a -k rndc-key -c /etc/bind/rndc.key
chown bind:bind /etc/bind/rndc.key
chmod 640 /etc/bind/rndc.key
```

### 3. Create TSIG Key for Dynamic Updates

```bash
# Generate TSIG key
tsig-keygen -a hmac-sha256 ddns-key > /etc/bind/keys/ddns-key.key

# Set permissions
chown bind:bind /etc/bind/keys/ddns-key.key
chmod 640 /etc/bind/keys/ddns-key.key

# Display the key (SAVE THIS - needed for API config)
cat /etc/bind/keys/ddns-key.key
```

### 4. Setup ACL File (for `bind9_acl` Terraform Resource)

The API can manage BIND9 ACLs (Access Control Lists) via the `bind9_acl` Terraform resource. ACLs are stored in a dedicated file.

```bash
# Allow the API to create/manage the ACL file
chmod g+w /etc/bind

# The API automatically creates the empty ACL file on startup
# OR create it manually:
touch /etc/bind/named.conf.acls
chown bind:bind /etc/bind/named.conf.acls
chmod 664 /etc/bind/named.conf.acls
```

The file will be managed by the API - **do not edit manually**.

### 5. Configure BIND9

On Debian/Ubuntu, BIND9 uses split config files by default. You have two options:

#### Option A: Modify Default Files (Recommended for Debian/Ubuntu)

**Step 1: Edit `/etc/bind/named.conf` to include keys and ACLs:**

```bash
cat > /etc/bind/named.conf << 'EOF'
// Include keys at the top
include "/etc/bind/rndc.key";
include "/etc/bind/keys/ddns-key.key";

// Include API-managed ACLs (for bind9_acl Terraform resource)
include "/etc/bind/named.conf.acls";

// Default includes
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
EOF
```

**Step 2: Edit `/etc/bind/named.conf.options`:**

```bash
cat > /etc/bind/named.conf.options << 'EOF'
options {
    directory "/var/cache/bind";

    // Allow queries from anywhere (adjust for production)
    allow-query { any; };

    // DNSSEC validation
    dnssec-validation auto;

    // Listen on all interfaces
    listen-on { any; };
    listen-on-v6 { any; };

    // CRITICAL: Enable dynamic zone management via API
    allow-new-zones yes;
};

// Statistics channel for API - MUST be outside options block
statistics-channels {
    inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
};

// RNDC control
controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};

// Logging
logging {
    channel default_log {
        file "/var/log/bind/default.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { default_log; };
    category queries { default_log; };
};
EOF
```

#### Option B: Single File Configuration

Replace `/etc/bind/named.conf` with a single consolidated file:

```bash
cat > /etc/bind/named.conf << 'EOF'
// BIND9 Configuration for bind9-api

include "/etc/bind/rndc.key";
include "/etc/bind/keys/ddns-key.key";

// Include API-managed ACLs (for bind9_acl Terraform resource)
include "/etc/bind/named.conf.acls";

options {
    directory "/var/cache/bind";

    // Allow queries from anywhere (adjust for production)
    allow-query { any; };

    // DNSSEC validation
    dnssec-validation auto;

    // Listen on all interfaces
    listen-on { any; };
    listen-on-v6 { any; };

    // CRITICAL: Enable dynamic zone management via API
    allow-new-zones yes;
};

// Statistics channel for API - MUST be outside options block
statistics-channels {
    inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
};

// RNDC control
controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};

// Logging
logging {
    channel default_log {
        file "/var/log/bind/default.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { default_log; };
    category queries { default_log; };
};

// Include zone configurations
include "/etc/bind/named.conf.local";
EOF
```

### Key Configuration Points

| Setting | Purpose | Required |
|---------|---------|----------|
| `include "rndc.key"` | RNDC authentication for server control | ✅ Yes |
| `include "ddns-key.key"` | TSIG key for authenticated DNS updates | ✅ Yes |
| `include "named.conf.acls"` | API-managed ACLs (for `bind9_acl` resource) | ✅ Yes |
| `allow-new-zones yes` | Allows API to create/delete zones dynamically | ✅ Yes |
| `controls { ... }` | RNDC control channel (port 953) | ✅ Yes |
| `statistics-channels` | Enables statistics API endpoint | Optional |
| `logging { ... }` | Log configuration for troubleshooting | Recommended |

### 5. Configure AppArmor (Ubuntu - Critical!)

**AppArmor restricts BIND9's file access by default.** This step is essential on Ubuntu.

```bash
# Create local AppArmor overrides
cat > /etc/apparmor.d/local/usr.sbin.named << 'EOF'
# Allow BIND9 to write to zone directory
/var/lib/bind/** rw,

# Allow BIND9 to write logs
/var/log/bind/** rw,

# Allow BIND9 to read keys
/etc/bind/keys/** r,

# Allow BIND9 to manage NZF database
/var/cache/bind/*.nzf rw,
/var/cache/bind/*.nzf.lock rwk,
/var/cache/bind/*.nzd rw,
/var/cache/bind/*.nzd-lock rwk,
EOF

# Reload AppArmor
apparmor_parser -r /etc/apparmor.d/usr.sbin.named

# Verify
aa-status | grep named
```

### 6. Restart BIND9

```bash
systemctl restart bind9
rndc status  # Verify it's running
```

---

## API Configuration

### 1. Create Configuration File

```bash
cp env.example .env

# Set secure permissions (contains sensitive API keys!)
chmod 600 .env
chown root:root .env
```

### 2. Edit Configuration

Edit `/opt/bind9-api/.env`:

```bash
# =============================================================================
# API Server
# =============================================================================
BIND9_API_HOST=0.0.0.0
BIND9_API_PORT=8080
BIND9_API_DEBUG=false

# =============================================================================
# Authentication
# =============================================================================
BIND9_API_AUTH_ENABLED=true
BIND9_API_AUTH_SECRET_KEY=<your-generated-secret-key>
BIND9_API_AUTH_STATIC_API_KEY=<your-generated-api-key>
BIND9_API_AUTH_STATIC_API_KEY_SCOPES=read,write,admin,dnssec,stats

# =============================================================================
# Database (disabled for static API key auth)
# =============================================================================
BIND9_API_DATABASE_ENABLED=false

# =============================================================================
# BIND9 Paths
# =============================================================================
BIND9_API_BIND9_CONFIG_PATH=/etc/bind/named.conf
BIND9_API_BIND9_ZONES_PATH=/var/lib/bind
BIND9_API_BIND9_KEYS_PATH=/etc/bind/keys
BIND9_API_BIND9_RNDC_KEY=/etc/bind/rndc.key
BIND9_API_BIND9_STATS_URL=http://127.0.0.1:8053
BIND9_API_BIND9_NAMED_CHECKZONE=/usr/bin/named-checkzone
BIND9_API_BIND9_NAMED_CHECKCONF=/usr/bin/named-checkconf

# =============================================================================
# TSIG Key (from /etc/bind/keys/ddns-key.key)
# =============================================================================
BIND9_API_TSIG_KEY_FILE=/etc/bind/keys/ddns-key.key
BIND9_API_TSIG_KEY_NAME=ddns-key
BIND9_API_TSIG_KEY_SECRET=<secret-from-ddns-key.key-file>
BIND9_API_TSIG_KEY_ALGORITHM=hmac-sha256

# =============================================================================
# Misc
# =============================================================================
BIND9_API_LOG_LEVEL=INFO
BIND9_API_CORS_ORIGINS=["*"]
BIND9_API_RATE_LIMIT_ENABLED=true
```

### 3. Get TSIG Key Secret

```bash
# View the key file
cat /etc/bind/keys/ddns-key.key

# Output looks like:
# key "ddns-key" {
#     algorithm hmac-sha256;
#     secret "YourBase64SecretHere==";
# };

# Copy the secret value (without quotes) to BIND9_API_TSIG_KEY_SECRET
```

---

## Systemd Service

### Create Service File

```bash
cat > /etc/systemd/system/bind9-api.service << 'EOF'
[Unit]
Description=BIND9 REST API
After=network.target named.service
Wants=named.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bind9-api
EnvironmentFile=/opt/bind9-api/.env
ExecStart=/opt/bind9-api/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and Start

```bash
systemctl daemon-reload
systemctl enable bind9-api
systemctl start bind9-api
systemctl status bind9-api
```

---

## Testing

### 1. Check Service

```bash
systemctl status bind9-api
```

### 2. Test Health Endpoint

```bash
curl http://localhost:8080/health
```

Expected:
```json
{"status": "healthy", "bind9": "running"}
```

### 3. Test Authentication

```bash
# Replace with your actual API key
API_KEY="your-api-key-here"

curl -H "X-API-Key: $API_KEY" http://localhost:8080/api/v1/zones
```

### 4. Create Test Zone

```bash
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/zones \
  -d '{
    "name": "test.example.com",
    "zone_type": "master",
    "soa_mname": "ns1.example.com",
    "soa_rname": "hostmaster.example.com",
    "nameservers": ["ns1.example.com"],
    "ns_addresses": {"ns1.example.com": "10.0.0.1"}
  }'
```

### 5. Check Logs

```bash
journalctl -u bind9-api -n 50 --no-pager
```

---

## HTTPS Setup

### Option 1: Nginx Reverse Proxy (Recommended)

```bash
apt install nginx

# Generate certificate (or use Let's Encrypt)
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/bind9-api.key \
  -out /etc/nginx/ssl/bind9-api.crt \
  -subj "/CN=dns.example.com"
```

Create `/etc/nginx/sites-available/bind9-api`:

```nginx
server {
    listen 443 ssl;
    server_name dns.example.com;

    ssl_certificate /etc/nginx/ssl/bind9-api.crt;
    ssl_certificate_key /etc/nginx/ssl/bind9-api.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and start:

```bash
ln -s /etc/nginx/sites-available/bind9-api /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

### Option 2: Direct SSL with Uvicorn

```bash
# Generate certificate
mkdir -p /etc/bind9-api/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/bind9-api/ssl/key.pem \
  -out /etc/bind9-api/ssl/cert.pem \
  -subj "/CN=dns.example.com"
```

Update systemd service:

```ini
ExecStart=/opt/bind9-api/venv/bin/uvicorn app.main:app \
  --host 0.0.0.0 --port 8080 \
  --ssl-keyfile=/etc/bind9-api/ssl/key.pem \
  --ssl-certfile=/etc/bind9-api/ssl/cert.pem
```

---

## Troubleshooting

### API Returns 401 Unauthorized

```bash
# Check if API key is configured
journalctl -u bind9-api | grep "Static API key"

# Verify .env file
grep BIND9_API_AUTH_STATIC_API_KEY /opt/bind9-api/.env
```

### Zone Creation Fails

**"not allowing new zones":**
```bash
# Check named.conf
grep "allow-new-zones" /etc/bind/named.conf.options
# Should show: allow-new-zones yes;
```

**"NOTAUTH" or TSIG errors:**
```bash
# Verify TSIG key matches
cat /etc/bind/keys/ddns-key.key
grep BIND9_API_TSIG /opt/bind9-api/.env
```

### Permission Errors

```bash
# Fix permissions
chown -R bind:bind /var/lib/bind
chmod 755 /var/lib/bind

# Check AppArmor
aa-status | grep named
```

### View Logs

```bash
# API logs
journalctl -u bind9-api -f

# BIND9 logs
journalctl -u named -f
# or
tail -f /var/log/syslog | grep named
```

---

## Quick Reference

| File | Purpose | Owner | Permissions |
|------|---------|-------|-------------|
| `/opt/bind9-api/.env` | API configuration | `root:root` | `600` |
| `/etc/bind/named.conf` | BIND9 main config | `root:bind` | `644` |
| `/etc/bind/rndc.key` | RNDC authentication | `bind:bind` | `640` |
| `/etc/bind/keys/ddns-key.key` | TSIG key for updates | `bind:bind` | `640` |
| `/var/lib/bind/` | Zone files directory | `bind:bind` | `755` |

| Command | Description |
|---------|-------------|
| `systemctl status bind9-api` | Check API status |
| `systemctl restart bind9-api` | Restart API |
| `journalctl -u bind9-api -f` | Follow API logs |
| `rndc status` | Check BIND9 status |
| `rndc reload` | Reload all zones |
