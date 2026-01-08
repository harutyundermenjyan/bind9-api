# BIND9 REST API

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)

A comprehensive REST API for BIND9 DNS Server management with full support for zones, records, DNSSEC, and server control.

---

## 🚀 Use with Terraform/OpenTofu

> **Manage your BIND9 DNS infrastructure as code!**
>
> This API is designed to work with the **[Terraform Provider for BIND9](https://github.com/harutyundermenjyan/terraform-provider-bind9)**.
>
> **Features:**
> - Single server or multi-primary architecture
> - Define records once, deploy to all or selected servers
> - Full zone and record lifecycle management
>
> 📦 **Get the Provider:** [github.com/harutyundermenjyan/terraform-provider-bind9](https://github.com/harutyundermenjyan/terraform-provider-bind9)

---

## Terraform/OpenTofu Usage Examples

### Option 1: Single Server Setup

For a simple single-server deployment:

```terraform
# providers.tf
terraform {
  required_providers {
    bind9 = {
      source  = "harutyundermenjyan/bind9"
      version = "~> 1.0"
    }
  }
}

provider "bind9" {
  endpoint = "http://localhost:8080"
  api_key  = var.bind9_api_key
}
```

```terraform
# zones.tf
resource "bind9_zone" "example" {
  name        = "example.com"
  type        = "master"
  soa_mname   = "ns1.example.com"
  soa_rname   = "hostmaster.example.com"
  soa_refresh = 3600
  soa_retry   = 600
  soa_expire  = 604800
  soa_minimum = 86400
  default_ttl = 3600

  nameservers = ["ns1.example.com", "ns2.example.com"]

  ns_addresses = {
    "ns1.example.com" = "10.0.0.1"
    "ns2.example.com" = "10.0.0.2"
  }

  allow_update           = ["key ddns-key"]
  delete_file_on_destroy = true
}
```

```terraform
# records.tf
resource "bind9_record" "www" {
  zone    = bind9_zone.example.name
  name    = "www"
  type    = "A"
  ttl     = 300
  records = ["10.0.0.100"]
}

resource "bind9_record" "mail" {
  zone    = bind9_zone.example.name
  name    = "mail"
  type    = "A"
  ttl     = 300
  records = ["10.0.0.50"]
}

resource "bind9_record" "mx" {
  zone    = bind9_zone.example.name
  name    = "@"
  type    = "MX"
  ttl     = 3600
  records = ["10 mail.example.com."]
}

resource "bind9_record" "spf" {
  zone    = bind9_zone.example.name
  name    = "@"
  type    = "TXT"
  ttl     = 3600
  records = ["v=spf1 mx ~all"]
}
```

---

### Option 2: Multi-Primary Server Setup

For managing multiple independent BIND9 servers - **define records once, deploy to all or selected servers**:

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   Terraform/    │──────▶│   BIND9 API     │──────▶│     BIND9       │
│   OpenTofu      │       │   (dns1:8080)   │       │   Server 1      │
│                 │       └─────────────────┘       └─────────────────┘
│                 │
│                 │       ┌─────────────────┐       ┌─────────────────┐
│                 │──────▶│   BIND9 API     │──────▶│     BIND9       │
│                 │       │   (dns2:8080)   │       │   Server 2      │
└─────────────────┘       └─────────────────┘       └─────────────────┘
```

#### File Structure

```
bind9-orchestrator/
├── providers.tf          # Provider aliases for each server
├── variables.tf          # Server definitions
├── locals.tf             # Helper locals
├── zones.tf              # Zone resources per server
├── records.tf            # Records with server targeting
├── outputs.tf            # Outputs
└── terraform.tfvars      # Your server configuration (gitignored)
```

#### providers.tf

```terraform
terraform {
  required_version = ">= 1.0"

  required_providers {
    bind9 = {
      source  = "harutyundermenjyan/bind9"
      version = "~> 1.0"
    }
  }
}

# Provider for each DNS server
provider "bind9" {
  alias    = "dns1"
  endpoint = var.servers["dns1"].endpoint
  api_key  = var.servers["dns1"].api_key
}

provider "bind9" {
  alias    = "dns2"
  endpoint = var.servers["dns2"].endpoint
  api_key  = var.servers["dns2"].api_key
}

# Default provider (required by OpenTofu)
provider "bind9" {
  endpoint = var.servers["dns1"].endpoint
  api_key  = var.servers["dns1"].api_key
}
```

#### variables.tf

```terraform
variable "servers" {
  description = "Map of BIND9 servers to manage"
  type = map(object({
    endpoint = string
    api_key  = string
    enabled  = bool
  }))
}
```

#### locals.tf

```terraform
locals {
  # Filter to only enabled servers
  enabled_servers = {
    for name, server in var.servers : name => server
    if server.enabled
  }
}
```

#### terraform.tfvars

```terraform
servers = {
  "dns1" = {
    endpoint = "http://localhost:8080"   # SSH tunnel or direct
    api_key  = "your-api-key-for-dns1"
    enabled  = true
  }
  "dns2" = {
    endpoint = "http://localhost:8081"
    api_key  = "your-api-key-for-dns2"
    enabled  = true
  }
}
```

#### zones.tf

```terraform
# Zone on dns1
resource "bind9_zone" "example_dns1" {
  count    = try(var.servers["dns1"].enabled, false) ? 1 : 0
  provider = bind9.dns1

  name        = "example.com"
  type        = "master"
  soa_mname   = "ns1.example.com"
  soa_rname   = "hostmaster.example.com"
  soa_refresh = 3600
  soa_retry   = 600
  soa_expire  = 604800
  soa_minimum = 86400
  default_ttl = 3600

  nameservers = ["ns1.example.com", "ns2.example.com"]

  ns_addresses = {
    "ns1.example.com" = "10.0.0.1"
    "ns2.example.com" = "10.0.0.2"
  }

  allow_update           = ["key ddns-key"]
  delete_file_on_destroy = true
}

# Zone on dns2
resource "bind9_zone" "example_dns2" {
  count    = try(var.servers["dns2"].enabled, false) ? 1 : 0
  provider = bind9.dns2

  name        = "example.com"
  type        = "master"
  soa_mname   = "ns1.example.com"
  soa_rname   = "hostmaster.example.com"
  soa_refresh = 3600
  soa_retry   = 600
  soa_expire  = 604800
  soa_minimum = 86400
  default_ttl = 3600

  nameservers = ["ns1.example.com", "ns2.example.com"]

  ns_addresses = {
    "ns1.example.com" = "10.0.0.1"
    "ns2.example.com" = "10.0.0.2"
  }

  allow_update           = ["key ddns-key"]
  delete_file_on_destroy = true
}
```

#### records.tf - Define Once, Deploy to Many

```terraform
locals {
  # ==========================================================================
  # Define records ONCE - deploy to ALL or SELECTED servers
  # ==========================================================================
  # servers = []           → deploy to ALL enabled servers
  # servers = ["dns1"]     → deploy to dns1 only
  # servers = ["dns1", "dns2"] → deploy to dns1 and dns2
  # ==========================================================================

  example_com_records = {
    # A Records
    "www_A" = {
      name    = "www"
      type    = "A"
      ttl     = 300
      records = ["10.0.0.100"]
      servers = []              # ALL servers
    }
    "app_A" = {
      name    = "app"
      type    = "A"
      ttl     = 300
      records = ["10.0.0.101"]
      servers = []              # ALL servers
    }
    "db_A" = {
      name    = "db"
      type    = "A"
      ttl     = 300
      records = ["10.0.0.102"]
      servers = ["dns1"]        # dns1 only
    }

    # CNAME Records
    "api_CNAME" = {
      name    = "api"
      type    = "CNAME"
      ttl     = 300
      records = ["app.example.com."]
      servers = []
    }

    # MX Records
    "mx_MX" = {
      name    = "@"
      type    = "MX"
      ttl     = 3600
      records = ["10 mail.example.com."]
      servers = []
    }

    # TXT Records
    "spf_TXT" = {
      name    = "@"
      type    = "TXT"
      ttl     = 3600
      records = ["v=spf1 mx ~all"]
      servers = []
    }

    # PTR Records (for reverse zone)
    "100_PTR" = {
      name    = "100"
      type    = "PTR"
      ttl     = 3600
      records = ["www.example.com."]
      servers = []
    }
  }

  # Expand records to target servers
  example_com_records_expanded = merge([
    for record_key, record in local.example_com_records : {
      for server_name, server in local.enabled_servers :
      "${record_key}_${server_name}" => merge(record, { server = server_name })
      if length(record.servers) == 0 || contains(record.servers, server_name)
    }
  ]...)
}

# Records for dns1
resource "bind9_record" "example_dns1" {
  for_each = {
    for k, v in local.example_com_records_expanded : k => v
    if v.server == "dns1" && v.type != "PTR"
  }
  provider = bind9.dns1

  zone    = bind9_zone.example_dns1[0].name
  name    = each.value.name
  type    = each.value.type
  ttl     = each.value.ttl
  records = each.value.records
}

# Records for dns2
resource "bind9_record" "example_dns2" {
  for_each = {
    for k, v in local.example_com_records_expanded : k => v
    if v.server == "dns2" && v.type != "PTR"
  }
  provider = bind9.dns2

  zone    = bind9_zone.example_dns2[0].name
  name    = each.value.name
  type    = each.value.type
  ttl     = each.value.ttl
  records = each.value.records
}
```

#### Bulk Record Generation ($GENERATE equivalent)

```terraform
locals {
  # Equivalent to BIND9: $GENERATE 1-50 host-$ A 10.0.1.$
  generated_hosts = {
    for i in range(1, 51) :
    "host-${i}_A" => {
      name    = "host-${i}"
      type    = "A"
      ttl     = 300
      records = ["10.0.1.${i}"]
      servers = []
    }
  }

  # With step - equivalent to: $GENERATE 0-100/2 even-$ A 10.0.2.$
  generated_even = {
    for i in range(0, 101, 2) :  # start, end, step
    "even-${i}_A" => {
      name    = "even-${i}"
      type    = "A"
      ttl     = 300
      records = ["10.0.2.${i}"]
      servers = []
    }
  }
}
```

---

## Features

### Zone Management
- ✅ Create, read, update, delete zones
- ✅ Zone reload, freeze, thaw, sync
- ✅ Zone transfer (AXFR/IXFR)
- ✅ Zone import/export
- ✅ Zone status monitoring

### Record Management (30+ Record Types)
- ✅ A, AAAA - IPv4/IPv6 addresses
- ✅ CNAME - Canonical names (aliases)
- ✅ MX - Mail exchangers
- ✅ TXT - Text records (SPF, DKIM, DMARC)
- ✅ NS - Name servers
- ✅ PTR - Pointer records (reverse DNS)
- ✅ SOA - Start of Authority
- ✅ SRV - Service locator
- ✅ CAA - Certificate Authority Authorization
- ✅ NAPTR - Naming Authority Pointer
- ✅ HTTPS, SVCB - Service binding
- ✅ TLSA - TLS Authentication (DANE)
- ✅ SSHFP - SSH fingerprints
- ✅ LOC - Geographic location
- ✅ And many more...

### Server Control (All RNDC Commands)
- ✅ Server status and version
- ✅ Reload configuration
- ✅ Cache flush (full, name, tree)
- ✅ Query logging toggle
- ✅ Debug/trace levels
- ✅ Database dumps

### DNSSEC Management
- ✅ Key generation (KSK, ZSK, CSK)
- ✅ Key listing and deletion
- ✅ Zone signing
- ✅ DS record generation
- ✅ Key rollover support

### Statistics & Monitoring
- ✅ Query statistics by type
- ✅ Resolver statistics
- ✅ Cache hit/miss statistics
- ✅ Memory usage
- ✅ Prometheus metrics endpoint

### Security
- ✅ API key authentication
- ✅ JWT authentication
- ✅ Role-based access control (scopes)
- ✅ Rate limiting
- ✅ CORS support

## BIND9 Server Configuration

Before installing the API, your BIND9 server must be properly configured.

### Required named.conf Settings

```bind
# /etc/bind/named.conf

# Include keys
include "/etc/bind/rndc.key";
include "/etc/bind/keys/ddns-key.key";

options {
    directory "/var/cache/bind";

    # Allow queries
    allow-query { any; };

    # DNSSEC validation
    dnssec-validation auto;

    # Listen on all interfaces
    listen-on { any; };
    listen-on-v6 { any; };

    # CRITICAL: Enable dynamic zone management via API
    allow-new-zones yes;
};

# Statistics channel for monitoring API
statistics-channels {
    inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
};

# RNDC control for zone management
controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};

# Logging (recommended)
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

# Include zone configurations
include "/etc/bind/named.conf.local";
```

### Key Configuration Points

| Setting | Purpose | Required |
|---------|---------|----------|
| `allow-new-zones yes` | Allows API to create/delete zones dynamically | ✅ Yes |
| `include "ddns-key.key"` | TSIG key for authenticated DNS updates | ✅ Yes |
| `include "rndc.key"` | RNDC authentication for server control | ✅ Yes |
| `controls { ... }` | RNDC control channel | ✅ Yes |
| `statistics-channels` | Enables statistics API endpoint | Optional |
| `logging { ... }` | Log configuration for troubleshooting | Recommended |

### Generate Required Keys

```bash
# Generate RNDC key (if not exists)
rndc-confgen -a -k rndc-key

# Generate TSIG key for dynamic updates
mkdir -p /etc/bind/keys
tsig-keygen -a hmac-sha256 ddns-key > /etc/bind/keys/ddns-key.key
chown bind:bind /etc/bind/keys/ddns-key.key
chmod 640 /etc/bind/keys/ddns-key.key
```

### Create Required Directories

```bash
mkdir -p /var/lib/bind
mkdir -p /var/log/bind
chown bind:bind /var/lib/bind /var/log/bind
chmod 755 /var/lib/bind /var/log/bind
```

### Verify Configuration

```bash
# Check configuration syntax
named-checkconf

# Restart BIND9
systemctl restart bind9

# Verify RNDC works
rndc status
```

### AppArmor Configuration (Ubuntu)

**Critical on Ubuntu!** AppArmor restricts BIND9's file access by default.

```bash
# Create/update local AppArmor overrides
cat > /etc/apparmor.d/local/usr.sbin.named << 'EOF'
# Allow BIND9 to write to zone directory
/var/lib/bind/** rw,

# Allow BIND9 to write logs
/var/log/bind/** rw,

# Allow BIND9 to read keys
/etc/bind/keys/** r,

# Allow BIND9 to manage NZF (new zone file) database
/var/cache/bind/*.nzf rw,
/var/cache/bind/*.nzf.lock rwk,
/var/cache/bind/*.nzd rw,
/var/cache/bind/*.nzd-lock rwk,
EOF

# Reload AppArmor profile
apparmor_parser -r /etc/apparmor.d/usr.sbin.named
```

If you get permission errors, check AppArmor:
```bash
dmesg | grep -i apparmor | tail -10
aa-status | grep named
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- BIND9 configured as shown above
- `rndc` and `nsupdate` available

### Installation

```bash
# Clone the repository
git clone https://github.com/harutyundermenjyan/bind9-api.git
cd bind9-api

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp env.example .env
# Edit .env with your settings

# Run
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### Docker

```bash
docker-compose up -d
```

## API Documentation

Once running, access the interactive documentation:

- **Swagger UI**: http://localhost:8080/docs
- **ReDoc**: http://localhost:8080/redoc
- **OpenAPI JSON**: http://localhost:8080/api/v1/openapi.json

## Authentication

### API Key (Recommended)

```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/zones
```

### JWT Token

```bash
# Get token
curl -X POST http://localhost:8080/api/v1/auth/token \
  -d "username=admin&password=admin"

# Use token
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/zones
```

## API Examples

### Zone Operations

```bash
# List zones
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/zones

# Create zone
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/zones \
  -d '{
    "name": "example.com",
    "zone_type": "master",
    "soa_mname": "ns1.example.com",
    "soa_rname": "hostmaster.example.com",
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "ns_addresses": {
      "ns1.example.com": "10.0.0.1",
      "ns2.example.com": "10.0.0.2"
    }
  }'

# Get zone
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/zones/example.com

# Delete zone
curl -X DELETE -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/zones/example.com
```

### Record Operations

```bash
# List records
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/zones/example.com/records

# Create A record
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/zones/example.com/records \
  -d '{
    "record_type": "A",
    "name": "www",
    "ttl": 300,
    "data": {"address": "10.0.0.100"}
  }'

# Create MX record
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/zones/example.com/records \
  -d '{
    "record_type": "MX",
    "name": "@",
    "ttl": 3600,
    "data": {"preference": 10, "exchange": "mail.example.com"}
  }'

# Delete record
curl -X DELETE -H "X-API-Key: $API_KEY" \
  "http://localhost:8080/api/v1/zones/example.com/records/www/A?rdata=10.0.0.100"
```

### Server Control

```bash
# Get server status
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/server/status

# Reload all zones
curl -X POST -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/server/reload

# Flush cache
curl -X POST -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/server/cache/flush
```

### DNSSEC

```bash
# Generate KSK
curl -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/dnssec/zones/example.com/keys \
  -d '{"key_type": "KSK", "algorithm": 13}'

# Get DS records for registrar
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/dnssec/zones/example.com/ds

# Sign zone
curl -X POST -H "X-API-Key: $API_KEY" \
  http://localhost:8080/api/v1/dnssec/zones/example.com/sign
```

## Configuration

See [SETUP.md](SETUP.md) for detailed configuration instructions.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BIND9_API_HOST` | Listen address | `0.0.0.0` |
| `BIND9_API_PORT` | Listen port | `8080` |
| `BIND9_API_AUTH_ENABLED` | Enable authentication | `true` |
| `BIND9_API_AUTH_STATIC_API_KEY` | Static API key | - |
| `BIND9_API_BIND9_ZONES_PATH` | Zone files directory | `/var/lib/bind` |
| `BIND9_API_TSIG_KEY_FILE` | TSIG key file path | `/etc/bind/keys/ddns-key.key` |

See `env.example` for all options.

## Scopes/Permissions

| Scope | Description |
|-------|-------------|
| `read` | Read-only access to zones and records |
| `write` | Create, update, delete zones and records |
| `admin` | Full administrative access |
| `dnssec` | DNSSEC key management |
| `stats` | Access to statistics |

## Health Checks

```bash
# Full health check
curl http://localhost:8080/health

# Kubernetes liveness
curl http://localhost:8080/health/live

# Kubernetes readiness
curl http://localhost:8080/health/ready
```

## Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

## Supported Record Types

| Type | Format | Example |
|------|--------|---------|
| A | IPv4 address | `["10.0.0.100"]` |
| AAAA | IPv6 address | `["2001:db8::1"]` |
| CNAME | FQDN (trailing dot) | `["www.example.com."]` |
| MX | priority + FQDN | `["10 mail.example.com."]` |
| TXT | text string | `["v=spf1 mx ~all"]` |
| SRV | priority weight port target | `["10 60 5060 sip.example.com."]` |
| CAA | flags tag value | `["0 issue \"letsencrypt.org\""]` |
| NS | FQDN | `["ns1.example.com."]` |
| PTR | FQDN | `["www.example.com."]` |

## Related Projects

| Project | Description | Status |
|---------|-------------|--------|
| **[terraform-provider-bind9](https://github.com/harutyundermenjyan/terraform-provider-bind9)** | Terraform/OpenTofu provider that uses this API | ✅ Available |

## Project Structure

```
bind9-api/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── auth.py              # Authentication
│   ├── models/              # Pydantic models
│   │   ├── records.py       # DNS record types
│   │   ├── zones.py         # Zone models
│   │   ├── server.py        # Server/RNDC models
│   │   └── dnssec.py        # DNSSEC models
│   ├── routers/             # API endpoints
│   │   ├── zones.py
│   │   ├── records.py
│   │   ├── server.py
│   │   ├── stats.py
│   │   ├── dnssec.py
│   │   └── health.py
│   └── services/            # Business logic
│       ├── rndc.py
│       ├── nsupdate.py
│       ├── zonefile.py
│       └── dnssec.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── env.example
├── SETUP.md
└── README.md
```

## Author

**Harutyun Dermenjyan**

- GitHub: [@harutyundermenjyan](https://github.com/harutyundermenjyan)

## License

MIT License - Copyright (c) 2024 Harutyun Dermenjyan

See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
