# BIND9 REST API

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)

A comprehensive REST API for BIND9 DNS Server management with full support for zones, records, DNSSEC, and server control.

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

## Quick Start

### Prerequisites

- Python 3.11+
- BIND9 with `rndc` and `nsupdate`
- Statistics channel enabled (optional)

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
    "ttl": 3600,
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

## Related Projects

| Project | Description |
|---------|-------------|
| [terraform-provider-bind9](https://github.com/harutyundermenjyan/terraform-provider-bind9) | Terraform/OpenTofu provider for BIND9 |

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
