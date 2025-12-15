# Mani 272 - UID Management System

A web-based UID management system with MITM proxy integration.

## Features
- Owner/Reseller dashboard
- UID whitelist management with expiry
- Multi-region support (IND, ID, BR, ME, VN, TH, CIS, BD, PK, SG, NA, SAC, EU, TW)
- MITM proxy for game traffic interception
- Credit system for resellers

## Ports
- **Web Dashboard**: 8247
- **MITM Proxy**: 7934

## Quick Start

### Using Docker Compose
```bash
docker-compose up -d
```

### Manual Start
```bash
python start_all.py
```

## Default Credentials
- **Username**: Mani272
- **Password**: mani@321

## Configuration
- Web runs on port 8247
- MITM Proxy runs on port 7934
- Database stored in `./database/`
- Whitelists stored in `./whitelists/`

## Coolify Deployment
1. Connect your GitHub repo to Coolify
2. Set build type to Dockerfile
3. Add your domain
4. Deploy!

## Contact
Discord: https://discord.gg/p4dB8YYMkp

Developed by Vivek
