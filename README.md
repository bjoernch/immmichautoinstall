# Immich VPS Installer

Interactive installer for deploying Immich on Ubuntu 24.04 / Debian 12 with:
- Docker Engine + Compose plugin
- Hetzner Storage Box mounted via SSHFS (password auth only)
- Nginx reverse proxy with Let’s Encrypt TLS (webroot)
- Optional IP allowlist access restriction
- Guided DNS setup + public IP detection
- Guided Storage Box SFTP verification
- Optional health checks with auto-repair (mount, containers, nginx)

## Usage

Quick install from GitHub (recommended):

```bash
curl -fsSL https://raw.githubusercontent.com/bjoernch/immmichautoinstall/main/install-immich.sh -o "$HOME/install-immich.sh"
chmod +x "$HOME/install-immich.sh"
sudo "$HOME/install-immich.sh"
```

Run locally as root or via sudo:

```bash
sudo ./install-immich.sh
```

Unattended mode with a prefilled config:

```bash
sudo ./install-immich.sh --unattended --config /srv/docker/immich/installer.env
```

Resume behavior:
- If a config file exists, the installer will offer to reuse it and skip prompts.
- Use `--force-prompts` to re-enter all values.

## Config file format

The installer writes/reads a simple env file. Example:

```env
IMMICH_DIR=/srv/docker/immich
DOMAIN=photos.example.com
LETSENCRYPT_EMAIL=admin@example.com
ALLOWED_IPS=203.0.113.4,2001:db8::1
AUTH_METHOD=password
STORAGEBOX_HOST=uXXXXX.your-storagebox.de
STORAGEBOX_USER=uXXXXX
REMOTE_PATH=/srv-fsn-1
LOCAL_MOUNT=/srv/storagebox
UPLOAD_LOCATION=/srv/storagebox/immich/library
DB_DATA_LOCATION=/srv/docker/immich/postgres
```

## Notes

- The Storage Box remote path must exist before running the installer.
- Password auth is interactive (prompts during SFTP test and SSHFS mount).
- The installer will open SFTP and guide you to create/verify the remote path.
- Ensure SSH access is enabled in the Hetzner Storage Box settings before running the installer.

## What the installer does

- Preflight checks: OS, sudo, base packages
- Docker install + Compose plugin setup
- SSHFS mount configuration and verification
- Immich compose download + .env generation
- Nginx reverse proxy with TLS
- Optional IP allowlist in Nginx
- Optional healthcheck timer for auto-repair
