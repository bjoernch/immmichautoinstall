# Immich VPS Installer

Interactive installer for deploying Immich on Ubuntu 24.04 / Debian 12 with:
- Docker Engine + Compose plugin
- Hetzner Storage Box mounted via SSHFS
- Nginx reverse proxy with Let's Encrypt TLS
- Optional IP allowlist access restriction
- Optional prompt to create missing remote Storage Box path
- Storage Box auth options: SSH key (recommended) or interactive password

## Usage

Run as root or via sudo:

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
AUTH_METHOD=key
STORAGEBOX_HOST=uXXXXX.your-storagebox.de
STORAGEBOX_USER=uXXXXX
REMOTE_PATH=/srv-fsn-1
LOCAL_MOUNT=/srv/storagebox
UPLOAD_LOCATION=/srv/storagebox/immich/library
DB_DATA_LOCATION=/srv/docker/immich/postgres
```
