#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
IMMICH_DIR_DEFAULT="/srv/docker/immich"
CONFIG_FILE_DEFAULT="${IMMICH_DIR_DEFAULT}/installer.env"
IMMICH_DIR="${IMMICH_DIR_DEFAULT}"
AUTH_METHOD="password"
LOG_FILE="/var/log/immich-installer.log"

UNATTENDED="false"
CONFIG_FILE=""
CONFIG_FILE_EXPLICIT="false"
FORCE_PROMPTS="false"
STORE_PASSWORD_IN_CONFIG="false"

log() {
  local ts
  ts="$(date +"%Y-%m-%d %H:%M:%S")"
  echo "[$ts] $*" | tee -a "$LOG_FILE"
}

die() {
  log "ERROR: $*"
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      log "Re-running with sudo..."
      exec sudo -E bash "$0" "$@"
    fi
    die "This script must be run as root or with sudo."
  fi
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [--config /path/to/config.env] [--unattended] [--force-prompts]

Options:
  --config       Path to config file (default: $CONFIG_FILE_DEFAULT)
  --unattended   Run without prompts; requires config file with all values
  --force-prompts  Ignore saved config and re-ask all prompts
  -h, --help     Show this help message
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        CONFIG_FILE="$2"
        CONFIG_FILE_EXPLICIT="true"
        shift 2
        ;;
      --unattended)
        UNATTENDED="true"
        shift
        ;;
      --force-prompts)
        FORCE_PROMPTS="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done
}

ensure_logfile() {
  touch "$LOG_FILE" || true
}

run_cmd() {
  log "RUN: $*"
  "$@"
}

prompt() {
  local var_name="$1"
  local prompt_text="$2"
  local default_val="$3"
  local validator="$4"
  local value=""

  while true; do
    read -r -p "$prompt_text [$default_val]: " value
    value="${value:-$default_val}"
    if [[ -n "$validator" ]]; then
      if ! "$validator" "$value"; then
        log "Invalid value. Please try again."
        continue
      fi
    fi
    printf -v "$var_name" "%s" "$value"
    return 0
  done
}

confirm() {
  local prompt_text="$1"
  local default_no="${2:-true}"
  local reply=""

  if [[ "$UNATTENDED" == "true" ]]; then
    return 0
  fi

  if [[ "$default_no" == "true" ]]; then
    read -r -p "$prompt_text [y/N]: " reply
  else
    read -r -p "$prompt_text [Y/n]: " reply
  fi

  case "${reply,,}" in
    y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

load_config() {
  if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$CONFIG_FILE"
    set +a
  elif [[ -z "$CONFIG_FILE" && -f "$CONFIG_FILE_DEFAULT" ]]; then
    CONFIG_FILE="$CONFIG_FILE_DEFAULT"
    # shellcheck disable=SC1090
    set -a
    source "$CONFIG_FILE"
    set +a
  elif [[ -z "$CONFIG_FILE" ]]; then
    CONFIG_FILE="$CONFIG_FILE_DEFAULT"
  fi
}

save_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat > "$CONFIG_FILE" <<EOF
IMMICH_DIR=${IMMICH_DIR}
DOMAIN=${DOMAIN}
LETSENCRYPT_EMAIL=${LETSENCRYPT_EMAIL}
ALLOWED_IPS=${ALLOWED_IPS}
AUTH_METHOD=${AUTH_METHOD}
STORAGEBOX_HOST=${STORAGEBOX_HOST}
STORAGEBOX_USER=${STORAGEBOX_USER}
REMOTE_PATH=${REMOTE_PATH}
LOCAL_MOUNT=${LOCAL_MOUNT}
UPLOAD_LOCATION=${UPLOAD_LOCATION}
DB_DATA_LOCATION=${DB_DATA_LOCATION}
STEPS_DONE=${STEPS_DONE:-}
EOF
  chmod 600 "$CONFIG_FILE"
}

validate_domain() {
  [[ "$1" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

validate_email() {
  [[ "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]
}

validate_path() {
  [[ "$1" == /* ]]
}

validate_ip_list() {
  local list="$1"
  local item=""
  local ok="true"
  IFS=',' read -r -a items <<< "$list"
  for item in "${items[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    if [[ -z "$item" ]]; then
      ok="false"
      break
    fi
    if ! [[ "$item" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$|^([0-9A-Fa-f:]+)(/[0-9]{1,3})?$ ]]; then
      ok="false"
      break
    fi
  done
  [[ "$ok" == "true" ]]
}

validate_auth_method() {
  [[ "$1" == "password" ]]
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    log "Detected OS: ${PRETTY_NAME}"
    if [[ "${ID}" == "ubuntu" && "${VERSION_ID}" == "24.04" ]]; then
      return 0
    fi
    if [[ "${ID}" == "debian" && "${VERSION_ID}" == "12" ]]; then
      return 0
    fi
    log "Warning: This script targets Ubuntu 24.04 and Debian 12."
  else
    die "Cannot detect OS. /etc/os-release not found."
  fi
}

install_packages() {
  local packages=("$@")
  run_cmd apt-get update -y
  run_cmd apt-get install -y "${packages[@]}"
}

get_public_ip() {
  local ipv4=""
  local ipv6=""
  if command -v curl >/dev/null 2>&1; then
    ipv4="$(curl -fsS https://api.ipify.org || true)"
    ipv6="$(curl -fsS https://api64.ipify.org || true)"
  fi
  echo "$ipv4|$ipv6"
}

collect_inputs() {
  local default_immich_dir="${IMMICH_DIR:-$IMMICH_DIR_DEFAULT}"
  local default_domain="${DOMAIN:-photos.example.com}"
  local default_email="${LETSENCRYPT_EMAIL:-admin@example.com}"
  local default_allowed_ips="${ALLOWED_IPS:-203.0.113.4}"
  local default_storage_host="${STORAGEBOX_HOST:-uXXXXX.your-storagebox.de}"
  local default_storage_user="${STORAGEBOX_USER:-uXXXXX}"
  local default_remote_path="${REMOTE_PATH:-/srv-fsn-1}"
  local default_local_mount="${LOCAL_MOUNT:-/srv/storagebox}"
  local default_upload="${UPLOAD_LOCATION:-/srv/storagebox/immich/library}"
  local default_db="${DB_DATA_LOCATION:-${default_immich_dir}/postgres}"
  local default_auth_method="${AUTH_METHOD}"

  if [[ "$UNATTENDED" == "true" ]]; then
    : "${IMMICH_DIR:?Missing IMMICH_DIR in config}"
    : "${DOMAIN:?Missing DOMAIN in config}"
    : "${LETSENCRYPT_EMAIL:?Missing LETSENCRYPT_EMAIL in config}"
    : "${ALLOWED_IPS:?Missing ALLOWED_IPS in config}"
    : "${AUTH_METHOD:?Missing AUTH_METHOD in config}"
    : "${STORAGEBOX_HOST:?Missing STORAGEBOX_HOST in config}"
    : "${STORAGEBOX_USER:?Missing STORAGEBOX_USER in config}"
    : "${REMOTE_PATH:?Missing REMOTE_PATH in config}"
    : "${LOCAL_MOUNT:?Missing LOCAL_MOUNT in config}"
    : "${UPLOAD_LOCATION:?Missing UPLOAD_LOCATION in config}"
    : "${DB_DATA_LOCATION:?Missing DB_DATA_LOCATION in config}"
    return 0
  fi

  prompt IMMICH_DIR "Immich compose directory" "$default_immich_dir" validate_path
  prompt DOMAIN "Enter the Immich domain (subdomain)" "$default_domain" validate_domain
  prompt LETSENCRYPT_EMAIL "Enter email for Let's Encrypt" "$default_email" validate_email
  if confirm "Restrict access by IP allowlist?" "false"; then
    prompt ALLOWED_IPS "Allowed IPs (comma-separated, IPv4/IPv6/CIDR)" "$default_allowed_ips" validate_ip_list
  else
    ALLOWED_IPS=""
  fi
  prompt AUTH_METHOD "Storage Box auth method (password only)" "$default_auth_method" validate_auth_method
  prompt STORAGEBOX_HOST "Hetzner Storage Box host" "$default_storage_host" ""
  prompt STORAGEBOX_USER "Hetzner Storage Box user" "$default_storage_user" ""
  prompt REMOTE_PATH "Remote path on Storage Box" "$default_remote_path" validate_path
  prompt LOCAL_MOUNT "Local mount point" "$default_local_mount" validate_path
  prompt UPLOAD_LOCATION "Immich upload location" "$default_upload" validate_path
  prompt DB_DATA_LOCATION "Immich DB data location" "$default_db" validate_path
}

preflight() {
  detect_os
  install_packages curl ca-certificates gnupg lsb-release openssh-client
}

install_docker() {
  local docker_ok="false"
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker_ok="true"
  fi

  if step_is_done "docker" && [[ "$docker_ok" == "true" ]]; then
    log "Docker already set up; skipping."
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    log "Docker already installed."
  else
    log "Installing Docker Engine..."
    run_cmd curl -fsSL https://get.docker.com | sh
  fi

  run_cmd systemctl enable --now docker

  if ! docker compose version >/dev/null 2>&1; then
    log "Docker Compose plugin missing; installing..."
    install_packages docker-compose-plugin
  fi
}

ensure_sshfs() {
  if step_is_done "sshfs"; then
    log "SSHFS already configured; skipping."
    return 0
  fi

  install_packages sshfs
  log "Password authentication selected for Storage Box."

  if [[ "$UNATTENDED" != "true" ]]; then
    log "Make sure Storage Box SSH access is enabled in the Hetzner panel (Storage Box settings)."
    confirm "Have you enabled SSH access for this Storage Box?" "false" || true
  fi
}

test_storagebox_ssh() {
  log "Testing SSH connectivity to Storage Box..."
  log "Opening SFTP test. Enter password, then type 'exit' to continue."
  if sftp -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=accept-new \
    "${STORAGEBOX_USER}@${STORAGEBOX_HOST}"; then
    log "SFTP session completed."
    return 0
  fi
  log "SSH connectivity failed. Ensure the key is added and access is allowed."
  if [[ "$UNATTENDED" == "true" ]]; then
    die "SSH connectivity failed in unattended mode."
  fi
  if ! confirm "Continue anyway and retry later?" "true"; then
    die "Aborting."
  fi
}

normalize_remote_path() {
  local path="$1"
  if [[ "$path" == "/" ]]; then
    echo ""
    return 0
  fi
  echo "${path#/}"
}

remote_path_exists() {
  local path_rel
  path_rel="$(normalize_remote_path "$REMOTE_PATH")"
  if [[ -z "$path_rel" ]]; then
    return 0
  fi
  storagebox_sftp_cmd "cd ${path_rel}" >/dev/null 2>&1
}

remote_path_mkdir_p() {
  local path_rel
  local current=""
  local part=""
  path_rel="$(normalize_remote_path "$REMOTE_PATH")"
  if [[ -z "$path_rel" ]]; then
    return 0
  fi
  IFS='/' read -r -a parts <<< "$path_rel"
  for part in "${parts[@]}"; do
    if [[ -z "$part" ]]; then
      continue
    fi
    current="${current}/${part}"
    if ! storagebox_sftp_cmd "mkdir ${current}" >/dev/null 2>&1; then
      log "mkdir ${current} may already exist; continuing."
    fi
  done
}

ensure_remote_path() {
  log "Checking remote path on Storage Box: ${REMOTE_PATH}"
  log "Note: Storage Box SFTP is chrooted; leading '/' refers to your home directory."

  log "Password auth is interactive; automated path checks are limited."
  if confirm "Open SFTP now to create/verify the path?" "false"; then
    log "In SFTP, run: mkdir ${REMOTE_PATH#/}  then: cd ${REMOTE_PATH#/}  then: pwd  then: exit"
    sftp -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=accept-new \
      "${STORAGEBOX_USER}@${STORAGEBOX_HOST}" || true
  fi
  if confirm "Confirm that ${REMOTE_PATH} exists in Storage Box?" "false"; then
    return 0
  fi
  die "Remote path missing or unconfirmed: ${REMOTE_PATH}"
}

ensure_fuse_allow_other() {
  if [[ -f /etc/fuse.conf ]]; then
    if ! grep -q "^user_allow_other" /etc/fuse.conf; then
      echo "user_allow_other" >> /etc/fuse.conf
    fi
  fi
}

ensure_storagebox_mount() {
  ensure_fuse_allow_other
  mkdir -p "$LOCAL_MOUNT"
  mkdir -p "$(dirname "$UPLOAD_LOCATION")"
  mkdir -p "$DB_DATA_LOCATION"

  if [[ "$AUTH_METHOD" == "password" ]]; then
    log "Password auth requires interactive mount. You will be prompted now."
    run_cmd sshfs -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,allow_other,noatime,StrictHostKeyChecking=accept-new,PreferredAuthentications=password,PubkeyAuthentication=no \
      "${STORAGEBOX_USER}@${STORAGEBOX_HOST}:${REMOTE_PATH}" "$LOCAL_MOUNT"
  else
    local fstab_line="${STORAGEBOX_USER}@${STORAGEBOX_HOST}:${REMOTE_PATH} ${LOCAL_MOUNT} fuse.sshfs _netdev,x-systemd.automount,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,allow_other,noatime,IdentityFile=${STORAGEBOX_KEY},StrictHostKeyChecking=accept-new 0 0 # immich-storagebox"

    if grep -q "immich-storagebox" /etc/fstab; then
      run_cmd sed -i "s|^.*immich-storagebox.*$|${fstab_line}|" /etc/fstab
    else
      echo "$fstab_line" >> /etc/fstab
    fi

    run_cmd systemctl daemon-reload
    if ! mountpoint -q "$LOCAL_MOUNT"; then
      run_cmd mount "$LOCAL_MOUNT"
    fi
  fi

  mkdir -p "$UPLOAD_LOCATION"
  local test_file="${LOCAL_MOUNT}/.immich_write_test"
  echo "test" > "$test_file"
  rm -f "$test_file"
}

troubleshoot_mount() {
  log "Storage Box mount not detected at ${LOCAL_MOUNT}."
  cat <<EOF

Troubleshooting steps:
  1) Verify SSH access:
     - Storage Box uses SFTP (no shell). Test with:
       sftp -o PreferredAuthentications=password -o PubkeyAuthentication=no ${STORAGEBOX_USER}@${STORAGEBOX_HOST}
  2) Check remote path exists: ${REMOTE_PATH}
  3) Check fuse config: grep user_allow_other /etc/fuse.conf
  4) Check mount status:
     - Key auth (fstab): systemctl status remote-fs.target
     - Password auth: mount | grep ${LOCAL_MOUNT}
  5) Inspect logs:
     - journalctl -u immich-storagebox.service -u remote-fs.target -e
EOF

  if confirm "Try to remount now?" "true"; then
    if [[ "$AUTH_METHOD" == "password" ]]; then
      run_cmd systemctl restart immich-storagebox.service
    else
      run_cmd mount "$LOCAL_MOUNT"
    fi
  fi
}

verify_mount_or_troubleshoot() {
  if ! mountpoint -q "$LOCAL_MOUNT"; then
    troubleshoot_mount
    if ! mountpoint -q "$LOCAL_MOUNT"; then
      die "Storage Box mount still missing at ${LOCAL_MOUNT}."
    fi
  fi
}

download_immich_compose() {
  mkdir -p "$IMMICH_DIR"
  if [[ ! -f "${IMMICH_DIR}/docker-compose.yml" ]]; then
    log "Downloading Immich Docker Compose..."
    run_cmd curl -fsSL -o "${IMMICH_DIR}/docker-compose.yml" \
      https://github.com/immich-app/immich/releases/latest/download/docker-compose.yml
  else
    log "docker-compose.yml already exists, keeping existing file."
  fi

  if [[ ! -f "${IMMICH_DIR}/example.env" ]]; then
    run_cmd curl -fsSL -o "${IMMICH_DIR}/example.env" \
      https://github.com/immich-app/immich/releases/latest/download/example.env
  fi
}

set_env_kv() {
  local file="$1"
  local key="$2"
  local value="$3"
  if grep -q "^${key}=" "$file"; then
    run_cmd sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

config_set_kv() {
  local key="$1"
  local value="$2"
  if [[ -f "$CONFIG_FILE" ]]; then
    if grep -q "^${key}=" "$CONFIG_FILE"; then
      run_cmd sed -i "s|^${key}=.*|${key}=${value}|" "$CONFIG_FILE"
    else
      echo "${key}=${value}" >> "$CONFIG_FILE"
    fi
  fi
}

step_is_done() {
  local step="$1"
  [[ ",${STEPS_DONE:-}," == *",${step},"* ]]
}

step_mark_done() {
  local step="$1"
  if step_is_done "$step"; then
    return 0
  fi
  if [[ -z "${STEPS_DONE:-}" ]]; then
    STEPS_DONE="$step"
  else
    STEPS_DONE="${STEPS_DONE},${step}"
  fi
  config_set_kv "STEPS_DONE" "$STEPS_DONE"
}

configure_immich_env() {
  local env_file="${IMMICH_DIR}/.env"
  if [[ ! -f "$env_file" ]]; then
    if [[ -f "${IMMICH_DIR}/example.env" ]]; then
      run_cmd cp "${IMMICH_DIR}/example.env" "$env_file"
    else
      touch "$env_file"
    fi
  fi

  local db_password="${DB_PASSWORD:-}"
  if [[ -z "$db_password" ]]; then
    db_password="$(openssl rand -hex 24)"
  fi

  set_env_kv "$env_file" "UPLOAD_LOCATION" "$UPLOAD_LOCATION"
  set_env_kv "$env_file" "DB_DATA_LOCATION" "$DB_DATA_LOCATION"
  set_env_kv "$env_file" "DB_PASSWORD" "$db_password"
  set_env_kv "$env_file" "DB_USERNAME" "immich"
  set_env_kv "$env_file" "DB_DATABASE" "immich"
  set_env_kv "$env_file" "IMMICH_VERSION" "release"

  DB_PASSWORD="$db_password"
}

deploy_immich() {
  if step_is_done "immich" && [[ -f "${IMMICH_DIR}/docker-compose.yml" ]]; then
    log "Immich already configured; ensuring services are up."
  fi
  download_immich_compose
  configure_immich_env

  pushd "$IMMICH_DIR" >/dev/null
  run_cmd docker compose pull
  run_cmd docker compose up -d
  popd >/dev/null

  if ! docker compose -f "${IMMICH_DIR}/docker-compose.yml" ps >/dev/null 2>&1; then
    log "Warning: Unable to verify docker compose status."
  fi
}

install_nginx_certbot() {
  if step_is_done "nginx" && command -v nginx >/dev/null 2>&1 && command -v certbot >/dev/null 2>&1; then
    log "Nginx and certbot already installed; skipping."
    return 0
  fi
  install_packages nginx certbot python3-certbot-nginx
  run_cmd systemctl enable --now nginx
}

normalize_ip_list() {
  local list="$1"
  local item=""
  IFS=',' read -r -a items <<< "$list"
  for item in "${items[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    if [[ -n "$item" ]]; then
      echo "$item"
    fi
  done
}

write_nginx_config() {
  local site="/etc/nginx/sites-available/${DOMAIN}"
  local allowlist=""
  local with_ssl="${1:-false}"

  while IFS= read -r ip; do
    allowlist="${allowlist}    allow ${ip};"$'\n'
  done < <(normalize_ip_list "$ALLOWED_IPS")

  if [[ -z "$allowlist" ]]; then
    allowlist="    # No IP allowlist configured; access is open."
  else
    allowlist="${allowlist}    deny all;"
  fi

  if [[ "$with_ssl" == "true" ]]; then
    ensure_ssl_snippets
    cat > "$site" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;

    client_max_body_size 0;

${allowlist}

    location / {
        proxy_pass http://127.0.0.1:2283;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
  else
    cat > "$site" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
  fi

  ln -sf "$site" "/etc/nginx/sites-enabled/${DOMAIN}"
  if [[ -f /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
  fi

  run_cmd nginx -t
  run_cmd systemctl reload nginx
}

ensure_ssl_snippets() {
  if [[ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]]; then
    log "Creating /etc/letsencrypt/options-ssl-nginx.conf (minimal TLS settings)."
    mkdir -p /etc/letsencrypt
    cat > /etc/letsencrypt/options-ssl-nginx.conf <<'EOF'
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
EOF
  fi
}

ensure_certbot() {
  if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
    log "Existing TLS cert found for ${DOMAIN}."
    return 0
  fi
  run_cmd certbot certonly --webroot -w /var/www/html -d "$DOMAIN" \
    -m "$LETSENCRYPT_EMAIL" --agree-tos --non-interactive
}

dns_guidance() {
  local ips
  local ipv4
  local ipv6
  ips="$(get_public_ip)"
  ipv4="${ips%%|*}"
  ipv6="${ips##*|}"

  log "Public IPs detected:"
  log "IPv4: ${ipv4:-not detected}"
  log "IPv6: ${ipv6:-not detected}"

  cat <<EOF

DNS Records to create:
  A     ${DOMAIN} -> ${ipv4:-<your IPv4>}
  AAAA  ${DOMAIN} -> ${ipv6:-<your IPv6>} (optional)
EOF

  if confirm "Wait for DNS to propagate before continuing?" "true"; then
    if command -v getent >/dev/null 2>&1; then
      log "DNS resolution check for ${DOMAIN}:"
      getent ahosts "$DOMAIN" || true
    else
      log "getent not available; skipping DNS check."
    fi
    if [[ "$UNATTENDED" != "true" ]]; then
      read -r -p "Press Enter to continue once DNS is ready..."
    fi
  fi
}

setup_firewall_optional() {
  if confirm "Configure UFW to allow only 22/80/443?" "true"; then
    install_packages ufw
    run_cmd ufw allow 22/tcp
    run_cmd ufw allow 80/tcp
    run_cmd ufw allow 443/tcp
    run_cmd ufw --force enable
  fi
}

install_healthcheck() {
  if ! confirm "Install health checks with auto-repair (mount, containers, nginx)?" "false"; then
    return 0
  fi

  local hc_script="/usr/local/bin/immich-healthcheck.sh"
  cat > "$hc_script" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

LOG_FILE="/var/log/immich-healthcheck.log"
IMMICH_DIR="${IMMICH_DIR}"
LOCAL_MOUNT="${LOCAL_MOUNT}"
AUTH_METHOD="${AUTH_METHOD}"

log() {
  echo "[\$(date +"%Y-%m-%d %H:%M:%S")] \$*" | tee -a "\$LOG_FILE"
}

ensure_mount() {
  if mountpoint -q "\$LOCAL_MOUNT"; then
    return 0
  fi
  log "Mount missing at \$LOCAL_MOUNT; attempting remount."
  if [[ "\$AUTH_METHOD" == "password" ]]; then
    log "Password auth requires interactive mount; manual action needed."
    return 1
  fi
  mount "\$LOCAL_MOUNT" || return 1
}

ensure_containers() {
  if [[ -d "\$IMMICH_DIR" ]]; then
    (cd "\$IMMICH_DIR" && docker compose up -d) || return 1
  fi
}

ensure_nginx() {
  systemctl is-active --quiet nginx || systemctl restart nginx || return 1
}

main() {
  log "Healthcheck start."
  ensure_mount || log "Mount check failed."
  ensure_containers || log "Container check failed."
  ensure_nginx || log "Nginx check failed."
  log "Healthcheck done."
}

main "\$@"
EOF
  chmod +x "$hc_script"

  cat > /etc/systemd/system/immich-healthcheck.service <<EOF
[Unit]
Description=Immich healthcheck and auto-repair

[Service]
Type=oneshot
ExecStart=${hc_script}
EOF

  cat > /etc/systemd/system/immich-healthcheck.timer <<EOF
[Unit]
Description=Run Immich healthcheck every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  run_cmd systemctl daemon-reload
  run_cmd systemctl enable --now immich-healthcheck.timer
  log "Healthcheck installed. Logs: /var/log/immich-healthcheck.log"
}

final_summary() {
  cat <<EOF

Immich setup complete.

URL: https://${DOMAIN}
You can now complete setup at: https://${DOMAIN}
Upload location: ${UPLOAD_LOCATION}
Database data: ${DB_DATA_LOCATION}
Compose dir: ${IMMICH_DIR}
Storage Box mount: ${LOCAL_MOUNT}
Installer config: ${CONFIG_FILE}

Runbook:
  Update Immich: (cd ${IMMICH_DIR} && docker compose pull && docker compose up -d)
  Check mount: systemctl status remote-fs.target; mount | grep ${LOCAL_MOUNT}
  Logs: journalctl -u sshfs -u remote-fs.target
  Edit allowed IPs: ${CONFIG_FILE} then re-run this script (set empty to open access)
  Reload Nginx: nginx -t && systemctl reload nginx

Immich CLI (inside container):
  Run: docker exec -it immich_server immich-admin <command>
  Commands: help, reset-admin-password, disable-password-login, enable-password-login,
            disable-maintenance-mode, enable-maintenance-mode, enable-oauth-login,
            disable-oauth-login, list-users, version, change-media-location
EOF
}

main() {
  parse_args "$@"
  require_root "$@"
  ensure_logfile
  load_config

  log "Immich installer starting."
  preflight

  if ! confirm "This will install Docker, SSHFS, Nginx, and configure Immich. Continue?" "true"; then
    die "Aborted by user."
  fi

  if [[ -f "$CONFIG_FILE" && "$FORCE_PROMPTS" == "false" && "$UNATTENDED" == "false" ]]; then
    if confirm "Found existing config at ${CONFIG_FILE}. Resume with saved values?" "false"; then
      log "Resuming with existing config."
    else
      collect_inputs
    fi
  else
    collect_inputs
  fi
  if [[ "$CONFIG_FILE_EXPLICIT" == "false" ]]; then
    CONFIG_FILE="${IMMICH_DIR}/installer.env"
  fi
  save_config

  if ! step_is_done "dns"; then
    dns_guidance
    step_mark_done "dns"
  fi

  install_docker
  step_mark_done "docker"

  ensure_sshfs
  test_storagebox_ssh
  ensure_remote_path
  ensure_storagebox_mount
  verify_mount_or_troubleshoot
  step_mark_done "sshfs"

  deploy_immich
  step_mark_done "immich"

  install_nginx_certbot
  if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
    write_nginx_config "true"
  else
    write_nginx_config "false"
    ensure_certbot
    write_nginx_config "true"
  fi
  step_mark_done "nginx"
  step_mark_done "certbot"

  setup_firewall_optional
  step_mark_done "ufw"

  install_healthcheck
  step_mark_done "healthcheck"

  final_summary
}

main "$@"
