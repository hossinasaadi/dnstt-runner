#!/usr/bin/env bash
set -euo pipefail

APP="dnstt-runner"
BIN_DIR="/usr/local/bin"
ETC_DIR="/etc/${APP}"
STATE_DIR="/var/lib/${APP}"
LOG_DIR="/var/log/${APP}"
RUNNER="${BIN_DIR}/${APP}.sh"
ENV_FILE="${ETC_DIR}/${APP}.env"
SECRET_FILE="${ETC_DIR}/secret.pass"
SERVICE_FILE="/etc/systemd/system/${APP}.service"
DNSTT_BIN="${BIN_DIR}/dnstt-client"

DNSTT_URL_AMD64="https://dnstt.network/dnstt-client-linux-amd64"
DNSTT_URL_ARM64="https://dnstt.network/dnstt-client-linux-arm64"

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}[!] Run as root (use sudo).${NC}"
    exit 1
  fi
}

arch_to_url() {
  local a
  a="$(uname -m)"
  case "$a" in
    x86_64|amd64) echo "$DNSTT_URL_AMD64" ;;
    aarch64|arm64) echo "$DNSTT_URL_ARM64" ;;
    *)
      echo -e "${RED}[!] Unsupported arch: ${a}${NC}"
      echo "Supported: amd64 (x86_64), arm64 (aarch64)"
      exit 2
      ;;
  esac
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

install_pkgs() {
  local missing=()

  have_cmd curl     || missing+=(curl)
  have_cmd haproxy  || missing+=(haproxy)
  have_cmd sshpass  || missing+=(sshpass)
  have_cmd timeout  || missing+=(coreutils)

  if (( ${#missing[@]} == 0 )); then
    echo "[*] Dependencies already installed. Skipping apt update/install."
    return 0
  fi

  echo "[*] Installing missing dependencies: ${missing[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y "${missing[@]}"
}

download_dnstt() {
  local url
  url="$(arch_to_url)"

  if [[ -x "$DNSTT_BIN" ]]; then
    echo "[*] DNSTT already exists: $DNSTT_BIN (skipping download)"
    return 0
  fi

  mkdir -p "$BIN_DIR"
  echo "[*] Downloading DNSTT client:"
  echo "    $url"

  if timeout 10s curl -fsSL \
      --connect-timeout 3 \
      --max-time 9 \
      "$url" -o "${DNSTT_BIN}.tmp"; then

    chmod +x "${DNSTT_BIN}.tmp"
    mv -f "${DNSTT_BIN}.tmp" "$DNSTT_BIN"
    echo "[+] Installed: $DNSTT_BIN"
    return 0
  fi

  rm -f "${DNSTT_BIN}.tmp" >/dev/null 2>&1 || true

  echo "[!] Could not download DNSTT within 10 seconds."
  echo "    Tip: download manually and upload it to this server."
  echo "      $url"
  echo "    Then run:"
  echo "      sudo install -m 0755 <downloaded-file> $DNSTT_BIN"
  echo
  echo "Important tip: This setup only works in SSH mode (DNSTT -> SSH dynamic SOCKS)."
  exit 1
}

prompt_defaults() {
  local prompt="$1" def="${2:-}"
  local out
  if [[ -n "$def" ]]; then
    read -rp "$prompt [$def]: " out
    echo "${out:-$def}"
  else
    read -rp "$prompt: " out
    echo "$out"
  fi
}

prompt_secret() {
  local prompt="$1"
  local out
  read -rsp "$prompt: " out
  echo
  echo "$out"
}

normalize_dns() {
  local dns="$1"
  if [[ "$dns" == *:* ]]; then
    echo "$dns"
  else
    echo "${dns}:53"
  fi
}

load_old_defaults() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE" || true
  fi
}

parse_target_auth() {
  # input: user@ip  -> sets TARGET_USER and TARGET_IP (if empty)
  local auth="$1"
  if [[ "$auth" == *@* ]]; then
    TARGET_USER="${auth%@*}"
    # ip part could be host; but you also ask TARGET_IP separately.
    # keep TARGET_IP as separate input (more reliable).
  else
    TARGET_USER="$auth"
  fi
  [[ -n "${TARGET_USER:-}" ]] || TARGET_USER="root"
}

write_env() {
  mkdir -p "$ETC_DIR" "$STATE_DIR" "$LOG_DIR"
  chmod 700 "$ETC_DIR" "$STATE_DIR"
  chmod 755 "$LOG_DIR"

  cat >"$ENV_FILE" <<EOF
# ${APP} config
# Important: This only works in SSH mode.

DNSTT_DOMAIN="${DNSTT_DOMAIN}"
DNSTT_PUBKEY="${DNSTT_PUBKEY}"
TARGET_IP="${TARGET_IP}"
TARGET_USER="${TARGET_USER}"
RUN_COUNT="${RUN_COUNT}"
UDP_DNS_SERVER="${UDP_DNS_SERVER}"

BASE_DNSTT_PORT="5002"
BASE_SOCKS_PORT="6002"

HAPROXY_ENABLE="1"
HAPROXY_LISTEN_IP="127.0.0.1"
HAPROXY_LISTEN_PORT="10802"
EOF

  chmod 600 "$ENV_FILE"
  echo -e "${GREEN}[+] Saved config: $ENV_FILE${NC}"
}

write_secret() {
  # root-only password storage so systemd can restart after reboot
  # If you want “never saved”, use SSH keys instead.
  mkdir -p "$ETC_DIR"
  printf '%s' "$TARGET_PASS" | tr -d '\r\n' >"$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
}

write_runner() {
  cat >"$RUNNER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP="dnstt-runner"
ENV_FILE="/etc/dnstt-runner/dnstt-runner.env"
SECRET_FILE="/etc/dnstt-runner/secret.pass"
STATE_DIR="/var/lib/dnstt-runner"
LOG_DIR="/var/log/dnstt-runner"
DNSTT_BIN="/usr/local/bin/dnstt-client"

mkdir -p "$STATE_DIR" "$LOG_DIR"

# shellcheck disable=SC1090
source "$ENV_FILE"

PUBKEY="${DNSTT_PUBKEY}"
DOMAIN="${DNSTT_DOMAIN}"
TARGET="${TARGET_USER}@127.0.0.1"   # optional convenience

if [[ ! -f "$SECRET_FILE" ]]; then
  echo "[!] Missing secret file: $SECRET_FILE"
  echo "    Re-run installer and enter password, or switch to SSH keys."
  exit 1
fi

IFS= read -r TARGET_PASS <"$SECRET_FILE" || true
TARGET_PASS="$(printf '%s' "$TARGET_PASS" | tr -d '\r\n')"

[[ -n "$TARGET_PASS" ]] || { echo "[!] stored password is empty"; exit 1; }

pidfile() { echo "$STATE_DIR/$1.pid"; }

kill_pidfile() {
  local pf="$1"
  [[ -f "$pf" ]] || return 0
  local pid
  pid="$(cat "$pf" 2>/dev/null || true)"
  if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 0.3
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pf" 2>/dev/null || true
}

start_one() {
  local idx="$1"
  local dport=$((BASE_DNSTT_PORT + idx))
  local sport=$((BASE_SOCKS_PORT + idx))
  local dlog="$LOG_DIR/dnstt_${idx}.log"
  local slog="$LOG_DIR/ssh_${idx}.log"

  echo "[*] instance $idx: dnstt=127.0.0.1:$dport socks=127.0.0.1:$sport dns=$UDP_DNS_SERVER"

  "$DNSTT_BIN" -udp "$UDP_DNS_SERVER" -pubkey "$DNSTT_PUBKEY" "$DNSTT_DOMAIN" "127.0.0.1:$dport" \
    >>"$dlog" 2>&1 &
  echo $! >"$(pidfile "dnstt_${idx}")"

  sleep $((idx * 1))
    
  SSH_CMD="ssh -N \
  -D 127.0.0.1:$sport \
  -C \
  -v \
  -o PreferredAuthentications=password \
  -o UserKnownHostsFile=/dev/null \
  -o PubkeyAuthentication=no \
  -o StrictHostKeyChecking=no \
  -o ServerAliveInterval=5 \
  -o ServerAliveCountMax=20 \
  -o ExitOnForwardFailure=yes \
  -p $dport \
  $TARGET_USER@127.0.0.1"
  
  sshpass -p "$TARGET_PASS" $SSH_CMD >>"$slog" 2>&1 &
  echo $! >"$(pidfile "ssh_${idx}")"
}

stop_all() {
  for pf in "$STATE_DIR"/*.pid; do
    [[ -e "$pf" ]] || continue
    kill_pidfile "$pf"
  done
}

haproxy_cfg="/etc/dnstt-runner/haproxy.cfg"
haproxy_pid="/run/haproxy-dnstt-runner.pid"

start_haproxy() {
  [[ "${HAPROXY_ENABLE:-0}" = "1" ]] || return 0

  {
    echo "global"
    echo "  daemon"
    echo "  pidfile $haproxy_pid"
    echo "  maxconn 4096"
    echo ""
    echo "defaults"
    echo "  mode tcp"
    echo "  timeout connect 5s"
    echo "  timeout client  60s"
    echo "  timeout server  60s"
    echo "  option tcplog"
    echo ""
    echo "frontend socks_in"
    echo "  bind ${HAPROXY_LISTEN_IP}:${HAPROXY_LISTEN_PORT}"
    echo "  default_backend socks_pool"
    echo ""
    echo "backend socks_pool"
    echo "  balance leastconn"
    echo "  option tcp-check"
    echo "  default-server inter 2s fall 3 rise 2"
    for ((i=0;i<RUN_COUNT;i++)); do
      sport=$((BASE_SOCKS_PORT + i))
      echo "  server s$i 127.0.0.1:$sport check"
    done
  } >"$haproxy_cfg"

  haproxy -c -f "$haproxy_cfg" >/dev/null 2>&1
  haproxy -f "$haproxy_cfg" >/dev/null 2>&1

  echo "[*] haproxy: listening on ${HAPROXY_LISTEN_IP}:${HAPROXY_LISTEN_PORT}"
}

stop_haproxy() {
  if [[ -f "$haproxy_pid" ]]; then
    pid="$(cat "$haproxy_pid" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.2
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$haproxy_pid" 2>/dev/null || true
  fi
  pkill -f "$haproxy_cfg" >/dev/null 2>&1 || true
}

test_dns_servers() {
  read -rp "Enter DNS IPs (space separated): " IP_LIST
  [ -z "$IP_LIST" ] && echo "No IPs entered" && return 1

  i=0
  PIDS=()

  cleanup() {
    echo
    echo "[!] Cleaning up..."
    for pid in "${PIDS[@]}"; do
      kill "$pid" 2>/dev/null || true
    done
  }
  trap cleanup INT TERM

  for IP in $IP_LIST; do
  (
    DNSTT_PORT=$((8001 + i))
    SOCKS_PORT=$((9001 + i))

    LOG="/tmp/test_${IP}_${DNSTT_PORT}.log"
    slog="/tmp/ssh_test_${i}.log"

    echo "[*] $IP -> testing (dnstt=$DNSTT_PORT socks=$SOCKS_PORT)"

    # ---- DNSTT ----
    "$DNSTT_BIN" \
      -pubkey "$PUBKEY" \
      -udp "$IP:53" \
      "$DOMAIN" 127.0.0.1:$DNSTT_PORT \
      >>"$LOG" 2>&1 &
    DPID=$!

    sleep 2

    dport="$DNSTT_PORT"
    sport="$SOCKS_PORT"
    idx="$i"

    SSH_CMD="ssh -N \
    -D 127.0.0.1:$sport \
    -C \
    -v \
    -o PreferredAuthentications=password \
    -o UserKnownHostsFile=/dev/null \
    -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=20 \
    -o ExitOnForwardFailure=yes \
    -p $dport \
    $TARGET_USER@127.0.0.1"

    sshpass -p "$TARGET_PASS" $SSH_CMD >>"$slog" 2>&1 &
    SPID=$!

    sleep 40

    # ---- CURL TEST ----
    CURL_TIME="$(
      curl --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
           -m 40 --fail -s \
           -w "%{time_total}" \
           http://ifconfig.me/ \
           -o /dev/null
    )"
    RC=$?

    if [ "$RC" -eq 0 ]; then
      echo "✅ $IP WORKS (time=${CURL_TIME}s)"
    elif [ "$RC" -eq 35 ]; then
      echo "🟡 $IP CONNECTED (SSL EOF) (time=${CURL_TIME}s)"
    else
      echo "❌ $IP FAIL (rc=$RC time=${CURL_TIME}s)"
    fi

    kill "$DPID" "$SPID" 2>/dev/null || true
  ) &

    PIDS+=($!)
    i=$((i+1))
  done

  echo
  echo "[*] Waiting for all tests..."
  wait
  echo "[*] All tests finished."
}

cmd="${1:-}"
case "$cmd" in
  start)
    stop_haproxy
    stop_all
    for ((i=0;i<RUN_COUNT;i++)); do
      start_one "$i"
    done
    start_haproxy
    ;;
  stop)
    stop_haproxy
    stop_all
    ;;
  restart)
    "$0" stop
    sleep 0.2
    "$0" start
    ;;
  status)
    echo "== dnstt-runner status =="
    echo "RUN_COUNT=$RUN_COUNT  HAPROXY=${HAPROXY_LISTEN_IP}:${HAPROXY_LISTEN_PORT}"
    ss -lntup | egrep ":(5002|6002|${HAPROXY_LISTEN_PORT})\b" || true
    ;;
  testdns)
    test_dns_servers
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac
EOF

  chmod 755 "$RUNNER"
  echo -e "${GREEN}[+] Runner installed: $RUNNER${NC}"
}

write_service() {
  cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=DNSTT Runner (DNSTT + SSHpass + HAProxy)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=$ENV_FILE
ExecStart=$RUNNER start
ExecStop=$RUNNER stop
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${APP}.service" >/dev/null
  echo -e "${GREEN}[+] systemd service installed: ${APP}.service${NC}"
}

collect_user_input() {
  load_old_defaults

  echo
  echo -e "${YELLOW}Important tip:${NC} This setup only works in SSH mode (DNSTT -> SSH dynamic SOCKS)."
  echo -e "${YELLOW}Security tip:${NC} SSH keys are recommended. Password is stored root-only in ${SECRET_FILE} for auto-restart."
  echo

  DNSTT_DOMAIN="$(prompt_defaults "Nameserver subdomain (DNSTT domain, ex: t.example.com)" "${DNSTT_DOMAIN:-}")"
  [[ -n "$DNSTT_DOMAIN" ]] || { echo "[!] domain required"; exit 1; }

  DNSTT_PUBKEY="$(prompt_defaults "Public Key Content" "${DNSTT_PUBKEY:-}")"
  [[ -n "$DNSTT_PUBKEY" ]] || { echo "[!] pubkey required"; exit 1; }

  TARGET_IP="$(prompt_defaults "Target Server IP (ex: 1.2.3.4)" "${TARGET_IP:-}")"
  [[ -n "$TARGET_IP" ]] || { echo "[!] target ip required"; exit 1; }

  echo "Tip: Target Server Auth example: root@1.2.3.4 (used only to extract username)"
  TARGET_AUTH_DEFAULT="${TARGET_USER:-root}@${TARGET_IP}"
  TARGET_AUTH="$(prompt_defaults "Target Server Auth (user@ip)" "$TARGET_AUTH_DEFAULT")"
  parse_target_auth "$TARGET_AUTH"

  RUN_COUNT="$(prompt_defaults "Running instance count" "${RUN_COUNT:-1}")"
  [[ "$RUN_COUNT" =~ ^[0-9]+$ ]] || { echo "[!] RUN_COUNT must be a number"; exit 1; }
  [[ "$RUN_COUNT" -ge 1 && "$RUN_COUNT" -le 50 ]] || { echo "[!] choose RUN_COUNT between 1 and 50"; exit 1; }

  dns_default="${UDP_DNS_SERVER:-1.1.1.1:53}"
  dns="$(prompt_defaults "DNS server (ex: 1.1.1.1 or 1.1.1.1:53)" "$dns_default")"
  UDP_DNS_SERVER="$(normalize_dns "$dns")"

    TARGET_PASS="$(prompt_secret "SSH password for ${TARGET_USER}@${TARGET_IP} (used via sshpass)")"
    # sanitize: remove CR/LF anywhere (common from paste), keep everything else
    TARGET_PASS="$(printf '%s' "$TARGET_PASS" | tr -d '\r\n')"

  [[ -n "$TARGET_PASS" ]] || { echo "[!] password required"; exit 1; }
}

cmd_install() {
  need_root
  install_pkgs
  download_dnstt
  collect_user_input
  write_env
  write_secret
  write_runner
  write_service
  systemctl restart "${APP}.service"
  systemctl --no-pager status "${APP}.service" || true

  echo
  echo -e "${GREEN}[+] Done.${NC}"
  echo "Public SOCKS (via HAProxy): 0.0.0.0:10802 (if enabled)"
  echo "Logs: $LOG_DIR"
}

cmd_uninstall() {
  need_root
  systemctl stop "${APP}.service" >/dev/null 2>&1 || true
  systemctl disable "${APP}.service" >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE" "$RUNNER" >/dev/null 2>&1 || true
  rm -f "$DNSTT_BIN" >/dev/null 2>&1 || true
  rm -rf "$ETC_DIR" "$STATE_DIR" "$LOG_DIR" >/dev/null 2>&1 || true
  systemctl daemon-reload
  echo -e "${GREEN}[+] Uninstalled.${NC}"
}

cmd_start()   { need_root; systemctl start  "${APP}.service"; systemctl --no-pager status "${APP}.service" || true; }
cmd_stop()    { need_root; systemctl stop   "${APP}.service"; }
cmd_restart() { need_root; systemctl restart "${APP}.service"; systemctl --no-pager status "${APP}.service" || true; }
cmd_status()  { need_root; systemctl --no-pager status "${APP}.service" || true; "$RUNNER" status || true; }
cmd_logs()    { need_root; journalctl -u "${APP}.service" -n 200 --no-pager; echo; ls -la "$LOG_DIR" 2>/dev/null || true; }

cmd_testdnsList() {
  need_root
#   load_old_defaults
  # run runner command directly (not via systemd)
  "$RUNNER" testdns
}

usage() {
  cat <<EOF
Usage: sudo $0 <command>

Commands:
  install     Install deps if missing, download dnstt, ask config (old values as defaults), create service, start
  start       Start service
  stop        Stop service
  restart     Restart service
  status      Show status + listening ports
  logs        Show last 200 journal logs + list log files
  testdns     Test DNS servers (spawns temp dnstt+ssh per IP, ctrl+c stops all)
  uninstall   Remove everything
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    install)   cmd_install ;;
    start)     cmd_start ;;
    stop)      cmd_stop ;;
    restart)   cmd_restart ;;
    status)    cmd_status ;;
    logs)      cmd_logs ;;
    testdns)   cmd_testdnsList ;;
    uninstall) cmd_uninstall ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"