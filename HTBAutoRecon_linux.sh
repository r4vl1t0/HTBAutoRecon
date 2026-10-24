#!/usr/bin/env bash
# Initial reconnaissance for authorized HTB/lab Linux targets.
set -uo pipefail

if [[ $# -ne 1 ]]; then
  echo "Uso: $0 <IP_TARGET>"
  echo "Ejemplo: $0 10.10.10.1"
  exit 1
fi

TARGET_IP="$1"
if ! [[ "$TARGET_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "[!] Introduce una dirección IPv4 válida."
  exit 1
fi

REPORT="${REPORT:-$PWD/PostRecon.txt}"
DIR_WORDLISTS="${DIR_WORDLISTS:-${DIR_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}}"
SUB_WORDLIST="${SUB_WORDLIST:-/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt}"
TARGET_DOM=""
PROTO="http"
VHOST_JSON="$(mktemp /tmp/htb-vhosts.XXXXXX.json)"
trap 'rm -f "$VHOST_JSON"' EXIT

: > "$REPORT"

status() {
  printf '\n[+] %s\n' "$1" | tee -a "$REPORT"
}

section() {
  printf '\n========== %s ==========\n' "$1" | tee -a "$REPORT"
}

run() {
  "$@" 2>&1 | tee -a "$REPORT"
  return ${PIPESTATUS[0]}
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[!] Falta la herramienta requerida: %s\n' "$1" | tee -a "$REPORT"
    return 1
  fi
}

require_sudo() {
  status "Solicitando permisos sudo para Nmap y /etc/hosts"
  if ! sudo -v; then
    printf '[!] No se obtuvieron permisos sudo; no se puede continuar.\n' | tee -a "$REPORT"
    exit 1
  fi
}

add_host() {
  local host="$1"
  if awk -v host="$host" '!/^[[:space:]]*#/ { for (i = 2; i <= NF; i++) if ($i == host) found = 1 } END { exit !found }' /etc/hosts; then
    printf '[*] %s ya existe en /etc/hosts\n' "$host" | tee -a "$REPORT"
  else
    if ! printf '%s  %s\n' "$TARGET_IP" "$host" | sudo tee -a /etc/hosts >/dev/null; then
      printf '[!] No se pudo escribir %s en /etc/hosts.\n' "$host" | tee -a "$REPORT"
      return 1
    fi
    if ! awk -v host="$host" '!/^[[:space:]]*#/ { for (i = 2; i <= NF; i++) if ($i == host) found = 1 } END { exit !found }' /etc/hosts; then
      printf '[!] La verificación de /etc/hosts falló para %s.\n' "$host" | tee -a "$REPORT"
      return 1
    fi
    printf '[+] Verificado en /etc/hosts: %s -> %s\n' "$host" "$TARGET_IP" | tee -a "$REPORT"
  fi
}

fuzz_directories() {
  local host="$1"
  local wordlist
  status "Fuzzing de directorios: $PROTO://$host/"
  for wordlist in $DIR_WORDLISTS; do
    if [[ ! -r "$wordlist" ]]; then
      printf '[!] Wordlist no encontrada: %s\n' "$wordlist" | tee -a "$REPORT"
      continue
    fi
    printf '\n----- DIRECTORIOS: %s | %s -----\n' "$host" "$wordlist" | tee -a "$REPORT"
    run ffuf -s -c -w "$wordlist" -u "$PROTO://$host/FUZZ" -ac || \
      printf '[!] Error durante fuzzing de directorios para %s\n' "$host" | tee -a "$REPORT"
  done
}

section "POST RECON"
printf 'Objetivo: %s\nInicio: %s\n' "$TARGET_IP" "$(date -Is)" | tee -a "$REPORT"

for tool in nmap curl ffuf jq; do
  require "$tool" || exit 1
done
require_sudo

status "Comprobando conectividad y TTL (solo orientativo)"
PING_OUTPUT="$(ping -c 1 -W 2 "$TARGET_IP" 2>&1 || true)"
printf '%s\n' "$PING_OUTPUT" | tee -a "$REPORT"
TTL="$(printf '%s\n' "$PING_OUTPUT" | sed -n 's/.*ttl=\([0-9][0-9]*\).*/\1/p' | head -n1)"
if [[ "$TTL" == "64" || "$TTL" == "63" ]]; then
  printf 'OS_HINT: posible Linux (TTL=%s; sin confirmar)\n' "$TTL" | tee -a "$REPORT"
else
  printf 'OS_HINT: sin confirmar%s\n' "${TTL:+ (TTL=$TTL)}" | tee -a "$REPORT"
fi

status "Ejecutando escaneo Nmap completo"
section "NMAP"
run sudo nmap -sS -sCV -p- --min-rate 5000 -Pn -n --disable-arp-ping --open "$TARGET_IP" || \
  printf '[!] Nmap terminó con error.\n' | tee -a "$REPORT"

status "Buscando redirección o nombre de dominio web"
section "WEB DISCOVERY"
HEADERS="$(curl -k -sS -I --connect-timeout 5 "http://$TARGET_IP" 2>&1 || true)"
printf '%s\n' "$HEADERS" | tee -a "$REPORT"
# mawk (the default awk on many Kali/Ubuntu systems) does not implement
# IGNORECASE, so compare the header name explicitly in lowercase.
LOCATION="$(printf '%s\n' "$HEADERS" | awk 'tolower($1) == "location:" {print $2; exit}' | tr -d '\r')"
if [[ "$LOCATION" =~ ^https?:// ]]; then
  PROTO="${LOCATION%%://*}"
  TARGET_DOM="$(printf '%s' "$LOCATION" | sed -E 's#^https?://([^/:]+).*#\1#')"
  if [[ "$TARGET_DOM" =~ ^[A-Za-z0-9.-]+$ ]]; then
    printf 'Dominio detectado: %s\nProtocolo detectado: %s\n' "$TARGET_DOM" "$PROTO" | tee -a "$REPORT"
    status "Resolviendo el dominio detectado en /etc/hosts"
    add_host "$TARGET_DOM" || exit 1
  else
    printf '[!] El dominio recibido no es válido: %s\n' "$TARGET_DOM" | tee -a "$REPORT"
    TARGET_DOM=""
  fi
else
  printf 'No se detectó redirección; se usará la IP.\n' | tee -a "$REPORT"
fi

WEB_TARGET="${TARGET_DOM:-$TARGET_IP}"
status "Guardando cabeceras y respuesta HTTP inicial"
section "HTTP RESPONSE"
run curl -k -sS -i --connect-timeout 10 "$PROTO://$WEB_TARGET/" || true

if [[ -n "$DIR_WORDLISTS" ]]; then
  section "DIRECTORY FUZZING"
  fuzz_directories "$WEB_TARGET"
else
  printf '[!] No se definieron wordlists de directorios.\n' | tee -a "$REPORT"
fi

if [[ -n "$TARGET_DOM" && -r "$SUB_WORDLIST" ]]; then
  status "Buscando vhosts para $TARGET_DOM"
  section "VHOST FUZZING"
  run ffuf -s -c -w "$SUB_WORDLIST" -u "$PROTO://$TARGET_IP/" -H "Host: FUZZ.$TARGET_DOM" -ac -of json -o "$VHOST_JSON" || \
    printf '[!] Error durante fuzzing de vhosts.\n' | tee -a "$REPORT"

  mapfile -t VHOSTS < <(jq -r '.results[]?.input.FUZZ // empty' "$VHOST_JSON" 2>/dev/null | sort -u)
  if [[ ${#VHOSTS[@]} -eq 0 ]]; then
    printf '[*] No se encontraron vhosts.\n' | tee -a "$REPORT"
  else
    section "VHOSTS ENCONTRADOS"
    for subdomain in "${VHOSTS[@]}"; do
      [[ "$subdomain" =~ ^[A-Za-z0-9-]+$ ]] || continue
      vhost="$subdomain.$TARGET_DOM"
      printf '%s\n' "$vhost" | tee -a "$REPORT"
      add_host "$vhost" || continue
      [[ -n "$DIR_WORDLISTS" ]] && fuzz_directories "$vhost"
    done
  fi
fi

section "FIN"
printf 'Finalizado: %s\nReporte único: %s\n' "$(date -Is)" "$REPORT" | tee -a "$REPORT"
