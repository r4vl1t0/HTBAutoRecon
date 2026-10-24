#!/usr/bin/env bash
# Reconocimiento ligero: directorios common.txt y 5 000 subdominios.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export REPORT="$PWD/post-recon-light.txt"
export DIR_WORDLISTS="/usr/share/seclists/Discovery/Web-Content/common.txt"
export SUB_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

exec "$SCRIPT_DIR/HTBAutoRecon_linux.sh" "$@"
