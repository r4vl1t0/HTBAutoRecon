#!/usr/bin/env bash
# Reconocimiento amplio: common.txt, quickhits.txt y 100 000 subdominios.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export REPORT="$PWD/post-recon-large.txt"
export DIR_WORDLISTS="/usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/quickhits.txt"
export SUB_WORDLIST="/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"

exec "$SCRIPT_DIR/HTBAutoRecon_linux.sh" "$@"
