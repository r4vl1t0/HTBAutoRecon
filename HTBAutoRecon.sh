#!/bin/bash
echo "[+] Made By: Raulitos"
echo "[+] Github https://github.com/r4vl1t0/HTBAutoRecon"
sudo su -c exit

if [ $# -eq 0 ]; then
    echo "[!] Uso: $0 <IP_TARGET>"
    echo "[!] Ejemplo: $0 10.10.10.1"
    exit 1
fi

TARGET_IP=$1
DIRFILE="$(pwd)/Directorios.full"
SUB_TMP="/tmp/subdominio.tmp"

WriteHelperScript() {
    cat > /tmp/htb_fuzz.sh << 'FUZZEOF'
#!/bin/bash
TARGET_DOM="$1"
TARGET_IP="$2"
DIRFILE="$3"
SUB_TMP="$4"
PROTO="$5"

FUZZ_TARGET="${TARGET_DOM:-$TARGET_IP}"
WORDLIST_DIRS="/usr/share/seclists/Discovery/Web-Content/common.txt"
WORDLIST_SUBS="/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"

> "$DIRFILE"
> "$SUB_TMP"

printf "=== $PROTO://$FUZZ_TARGET/ ===\n" >> "$DIRFILE"
ffuf -s -c -w "$WORDLIST_DIRS" \
    -u "$PROTO://$FUZZ_TARGET/FUZZ" \
    -ac | while IFS= read -r word; do
    [ -z "$word" ] && continue
    echo "$PROTO://$FUZZ_TARGET/$word" >> "$DIRFILE"
done

[ -z "$TARGET_DOM" ] && exit 0

ffuf -s -c -w "$WORDLIST_SUBS" \
    -u "$PROTO://$TARGET_DOM/" \
    -H "Host: FUZZ.$TARGET_DOM" \
    -ac >> "$SUB_TMP" &

tail -f "$SUB_TMP" | while IFS= read -r sub; do
    [ -z "$sub" ] && continue
    FULL_SUB="$sub.$TARGET_DOM"

    if ! grep -q "$FULL_SUB" /etc/hosts; then
        echo "$TARGET_IP  $FULL_SUB" | sudo tee -a /etc/hosts > /dev/null
    fi

    (
        printf "\n=== $PROTO://$FULL_SUB/ ===\n" >> "$DIRFILE"
        ffuf -s -c -w "$WORDLIST_DIRS" \
            -u "$PROTO://$FULL_SUB/FUZZ" \
            -ac | while IFS= read -r path; do
            [ -z "$path" ] && continue
            echo "$PROTO://$FULL_SUB/$path" >> "$DIRFILE"
        done
    ) &
done
FUZZEOF
    chmod +x /tmp/htb_fuzz.sh
}

TmuxInvoke_Linux() {
    SESSION_NAME="htb_scan_linux"

    WriteHelperScript
    bash /tmp/htb_fuzz.sh "$TARGET_DOM" "$TARGET_IP" "$DIRFILE" "$SUB_TMP" "$PROTO" &

    tmux new-session -d -s $SESSION_NAME
    tmux split-window -h -t $SESSION_NAME:0.0
    tmux split-window -h -t $SESSION_NAME:0.1
    tmux split-window -v -t $SESSION_NAME:0.2

    tmux send-keys -t $SESSION_NAME:0.0 "tail -f scan" Enter
    tmux send-keys -t $SESSION_NAME:0.1 "tail -f $DIRFILE" Enter
    tmux send-keys -t $SESSION_NAME:0.2 "curl -k -i $TARGET_IP" Enter
    tmux send-keys -t $SESSION_NAME:0.3 "whatweb $TARGET_IP" Enter
}

TmuxInvoke_Windows() {
    SESSION_NAME="htb_scan_windows"

    WriteHelperScript
    bash /tmp/htb_fuzz.sh "$TARGET_DOM" "$TARGET_IP" "$DIRFILE" "$SUB_TMP" "$PROTO" &

    tmux new-session -d -s $SESSION_NAME
    tmux split-window -h -t $SESSION_NAME:0.0
    tmux split-window -h -t $SESSION_NAME:0.1
    tmux split-window -v -t $SESSION_NAME:0.2

    tmux send-keys -t $SESSION_NAME:0.0 "tail -f scan" Enter
    tmux send-keys -t $SESSION_NAME:0.1 "tail -f $DIRFILE" Enter
    tmux send-keys -t $SESSION_NAME:0.2 "bloodhound-python -u '$User_Windows' -p '$Pass_Windows' -d $TARGET_DOM -c all --zip -ns $TARGET_IP" Enter
    tmux send-keys -t $SESSION_NAME:0.3 "rpcclient -U '$User_Windows'%'$Pass_Windows' $TARGET_IP -c enumdomusers | cut -d '[' -f 2 | cut -d ']' -f 1" Enter

    # Pendiente: nxc smb $TARGET_IP -u "$User_Windows" -p "$Pass_Windows" --shares
}

PingSo() {
    PING_RESULT=$(ping -c 1 $TARGET_IP 2>/dev/null)
    if [ $? -eq 0 ]; then
        TTL=$(echo "$PING_RESULT" | grep -oP 'ttl=\K\d+')
        if [ "$TTL" -eq 64 ] || [ "$TTL" -eq 63 ]; then
            OSType="LINUX"
        elif [ "$TTL" -eq 128 ] || [ "$TTL" -eq 127 ]; then
            OSType="WINDOWS"
        else
            OSType="OTHER"
        fi
    else
        echo "[!] Ha ocurrido un error con el ping"
        return 1
    fi
}

TakingDomain_Linux() {
    LOCATION=$(curl -i -k $TARGET_IP --silent | grep -i "Location:")
    PROTO=$(echo "$LOCATION" | grep -oP 'https?(?=://)')
    TARGET_DOM=$(echo "$LOCATION" | cut -d "/" -f 3 | tr -d '\r\n')
    PROTO="${PROTO:-http}"
    echo "[+] Protocolo detectado: $PROTO"
    echo "[+] El dominio es: ${TARGET_DOM:-'(ninguno detectado, se usará la IP)'}"
    if [ -n "$TARGET_DOM" ]; then
        if grep -q "$TARGET_IP" /etc/hosts; then
            echo "[*] Ya está presente en /etc/hosts"
        else
            echo "$TARGET_IP  $TARGET_DOM" | sudo tee -a /etc/hosts > /dev/null
            echo "[+] Agregado a /etc/hosts"
        fi
    fi
}

TakingDomain_Windows() {
    TARGET_DOM=$(nxc smb $TARGET_IP -u "$User_Windows" -p "$Pass_Windows" | grep "domain" | cut -d ":" -f 3 | cut -d ")" -f 1 | tr -d ' ')
    PROTO="http"
    echo "[+] Comprobando si está correcto..."
    echo "[+] El dominio es: $TARGET_DOM"
    if grep -q "$TARGET_IP" /etc/hosts; then
        echo "[*] Ya está presente en /etc/hosts"
    else
        echo "$TARGET_IP  $TARGET_DOM" | sudo tee -a /etc/hosts > /dev/null
        echo "[+] Agregado a /etc/hosts"
    fi
}

NmapFunction() {
    sudo nmap -sS -sCV -p- --min-rate 5000 -Pn -n --disable-arp-ping --open $TARGET_IP \
        -oN $(pwd)/scan -v 1>/dev/null &
}

Grep_Ports() {
    sudo nmap -F -sS --min-rate 5000 -n -Pn --open $TARGET_IP \
        | grep "tcp" | cut -d "/" -f 1 | grep -Ev "Not|22" > /tmp/ports.log
}

echo ""
echo "[+] Bienvenido al programa de automatización para HTB"
echo "[+] Iniciando reconocimiento de sistema operativo: $TARGET_IP..."

Grep_Ports
PORTS=/tmp/ports.log
NmapFunction
PingSo

echo -e "\t[+] El sistema operativo es: $OSType"

if [ "$OSType" == "LINUX" ]; then
    TakingDomain_Linux
    sleep 3
    TmuxInvoke_Linux

elif [ "$OSType" == "WINDOWS" ]; then
    read -p "Tienes credenciales? [Y/n]: " Respuesta
    if [ "$Respuesta" == "Y" ] || [ "$Respuesta" == "y" ]; then
        read -p "Usuario: " User_Windows
        read -p "Contraseña: " Pass_Windows
        TakingDomain_Windows
        TmuxInvoke_Windows
    elif [ "$Respuesta" == "n" ]; then
        echo "[+] Continuando con escaneo sin credenciales"
        TakingDomain_Linux
        TmuxInvoke_Linux
    else
        echo "[!] Input Incorrecto..."
        sleep 2
        exit 1
    fi
fi

sleep 3
tmux attach-session -t $SESSION_NAME
