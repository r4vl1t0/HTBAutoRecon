#!/bin/bash

echo "[+] Made By: Raulitos"
echo "[+] Github https://github.com/r4vl1t0/HTBAutoRecon"

sudo su -c exit


# Verificar que se proporcione una IP
if [ $# -eq 0 ]; then
    echo "[!] Uso: $0 <IP_TARGET>"
    echo "[!] Ejemplo: $0 10.10.10.1"
    exit 1 #Sale con un error
fi

TARGET_IP=$1

TmuxInvoke_Windows() {

        # Crear nueva sesión tmux
        SESSION_NAME="htb_scan_windows"
        tmux new-session -d -s $SESSION_NAME
        
        # Dividir la pantalla horizontalmente
        tmux split-window -h -t $SESSION_NAME
        tmux split-window -h -t $SESSION_NAME
        tmux split-window -v -t $SESSION_NAME
    
        #rpcclient
        tmux send-keys -t $SESSION_NAME:0.1 "rpcclient -U '$User_Windows'%'$Pass_Windows' $TARGET_IP -c enumdomusers | cut -d "[" -f 2 | cut -d "]" -f 1" Enter
        
        # Cambiar al panel izquierdo para el escaneo    
        tmux select-pane -t $SESSION_NAME:0.0
        
        # nmap scan
        tmux send-keys -t $SESSION_NAME:0.0 "tail -f scan" Enter
        
        # nxc smb shares
        tmux send-keys -t $SESSION_NAME:0.2 "nxc smb $TARGET_IP -u '$User_Windows' -p '$Pass_Windows' --shares" Enter

        # bloodhound
        tmux send-keys -t $SESSION_NAME:0.3 "bloodhound-python -u '$User_Windows' -p '$Pass_Windows' -d $TARGET_DOM -c all --zip -ns $TARGET_IP" Enter

}

# agregar si no hay puerto 80 - buscar otro puerto  - grepear el nmap para hacerle whhatweb
TmuxInvoke_Linux() {

        # Crear nueva sesión tmux
        SESSION_NAME="htb_scan_linux"
        tmux new-session -d -s $SESSION_NAME
        
        # Dividir la pantalla horizontalmente
        tmux split-window -h -t $SESSION_NAME
        tmux split-window -h -t $SESSION_NAME
        tmux split-window -v -t $SESSION_NAME
        tmux select-pane -t $SESSION_NAME:0.1
        tmux split-window -v -t $SESSION_NAME

        tmux send-keys -t $SESSION_NAME:0.2 "ffuf -c -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -u 'http://$TARGET_DOM/' -H 'Host: FUZZ.$TARGET_DOM' -ac" Enter
                
        # Cambiar al panel izquierdo para el escaneo    
        tmux select-pane -t $SESSION_NAME:0.0
        
        # Script para ejecutar dentro de tmux
        tmux send-keys -t $SESSION_NAME:0.0 "tail -f scan" Enter
        tmux send-keys -t $SESSION_NAME:0.1 "dirsearch -u http://$TARGET_DOM/ -F -f -x 404" Enter
        tmux send-keys -t $SESSION_NAME:0.3 "curl -k -i $TARGET_IP" Enter     
        tmux send-keys -t $SESSION_NAME:0.4 "whatweb $TARGET_IP" Enter
        

}

echo ""
echo "[+] Bienvenido al programa de automatización para HTB"
echo "[+] Iniciando reconocimiento de sistema operativo: $TARGET_IP..."

# !!!!! hacerlo repetitivo por errores
PingSo () {
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
        echo "[!] Ha ocurrido un error"
        return 1
    fi
}

TakingDomain_Linux(){
    TARGET_DOM=$(curl -i -k $TARGET_IP --silent | grep "Location" | cut -d "/" -f 3 | tr -d '\r\n')
    echo "[+] El dominio es: $TARGET_DOM"
    CHECKER_DOM=$(echo "$TARGET_IP")

    if grep -q "$CHECKER_DOM" /etc/hosts; then
        echo "[*] Ya está presente en /etc/hosts"
    else
        echo "$CHECKER_DOM  $TARGET_DOM" | sudo tee -a /etc/hosts > /dev/null
        echo "[+] Agregado a /etc/hosts"
    fi     
}

TakingDomain_Windows(){
    TARGET_DOM=$(nxc smb $TARGET_IP -u "$User_Windows" -p "$Pass_Windows" | cut -d "/" -f 2 | grep "domain" | cut -d ":" -f 3 | cut -d ")" -f 1)
    echo "[+] Comprobando si está correcto..."
    echo "[+] El dominio es: $TARGET_DOM"
    
    CHECKER_DOM=$(echo "$TARGET_IP")

    if grep -q "$CHECKER_DOM" /etc/hosts; then
        echo "[*] Ya está presente en /etc/hosts"
    else
        echo "$CHECKER_DOM  $TARGET_DOM" |  sudo tee -a /etc/hosts > /dev/null
        echo "[+] Agregado a /etc/hosts"
    fi   
}

# --script vuln
NmapFunction(){
     sudo nmap -sS -sCV -p- --min-rate 5000 -Pn -n --disable-arp-ping --open $TARGET_IP -oN $(pwd)/scan -v 1>/dev/null &
}

Grep_Ports(){
    PORTS1=$(sudo nmap -F -sS --min-rate 5000 -n -Pn --open $TARGET_IP | grep "tcp" | cut -d "/" -f 1 | grep -Ev "Not|22" > /tmp/ports.log)
}

Grep_Ports
PORTS=/tmp/ports.log
NmapFunction
PingSo
 
echo -e  "\t[+] El sistema operativo es: $OSType"

if [ "$OSType" == "LINUX" ]; then
    TakingDomain_Linux
    sleep 3

    TmuxInvoke_Linux

elif [ "$OSType" == "WINDOWS" ];then
    read -p "Tienes credenciales? [Y/n]: " Respuesta

    if [ "$Respuesta" == "Y" ] || [ $Respuesta == "y" ]; then
        read -p "Usuario:" User_Windows
        read -p "Contraseña:" Pass_Windows

        TakingDomain_Windows

        TmuxInvoke_Windows 

    elif [ "$Respuesta" == "n" ]; then
        echo "[+] Continuando con escaneo"
        TakingDomain_Linux
        TmuxInvoke_Linux

    else
        echo "[!] Input Incorrecto... "
        sleep 2
        exit 1
    fi

fi

sleep 3
tmux attach-session -t $SESSION_NAME

