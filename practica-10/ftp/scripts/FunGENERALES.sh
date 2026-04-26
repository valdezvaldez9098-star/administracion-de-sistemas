#!/bin/bash
# FunGENERALES.sh — Adaptado para Devuan Daedalus 5.0.1 (SysVinit, sin systemd)

INTERFAZ="eth0"
MASCARA="255.255.255.0"
GENERAL="/var/ftp/publico"
USUARIOS="/var/ftp/usuarios"
FTP_ROOT="/var/ftp"

pause(){
    echo ""
    read -p "Presione ENTER para continuar..." temp
}

VerificarRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo "Este script debe ejecutarse como root"
        exit 1
    fi
}

InstalarPaquete() {
    local paquete=$1
    read -p "¿Deseas instalarlo? (S/N): " r
    if [[ $r =~ ^[sS]$ ]]; then
        echo "Instalando paquete: '$paquete'"
        apt-get update -y -qq > /dev/null 2>&1
        apt-get install -y -qq "$paquete" > /dev/null 2>&1
        echo "Instalación finalizada"
    fi
}

VerificarPaquete() {
    local paquete=$1
    if dpkg -l | grep -q "^ii.*$paquete"; then
        echo "'$paquete' ya está instalado"
        read -p "¿Deseas reinstalarlo? (S/N): " r
        if [[ $r =~ ^[sS]$ ]]; then
            InstalarPaquete "$paquete"
        fi
    else
        echo "El servicio '$paquete' no está instalado"
    fi
}

DesinstalarPaquete() {
    local paquete="$1"
    if [ "$(dpkg -l "$paquete" 2>/dev/null | grep '^ii')" = "" ]; then
        echo "No se ha detectado el servicio $paquete"
    else
        echo "Se ha detectado el servicio $paquete"
        read -p "¿Desea desinstalarlo? (s/n): " confirmacion
        if [[ "$confirmacion" =~ ^[sS]$ ]]; then
            echo "Desinstalando..."
            apt-get remove -y --purge "$paquete" > /dev/null 2>&1
            echo "Se ha desinstalado el servicio $paquete"
        else
            echo "Desinstalación cancelada."
        fi
    fi
}

# Devuan usa /etc/init.d/ en lugar de systemctl
EstadoPaquete() {
    local servicio="$1"
    if [ -f "/etc/init.d/$servicio" ]; then
        echo -e "\n=== Estado del servicio $servicio ===\n"
        /etc/init.d/"$servicio" status 2>&1 | head -n 12
    else
        # Fallback: buscar proceso corriendo
        if pgrep -x "$servicio" > /dev/null 2>&1; then
            echo -e "\nServicio $servicio está corriendo (PID: $(pgrep -x "$servicio"))"
        else
            echo -e "\nNo se ha detectado el servicio $servicio corriendo"
        fi
    fi
}

# En Devuan/contenedor vsftpd se maneja directo con pkill + vsftpd
ReiniciarPaquete() {
    local servicio="$1"
    if [ "$(dpkg -l "$servicio" 2>&1 | grep 'ii')" = "" ]; then
        echo -e "\nNo se ha detectado el servicio $servicio"
    else
        echo "Reiniciando servicio $servicio..."
        if [ -f "/etc/init.d/$servicio" ]; then
            /etc/init.d/"$servicio" restart 2>/dev/null || true
        else
            pkill "$servicio" 2>/dev/null; sleep 1
            "$servicio" /etc/"$servicio".conf &
        fi
        echo "$servicio reiniciado."
    fi
}

ValidarIp() {
    local ip=$1
    if [[ $ip =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$ ]]; then
        [[ "$ip" != "255.255.255.255" && "$ip" != "0.0.0.0" && "$ip" != "127.0.0.1" ]]
        return $?
    fi
    return 1
}

IPaInt() {
    local IFS=.
    read -r a b c d <<< "$1"
    echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

PedirIp() {
    local mensaje=$1
    while true; do
        read -p "$mensaje" ip
        if ValidarIp "$ip"; then
            echo "$ip"
            return
        else
            echo "IP no válida, intenta de nuevo"
        fi
    done
}

CalcularMascara() {
    local ip=$1
    local IFS=.
    read -r a b c d <<< "$ip"
    if (( a >= 1 && a <= 126 )); then
        echo "255.0.0.0"
    elif (( a >= 128 && a <= 191 )); then
        echo "255.255.0.0"
    elif (( a >= 192 && a <= 223 )); then
        echo "255.255.255.0"
    else
        echo "255.255.255.0"
    fi
}

MaskToPrefix() {
    case "$1" in
        255.0.0.0)       echo 8  ;;
        255.255.0.0)     echo 16 ;;
        255.255.255.0)   echo 24 ;;
        255.255.255.128) echo 25 ;;
        255.255.255.192) echo 26 ;;
        255.255.255.224) echo 27 ;;
        255.255.255.240) echo 28 ;;
        255.255.255.248) echo 29 ;;
        255.255.255.252) echo 30 ;;
        255.255.255.254) echo 31 ;;
        255.255.255.255) echo 32 ;;
        *)               echo 0  ;;
    esac
}

CampoRequerido() {
    local patron='\S+'
    if ! [[ "$1" =~ $patron ]]; then
        echo "El campo no puede estar vacío (${2:-campo desconocido}), abortando..."
        exit 1
    fi
}

CampoEntero() {
    local patron='^[0-9]+$'
    if ! [[ "$1" =~ $patron ]]; then
        echo "Se esperaba un número entero positivo (${2:-campo desconocido}), abortando..."
        exit 1
    fi
}

FormatoIpValido() {
    local patron='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    if ! [[ "$1" =~ $patron ]]; then
        echo "Formato IPv4 incorrecto (${2:-ip}), abortando..."
        exit 1
    fi
}

RestringirOctetos() {
    IFS='.' read -ra _oct <<< "$1"
    if [ "${_oct[0]}" -eq 0 ]; then
        echo "El primer octeto no puede ser 0, abortando..."; exit 1
    elif [ "${_oct[0]}" -eq 127 ]; then
        echo "El primer octeto no puede ser 127 (loopback), abortando..."; exit 1
    elif [ "${_oct[0]}" -eq 255 ]; then
        echo "El primer octeto no puede ser 255, abortando..."; exit 1
    fi
}

ValidarIpCompleta() {
    if [ "$3" = "true" ] && [ "$1" = "" ]; then return 1; fi
    FormatoIpValido "$1" "$2"
    RestringirOctetos "$1"
}

ObtenerSegmento() {
    IFS='.' read -ra _oct <<< "$1"
    if   [ "${_oct[0]}" -ge 1   ] && [ "${_oct[0]}" -le 126 ]; then echo "${_oct[0]}.0.0.0"
    elif [ "${_oct[0]}" -ge 128 ] && [ "${_oct[0]}" -le 191 ]; then echo "${_oct[0]}.${_oct[1]}.0.0"
    elif [ "${_oct[0]}" -ge 192 ] && [ "${_oct[0]}" -le 223 ]; then echo "${_oct[0]}.${_oct[1]}.${_oct[2]}.0"
    else echo "0.0.0.0"; fi
}

ObtenerMascara() {
    IFS='.' read -ra _oct <<< "$1"
    if   [ "${_oct[0]}" -ge 1   ] && [ "${_oct[0]}" -le 126 ]; then echo "255.0.0.0"
    elif [ "${_oct[0]}" -ge 128 ] && [ "${_oct[0]}" -le 191 ]; then echo "255.255.0.0"
    elif [ "${_oct[0]}" -ge 192 ] && [ "${_oct[0]}" -le 223 ]; then echo "255.255.255.0"
    else echo "255.255.255.255"; fi
}

IpAEntero() {
    IFS='.' read -ra _oct <<< "$1"
    echo $(( ${_oct[0]}*16777216 + ${_oct[1]}*65536 + ${_oct[2]}*256 + ${_oct[3]} ))
}

CompararIps() {
    if [ "$1" -gt "$2" ]; then echo "true"; else echo "false"; fi
}

IncrementarIp() {
    IFS='.' read -ra _oct <<< "$1"
    _oct[3]=$(( ${_oct[3]} + 1 ))
    if [ "${_oct[3]}" -ge 256 ]; then _oct[3]=0; _oct[2]=$(( ${_oct[2]} + 1 )); fi
    if [ "${_oct[2]}" -ge 256 ]; then _oct[2]=0; _oct[1]=$(( ${_oct[1]} + 1 )); fi
    if [ "${_oct[1]}" -ge 256 ]; then _oct[1]=0; _oct[0]=$(( ${_oct[0]} + 1 )); fi
    echo "${_oct[0]}.${_oct[1]}.${_oct[2]}.${_oct[3]}"
}

ValidarArregloLleno() {
    local _arr=("$@")
    local _i=0
    local _total=${#_arr[@]}
    while [ "$_i" -lt "$_total" ]; do
        if [ -z "${_arr[$_i]}" ]; then
            echo "Se encontró un valor vacío dentro del listado, abortando..."; exit 1
        fi
        ((_i++))
    done
}

ValidarUsuarioNuevo() {
    local _arr=("$@")
    local _i=0
    local _total=${#_arr[@]}
    while [ "$_i" -lt "$_total" ]; do
        if grep -q "^${_arr[$_i]}:" /etc/passwd; then
            echo "El usuario '${_arr[$_i]}' ya existe en el sistema, abortando..."; exit 1
        fi
        ((_i++))
    done
}
