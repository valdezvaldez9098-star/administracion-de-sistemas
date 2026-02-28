#!/bin/bash
# ==============================================
#        DHCP AUTOMATIZADO - RED_SISTEMAS
#        Linux Devuan Daedalus
#        CON DNS PRIMARIO Y SECUNDARIO
# ==============================================

ADAPTADOR="eth1"
CONFIG_FILE="/etc/dhcp/dhcpd.conf"
DEFAULT_FILE="/etc/default/isc-dhcp-server"
LEASES_FILE="/var/lib/dhcp/dhcpd.leases"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ---------------- FUNCIONES AUXILIARES ----------------

function pause {
    echo ""
    read -p "Presiona ENTER para continuar"
}

function mostrar_error {
    echo -e "${RED}ERROR: $1${NC}"
}

function mostrar_exito {
    echo -e "${GREEN}$1${NC}"
}

function mostrar_info {
    echo -e "${YELLOW}$1${NC}"
}

# ---------------- VALIDACIONES ----------------

function validar_ip {
    local ip=$1
    local IFS='.'
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local octetos=($ip)
        for octeto in "${octetos[@]}"; do
            if [[ $octeto -gt 255 ]]; then
                return 1
            fi
        done
        if [[ $ip == "0.0.0.0" ]] || [[ $ip == 127.* ]]; then
            return 1
        fi
        return 0
    fi
    return 1
}

function obtener_mascara_sugerida {
    local ip=$1
    local primer_octeto=$(echo $ip | cut -d. -f1)
    
    if [[ $primer_octeto -ge 1 && $primer_octeto -le 126 ]]; then
        echo "255.0.0.0"
    elif [[ $primer_octeto -ge 128 && $primer_octeto -le 191 ]]; then
        echo "255.255.0.0"
    elif [[ $primer_octeto -ge 192 && $primer_octeto -le 223 ]]; then
        echo "255.255.255.0"
    else
        echo "255.255.255.0"
    fi
}

function calcular_prefijo {
    local mascara=$1
    
    case $mascara in
        "255.0.0.0") echo "8" ;;
        "255.255.0.0") echo "16" ;;
        "255.255.255.0") echo "24" ;;
        *) echo "24" ;;
    esac
}

# ---------------- VERIFICAR DEPENDENCIAS ----------------

function verificar_dependencias {
    mostrar_info "Verificando dependencias..."
    
    # Verificar e instalar ifupdown si es necesario
    if ! command -v ifup &> /dev/null; then
        mostrar_info "Instalando ifupdown..."
        apt-get update
        apt-get install -y ifupdown
    fi
    
    # Verificar e instalar isc-dhcp-server si es necesario
    if ! command -v dhcpd &> /dev/null; then
        mostrar_info "Instalando isc-dhcp-server..."
        apt-get update
        apt-get install -y isc-dhcp-server
        
        # Buscar dónde se instaló dhcpd
        if command -v dhcpd &> /dev/null; then
            mostrar_exito "dhcpd encontrado en $(which dhcpd)"
        else
            # Buscar en ubicaciones comunes
            if [[ -f /usr/sbin/dhcpd ]]; then
                mostrar_info "dhcpd encontrado en /usr/sbin/dhcpd"
                # Crear enlace simbólico si es necesario
                ln -sf /usr/sbin/dhcpd /usr/bin/dhcpd 2>/dev/null
            elif [[ -f /usr/local/sbin/dhcpd ]]; then
                mostrar_info "dhcpd encontrado en /usr/local/sbin/dhcpd"
                ln -sf /usr/local/sbin/dhcpd /usr/bin/dhcpd 2>/dev/null
            else
                mostrar_error "No se pudo encontrar dhcpd después de la instalación"
            fi
        fi
    fi
    
    # Verificar que el comando dhcpd esté disponible
    if ! command -v dhcpd &> /dev/null; then
        # Añadir /usr/sbin al PATH si es necesario
        export PATH=$PATH:/usr/sbin:/usr/local/sbin
        if ! command -v dhcpd &> /dev/null; then
            mostrar_error "dhcpd no está disponible después de la instalación"
        else
            mostrar_exito "dhcpd encontrado después de añadir al PATH"
        fi
    fi
    
    mostrar_exito "Dependencias verificadas"
}

# ---------------- ESTADO ----------------

function estado_dhcp {
    mostrar_info "===== ESTADO DHCP ====="
    echo ""
    
    # Verificar si está instalado
    if dpkg -l | grep -q "isc-dhcp-server"; then
        mostrar_exito "Paquete DHCP: INSTALADO"
    else
        mostrar_error "Paquete DHCP: NO instalado"
    fi
    
    # Verificar servicio
    if systemctl is-active --quiet isc-dhcp-server 2>/dev/null; then
        mostrar_exito "Servicio DHCP: ACTIVO"
    elif /etc/init.d/isc-dhcp-server status | grep -q "running"; then
        mostrar_exito "Servicio DHCP: ACTIVO (sysvinit)"
    else
        mostrar_error "Servicio DHCP: INACTIVO"
    fi
    
    # Verificar adaptador
    if ip link show $ADAPTADOR &>/dev/null; then
        local estado=$(ip link show $ADAPTADOR | grep -o "state [^ ]*" | cut -d' ' -f2)
        mostrar_exito "Adaptador $ADAPTADOR: $estado"
        
        # Mostrar IP actual
        local ip_actual=$(ip addr show $ADAPTADOR | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        if [[ -n $ip_actual ]]; then
            echo "IP actual: $ip_actual"
        fi
    else
        mostrar_error "Adaptador $ADAPTADOR no encontrado"
    fi
    
    pause
}

# ---------------- INSTALAR ----------------

function instalar_dhcp {
    mostrar_info "===== INSTALAR / REINSTALAR DHCP ====="
    
    # Primero verificar dependencias
    verificar_dependencias
    
    # Verificar si ya está instalado
    if dpkg -l | grep -q "isc-dhcp-server"; then
        read -p "DHCP ya está instalado. ¿Reinstalar? (s/n): " resp
        if [[ $resp == "s" || $resp == "S" ]]; then
            systemctl stop isc-dhcp-server 2>/dev/null || /etc/init.d/isc-dhcp-server stop
            apt-get remove --purge -y isc-dhcp-server
            apt-get install -y isc-dhcp-server
        else
            return
        fi
    else
        apt-get update
        apt-get install -y isc-dhcp-server
    fi
    
    # Configurar adaptador en archivo por defecto
    echo "INTERFACESv4=\"$ADAPTADOR\"" > $DEFAULT_FILE
    echo "INTERFACESv6=\"\"" >> $DEFAULT_FILE
    
    systemctl restart isc-dhcp-server 2>/dev/null || /etc/init.d/isc-dhcp-server restart
    
    mostrar_exito "DHCP instalado correctamente."
    pause
}

# ---------------- CONFIGURAR ----------------

function configurar_dhcp {
    mostrar_info "===== CONFIGURAR DHCP ====="
    
    # Verificar dependencias antes de configurar
    verificar_dependencias
    
    # Verificar que el comando dhcpd existe
    DHCPD_CMD=""
    if command -v dhcpd &> /dev/null; then
        DHCPD_CMD=$(command -v dhcpd)
    elif [[ -f /usr/sbin/dhcpd ]]; then
        DHCPD_CMD="/usr/sbin/dhcpd"
    elif [[ -f /usr/local/sbin/dhcpd ]]; then
        DHCPD_CMD="/usr/local/sbin/dhcpd"
    else
        mostrar_error "No se encuentra el comando dhcpd. Asegúrate de que isc-dhcp-server esté instalado."
        pause
        return
    fi
    
    # Solicitar parámetros
    read -p "Nombre del Scope: " SCOPE_NAME
    
    while true; do
        read -p "IP inicial (sera IP del servidor): " IP_INICIO
        if validar_ip $IP_INICIO; then
            break
        fi
        mostrar_error "IP invalida"
    done
    
    while true; do
        read -p "IP final del rango: " IP_FIN
        if validar_ip $IP_FIN; then
            break
        fi
        mostrar_error "IP invalida"
    done
    
    local MASCARA_SUGERIDA=$(obtener_mascara_sugerida $IP_INICIO)
    read -p "Mascara de red (Enter=$MASCARA_SUGERIDA): " MASCARA
    if [[ -z $MASCARA ]]; then
        MASCARA=$MASCARA_SUGERIDA
    fi
    
    read -p "Gateway (opcional, Enter vacio): " GATEWAY
    read -p "Tiempo de concesion (segundos): " LEASE
    
    # SOLICITAR DNS PRIMARIO Y SECUNDARIO
    echo ""
    mostrar_info "--- CONFIGURACION DE DNS ---"
    
    while true; do
        read -p "DNS Primario (obligatorio): " DNS_PRIMARIO
        if validar_ip $DNS_PRIMARIO; then
            break
        fi
        mostrar_error "IP invalida"
    done
    
    read -p "DNS Secundario (opcional, Enter vacio): " DNS_SECUNDARIO
    if [[ -z $DNS_SECUNDARIO ]]; then
        DNS_SECUNDARIO=""
        echo "DNS Secundario no configurado"
    else
        while true; do
            if validar_ip $DNS_SECUNDARIO; then
                break
            fi
            mostrar_error "IP invalida para DNS Secundario"
            read -p "DNS Secundario (opcional, Enter vacio): " DNS_SECUNDARIO
            if [[ -z $DNS_SECUNDARIO ]]; then
                DNS_SECUNDARIO=""
                break
            fi
        done
    fi
    
    # Configurar IP fija
    mostrar_info "Configurando IP fija al servidor..."
    
    # Calcular prefijo desde máscara
    local PREFIJO=$(calcular_prefijo $MASCARA)
    
    # Configurar IP estática en Devuan
    cat > /etc/network/interfaces.d/$ADAPTADOR << EOF
auto $ADAPTADOR
iface $ADAPTADOR inet static
    address $IP_INICIO
    netmask $MASCARA
EOF
    
    if [[ -n $GATEWAY ]]; then
        echo "    gateway $GATEWAY" >> /etc/network/interfaces.d/$ADAPTADOR
    fi
    
    # Aplicar configuración de red usando ip en lugar de ifup/ifdown
    mostrar_info "Aplicando configuración de red..."
    ip addr flush dev $ADAPTADOR
    ip addr add $IP_INICIO/$PREFIJO dev $ADAPTADOR
    ip link set $ADAPTADOR up
    
    # Configurar gateway si existe
    if [[ -n $GATEWAY ]]; then
        ip route add default via $GATEWAY dev $ADAPTADOR 2>/dev/null || true
    fi
    
    # Configurar DNS del servidor
    cat > /etc/resolv.conf << EOF
nameserver $DNS_PRIMARIO
EOF
    
    if [[ -n $DNS_SECUNDARIO ]]; then
        echo "nameserver $DNS_SECUNDARIO" >> /etc/resolv.conf
    fi
    
    mostrar_exito "DNS configurado: Primario=$DNS_PRIMARIO, Secundario=$DNS_SECUNDARIO"
    
    # Calcular rango (IP inicial +1 hasta IP final)
    local octetos=(${IP_INICIO//./ })
    local ultimo_octeto=$((octetos[3] + 1))
    local RANGO_INICIO="${octetos[0]}.${octetos[1]}.${octetos[2]}.$ultimo_octeto"
    
    # CALCULAR SUBNET CORRECTA SEGÚN LA MÁSCARA
    local SUBNET=""
    case $MASCARA in
        "255.0.0.0")
            SUBNET="${octetos[0]}.0.0.0"
            ;;
        "255.255.0.0")
            SUBNET="${octetos[0]}.${octetos[1]}.0.0"
            ;;
        "255.255.255.0")
            SUBNET="${octetos[0]}.${octetos[1]}.${octetos[2]}.0"
            ;;
        *)
            SUBNET="${octetos[0]}.${octetos[1]}.${octetos[2]}.0"
            ;;
    esac
    
    # Crear archivo de configuración DHCP
    cat > $CONFIG_FILE << EOF
# Configuracion DHCP para $SCOPE_NAME
# Generado automaticamente

option subnet-mask $MASCARA;
option broadcast-address ${octetos[0]}.${octetos[1]}.${octetos[2]}.255;

default-lease-time $LEASE;
max-lease-time $((LEASE * 2));

authoritative;

subnet $SUBNET netmask $MASCARA {
    range $RANGO_INICIO $IP_FIN;
    
EOF
    
    # Agregar gateway si existe
    if [[ -n $GATEWAY ]]; then
        echo "    option routers $GATEWAY;" >> $CONFIG_FILE
    fi
    
    # Agregar DNS primario
    echo "    option domain-name-servers $DNS_PRIMARIO;" >> $CONFIG_FILE
    
    # Agregar DNS secundario si existe
    if [[ -n $DNS_SECUNDARIO ]]; then
        sed -i "s/option domain-name-servers.*/option domain-name-servers $DNS_PRIMARIO, $DNS_SECUNDARIO;/" $CONFIG_FILE
    fi
    
    echo "}" >> $CONFIG_FILE
    
    # Verificar configuración
    mostrar_info "Verificando configuración con $DHCPD_CMD..."
    if $DHCPD_CMD -t -cf $CONFIG_FILE 2>&1; then
        mostrar_exito "Configuración DHCP válida"
        
        # Reiniciar servicio
        systemctl restart isc-dhcp-server 2>/dev/null || /etc/init.d/isc-dhcp-server restart
        
        mostrar_exito ""
        mostrar_exito "========================================="
        mostrar_exito "DHCP configurado correctamente."
        mostrar_exito "========================================="
        echo ""
        echo "Resumen de configuracion:"
        echo "-------------------------"
        echo "IP Servidor: $IP_INICIO"
        echo "Mascara: $MASCARA"
        echo "Rango DHCP: $RANGO_INICIO - $IP_FIN"
        echo "Gateway: ${GATEWAY:-No configurado}"
        echo "DNS Primario: $DNS_PRIMARIO"
        echo "DNS Secundario: ${DNS_SECUNDARIO:-No configurado}"
        echo "Tiempo concesion: $LEASE segundos"
    else
        mostrar_error "Error en la configuración DHCP"
        $DHCPD_CMD -t -cf $CONFIG_FILE
    fi
    
    pause
}

# ---------------- MONITOREO ----------------

function monitorear_dhcp {
    mostrar_info "===== MONITOREO DHCP ====="
    
    # Iniciar servicio si no está activo
    if ! systemctl is-active --quiet isc-dhcp-server 2>/dev/null && \
       ! /etc/init.d/isc-dhcp-server status | grep -q "running"; then
        systemctl start isc-dhcp-server 2>/dev/null || /etc/init.d/isc-dhcp-server start
    fi
    
    # Mostrar scopes activos
    echo ""
    echo "Scopes configurados:"
    echo "--------------------"
    if [[ -f $CONFIG_FILE ]]; then
        grep -A10 "subnet" $CONFIG_FILE | grep -v "^#" | head -20
    else
        echo "No hay scopes configurados."
    fi
    
    # Mostrar opciones DNS configuradas
    echo ""
    echo "Opciones de DNS configuradas:"
    echo "------------------------------"
    if [[ -f $CONFIG_FILE ]]; then
        local dns_line=$(grep "domain-name-servers" $CONFIG_FILE | grep -v "^#")
        if [[ -n $dns_line ]]; then
            echo $dns_line
        else
            echo "No hay servidores DNS configurados"
        fi
    else
        echo "No hay servidores DNS configurados"
    fi
    
    # Mostrar concesiones activas
    echo ""
    echo "Concesiones activas:"
    echo "---------------------"
    if [[ -f $LEASES_FILE ]]; then
        grep -B1 -A5 "binding state active" $LEASES_FILE | head -20
    else
        echo "No hay concesiones activas"
    fi
    
    pause
}

# ---------------- MENU PRINCIPAL ----------------

# Verificar dependencias al iniciar el script
verificar_dependencias

while true; do
    clear
    echo "====== MENU DHCP (Linux Devuan Daedalus) ======"
    echo "Adaptador: $ADAPTADOR"
    echo ""
    echo "1) Ver estado del servicio"
    echo "2) Instalar / Reinstalar DHCP"
    echo "3) Configurar DHCP"
    echo "4) Monitorear"
    echo "5) Salir"
    echo ""
    read -p "Opcion: " opcion
    
    case $opcion in
        1) estado_dhcp ;;
        2) instalar_dhcp ;;
        3) configurar_dhcp ;;
        4) monitorear_dhcp ;;
        5) exit 0 ;;
        *) 
            mostrar_error "Opcion invalida"
            pause
            ;;
    esac
done