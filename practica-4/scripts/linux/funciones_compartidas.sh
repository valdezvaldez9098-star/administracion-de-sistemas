#!/bin/bash
# ==============================================================================
# FUNCIONES COMPARTIDAS - VERSION FINAL (SIN RESTRICCION DE RED)
# ==============================================================================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# =========================
# VARIABLES GLOBALES
# =========================
INTERFACE=""
IPS_VIRTUALES=()

# =========================
# FUNCIONES DE VALIDACION
# =========================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        echo -e "${RED}  ✗ ERROR: ESTE SCRIPT DEBE EJECUTARSE COMO ROOT  ✗${NC}"
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        exit 1
    fi
}

validar_ip_sintaxis() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        set -- $ip
        if [ $1 -le 255 ] && [ $2 -le 255 ] && [ $3 -le 255 ] && [ $4 -le 255 ]; then
            return 0
        fi
    fi
    return 1
}

es_ip_prohibida() {
    local ip=$1
    if [[ "$ip" == "0.0.0.0" ]] || [[ "$ip" == "255.255.255.255" ]]; then return 0; fi
    if [[ "$ip" == 127.* ]]; then return 0; fi
    local first_octet=$(echo $ip | cut -d'.' -f1)
    if (( first_octet >= 224 )); then return 0; fi
    return 1
}

validar_ip_completa() {
    local ip=$1
    if validar_ip_sintaxis "$ip"; then
        if ! es_ip_prohibida "$ip"; then
            return 0
        else
            return 2
        fi
    else
        return 1
    fi
}

# =========================
# FUNCIONES DE RED
# =========================

seleccionar_interfaz() {
    clear
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}         SELECCIÓN DE INTERFAZ DE RED         ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}INTERFACES DISPONIBLES:${NC}"
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
    echo "$interfaces" | while read iface; do
        echo -e "  ${GREEN}▶${NC} ${WHITE}$iface${NC}"
    done
    
    echo ""
    read -p " $(echo -e ${YELLOW}▶${NC} ${WHITE}NOMBRE DE LA INTERFAZ:${NC} ) " INTERFACE

    if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        echo -e "${RED}  ✗ ERROR: LA INTERFAZ $INTERFACE NO EXISTE  ✗${NC}"
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ TRABAJANDO SOBRE: ${CYAN}$INTERFACE${NC}"
    sleep 1
}

obtener_ip_actual() {
    ip -4 addr show $INTERFACE 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1
}

activar_interfaces_red() {
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}         ACTIVANDO INTERFACES DE RED         ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    for iface in eth1 eth2; do
        if ip link show $iface > /dev/null 2>&1; then
            echo -e " ${YELLOW}▶${NC} ${WHITE}ACTIVANDO ${CYAN}$iface${WHITE}...${NC}"
            ip link set $iface up
            echo -e "   ${GREEN}✓ $iface ACTIVADA${NC}"
        fi
    done
    
    echo ""
    echo -e "${CYAN}ESTADO ACTUAL DE INTERFACES:${NC}"
    ip addr show | grep -E "^[0-9]+:" | while read line; do
        echo -e "  ${GREEN}▶${NC} $line"
    done
}

configurar_firewall_ping() {
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}         CONFIGURANDO FIREWALL PARA PING         ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    if ! command -v iptables >/dev/null 2>&1; then
        echo -e " ${YELLOW}⚠ INSTALANDO IPTABLES...${NC}"
        apt-get install -y iptables > /dev/null 2>&1
        echo -e "   ${GREEN}✓ IPTABLES INSTALADO${NC}"
    fi
    
    iptables -A INPUT -i $INTERFACE -p icmp --icmp-type echo-request -j ACCEPT > /dev/null 2>&1
    iptables -A OUTPUT -o $INTERFACE -p icmp --icmp-type echo-reply -j ACCEPT > /dev/null 2>&1
    
    echo -e " ${GREEN}✓ REGLAS ICMP APLICADAS${NC}"
}

# =========================
# FUNCIONES DE IP VIRTUAL
# =========================

crear_ip_virtual() {
    local ip=$1
    local interfaz=$2
    
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         VERIFICANDO IP VIRTUAL: ${WHITE}$ip${CYAN}         ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    
    if ip addr show $interfaz | grep -q "$ip"; then
        echo -e " ${YELLOW}⚠${NC} ${WHITE}LA IP ${CYAN}$ip${WHITE} YA ESTÁ CONFIGURADA EN ${CYAN}$interfaz${NC}"
        return 0
    fi
    
    local ip_principal=$(obtener_ip_actual)
    if [ "$ip" == "$ip_principal" ]; then
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        echo -e "${RED}  ✗ ERROR: NO PUEDES USAR LA IP PRINCIPAL COMO VIRTUAL  ✗${NC}"
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        return 1
    fi
    
    echo -e " ${YELLOW}▶${NC} ${WHITE}CREANDO IP VIRTUAL: ${CYAN}$ip${WHITE} EN ${CYAN}$interfaz${WHITE}...${NC}"
    
    if ip addr add $ip/24 dev $interfaz; then
        sleep 1
        if ip addr show $interfaz | grep -q "$ip"; then
            echo -e " ${GREEN}✓${NC} ${WHITE}IP VIRTUAL ${CYAN}$ip${WHITE} CREADA EXITOSAMENTE${NC}"
            
            local config_file="/etc/network/interfaces"
            
            if ! grep -q "up ip addr add $ip/24 dev $interfaz" "$config_file" 2>/dev/null; then
                echo "    up ip addr add $ip/24 dev $interfaz" >> "$config_file"
                echo "    down ip addr del $ip/24 dev $interfaz" >> "$config_file"
            fi
            
            IPS_VIRTUALES+=("$ip")
            
            echo ""
            echo -e "${CYAN}ESTADO ACTUAL DE $interfaz:${NC}"
            ip addr show $interfaz | grep "inet" | while read line; do
                echo -e "  ${GREEN}▶${NC} $line"
            done
            
            return 0
        else
            echo -e "${RED}══════════════════════════════════════════════════${NC}"
            echo -e "${RED}  ✗ ERROR: LA IP $ip NO APARECE DESPUÉS DE CREARLA  ✗${NC}"
            echo -e "${RED}══════════════════════════════════════════════════${NC}"
            return 1
        fi
    else
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        echo -e "${RED}  ✗ ERROR AL EJECUTAR COMANDO IP ADDR ADD  ✗${NC}"
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        return 1
    fi
}

eliminar_ip_virtual() {
    local ip=$1
    local interfaz=$2
    
    echo -e "${RED}══════════════════════════════════════════════════${NC}"
    echo -e "${RED}         ELIMINANDO IP VIRTUAL: ${WHITE}$ip${RED}         ${NC}"
    echo -e "${RED}══════════════════════════════════════════════════${NC}"
    
    if ip addr show $interfaz | grep -q "$ip"; then
        echo -e " ${YELLOW}▶${NC} ${WHITE}ELIMINANDO IP VIRTUAL: ${CYAN}$ip${WHITE} DE ${CYAN}$interfaz${WHITE}...${NC}"
        
        if ip addr del $ip/24 dev $interfaz; then
            echo -e " ${GREEN}✓${NC} ${WHITE}IP VIRTUAL ${CYAN}$ip${WHITE} ELIMINADA${NC}"
            
            sed -i "/up ip addr add $ip\/24 dev $interfaz/d" /etc/network/interfaces 2>/dev/null
            sed -i "/down ip addr del $ip\/24 dev $interfaz/d" /etc/network/interfaces 2>/dev/null
            
            echo ""
            echo -e "${CYAN}ESTADO ACTUAL DE $interfaz:${NC}"
            ip addr show $interfaz | grep "inet" | while read line; do
                echo -e "  ${GREEN}▶${NC} $line"
            done
            
            return 0
        else
            echo -e "${RED}══════════════════════════════════════════════════${NC}"
            echo -e "${RED}  ✗ ERROR AL ELIMINAR IP VIRTUAL $ip  ✗${NC}"
            echo -e "${RED}══════════════════════════════════════════════════${NC}"
            return 1
        fi
    else
        echo -e " ${YELLOW}⚠${NC} ${WHITE}LA IP ${CYAN}$ip${WHITE} NO EXISTE EN ${CYAN}$interfaz${NC}"
        return 0
    fi
}