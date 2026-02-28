#!/bin/bash
# ==============================================================================
# FUNCIONES SSH - VERSION ULTRA CORREGIDA PARA DEVUAN
# ==============================================================================

source ./funciones_compartidas.sh

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

verificar_instalacion_ssh() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}         VERIFICANDO SERVICIO SSH         ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    
    if dpkg -s openssh-server >/dev/null 2>&1; then 
        echo -e " ${GREEN}✓${NC} ${WHITE}OPENSSH SERVER${NC} ${GREEN}INSTALADO${NC}"
    else 
        echo -e " ${RED}✗${NC} ${WHITE}OPENSSH SERVER${NC} ${RED}NO INSTALADO${NC}"
        return 1
    fi
    
    if service ssh status >/dev/null 2>&1; then
        if service ssh status | grep -q "running"; then
            echo -e " ${GREEN}✓${NC} ${WHITE}SERVICIO SSH${NC} ${GREEN}ACTIVO${NC}"
        else
            echo -e " ${RED}✗${NC} ${WHITE}SERVICIO SSH${NC} ${RED}INACTIVO${NC}"
        fi
    else
        echo -e " ${RED}✗${NC} ${WHITE}SERVICIO SSH${NC} ${RED}NO DISPONIBLE${NC}"
    fi
}

activar_eth2() {
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}         ACTIVANDO ETH2 (MODO FORZADO)         ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    if ! ip link show eth2 > /dev/null 2>&1; then
        echo -e " ${RED}✗ ERROR: ETH2 NO EXISTE${NC}"
        return 1
    fi
    
    echo -e " ${YELLOW}▶ PASO 1:${NC} ${WHITE}DERRIBANDO ETH2...${NC}"
    ip link set eth2 down
    sleep 2
    
    echo -e " ${YELLOW}▶ PASO 2:${NC} ${WHITE}ACTIVANDO ETH2...${NC}"
    ip link set eth2 up
    sleep 2
    
    echo -e " ${YELLOW}▶ PASO 3:${NC} ${WHITE}REACTIVANDO ETH2...${NC}"
    ip link set eth2 up
    sleep 2
    
    echo -e " ${YELLOW}▶ PASO 4:${NC} ${WHITE}ASIGNANDO IP ${CYAN}192.168.56.69${WHITE}...${NC}"
    ip addr flush dev eth2 2>/dev/null
    ip addr add 192.168.56.69/24 dev eth2
    sleep 2
    
    echo -e " ${YELLOW}▶ PASO 5:${NC} ${WHITE}VERIFICANDO ESTADO...${NC}"
    ip link show eth2 | grep -q "UP"
    if [ $? -eq 0 ]; then
        echo -e "   ${GREEN}✓ ETH2 ACTIVADA${NC}"
    else
        echo -e "   ${RED}✗ NO SE PUDO ACTIVAR ETH2${NC}"
        return 1
    fi
    
    echo -e " ${YELLOW}▶ PASO 6:${NC} ${WHITE}VERIFICANDO IP...${NC}"
    ip addr show eth2 | grep -q "192.168.56.69"
    if [ $? -eq 0 ]; then
        echo -e "   ${GREEN}✓ IP 192.168.56.69 ASIGNADA${NC}"
    else
        echo -e "   ${RED}✗ IP NO ASIGNADA${NC}"
        return 1
    fi
    
    echo -e " ${YELLOW}▶ PASO 7:${NC} ${WHITE}VERIFICANDO RUTAS...${NC}"
    ip route | grep -q "192.168.56.0/24 dev eth2"
    if [ $? -eq 0 ]; then
        echo -e "   ${GREEN}✓ RUTA CONFIGURADA${NC}"
    else
        echo -e "   ${YELLOW}⚠ AVISO:${NC} RUTA NO CONFIGURADA, AGREGANDO..."
        ip route add 192.168.56.0/24 dev eth2 2>/dev/null
    fi
    
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   ✓ ETH2 CONFIGURADA CORRECTAMENTE   ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    return 0
}

verificar_eth2() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         VERIFICACIÓN COMPLETA DE ETH2         ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}ESTADO DE LA INTERFAZ:${NC}"
    ip link show eth2 | while read line; do
        echo -e "  ${GREEN}▶${NC} $line"
    done
    echo ""
    echo -e "${YELLOW}DIRECCIONES IP:${NC}"
    ip addr show eth2 | grep inet | while read line; do
        echo -e "  ${GREEN}▶${NC} ${CYAN}$line${NC}"
    done || echo -e "  ${YELLOW}⚠ SIN IP ASIGNADA${NC}"
    echo ""
    echo -e "${YELLOW}RUTAS:${NC}"
    ip route | grep eth2 | while read line; do
        echo -e "  ${GREEN}▶${NC} $line"
    done || echo -e "  ${YELLOW}⚠ SIN RUTAS${NC}"
    echo ""
    echo -e "${YELLOW}ESTADÍSTICAS:${NC}"
    ip -s link show eth2 | grep -A2 "RX" | head -4 | while read line; do
        echo -e "  ${GREEN}▶${NC} $line"
    done
}

configurar_ssh_eth2() {
    echo ""
    echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}         CONFIGURACIÓN DE SSH EN ETH2         ${NC}"
    echo -e "${PURPLE}         (HOST-ONLY)         ${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
    
    if ! ip link show eth2 > /dev/null 2>&1; then
        echo -e " ${RED}✗ ERROR: ETH2 NO EXISTE${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}▶ ACTIVANDO ETH2...${NC}"
    activar_eth2
    if [ $? -ne 0 ]; then
        echo -e " ${RED}✗ ERROR: NO SE PUDO ACTIVAR ETH2${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}▶ VERIFICANDO INSTALACIÓN SSH...${NC}"
    if ! command -v sshd >/dev/null 2>&1; then
        echo -e " ${YELLOW}⚠ INSTALANDO OPENSSH-SERVER...${NC}"
        apt-get update > /dev/null 2>&1
        apt-get install -y openssh-server > /dev/null 2>&1
        echo -e "   ${GREEN}✓ OPENSSH SERVER INSTALADO${NC}"
    else
        echo -e "   ${GREEN}✓ OPENSSH SERVER YA INSTALADO${NC}"
    fi
    
    echo -e "${YELLOW}▶ CONFIGURANDO SSHD...${NC}"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    echo -e "   ${GREEN}✓ BACKUP CREADO${NC}"
    
    cat > /etc/ssh/sshd_config <<EOF
Port 22
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    echo -e "   ${GREEN}✓ CONFIGURACIÓN SSH ACTUALIZADA${NC}"
    
    echo -e "${YELLOW}▶ CONFIGURACIÓN PERMANENTE EN INTERFACES...${NC}"
    if ! grep -q "iface eth2" /etc/network/interfaces; then
        cat >> /etc/network/interfaces <<EOF

auto eth2
iface eth2 inet static
    address 192.168.56.69
    netmask 255.255.255.0
    pre-up ip link set eth2 up
    up ip link set eth2 up
    post-up ip addr add 192.168.56.69/24 dev eth2 2>/dev/null
    down ip addr del 192.168.56.69/24 dev eth2
    down ip link set eth2 down
EOF
        echo -e "   ${GREEN}✓ CONFIGURACIÓN PERMANENTE AGREGADA${NC}"
    else
        echo -e "   ${YELLOW}⚠ CONFIGURACIÓN PERMANENTE YA EXISTE${NC}"
    fi
    
    echo -e "${YELLOW}▶ REINICIANDO SERVICIO SSH...${NC}"
    service ssh restart > /dev/null 2>&1
    sleep 3
    echo -e "   ${GREEN}✓ SERVICIO SSH REINICIADO${NC}"
    
    echo -e "${YELLOW}▶ REINICIANDO RED...${NC}"
    service networking restart 2>/dev/null
    sleep 3
    echo -e "   ${GREEN}✓ RED REINICIADA${NC}"
    
    activar_eth2 > /dev/null 2>&1
    
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         VERIFICACIÓN FINAL         ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}ESTADO ETH2:${NC}"
    if ip link show eth2 | grep -q "UP"; then
        echo -e "   ${GREEN}✓ INTERFAZ ACTIVA${NC}"
    else
        echo -e "   ${RED}✗ INTERFAZ INACTIVA${NC}"
    fi
    
    if ip addr show eth2 | grep -q "192.168.56.69"; then
        echo -e "   ${GREEN}✓ IP CORRECTA${NC}"
    else
        echo -e "   ${RED}✗ IP INCORRECTA${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}ESTADO SSH:${NC}"
    if netstat -tlnp 2>/dev/null | grep -q ":22 "; then
        echo -e "   ${GREEN}✓ PUERTO 22 ESCUCHANDO${NC}"
    else
        echo -e "   ${RED}✗ PUERTO 22 NO ESCUCHA${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   SSH CONFIGURADO EN ETH2   ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}IP:${NC} ${CYAN}192.168.56.69${NC}"
    echo -e " ${WHITE}USUARIO:${NC} ${CYAN}$(whoami)${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}PRUEBA DESDE WINDOWS (POWERSHELL):${NC}"
    echo -e "  ${GREEN}▶${NC} ${WHITE}ssh $(whoami)@192.168.56.69${NC}"
    echo ""
    echo -e "${RED}SI NO FUNCIONA, VERIFICA MANUALMENTE:${NC}"
    echo -e "  ${YELLOW}1.${NC} ${WHITE}ip link set eth2 up${NC}"
    echo -e "  ${YELLOW}2.${NC} ${WHITE}ip addr add 192.168.56.69/24 dev eth2${NC}"
    echo -e "  ${YELLOW}3.${NC} ${WHITE}service ssh restart${NC}"
    echo -e "  ${YELLOW}4.${NC} ${WHITE}netstat -tlnp | grep :22${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
}

submenu_ssh() {
    while true; do
        clear
        echo ""
        echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
        echo -e "${PURPLE}         GESTIÓN DE SSH         ${NC}"
        echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
        echo -e " ${WHITE}1)${NC} ${CYAN}VERIFICAR ESTADO DE SSH${NC}"
        echo -e " ${WHITE}2)${NC} ${CYAN}ACTIVAR ETH2 (MODO FORZADO)${NC}"
        echo -e " ${WHITE}3)${NC} ${CYAN}VERIFICAR ESTADO DE ETH2${NC}"
        echo -e " ${WHITE}4)${NC} ${CYAN}CONFIGURAR SSH EN ETH2${NC}"
        echo -e " ${WHITE}5)${NC} ${RED}VOLVER${NC}"
        echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
        
        read -p " $(echo -e ${YELLOW}▶${NC} ${WHITE}SELECCIONE OPCIÓN:${NC} ) " subopc
        case $subopc in
            1) verificar_instalacion_ssh; read -p " $(echo -e ${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} )" ;;
            2) activar_eth2; read -p " $(echo -e ${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} )" ;;
            3) verificar_eth2; read -p " $(echo -e ${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} )" ;;
            4) configurar_ssh_eth2; read -p " $(echo -e ${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} )" ;;
            5) return ;;
            *) echo -e " ${RED}✗ OPCIÓN INVÁLIDA${NC}"; sleep 1 ;;
        esac
    done
}