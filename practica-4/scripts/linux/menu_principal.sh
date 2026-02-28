#!/bin/bash
# ==============================================================================
# MENU PRINCIPAL - VERSION FINAL (SIN RESTRICCION DE RED)
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

echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         CARGANDO MÓDULOS...         ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"

source ./funciones_compartidas.sh
source ./funciones_dhcp.sh
source ./funciones_dns.sh
source ./funciones_ssh.sh

echo -e " ${GREEN}✓${NC} ${WHITE}TODOS LOS MÓDULOS CARGADOS CORRECTAMENTE${NC}"
sleep 2

# =========================
# FUNCIONES ADICIONALES
# =========================

instalar_todos_roles() {
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}         INSTALANDO TODOS LOS ROLES         ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e " ${YELLOW}▶${NC} ${WHITE}ACTUALIZANDO REPOSITORIOS...${NC}"
    apt-get update > /dev/null 2>&1
    echo -e "   ${GREEN}✓ REPOSITORIOS ACTUALIZADOS${NC}"
    
    instalar_dhcp
    instalar_dns
    
    echo ""
    echo -e " ${GREEN}✓ INSTALACIÓN COMPLETADA${NC}"
    echo -e " ${YELLOW}⚠${NC} ${WHITE}USA LA OPCIÓN 6 PARA CONFIGURAR SSH EN ETH2${NC}"
}

activar_todas_interfaces() {
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}         ACTIVANDO TODAS LAS INTERFACES         ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    activar_interfaces_red
    activar_eth2
}

configurar_ip_estatica() {
    if [ -z "$INTERFACE" ] || [ "$INTERFACE" == "PENDIENTE" ]; then
        echo ""
        echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}         CONFIGURACIÓN IP ESTÁTICA         ${NC}"
        echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
        echo -e " ${YELLOW}⚠ AVISO:${NC} ${WHITE}PRIMERO DEBES SELECCIONAR UNA INTERFAZ${NC}"
        seleccionar_interfaz
    fi
    
    CURRENT_IP=$(obtener_ip_actual 2>/dev/null)
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         CONFIGURACIÓN IP ESTÁTICA (${WHITE}$INTERFACE${CYAN})         ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}IP ACTUAL:${NC} ${GREEN}${CURRENT_IP:-NINGUNA}${NC}"
    echo ""
    
    # CORREGIDO
    read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}INGRESE IP ESTÁTICA:${NC} ")" nueva_ip
    validar_ip_completa "$nueva_ip"
    if [ $? -ne 0 ]; then
        echo -e " ${RED}✗ IP INVÁLIDA${NC}"
        return
    fi
    
    echo -e " ${YELLOW}▶${NC} ${WHITE}APLICANDO CONFIGURACIÓN...${NC}"
    ip addr flush dev $INTERFACE 2>/dev/null
    ip addr add $nueva_ip/24 dev $INTERFACE
    ip link set $INTERFACE up
    
    cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

allow-hotplug eth0
iface eth0 inet dhcp

auto $INTERFACE
iface $INTERFACE inet static
    address $nueva_ip
    netmask 255.255.255.0
EOF

    echo -e " ${GREEN}✓${NC} ${WHITE}IP ${CYAN}$nueva_ip${WHITE} ASIGNADA A ${CYAN}$INTERFACE${NC}"
}

verificar_instalacion() {
    echo ""
    echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}         VERIFICACIÓN COMPLETA         ${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
    
    echo ""
    echo -e "${YELLOW}INTERFACES DE RED:${NC}"
    ip -4 addr show | grep -v "127.0.0.1" | while read line; do
        echo -e "  ${GREEN}▶${NC} $line"
    done
    
    echo ""
    echo -e "${YELLOW}SERVICIOS INSTALADOS:${NC}"
    dpkg -s isc-dhcp-server >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} DHCP: INSTALADO" || echo -e "  ${RED}✗${NC} DHCP: NO INSTALADO"
    dpkg -s bind9 >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} DNS: INSTALADO" || echo -e "  ${RED}✗${NC} DNS: NO INSTALADO"
    dpkg -s openssh-server >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} SSH: INSTALADO" || echo -e "  ${RED}✗${NC} SSH: NO INSTALADO"
    
    echo ""
    echo -e "${YELLOW}ESTADO DE SERVICIOS:${NC}"
    service isc-dhcp-server status >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} DHCP: ACTIVO" || echo -e "  ${RED}✗${NC} DHCP: INACTIVO"
    service named status >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} DNS: ACTIVO" || echo -e "  ${RED}✗${NC} DNS: INACTIVO"
    service ssh status >/dev/null 2>&1 | grep -q "running" && echo -e "  ${GREEN}✓${NC} SSH: ACTIVO" || echo -e "  ${RED}✗${NC} SSH: INACTIVO"
}

mostrar_instrucciones() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}         INSTRUCCIONES FINALES         ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e " ${WHITE}1.${NC} ${CYAN}CONFIGURA EL ADAPTADOR 3 EN VIRTUALBOX COMO 'SOLO ANFITRIÓN'${NC}"
    echo ""
    echo -e " ${WHITE}2.${NC} ${CYAN}USA OPCIÓN 2a PARA ACTIVAR TODAS LAS INTERFACES${NC}"
    echo ""
    echo -e " ${WHITE}3.${NC} ${CYAN}USA OPCIÓN 6 PARA CONFIGURAR SSH EN ETH2${NC}"
    echo ""
    echo -e " ${WHITE}4.${NC} ${CYAN}CONÉCTATE DESDE WINDOWS:${NC} ${GREEN}ssh USUARIO@192.168.56.10${NC}"
    echo ""
    echo -e " ${WHITE}5.${NC} ${CYAN}CONFIGURA IP ESTÁTICA EN ETH1 (EJ. 10.10.10.1)${NC}"
    echo ""
    echo -e " ${WHITE}6.${NC} ${CYAN}INSTALA DHCP Y DNS CON OPCIÓN 2${NC}"
    echo ""
    echo -e " ${WHITE}7.${NC} ${CYAN}CONFIGURA DHCP CON OPCIÓN 4${NC}"
    echo ""
    echo -e " ${WHITE}8.${NC} ${CYAN}AGREGA DOMINIOS CON OPCIÓN 5${NC}"
    echo ""
    echo -e " ${WHITE}9.${NC} ${CYAN}PRUEBAS:${NC}"
    echo -e "    ${GREEN}▶${NC} ${WHITE}nslookup siganplaticando.com${NC}"
    echo -e "    ${GREEN}▶${NC} ${WHITE}ping 10.10.10.50${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
}

# =========================
# VERIFICACIÓN INICIAL
# =========================

check_root

clear
echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
echo -e "${PURPLE}   GESTOR DE INFRAESTRUCTURA - VERSIÓN FINAL   ${NC}"
echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
echo ""

# CORREGIDO - ESTA ERA LA LÍNEA 169 QUE CAUSABA EL ERROR
read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}SELECCIONAR INTERFAZ INTERNA AHORA? (S/N):${NC} ")" sel_interfaz
if [[ "$sel_interfaz" == "S" ]] || [[ "$sel_interfaz" == "s" ]]; then
    seleccionar_interfaz
else
    INTERFACE="PENDIENTE"
fi

while true; do
    clear
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}         MENÚ PRINCIPAL          ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}INTERFAZ INTERNA:${NC} ${CYAN}${INTERFACE:-NO DEFINIDA}${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e " ${GREEN}1)${NC} ${WHITE}VERIFICAR INSTALACIÓN${NC}"
    echo -e " ${GREEN}2)${NC} ${WHITE}INSTALAR TODOS LOS ROLES (DHCP Y DNS)${NC}"
    echo -e " ${GREEN}2a)${NC} ${WHITE}ACTIVAR TODAS LAS INTERFACES (ETH1 Y ETH2)${NC}"
    echo ""
    echo -e " ${GREEN}3)${NC} ${WHITE}CONFIGURAR IP ESTÁTICA${NC}"
    echo -e " ${GREEN}4)${NC} ${WHITE}CONFIGURAR SERVIDOR DHCP${NC}"
    echo -e " ${GREEN}5)${NC} ${WHITE}GESTIÓN DE DOMINIOS DNS${NC}"
    echo -e " ${GREEN}6)${NC} ${WHITE}CONFIGURAR SSH EN ETH2${NC}"
    echo ""
    echo -e " ${GREEN}7)${NC} ${WHITE}VER INSTRUCCIONES FINALES${NC}"
    echo -e " ${GREEN}8)${NC} ${WHITE}SELECCIONAR INTERFAZ${NC}"
    echo -e " ${RED}9)${NC} ${WHITE}SALIR${NC}"
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    
    # CORREGIDO
    read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}SELECCIONE OPCIÓN:${NC} ")" MAIN_OPC
    
    case $MAIN_OPC in
        1) verificar_instalacion; 
           read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
        2) instalar_todos_roles; 
           read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
        2a) activar_todas_interfaces; 
           read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
        3) configurar_ip_estatica; 
           read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
        4) configurar_dhcp; 
           read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
        5) submenu_dns ;;
        6) submenu_ssh ;;
        7) mostrar_instrucciones; 
           read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
        8) seleccionar_interfaz; 
           read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
        9) 
            echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}         HASTA LUEGO         ${NC}"
            echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
            exit 0 
            ;;
        *) echo -e " ${RED}✗ OPCIÓN INVÁLIDA${NC}"; sleep 1 ;;
    esac
done