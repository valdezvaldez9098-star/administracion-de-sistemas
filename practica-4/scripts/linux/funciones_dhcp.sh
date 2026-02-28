#!/bin/bash
# ==============================================================================
# FUNCIONES DHCP - VERSION CON VALIDACION DE DNS
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

verificar_instalacion_dhcp() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}     VERIFICANDO PAQUETES DHCP     ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    
    if dpkg -s isc-dhcp-server >/dev/null 2>&1; then 
        echo -e " ${GREEN}✓${NC} ${WHITE}DHCP SERVER${NC} ${GREEN}INSTALADO${NC}"
    else 
        echo -e " ${RED}✗${NC} ${WHITE}DHCP SERVER${NC} ${RED}NO INSTALADO${NC}"
    fi
}

instalar_dhcp() {
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     INSTALANDO SERVIDOR DHCP...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y isc-dhcp-server
    
    if [ $? -eq 0 ]; then
        echo -e " ${GREEN}✓${NC} ${WHITE}INSTALACIÓN DHCP COMPLETADA${NC}"
        
        if [ -f "/etc/init.d/isc-dhcp-server" ]; then
            update-rc.d isc-dhcp-server defaults > /dev/null 2>&1
            echo -e " ${GREEN}✓${NC} ${WHITE}SERVICIO CONFIGURADO PARA INICIO AUTOMÁTICO${NC}"
        fi
    else
        echo -e " ${RED}✗${NC} ${WHITE}ERROR EN LA INSTALACIÓN DHCP${NC}"
    fi
}

validar_ip_dns() {
    local ip=$1
    
    # NO PERMITIR 0.0.0.0
    if [ "$ip" == "0.0.0.0" ]; then
        return 1
    fi
    
    # NO PERMITIR 255.255.255.255
    if [ "$ip" == "255.255.255.255" ]; then
        return 1
    fi
    
    # NO PERMITIR 127.0.0.1
    if [ "$ip" == "127.0.0.1" ]; then
        return 1
    fi
    
    # VALIDAR SINTAXIS
    validar_ip_completa "$ip"
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    return 0
}

validar_rango_dhcp() {
    local ip_ini=$1
    local ip_fin=$2
    local server_ip=$3
    
    local red_server=$(echo $server_ip | cut -d'.' -f1-3)
    local red_ini=$(echo $ip_ini | cut -d'.' -f1-3)
    local red_fin=$(echo $ip_fin | cut -d'.' -f1-3)
    
    if [ "$red_server" != "$red_ini" ] || [ "$red_server" != "$red_fin" ]; then
        echo -e " ${RED}✗ ERROR:${NC} ${WHITE}LAS IPS DEBEN ESTAR EN LA MISMA RED QUE EL SERVIDOR${NC}"
        return 1
    fi
    
    local num_ini=$(echo $ip_ini | cut -d'.' -f4)
    local num_fin=$(echo $ip_fin | cut -d'.' -f4)
    
    if [ $num_ini -ge $num_fin ]; then
        echo -e " ${RED}✗ ERROR:${NC} ${WHITE}LA IP INICIAL DEBE SER MENOR QUE LA IP FINAL${NC}"
        return 1
    fi
    
    if [ "$ip_ini" == "$server_ip" ] || [ "$ip_fin" == "$server_ip" ]; then
        echo -e " ${RED}✗ ERROR:${NC} ${WHITE}NO PUEDES USAR LA IP DEL SERVIDOR EN EL RANGO${NC}"
        return 1
    fi
    
    return 0
}

configurar_dhcp() {
    SERVER_IP=$(obtener_ip_actual)
    if [ -z "$SERVER_IP" ]; then 
        echo -e " ${YELLOW}⚠ ALERTA:${NC} ${WHITE}CONFIGURA LA IP ESTÁTICA PRIMERO${NC}"
        return
    fi

    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}     CONFIGURAR SERVIDOR DHCP     ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}IP DEL SERVIDOR:${NC} ${GREEN}$SERVER_IP${NC}"
    echo ""
    
    # CORREGIDO: read -p con echo -e dentro
    read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}NOMBRE DEL ÁMBITO DHCP:${NC} ")" scope_name
    
    local ip_ini=""
    while true; do
        # CORREGIDO
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}IP INICIAL DEL RANGO:${NC} ")" ip_ini
        validar_ip_completa "$ip_ini"
        if [ $? -eq 0 ]; then break; fi
        echo -e " ${RED}✗ IP INVÁLIDA${NC}"
    done

    local ip_fin=""
    while true; do
        # CORREGIDO
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}IP FINAL DEL RANGO:${NC} ")" ip_fin
        validar_ip_completa "$ip_fin"
        if [ $? -eq 0 ]; then break; fi
        echo -e " ${RED}✗ IP INVÁLIDA${NC}"
    done
    
    if ! validar_rango_dhcp "$ip_ini" "$ip_fin" "$SERVER_IP"; then
        echo -e " ${RED}✗ RANGO INVÁLIDO${NC}"
        # CORREGIDO
        read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")"
        return
    fi
    
    local gateway=""
    while true; do
        # CORREGIDO - ESTA ERA LA LÍNEA 147 QUE CAUSABA EL ERROR
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}GATEWAY (ENTER PARA OMITIR):${NC} ")" input_gw
        if [ -z "$input_gw" ]; then 
            gateway=""; break
        fi
        validar_ip_completa "$input_gw"
        if [ $? -eq 0 ]; then 
            local red_gw=$(echo $input_gw | cut -d'.' -f1-3)
            local red_server=$(echo $SERVER_IP | cut -d'.' -f1-3)
            if [ "$red_gw" == "$red_server" ]; then
                gateway=$input_gw; break
            else
                echo -e " ${RED}✗ ERROR:${NC} ${WHITE}EL GATEWAY DEBE ESTAR EN LA MISMA RED${NC}"
            fi
        else
            echo -e " ${RED}✗ IP INVÁLIDA${NC}"
        fi
    done

    # SOLICITAR DNS CON VALIDACIÓN ESTRICTA
    local dns_server=""
    while true; do
        # CORREGIDO
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}SERVIDOR DNS [ENTER PARA USAR $SERVER_IP]:${NC} ")" input_dns
        if [ -z "$input_dns" ]; then
            dns_server="$SERVER_IP"
            break
        fi
        if validar_ip_dns "$input_dns"; then
            dns_server="$input_dns"
            break
        else
            echo -e " ${RED}✗ ERROR:${NC} ${WHITE}DNS INVÁLIDO (NO PUEDE SER 0.0.0.0, 255.255.255.255, 127.0.0.1 O IP MAL FORMADA)${NC}"
        fi
    done

    local lease_time=""
    while true; do
        # CORREGIDO
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}TIEMPO CONCESIÓN (SEGUNDOS) [ENTER=86400]:${NC} ")" input_lease
        if [ -z "$input_lease" ]; then 
            lease_time=86400; break
        fi
        if [[ "$input_lease" =~ ^[0-9]+$ ]] && [ "$input_lease" -gt 0 ]; then
            lease_time=$input_lease; break
        else
            echo -e " ${RED}✗ ERROR:${NC} ${WHITE}DEBE SER UN NÚMERO ENTERO POSITIVO${NC}"
        fi
    done
    
    local subnet_base=$(echo $SERVER_IP | cut -d'.' -f1-3)
    SUBNET="${subnet_base}.0"
    BROADCAST="${subnet_base}.255"
    
    if [ -f "/etc/default/isc-dhcp-server" ]; then
        sed -i 's/^INTERFACESv4=.*/INTERFACESv4="eth1"/' /etc/default/isc-dhcp-server
    else
        echo "INTERFACESv4=\"eth1\"" > /etc/default/isc-dhcp-server
    fi
    
    cat > /etc/dhcp/dhcpd.conf <<EOF
# CONFIGURACIÓN DHCP
# ÁMBITO: $scope_name
# GENERADO: $(date)

option subnet-mask 255.255.255.0;
option broadcast-address $BROADCAST;
option domain-name "lab.local";
option domain-name-servers $dns_server;

default-lease-time $lease_time;
max-lease-time $((lease_time * 2));
authoritative;

subnet $SUBNET netmask 255.255.255.0 {
    range $ip_ini $ip_fin;
EOF

    if [ ! -z "$gateway" ]; then
        echo "    option routers $gateway;" >> /etc/dhcp/dhcpd.conf
    fi

    echo "}" >> /etc/dhcp/dhcpd.conf
    
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     REINICIANDO SERVICIO DHCP...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    if [ -f "/etc/init.d/isc-dhcp-server" ]; then
        /etc/init.d/isc-dhcp-server stop > /dev/null 2>&1
        sleep 2
        /etc/init.d/isc-dhcp-server start > /dev/null 2>&1
        sleep 3
        
        if /etc/init.d/isc-dhcp-server status > /dev/null 2>&1; then
            echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}   ✓ SERVIDOR DHCP CONFIGURADO CORRECTAMENTE ✓   ${NC}"
            echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
            echo -e " ${WHITE}DNS CONFIGURADO:${NC} ${CYAN}$dns_server${NC}"
            echo -e " ${WHITE}RANGO DHCP:${NC} ${CYAN}$ip_ini - $ip_fin${NC}"
            echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        else
            echo -e "${RED}══════════════════════════════════════════════════${NC}"
            echo -e "${RED}  ✗ FALLO: EL SERVICIO DHCP NO ARRANCÓ ✗  ${NC}"
            echo -e "${RED}══════════════════════════════════════════════════${NC}"
            tail -10 /var/log/syslog | grep -i "dhcpd" | while read line; do
                echo -e " ${YELLOW}▶${NC} $line"
            done
        fi
    else
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
        echo -e "${RED}  ✗ ERROR: EL SERVICIO ISC-DHCP-SERVER NO ESTÁ INSTALADO ✗  ${NC}"
        echo -e "${RED}══════════════════════════════════════════════════${NC}"
    fi
}