#!/bin/bash
# ==============================================================================
# FUNCIONES DNS - VERSION CORREGIDA (PERMITE CUALQUIER RED)
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

verificar_instalacion_dns() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}     VERIFICANDO PAQUETES DNS     ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    
    if dpkg -s bind9 >/dev/null 2>&1; then 
        echo -e " ${GREEN}✓${NC} ${WHITE}DNS SERVER (BIND9)${NC} ${GREEN}INSTALADO${NC}"
        if [ -f "/etc/init.d/named" ]; then
            echo -e "    ${CYAN}└─ SERVICIO:${NC} ${WHITE}NAMED${NC}"
        fi
    else 
        echo -e " ${RED}✗${NC} ${WHITE}DNS SERVER${NC} ${RED}NO INSTALADO${NC}"
    fi
}

instalar_dns() {
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     INSTALANDO SERVIDOR DNS (BIND9)...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    apt update > /dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y bind9 bind9utils dnsutils > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e " ${GREEN}✓${NC} ${WHITE}INSTALACIÓN DNS COMPLETADA${NC}"
        
        if [ -f "/etc/init.d/named" ]; then
            update-rc.d named defaults > /dev/null 2>&1
            echo -e " ${GREEN}✓${NC} ${WHITE}SERVICIO NAMED CONFIGURADO PARA INICIO AUTOMÁTICO${NC}"
        fi
    else
        echo -e " ${RED}✗${NC} ${WHITE}ERROR EN LA INSTALACIÓN DNS${NC}"
    fi
}

reiniciar_servicio_dns() {
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     REINICIANDO SERVICIO DNS (NAMED)...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    if [ -f "/etc/init.d/named" ]; then
        /etc/init.d/named stop > /dev/null 2>&1
        sleep 2
        /etc/init.d/named start > /dev/null 2>&1
        sleep 3
        echo -e " ${GREEN}✓${NC} ${WHITE}SERVICIO REINICIADO CORRECTAMENTE${NC}"
        return 0
    fi
    
    echo -e " ${RED}✗${NC} ${WHITE}ERROR: SERVICIO NAMED NO ENCONTRADO${NC}"
    return 1
}

configurar_resolv_conf() {
    local SERVER_IP=$1
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     CONFIGURANDO /etc/resolv.conf...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null
    
    cat > /etc/resolv.conf <<EOF
nameserver $SERVER_IP
EOF
    
    chattr +i /etc/resolv.conf 2>/dev/null
    echo -e " ${GREEN}✓${NC} ${WHITE}RESOLV.CONF CONFIGURADO CON DNS ${CYAN}$SERVER_IP${NC}"
}

configurar_opciones_bind() {
    local SERVER_IP=$1
    
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     CONFIGURANDO OPCIONES DE BIND...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    
    cat > /etc/bind/named.conf.options <<EOF
options {
    directory "/var/cache/bind";
    listen-on { $SERVER_IP; 127.0.0.1; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion yes;
    
    forwarders {
        8.8.8.8;
        8.8.4.4;
    };
    
    dnssec-validation no;
    check-names master ignore;
};
EOF

    echo -e " ${GREEN}✓${NC} ${WHITE}OPCIONES DE BIND CONFIGURADAS${NC}"
}

agregar_zona() {
    SERVER_IP=$(obtener_ip_actual)
    if [ -z "$SERVER_IP" ]; then 
        SERVER_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        [ -z "$SERVER_IP" ] && SERVER_IP="192.168.56.100"
    fi
    
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}     AGREGAR ZONA DNS     ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    
    # CORREGIDO
    read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}NOMBRE DEL DOMINIO:${NC} ")" dominio
    [ -z "$dominio" ] && return
    
    local virtual_ip=""
    while true; do
        # CORREGIDO
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}IP VIRTUAL PARA ${CYAN}$dominio${WHITE}:${NC} ")" virtual_ip
        validar_ip_completa "$virtual_ip" || continue
        
        # AVISO SI USA LA MISMA IP DEL SERVIDOR
        if [ "$virtual_ip" == "$SERVER_IP" ]; then
            echo -e " ${YELLOW}⚠ AVISO:${NC} ${WHITE}USANDO LA MISMA IP DEL SERVIDOR${NC}"
        fi
        
        break
    done
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     CREANDO IP VIRTUAL...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    crear_ip_virtual "$virtual_ip" "$INTERFACE"
    
    # EXTRAER OCTETOS DE LA IP VIRTUAL
    OCT1=$(echo $virtual_ip | cut -d'.' -f1)
    OCT2=$(echo $virtual_ip | cut -d'.' -f2)
    OCT3=$(echo $virtual_ip | cut -d'.' -f3)
    OCT4=$(echo $virtual_ip | cut -d'.' -f4)
    
    CONF="/etc/bind/named.conf.local"
    FILE="/var/cache/bind/db.$dominio"
    
    mkdir -p /var/cache/bind
    
    # CONFIGURAR OPCIONES DE BIND SI NO EXISTEN
    if [ ! -f "/etc/bind/named.conf.options" ]; then
        configurar_opciones_bind "$SERVER_IP"
    fi
    
    # VERIFICAR SI LA ZONA DIRECTA YA EXISTE
    if [ -f "$CONF" ] && grep -q "zone \"$dominio\"" "$CONF" 2>/dev/null; then
        echo -e " ${YELLOW}⚠ AVISO:${NC} ${WHITE}LA ZONA DIRECTA YA EXISTE${NC}"
        # CORREGIDO - ESTA ERA LA LÍNEA 169 QUE CAUSABA EL ERROR
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}RECREAR? (S/N):${NC} ")" rec
        [ "$rec" != "S" ] && [ "$rec" != "s" ] && return
        sed -i "/zone \"$dominio\" {/,/};/d" "$CONF"
    fi
    
    # AGREGAR ZONA DIRECTA
    cat >> "$CONF" <<EOF

zone "$dominio" {
    type master;
    file "$FILE";
};
EOF

    # CREAR ARCHIVO DE ZONA DIRECTA
    cat > "$FILE" <<EOF
\$TTL 604800
@ IN SOA ns1.$dominio. admin.$dominio. (
    $(date +%Y%m%d)01
    604800
    86400
    2419200
    604800 )

; SERVIDORES DE NOMBRES
@ IN NS ns1.$dominio.
@ IN NS ns2.$dominio.

; REGISTROS A
ns1.$dominio. IN A $SERVER_IP
ns2.$dominio. IN A $SERVER_IP
$dominio. IN A $virtual_ip
www.$dominio. IN A $virtual_ip
mail.$dominio. IN A $virtual_ip
ftp.$dominio. IN A $virtual_ip

; REGISTRO MX
$dominio. IN MX 10 mail.$dominio.
EOF
    
    chmod 644 "$FILE"
    chown bind:bind "$FILE" 2>/dev/null
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     VERIFICANDO SINTAXIS DE LA ZONA...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    named-checkzone "$dominio" "$FILE"
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}     REINICIANDO SERVICIO DNS...     ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    reiniciar_servicio_dns
    
    echo ""
    configurar_resolv_conf "$SERVER_IP"
    
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   ✓ DOMINIO CONFIGURADO CORRECTAMENTE ✓   ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}DOMINIO:${NC} ${CYAN}$dominio${NC}"
    echo -e " ${WHITE}IP VIRTUAL:${NC} ${CYAN}$virtual_ip${NC}"
    echo -e " ${WHITE}SERVIDOR DNS:${NC} ${CYAN}$SERVER_IP${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}PRUEBAS LOCALES:${NC}"
    echo -e " ${GREEN}▶${NC} ${WHITE}nslookup${NC} ${CYAN}$dominio${NC}"
    echo -e " ${GREEN}▶${NC} ${WHITE}nslookup${NC} ${CYAN}$virtual_ip${NC}"
    echo -e " ${GREEN}▶${NC} ${WHITE}ping${NC} ${CYAN}$dominio${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
}

eliminar_zona() {
    echo ""
    echo -e "${RED}══════════════════════════════════════════════════${NC}"
    echo -e "${RED}     ELIMINAR ZONA DNS     ${NC}"
    echo -e "${RED}══════════════════════════════════════════════════${NC}"
    CONF="/etc/bind/named.conf.local"
    
    if [ ! -f "$CONF" ]; then
        echo -e " ${RED}✗${NC} ${WHITE}NO HAY ARCHIVO DE CONFIGURACIÓN${NC}"
        return
    fi
    
    echo -e "${CYAN}ZONAS ACTUALES:${NC}"
    grep "zone" "$CONF" | grep -v "in-addr.arpa" | cut -d'"' -f2 | while read zona; do
        echo -e " ${GREEN}▶${NC} ${WHITE}$zona${NC}"
    done
    
    # CORREGIDO
    read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}NOMBRE DE LA ZONA A BORRAR:${NC} ")" zona_del
    [ -z "$zona_del" ] && return
    
    if grep -q "zone \"$zona_del\"" "$CONF"; then
        archivo="/var/cache/bind/db.$zona_del"
        if [ -f "$archivo" ]; then
            virtual_ip=$(grep -E "^$zona_del\.\s+IN\s+A" "$archivo" | awk '{print $4}')
            if [ -n "$virtual_ip" ]; then
                echo -e " ${YELLOW}⚠${NC} ${WHITE}ELIMINANDO IP VIRTUAL ${CYAN}$virtual_ip${NC}"
                eliminar_ip_virtual "$virtual_ip" "$INTERFACE"
            fi
        fi
        
        sed -i "/zone \"$zona_del\" {/,/};/d" "$CONF"
        rm -f "$archivo"
        
        reiniciar_servicio_dns
        echo -e " ${GREEN}✓${NC} ${WHITE}ZONA ELIMINADA${NC}"
    else
        echo -e " ${RED}✗${NC} ${WHITE}ZONA NO ENCONTRADA${NC}"
    fi
}

listar_zonas() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}     DOMINIOS CONFIGURADOS     ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    if [ -f "/etc/bind/named.conf.local" ]; then
        zonas=$(grep "zone" /etc/bind/named.conf.local | grep -v "in-addr.arpa" | cut -d'"' -f2)
        if [ -n "$zonas" ]; then
            echo "$zonas" | while read zona; do
                echo -e " ${GREEN}▶${NC} ${WHITE}$zona${NC}"
            done
        else
            echo -e " ${YELLOW}⚠${NC} ${WHITE}NO HAY ZONAS CONFIGURADAS${NC}"
        fi
    else
        echo -e " ${YELLOW}⚠${NC} ${WHITE}NO HAY ARCHIVO DE CONFIGURACIÓN${NC}"
    fi
}

submenu_dns() {
    while true; do
        clear
        echo ""
        echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
        echo -e "${PURPLE}         GESTIÓN DE DNS          ${NC}"
        echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
        echo -e " ${WHITE}1)${NC} ${CYAN}VERIFICAR INSTALACIÓN DNS${NC}"
        echo -e " ${WHITE}2)${NC} ${CYAN}INSTALAR SERVIDOR DNS${NC}"
        echo -e " ${WHITE}3)${NC} ${CYAN}AGREGAR ZONA${NC}"
        echo -e " ${WHITE}4)${NC} ${CYAN}ELIMINAR ZONA${NC}"
        echo -e " ${WHITE}5)${NC} ${CYAN}LISTAR ZONAS${NC}"
        echo -e " ${WHITE}6)${NC} ${CYAN}REINICIAR NAMED${NC}"
        echo -e " ${WHITE}7)${NC} ${RED}VOLVER${NC}"
        echo -e "${PURPLE}══════════════════════════════════════════════════${NC}"
        
        # CORREGIDO
        read -p "$(echo -e "${YELLOW}▶${NC} ${WHITE}SELECCIONE OPCIÓN:${NC} ")" subopc
        case $subopc in
            1) verificar_instalacion_dns; 
               read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            2) instalar_dns; 
               read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            3) agregar_zona; 
               read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            4) eliminar_zona; 
               read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            5) listar_zonas; 
               read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            6) reiniciar_servicio_dns; 
               read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            7) return ;;
            *) echo -e " ${RED}✗ OPCIÓN INVÁLIDA${NC}"; sleep 1 ;;
        esac
    done
}