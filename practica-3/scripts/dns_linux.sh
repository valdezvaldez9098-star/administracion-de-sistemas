#!/bin/bash

# ==============================================================================
# GESTOR INFRAESTRUCTURA V5 - PARA DEVUAN (SERVIDOR) Y WINDOWS 10 (CLIENTE)
# ==============================================================================

# COLORES
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =========================
# VARIABLES GLOBALES
# =========================
IPS_VIRTUALES=()  # Array para almacenar IPs virtuales creadas

# =========================
# 0. SELECCIÓN DE INTERFAZ Y FIREWALL
# =========================

seleccionar_interfaz() {
    clear
    echo -e "${CYAN}--- SELECCIÓN DE INTERFAZ DE RED ---${NC}"
    echo "Interfaces disponibles:"
    ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"
    
    echo -e "\n${YELLOW}NOTA: Selecciona la interfaz de RED INTERNA (ej. eth1).${NC}"
    read -p "Escribe el nombre de la interfaz: " INTERFACE

    if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
        echo -e "${RED}Error: La interfaz $INTERFACE no existe.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Trabajando sobre: $INTERFACE${NC}"
    sleep 1
}

configurar_firewall_ping() {
    echo -e "${CYAN}Configurando Firewall para permitir PING (ICMP)...${NC}"
    
    # En Devuan, usar iptables (instalar si es necesario)
    if ! command -v iptables >/dev/null 2>&1; then
        apt-get install -y iptables > /dev/null 2>&1
    fi
    
    iptables -A INPUT -i $INTERFACE -p icmp --icmp-type echo-request -j ACCEPT > /dev/null 2>&1
    iptables -A OUTPUT -o $INTERFACE -p icmp --icmp-type echo-reply -j ACCEPT > /dev/null 2>&1
    
    echo -e "${GREEN}Reglas ICMP aplicadas con iptables.${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Ejecuta con sudo.${NC}"; exit 1
    fi
}

# =========================
# VALIDACIONES
# =========================

validar_ip_sintaxis() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
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

obtener_ip_actual() {
    ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1
}

# =========================
# FUNCIÓN PARA CREAR IP VIRTUAL (CORREGIDA Y MEJORADA)
# =========================

crear_ip_virtual() {
    local ip=$1
    local interfaz=$2
    
    echo -e "${CYAN}--- VERIFICANDO IP VIRTUAL: $ip ---${NC}"
    
    # Verificar si la IP ya existe (como principal o virtual)
    if ip addr show $interfaz | grep -q "$ip"; then
        echo -e "${GREEN}✓ La IP $ip ya está configurada en $interfaz${NC}"
        return 0
    fi
    
    # Verificar que la IP no sea la principal
    local ip_principal=$(obtener_ip_actual)
    if [ "$ip" == "$ip_principal" ]; then
        echo -e "${RED}✗ Error: No puedes usar la IP principal ($ip_principal) como virtual${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}➜ Creando IP virtual: $ip en $interfaz...${NC}"
    
    # Agregar IP a la interfaz
    if ip addr add $ip/24 dev $interfaz; then
        echo -e "${GREEN}✓ Comando ejecutado correctamente${NC}"
        
        # Verificar que se creó (con un pequeño retraso)
        sleep 1
        if ip addr show $interfaz | grep -q "$ip"; then
            echo -e "${GREEN}✓ IP virtual $ip creada y verificada exitosamente${NC}"
            
            # Hacer la configuración persistente
            local config_file="/etc/network/interfaces"
            
            # Verificar si ya existe la entrada para evitar duplicados
            if ! grep -q "up ip addr add $ip/24 dev $interfaz" "$config_file"; then
                echo "    up ip addr add $ip/24 dev $interfaz" >> "$config_file"
                echo "    down ip addr del $ip/24 dev $interfaz" >> "$config_file"
                echo -e "${GREEN}✓ Configuración persistente agregada${NC}"
            fi
            
            # Agregar al array global
            IPS_VIRTUALES+=("$ip")
            
            # Mostrar estado actual de la interfaz
            echo -e "\n${CYAN}Estado actual de $interfaz:${NC}"
            ip addr show $interfaz | grep "inet" | sed 's/^/  /'
            
            return 0
        else
            echo -e "${RED}✗ ERROR: La IP $ip no aparece después de crearla${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Error al ejecutar comando ip addr add${NC}"
        return 1
    fi
}

# =========================
# FUNCIÓN PARA ELIMINAR IP VIRTUAL (MEJORADA)
# =========================

eliminar_ip_virtual() {
    local ip=$1
    local interfaz=$2
    
    echo -e "${CYAN}--- ELIMINANDO IP VIRTUAL: $ip ---${NC}"
    
    if ip addr show $interfaz | grep -q "$ip"; then
        echo -e "${YELLOW}➜ Eliminando IP virtual: $ip de $interfaz...${NC}"
        
        if ip addr del $ip/24 dev $interfaz; then
            echo -e "${GREEN}✓ IP virtual $ip eliminada${NC}"
            
            # Eliminar del archivo de configuración
            sed -i "/up ip addr add $ip\/24 dev $interfaz/d" /etc/network/interfaces
            sed -i "/down ip addr del $ip\/24 dev $interfaz/d" /etc/network/interfaces
            
            echo -e "${GREEN}✓ Configuración persistente eliminada${NC}"
            
            # Mostrar estado actual
            echo -e "\n${CYAN}Estado actual de $interfaz:${NC}"
            ip addr show $interfaz | grep "inet" | sed 's/^/  /'
            
            return 0
        else
            echo -e "${RED}✗ Error al eliminar IP virtual $ip${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠ La IP $ip no existe en $interfaz${NC}"
        return 0
    fi
}

# =========================
# 1. GESTIÓN DE PAQUETES
# =========================

verificar_instalacion() {
    echo -e "\n${CYAN}--- VERIFICANDO PAQUETES INSTALADOS (DEVUAN) ---${NC}"
    
    if dpkg -s isc-dhcp-server >/dev/null 2>&1; then 
        echo -e "${GREEN}[OK] DHCP Server${NC}"
        if [ -f "/etc/init.d/isc-dhcp-server" ]; then
            echo -e "      ${GREEN}✓ Script de inicio encontrado${NC}"
        fi
    else 
        echo -e "${RED}[X] DHCP Server NO instalado${NC}"
    fi
    
    if dpkg -s bind9 >/dev/null 2>&1; then 
        echo -e "${GREEN}[OK] DNS Server (BIND9)${NC}"
        if [ -f "/etc/init.d/bind9" ] || [ -f "/etc/init.d/named" ]; then
            echo -e "      ${GREEN}✓ Script de inicio encontrado${NC}"
        fi
    else 
        echo -e "${RED}[X] DNS Server NO instalado${NC}"
    fi
    
    # Mostrar IPs virtuales actuales
    echo -e "\n${CYAN}IPs configuradas en $INTERFACE:${NC}"
    ip addr show $INTERFACE | grep "inet" | awk '{print "   " $2}'
    
    read -p "Presiona Enter para continuar..."
}

instalar_roles() {
    echo -e "${YELLOW}Actualizando e instalando paquetes (DEVUAN)...${NC}"
    apt-get update
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y isc-dhcp-server bind9 bind9utils dnsutils net-tools iptables
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Instalación completada.${NC}"
        
        # Verificar scripts de inicio
        if [ -f "/etc/init.d/isc-dhcp-server" ]; then
            update-rc.d isc-dhcp-server defaults > /dev/null 2>&1
        fi
        
        if [ -f "/etc/init.d/bind9" ]; then
            update-rc.d bind9 defaults > /dev/null 2>&1
        elif [ -f "/etc/init.d/named" ]; then
            update-rc.d named defaults > /dev/null 2>&1
        fi
    else
        echo -e "${RED}Error en la instalación.${NC}"
    fi
    
    configurar_firewall_ping
    read -p "Presiona Enter para continuar..."
}

# =========================
# 2. IP ESTÁTICA PRINCIPAL
# =========================

configurar_ip_estatica() {
    CURRENT_IP=$(obtener_ip_actual)
    echo -e "\n${YELLOW}--- CONFIGURACIÓN IP ESTÁTICA ($INTERFACE) ---${NC}"
    echo "IP Actual: ${CURRENT_IP:-Ninguna}"
    
    read -p "¿Configurar IP ESTATICA nueva? (s/n): " resp
    if [[ "$resp" == "s" ]]; then
        local nueva_ip=""
        
        while true; do
            read -p "Ingrese IP Estática: " nueva_ip
            validar_ip_completa "$nueva_ip"
            res=$?
            if [ $res -eq 0 ]; then
                break
            elif [ $res -eq 2 ]; then
                echo -e "${RED}Error: IP Prohibida o Reservada.${NC}"
            else
                echo -e "${RED}Error: Formato inválido.${NC}"
            fi
        done

        echo -e "${CYAN}Aplicando configuración...${NC}"
        
        cp /etc/network/interfaces /etc/network/interfaces.bak 2>/dev/null
        
        cat > /etc/network/interfaces <<EOF
# Configuración de red - Devuan
# Generado automáticamente por gestor-infraestructura

auto lo
iface lo inet loopback

allow-hotplug eth0
iface eth0 inet dhcp

auto $INTERFACE
iface $INTERFACE inet static
    address $nueva_ip
    netmask 255.255.255.0
EOF

        ip addr flush dev $INTERFACE
        ip addr add $nueva_ip/24 dev $INTERFACE
        ip link set $INTERFACE up
        
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        
        configurar_firewall_ping
        
        echo -e "${GREEN}IP $nueva_ip asignada a $INTERFACE.${NC}"
    fi
}

# =========================
# 3. CONFIGURACIÓN DHCP
# =========================

configurar_dhcp() {
    SERVER_IP=$(obtener_ip_actual)
    if [ -z "$SERVER_IP" ]; then 
        echo -e "${RED}¡ALERTA! Configura la IP Estática primero.${NC}"
        return
    fi

    echo -e "\n${YELLOW}--- CONFIGURAR SERVIDOR DHCP (PARA CLIENTES WINDOWS) ---${NC}"
    read -p "Nombre del Ámbito DHCP (ej. Red_Windows): " scope_name
    
    local ip_ini=""
    while true; do
        read -p "IP Inicial del rango (para clientes Windows): " ip_ini
        validar_ip_completa "$ip_ini"
        if [ $? -eq 0 ]; then break; fi
        echo -e "${RED}IP inválida o prohibida.${NC}"
    done

    local ip_fin=""
    while true; do
        read -p "IP Final del rango: " ip_fin
        validar_ip_completa "$ip_fin"
        if [ $? -eq 0 ]; then break; fi
        echo -e "${RED}IP inválida o prohibida.${NC}"
    done
    
    local gateway=""
    while true; do
        read -p "Gateway para clientes (Enter para omitir): " input_gw
        if [ -z "$input_gw" ]; then 
            gateway=""; break
        fi
        validar_ip_completa "$input_gw"
        if [ $? -eq 0 ]; then 
            gateway=$input_gw; break
        fi
        echo -e "${RED}IP inválida o prohibida.${NC}"
    done

    local lease_time=""
    while true; do
        read -p "Tiempo concesión (segundos) [Enter=86400]: " input_lease
        if [ -z "$input_lease" ]; then 
            lease_time=86400; break
        fi
        if [[ "$input_lease" =~ ^[0-9]+$ ]] && [ "$input_lease" -gt 0 ]; then
            lease_time=$input_lease; break
        else
            echo -e "${RED}Error: Debe ser un número entero positivo.${NC}"
        fi
    done
    
    SUBNET=$(echo $SERVER_IP | cut -d'.' -f1-3).0
    BROADCAST="${SUBNET%.*}.255"
    
    echo -e "${CYAN}Generando configuración DHCP...${NC}"
    
    if [ -f "/etc/default/isc-dhcp-server" ]; then
        sed -i 's/^INTERFACESv4=.*/INTERFACESv4="'$INTERFACE'"/' /etc/default/isc-dhcp-server
    else
        echo "INTERFACESv4=\"$INTERFACE\"" > /etc/default/isc-dhcp-server
    fi
    
    cat > /etc/dhcp/dhcpd.conf <<EOF
# Configuración DHCP para clientes Windows
# Ámbito: $scope_name
# Generado: $(date)

option subnet-mask 255.255.255.0;
option broadcast-address $BROADCAST;
option netbios-name-servers $SERVER_IP;
option netbios-node-type 8;

default-lease-time $lease_time;
max-lease-time $((lease_time * 2));
authoritative;

subnet $SUBNET netmask 255.255.255.0 {
    range $ip_ini $ip_fin;
    option domain-name-servers $SERVER_IP;
    option domain-name "lab.local";
EOF

    if [ ! -z "$gateway" ]; then
        echo "    option routers $gateway;" >> /etc/dhcp/dhcpd.conf
    fi

    echo "}" >> /etc/dhcp/dhcpd.conf
    
    echo -e "${YELLOW}Reiniciando servicio DHCP...${NC}"
    /etc/init.d/isc-dhcp-server restart
    sleep 3
    
    if /etc/init.d/isc-dhcp-server status > /dev/null 2>&1; then
        echo -e "${GREEN}>>> SERVIDOR DHCP CONFIGURADO CORRECTAMENTE <<<${NC}"
    else
        echo -e "${RED}FALLO: El servicio DHCP no arrancó.${NC}"
        tail -30 /var/log/syslog | grep -i "dhcpd\|dhcp" | tail -10
    fi
}

# =========================
# FUNCIONES PARA GESTIONAR SERVICIO DNS
# =========================

reiniciar_servicio_dns() {
    echo -e "${YELLOW}Reiniciando servicio DNS...${NC}"
    
    if [ -f "/etc/init.d/bind9" ]; then
        /etc/init.d/bind9 restart
        sleep 2
        return 0
    elif [ -f "/etc/init.d/named" ]; then
        /etc/init.d/named restart
        sleep 2
        return 0
    elif pgrep named > /dev/null; then
        pkill -HUP named
        sleep 2
        return 0
    fi
    
    return 1
}

# =========================
# 4. GESTIÓN DNS (CON IPS VIRTUALES AUTOMÁTICAS - VERSIÓN CORREGIDA)
# =========================

agregar_zona() {
    SERVER_IP=$(obtener_ip_actual)
    if [ -z "$SERVER_IP" ]; then 
        SERVER_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        [ -z "$SERVER_IP" ] && SERVER_IP="10.0.0.1"
    fi
    
    echo -e "\n${YELLOW}--- AGREGAR ZONA DNS (CON IP VIRTUAL AUTOMÁTICA) ---${NC}"
    echo -e "${CYAN}NOTA: Se creará automáticamente una IP virtual en el servidor para que responda al ping${NC}"
    
    read -p "Nombre del Dominio (ej. reprobados.com): " dominio
    [ -z "$dominio" ] && return
    
    local virtual_ip=""
    while true; do
        read -p "IP virtual para $dominio (ej. 10.0.0.6): " virtual_ip
        validar_ip_completa "$virtual_ip"
        if [ $? -eq 0 ]; then 
            # Verificar que no sea la IP del servidor
            if [ "$virtual_ip" == "$SERVER_IP" ]; then
                echo -e "${RED}Error: No puedes usar la IP del servidor ($SERVER_IP) como IP virtual${NC}"
                continue
            fi
            break 
        else
            echo -e "${RED}IP inválida o prohibida.${NC}"
        fi
    done
    
    # Crear IP virtual en el servidor (con verificación)
    echo -e "\n${CYAN}PASO 1: Creando IP virtual${NC}"
    if ! crear_ip_virtual "$virtual_ip" "$INTERFACE"; then
        echo -e "${RED}ERROR CRÍTICO: No se pudo crear la IP virtual. Abortando.${NC}"
        return 1
    fi
    
    # Verificación adicional
    echo -e "\n${CYAN}PASO 2: Verificando IP virtual${NC}"
    if ! ip addr show $INTERFACE | grep -q "$virtual_ip"; then
        echo -e "${RED}ERROR: La IP virtual $virtual_ip no aparece después de crearla.${NC}"
        echo -e "${YELLOW}Intentando crear nuevamente...${NC}"
        ip addr add $virtual_ip/24 dev $INTERFACE
        sleep 1
        if ! ip addr show $INTERFACE | grep -q "$virtual_ip"; then
            echo -e "${RED}ERROR FATAL: No se pudo crear la IP virtual.${NC}"
            return 1
        fi
    fi
    echo -e "${GREEN}✓ IP virtual verificada correctamente${NC}"
    
    # Configurar zona DNS
    echo -e "\n${CYAN}PASO 3: Configurando zona DNS${NC}"
    CONF="/etc/bind/named.conf.local"
    FILE="/var/cache/bind/db.$dominio"
    
    mkdir -p /var/cache/bind
    
    if [ -f "$CONF" ] && grep -q "$dominio" "$CONF" 2>/dev/null; then
        echo -e "${YELLOW}La zona ya existe.${NC}"
        read -p "¿Recrear? (s/n): " rec
        if [ "$rec" != "s" ]; then return; fi
        sed -i "/zone \"$dominio\" {/,/};/d" "$CONF"
    fi
    
    if [ ! -f "$CONF" ]; then
        touch "$CONF"
    fi
    
    cat >> "$CONF" <<EOF

zone "$dominio" {
    type master;
    file "$FILE";
};
EOF
    
    cat > "$FILE" <<EOF
; Archivo de zona para $dominio
; IP virtual creada: $virtual_ip
\$TTL 604800
@ IN SOA ns1.$dominio. admin.$dominio. (
    $(date +%Y%m%d)01   ; Serial
    604800              ; Refresh
    86400               ; Retry
    2419200             ; Expire
    604800 )            ; Negative Cache TTL

; Servidores de nombres
@ IN NS ns1.$dominio.
@ IN NS ns2.$dominio.

; Servidores DNS
ns1 IN A $SERVER_IP
ns2 IN A $SERVER_IP

; Registros del dominio (APUNTA A LA IP VIRTUAL)
@ IN A $virtual_ip
www IN CNAME @
mail IN A $virtual_ip
ftp IN A $virtual_ip

; Registro MX
@ IN MX 10 mail.$dominio.
EOF
    
    chown bind:bind "$FILE" 2>/dev/null || chmod 644 "$FILE"
    
    echo -e "\n${CYAN}PASO 4: Verificando configuración DNS${NC}"
    if command -v named-checkconf >/dev/null 2>&1; then
        named-checkconf "$CONF"
    fi
    
    if command -v named-checkzone >/dev/null 2>&1; then
        named-checkzone "$dominio" "$FILE"
    fi
    
    echo -e "\n${CYAN}PASO 5: Reiniciando servicio DNS${NC}"
    reiniciar_servicio_dns
    
    # Resumen final
    echo -e "\n${GREEN}✅ CONFIGURACIÓN COMPLETADA EXITOSAMENTE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo -e "  Dominio:        ${GREEN}$dominio${NC}"
    echo -e "  IP Virtual:     ${GREEN}$virtual_ip${NC}"
    echo -e "  Servidor DNS:   ${GREEN}$SERVER_IP${NC}"
    echo -e "  Interfaz:       ${GREEN}$INTERFACE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    
    echo -e "\n${YELLOW}PRUEBAS DESDE WINDOWS:${NC}"
    echo "  ping $virtual_ip      # ✅ Debe funcionar"
    echo "  ping $dominio         # ✅ Debe funcionar"
    echo "  nslookup $dominio     # ✅ Debe mostrar $virtual_ip"
    
    echo -e "\n${CYAN}ESTADO ACTUAL DE LA INTERFAZ:${NC}"
    ip addr show $INTERFACE | grep "inet" | sed 's/^/  /'
}

eliminar_zona() {
    echo -e "\n${YELLOW}--- ELIMINAR ZONA DNS ---${NC}"
    CONF="/etc/bind/named.conf.local"
    
    if [ -f "$CONF" ]; then
        echo "Zonas actuales:"
        grep "zone" "$CONF" | cut -d'"' -f2
    else
        echo "No hay archivo de configuración."
        return
    fi
    
    read -p "Nombre EXACTO de la zona a borrar: " zona_del
    [ -z "$zona_del" ] && return
    
    if grep -q "$zona_del" "$CONF"; then
        # Extraer IP virtual del archivo de zona antes de borrar
        archivo="/var/cache/bind/db.$zona_del"
        if [ -f "$archivo" ]; then
            virtual_ip=$(grep -E "^@\s+IN\s+A" "$archivo" | awk '{print $4}')
            if [ -n "$virtual_ip" ]; then
                echo -e "${CYAN}Eliminando IP virtual asociada: $virtual_ip${NC}"
                eliminar_ip_virtual "$virtual_ip" "$INTERFACE"
            fi
        fi
        
        cp "$CONF" "$CONF.bak"
        sed -i "/zone \"$zona_del\" {/,/};/d" "$CONF"
        rm -f "$archivo"
        
        reiniciar_servicio_dns
        echo -e "${GREEN}Zona eliminada.${NC}"
    else
        echo -e "${RED}Zona no encontrada.${NC}"
    fi
}

listar_zonas() {
    echo -e "\n${CYAN}--- DOMINIOS CONFIGURADOS ---${NC}"
    if [ -f "/etc/bind/named.conf.local" ] && grep -q "zone" "/etc/bind/named.conf.local"; then
        while IFS= read -r line; do
            if [[ "$line" =~ zone\ \"([^\"]+)\" ]]; then
                dominio="${BASH_REMATCH[1]}"
                archivo="/var/cache/bind/db.$dominio"
                if [ -f "$archivo" ]; then
                    ip_virtual=$(grep -E "^@\s+IN\s+A" "$archivo" | awk '{print $4}')
                    echo "  - $dominio → $ip_virtual (IP virtual)"
                else
                    echo "  - $dominio"
                fi
            fi
        done < "/etc/bind/named.conf.local"
    else
        echo "No hay zonas configuradas."
    fi
    
    echo -e "\n${CYAN}IPs activas en $INTERFACE:${NC}"
    ip addr show $INTERFACE | grep "inet" | awk '{print "   " $2}' || echo "   No hay IPs"
    
    read -p "Enter para volver..."
}

submenu_dns() {
    while true; do
        clear
        echo -e "\n${CYAN}=== GESTIÓN DE DOMINIOS DNS (CON IPS VIRTUALES) ===${NC}"
        echo "1) Agregar Dominio (crea IP virtual automáticamente)"
        echo "2) Eliminar Dominio (elimina IP virtual asociada)"
        echo "3) Ver Dominios e IPs Virtuales"
        echo "4) Volver al Menú Principal"
        
        read -p "Seleccione opción: " subopc
        case $subopc in
            1) agregar_zona; read -p "Enter..." ;;
            2) eliminar_zona; read -p "Enter..." ;;
            3) listar_zonas ;;
            4) return ;;
            *) echo "Inválido" ;;
        esac
    done
}

# =========================
# 5. PRUEBAS
# =========================

ejecutar_pruebas() {
    SERVER_IP=$(obtener_ip_actual)
    echo -e "\n${CYAN}--- PRUEBAS DE RESOLUCIÓN ---${NC}"
    read -p "Dominio a probar (ej. reprobados.com): " dom
    if [ -z "$dom" ]; then return; fi
    
    echo -e "\n${YELLOW}[PRUEBA 1: NSLOOKUP desde Devuan]${NC}"
    nslookup "$dom" localhost
    
    echo -e "\n${YELLOW}[PRUEBA 2: PING desde Devuan al dominio]${NC}"
    ping -c 2 "$dom"
    
    echo -e "\n${YELLOW}[PRUEBA 3: Verificar IP virtual]${NC}"
    ip addr show $INTERFACE | grep "inet"
    
    echo -e "\n${CYAN}--- INSTRUCCIONES PARA CLIENTE WINDOWS ---${NC}"
    echo "1. Abre CMD como administrador"
    echo "2. Ejecuta: ipconfig /flushdns"
    echo "3. Prueba: ping $dom"
    echo "4. Prueba: nslookup $dom"
    
    read -p "Enter para continuar..."
}

# =========================
# MENU PRINCIPAL
# =========================

check_root
sed -i 's/\r$//' "$0" 2>/dev/null

seleccionar_interfaz
configurar_firewall_ping

echo -e "\n${CYAN}Sistema detectado:${NC} $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Devuan')"
echo -e "${CYAN}Interfaz interna:${NC} $INTERFACE"
echo -e "${CYAN}IP principal:${NC} $(obtener_ip_actual)"
sleep 2

while true; do
    echo -e "\n${YELLOW}=============================================${NC}"
    echo -e "${YELLOW}   GESTOR DEVUAN - CON IPS VIRTUALES        ${NC}"
    echo -e "${YELLOW}=============================================${NC}"
    echo -e "Interfaz: ${GREEN}$INTERFACE${NC}"
    echo -e "IP principal: ${GREEN}$(obtener_ip_actual)${NC}"
    echo -e "IPs virtuales: ${GREEN}$(ip addr show $INTERFACE | grep -c "inet" | awk '{print $1-1}')${NC}"
    echo ""
    echo "1) Verificar Instalación"
    echo "2) Instalar Roles (DHCP + DNS + iptables)"
    echo "3) Configurar IP Estática (principal)"
    echo "4) Configurar DHCP"
    echo "5) Gestión de Dominios DNS (con IPs virtuales) [CORREGIDO]"
    echo "6) Pruebas de Resolución"
    echo "7) Salir"
    
    read -p "Seleccione opción: " MAIN_OPC
    
    case $MAIN_OPC in
        1) verificar_instalacion ;;
        2) instalar_roles ;;
        3) configurar_ip_estatica ;;
        4) configurar_dhcp ;;
        5) submenu_dns ;;
        6) ejecutar_pruebas ;;
        7) exit 0 ;;
        *) echo "Opción inválida" ;;
    esac
done