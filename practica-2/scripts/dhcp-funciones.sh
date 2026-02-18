#!/bin/bash

# ARCHIVO DE FUNCIONES PARA CONFIGURACION DE SERVIDOR DHCP EN DEVUAN

# VARIABLES GLOBALES COMPARTIDAS
SUBRED=""
MASCARA=""
GATEWAY=""
DNS_SERVER=""
INTERFAZ_DHCP="eth1"
NOMBRE_SCOPE="Red_Sistemas_DHCP"
TIEMPO_CONCESION="7200"
IP_SERVIDOR=""
IP_RANGO_INICIO=""
IP_RANGO_FIN=""
RED_OCTETOS=""
MASCARA_CIDR="24"
MAX_TIEMPO="14400"

# FUNCION: VERIFICAR ESTADO DE SERVICIO (DEVUAN)
verificar_estado_servicio() {
    local servicio=$1
    if /etc/init.d/$servicio status > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# FUNCION: VERIFICAR INSTALACION
verificar_instalacion() {
    echo ""
    echo "=== VERIFICANDO INSTALACION ==="
    if dpkg -l | grep -q "isc-dhcp-server"; then
        echo "OK isc-dhcp-server esta instalado"
        if which dhcpd > /dev/null 2>&1; then
            dhcpd --version 2>&1 | head -1
        fi
        if verificar_estado_servicio "isc-dhcp-server"; then
            echo "OK Servicio DHCP esta activo"
        else
            echo "ERROR Servicio DHCP NO esta activo"
        fi
        return 0
    else
        echo "ERROR isc-dhcp-server NO esta instalado"
        return 1
    fi
}

# FUNCION: CONVERTIR IP A NUMERO ENTERO
ip_to_num() {
    local ip=$1
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo $((a * 256**3 + b * 256**2 + c * 256 + d))
}

# FUNCION: CONVERTIR NUMERO A IP
num_to_ip() {
    local num=$1
    echo "$((num >> 24 & 255)).$((num >> 16 & 255)).$((num >> 8 & 255)).$((num & 255))"
}

# FUNCION: VALIDAR DIRECCION IP
validar_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ERROR: Formato de IP invalido: $ip"
        return 1
    fi
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    if [[ $i1 -lt 0 || $i1 -gt 255 || $i2 -lt 0 || $i2 -gt 255 || \
          $i3 -lt 0 || $i3 -gt 255 || $i4 -lt 0 || $i4 -gt 255 ]]; then
        echo "ERROR: Octetos fuera de rango: $ip"
        return 1
    fi
    if [[ "$ip" == "0.0.0.0" ]]; then
        echo "ERROR: IP PROHIBIDA: $ip (0.0.0.0 no se puede usar)"
        return 1
    fi
    if [[ $i1 -eq 127 ]] && [[ $i2 -eq 0 ]] && [[ $i3 -eq 0 ]] && [[ $i4 -ge 0 ]] && [[ $i4 -le 2 ]]; then
        echo "ERROR: IP PROHIBIDA: $ip (Rango de loopback 127.0.0.0-127.0.0.2 no se puede usar)"
        return 1
    fi
    if [[ "$ip" == "255.255.255.255" ]]; then
        echo "ERROR: IP PROHIBIDA: $ip (255.255.255.255 no se puede usar)"
        return 1
    fi
    if [[ $i4 -eq 0 ]]; then
        echo "ADVERTENCIA: $ip es una direccion de red"
    fi
    if [[ $i4 -eq 255 ]]; then
        echo "ADVERTENCIA: $ip es una direccion de broadcast"
    fi
    return 0
}

# FUNCION: VALIDAR RANGO DE IP
validar_rango_ip() {
    local inicio=$1
    local fin=$2
    
    if [[ -z "$inicio" || -z "$fin" ]]; then
        echo "ERROR: IP de inicio o fin no especificada"
        return 1
    fi
    
    local inicio_num=$(ip_to_num "$inicio")
    local fin_num=$(ip_to_num "$fin")
    
    if [[ -z "$inicio_num" || -z "$fin_num" ]]; then
        echo "ERROR: No se pudo convertir las IPs a numero"
        return 1
    fi
    
    if [[ $fin_num -lt $inicio_num ]]; then
        echo "ERROR: La IP final ($fin) es menor que la IP inicial ($inicio)"
        return 1
    fi
    
    return 0
}

# FUNCION: CALCULAR RED A PARTIR DE IP Y MASCARA
calcular_red() {
    local ip=$1
    local mascara=$2
    
    if [[ -z "$ip" || -z "$mascara" ]]; then
        return 1
    fi
    
    local ip_num=$(ip_to_num "$ip")
    local mascara_num=$(ip_to_num "$mascara")
    local red_num=$((ip_num & mascara_num))
    
    echo "$(num_to_ip $red_num)"
}

# FUNCION: CALCULAR BROADCAST
calcular_broadcast() {
    local ip=$1
    local mascara=$2
    
    local ip_num=$(ip_to_num "$ip")
    local mascara_num=$(ip_to_num "$mascara")
    local red_num=$((ip_num & mascara_num))
    local broadcast_num=$((red_num | (~mascara_num & 0xFFFFFFFF)))
    
    echo "$(num_to_ip $broadcast_num)"
}

# FUNCION: VALIDAR SEGUNDOS
validar_segundos() {
    local segundos=$1
    if [[ ! "$segundos" =~ ^[0-9]+$ ]]; then
        echo "ERROR: El tiempo debe ser un numero entero sin decimales"
        return 1
    fi
    if [[ $segundos -lt 60 ]]; then
        echo "ERROR: El tiempo minimo es 60 segundos"
        return 1
    fi
    if [[ $segundos -gt 86400 ]]; then
        echo "ADVERTENCIA: Tiempo muy largo (maximo recomendado: 86400 segundos = 24 horas)"
        read -p "Continuar de todos modos? (s/n): " respuesta
        if [[ "$respuesta" != "s" && "$respuesta" != "S" ]]; then
            return 1
        fi
    fi
    return 0
}

# FUNCION: VALIDAR MASCARA DE RED
validar_mascara() {
    local mascara=$1
    
    if [[ ! $mascara =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ERROR: Formato de mascara invalido"
        return 1
    fi
    
    IFS='.' read -r m1 m2 m3 m4 <<< "$mascara"
    
    if [[ $m1 -lt 0 || $m1 -gt 255 || $m2 -lt 0 || $m2 -gt 255 || \
          $m3 -lt 0 || $m3 -gt 255 || $m4 -lt 0 || $m4 -gt 255 ]]; then
        echo "ERROR: Octetos de mascara fuera de rango"
        return 1
    fi
    
    local mascaras_validas=(
        "255.255.255.255" "255.255.255.254" "255.255.255.252" "255.255.255.248"
        "255.255.255.240" "255.255.255.224" "255.255.255.192" "255.255.255.128"
        "255.255.255.0"   "255.255.254.0"   "255.255.252.0"   "255.255.248.0"
        "255.255.240.0"   "255.255.224.0"   "255.255.192.0"   "255.255.128.0"
        "255.255.0.0"     "255.254.0.0"     "255.252.0.0"     "255.248.0.0"
        "255.240.0.0"     "255.224.0.0"     "255.192.0.0"     "255.128.0.0"
        "255.0.0.0"       "254.0.0.0"       "252.0.0.0"       "248.0.0.0"
        "240.0.0.0"       "224.0.0.0"       "192.0.0.0"       "128.0.0.0"
        "0.0.0.0"
    )
    
    local valida=1
    for m in "${mascaras_validas[@]}"; do
        if [[ "$mascara" == "$m" ]]; then
            valida=0
            break
        fi
    done
    
    if [[ $valida -eq 1 ]]; then
        echo "ERROR: Mascara de red no valida"
        return 1
    fi
    
    return 0
}

# FUNCION: CONFIGURAR INTERFAZ DE RED
configurar_interfaz() {
    local interfaz=$1
    local ip=$2
    local mascara=$3

    echo ""
    echo "=== CONFIGURANDO INTERFAZ DE RED ==="

    if ! ip link show $interfaz > /dev/null 2>&1; then
        echo "ERROR: La interfaz $interfaz no existe"
        echo ""
        echo "Interfaces disponibles:"
        echo "-----------------------"
        ip link show | grep "^[0-9]:" | awk '{print $2}' | tr -d ':'
        echo ""
        read -p "Ingrese el nombre de la interfaz a usar: " INTERFAZ_DHCP
        interfaz=$INTERFAZ_DHCP

        if ! ip link show $interfaz > /dev/null 2>&1; then
            echo "ERROR: La interfaz $interfaz tampoco existe"
            return 1
        fi
    fi

    echo "Configurando $interfaz con IP $ip mascara $mascara..."

    if ip link show $interfaz | grep -q "state DOWN"; then
        echo "Activando interfaz $interfaz..."
        ip link set $interfaz up
    fi

    local cidr=24
    case $mascara in
        "255.255.255.255") cidr=32 ;;
        "255.255.255.254") cidr=31 ;;
        "255.255.255.252") cidr=30 ;;
        "255.255.255.248") cidr=29 ;;
        "255.255.255.240") cidr=28 ;;
        "255.255.255.224") cidr=27 ;;
        "255.255.255.192") cidr=26 ;;
        "255.255.255.128") cidr=25 ;;
        "255.255.255.0")   cidr=24 ;;
        "255.255.254.0")   cidr=23 ;;
        "255.255.252.0")   cidr=22 ;;
        "255.255.248.0")   cidr=21 ;;
        "255.255.240.0")   cidr=20 ;;
        "255.255.224.0")   cidr=19 ;;
        "255.255.192.0")   cidr=18 ;;
        "255.255.128.0")   cidr=17 ;;
        "255.255.0.0")     cidr=16 ;;
        "255.254.0.0")     cidr=15 ;;
        "255.252.0.0")     cidr=14 ;;
        "255.248.0.0")     cidr=13 ;;
        "255.240.0.0")     cidr=12 ;;
        "255.224.0.0")     cidr=11 ;;
        "255.192.0.0")     cidr=10 ;;
        "255.128.0.0")     cidr=9 ;;
        "255.0.0.0")       cidr=8 ;;
        "254.0.0.0")       cidr=7 ;;
        "252.0.0.0")       cidr=6 ;;
        "248.0.0.0")       cidr=5 ;;
        "240.0.0.0")       cidr=4 ;;
        "224.0.0.0")       cidr=3 ;;
        "192.0.0.0")       cidr=2 ;;
        "128.0.0.0")       cidr=1 ;;
        "0.0.0.0")         cidr=0 ;;
    esac

    ip addr flush dev $interfaz 2>/dev/null
    ip addr add $ip/$cidr dev $interfaz
    ip link set $interfaz up

    if [ ! -d /etc/network/interfaces.d ]; then
        mkdir -p /etc/network/interfaces.d
    fi

    cat > /etc/network/interfaces.d/$interfaz << EOF
auto $interfaz
iface $interfaz inet static
    address $ip
    netmask $mascara
EOF

    echo "OK Interfaz $interfaz configurada"
    return 0
}

# FUNCION: INSTALAR SERVIDOR DHCP (DEVUAN) - COMPLETAMENTE SILENCIOSA
instalar_dhcp() {
    # Redirigir toda la salida a /dev/null para instalacion silenciosa
    {
        if dpkg -l | grep -q "isc-dhcp-server"; then
            if verificar_estado_servicio "isc-dhcp-server"; then
                /etc/init.d/isc-dhcp-server stop > /dev/null 2>&1
            fi
            DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y isc-dhcp-server > /dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get autoremove -y > /dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get autoclean -y > /dev/null 2>&1
        fi

        DEBIAN_FRONTEND=noninteractive apt-get update > /dev/null 2>&1
        
        cat > /usr/sbin/policy-rc.d << 'EOF'
#!/bin/sh
exit 101
EOF
        chmod +x /usr/sbin/policy-rc.d

        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq isc-dhcp-server > /dev/null 2>&1
        
        rm -f /usr/sbin/policy-rc.d

        if [ $? -eq 0 ]; then
            echo "INTERFACESv4=\"$INTERFAZ_DHCP\"" > /etc/default/isc-dhcp-server
            echo "INTERFACESv6=\"\"" >> /etc/default/isc-dhcp-server
            update-rc.d -f isc-dhcp-server remove > /dev/null 2>&1
            return 0
        else
            return 1
        fi
    } > /dev/null 2>&1
    
    # Devolver el codigo de salida
    return $?
}

# FUNCION: CONFIGURAR SERVIDOR DHCP
configurar_dhcp() {
    echo ""
    echo "=== CONFIGURACION DE PARAMETROS DHCP ==="

    read -p "Nombre del ambito [$NOMBRE_SCOPE]: " input_nombre
    NOMBRE_SCOPE=${input_nombre:-$NOMBRE_SCOPE}
    
    while true; do
        read -p "Mascara de subred [255.255.255.0]: " input_mascara
        MASCARA=${input_mascara:-"255.255.255.0"}
        if validar_mascara "$MASCARA"; then
            break
        fi
    done

    while true; do
        read -p "IP estatica del servidor: " IP_SERVIDOR
        if [ -z "$IP_SERVIDOR" ]; then
            echo "ERROR: La IP del servidor es obligatoria"
            continue
        fi
        if validar_ip "$IP_SERVIDOR"; then
            break
        fi
    done
    
    SUBRED=$(calcular_red "$IP_SERVIDOR" "$MASCARA")
    BROADCAST=$(calcular_broadcast "$IP_SERVIDOR" "$MASCARA")
    
    echo "Subred calculada: $SUBRED"
    echo "Broadcast calculado: $BROADCAST"
    
    IFS='.' read -r o1 o2 o3 o4 <<< "$IP_SERVIDOR"
    
    IP_RANGO_INICIO_SUG="$o1.$o2.$o3.$((o4 + 1))"
    IP_RANGO_FIN_SUG="$o1.$o2.$o3.150"
    
    if [[ "$MASCARA" != "255.255.255.0" ]]; then
        IP_RANGO_FIN_SUG="$o1.$o2.$o3.$((o4 + 50))"
    fi

    while true; do
        read -p "IP de inicio del rango DHCP [$IP_RANGO_INICIO_SUG]: " IP_RANGO_INICIO
        IP_RANGO_INICIO=${IP_RANGO_INICIO:-$IP_RANGO_INICIO_SUG}
        if validar_ip "$IP_RANGO_INICIO"; then
            if [[ "$IP_RANGO_INICIO" == "$IP_SERVIDOR" ]]; then
                echo "ERROR: La IP de inicio no puede ser igual a la IP del servidor"
                continue
            fi
            break
        fi
    done

    while true; do
        read -p "IP de fin del rango DHCP [$IP_RANGO_FIN_SUG]: " IP_RANGO_FIN
        IP_RANGO_FIN=${IP_RANGO_FIN:-$IP_RANGO_FIN_SUG}
        if validar_ip "$IP_RANGO_FIN"; then
            if validar_rango_ip "$IP_RANGO_INICIO" "$IP_RANGO_FIN"; then
                break
            fi
        fi
    done

    while true; do
        GATEWAY_SUG="$o1.$o2.$o3.1"
        read -p "Gateway (puerta de enlace) [$GATEWAY_SUG]: " input_gateway
        GATEWAY=${input_gateway:-$GATEWAY_SUG}
        if [ -z "$GATEWAY" ]; then
            echo "OK Sin gateway configurado"
            break
        elif validar_ip "$GATEWAY"; then
            break
        fi
    done

    while true; do
        read -p "Servidor DNS [8.8.8.8]: " input_dns
        DNS_SERVER=${input_dns:-"8.8.8.8"}
        if [ -z "$DNS_SERVER" ]; then
            echo "OK Sin DNS configurado"
            break
        elif validar_ip "$DNS_SERVER"; then
            break
        fi
    done

    while true; do
        read -p "Tiempo de concesion en segundos [$TIEMPO_CONCESION]: " input_tiempo
        input_tiempo=${input_tiempo:-$TIEMPO_CONCESION}
        if validar_segundos "$input_tiempo"; then
            TIEMPO_CONCESION=$input_tiempo
            MAX_TIEMPO=$((TIEMPO_CONCESION * 2))
            break
        fi
    done

    echo ""
    echo "=== RESUMEN DE CONFIGURACION ==="
    echo "Nombre del ambito:    $NOMBRE_SCOPE"
    echo "Interfaz:             $INTERFAZ_DHCP"
    echo "IP del servidor:      $IP_SERVIDOR"
    echo "Mascara de red:       $MASCARA"
    echo "Subred:               $SUBRED"
    echo "Broadcast:            $BROADCAST"
    echo "Rango DHCP:           $IP_RANGO_INICIO - $IP_RANGO_FIN"
    echo "Gateway:              ${GATEWAY:-No configurado}"
    echo "DNS:                  ${DNS_SERVER:-No configurado}"
    echo "Tiempo concesion:     $TIEMPO_CONCESION segundos"
    echo ""

    read -p "Continuar con la configuracion? (s/n): " respuesta
    if [[ "$respuesta" != "s" && "$respuesta" != "S" ]]; then
        echo "Configuracion cancelada."
        return 1
    fi

    if ! configurar_interfaz "$INTERFAZ_DHCP" "$IP_SERVIDOR" "$MASCARA"; then
        echo "ERROR: No se pudo configurar la interfaz de red"
        return 1
    fi

    echo ""
    echo "=== CONFIGURANDO SERVIDOR DHCP ==="

    echo "INTERFACESv4=\"$INTERFAZ_DHCP\"" > /etc/default/isc-dhcp-server
    echo "INTERFACESv6=\"\"" >> /etc/default/isc-dhcp-server

    cat > /etc/dhcp/dhcpd.conf << EOF
# Configuracion para: $NOMBRE_SCOPE
# Generado automaticamente
# Fecha: $(date)

option subnet-mask $MASCARA;
option broadcast-address $BROADCAST;

default-lease-time $TIEMPO_CONCESION;
max-lease-time $MAX_TIEMPO;

authoritative;

subnet $SUBRED netmask $MASCARA {
    range $IP_RANGO_INICIO $IP_RANGO_FIN;
EOF

    if [ -n "$GATEWAY" ]; then
        echo "    option routers $GATEWAY;" >> /etc/dhcp/dhcpd.conf
    fi

    if [ -n "$DNS_SERVER" ]; then
        echo "    option domain-name-servers $DNS_SERVER;" >> /etc/dhcp/dhcpd.conf
    fi

    echo "}" >> /etc/dhcp/dhcpd.conf

    echo "OK Archivo de configuracion creado: /etc/dhcp/dhcpd.conf"

    echo "Validando configuracion DHCP..."
    if dhcpd -t -cf /etc/dhcp/dhcpd.conf 2>/dev/null; then
        echo "OK Configuracion DHCP valida"
    else
        echo "ERROR: Configuracion DHCP invalida"
        dhcpd -t -cf /etc/dhcp/dhcpd.conf 2>&1
        return 1
    fi

    echo ""
    echo "=== INICIANDO SERVICIO DHCP ==="

    if verificar_estado_servicio "isc-dhcp-server"; then
        /etc/init.d/isc-dhcp-server stop > /dev/null 2>&1
    fi

    sleep 1
    echo "Iniciando servicio DHCP..."
    /etc/init.d/isc-dhcp-server start > /dev/null 2>&1

    sleep 2
    if verificar_estado_servicio "isc-dhcp-server" || ps aux | grep -v grep | grep -q dhcpd; then
        echo "OK Servicio DHCP iniciado correctamente"
        update-rc.d isc-dhcp-server defaults > /dev/null 2>&1
        echo "OK Servicio configurado para iniciar en el arranque"
    else
        echo "ADVERTENCIA: No se pudo iniciar el servicio normalmente"
        echo "Intentando iniciar manualmente..."
        dhcpd -4 -pf /var/run/dhcpd.pid -cf /etc/dhcp/dhcpd.conf $INTERFAZ_DHCP > /dev/null 2>&1 &
        sleep 1
        if ps aux | grep -v grep | grep -q dhcpd; then
            echo "OK Servicio iniciado manualmente"
        else
            echo "ERROR: No se pudo iniciar el servicio"
            return 1
        fi
    fi

    echo ""
    echo "=== CONFIGURANDO FIREWALL ==="

    if which iptables > /dev/null 2>&1; then
        echo "Configurando reglas de firewall para DHCP..."
        iptables -A INPUT -i $INTERFAZ_DHCP -p udp --dport 67:68 -j ACCEPT 2>/dev/null || true
        iptables -A OUTPUT -o $INTERFAZ_DHCP -p udp --dport 67:68 -j ACCEPT 2>/dev/null || true
        echo "OK Reglas de firewall configuradas"
    else
        echo "OK iptables no encontrado, omitiendo configuracion de firewall"
    fi

    echo ""
    echo "OK CONFIGURACION COMPLETADA EXITOSAMENTE"
    return 0
}

# FUNCION: MONITOREAR ESTADO
monitorear_estado() {
    echo ""
    echo "=== MONITOREO DEL SERVICIO DHCP ==="
    echo ""

    echo "1. ESTADO DEL SERVICIO:"
    if verificar_estado_servicio "isc-dhcp-server"; then
        echo "   OK Servicio DHCP activo"
        /etc/init.d/isc-dhcp-server status | head -3
    elif ps aux | grep -v grep | grep -q dhcpd; then
        echo "   OK Proceso DHCP activo (manual)"
        ps aux | grep -v grep | grep dhcpd | head -1
    else
        echo "   ERROR Servicio DHCP NO activo"
    fi

    echo ""
    echo "2. PUERTOS ESCUCHANDO:"
    if command -v netstat > /dev/null 2>&1 && netstat -tulpn 2>/dev/null | grep -q ":67 "; then
        echo "   OK Puerto 67 (DHCP) escuchando:"
        netstat -tulpn | grep ":67 " | head -2
    elif command -v ss > /dev/null 2>&1 && ss -tulpn 2>/dev/null | grep -q ":67 "; then
        echo "   OK Puerto 67 (DHCP) escuchando:"
        ss -tulpn | grep ":67 " | head -2
    else
        echo "   ERROR Puerto 67 NO escuchando"
    fi

    echo ""
    echo "3. CONCESIONES ACTIVAS:"
    if [ -f /var/lib/dhcp/dhcpd.leases ]; then
        if [ -s /var/lib/dhcp/dhcpd.leases ]; then
            echo "   OK Archivo de concesiones encontrado"
            local total_leases=$(grep -c "lease " /var/lib/dhcp/dhcpd.leases)
            echo "   Total de leases: $total_leases"
            local leases_activas=$(grep -c "binding state active" /var/lib/dhcp/dhcpd.leases)
            echo "   Leases activas: $leases_activas"
            echo ""
            echo "   Ultimas 5 concesiones:"
            echo "   -----------------------"
            grep -B1 -A4 "lease " /var/lib/dhcp/dhcpd.leases | tail -25
        else
            echo "   Archivo de concesiones vacio"
        fi
    else
        echo "   No hay archivo de concesiones"
    fi

    echo ""
    echo "4. LOGS RECIENTES:"
    local log_files=("/var/log/syslog" "/var/log/messages" "/var/log/daemon.log")
    local found_logs=0
    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            echo "   Logs desde $log_file:"
            echo "   -----------------------"
            grep -i "dhcp" "$log_file" 2>/dev/null | tail -5
            if [ $? -eq 0 ]; then
                found_logs=1
            fi
            break
        fi
    done
    if [ $found_logs -eq 0 ]; then
        echo "   No se encontraron logs DHCP recientes"
    fi

    echo ""
    echo "5. CONFIGURACION DE INTERFAZ $INTERFAZ_DHCP:"
    if ip link show $INTERFAZ_DHCP > /dev/null 2>&1; then
        ip addr show $INTERFAZ_DHCP | grep -A2 "inet "
    else
        echo "   ERROR Interfaz $INTERFAZ_DHCP no encontrada"
    fi

    echo ""
    read -p "Presione Enter para continuar..."
}

# FUNCION: MOSTRAR CONFIGURACION
mostrar_configuracion() {
    echo ""
    echo "=== CONFIGURACION ACTUAL ==="
    echo ""

    if [ -f /etc/dhcp/dhcpd.conf ]; then
        echo "Archivo de configuracion: /etc/dhcp/dhcpd.conf"
        echo "----------------------------------------------"
        grep -v "^#" /etc/dhcp/dhcpd.conf | grep -v "^$"
        echo ""
        echo "Configuracion de interfaz:"
        echo "--------------------------"
        if [ -f /etc/network/interfaces.d/$INTERFAZ_DHCP ]; then
            cat /etc/network/interfaces.d/$INTERFAZ_DHCP
        else
            echo "No hay configuracion persistente para $INTERFAZ_DHCP"
        fi
    else
        echo "No hay configuracion DHCP almacenada"
    fi

    echo ""
    read -p "Presione Enter para continuar..."
}

# FUNCION: REINSTALAR DHCP - VERSION COMPLETAMENTE SILENCIOSA
reinstalar_dhcp() {
    # Redirigir toda la salida a /dev/null para reinstalacion silenciosa
    {
        if dpkg -l | grep -q "isc-dhcp-server"; then
            /etc/init.d/isc-dhcp-server stop > /dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y isc-dhcp-server > /dev/null 2>&1
            rm -f /etc/dhcp/dhcpd.conf /etc/default/isc-dhcp-server
            rm -f /var/lib/dhcp/dhcpd.leases*
            rm -f /etc/network/interfaces.d/$INTERFAZ_DHCP 2>/dev/null
        fi
    } > /dev/null 2>&1

    instalar_dhcp
    return $?
}

# FUNCION: VERIFICAR DEPENDENCIAS
verificar_dependencias() {
    local missing_deps=0
    echo "Verificando dependencias del sistema..."
    for cmd in ip apt-get dpkg grep awk sed tr head tail cat which; do
        if ! command -v $cmd > /dev/null 2>&1; then
            echo "ERROR: Comando no encontrado: $cmd"
            missing_deps=1
        fi
    done
    if [ $missing_deps -eq 1 ]; then
        echo "ADVERTENCIA: Faltan comandos basicos"
        return 1
    fi
    echo "OK Todas las dependencias basicas estan instaladas"
    return 0
}

# FUNCION: LIMPIAR CARACTERES WINDOWS (UTILITARIA)
limpiar_archivo() {
    local archivo=$1
    if [ -f "$archivo" ]; then
        tr -d '\r' < "$archivo" > "${archivo}.tmp"
        mv "${archivo}.tmp" "$archivo"
        echo "OK Archivo $archivo limpiado de caracteres Windows"
    else
        echo "ERROR: Archivo no encontrado"
        return 1
    fi
}

# EXPORTAR FUNCIONES PARA QUE ESTEN DISPONIBLES
export -f verificar_estado_servicio
export -f verificar_instalacion
export -f ip_to_num
export -f num_to_ip
export -f validar_ip
export -f validar_rango_ip
export -f calcular_red
export -f calcular_broadcast
export -f validar_segundos
export -f validar_mascara
export -f configurar_interfaz
export -f instalar_dhcp
export -f configurar_dhcp
export -f monitorear_estado
export -f mostrar_configuracion
export -f reinstalar_dhcp
export -f verificar_dependencias
export -f limpiar_archivo

# VARIABLES EXPORTADAS
export SUBRED MASCARA GATEWAY DNS_SERVER INTERFAZ_DHCP NOMBRE_SCOPE
export TIEMPO_CONCESION IP_SERVIDOR IP_RANGO_INICIO IP_RANGO_FIN MAX_TIEMPO