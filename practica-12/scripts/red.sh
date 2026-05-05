#!/usr/bin/env bash
# =============================================================================
# red.sh — Configuración de red, adaptadores VirtualBox e IP estática en Devuan
# =============================================================================

# ─── Detectar adaptadores ────────────────────────────────────────────────────
detectar_adaptadores() {
    paso 1 "Adaptadores de red detectados"
    echo ""

    # Listar interfaces con ip
    local interfaces
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')

    printf "  %-18s %-20s %-18s %s\n" "INTERFAZ" "ESTADO" "IP ACTUAL" "MAC"
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────${RESET}"

    while IFS= read -r iface; do
        local estado ip_addr mac
        estado=$(ip link show "$iface" | grep -oP '(?<=state )\w+' || echo "UNKNOWN")
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+/\d+' || echo "sin IP")
        mac=$(ip link show "$iface" | awk '/ether/ {print $2}')
        printf "  %-18s %-20s %-18s %s\n" "$iface" "$estado" "$ip_addr" "$mac"
    done <<< "$interfaces"

    echo ""
    # Detectar la IP principal
    IP_HOST=$(hostname -I | awk '{print $1}')
    exito "IP principal del host: ${IP_HOST}"
    export IP_HOST
}

# ─── Guía VirtualBox ─────────────────────────────────────────────────────────
guia_virtualbox() {
    paso 1 "Guía de configuración de adaptadores en Oracle VirtualBox"
    echo ""
    echo -e "  ${BOLD}Esta práctica requiere DOS adaptadores de red en la VM:${RESET}"
    echo ""
    echo -e "  ${CYAN}ADAPTADOR 1 — NAT (acceso a Internet)${RESET}"
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo -e "  • En VirtualBox: Configuración → Red → Adaptador 1"
    echo -e "  • Tipo: ${YELLOW}NAT${RESET}"
    echo -e "  • Permite que la VM salga a Internet para descargar paquetes."
    echo -e "  • Interfaz en Devuan: ${GREEN}eth0${RESET} (normalmente 10.0.2.x)"
    echo ""
    echo -e "  ${CYAN}ADAPTADOR 2 — Red Solo-Anfitrión (comunicación host↔VM)${RESET}"
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo -e "  • En VirtualBox: Configuración → Red → Adaptador 2"
    echo -e "  • Tipo: ${YELLOW}Red solo-anfitrión (Host-Only)${RESET}"
    echo -e "  • Selecciona: ${YELLOW}vboxnet0${RESET} (créala si no existe)"
    echo -e "  • Interfaz en Devuan: ${GREEN}eth1${RESET}"
    echo -e "  • Esta IP es la que usarás para acceder a Roundcube y SMTP."
    echo ""
    echo -e "  ${CYAN}Cómo crear vboxnet0 en VirtualBox:${RESET}"
    echo -e "  ${DIM}────────────────────────────────────────${RESET}"
    echo -e "  1. Abre VirtualBox → Archivo → Administrador de Red"
    echo -e "  2. Clic en ${BOLD}Crear${RESET} → aparece ${GREEN}vboxnet0${RESET}"
    echo -e "  3. Configura: IP ${YELLOW}192.168.56.1${RESET} / Máscara ${YELLOW}255.255.255.0${RESET}"
    echo -e "  4. Deshabilita el servidor DHCP (usaremos IP estática)"
    echo -e "  5. La VM tomará la IP ${YELLOW}192.168.56.10${RESET} (configurada abajo)"
    echo ""
    echo -e "  ${BOLD}Resumen de IPs:${RESET}"
    echo "  HOST (tu PC)       → 192.168.56.1"   | tabla_linea
    echo "  VM Devuan (mail)   → 192.168.56.10"  | tabla_linea
    echo ""
    echo -e "  ${GREEN}Accede a Roundcube desde tu PC en: http://192.168.56.10${RESET}"
}

tabla_linea() {
    while IFS= read -r linea; do
        echo -e "  ${DIM}│${RESET} $linea"
    done
}

# ─── Configurar IP estática ───────────────────────────────────────────────────
configurar_ip_estatica() {
    paso 2 "Configurar IP estática en Devuan Daedalus (eth1)"
    requerir_root

    local iface="eth1"
    local ip_estatica="192.168.56.10"
    local mascara="24"
    local gateway_host="192.168.56.1"
    local interfaces_file="/etc/network/interfaces"

    info "Adaptador a configurar: ${iface}"
    info "IP estática objetivo:   ${ip_estatica}/${mascara}"
    echo ""

    # Verificar si ya está configurada
    if grep -q "$iface" "$interfaces_file" 2>/dev/null; then
        advertencia "Ya existe configuración para ${iface} en ${interfaces_file}"
        echo -ne "  ¿Sobreescribir? [s/N]: "
        read -r respuesta
        [[ "$respuesta" =~ ^[sS]$ ]] || { info "Sin cambios."; return 0; }
        # Eliminar configuración previa de eth1
        sed -i "/^auto ${iface}/,/^$/d" "$interfaces_file"
    fi

    # Agregar configuración
    cat >> "$interfaces_file" << EOF

# Adaptador Host-Only para el servidor de correo
auto ${iface}
iface ${iface} inet static
    address ${ip_estatica}/${mascara}
EOF

    exito "Configuración escrita en ${interfaces_file}"

    # Aplicar sin reiniciar
    info "Levantando la interfaz ${iface}..."
    if ifup "$iface" 2>/dev/null; then
        exito "Interfaz ${iface} activa con IP ${ip_estatica}"
    else
        advertencia "No se pudo levantar ${iface} automáticamente."
        info "Reinicia la VM o ejecuta: sudo ifup ${iface}"
    fi

    # Actualizar IP_HOST al nuevo valor
    export IP_HOST="$ip_estatica"
    info "Variable IP_HOST actualizada a: ${IP_HOST}"

    # Configurar /etc/hosts para el dominio local
    info "Actualizando /etc/hosts para ${DOMINIO}..."
    local entrada="${ip_estatica} ${DOMINIO} ${HOSTNAME_MAIL}"
    if grep -q "${DOMINIO}" /etc/hosts; then
        sed -i "/${DOMINIO}/d" /etc/hosts
    fi
    echo "$entrada" >> /etc/hosts
    exito "Entrada añadida: $entrada"
}

# ─── Probar conectividad ──────────────────────────────────────────────────────
probar_conectividad() {
    paso 3 "Prueba de conectividad"
    echo ""

    local gateway_nat="10.0.2.2"        # gateway NAT por defecto en VirtualBox
    local gateway_hostonly="192.168.56.1"
    local dns_externo="8.8.8.8"

    _ping_test "Gateway NAT (salida a Internet)" "$gateway_nat"
    _ping_test "Host anfitrión (Host-Only)"       "$gateway_hostonly"
    _ping_test "DNS externo (Google)"             "$dns_externo"

    # Probar resolución de nombres
    info "Resolución DNS..."
    if host docker.com &>/dev/null 2>&1 || nslookup docker.com &>/dev/null 2>&1; then
        exito "Resolución DNS funcional"
    else
        advertencia "Resolución DNS con problemas — revisa /etc/resolv.conf"
        echo -e "  ${DIM}Contenido actual de /etc/resolv.conf:${RESET}"
        cat /etc/resolv.conf 2>/dev/null | while read -r l; do echo "    $l"; done
    fi
}

_ping_test() {
    local nombre="$1"
    local host="$2"
    if ping -c 2 -W 2 "$host" &>/dev/null; then
        exito "$nombre ($host) — alcanzable"
    else
        error "$nombre ($host) — NO alcanzable"
    fi
}
