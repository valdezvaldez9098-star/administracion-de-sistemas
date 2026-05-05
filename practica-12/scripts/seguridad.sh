#!/usr/bin/env bash
# =============================================================================
# seguridad.sh — Certificados TLS/SSL, DKIM y registros DNS
# =============================================================================

CERTS_DIR="${PROYECTO_DIR}/data/certs"
DKIM_DIR="${PROYECTO_DIR}/data/dkim"

# ─── Generar certificado autofirmado ─────────────────────────────────────────
generar_cert_autofirmado() {
    paso 1 "Generando certificado TLS autofirmado para ${DOMINIO}"
    mkdir -p "$CERTS_DIR"

    local cert_file="${CERTS_DIR}/mail.crt"
    local key_file="${CERTS_DIR}/mail.key"
    local csr_file="${CERTS_DIR}/mail.csr"
    local cnf_file="${CERTS_DIR}/openssl.cnf"

    if [ -f "$cert_file" ]; then
        advertencia "Certificado ya existe en ${cert_file}"
        echo -ne "  ¿Regenerar? [s/N]: "
        read -r resp
        [[ "$resp" =~ ^[sS]$ ]] || { info "Certificado no modificado."; return 0; }
    fi

    info "Generando configuración OpenSSL con SAN (Subject Alternative Names)..."
    cat > "$cnf_file" << CNF
[req]
default_bits       = 4096
default_md         = sha256
prompt             = no
encrypt_key        = no
distinguished_name = dn
req_extensions     = req_ext
x509_extensions    = v3_req

[dn]
C  = MX
ST = Sinaloa
L  = Guasave
O  = Reprobados Corp
OU = IT
CN = ${HOSTNAME_MAIL}

[req_ext]
subjectAltName = @alt_names

[v3_req]
subjectAltName = @alt_names
keyUsage       = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = ${DOMINIO}
DNS.2 = ${HOSTNAME_MAIL}
DNS.3 = smtp.${DOMINIO}
DNS.4 = imap.${DOMINIO}
CNF

    info "Generando clave privada RSA-4096..."
    openssl genrsa -out "$key_file" 4096 2>/dev/null
    exito "Clave privada: ${key_file}"

    info "Generando certificado autofirmado (válido 3 años)..."
    openssl req -new -x509 \
        -key "$key_file" \
        -out "$cert_file" \
        -days 1095 \
        -config "$cnf_file" 2>/dev/null
    exito "Certificado: ${cert_file}"

    # Permisos correctos
    chmod 600 "$key_file"
    chmod 644 "$cert_file"

    # Mostrar info del certificado
    echo ""
    info "Resumen del certificado generado:"
    openssl x509 -in "$cert_file" -noout -subject -issuer -dates 2>/dev/null \
        | while IFS= read -r linea; do echo "  $linea"; done

    echo ""
    exito "Certificado autofirmado listo. Los clientes deberán aceptar la excepción de seguridad."
}

# ─── Generar par de claves DKIM ───────────────────────────────────────────────
generar_dkim() {
    paso 2 "Generando claves DKIM (DomainKeys Identified Mail)"
    mkdir -p "$DKIM_DIR"

    local selector="mail"   # nombre del selector, puede ser cualquier string
    local priv_key="${DKIM_DIR}/${selector}.private"
    local pub_key="${DKIM_DIR}/${selector}.public"
    local dns_record="${DKIM_DIR}/dkim_dns_record.txt"

    if [ -f "$priv_key" ]; then
        advertencia "Claves DKIM ya existen."
        echo -ne "  ¿Regenerar? [s/N]: "
        read -r resp
        [[ "$resp" =~ ^[sS]$ ]] || { info "Claves no modificadas."; return 0; }
    fi

    info "Generando par de claves RSA-2048 para DKIM (selector: ${selector})..."
    openssl genrsa -out "$priv_key" 2048 2>/dev/null

    # Extraer clave pública en formato DER → Base64
    openssl rsa -in "$priv_key" -pubout -outform DER 2>/dev/null \
        | openssl base64 -A > "$pub_key"

    chmod 600 "$priv_key"
    chmod 644 "$pub_key"

    local pub_content
    pub_content=$(cat "$pub_key")

    # Generar el registro DNS TXT
    cat > "$dns_record" << DNS
; ══════════════════════════════════════════════════════════
; REGISTRO DNS TXT para DKIM — ${DOMINIO}
; Agrega este registro en tu servidor DNS / archivo hosts
; ══════════════════════════════════════════════════════════

${selector}._domainkey.${DOMINIO}. IN TXT "v=DKIM1; k=rsa; p=${pub_content}"

; NOTAS:
; - v=DKIM1        → versión del protocolo
; - k=rsa          → algoritmo
; - p=<clave>      → clave pública
; Selector usado: ${selector}
; Si usas docker-mailserver, coloca las claves en el volumen
; mail_dkim y el daemon opendkim las cargará automáticamente.
DNS

    exito "Clave privada: ${priv_key}"
    exito "Clave pública:  ${pub_key}"
    exito "Registro DNS:   ${dns_record}"

    echo ""
    info "Fragmento del registro DNS DKIM:"
    echo ""
    echo -e "  ${YELLOW}${selector}._domainkey.${DOMINIO}${RESET}"
    echo -e "  ${DIM}→ TXT: \"v=DKIM1; k=rsa; p=${pub_content:0:40}...\"${RESET}"
}

# ─── Mostrar todos los registros DNS necesarios ───────────────────────────────
mostrar_registros_dns() {
    paso 3 "Registros DNS requeridos para ${DOMINIO}"

    local ip="${IP_HOST:-192.168.56.10}"
    local pub_key_file="${DKIM_DIR}/mail.public"
    local dkim_val="(genera las claves DKIM primero — opción 2)"

    if [ -f "$pub_key_file" ]; then
        dkim_val=$(cat "$pub_key_file")
    fi

    echo ""
    echo -e "  ${BOLD}Para un entorno de laboratorio local, agrega estas líneas${RESET}"
    echo -e "  ${BOLD}en el archivo /etc/hosts de tu PC anfitriona:${RESET}"
    echo ""
    echo -e "  ${GREEN}${ip}  ${DOMINIO} mail.${DOMINIO} smtp.${DOMINIO} imap.${DOMINIO}${RESET}"
    echo ""
    echo -e "  ${DIM}────────────────────────────────────────────────────────────${RESET}"
    echo -e "  ${BOLD}Si tuvieras un servidor DNS real, agregarías:${RESET}"
    echo ""

    printf "  %-40s %-8s %-10s %s\n" "NOMBRE" "TTL" "TIPO" "VALOR"
    echo -e "  ${DIM}───────────────────────────────────────────────────────────────────${RESET}"
    printf "  %-40s %-8s %-10s %s\n" "${DOMINIO}." "3600" "A"    "${ip}"
    printf "  %-40s %-8s %-10s %s\n" "mail.${DOMINIO}." "3600" "A"  "${ip}"
    printf "  %-40s %-8s %-10s %s\n" "${DOMINIO}." "3600" "MX"   "10 mail.${DOMINIO}."
    printf "  %-40s %-8s %-10s %s\n" "${DOMINIO}." "3600" "TXT"  "\"v=spf1 a mx ip4:${ip} ~all\""
    printf "  %-40s %-8s %-10s %s\n" "mail._domainkey.${DOMINIO}." "3600" "TXT" "\"v=DKIM1; k=rsa; p=${dkim_val:0:20}...\""
    printf "  %-40s %-8s %-10s %s\n" "_dmarc.${DOMINIO}." "3600" "TXT" "\"v=DMARC1; p=quarantine; rua=mailto:postmaster@${DOMINIO}\""
    echo ""

    echo -e "  ${CYAN}Explicación de cada registro:${RESET}"
    echo -e "  ${BOLD}A${RESET}      → Asocia el nombre del dominio con la IP del servidor"
    echo -e "  ${BOLD}MX${RESET}     → Le dice al mundo qué servidor recibe correos de ${DOMINIO}"
    echo -e "  ${BOLD}SPF${RESET}    → Autoriza solo esta IP a enviar correos en nombre de ${DOMINIO}"
    echo -e "  ${BOLD}DKIM${RESET}   → Firma criptográfica para verificar autenticidad del remitente"
    echo -e "  ${BOLD}DMARC${RESET}  → Política de manejo cuando SPF/DKIM fallan"
}

# ─── Verificar certificados ───────────────────────────────────────────────────
verificar_certificados() {
    paso 1 "Verificando certificados en ${CERTS_DIR}"
    echo ""

    local cert="${CERTS_DIR}/mail.crt"
    local key="${CERTS_DIR}/mail.key"

    if [ ! -f "$cert" ]; then
        advertencia "No hay certificado en ${cert}. Genera uno primero."
        return 1
    fi

    exito "Certificado encontrado: ${cert}"

    echo ""
    info "Detalles del certificado:"
    openssl x509 -in "$cert" -noout -text 2>/dev/null \
        | grep -E "(Subject:|Issuer:|Not Before|Not After|DNS:)" \
        | while IFS= read -r linea; do echo "    $linea"; done

    echo ""
    info "Verificando que la clave coincide con el certificado..."
    local cert_md5 key_md5
    cert_md5=$(openssl x509 -noout -modulus -in "$cert" 2>/dev/null | openssl md5)
    key_md5=$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | openssl md5)

    if [ "$cert_md5" = "$key_md5" ]; then
        exito "La clave privada y el certificado coinciden correctamente"
    else
        error "¡La clave y el certificado NO coinciden! Regenera los certificados."
    fi

    # Días de validez restantes
    local expiry_date days_left
    expiry_date=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2)
    days_left=$(( ( $(date -d "$expiry_date" +%s) - $(date +%s) ) / 86400 ))

    if [ "$days_left" -gt 30 ]; then
        exito "Certificado válido por ${days_left} días más (expira: ${expiry_date})"
    elif [ "$days_left" -gt 0 ]; then
        advertencia "Certificado expira en ${days_left} días — renuévalo pronto"
    else
        error "¡Certificado EXPIRADO! Regenera con la opción 1."
    fi
}
