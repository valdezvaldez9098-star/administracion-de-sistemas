#!/usr/bin/env bash
# =============================================================================
# docker_stack.sh — Instalación de Docker, generación y gestión del stack
# =============================================================================

# ─── Instalar dependencias del sistema ───────────────────────────────────────
instalar_dependencias() {
    paso 1 "Instalando dependencias del sistema en Devuan Daedalus"
    requerir_root

    local paquetes=(
        curl wget gnupg2 ca-certificates apt-transport-https
        software-properties-common openssl dnsutils net-tools
        swaks mailutils procmail cron rsync tar gzip
    )

    info "Actualizando lista de paquetes..."
    apt-get update -qq

    info "Instalando: ${paquetes[*]}"
    apt-get install -y "${paquetes[@]}" 2>&1 | grep -E "(Instalando|Installing|already)" || true

    exito "Dependencias instaladas correctamente"
}

# ─── Instalar Docker ─────────────────────────────────────────────────────────
instalar_docker() {
    paso 2 "Instalando Docker CE en Devuan Daedalus 5.0.1"
    requerir_root

    # Devuan Daedalus es compatible con Debian Bookworm
    local DOCKER_KEYRING="/etc/apt/keyrings/docker.gpg"
    local CODENAME="bookworm"   # Devuan Daedalus ≡ Debian Bookworm

    if command -v docker &>/dev/null; then
        advertencia "Docker ya está instalado: $(docker --version)"
        return 0
    fi

    info "Configurando repositorio Docker para Debian ${CODENAME}..."
    install -m 0755 -d /etc/apt/keyrings

    curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o "$DOCKER_KEYRING"
    chmod a+r "$DOCKER_KEYRING"

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=${DOCKER_KEYRING}] \
      https://download.docker.com/linux/debian ${CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

    # Habilitar e iniciar Docker (Devuan usa SysVinit)
    info "Habilitando servicio Docker (SysVinit)..."
    update-rc.d docker defaults 2>/dev/null || true
    /etc/init.d/docker start

    # Agregar usuario actual al grupo docker
    if [ -n "${SUDO_USER:-}" ]; then
        usermod -aG docker "$SUDO_USER"
        info "Usuario ${SUDO_USER} agregado al grupo docker"
        advertencia "Cierra sesión y vuelve a entrar para que el cambio de grupo surta efecto"
    fi

    exito "Docker instalado: $(docker --version)"
    exito "Docker Compose: $(docker compose version)"
}

# ─── Verificar Docker ─────────────────────────────────────────────────────────
verificar_docker() {
    paso 1 "Verificación de la instalación de Docker"
    echo ""

    local ok=true

    _check_cmd "docker" && exito "docker CLI disponible: $(docker --version)" || ok=false
    _check_cmd "docker compose" "docker compose version" && \
        exito "docker compose disponible: $(docker compose version)" || ok=false

    if /etc/init.d/docker status &>/dev/null 2>&1; then
        exito "Servicio docker: ACTIVO"
    else
        error "Servicio docker: INACTIVO — ejecuta: sudo /etc/init.d/docker start"
        ok=false
    fi

    # Prueba rápida
    if $ok; then
        info "Ejecutando prueba hello-world..."
        if docker run --rm hello-world 2>&1 | grep -q "Hello from Docker"; then
            exito "Docker funciona correctamente"
        else
            advertencia "El contenedor hello-world no respondió como esperado"
        fi
    fi
}

_check_cmd() {
    local cmd="${1}"
    command -v ${cmd%% *} &>/dev/null
}

# ─── Crear estructura de directorios ─────────────────────────────────────────
crear_estructura() {
    paso 1 "Creando estructura de directorios del proyecto"

    local dirs=(
        "${PROYECTO_DIR}/data/mail"
        "${PROYECTO_DIR}/data/mailstate"
        "${PROYECTO_DIR}/data/logs"
        "${PROYECTO_DIR}/data/certs"
        "${PROYECTO_DIR}/data/dkim"
        "${PROYECTO_DIR}/data/roundcube"
        "${PROYECTO_DIR}/data/mariadb"
        "${PROYECTO_DIR}/config"
        "${PROYECTO_DIR}/backups"
        "${PROYECTO_DIR}/logs"
    )

    for d in "${dirs[@]}"; do
        mkdir -p "$d"
        echo -e "  ${GREEN}✔${RESET} $d"
    done

    exito "Estructura creada correctamente"
}

# ─── Generar archivos de configuración ───────────────────────────────────────
generar_configs() {
    paso 2 "Generando archivos de configuración"

    _generar_env_file
    _generar_roundcube_config
    exito "Archivos de configuración generados"
}

_generar_env_file() {
    local env_file="${PROYECTO_DIR}/config/mailserver.env"
    info "Generando ${env_file}..."

    cat > "$env_file" << EOF
# ─── Configuración general ────────────────────────────────────────────────────
OVERRIDE_HOSTNAME=${HOSTNAME_MAIL}
DOMAINNAME=${DOMINIO}
POSTMASTER_ADDRESS=postmaster@${DOMINIO}

# ─── Características habilitadas ─────────────────────────────────────────────
ENABLE_DKIM=1
ENABLE_SPAMASSASSIN=1
ENABLE_CLAMAV=0
ENABLE_FAIL2BAN=0
ENABLE_POSTGREY=0
ENABLE_SASLAUTHD=0

# ─── TLS ─────────────────────────────────────────────────────────────────────
SSL_TYPE=self-signed
TLS_LEVEL=intermediate

# ─── Auth: permitir plaintext en conexiones internas Docker ──────────────────
DOVECOT_INET_PROTOCOLS=all

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_LEVEL=info
ENABLE_MAILLOG=1
EOF
    exito "Generado: ${env_file}"
}

_generar_roundcube_config() {
    local rc_dir="${PROYECTO_DIR}/config/roundcube"
    mkdir -p "$rc_dir"
    local rc_conf="${rc_dir}/config.inc.php"
    info "Generando ${rc_conf}..."

    # Generar clave DES aleatoria
    local des_key
    des_key=$(openssl rand -base64 24 | tr -d '\n')

    cat > "$rc_conf" << RCEOF
<?php
// ─── Configuración Roundcube para ${DOMINIO} ──────────────────────────────────

// Conexión IMAP — IP directa del mailserver en red Docker
\$config['imap_host'] = '172.28.0.10';
\$config['imap_port'] = 143;
\$config['imap_timeout'] = 10;
// Permitir auth sin SSL en red interna Docker
\$config['imap_conn_options'] = [
    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
];

// Conexión SMTP — IP directa del mailserver en red Docker
\$config['smtp_host'] = '172.28.0.10';
\$config['smtp_port'] = 587;
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['smtp_auth_type'] = 'PLAIN';
\$config['smtp_conn_options'] = [
    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
];

// Base de datos SQLite para preferencias
\$config['db_dsnw'] = 'sqlite:////var/roundcube/db/roundcube.db?mode=0646';

// Seguridad de sesión
\$config['des_key'] = '${des_key}';
\$config['session_lifetime'] = 15;
\$config['session_domain'] = '${DOMINIO}';

// Personalización institucional
\$config['product_name'] = 'Correo Corporativo ${DOMINIO}';
\$config['username_domain'] = '${DOMINIO}';
\$config['logo'] = '/skins/elastic/images/logo.svg';
\$config['support_url'] = '';

// Interfaz
\$config['language'] = 'es_ES';
\$config['timezone'] = 'America/Mexico_City';
\$config['skin'] = 'elastic';
\$config['default_charset'] = 'UTF-8';

// HTTP (sin forzar HTTPS — certificado autofirmado en laboratorio)
\$config['force_https'] = false;

// Tamaño máximo de adjuntos — 25 MB
\$config['max_message_size'] = '25M';

// Plugins habilitados
\$config['plugins'] = [
    'archive',
    'zipdownload',
];
RCEOF
    exito "Generado: ${rc_conf}"
}

# ─── Generar docker-compose.yml ───────────────────────────────────────────────
generar_compose() {
    paso 1 "Generando docker-compose.yml"

    local compose_file="${PROYECTO_DIR}/docker-compose.yml"
    local ip_host="${IP_HOST:-192.168.56.10}"

    info "IP del host: ${ip_host}"
    info "Dominio:     ${DOMINIO}"

    cat > "$compose_file" << COMPOSE
version: "3.8"

# =============================================================================
# Stack de Correo Privado Corporativo — ${DOMINIO}
# Tarea 12 & 13  ·  Devuan Daedalus 5.0.1
# =============================================================================

networks:
  mail_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

volumes:
  mail_data:
    name: mail_data
  mail_state:
    name: mail_state
  mail_logs:
    name: mail_logs
  mail_certs:
    name: mail_certs
  mail_dkim:
    name: mail_dkim
  roundcube_db:
    name: roundcube_db

services:

  # ──────────────────────────────────────────────────────────────────────────
  # MAILSERVER: Postfix + Dovecot + Rspamd + Fail2Ban + OpenDKIM
  # ──────────────────────────────────────────────────────────────────────────
  mailserver:
    image: ghcr.io/docker-mailserver/docker-mailserver:latest
    container_name: mailserver
    hostname: mail.${DOMINIO}
    domainname: ${DOMINIO}
    env_file: ./config/mailserver.env
    ports:
      - "${ip_host}:25:25"     # SMTP (recepción entre servidores)
      - "${ip_host}:143:143"   # IMAP (sin cifrado, sólo interno)
      - "${ip_host}:465:465"   # SMTPS (SMTP sobre SSL)
      - "${ip_host}:587:587"   # Submission (SMTP con STARTTLS)
      - "${ip_host}:993:993"   # IMAPS (IMAP sobre SSL)
    volumes:
      - mail_data:/var/mail
      - mail_state:/var/mail-state
      - mail_logs:/var/log/mail
      - mail_certs:/etc/letsencrypt
      - mail_dkim:/tmp/docker-mailserver/opendkim/keys
      - ./config/mailserver.env:/tmp/docker-mailserver/mailserver.env
      - ./data/certs:/etc/ssl/mailserver:ro
    networks:
      mail_network:
        ipv4_address: 172.28.0.10
    cap_add:
      - NET_ADMIN   # necesario para Fail2Ban (iptables)
      - SYS_PTRACE
    security_opt:
      - apparmor:unconfined
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "ss", "-lntp", "|", "grep", ":25"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  # ──────────────────────────────────────────────────────────────────────────
  # ROUNDCUBE: Portal webmail (PHP)
  # ──────────────────────────────────────────────────────────────────────────
  roundcube:
    image: roundcube/roundcubemail:latest
    container_name: roundcube
    depends_on:
      - mailserver
    ports:
      - "${ip_host}:80:80"
      - "${ip_host}:443:443"
    environment:
      - ROUNDCUBEMAIL_DEFAULT_HOST=mailserver
      - ROUNDCUBEMAIL_DEFAULT_PORT=143
      - ROUNDCUBEMAIL_SMTP_SERVER=mailserver
      - ROUNDCUBEMAIL_SMTP_PORT=587
      - ROUNDCUBEMAIL_DB_TYPE=sqlite
      - ROUNDCUBEMAIL_SKIN=elastic
      - ROUNDCUBEMAIL_UPLOAD_MAX_FILESIZE=25M
      - ROUNDCUBEMAIL_ASPELL_DICTS=es,en
    volumes:
      - roundcube_db:/var/roundcube/db
      - ./config/roundcube/config.inc.php:/var/roundcube/config/config.inc.php:ro
      - ./data/certs:/etc/ssl/roundcube:ro
    networks:
      - mail_network
    restart: unless-stopped

COMPOSE

    exito "Generado: ${compose_file}"
    info "Revisa el archivo antes de ejecutar: cat ${compose_file}"
}

# ─── Iniciar stack ────────────────────────────────────────────────────────────
iniciar_stack() {
    paso 1 "Iniciando el stack Docker Compose"
    requerir_cmd "docker"

    local compose_file="${PROYECTO_DIR}/docker-compose.yml"

    if [ ! -f "$compose_file" ]; then
        error "No existe docker-compose.yml. Genéralo primero (opción 1 en este menú)."
        return 1
    fi

    # Habilitar IP forwarding para comunicación entre contenedores
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

    info "Descargando imágenes y levantando servicios..."
    cd "$PROYECTO_DIR" && docker compose up -d

    echo ""
    info "Esperando que mailserver inicialice (45 seg)..."
    sleep 45

    # Crear cuentas de práctica automáticamente si no existen
    info "Verificando cuentas de correo..."
    if ! docker exec mailserver setup email list 2>/dev/null | grep -q "director@"; then
        info "Creando cuentas de práctica..."
        docker exec mailserver setup email add "director@${DOMINIO}" 'Director2024' 2>/dev/null || true
        docker exec mailserver setup email add "admin@${DOMINIO}" 'Admin2024' 2>/dev/null || true
        sleep 10
    else
        exito "Cuentas ya existen"
    fi

    # Asegurar que fail2ban esté detenido
    docker exec mailserver supervisorctl stop fail2ban 2>/dev/null || true

    estado_stack
    echo ""
    exito "Stack listo. Roundcube disponible en: http://${IP_HOST:-192.168.56.10}"
    info "Login: director@${DOMINIO} / Director2024"
}

# ─── Estado del stack ─────────────────────────────────────────────────────────
estado_stack() {
    paso 1 "Estado de los contenedores"
    echo ""
    cd "$PROYECTO_DIR" && docker compose ps 2>/dev/null || \
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
        error "No se pudo obtener el estado — ¿está Docker corriendo?"
}

# ─── Reiniciar stack ──────────────────────────────────────────────────────────
reiniciar_stack() {
    paso 1 "Reiniciando el stack"
    cd "$PROYECTO_DIR" && docker compose restart
    info "Esperando que los servicios inicien (30 seg)..."
    sleep 30
    docker exec mailserver supervisorctl stop fail2ban 2>/dev/null || true
    exito "Stack reiniciado"
}

# ─── Logs de contenedor específico ───────────────────────────────────────────
logs_contenedor() {
    echo -ne "\n  Nombre del contenedor [mailserver/roundcube]: "
    read -r cnt
    cnt="${cnt:-mailserver}"
    echo ""
    docker logs --tail 50 "$cnt" 2>&1 || error "Contenedor '${cnt}' no encontrado"
}

# ─── Detener stack ────────────────────────────────────────────────────────────
detener_stack() {
    paso 1 "Deteniendo y eliminando contenedores"
    cd "$PROYECTO_DIR" && docker compose down
    exito "Stack detenido"
}
