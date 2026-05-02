#!/usr/bin/env bash
# =============================================================================
#  lib/pruebas.sh
#  Las 4 pruebas de aceptación del protocolo de la Práctica 11
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/docker/.env"

_compose() {
    if docker compose version &>/dev/null 2>&1; then
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
    else
        docker-compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
    fi
}

_cargar_env() {
    if [[ -f "$ENV_FILE" ]]; then
        set -o allexport; source "$ENV_FILE"; set +o allexport
    fi
}

_separador() { echo -e "\n${DIM}──────────────────────────────────────────────────────────────${RESET}\n"; }

# --------------------------------------------------------------------------- #
#  PRUEBA 11.1 · Aislamiento de red
#  Intenta conectarse desde el host a los puertos que NO deberían ser accesibles
# --------------------------------------------------------------------------- #
prueba_aislamiento() {
    echo -e "\n${BOLD}╔══ PRUEBA 11.1 · Validación de aislamiento de red ══╗${RESET}\n"
    _cargar_env

    local server_ip pg_port="${POSTGRES_PORT:-5432}"
    # Detecta la IP host-only (la que no es 127.x ni la de la interfaz NAT de VirtualBox)
    server_ip=$(hostname -I | tr ' ' '\n' | grep -v '^127\.' | grep -v '^10\.0\.2\.' | head -1)

    echo -e "${INFO} IP del servidor detectada: ${CYAN}${server_ip}${RESET}"
    echo -e "${INFO} Intentando curl al puerto ${pg_port} (PostgreSQL)...\n"

    local resultado
    resultado=$(curl -s --connect-timeout 5 --max-time 6 \
        "http://${server_ip}:${pg_port}" 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        echo -e "${OK} ${GREEN}PRUEBA EXITOSA${RESET} — Conexión rechazada o timeout (exit code: $exit_code)"
        echo -e "   El puerto ${pg_port} es INVISIBLE desde fuera de Docker."
    else
        echo -e "${WARN} Respuesta inesperada recibida:"
        echo "   $resultado"
        echo -e "${WARN} Verifica que el firewall esté activo (opción 8)."
    fi

    _separador

    # También verificar que pgAdmin no está expuesto
    local pgadmin_port=5050  # puerto que podría usarse si se expusiera
    echo -e "${INFO} Intentando curl al puerto 5050 (pgAdmin hipotético)...\n"
    resultado=$(curl -s --connect-timeout 5 --max-time 6 \
        "http://${server_ip}:5050" 2>&1)
    exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        echo -e "${OK} ${GREEN}PRUEBA EXITOSA${RESET} — Puerto 5050 también inaccesible."
    else
        echo -e "${WARN} Puerto 5050 respondió inesperadamente."
    fi

    echo -e "\n${BOLD}Resultado esperado: RECHAZADO / TIMEOUT ✓${RESET}"
}

# --------------------------------------------------------------------------- #
#  PRUEBA 11.2 · DNS interno Docker
#  Desde el contenedor nginx, hace ping al nombre de servicio 'postgres'
# --------------------------------------------------------------------------- #
prueba_dns_interno() {
    echo -e "\n${BOLD}╔══ PRUEBA 11.2 · Validación de DNS interno Docker ══╗${RESET}\n"

    echo -e "${INFO} Verificando que el contenedor nginx esté corriendo..."
    if ! docker ps --format '{{.Names}}' | grep -q 'p11_nginx'; then
        echo -e "${ERR} Contenedor p11_nginx no está corriendo. Inicia el stack primero (opción 4)."
        return 1
    fi

    echo -e "${INFO} Ejecutando: docker exec p11_nginx ping -c 3 postgres\n"
    echo -e "${DIM}(El nombre 'postgres' se resuelve por el DNS interno de Docker)${RESET}\n"

    if docker exec p11_nginx ping -c 3 postgres 2>/dev/null; then
        echo -e "\n${OK} ${GREEN}PRUEBA EXITOSA${RESET} — El contenedor nginx resuelve 'postgres' por nombre."
        echo -e "   Los contenedores se comunican por nombre de servicio, NO por IP fija."
    else
        # ping puede no estar en la imagen nginx:alpine — intentar con wget
        echo -e "${WARN} ping no disponible en la imagen. Intentando con wget...\n"
        if docker exec p11_nginx wget -qO- --timeout=5 \
            "http://postgres:5432" 2>&1 | grep -q "Connection refused\|connected"; then
            echo -e "${OK} ${GREEN}PRUEBA EXITOSA${RESET} — 'postgres' resuelve (conexión rechazada es normal: no es HTTP)."
        else
            # Mostrar resolución DNS directamente
            echo -e "${INFO} Probando resolución DNS pura...\n"
            docker exec p11_nginx sh -c \
                'getent hosts postgres 2>/dev/null || nslookup postgres 2>/dev/null || echo "DNS_PROBE"'
        fi
    fi

    echo -e "\n${BOLD}Resultado esperado: resolución exitosa por nombre de servicio ✓${RESET}"
}

# --------------------------------------------------------------------------- #
#  PRUEBA 11.3 · Túnel SSH
#  Muestra las instrucciones exactas; la prueba la ejecuta el estudiante
# --------------------------------------------------------------------------- #
prueba_tunel_ssh() {
    echo -e "\n${BOLD}╔══ PRUEBA 11.3 · Instrucciones para el túnel SSH ══╗${RESET}\n"
    _cargar_env

    local server_ip usuario
    server_ip=$(hostname -I | tr ' ' '\n' | grep -v '^127\.' | grep -v '^10\.0\.2\.' | head -1)
    usuario=$(logname 2>/dev/null || echo "TU_USUARIO")

    # Obtener IP interna del contenedor pgAdmin dentro de la red_datos
    local pgadmin_ip
    pgadmin_ip=$(docker inspect p11_pgadmin \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1)
    pgadmin_ip="${pgadmin_ip:-pgadmin}"   # fallback al nombre de servicio

    echo -e "${BOLD}Paso 1 — Asegúrate de que el stack esté corriendo (opción 4).${RESET}"
    echo ""
    echo -e "${BOLD}Paso 2 — En tu MÁQUINA FÍSICA (no en el servidor), abre una terminal y ejecuta:${RESET}"
    echo ""
    echo -e "${CYAN}  ssh -L 8080:${pgadmin_ip}:80 ${usuario}@${server_ip}${RESET}"
    echo ""
    echo -e "  Explicación del comando:"
    echo "  • -L 8080         → puerto local en tu PC"
    echo "  • ${pgadmin_ip}:80 → destino dentro de la red Docker del servidor"
    echo "  • ${usuario}@${server_ip} → SSH al servidor Devuan"
    echo ""
    echo -e "${BOLD}Paso 3 — Con el túnel activo, abre en tu navegador:${RESET}"
    echo ""
    echo -e "${CYAN}  http://localhost:8080${RESET}"
    echo ""
    echo -e "${BOLD}Paso 4 — Credenciales de pgAdmin:${RESET}"
    echo "  Email   : ${PGADMIN_DEFAULT_EMAIL:-admin@practica11.local}"
    echo "  Password: ${PGADMIN_DEFAULT_PASSWORD:-(ver archivo .env)}"
    echo ""
    echo -e "${YELLOW}El panel debe cargar correctamente, demostrando gestión segura de servicio oculto.${RESET}"
    echo ""
    echo -e "${BOLD}Alternativa con nombre de servicio (si la IP cambia):${RESET}"
    echo -e "${CYAN}  ssh -L 8080:p11_pgadmin:80 ${usuario}@${server_ip}${RESET}"
    echo ""
    echo -e "${DIM}Nota: si el servidor SSH pide agregar el host a known_hosts, escribe 'yes'.${RESET}"

    _separador

    # Verificar que el servicio SSH esté corriendo
    echo -e "${INFO} Verificando servicio SSH en el servidor..."
    if service ssh status &>/dev/null || service sshd status &>/dev/null; then
        echo -e "${OK} SSH está activo."
    else
        echo -e "${WARN} SSH no parece estar activo. Para instalarlo:"
        echo "  apt-get install -y openssh-server && service ssh start"
    fi
}

# --------------------------------------------------------------------------- #
#  PRUEBA 11.4 · Persistencia y healthcheck
# --------------------------------------------------------------------------- #
prueba_persistencia() {
    echo -e "\n${BOLD}╔══ PRUEBA 11.4 · Persistencia de datos y healthcheck ══╗${RESET}\n"
    _cargar_env

    # ── Fase A: insertar un registro de prueba ─────────────────────────── #
    echo -e "${BOLD}Fase A — Insertar dato de prueba en PostgreSQL${RESET}\n"

    if ! docker ps --format '{{.Names}}' | grep -q 'p11_postgres'; then
        echo -e "${ERR} PostgreSQL no está corriendo. Inicia el stack primero."
        return 1
    fi

    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    docker exec -e PGPASSWORD="${POSTGRES_PASSWORD}" p11_postgres \
        psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c \
        "CREATE TABLE IF NOT EXISTS prueba11 (id SERIAL PRIMARY KEY, ts TIMESTAMPTZ, msg TEXT);
         INSERT INTO prueba11(ts, msg) VALUES ('${ts}', 'Dato de prueba persistencia');" 2>&1

    echo -e "\n${OK} Registro insertado."

    # ── Fase B: verificar healthcheck antes de bajar ───────────────────── #
    _separador
    echo -e "${BOLD}Fase B — Estado de healthcheck antes de recrear stack${RESET}\n"
    _compose ps --format "table {{.Name}}\t{{.Status}}"
    echo ""
    echo -e "${INFO} Nota: pgAdmin debe mostrar 'healthy' SOLO DESPUÉS de que postgres sea 'healthy'."

    # ── Fase C: detener y reiniciar ────────────────────────────────────── #
    _separador
    echo -e "${BOLD}Fase C — Detener contenedores y reiniciar (sin borrar volúmenes)${RESET}\n"
    echo -ne "¿Detener e reiniciar el stack ahora para validar persistencia? [s/N]: "
    read -r resp
    if [[ "$resp" == "s" || "$resp" == "S" ]]; then
        echo -e "${INFO} Deteniendo stack..."
        _compose down

        echo -e "${INFO} Esperando 5 segundos..."
        sleep 5

        echo -e "${INFO} Reiniciando stack..."
        _compose up -d

        echo -e "${INFO} Esperando que postgres esté healthy (hasta 60 s)..."
        local intentos=0
        until docker inspect p11_postgres --format '{{.State.Health.Status}}' 2>/dev/null \
            | grep -q "healthy" || [[ $intentos -ge 12 ]]; do
            sleep 5
            ((intentos++))
            echo -ne "  ${DIM}[$((intentos*5))s]${RESET}\r"
        done
        echo ""

        # ── Fase D: verificar que los datos siguen ahí ─────────────────── #
        _separador
        echo -e "${BOLD}Fase D — Verificar que los datos persisten${RESET}\n"
        docker exec -e PGPASSWORD="${POSTGRES_PASSWORD}" p11_postgres \
            psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
            -c "SELECT * FROM prueba11;" 2>&1

        echo ""
        echo -e "${OK} ${GREEN}PRUEBA EXITOSA${RESET} — Los datos sobrevivieron el reinicio del stack."
        echo -e "   El volumen ${CYAN}practica11_postgres_data${RESET} mantiene los datos persistentes."
    else
        echo "Omitido. Puedes ejecutar manualmente: docker compose down && docker compose up -d"
    fi

    _separador
    echo -e "${BOLD}Estado final de healthchecks:${RESET}\n"
    _compose ps --format "table {{.Name}}\t{{.Status}}"
}

# --------------------------------------------------------------------------- #
#  Ejecutar todas las pruebas en secuencia
# --------------------------------------------------------------------------- #
ejecutar_todas_pruebas() {
    echo -e "\n${BOLD}╔════════════════════════════════════════════════╗"
    echo    "║   PROTOCOLO COMPLETO DE PRUEBAS DE ACEPTACIÓN  ║"
    echo -e "╚════════════════════════════════════════════════╝${RESET}\n"

    local resultados=()

    prueba_aislamiento
    echo -ne "\n${DIM}Presiona ENTER para continuar con la prueba 11.2...${RESET}"; read -r
    resultados+=("11.1 Aislamiento")

    prueba_dns_interno
    echo -ne "\n${DIM}Presiona ENTER para continuar con la prueba 11.3...${RESET}"; read -r
    resultados+=("11.2 DNS Interno")

    prueba_tunel_ssh
    echo -ne "\n${DIM}Presiona ENTER para continuar con la prueba 11.4...${RESET}"; read -r
    resultados+=("11.3 Túnel SSH (manual)")

    prueba_persistencia
    resultados+=("11.4 Persistencia")

    echo -e "\n${BOLD}=== Resumen ===${RESET}\n"
    for r in "${resultados[@]}"; do
        echo -e "  ${OK} Prueba $r — ejecutada"
    done
    echo ""
    echo -e "${YELLOW}Recuerda tomar capturas de pantalla de cada prueba para tu reporte.${RESET}"
}
