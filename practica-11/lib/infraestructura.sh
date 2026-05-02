#!/usr/bin/env bash
# =============================================================================
#  lib/infraestructura.sh
#  Funciones para gestionar el ciclo de vida del stack Docker Compose
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/docker/.env"

# ── Wrapper que elige entre 'docker compose' (v2) y 'docker-compose' ──────── #
_compose() {
    if docker compose version &>/dev/null 2>&1; then
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
    else
        docker-compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
    fi
}

# --------------------------------------------------------------------------- #
#  Valida que existan los archivos necesarios antes de operar
# --------------------------------------------------------------------------- #
_validar_archivos() {
    local fallo=0
    [[ ! -f "$COMPOSE_FILE" ]] && echo -e "${ERR} Falta docker-compose.yml. Ejecuta opción 3 primero." && fallo=1
    [[ ! -f "$ENV_FILE" ]]     && echo -e "${ERR} Falta .env. Ejecuta opción 2 primero."              && fallo=1
    return $fallo
}

# --------------------------------------------------------------------------- #
#  iniciar_stack
# --------------------------------------------------------------------------- #
iniciar_stack() {
    echo -e "\n${BOLD}=== Iniciando stack ===${RESET}\n"
    _validar_archivos || return 1

    echo -e "${INFO} Construyendo imágenes y levantando servicios..."
    _compose up -d --build

    echo -e "\n${INFO} Esperando que los servicios estén saludables (hasta 60 s)..."
    local intentos=0
    until _compose ps | grep -q "healthy" || [[ $intentos -ge 12 ]]; do
        sleep 5
        ((intentos++))
        echo -ne "  ${DIM}[$((intentos*5))s]${RESET}\r"
    done

    echo -e "\n"
    _compose ps
    echo -e "\n${OK} Stack iniciado.\n"
    mostrar_puertos
}

# --------------------------------------------------------------------------- #
#  detener_stack
# --------------------------------------------------------------------------- #
detener_stack() {
    echo -e "\n${BOLD}=== Deteniendo stack ===${RESET}\n"
    _validar_archivos || return 1
    _compose down
    echo -e "${OK} Stack detenido. Los volúmenes con datos persisten."
}

# --------------------------------------------------------------------------- #
#  reconstruir_stack
# --------------------------------------------------------------------------- #
reconstruir_stack() {
    echo -e "\n${BOLD}=== Reconstruyendo stack ===${RESET}\n"
    _validar_archivos || return 1
    echo -e "${WARN} Esto reconstruye las imágenes y reinicia todos los contenedores."
    echo -ne "¿Continuar? [s/N]: "
    read -r resp
    [[ "$resp" != "s" && "$resp" != "S" ]] && echo "Cancelado." && return

    _compose down
    _compose up -d --build --force-recreate
    echo -e "${OK} Stack reconstruido."
}

# --------------------------------------------------------------------------- #
#  ver_logs
# --------------------------------------------------------------------------- #
ver_logs() {
    echo -e "\n${BOLD}=== Logs en tiempo real (Ctrl+C para salir) ===${RESET}\n"
    _validar_archivos || return 1
    echo -e "${INFO} ¿Qué servicio quieres ver?"
    echo "  1) Todos"
    echo "  2) nginx-balanceador"
    echo "  3) app-interna"
    echo "  4) postgres"
    echo "  5) pgadmin"
    echo -ne "Opción [1]: "
    read -r srv

    case "$srv" in
        2) _compose logs -f nginx-balanceador ;;
        3) _compose logs -f app-interna ;;
        4) _compose logs -f postgres ;;
        5) _compose logs -f pgadmin ;;
        *) _compose logs -f ;;
    esac
}

# --------------------------------------------------------------------------- #
#  mostrar_ips
# --------------------------------------------------------------------------- #
mostrar_ips() {
    echo -e "\n${BOLD}=== Interfaces de red del servidor ===${RESET}\n"
    ip -4 addr show | awk '/inet / {
        split($2, a, "/")
        "ip -4 addr show " $NF " | grep -oP \"(?<=inet ).*(?=/)\"" | getline ip
        print "  Interfaz: " $NF "  →  IP: " a[1]
    }' 2>/dev/null || ip addr show

    echo ""
    echo -e "${CYAN}Para la prueba 11.3 (túnel SSH), usa la IP de la interfaz Host-Only${RESET}"
    echo -e "${DIM}(normalmente 192.168.56.x o la que configuraste en VirtualBox)${RESET}"
}

# --------------------------------------------------------------------------- #
#  mostrar_puertos
# --------------------------------------------------------------------------- #
mostrar_puertos() {
    echo -e "\n${BOLD}=== Resumen de puertos expuestos ===${RESET}\n"

    local nginx_port pgadmin_port pg_port
    if [[ -f "$ENV_FILE" ]]; then
        nginx_port=$(grep 'NGINX_PUBLIC_PORT' "$ENV_FILE" | cut -d= -f2)
        pgadmin_port=$(grep 'PGADMIN_LISTEN_PORT' "$ENV_FILE" | cut -d= -f2)
        pg_port=$(grep 'POSTGRES_PORT' "$ENV_FILE" | cut -d= -f2)
    fi

    echo -e "  ${GREEN}Puerto ${nginx_port:-80} (HTTP)${RESET}    → nginx balanceador    → PÚBLICO (expuesto al host)"
    echo -e "  ${RED}Puerto 5432 (PG)${RESET}        → PostgreSQL            → BLOQUEADO por firewall"
    echo -e "  ${RED}Puerto 80/pgAdmin${RESET}       → pgAdmin               → BLOQUEADO (solo vía túnel SSH)"
    echo -e ""
    echo -e "  ${YELLOW}Acceso a pgAdmin:${RESET}  ssh -L 8080:<ip_pgadmin_en_docker>:80 usuario@<ip_servidor>"
    echo -e "                     luego abre http://localhost:8080 en tu navegador local"
}
