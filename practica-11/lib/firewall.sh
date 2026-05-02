#!/usr/bin/env bash
# =============================================================================
#  lib/firewall.sh
#  Configura UFW para bloquear acceso externo a pgAdmin y PostgreSQL
#  Permite solo SSH y el puerto del balanceador nginx
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$SCRIPT_DIR/docker/.env"

# Lee variables del .env si existe
_cargar_env() {
    if [[ -f "$ENV_FILE" ]]; then
        # shellcheck disable=SC1090
        set -o allexport
        source "$ENV_FILE"
        set +o allexport
    fi
}

# --------------------------------------------------------------------------- #
#  configurar_firewall
# --------------------------------------------------------------------------- #
configurar_firewall() {
    echo -e "\n${BOLD}=== Configurando firewall (UFW) ===${RESET}\n"
    _cargar_env

    local nginx_port="${NGINX_PUBLIC_PORT:-80}"
    local pg_port="${POSTGRES_PORT:-5432}"

    echo -e "${INFO} Configuración que se aplicará:"
    echo "  • Política por defecto: DENY (entrada)"
    echo "  • Permitir: SSH (22)"
    echo "  • Permitir: HTTP nginx público (${nginx_port})"
    echo "  • Bloquear: PostgreSQL (${pg_port})"
    echo "  • pgAdmin y app-interna no tienen puertos en el host → ya invisibles"
    echo ""
    echo -e "${WARN} NOTA: pgAdmin y PostgreSQL no exponen puertos al host en docker-compose.yml,"
    echo "       por lo que ya son inaccesibles externamente. Las reglas UFW añaden una capa extra."
    echo ""

    echo -ne "¿Aplicar estas reglas? [s/N]: "
    read -r resp
    [[ "$resp" != "s" && "$resp" != "S" ]] && echo "Cancelado." && return

    # Asegurar que UFW esté disponible
    if ! command -v ufw &>/dev/null; then
        echo -e "${ERR} UFW no instalado. Ejecuta opción 1 primero."
        return 1
    fi

    # Resetear estado previo no esencial
    ufw --force reset

    # Políticas base
    ufw default deny incoming
    ufw default allow outgoing

    # Reglas permitidas
    ufw allow 22/tcp    comment "SSH - acceso administrativo"
    ufw allow "${nginx_port}"/tcp comment "HTTP - nginx balanceador público"

    # Bloqueo explícito de puertos de base de datos (doble capa de seguridad)
    ufw deny "${pg_port}"/tcp comment "PostgreSQL - bloqueado; usar tunel SSH"

    # Activar UFW
    ufw --force enable

    echo -e "\n${OK} Firewall configurado."
    echo -e "${CYAN}Para acceder a pgAdmin, usa el túnel SSH (opción 13).${RESET}"

    ufw status numbered
}

# --------------------------------------------------------------------------- #
#  mostrar_firewall
# --------------------------------------------------------------------------- #
mostrar_firewall() {
    echo -e "\n${BOLD}=== Reglas de firewall activas ===${RESET}\n"
    if command -v ufw &>/dev/null; then
        ufw status verbose
    else
        echo -e "${WARN} UFW no disponible. Mostrando iptables:"
        iptables -L INPUT -n --line-numbers 2>/dev/null || echo "iptables no disponible."
    fi
}

# --------------------------------------------------------------------------- #
#  limpiar_firewall  (modo desarrollo / pruebas)
# --------------------------------------------------------------------------- #
limpiar_firewall() {
    echo -e "\n${BOLD}=== Limpiando reglas de firewall ===${RESET}\n"
    echo -e "${WARN} Esto desactiva UFW y permite todo el tráfico (solo para desarrollo)."
    echo -ne "¿Continuar? [s/N]: "
    read -r resp
    [[ "$resp" != "s" && "$resp" != "S" ]] && echo "Cancelado." && return

    ufw --force disable
    ufw --force reset
    echo -e "${OK} Firewall desactivado. Todos los puertos accesibles."
}
