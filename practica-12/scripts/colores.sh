#!/usr/bin/env bash
# =============================================================================
# colores.sh — Utilidades de color, logging y salida formateada
# =============================================================================

# ─── Códigos ANSI ────────────────────────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"

BLACK="\033[30m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
WHITE="\033[37m"

BG_RED="\033[41m"
BG_GREEN="\033[42m"
BG_YELLOW="\033[43m"
BG_BLUE="\033[44m"

# ─── Funciones de mensaje ────────────────────────────────────────────────────

# info: mensaje informativo (azul)
info() {
    local msg="$*"
    echo -e "  ${BLUE}[INFO]${RESET} $msg"
    _log "INFO" "$msg"
}

# exito: operación completada correctamente (verde)
exito() {
    local msg="$*"
    echo -e "  ${GREEN}${BOLD}[✔ OK]${RESET} $msg"
    _log "OK" "$msg"
}

# advertencia: situación no crítica (amarillo)
advertencia() {
    local msg="$*"
    echo -e "  ${YELLOW}[AVISO]${RESET} $msg"
    _log "WARN" "$msg"
}

# error: fallo crítico (rojo)
error() {
    local msg="$*"
    echo -e "  ${RED}${BOLD}[ERROR]${RESET} $msg" >&2
    _log "ERROR" "$msg"
}

# paso: encabezado de sección numerada
paso() {
    local num="$1"
    local titulo="$2"
    echo ""
    echo -e "  ${CYAN}${BOLD}══ Paso $num: $titulo ${RESET}"
    echo -e "  ${DIM}────────────────────────────────────────────────${RESET}"
    _log "STEP" "Paso $num: $titulo"
}

# resultado_prueba: muestra resultado PASS/FAIL de pruebas
resultado_prueba() {
    local nombre="$1"
    local estado="$2"   # "PASS" o "FAIL"
    local detalle="${3:-}"
    if [[ "$estado" == "PASS" ]]; then
        echo -e "  ${BG_GREEN}${BLACK} PASS ${RESET} ${BOLD}$nombre${RESET}"
        [ -n "$detalle" ] && echo -e "         ${DIM}$detalle${RESET}"
        _log "PASS" "$nombre: $detalle"
    else
        echo -e "  ${BG_RED}${WHITE} FAIL ${RESET} ${BOLD}$nombre${RESET}"
        [ -n "$detalle" ] && echo -e "         ${RED}$detalle${RESET}"
        _log "FAIL" "$nombre: $detalle"
    fi
}

# tabla: dibuja una tabla simple de dos columnas
tabla() {
    local ancho=52
    echo -e "  ${DIM}┌$(printf '─%.0s' $(seq 1 $ancho))┐${RESET}"
    while IFS='|' read -r col1 col2; do
        printf "  ${DIM}│${RESET} %-20s ${DIM}│${RESET} %-27s ${DIM}│${RESET}\n" "$col1" "$col2"
    done
    echo -e "  ${DIM}└$(printf '─%.0s' $(seq 1 $ancho))┘${RESET}"
}

# ─── Log interno a archivo ────────────────────────────────────────────────────
_log() {
    local nivel="$1"
    local msg="$2"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    # LOG_FILE debe estar definido en el script que llama
    if [ -n "${LOG_FILE:-}" ]; then
        echo "[$ts] [$nivel] $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# ─── Verificar que se ejecuta como root ──────────────────────────────────────
requerir_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "Este script debe ejecutarse como root (usa: sudo $0)"
        exit 1
    fi
}

# ─── Verificar comando disponible ────────────────────────────────────────────
requerir_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        error "Comando no encontrado: '$cmd'. Instálalo antes de continuar."
        return 1
    fi
    return 0
}
