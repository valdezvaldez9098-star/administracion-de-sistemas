#!/usr/bin/env bash
# =============================================================================
# TAREA 12 & 13 — Infraestructura de Correo Privado Corporativo
# Devuan Daedalus 5.0.1 / Oracle VirtualBox
# Archivo principal: MENÚ MAESTRO DE FLUJO DE TRABAJO
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Variables de entorno globales ──────────────────────────────────────────
export PROYECTO_DIR="$SCRIPT_DIR"
export DOMINIO="${DOMINIO:-reprobados.com}"
export HOSTNAME_MAIL="mail.${DOMINIO}"
export IP_HOST=""          # se detecta automáticamente
export LOG_FILE="$SCRIPT_DIR/logs/instalacion.log"

# ─── Importar módulos ────────────────────────────────────────────────────────
source "$SCRIPT_DIR/scripts/colores.sh"
source "$SCRIPT_DIR/scripts/red.sh"
source "$SCRIPT_DIR/scripts/docker_stack.sh"
source "$SCRIPT_DIR/scripts/seguridad.sh"
source "$SCRIPT_DIR/scripts/cuentas.sh"
source "$SCRIPT_DIR/scripts/respaldos.sh"
source "$SCRIPT_DIR/scripts/pruebas.sh"

# ─── Banner ──────────────────────────────────────────────────────────────────
mostrar_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
 ╔══════════════════════════════════════════════════════════════════╗
 ║      SERVIDOR DE CORREO PRIVADO CORPORATIVO — Tarea 12/13       ║
 ║         Devuan Daedalus 5.0.1  ·  Docker  ·  Postfix            ║
 ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${RESET}"
    echo -e "  ${DIM}Dominio activo: ${WHITE}${DOMINIO}${RESET}   ${DIM}Host: ${WHITE}$(hostname)${RESET}"
    echo -e "  ${DIM}Directorio del proyecto: ${WHITE}${PROYECTO_DIR}${RESET}"
    echo ""
}

# ─── Menú principal ──────────────────────────────────────────────────────────
menu_principal() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ MENÚ PRINCIPAL ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  🌐  Configuración de Red y VirtualBox"
    echo -e "  ${GREEN}[2]${RESET}  🐳  Preparación del Sistema y Docker"
    echo -e "  ${GREEN}[3]${RESET}  🔒  Generación de Certificados TLS/SSL"
    echo -e "  ${GREEN}[4]${RESET}  📦  Desplegar Stack de Correo (Docker Compose)"
    echo -e "  ${GREEN}[5]${RESET}  👤  Gestión de Cuentas de Usuario"
    echo -e "  ${GREEN}[6]${RESET}  💾  Configurar Respaldos Automáticos"
    echo -e "  ${GREEN}[7]${RESET}  🧪  Ejecutar Pruebas de Aceptación"
    echo -e "  ${GREEN}[8]${RESET}  📋  Ver Logs del Sistema"
    echo -e "  ${GREEN}[9]${RESET}  🗑️   Detener y Limpiar Stack"
    echo -e "  ${GREEN}[0]${RESET}  ❌  Salir"
    echo ""
    echo -e "  ${DIM}──────────────────────────────────────────${RESET}"
    echo -ne "  ${BOLD}Selecciona una opción: ${RESET}"
    read -r opcion
    echo ""

    case "$opcion" in
        1) menu_red ;;
        2) menu_docker ;;
        3) menu_certificados ;;
        4) menu_stack ;;
        5) menu_cuentas ;;
        6) menu_respaldos ;;
        7) menu_pruebas ;;
        8) ver_logs ;;
        9) limpiar_stack ;;
        0) echo -e "\n  ${GREEN}¡Hasta luego!${RESET}\n"; exit 0 ;;
        *) advertencia "Opción inválida. Presiona Enter para continuar."; read -r; menu_principal ;;
    esac
}

# ─── Submenú: Red ─────────────────────────────────────────────────────────
menu_red() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ CONFIGURACIÓN DE RED ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  Detectar adaptadores de red actuales"
    echo -e "  ${GREEN}[2]${RESET}  Mostrar guía de configuración VirtualBox"
    echo -e "  ${GREEN}[3]${RESET}  Configurar IP estática en Devuan"
    echo -e "  ${GREEN}[4]${RESET}  Probar conectividad (ping al gateway)"
    echo -e "  ${GREEN}[0]${RESET}  ← Volver al menú principal"
    echo ""
    echo -ne "  ${BOLD}Selecciona: ${RESET}"
    read -r op
    case "$op" in
        1) detectar_adaptadores; pausa; menu_red ;;
        2) guia_virtualbox; pausa; menu_red ;;
        3) configurar_ip_estatica; pausa; menu_red ;;
        4) probar_conectividad; pausa; menu_red ;;
        0) menu_principal ;;
        *) menu_red ;;
    esac
}

# ─── Submenú: Docker ─────────────────────────────────────────────────────────
menu_docker() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ PREPARACIÓN DEL SISTEMA ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  Instalar dependencias del sistema"
    echo -e "  ${GREEN}[2]${RESET}  Instalar Docker y Docker Compose"
    echo -e "  ${GREEN}[3]${RESET}  Verificar instalación de Docker"
    echo -e "  ${GREEN}[4]${RESET}  Crear estructura de directorios del proyecto"
    echo -e "  ${GREEN}[5]${RESET}  Generar archivos de configuración base"
    echo -e "  ${GREEN}[0]${RESET}  ← Volver"
    echo ""
    echo -ne "  ${BOLD}Selecciona: ${RESET}"
    read -r op
    case "$op" in
        1) instalar_dependencias; pausa; menu_docker ;;
        2) instalar_docker; pausa; menu_docker ;;
        3) verificar_docker; pausa; menu_docker ;;
        4) crear_estructura; pausa; menu_docker ;;
        5) generar_configs; pausa; menu_docker ;;
        0) menu_principal ;;
        *) menu_docker ;;
    esac
}

# ─── Submenú: Certificados ────────────────────────────────────────────────────
menu_certificados() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ CERTIFICADOS TLS/SSL ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  Generar certificado autofirmado (desarrollo)"
    echo -e "  ${GREEN}[2]${RESET}  Generar claves DKIM para el dominio"
    echo -e "  ${GREEN}[3]${RESET}  Mostrar registros DNS necesarios (SPF, DKIM, MX)"
    echo -e "  ${GREEN}[4]${RESET}  Verificar certificados existentes"
    echo -e "  ${GREEN}[0]${RESET}  ← Volver"
    echo ""
    echo -ne "  ${BOLD}Selecciona: ${RESET}"
    read -r op
    case "$op" in
        1) generar_cert_autofirmado; pausa; menu_certificados ;;
        2) generar_dkim; pausa; menu_certificados ;;
        3) mostrar_registros_dns; pausa; menu_certificados ;;
        4) verificar_certificados; pausa; menu_certificados ;;
        0) menu_principal ;;
        *) menu_certificados ;;
    esac
}

# ─── Submenú: Stack ──────────────────────────────────────────────────────────
menu_stack() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ STACK DOCKER COMPOSE ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  Generar docker-compose.yml completo"
    echo -e "  ${GREEN}[2]${RESET}  Iniciar el stack (docker compose up)"
    echo -e "  ${GREEN}[3]${RESET}  Ver estado de los contenedores"
    echo -e "  ${GREEN}[4]${RESET}  Reiniciar el stack"
    echo -e "  ${GREEN}[5]${RESET}  Ver logs de un contenedor específico"
    echo -e "  ${GREEN}[0]${RESET}  ← Volver"
    echo ""
    echo -ne "  ${BOLD}Selecciona: ${RESET}"
    read -r op
    case "$op" in
        1) generar_compose; pausa; menu_stack ;;
        2) iniciar_stack; pausa; menu_stack ;;
        3) estado_stack; pausa; menu_stack ;;
        4) reiniciar_stack; pausa; menu_stack ;;
        5) logs_contenedor; pausa; menu_stack ;;
        0) menu_principal ;;
        *) menu_stack ;;
    esac
}

# ─── Submenú: Cuentas ─────────────────────────────────────────────────────────
menu_cuentas() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ GESTIÓN DE CUENTAS ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  Crear cuenta de correo"
    echo -e "  ${GREEN}[2]${RESET}  Listar cuentas existentes"
    echo -e "  ${GREEN}[3]${RESET}  Cambiar contraseña"
    echo -e "  ${GREEN}[4]${RESET}  Eliminar cuenta"
    echo -e "  ${GREEN}[5]${RESET}  Crear cuentas de práctica (director + admin)"
    echo -e "  ${GREEN}[0]${RESET}  ← Volver"
    echo ""
    echo -ne "  ${BOLD}Selecciona: ${RESET}"
    read -r op
    case "$op" in
        1) crear_cuenta; pausa; menu_cuentas ;;
        2) listar_cuentas; pausa; menu_cuentas ;;
        3) cambiar_password; pausa; menu_cuentas ;;
        4) eliminar_cuenta; pausa; menu_cuentas ;;
        5) crear_cuentas_practica; pausa; menu_cuentas ;;
        0) menu_principal ;;
        *) menu_cuentas ;;
    esac
}

# ─── Submenú: Respaldos ───────────────────────────────────────────────────────
menu_respaldos() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ RESPALDOS Y RECUPERACIÓN ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  Crear respaldo manual ahora"
    echo -e "  ${GREEN}[2]${RESET}  Instalar tarea programada (cron 24h)"
    echo -e "  ${GREEN}[3]${RESET}  Listar respaldos disponibles"
    echo -e "  ${GREEN}[4]${RESET}  Restaurar un respaldo"
    echo -e "  ${GREEN}[5]${RESET}  Verificar integridad de respaldos"
    echo -e "  ${GREEN}[0]${RESET}  ← Volver"
    echo ""
    echo -ne "  ${BOLD}Selecciona: ${RESET}"
    read -r op
    case "$op" in
        1) respaldo_manual; pausa; menu_respaldos ;;
        2) instalar_cron_respaldo; pausa; menu_respaldos ;;
        3) listar_respaldos; pausa; menu_respaldos ;;
        4) restaurar_respaldo; pausa; menu_respaldos ;;
        5) verificar_respaldos; pausa; menu_respaldos ;;
        0) menu_principal ;;
        *) menu_respaldos ;;
    esac
}

# ─── Submenú: Pruebas ─────────────────────────────────────────────────────────
menu_pruebas() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ PRUEBAS DE ACEPTACIÓN ════${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET}  Prueba 12.1 — Envío y recepción local"
    echo -e "  ${GREEN}[2]${RESET}  Prueba 12.2 — Auditoría de registros (logging)"
    echo -e "  ${GREEN}[3]${RESET}  Prueba 12.3 — Verificación Fail2Ban"
    echo -e "  ${GREEN}[4]${RESET}  Prueba 13.4 — Integridad de respaldo"
    echo -e "  ${GREEN}[5]${RESET}  Prueba 13.5 — Inicio de sesión Roundcube"
    echo -e "  ${GREEN}[6]${RESET}  Prueba 13.6 — Envío de adjuntos"
    echo -e "  ${GREEN}[7]${RESET}  Prueba 13.7 — Persistencia de preferencias"
    echo -e "  ${GREEN}[8]${RESET}  Ejecutar TODAS las pruebas"
    echo -e "  ${GREEN}[0]${RESET}  ← Volver"
    echo ""
    echo -ne "  ${BOLD}Selecciona: ${RESET}"
    read -r op
    case "$op" in
        1) prueba_12_1; pausa; menu_pruebas ;;
        2) prueba_12_2; pausa; menu_pruebas ;;
        3) prueba_12_3; pausa; menu_pruebas ;;
        4) prueba_13_4; pausa; menu_pruebas ;;
        5) prueba_13_5; pausa; menu_pruebas ;;
        6) prueba_13_6; pausa; menu_pruebas ;;
        7) prueba_13_7; pausa; menu_pruebas ;;
        8) ejecutar_todas_pruebas; pausa; menu_pruebas ;;
        0) menu_principal ;;
        *) menu_pruebas ;;
    esac
}

# ─── Ver logs ─────────────────────────────────────────────────────────────────
ver_logs() {
    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ REGISTROS DEL SISTEMA ════${RESET}\n"
    if [ -f "$LOG_FILE" ]; then
        tail -n 50 "$LOG_FILE" | while IFS= read -r linea; do
            echo "  $linea"
        done
    else
        advertencia "No hay archivo de log todavía en $LOG_FILE"
    fi
    pausa
    menu_principal
}

# ─── Limpiar stack ────────────────────────────────────────────────────────────
limpiar_stack() {
    mostrar_banner
    echo -e "${RED}${BOLD}  ⚠  ADVERTENCIA: Esto detendrá y eliminará los contenedores.${RESET}"
    echo -ne "  ¿Confirmas? [s/N]: "
    read -r conf
    if [[ "$conf" =~ ^[sS]$ ]]; then
        detener_stack
    else
        info "Operación cancelada."
    fi
    pausa
    menu_principal
}

# ─── Pausa helper ─────────────────────────────────────────────────────────────
pausa() {
    echo ""
    echo -ne "  ${DIM}Presiona Enter para continuar...${RESET}"
    read -r
}

# ─── Punto de entrada ─────────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/logs"
touch "$LOG_FILE"
menu_principal
