#!/usr/bin/env bash
# =============================================================================
#  PRÁCTICA 11 - MENÚ PRINCIPAL
#  Orquestación de microservicios, alta disponibilidad y túneles SSH
#  Devuan Daedalus 5.0.1
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/colores.sh"
source "$SCRIPT_DIR/lib/prerequisitos.sh"
source "$SCRIPT_DIR/lib/infraestructura.sh"
source "$SCRIPT_DIR/lib/firewall.sh"
source "$SCRIPT_DIR/lib/pruebas.sh"

# --------------------------------------------------------------------------- #
#  Banner
# --------------------------------------------------------------------------- #
mostrar_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          PRÁCTICA 11 · MICROSERVICIOS & TÚNELES SSH          ║"
    echo "║              Devuan Daedalus 5.0.1 · Docker Compose          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# --------------------------------------------------------------------------- #
#  Estado rápido del stack
# --------------------------------------------------------------------------- #
mostrar_estado() {
    echo -e "${BOLD}Estado actual del stack:${RESET}"
    if command -v docker &>/dev/null && docker compose -f "$SCRIPT_DIR/docker/docker-compose.yml" ps --quiet 2>/dev/null | grep -q .; then
        docker compose -f "$SCRIPT_DIR/docker/docker-compose.yml" ps \
            --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
            || echo -e "  ${YELLOW}(usa 'docker-compose' legacy)${RESET}"
    else
        echo -e "  ${YELLOW}Stack detenido o Docker no instalado.${RESET}"
    fi
    echo ""
}

# --------------------------------------------------------------------------- #
#  Menú principal
# --------------------------------------------------------------------------- #
menu_principal() {
    while true; do
        mostrar_banner
        mostrar_estado

        echo -e "${BOLD}─── FASE 1 · PREPARACIÓN ──────────────────────────────────────${RESET}"
        echo "  1) Verificar e instalar prerequisitos (Docker, Docker Compose)"
        echo "  2) Generar archivo .env con credenciales"
        echo "  3) Crear estructura de archivos de configuración"
        echo ""
        echo -e "${BOLD}─── FASE 2 · INFRAESTRUCTURA ──────────────────────────────────${RESET}"
        echo "  4) Iniciar stack completo (docker compose up)"
        echo "  5) Detener stack (docker compose down)"
        echo "  6) Reconstruir y reiniciar stack"
        echo "  7) Ver logs en tiempo real"
        echo ""
        echo -e "${BOLD}─── FASE 3 · SEGURIDAD / FIREWALL ─────────────────────────────${RESET}"
        echo "  8) Configurar firewall (bloquear pgAdmin y PostgreSQL externos)"
        echo "  9) Mostrar reglas de firewall activas"
        echo " 10) Limpiar reglas de firewall (modo desarrollo)"
        echo ""
        echo -e "${BOLD}─── FASE 4 · PRUEBAS DE ACEPTACIÓN ────────────────────────────${RESET}"
        echo " 11) Prueba 11.1 · Validación de aislamiento de red"
        echo " 12) Prueba 11.2 · Validación de DNS interno Docker"
        echo " 13) Prueba 11.3 · Instrucciones de túnel SSH"
        echo " 14) Prueba 11.4 · Persistencia y healthcheck"
        echo " 15) Ejecutar TODAS las pruebas en secuencia"
        echo ""
        echo -e "${BOLD}─── UTILIDADES ────────────────────────────────────────────────${RESET}"
        echo " 16) Mostrar IPs de la máquina (para configurar SSH)"
        echo " 17) Mostrar resumen de puertos del stack"
        echo "  0) Salir"
        echo ""
        echo -ne "${CYAN}Selecciona una opción: ${RESET}"
        read -r opcion

        case "$opcion" in
            1)  verificar_prerequisitos ;;
            2)  generar_env ;;
            3)  crear_estructura ;;
            4)  iniciar_stack ;;
            5)  detener_stack ;;
            6)  reconstruir_stack ;;
            7)  ver_logs ;;
            8)  configurar_firewall ;;
            9)  mostrar_firewall ;;
           10)  limpiar_firewall ;;
           11)  prueba_aislamiento ;;
           12)  prueba_dns_interno ;;
           13)  prueba_tunel_ssh ;;
           14)  prueba_persistencia ;;
           15)  ejecutar_todas_pruebas ;;
           16)  mostrar_ips ;;
           17)  mostrar_puertos ;;
            0)  echo -e "\n${GREEN}¡Hasta luego!${RESET}\n"; exit 0 ;;
            *)  echo -e "${RED}Opción inválida.${RESET}"; sleep 1 ;;
        esac

        echo -e "\n${DIM}Presiona ENTER para continuar...${RESET}"
        read -r
    done
}

# --------------------------------------------------------------------------- #
#  Punto de entrada
# --------------------------------------------------------------------------- #
# Verificar que se ejecuta como root o con sudo
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Este script requiere privilegios de root.${RESET}"
    echo "Ejecuta: sudo bash menu.sh"
    exit 1
fi

menu_principal
