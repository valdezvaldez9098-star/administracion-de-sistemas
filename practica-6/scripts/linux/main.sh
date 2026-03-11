#!/usr/bin/env bash
# =============================================================================
# main.sh — Despliegue Dinamico de Servicios HTTP | Devuan Daedalus 5.0.1
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUNCTIONS_FILE="${SCRIPT_DIR}/http_funciones.sh"

if [[ ! -f "$FUNCTIONS_FILE" ]]; then
    echo -e "\033[0;31m  [ERROR] No se encontro http_funciones.sh en ${SCRIPT_DIR}\033[0m" >&2
    exit 1
fi

source "$FUNCTIONS_FILE"
fn_check_root

fn_main_menu() {
    clear

    echo -e "${BOLD}${CYAN}  +----------------------------------------------------------+${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${BOLD}                                                          ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${BOLD}       SISTEMA DE DESPLIEGUE - DEVUAN DAEDALUS 5.0.1     ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${CYAN}                (HTTP MULTI-VERSION DEPLOY)               ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${BOLD}                                                          ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  +----------------------------------------------------------+${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${BOLD}                                                          ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}  ${GREEN}[1]${RESET} Instalar Servidor Apache2                          ${BOLD}${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}  ${GREEN}[2]${RESET} Instalar Servidor Nginx                            ${BOLD}${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}  ${GREEN}[3]${RESET} Instalar Servidor Tomcat                           ${BOLD}${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${BOLD}                                                          ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  +----------------------------------------------------------+${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${BOLD}                                                          ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}  ${YELLOW}[9]${RESET} Limpieza de Instalaciones Previas                 ${BOLD}${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}  ${RED}[0]${RESET} Salir del Sistema                                  ${BOLD}${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  |${RESET}${BOLD}                                                          ${CYAN}|${RESET}"
    echo -e "${BOLD}${CYAN}  +----------------------------------------------------------+${RESET}"
    echo ""
    echo -ne "  ${BOLD}${YELLOW}>>${RESET} ${CYAN}Selecciona una opcion [0-3, 9]:${RESET} "
    read -r MENU_OPT
}

fn_run() {
    while true; do
        fn_main_menu
        case "$MENU_OPT" in
            1)
                fn_get_apt_versions "apache2" && \
                fn_select_version "apache2" VERSION_LIST && \
                fn_prompt_port && \
                fn_install_apache "$CHOSEN_VERSION" "$CHOSEN_PORT"
                ;;
            2)
                fn_get_apt_versions "nginx" && \
                fn_select_version "nginx" VERSION_LIST && \
                fn_prompt_port && \
                fn_install_nginx "$CHOSEN_VERSION" "$CHOSEN_PORT"
                ;;
            3)
                fn_get_tomcat_versions && \
                fn_select_version "$TOMCAT_PKG" VERSION_LIST && \
                fn_prompt_port && \
                fn_install_tomcat "$CHOSEN_VERSION" "$CHOSEN_PORT"
                ;;
            9)
                fn_menu_cleanup
                ;;
            0)
                echo ""
                msg_info "Saliendo del sistema. Hasta luego."
                echo ""
                exit 0
                ;;
            *)
                msg_err "Opcion no valida. Elige 1, 2, 3, 9 o 0."
                sleep 1
                ;;
        esac
        echo ""
        echo -ne "  ${CYAN}Presiona ENTER para continuar...${RESET}"
        read -r
    done
}

fn_run