#!/usr/bin/env bash
# ======================================================
# orquestador.sh - Orquestador Híbrido Final (Linux Modular)
# ======================================================

# Garantizar PATH completo en Devuan (sbin ausente en scripts no-interactivos)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Importar Módulos
source ./conf_ftp.sh
source ./http_funciones.sh

# Credenciales Globales y Automáticas
export FTP_IP="localhost"
export FTP_USER="chepe"
export FTP_PASS="XnightX321456"

fn_p7_ftp_nav() {
    echo -e "\n\e[1;36m+--- INSTALACIÓN VÍA FTP PRIVADO ---+\e[0m"
    echo -e "\e[1;30mConectando automáticamente al FTP como $FTP_USER...\e[0m"

    local BASE="ftp://${FTP_IP}/http/Linux"
    SERVICIOS=$(curl -s -k --ssl -u "${FTP_USER}:${FTP_PASS}" "${BASE}/" | awk '{print $NF}')
    
    if [[ -z "$SERVICIOS" ]]; then 
        echo -e "\e[1;31m[ERROR] FTP vacío o Conexión Rechazada.\e[0m"; return
    fi

    echo -e "\n\e[1;36mRepositorio FTP:\e[0m"
    select S in $SERVICIOS; do 
        [[ -n "$S" ]] && break
    done

    fn_solicitar_puertos

    local BIN_URL="${BASE}/${S}"
    ARCHIVOS=$(curl -s -k --ssl -u "${FTP_USER}:${FTP_PASS}" "${BIN_URL}/" | awk '{print $NF}' | grep -v ".sha256")
    
    echo -e "\n\e[1;36mSeleccione binario a instalar:\e[0m"
    select B in $ARCHIVOS; do 
        [[ -n "$B" ]] && break
    done

    echo -e "\e[1;33mDescargando binario seguro desde FTP...\e[0m"
    curl -s -k --ssl -u "${FTP_USER}:${FTP_PASS}" "${BIN_URL}/${B}" -O
    curl -s -k --ssl -u "${FTP_USER}:${FTP_PASS}" "${BIN_URL}/${B}.sha256" -O
    
    if sha256sum -c "${B}.sha256" &>/dev/null; then
        echo -e "\e[1;32mInstalando desde repositorio local...\e[0m"
        sleep 1
        
        case "${S,,}" in 
            apache) fn_p7_ssl "apache2" "$pHTTP" "$pHTTPS" ;;
            nginx) fn_p7_ssl "nginx" "$pHTTP" "$pHTTPS" ;; 
            tomcat) fn_p7_ssl "tomcat" "$pHTTP" "$pHTTPS" ;; 
        esac
        
        fn_resumen_instalacion "$pHTTP" "$pHTTPS"
    else
        echo -e "\e[1;31m[ERROR] Fallo de integridad: HASH INCORRECTO.\e[0m"
    fi
}

fn_p7_web_nav() {
    echo -e "\n\e[1;36m+--- INSTALACIÓN VÍA WEB (APT/WGET) ---+\e[0m"
    echo "1. Apache"
    echo "2. Nginx"
    echo "3. Tomcat"
    read -p "Servicio (1/2/3): " s_web
    
    fn_solicitar_puertos
    
    case $s_web in
        1) fn_p7_ssl "apache2" "$pHTTP" "$pHTTPS" ;;
        2) fn_p7_ssl "nginx" "$pHTTP" "$pHTTPS" ;;
        3) fn_p7_ssl "tomcat" "$pHTTP" "$pHTTPS" ;;
    esac
    
    fn_resumen_instalacion "$pHTTP" "$pHTTPS"
}

# Iniciador
preparar_entorno

while true; do
    echo -e "\n\e[1;33m======== PRACTICA 7: DESPLIEGUE HIBRIDO ========\e[0m"
    echo "1. Instalar via WEB (Oficial / APT)"
    echo "2. Instalar via FTP (Privado)"
    echo "3. Preparar Servidor (Roles e Infraestructura)"
    echo "4. Liberar Puertos Web"
    echo "5. Blindar FTP Local (vsftpd)"
    echo "0. Salir"
    read -p "Opcion: " OP
    case $OP in
        1) fn_p7_web_nav ;;
        2) fn_p7_ftp_nav ;;
        3) preparar_repo_local ;;
        4) fn_liberar_puertos ;;
        5) blindar_ftp ;;
        0) exit 0 ;;
        *) echo -e "\e[1;31mOpción inválida\e[0m" ;;
    esac
done