#!/usr/bin/env bash
# ======================================================
# conf_ftp.sh - Preparacion de Entorno y FTP (Fijado)
# ======================================================

# Garantizar PATH completo en Devuan (sbin no siempre está en scripts no-interactivos)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

export DOMAIN="www.reprobados.com"
export CERT_DIR="/etc/ssl/reprobados"

preparar_entorno() {
    echo -e "\e[1;34m[SISTEMA] Verificando dependencias...\e[0m"
    apt-get update &>/dev/null
    for pkg in curl openssl coreutils net-tools psmisc; do
        if ! command -v $pkg &>/dev/null && [ ! -f "/sbin/$pkg" ] && [ ! -f "/usr/bin/$pkg" ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg &>/dev/null
        fi
    done
    mkdir -p "$CERT_DIR"
}

preparar_repo_local() {
    # Crear usuario FTP si no existe
    if /usr/bin/id "$FTP_USER" &>/dev/null; then
        echo "${FTP_USER}:${FTP_PASS}" | /usr/sbin/chpasswd
    else
        /usr/sbin/useradd -m -s /bin/bash "$FTP_USER"
        echo "${FTP_USER}:${FTP_PASS}" | /usr/sbin/chpasswd
    fi

    local BASE_PATH="/srv/ftp/http/Linux"
    echo -e "\e[1;34m[INFO] Limpiando y reconstruyendo repositorio FTP...\e[0m"
    
    # Destruimos la carpeta corrupta de intentos anteriores
    rm -rf "$BASE_PATH"
    
    # Creamos los directorios limpios
    for SVC in Apache Nginx Tomcat; do
        mkdir -p "$BASE_PATH/$SVC"
    done
    
    # Inyectamos los archivos en su lugar correcto
    echo "Instalador Apache" > "$BASE_PATH/Apache/apache_v2.deb"
    echo "Instalador Nginx" > "$BASE_PATH/Nginx/nginx_v2.deb"
    echo "Instalador Tomcat" > "$BASE_PATH/Tomcat/tomcat_v9.tar.gz"
    
    # Usamos sub-consolas (...) para que el cd no contamine el script principal
    (cd "$BASE_PATH/Apache" && sha256sum apache_v2.deb > apache_v2.deb.sha256)
    (cd "$BASE_PATH/Nginx" && sha256sum nginx_v2.deb > nginx_v2.deb.sha256)
    (cd "$BASE_PATH/Tomcat" && sha256sum tomcat_v9.tar.gz > tomcat_v9.tar.gz.sha256)
    
    chown -R root:root /srv/ftp
    chmod -R 755 /srv/ftp
    
    if [[ ! -f /etc/vsftpd.conf ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd &>/dev/null
    fi
    
    sed -i '/listen=/d; /listen_ipv6=/d; /local_root=/d; /chroot_local_user=/d; /local_enable=/d; /allow_writeable_chroot=/d' /etc/vsftpd.conf
    cat <<EOF >> /etc/vsftpd.conf
listen=YES
listen_ipv6=NO
local_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
local_root=/srv/ftp
EOF
    /etc/init.d/vsftpd restart &>/dev/null
    sleep 1
    echo -e "\e[1;32m[OK] Infraestructura FTP lista.\e[0m"
}

blindar_ftp() {
    echo -e "\e[1;34m[INFO] Generando certificados auto-firmados para FTP...\e[0m"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/reprobados.key" \
        -out "${CERT_DIR}/reprobados.crt" \
        -subj "/C=MX/ST=Sinaloa/L=Mazatlan/O=UAS/CN=${DOMAIN}" &>/dev/null
        
    sed -i '/ssl_enable/d' /etc/vsftpd.conf
    echo -e "ssl_enable=YES\nallow_anon_ssl=NO\nforce_local_data_ssl=YES\nforce_local_logins_ssl=YES\nrsa_cert_file=${CERT_DIR}/reprobados.crt\nrsa_private_key_file=${CERT_DIR}/reprobados.key" >> /etc/vsftpd.conf
    /etc/init.d/vsftpd restart
    echo -e "  \e[1;32m[OK]\e[0m FTPS activo (Canal cifrado)."
}