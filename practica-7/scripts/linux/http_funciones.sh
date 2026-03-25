#!/usr/bin/env bash
# ======================================================
# http_funciones.sh - FIX DEFINITIVO (POSICIÓN XML)
# ======================================================

# Garantizar PATH completo en Devuan
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

fn_solicitar_puertos() {
    read -p "Ingresa el Puerto HTTP (Ej. 80 o 8080) [Enter para 80]: " pHTTP
    pHTTP=${pHTTP:-80}
    read -p "Ingresa el Puerto HTTPS (Ej. 443 o 8443) [Enter para 443]: " pHTTPS
    pHTTPS=${pHTTPS:-443}
}

fn_obtener_ip() {
    local IP=$(hostname -I | awk '{for(i=1;i<=NF;i++) if($i ~ /^192\.168\./) {print $i; exit}}')
    if [[ -z "$IP" ]]; then IP=$(hostname -I | awk '{print $1}'); fi
    echo "$IP"
}

fn_resumen_instalacion() {
    local p_h=$1
    local p_hs=$2
    local IP=$(fn_obtener_ip)
    echo -e "\n\e[1;36m=======================================================\e[0m"
    echo -e "       RESUMEN Y VERIFICACION AUTOMATIZADA             "
    echo -e "=======================================================\e[0m"
    echo -e "Esperando 12 segundos a que los servicios estabilicen..."
    sleep 12
    
    # Auditoría con netstat/ss (más precisa)
    if ss -tuln | grep -q ":$p_h " ; then echo -e "[Puerto $p_h - HTTP ] Activo: \e[1;32mTrue\e[0m"; else echo -e "[Puerto $p_h - HTTP ] Activo: \e[1;31mFalse\e[0m"; fi
    if ss -tuln | grep -q ":$p_hs " ; then echo -e "[Puerto $p_hs - HTTPS] Activo: \e[1;32mTrue\e[0m"; else echo -e "[Puerto $p_hs - HTTPS] Activo: \e[1;31mFalse\e[0m"; fi
    
    echo -e "URL HTTP:  http://$IP:$p_h/index.html"
    echo -e "URL HTTPS: https://$IP:$p_hs/index.html"
    echo -e "\e[1;36m=======================================================\e[0m"
}

fn_liberar_puertos() {
    echo -e "\e[1;33m-> Limpiando procesos de red anteriores...\e[0m"
    /etc/init.d/apache2 stop 2>/dev/null
    /etc/init.d/nginx stop 2>/dev/null
    # Matar Tomcat y Java de raíz
    pkill -9 -f "catalina" 2>/dev/null
    pkill -9 -f "java" 2>/dev/null
    fuser -k 80/tcp 443/tcp 8080/tcp 8443/tcp 8000/tcp 2>/dev/null
    sleep 2
}

fn_p7_ssl() {
    local svc="$1"
    local p_h="$2"
    local p_hs="$3"
    local IP=$(fn_obtener_ip)

    echo -e "\e[1;34m[CERT] Generando certificados...\e[0m"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/reprobados.key" \
        -out "${CERT_DIR}/reprobados.crt" \
        -subj "/C=MX/ST=Sinaloa/L=Mazatlan/O=UAS/CN=${DOMAIN}"

    case "$svc" in
        "apache2")
            fn_liberar_puertos
            apt-get install -y apache2
            /usr/sbin/a2enmod ssl rewrite
            echo -e "Listen $p_h\nListen $p_hs" > /etc/apache2/ports.conf
            cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:$p_h>
    DocumentRoot /var/www/apache
</VirtualHost>
<VirtualHost *:$p_hs>
    DocumentRoot /var/www/apache
    SSLEngine on
    SSLCertificateFile ${CERT_DIR}/reprobados.crt
    SSLCertificateKeyFile ${CERT_DIR}/reprobados.key
</VirtualHost>
EOF
            mkdir -p /var/www/apache
            echo "<h1>Apache OK</h1>" > /var/www/apache/index.html
            /etc/init.d/apache2 restart
            ;;
        "nginx")
            fn_liberar_puertos
            apt-get install -y nginx
            cat <<EOF > /etc/nginx/sites-available/default
server { listen $p_h; root /var/www/nginx; }
server {
    listen $p_hs ssl;
    ssl_certificate ${CERT_DIR}/reprobados.crt;
    ssl_certificate_key ${CERT_DIR}/reprobados.key;
    root /var/www/nginx;
}
EOF
            mkdir -p /var/www/nginx
            echo "<h1>Nginx OK</h1>" > /var/www/nginx/index.html
            /etc/init.d/nginx restart
            ;;
        "tomcat")
            fn_liberar_puertos
            rm -rf /opt/tomcat-9
            
            # Sincronización de reloj (importante para certificados)
            date -s "$(curl -s --head http://google.com | grep ^Date: | sed 's/Date: //g')" 2>/dev/null

            echo "Generando Keystore PKCS12..."
            openssl pkcs12 -export -in "${CERT_DIR}/reprobados.crt" -inkey "${CERT_DIR}/reprobados.key" -out "${CERT_DIR}/reprobados.p12" -name tomcat -password pass:reprobados
            chmod 644 "${CERT_DIR}/reprobados.p12" # Permisos de lectura
            
            echo "Instalando motor Java..."
            apt-get update && apt-get install -y default-jdk wget tar
            
            REAL_JAVA=$(readlink -f $(which java))
            export JAVA_HOME=$(echo "$REAL_JAVA" | sed 's|/bin/java||')
            export JRE_HOME="$JAVA_HOME"

            TOMCAT_DIR="/opt/tomcat-9"
            wget -q "https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.87/bin/apache-tomcat-9.0.87.tar.gz" -O /tmp/tomcat.tar.gz
            mkdir -p "$TOMCAT_DIR"
            tar -xf /tmp/tomcat.tar.gz -C "$TOMCAT_DIR" --strip-components=1
            
            echo "Configurando server.xml de forma segura..."
            # 1. Cambiar puerto HTTP
            sed -i "s#port=\"8080\"#port=\"$p_h\"#g" "$TOMCAT_DIR/conf/server.xml"
            
            # 2. Inyección del conector SSL GARANTIZADA DENTRO del Service
            cat <<EOF > /tmp/ssl_block.txt
    <Connector port="$p_hs" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="false" sslProtocol="TLS" 
               keystoreFile="${CERT_DIR}/reprobados.p12" 
               keystorePass="reprobados" keystoreType="PKCS12" />
EOF
            # Paso maestro: reemplazamos la etiqueta </Service> por el bloque + la propia etiqueta
            # Esto garantiza que el bloque quede justo antes del cierre y dentro del motor.
            sed -i "s|</Service>|MARKER\n</Service>|g" "$TOMCAT_DIR/conf/server.xml"
            sed -i "/MARKER/r /tmp/ssl_block.txt" "$TOMCAT_DIR/conf/server.xml"
            sed -i "/MARKER/d" "$TOMCAT_DIR/conf/server.xml"
            
            mkdir -p "$TOMCAT_DIR/webapps/ROOT"
            echo "<h1>Tomcat Dual OK</h1><p>HTTP: $p_h | HTTPS: $p_hs</p>" > "$TOMCAT_DIR/webapps/ROOT/index.html"
            
            chmod +x "$TOMCAT_DIR"/bin/*.sh
            echo "Iniciando motor con JRE_HOME: $JRE_HOME"
            JRE_HOME="$JRE_HOME" JAVA_HOME="$JAVA_HOME" sh "$TOMCAT_DIR/bin/startup.sh"
            ;;
    esac
}