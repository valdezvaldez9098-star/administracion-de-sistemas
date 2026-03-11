#!/usr/bin/env bash
# =============================================================================
# http_funciones.sh — Libreria definitiva con Directorios Aislados
# Practica 6 | Devuan Daedalus 5.0.1
# =============================================================================

# PATH completo — necesario en Devuan cuando se accede con su sin -
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

msg_ok()   { echo -e "  ${GREEN}[OK]${RESET}    $*"; }
msg_err()  { echo -e "  ${RED}[ERROR]${RESET} $*" >&2; }
msg_info() { echo -e "  ${CYAN}[INFO]${RESET}  $*"; }
msg_warn() { echo -e "  ${YELLOW}[WARN]${RESET}  $*"; }

msg_title() {
    local text="$*"
    local width=55
    echo ""
    echo -e "${BOLD}${CYAN}  ====================================================${RESET}"
    printf "  ${BOLD}${CYAN}  %-${width}s${RESET}\n" "$text"
    echo -e "${BOLD}${CYAN}  ====================================================${RESET}"
    echo ""
}

fn_check_root() {
    [[ $EUID -ne 0 ]] && { msg_err "Ejecuta como root (sudo bash main.sh)."; exit 1; }
}

# Retorna 0 si el puerto esta LIBRE, 1 si esta ocupado
fn_port_free() {
    ! ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":$1$"
}

fn_validate_port() {
    local port="$1"
    local -a reserved=(22 21 23 25 53 443 3306 5432 6379 27017)
    [[ "$port" =~ ^[0-9]+$ ]] || { msg_err "El puerto debe ser numerico."; return 1; }
    (( port >= 1 && port <= 65535 )) || { msg_err "Puerto fuera de rango (1-65535)."; return 1; }
    for r in "${reserved[@]}"; do
        (( port == r )) && { msg_err "Puerto $port reservado para otro servicio critico."; return 1; }
    done
    return 0
}

fn_get_apt_versions() {
    local pkg="$1"
    apt-get update -qq &>/dev/null
    mapfile -t VERSION_LIST < <(apt-cache madison "$pkg" 2>/dev/null | awk '{print $3}' | sort -uV)
    [[ ${#VERSION_LIST[@]} -eq 0 ]] && { msg_warn "No hay versiones disponibles para '$pkg'."; return 1; }
    return 0
}

fn_select_version() {
    local pkg="$1"
    local -n _versions=$2
    msg_title "Seleccion de Version: $pkg"
    echo -e "  ${CYAN}----------------------------------------------------${RESET}"
    local i=1
    for v in "${_versions[@]}"; do
        printf "    ${GREEN}%2d.${RESET}  %s\n" "$i" "$v"
        (( i++ ))
    done
    echo -e "  ${CYAN}----------------------------------------------------${RESET}"
    while true; do
        echo -ne "\n  ${BOLD}${YELLOW}>>${RESET} Seleccione version [1-${#_versions[@]}]: "
        read -r sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#_versions[@]} )); then
            CHOSEN_VERSION="${_versions[$((sel-1))]}"
            msg_ok "Version seleccionada: ${CHOSEN_VERSION}"
            return 0
        fi
        msg_err "Seleccion invalida."
    done
}

fn_prompt_port() {
    echo -e "  ${CYAN}----------------------------------------------------${RESET}"
    while true; do
        echo -ne "  ${BOLD}${YELLOW}>>${RESET} Ingrese puerto (ej. 8080, 8888): "
        read -r port
        fn_validate_port "$port" || continue
        if fn_port_free "$port"; then
            CHOSEN_PORT="$port"
            msg_ok "Puerto ${port} disponible."
            echo -e "  ${CYAN}----------------------------------------------------${RESET}"
            return 0
        fi
        msg_err "Puerto $port ya esta en uso:"
        ss -tlnp | grep ":$port" || true
    done
}

# =============================================================================
# APACHE2
# =============================================================================
fn_install_apache() {
    local ver="$1" port="$2"
    msg_title "Instalando Apache2 v${ver} en puerto ${port}"

    # Instalar: intentar version exacta, fallback al repo
    msg_info "Descargando e instalando apache2..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            "apache2=${ver}" "apache2-bin=${ver}" "apache2-utils" 2>/dev/null; then
        msg_warn "Version exacta no disponible. Instalando version del repositorio..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apache2 apache2-utils
    fi

    # Validar instalacion
    if ! dpkg -l apache2 2>/dev/null | grep -q "^ii"; then
        msg_err "Instalacion de Apache2 fallida."
        return 1
    fi
    local installed_ver; installed_ver=$(dpkg -l apache2 | awk '/^ii/{print $3}')
    msg_ok "Apache2 instalado: version ${installed_ver}"

    # Directorio aislado
    local web_root="/var/www/apache"
    mkdir -p "$web_root"

    # Puerto en ports.conf
    local old_port
    old_port=$(grep -oP '(?<=Listen )\d+' /etc/apache2/ports.conf | head -1)
    old_port="${old_port:-80}"
    sed -i "s/Listen ${old_port}/Listen ${port}/g" /etc/apache2/ports.conf
    sed -i "s/<VirtualHost \*:${old_port}>/<VirtualHost *:${port}>/g" \
        /etc/apache2/sites-available/000-default.conf 2>/dev/null || true

    # Apuntar DocumentRoot al directorio aislado
    sed -i "s|DocumentRoot /var/www/html|DocumentRoot ${web_root}|g" \
        /etc/apache2/sites-available/000-default.conf 2>/dev/null || true
    msg_ok "Apache2: puerto ${old_port} -> ${port}, root -> ${web_root}"

    # Seguridad: ocultar version
    local sec_conf="/etc/apache2/conf-available/security.conf"
    [[ -f "$sec_conf" ]] || sec_conf="/etc/apache2/conf.d/security.conf"
    if [[ -f "$sec_conf" ]]; then
        sed -i 's/^ServerTokens.*/ServerTokens Prod/'      "$sec_conf"
        sed -i 's/^ServerSignature.*/ServerSignature Off/' "$sec_conf"
    fi
    a2enmod headers &>/dev/null || true

    # Pagina personalizada
    cat > "${web_root}/index.html" <<HTML
<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Apache2</title>
<style>body{font-family:monospace;background:#1e1e2e;color:#cdd6f4;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
.box{border:2px solid #89b4fa;padding:2rem 3rem;border-radius:8px;text-align:center}
h1{color:#89b4fa}span{color:#a6e3a1;font-weight:bold}</style></head>
<body><div class="box"><h1>&#9881; Servidor HTTP Desplegado</h1>
<p>Servidor : <span>Apache2</span></p>
<p>Version  : <span>${installed_ver}</span></p>
<p>Puerto   : <span>${port}</span></p></div></body></html>
HTML
    msg_ok "index.html creado en ${web_root}"

    # Reiniciar
    if [[ -x /etc/init.d/apache2 ]]; then
        /etc/init.d/apache2 restart &>/dev/null && msg_ok "Apache2 reiniciado (init.d)."
    fi

    # Verificar
    sleep 2
    if ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"; then
        msg_ok "Puerto ${port} escuchando. ✓"
    else
        msg_warn "Puerto ${port} aun no detectado. Verifica con: ss -tlnp | grep :${port}"
    fi
    curl -s -I --max-time 5 "http://127.0.0.1:${port}/" 2>/dev/null | head -5 || true
}

# =============================================================================
# NGINX
# =============================================================================
fn_install_nginx() {
    local ver="$1" port="$2"
    msg_title "Instalando Nginx v${ver} en puerto ${port}"

    # Limpieza total previa (dpkg no sobreescribe nginx.conf si ya existio)
    msg_info "Limpiando instalacion previa de nginx..."
    /etc/init.d/nginx stop &>/dev/null || true
    DEBIAN_FRONTEND=noninteractive dpkg --purge --force-all \
        nginx nginx-common nginx-core nginx-full nginx-light \
        libnginx-mod-http-geoip2 libnginx-mod-http-image-filter \
        libnginx-mod-http-xslt-filter libnginx-mod-mail \
        libnginx-mod-stream libnginx-mod-stream-geoip2 \
        2>/dev/null || true
    rm -rf /etc/nginx /var/log/nginx /var/lib/nginx
    msg_ok "Limpieza previa completada."

    # nginx-common primero: genera nginx.conf y estructura /etc/nginx
    msg_info "Instalando nginx-common..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx-common
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
        msg_err "nginx-common no genero /etc/nginx/nginx.conf. Abortando."
        return 1
    fi
    msg_ok "nginx-common instalado: /etc/nginx/nginx.conf generado. ✓"

    # Instalar nginx: mismo lote que nginx-common para evitar conflicto de version
    msg_info "Instalando nginx version ${ver}..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y \
            "nginx-common=${ver}" "nginx=${ver}" 2>/dev/null; then
        msg_ok "Nginx version ${ver} instalado."
    else
        msg_warn "Version ${ver} no disponible. Instalando version del repositorio..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
    fi

    if ! dpkg -l nginx 2>/dev/null | grep -q "^ii"; then
        msg_err "Instalacion de Nginx fallida."
        return 1
    fi
    local installed_ver; installed_ver=$(dpkg -l nginx | awk '/^ii/{print $3}')
    msg_ok "Nginx instalado: version ${installed_ver}"

    # Directorio aislado
    local web_root="/var/www/nginx"
    mkdir -p "$web_root"

    # Puerto
    local default_site="/etc/nginx/sites-available/default"
    [[ -f "$default_site" ]] || default_site="/etc/nginx/conf.d/default.conf"
    local old_port
    old_port=$(grep -oP '(?<=listen )\d+' "$default_site" 2>/dev/null | head -1)
    old_port="${old_port:-80}"
    sed -i "s/listen ${old_port} default_server;/listen ${port} default_server;/g" "$default_site"
    sed -i "s/listen \[::\]:${old_port} default_server;/listen [::]:${port} default_server;/g" "$default_site"
    msg_ok "Nginx: puerto ${old_port} -> ${port}"

    # Directorio root aislado en el site
    sed -i "s|root /var/www/html;|root ${web_root};|g" "$default_site"
    # Habilitar sitio
    ln -sf "$default_site" /etc/nginx/sites-enabled/default 2>/dev/null || true
    msg_ok "Nginx: root -> ${web_root}"

    # Ocultar version
    local nginx_conf="/etc/nginx/nginx.conf"
    if grep -q "server_tokens" "$nginx_conf"; then
        sed -i 's/server_tokens.*/server_tokens off;/' "$nginx_conf"
    else
        sed -i '/http {/a\\tserver_tokens off;' "$nginx_conf"
    fi
    msg_ok "Nginx: server_tokens off aplicado."

    # Security headers DENTRO del bloque server{}
    python3 << PYEOF
path = "${default_site}"
txt  = open(path).read()
headers = """
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    if (\$request_method !~ ^(GET|POST|HEAD|OPTIONS)\$) { return 405; }
"""
def insert(text, ins):
    depth = 0; started = False
    for i, ch in enumerate(text):
        if ch == "{": depth += 1; started = True
        elif ch == "}" and started:
            depth -= 1
            if depth == 0: return text[:i] + ins + text[i:]
    return text
if "Security headers" not in txt:
    open(path, "w").write(insert(txt, headers))
    print("  [OK]    Security headers insertados dentro de server{}")
else:
    print("  [INFO]  Security headers ya presentes")
PYEOF

    # Pagina personalizada
    cat > "${web_root}/index.html" <<HTML
<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Nginx</title>
<style>body{font-family:monospace;background:#1e1e2e;color:#cdd6f4;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
.box{border:2px solid #89b4fa;padding:2rem 3rem;border-radius:8px;text-align:center}
h1{color:#89b4fa}span{color:#a6e3a1;font-weight:bold}</style></head>
<body><div class="box"><h1>&#9881; Servidor HTTP Desplegado</h1>
<p>Servidor : <span>Nginx</span></p>
<p>Version  : <span>${installed_ver}</span></p>
<p>Puerto   : <span>${port}</span></p></div></body></html>
HTML
    msg_ok "index.html creado en ${web_root}"

    # Validar config y reiniciar
    if nginx -t &>/dev/null; then
        msg_ok "nginx -t: configuracion valida."
        if [[ -x /etc/init.d/nginx ]]; then
            /etc/init.d/nginx restart && msg_ok "Nginx reiniciado (init.d)."
        fi
    else
        msg_err "Configuracion de nginx invalida:"
        nginx -t
        return 1
    fi

    # Verificar
    sleep 2
    if ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"; then
        msg_ok "Puerto ${port} escuchando. ✓"
    else
        msg_warn "Puerto ${port} aun no detectado. Verifica con: ss -tlnp | grep :${port}"
    fi
    curl -s -I --max-time 5 "http://127.0.0.1:${port}/" 2>/dev/null | head -5 || true
}

# =============================================================================
# TOMCAT (binario desde archive.apache.org)
# =============================================================================
fn_get_tomcat_versions() {
    VERSION_LIST=("9.0.87" "9.0.85" "9.0.83")
    TOMCAT_PKG="tomcat-binario"
    msg_info "Versiones Tomcat 9 disponibles (binario oficial):"
    return 0
}

fn_install_tomcat() {
    local ver="$1" port="$2"
    local target_dir="/opt/tomcat-${ver}"
    msg_title "Instalando Tomcat v${ver} en puerto ${port}"

    # Dependencias
    msg_info "Instalando dependencias (JRE + wget + tar)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq default-jre-headless wget tar
    if ! command -v java &>/dev/null; then
        msg_err "Java no encontrado. Abortando."
        return 1
    fi
    msg_ok "Java disponible: $(java -version 2>&1 | head -1)"

    # Descargar si no existe
    if [[ ! -d "$target_dir" ]]; then
        local url="https://archive.apache.org/dist/tomcat/tomcat-9/v${ver}/bin/apache-tomcat-${ver}.tar.gz"
        msg_info "Descargando Tomcat ${ver} desde archive.apache.org..."
        if ! wget -q --timeout=30 "$url" -O "/tmp/tomcat-${ver}.tar.gz"; then
            msg_err "Descarga fallida. Verifica conexion a internet y version."
            msg_info "URL intentada: ${url}"
            return 1
        fi
        mkdir -p "$target_dir"
        tar -xf "/tmp/tomcat-${ver}.tar.gz" -C "$target_dir" --strip-components=1
        rm -f "/tmp/tomcat-${ver}.tar.gz"
        msg_ok "Tomcat ${ver} descomprimido en ${target_dir}"
    else
        msg_info "Tomcat ${ver} ya existe en ${target_dir}. Reutilizando."
    fi

    # Detener instancia previa si existe
    pkill -f "tomcat-${ver}" 2>/dev/null || true
    sleep 1

    # Puerto en server.xml
    sed -i "s/Connector port=\"[0-9]*\" protocol=\"HTTP/Connector port=\"${port}\" protocol=\"HTTP/" \
        "${target_dir}/conf/server.xml"
    msg_ok "Tomcat: puerto configurado -> ${port}"

    # Pagina personalizada
    mkdir -p "${target_dir}/webapps/ROOT"
    cat > "${target_dir}/webapps/ROOT/index.html" <<HTML
<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Tomcat</title>
<style>body{font-family:monospace;background:#1e1e2e;color:#cdd6f4;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
.box{border:2px solid #89b4fa;padding:2rem 3rem;border-radius:8px;text-align:center}
h1{color:#89b4fa}span{color:#a6e3a1;font-weight:bold}</style></head>
<body><div class="box"><h1>&#9881; Servidor HTTP Desplegado</h1>
<p>Servidor : <span>Tomcat</span></p>
<p>Version  : <span>${ver}</span></p>
<p>Puerto   : <span>${port}</span></p></div></body></html>
HTML
    msg_ok "index.html creado en ${target_dir}/webapps/ROOT"

    # Arrancar
    export CATALINA_HOME="$target_dir"
    bash "${target_dir}/bin/startup.sh" &>/dev/null
    msg_ok "Tomcat arrancado."

    # Verificar (Tomcat tarda mas en arrancar)
    msg_info "Esperando que Tomcat levante (hasta 15s)..."
    local i=0
    while (( i < 15 )); do
        sleep 1; (( i++ ))
        if ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"; then
            msg_ok "Puerto ${port} escuchando. ✓"
            curl -s -I --max-time 5 "http://127.0.0.1:${port}/" 2>/dev/null | head -5 || true
            return 0
        fi
    done
    msg_warn "Puerto ${port} aun no detectado tras 15s."
    msg_info "Revisa los logs: tail -f ${target_dir}/logs/catalina.out"
}

# =============================================================================
# LIMPIEZA
# =============================================================================
fn_do_cleanup() {
    local svc="$1"
    msg_title "Limpiando: ${svc}"
    case "$svc" in
        apache2)
            /etc/init.d/apache2 stop &>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq apache2 apache2-bin apache2-utils apache2-data 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq &>/dev/null || true
            rm -rf /etc/apache2 /var/www/apache
            msg_ok "Apache2 eliminado."
            ;;
        nginx)
            /etc/init.d/nginx stop &>/dev/null || true
            DEBIAN_FRONTEND=noninteractive dpkg --purge --force-all \
                nginx nginx-common nginx-core nginx-full nginx-light \
                libnginx-mod-http-geoip2 libnginx-mod-http-image-filter \
                libnginx-mod-http-xslt-filter libnginx-mod-mail \
                libnginx-mod-stream libnginx-mod-stream-geoip2 \
                2>/dev/null || true
            rm -rf /etc/nginx /var/log/nginx /var/lib/nginx /var/www/nginx
            msg_ok "Nginx eliminado."
            ;;
        tomcat)
            pkill -9 -f "org.apache.catalina" 2>/dev/null || true
            pkill -9 -f "tomcat" 2>/dev/null || true
            rm -rf /opt/tomcat-*
            msg_ok "Tomcat eliminado."
            ;;
    esac
}

fn_menu_cleanup() {
    clear
    msg_title "Limpieza de Instalaciones Previas"
    echo -e "  ${YELLOW}Que deseas limpiar?${RESET}"
    echo -e "  ${CYAN}----------------------------------------------------${RESET}"
    echo -e "  ${GREEN}[1]${RESET} Apache2"
    echo -e "  ${GREEN}[2]${RESET} Nginx"
    echo -e "  ${GREEN}[3]${RESET} Tomcat"
    echo -e "  ${CYAN}----------------------------------------------------${RESET}"
    echo -e "  ${YELLOW}[A]${RESET} Limpiar Todo"
    echo -e "  ${RED}[0]${RESET} Cancelar"
    echo -e "  ${CYAN}----------------------------------------------------${RESET}"
    echo -ne "\n  ${BOLD}${YELLOW}>>${RESET} Seleccion: "
    read -r sel
    case "${sel^^}" in
        1) fn_do_cleanup "apache2" ;;
        2) fn_do_cleanup "nginx"   ;;
        3) fn_do_cleanup "tomcat"  ;;
        A) fn_do_cleanup "apache2"; fn_do_cleanup "nginx"; fn_do_cleanup "tomcat"
           msg_ok "Sistema limpio." ;;
        0) msg_info "Cancelado." ;;
        *) msg_err "Opcion invalida." ;;
    esac
}