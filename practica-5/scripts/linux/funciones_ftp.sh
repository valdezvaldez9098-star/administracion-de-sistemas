#!/bin/bash
# ==============================================================================
# SCRIPT COMPLETO DE GESTION FTP - VERSION PARA DEVUAN DAEDALUS (CORREGIDO)
# CON PERMISOS DE ESCRITURA PARA USUARIOS EN GENERAL Y SU GRUPO
# ==============================================================================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Variables globales
FTP_ROOT="/srv/ftp"
FTP_CONFIG="/etc/vsftpd.conf"
FTP_SERVICE="vsftpd"
INIT_SCRIPT="/etc/init.d/vsftpd"

# ============================================
# CORRECCIÓN PARA DEVUAN - AGREGAR /usr/sbin AL PATH
# ============================================
export PATH=$PATH:/usr/sbin:/sbin

# Verificar root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Este script debe ejecutarse como root${NC}"
    exit 1
fi

# ============================================
# FUNCION AUXILIAR PARA VERIFICAR COMANDOS
# ============================================

verificar_comando() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e " ${YELLOW}⚠${NC} Comando '$1' no encontrado. Instalando paquete requerido..."
        apt-get update -qq > /dev/null 2>&1
        case "$1" in
            groupadd|groupdel|useradd|userdel|chpasswd)
                DEBIAN_FRONTEND=noninteractive apt-get install -y passwd > /dev/null 2>&1
                ;;
            chown|chmod)
                DEBIAN_FRONTEND=noninteractive apt-get install -y coreutils > /dev/null 2>&1
                ;;
            setfacl|getfacl)
                DEBIAN_FRONTEND=noninteractive apt-get install -y acl > /dev/null 2>&1
                ;;
        esac
        if command -v "$1" >/dev/null 2>&1; then
            echo -e " ${GREEN}✓${NC} Comando '$1' instalado correctamente"
        else
            echo -e " ${RED}✗${NC} Error instalando '$1'"
        fi
    fi
}

# ============================================
# FUNCION AUXILIAR PARA VERIFICAR SERVICIO (DEVUAN)
# ============================================

verificar_servicio() {
    if [ -f "$INIT_SCRIPT" ]; then
        if $INIT_SCRIPT status | grep -q "running"; then
            return 0
        elif $INIT_SCRIPT status | grep -q "is running"; then
            return 0
        elif ps aux | grep -v grep | grep -q "[v]sftpd"; then
            return 0
        else
            return 1
        fi
    else
        if ps aux | grep -v grep | grep -q "[v]sftpd"; then
            return 0
        else
            return 1
        fi
    fi
}

iniciar_servicio() {
    if [ -f "$INIT_SCRIPT" ]; then
        $INIT_SCRIPT start > /dev/null 2>&1
    else
        /usr/sbin/vsftpd > /dev/null 2>&1 &
    fi
    sleep 2
}

detener_servicio() {
    if [ -f "$INIT_SCRIPT" ]; then
        $INIT_SCRIPT stop > /dev/null 2>&1
    else
        killall vsftpd 2>/dev/null
    fi
    sleep 2
}

reiniciar_servicio() {
    detener_servicio
    iniciar_servicio
}

estado_servicio() {
    if verificar_servicio; then
        echo -e " ${GREEN}✓${NC} Servicio vsftpd activo"
    else
        echo -e " ${YELLOW}⚠${NC} Servicio vsftpd inactivo"
    fi
}

# ============================================
# FUNCIONES DE CONFIGURACION FTP
# ============================================

function Verificar-FTP {
    echo -e "${CYAN}=== VERIFICANDO INSTALACION FTP ===${NC}"
    
    if dpkg -s vsftpd >/dev/null 2>&1; then
        echo -e " ${GREEN}✓${NC} FTP ya esta instalado"
        estado_servicio
        return 0
    else
        echo -e " ${RED}✗${NC} FTP no esta instalado"
        return 1
    fi
}

function Instalar-FTP {
    echo -e "${CYAN}=== INSTALANDO VSFTPD ===${NC}"
    
    if Verificar-FTP; then
        echo -e " ${YELLOW}⚠${NC} FTP ya esta instalado"
        return
    fi
    
    echo -e " ${WHITE}▶${NC} Actualizando repositorios..."
    apt-get update -qq
    
    echo -e " ${WHITE}▶${NC} Instalando vsftpd y utilerías..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd ftp acl passwd coreutils > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e " ${GREEN}✓${NC} Instalacion completada"
        
        if [ -f "$INIT_SCRIPT" ]; then
            update-rc.d vsftpd defaults > /dev/null 2>&1
            echo -e " ${GREEN}✓${NC} Servicio configurado para inicio automatico"
        fi
        
        [ -f "$FTP_CONFIG" ] && cp "$FTP_CONFIG" "${FTP_CONFIG}.original" 2>/dev/null
    else
        echo -e " ${RED}✗${NC} Error en la instalacion"
    fi
}

function Configurar-SitioFTP {
    echo -e "${CYAN}=== CONFIGURANDO SERVIDOR FTP ===${NC}"
    
    # Crear directorios base
    mkdir -p "$FTP_ROOT"
    mkdir -p "$FTP_ROOT/general"
    echo -e " ${GREEN}✓${NC} Directorios base creados en $FTP_ROOT"
    
    # Crear archivo de bienvenida
    echo "Bienvenido al servidor FTP - Acceso anonimo" > "$FTP_ROOT/general/leeme.txt"
    
    echo -e " ${GREEN}✓${NC} Estructura de directorios creada"
    
    # ============================================
    # CONFIGURACION VSFTPD CON CHROOT PARA USUARIOS
    # ============================================
    cat > "$FTP_CONFIG" <<EOF
# ============================================
# CONFIGURACION VSFTPD - CON CHROOT POR USUARIO
# ============================================

# MODO STANDALONE
listen=YES
listen_port=21

# CONFIGURACION GENERAL
anonymous_enable=YES
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES

# CONFIGURACION ANONIMO
anonymous_enable=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
anon_world_readable_only=YES
anon_root=$FTP_ROOT/general

# CONFIGURACION USUARIOS LOCALES - CHROOT
chroot_local_user=YES
allow_writeable_chroot=YES
local_root=$FTP_ROOT
user_sub_token=\$USER

# LOGS
xferlog_file=/var/log/vsftpd.log
vsftpd_log_file=/var/log/vsftpd.log

# SEGURIDAD
seccomp_sandbox=NO
hide_ids=YES

# RED
pasv_enable=YES
pasv_min_port=50000
pasv_max_port=50100

# BIENVENIDA
ftpd_banner=Bienvenido al servidor FTP - Practica 5
EOF
    
    echo -e " ${GREEN}✓${NC} Archivo de configuracion generado en $FTP_CONFIG"
    
    # Configurar firewall
    if command -v iptables >/dev/null 2>&1; then
        iptables -A INPUT -p tcp --dport 21 -j ACCEPT 2>/dev/null
        iptables -A INPUT -p tcp --dport 50000:50100 -j ACCEPT 2>/dev/null
        echo -e " ${GREEN}✓${NC} Reglas iptables configuradas"
    fi
    
    echo -e " ${GREEN}✓${NC} Sitio FTP configurado correctamente"
}

# ============================================
# FUNCIÓN CORREGIDA PARA CONFIGURAR PERMISOS
# ============================================

function Configurar-Permisos {
    echo -e "${CYAN}=== CONFIGURANDO PERMISOS ===${NC}"
    
    verificar_comando "chown"
    verificar_comando "chmod"
    verificar_comando "setfacl"
    
    # ============================================
    # PERMISOS DE LA RAÍZ FTP
    # ============================================
    chown root:root "$FTP_ROOT"
    chmod 755 "$FTP_ROOT"
    
    # ============================================
    # CARPETA GENERAL - PERMISOS DE ESCRITURA PARA USUARIOS
    # ============================================
    echo -e " ${YELLOW}▶${NC} Configurando permisos de carpeta general..."
    
    # Cambiar propietario y grupo
    chown -R root:users "$FTP_ROOT/general"
    
    # Dar permisos 775 (rwxrwxr-x) - usuarios del grupo pueden escribir
    chmod 775 "$FTP_ROOT/general"
    
    # Asegurar que el sticky bit no esté activado
    chmod -s "$FTP_ROOT/general"
    
    # ============================================
    # ACLs PARA PERMISOS FINOS
    # ============================================
    if command -v setfacl >/dev/null 2>&1; then
        # Permitir lectura/escritura/ejecución al grupo users
        setfacl -m group:users:rwx "$FTP_ROOT/general"
        setfacl -m default:group:users:rwx "$FTP_ROOT/general"
        
        # Usuario anónimo solo lectura
        setfacl -m u:ftp:r-x "$FTP_ROOT/general"
        setfacl -m default:u:ftp:r-x "$FTP_ROOT/general"
        
        echo -e " ${GREEN}✓${NC} ACLs configuradas para permisos de escritura"
    fi
    
    # Crear archivos de prueba
    touch "$FTP_ROOT/general/prueba_escritura.txt"
    chmod 664 "$FTP_ROOT/general/prueba_escritura.txt"
    chown root:users "$FTP_ROOT/general/prueba_escritura.txt"
    
    echo -e " ${GREEN}✓${NC} Permisos configurados - Usuarios pueden escribir en general"
}

function Configurar-ACLs {
    echo -e "${CYAN}=== CONFIGURANDO ACLs ADICIONALES ===${NC}"
    
    if command -v setfacl >/dev/null 2>&1; then
        # Ya se configuraron en Configurar-Permisos
        echo -e " ${GREEN}✓${NC} ACLs ya configuradas"
    else
        echo -e " ${YELLOW}⚠${NC} setfacl no instalado, instalando..."
        apt-get install -y acl > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            Configurar-Permisos
        else
            echo -e " ${RED}✗${NC} No se pudo instalar ACL, usando permisos estandar"
        fi
    fi
}

function Configurar-ReglasFTP {
    echo -e "${CYAN}=== CONFIGURANDO REGLAS DE ACCESO ===${NC}"
    
    cat > /etc/pam.d/vsftpd <<EOF
#%PAM-1.0
auth    required    pam_unix.so
account required    pam_unix.so
session required    pam_unix.so
EOF
    
    echo -e " ${GREEN}✓${NC} Reglas FTP configuradas via PAM"
}

function Configurar-Red {
    echo -e "${CYAN}=== CONFIGURANDO RED ===${NC}"
    
    echo 1 > /proc/sys/net/ipv4/ip_forward
    grep -q "net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    
    echo -e " ${GREEN}✓${NC} Red configurada"
}

function Instalar-Todo {
    echo -e "${PURPLE}=== INSTALACION COMPLETA ===${NC}"
    Instalar-FTP
    Configurar-SitioFTP
    Configurar-Permisos
    Configurar-ACLs
    Configurar-ReglasFTP
    Configurar-Red
    verificar_usuario_anonimo
    configurar_usuario_anonimo
    
    reiniciar_servicio
    
    if verificar_servicio; then
        echo -e "${GREEN}✓ INSTALACION COMPLETADA${NC}"
    else
        echo -e "${RED}✗ ERROR: El servicio no inicio correctamente${NC}"
        if [ -f "$INIT_SCRIPT" ]; then
            $INIT_SCRIPT status
        fi
    fi
}

# ============================================
# FUNCIONES DE GESTION DE GRUPOS
# ============================================

function Crear-Grupo {
    echo -e "${CYAN}=== CREAR NUEVO GRUPO ===${NC}"
    
    verificar_comando "groupadd"
    
    read -p "Nombre del nuevo grupo: " grupo
    
    if grep -q "^$grupo:" /etc/group; then
        echo -e " ${YELLOW}⚠${NC} El grupo $grupo ya existe"
        return
    fi
    
    if groupadd "$grupo"; then
        echo -e " ${GREEN}✓${NC} Grupo $grupo creado correctamente"
        
        # Crear carpeta para el grupo
        mkdir -p "$FTP_ROOT/$grupo"
        mkdir -p "$FTP_ROOT/$grupo/grupo"  # Carpeta compartida del grupo
        
        # Configurar permisos: root:grupo, permisos 770
        if chown -R root:"$grupo" "$FTP_ROOT/$grupo" 2>/dev/null; then
            chmod 770 "$FTP_ROOT/$grupo"      # Solo root y grupo tienen acceso
            chmod 770 "$FTP_ROOT/$grupo/grupo"
            echo -e " ${GREEN}✓${NC} Grupo $grupo configurado y carpeta creada"
        else
            echo -e " ${RED}✗${NC} Error al configurar permisos para el grupo $grupo"
        fi
    else
        echo -e " ${RED}✗${NC} Error al crear el grupo $grupo"
    fi
}

function Eliminar-Grupo {
    echo -e "${CYAN}=== ELIMINAR GRUPO ===${NC}"
    
    verificar_comando "groupdel"
    
    read -p "Nombre del grupo a eliminar: " grupo
    
    if ! grep -q "^$grupo:" /etc/group; then
        echo -e " ${RED}✗${NC} El grupo $grupo no existe"
        return
    fi
    
    local miembros=$(getent group "$grupo" | cut -d: -f4)
    if [ -n "$miembros" ]; then
        echo -e " ${YELLOW}⚠${NC} El grupo tiene miembros: $miembros"
        read -p "¿Eliminar grupo de todas formas? (s/n): " conf
        if [ "$conf" != "s" ]; then
            return
        fi
    fi
    
    if groupdel "$grupo"; then
        echo -e " ${GREEN}✓${NC} Grupo $grupo eliminado del sistema"
        
        if [ -d "$FTP_ROOT/$grupo" ]; then
            read -p "¿Eliminar carpeta física $FTP_ROOT/$grupo? (s/n): " eliminar
            if [ "$eliminar" = "s" ]; then
                rm -rf "$FTP_ROOT/$grupo"
                echo -e " ${GREEN}✓${NC} Carpeta eliminada"
            fi
        fi
    else
        echo -e " ${RED}✗${NC} Error al eliminar el grupo $grupo"
    fi
    
    reiniciar_servicio
}

function Listar-Grupos {
    echo -e "${CYAN}=== GRUPOS EXISTENTES ===${NC}"
    
    local grupos_sistema="root daemon bin sys adm tty disk lp mail news uucp man games audio video cdrom floppy dialout fax voice users"
    local todos_grupos=$(getent group | cut -d: -f1)
    local grupos_filtrados=""
    
    for g in $todos_grupos; do
        if ! echo "$grupos_sistema" | grep -qw "$g"; then
            grupos_filtrados="$grupos_filtrados $g"
        fi
    done
    
    if [ -z "$grupos_filtrados" ]; then
        echo -e " ${YELLOW}⚠${NC} No hay grupos creados"
        return
    fi
    
    for g in $grupos_filtrados; do
        echo -e " ${GREEN}▶${NC} Grupo: $g"
        local miembros_secundarios=$(getent group "$g" | cut -d: -f4)
        local miembros_primarios=$(getent passwd | awk -F: -v gid="$(getent group "$g" | cut -d: -f3)" '$4 == gid {print $1}')
        local todos_miembros=""
        
        if [ -n "$miembros_primarios" ]; then
            todos_miembros="$miembros_primarios"
        fi
        if [ -n "$miembros_secundarios" ]; then
            if [ -n "$todos_miembros" ]; then
                todos_miembros="$todos_miembros $miembros_secundarios"
            else
                todos_miembros="$miembros_secundarios"
            fi
        fi
        
        if [ -n "$todos_miembros" ]; then
            echo "$todos_miembros" | tr ' ' '\n' | sort -u | while read m; do
                echo -e "    ${WHITE}Usuario:${NC} $m"
            done
        else
            echo -e "    ${GRAY}Sin usuarios${NC}"
        fi
    done
}

# ============================================
# FUNCIONES DE GESTION DE USUARIOS (CORREGIDAS)
# ============================================

function Crear-Usuario {
    echo -e "${CYAN}=== CREAR NUEVO USUARIO ===${NC}"
    
    verificar_comando "useradd"
    verificar_comando "chpasswd"
    
    read -p "Nombre del usuario: " usuario
    read -s -p "Password: " password
    echo ""
    read -s -p "Confirmar password: " password2
    echo ""
    
    if [ "$password" != "$password2" ]; then
        echo -e " ${RED}✗${NC} Las contraseñas no coinciden"
        return
    fi
    
    read -p "Grupo para el usuario: " grupo
    
    if ! grep -q "^$grupo:" /etc/group; then
        echo -e " ${RED}✗${NC} El grupo $grupo no existe"
        return
    fi
    
    if id "$usuario" >/dev/null 2>&1; then
        echo -e " ${YELLOW}⚠${NC} El usuario $usuario ya existe"
        return
    fi
    
    # Crear usuario con shell restringido
    if useradd -m -d "/home/$usuario" -s /bin/false -g "$grupo" "$usuario" 2>/dev/null; then
        # Establecer contraseña
        echo "$usuario:$password" | chpasswd
        
        # Añadir al grupo 'users' para permisos de escritura en general
        usermod -a -G users "$usuario"
        
        # ============================================
        # CONFIGURACIÓN DE CARPETAS PARA EL USUARIO
        # ============================================
        
        # 1. Crear carpeta personal del usuario
        mkdir -p "/home/$usuario"
        
        # 2. Crear enlaces simbólicos a las carpetas que debe ver
        ln -sf "$FTP_ROOT/general" "/home/$usuario/general" 2>/dev/null
        ln -sf "$FTP_ROOT/$grupo" "/home/$usuario/mi_grupo" 2>/dev/null
        ln -sf "$FTP_ROOT/$grupo/grupo" "/home/$usuario/grupo_compartido" 2>/dev/null
        
        # 3. Crear carpeta personal DENTRO del grupo
        mkdir -p "$FTP_ROOT/$grupo/$usuario"
        chown "$usuario:$grupo" "$FTP_ROOT/$grupo/$usuario"
        chmod 770 "$FTP_ROOT/$grupo/$usuario"
        
        # 4. Configurar permisos del home del usuario
        chown -R "$usuario:$grupo" "/home/$usuario"
        chmod 750 "/home/$usuario"
        
        # 5. Crear archivo de bienvenida
        cat > "/home/$usuario/bienvenido.txt" <<EOF
Bienvenido $usuario a tu espacio FTP

Accesos disponibles:
  - general/ (carpeta pública - LECTURA/ESCRITURA)
  - mi_grupo/ (tu grupo: $grupo - LECTURA/ESCRITURA)
  - grupo_compartido/ (carpeta compartida del grupo - LECTURA/ESCRITURA)
  - $usuario/ (tu carpeta personal dentro del grupo - LECTURA/ESCRITURA)

Puedes crear, modificar y eliminar archivos en todas estas carpetas.
EOF
        
        echo -e " ${GREEN}✓${NC} Usuario $usuario creado exitosamente"
        echo -e "   ${WHITE}Accesos:${NC}"
        echo -e "   - ${CYAN}/general${NC} (lectura/escritura)"
        echo -e "   - ${CYAN}/mi_grupo${NC} (carpeta del grupo)"
        echo -e "   - ${CYAN}/grupo_compartido${NC} (carpeta compartida)"
        echo -e "   - ${CYAN}/$usuario${NC} (carpeta personal en el grupo)"
    else
        echo -e " ${RED}✗${NC} Error al crear usuario"
    fi
    
    reiniciar_servicio
}

function Crear-Usuarios-Lote {
    echo -e "${CYAN}=== CREAR USUARIOS EN LOTE ===${NC}"
    
    verificar_comando "useradd"
    verificar_comando "chpasswd"
    
    read -p "Cuantos usuarios? " cantidad
    read -s -p "Password base para todos: " password_base
    echo ""
    
    local creados=0
    local fallidos=0
    
    for ((i=1; i<=cantidad; i++)); do
        echo -e "\n${YELLOW}--- Datos del usuario $i ---${NC}"
        read -p "Nombre: " nombre
        read -p "Grupo para $nombre: " grupo
        
        if ! grep -q "^$grupo:" /etc/group; then
            echo -e " ${RED}✗${NC} El grupo $grupo no existe, saltando..."
            fallidos=$((fallidos+1))
            continue
        fi
        
        if id "$nombre" >/dev/null 2>&1; then
            echo -e " ${YELLOW}⚠${NC} El usuario $nombre ya existe, saltando..."
            fallidos=$((fallidos+1))
            continue
        fi
        
        if useradd -m -d "/home/$nombre" -s /bin/false -g "$grupo" "$nombre" 2>/dev/null; then
            echo "$nombre:$password_base" | chpasswd
            usermod -a -G users "$nombre"
            
            # Configurar accesos
            mkdir -p "/home/$nombre"
            ln -sf "$FTP_ROOT/general" "/home/$nombre/general" 2>/dev/null
            ln -sf "$FTP_ROOT/$grupo" "/home/$nombre/mi_grupo" 2>/dev/null
            ln -sf "$FTP_ROOT/$grupo/grupo" "/home/$nombre/grupo_compartido" 2>/dev/null
            
            # Crear carpeta personal dentro del grupo
            mkdir -p "$FTP_ROOT/$grupo/$nombre"
            chown "$nombre:$grupo" "$FTP_ROOT/$grupo/$nombre"
            chmod 770 "$FTP_ROOT/$grupo/$nombre"
            
            chown -R "$nombre:$grupo" "/home/$nombre"
            chmod 750 "/home/$nombre"
            
            cat > "/home/$nombre/bienvenido.txt" <<EOF
Bienvenido $nombre a tu espacio FTP

Accesos disponibles:
  - general/ (carpeta pública - LECTURA/ESCRITURA)
  - mi_grupo/ (tu grupo: $grupo - LECTURA/ESCRITURA)
  - grupo_compartido/ (carpeta compartida del grupo - LECTURA/ESCRITURA)
  - $nombre/ (tu carpeta personal dentro del grupo - LECTURA/ESCRITURA)
EOF
            
            echo -e " ${GREEN}✓${NC} OK: $nombre agregado"
            creados=$((creados+1))
        else
            echo -e " ${RED}✗${NC} Error en $nombre"
            fallidos=$((fallidos+1))
        fi
    done
    
    echo -e "\n${GREEN}✓${NC} Usuarios creados: $creados, Fallidos: $fallidos"
    reiniciar_servicio
}

function Eliminar-Usuario {
    echo -e "${CYAN}=== ELIMINAR USUARIO ===${NC}"
    
    verificar_comando "userdel"
    
    read -p "Nombre del usuario a eliminar: " usuario
    
    if id "$usuario" >/dev/null 2>&1; then
        grupo=$(id -gn "$usuario" 2>/dev/null)
        
        if [ -d "$FTP_ROOT/$grupo/$usuario" ]; then
            rm -rf "$FTP_ROOT/$grupo/$usuario"
        fi
        
        if userdel -r "$usuario" 2>/dev/null; then
            echo -e " ${GREEN}✓${NC} Usuario eliminado"
        else
            echo -e " ${RED}✗${NC} Error al eliminar usuario"
        fi
    else
        echo -e " ${RED}✗${NC} El usuario $usuario no existe"
    fi
    
    reiniciar_servicio
}

function Cambiar-GrupoUsuario {
    echo -e "${CYAN}=== CAMBIAR GRUPO DE USUARIO ===${NC}"
    
    read -p "Nombre del usuario: " usuario
    read -p "Nuevo grupo: " nuevo_grupo
    
    if ! id "$usuario" >/dev/null 2>&1; then
        echo -e " ${RED}✗${NC} El usuario $usuario no existe"
        return
    fi
    
    if ! grep -q "^$nuevo_grupo:" /etc/group; then
        echo -e " ${RED}✗${NC} El grupo $nuevo_grupo no existe"
        return
    fi
    
    grupo_anterior=$(id -gn "$usuario" 2>/dev/null)
    
    if usermod -g "$nuevo_grupo" "$usuario"; then
        # Mover carpeta personal
        if [ -d "$FTP_ROOT/$grupo_anterior/$usuario" ]; then
            mv "$FTP_ROOT/$grupo_anterior/$usuario" "$FTP_ROOT/$nuevo_grupo/" 2>/dev/null
        else
            mkdir -p "$FTP_ROOT/$nuevo_grupo/$usuario"
            chown "$usuario:$nuevo_grupo" "$FTP_ROOT/$nuevo_grupo/$usuario"
        fi
        
        chown -R "$usuario:$nuevo_grupo" "$FTP_ROOT/$nuevo_grupo/$usuario" 2>/dev/null
        
        # Actualizar enlaces
        rm -f "/home/$usuario/mi_grupo" 2>/dev/null
        rm -f "/home/$usuario/grupo_compartido" 2>/dev/null
        
        ln -sf "$FTP_ROOT/$nuevo_grupo" "/home/$usuario/mi_grupo" 2>/dev/null
        ln -sf "$FTP_ROOT/$nuevo_grupo/grupo" "/home/$usuario/grupo_compartido" 2>/dev/null
        
        chown -R "$usuario:$nuevo_grupo" "/home/$usuario"
        
        echo -e " ${GREEN}✓${NC} Usuario movido al grupo $nuevo_grupo"
    else
        echo -e " ${RED}✗${NC} Error al cambiar grupo"
    fi
    
    reiniciar_servicio
}

# ============================================
# FUNCIONES DE UTILIDADES
# ============================================

function Verificar-Configuracion {
    echo -e "${CYAN}=== VERIFICACION DE CONFIGURACION ===${NC}"
    
    if verificar_servicio; then
        echo -e " ${GREEN}✓${NC} Servicio vsftpd: RUNNING"
    else
        echo -e " ${RED}✗${NC} Servicio vsftpd: INACTIVO"
    fi
    
    if netstat -tlnp 2>/dev/null | grep -q ":21 "; then
        echo -e " ${GREEN}✓${NC} Puerto 21 (FTP): LISTENING"
    else
        echo -e " ${RED}✗${NC} Puerto 21: NO LISTENING"
    fi
    
    if [ -f "$FTP_CONFIG" ]; then
        echo -e " ${GREEN}✓${NC} Archivo config: $FTP_CONFIG"
        echo -e "${WHITE}Configuración destacada:${NC}"
        grep -E "chroot_local_user|anon_root" "$FTP_CONFIG" | head -3
    fi
    
    echo -e "\n${WHITE}Permisos de carpetas:${NC}"
    ls -la "$FTP_ROOT" 2>/dev/null | grep -E "general|reprobados|recursadores" || echo "  No hay carpetas"
    
    echo -e "\n${WHITE}Permisos de general:${NC}"
    ls -la "$FTP_ROOT/general" 2>/dev/null | head -5 || echo "  No existe"
}

function Resetear-Todo {
    echo -e "${RED}=== RESETEAR TODO EL SISTEMA ===${NC}"
    read -p "¿Esta seguro? Escriba 'SI' para confirmar: " confirmar
    
    if [ "$confirmar" != "SI" ]; then
        return
    fi
    
    getent passwd | grep "/bin/false" | cut -d: -f1 | while read u; do
        userdel -r "$u" 2>/dev/null
    done
    echo -e " ${GREEN}✓${NC} Usuarios FTP eliminados"
    
    getent group | cut -d: -f1 | while read g; do
        if [ "$g" != "root" ] && [ "$g" != "daemon" ] && [ "$g" != "bin" ] && \
           [ "$g" != "sys" ] && [ "$g" != "adm" ] && [ "$g" != "tty" ] && \
           [ "$g" != "disk" ] && [ "$g" != "lp" ] && [ "$g" != "mail" ] && \
           [ "$g" != "news" ] && [ "$g" != "uucp" ] && [ "$g" != "man" ] && \
           [ "$g" != "games" ] && [ "$g" != "audio" ] && [ "$g" != "video" ] && \
           [ "$g" != "cdrom" ] && [ "$g" != "floppy" ] && [ "$g" != "dialout" ] && \
           [ "$g" != "fax" ] && [ "$g" != "voice" ] && [ "$g" != "users" ]; then
            groupdel "$g" 2>/dev/null
        fi
    done
    echo -e " ${GREEN}✓${NC} Grupos personalizados eliminados"
    
    if [ -d "$FTP_ROOT" ]; then
        rm -rf "$FTP_ROOT"
        echo -e " ${GREEN}✓${NC} Directorio $FTP_ROOT eliminado"
    fi
    
    if [ -f "${FTP_CONFIG}.original" ]; then
        cp "${FTP_CONFIG}.original" "$FTP_CONFIG"
        echo -e " ${GREEN}✓${NC} Configuracion restaurada"
    fi
    
    reiniciar_servicio
    echo -e "${GREEN}✓ Limpieza completa${NC}"
}

# ============================================
# FUNCIONES PARA USUARIO ANÓNIMO
# ============================================

verificar_usuario_anonimo() {
    echo -e "${CYAN}=== VERIFICANDO USUARIO PARA ACCESO ANÓNIMO ===${NC}"
    
    if id ftp >/dev/null 2>&1; then
        echo -e " ${GREEN}✓${NC} Usuario 'ftp' existe en el sistema"
        return 0
    else
        echo -e " ${YELLOW}⚠${NC} Usuario 'ftp' no encontrado. Creándolo..."
        useradd -r -s /bin/false ftp
        if [ $? -eq 0 ]; then
            echo -e " ${GREEN}✓${NC} Usuario 'ftp' creado correctamente"
        else
            echo -e " ${RED}✗${NC} Error al crear usuario 'ftp'"
        fi
    fi
}

configurar_usuario_anonimo() {
    echo -e "${CYAN}=== CONFIGURANDO USUARIO PARA ACCESO ANÓNIMO ===${NC}"
    
    if ! id ftp >/dev/null 2>&1; then
        echo -e " ${YELLOW}⚠${NC} Usuario 'ftp' no encontrado. Creándolo..."
        useradd -r -s /bin/false ftp
    fi
    
    if [ ! -d "/home/ftp" ]; then
        echo -e " ${YELLOW}⚠${NC} Directorio /home/ftp no existe. Creándolo..."
        mkdir -p /home/ftp
        chown ftp:ftp /home/ftp
        chmod 755 /home/ftp
        echo -e " ${GREEN}✓${NC} Directorio /home/ftp creado"
    fi
    
    local ftp_home=$(grep ^ftp /etc/passwd | cut -d: -f6)
    if [ "$ftp_home" != "/home/ftp" ] && [ "$ftp_home" != "/var/empty" ]; then
        echo -e " ${YELLOW}⚠${NC} Home del usuario ftp es $ftp_home. Cambiando a /home/ftp..."
        usermod -d /home/ftp ftp
    fi
    
    echo -e " ${GREEN}✓${NC} Usuario anónimo configurado correctamente"
}

# ============================================
# MENU PRINCIPAL
# ============================================

function Menu {
    local opcion
    
    while true; do
        clear
        echo -e "${PURPLE}===========================================================${NC}"
        echo -e "${PURPLE}           MENU PRINCIPAL FTP - DEVUAN DAEDALUS           ${NC}"
        echo -e "${PURPLE}===========================================================${NC}"
        echo -e "${WHITE} 1  Verificar instalacion FTP${NC}"
        echo -e "${WHITE} 2  Instalar FTP${NC}"
        echo -e "${WHITE} 3  Configurar sitio FTP${NC}"
        echo -e "${WHITE} 4  Configurar permisos${NC}"
        echo -e "${WHITE} 5  Configurar ACLs${NC}"
        echo -e "${WHITE} 6  Configurar red${NC}"
        echo -e "${WHITE} 7  INSTALAR TODO${NC}"
        echo -e "${WHITE} 8  Crear grupo${NC}"
        echo -e "${WHITE} 8a ${CYAN}VERIFICAR USUARIO ANÓNIMO FTP${NC}"
        echo -e "${WHITE} 8b ${CYAN}CONFIGURAR USUARIO ANÓNIMO${NC}"
        echo -e "${WHITE} 9  Eliminar grupo${NC}"
        echo -e "${WHITE}10 Listar grupos y usuarios${NC}"
        echo -e "${WHITE}11 Crear usuario individual${NC}"
        echo -e "${WHITE}12 Crear usuarios en lote${NC}"
        echo -e "${WHITE}13 Eliminar usuario${NC}"
        echo -e "${WHITE}14 Cambiar grupo de usuario${NC}"
        echo -e "${WHITE}15 Verificar configuracion actual${NC}"
        echo -e "${WHITE}16 Resetear todo${NC}"
        echo -e "${RED}17 Salir${NC}"
        echo -e "${PURPLE}===========================================================${NC}"
        
        read -p "Selecciona una opcion: " opcion
        
        case $opcion in
            1) Verificar-FTP ;;
            2) Instalar-FTP ;;
            3) Configurar-SitioFTP ;;
            4) Configurar-Permisos ;;
            5) Configurar-ACLs ;;
            6) Configurar-Red ;;
            7) Instalar-Todo ;;
            8) Crear-Grupo ;;
            8a) verificar_usuario_anonimo; 
                read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            8b) configurar_usuario_anonimo; 
                read -p "$(echo -e "${YELLOW}⏎${NC} ${WHITE}PRESIONE ENTER...${NC} ")" ;;
            9) Eliminar-Grupo ;;
            10) Listar-Grupos ;;
            11) Crear-Usuario ;;
            12) Crear-Usuarios-Lote ;;
            13) Eliminar-Usuario ;;
            14) Cambiar-GrupoUsuario ;;
            15) Verificar-Configuracion ;;
            16) Resetear-Todo ;;
            17) 
                echo -e "${GREEN}¡Hasta luego!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Opcion invalida${NC}"
                ;;
        esac
        
        if [ "$opcion" != "17" ]; then
            echo ""
            read -p "Presiona ENTER para continuar..."
        fi
    done
}

# Limpiar pantalla y mostrar menu
clear
Menu