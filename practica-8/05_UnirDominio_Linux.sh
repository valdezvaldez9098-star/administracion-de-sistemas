#!/bin/bash
# ============================================================
# PRACTICA 8 - Script 05: Union al Dominio (Ubuntu 24.04)
# Ejecutar como root: sudo bash 05_UnirDominio_Linux.sh
# ============================================================

# ============== CONFIGURACION - EDITAR AQUI ================
DOMAIN="PRACTICA8.LOCAL"            # dominio en MAYUSCULAS
DOMAIN_LOWER="practica8.local"      # dominio en minusculas
DC_IP="192.168.10.10"               # IP del Windows Server DC
AD_USER="Administrator"             # usuario administrador del dominio
AD_PASS="P@ssw0rd123"               # contrasena del admin de dominio
HOSTNAME_LINUX="ubuntu-practica8"   # nombre de esta maquina Linux
# ===========================================================

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()     { echo -e "${GREEN}[OK]${NC} $1"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    error "Ejecuta este script como root: sudo bash $0"
fi

# ============================================================
# PASO 1: Configurar hostname
# ============================================================
log "Configurando hostname: $HOSTNAME_LINUX"
hostnamectl set-hostname "$HOSTNAME_LINUX"
ok "Hostname establecido: $(hostname)"

# ============================================================
# PASO 2: Configurar DNS para apuntar al DC
# ============================================================
log "Configurando DNS para apuntar al DC ($DC_IP)..."

# Detectar interfaz de red activa
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
log "Interfaz de red detectada: $IFACE"

# Configurar DNS via systemd-resolved
cat > /etc/systemd/resolved.conf << EOF
[Resolve]
DNS=$DC_IP
Domains=$DOMAIN_LOWER
FallbackDNS=8.8.8.8
EOF

systemctl restart systemd-resolved
ok "DNS configurado en systemd-resolved."

# Configurar /etc/hosts
# Eliminar entradas antiguas del dominio y agregar la nueva
sed -i "/practica8/d" /etc/hosts
echo "$DC_IP    practica8-dc.$DOMAIN_LOWER    practica8-dc" >> /etc/hosts
ok "/etc/hosts actualizado."

# Verificar conectividad con el DC
log "Probando conectividad con el DC ($DC_IP)..."
if ping -c 2 "$DC_IP" &>/dev/null; then
    ok "El DC responde."
else
    error "No se puede alcanzar el DC en $DC_IP. Verifica la red."
fi

# ============================================================
# PASO 3: Instalar paquetes necesarios
# ============================================================
log "Actualizando repositorios e instalando paquetes..."
apt-get update -qq

PAQUETES="realmd sssd sssd-tools adcli samba-common-bin krb5-user packagekit"
apt-get install -y $PAQUETES || error "Fallo la instalacion de paquetes."
ok "Paquetes instalados: $PAQUETES"

# ============================================================
# PASO 4: Configurar Kerberos
# ============================================================
log "Configurando Kerberos (/etc/krb5.conf)..."
cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $DOMAIN
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    $DOMAIN = {
        kdc = practica8-dc.$DOMAIN_LOWER
        admin_server = practica8-dc.$DOMAIN_LOWER
    }

[domain_realm]
    .$DOMAIN_LOWER = $DOMAIN
    $DOMAIN_LOWER  = $DOMAIN
EOF
ok "Kerberos configurado."

# ============================================================
# PASO 5: Configurar realm para descubrir el dominio
# ============================================================
log "Descubriendo el dominio con realm..."
realm discover "$DOMAIN_LOWER" || warn "realm discover fallo, continuando de todos modos..."

# ============================================================
# PASO 6: Unir al dominio
# ============================================================
log "Uniendo Ubuntu al dominio $DOMAIN ..."
echo "$AD_PASS" | realm join --user="$AD_USER" "$DOMAIN_LOWER" --membership-software=adcli -v

if [ $? -eq 0 ]; then
    ok "Union al dominio exitosa!"
else
    # Intento alternativo con kinit
    warn "realm join fallo. Intentando con kinit + net ads..."
    echo "$AD_PASS" | kinit "${AD_USER}@${DOMAIN}"
    net ads join -k
    if [ $? -ne 0 ]; then
        error "No se pudo unir al dominio. Verifica las credenciales y la conectividad."
    fi
fi

# ============================================================
# PASO 7: Configurar SSSD
# ============================================================
log "Configurando /etc/sssd/sssd.conf ..."
cat > /etc/sssd/sssd.conf << EOF
[sssd]
domains = $DOMAIN_LOWER
config_file_version = 2
services = nss, pam

[domain/$DOMAIN_LOWER]
ad_domain = $DOMAIN_LOWER
krb5_realm = $DOMAIN
realmd_tags = manages-system joined-with-adcli
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = False
fallback_homedir = /home/%u@%d
access_provider = ad

# Desactivar lista de control de acceso (todos los usuarios AD pueden iniciar sesion)
ad_access_filter = (objectClass=user)
EOF

chmod 600 /etc/sssd/sssd.conf
ok "/etc/sssd/sssd.conf configurado (fallback_homedir = /home/%u@%d)."

# ============================================================
# PASO 8: Habilitar creacion automatica de home directory
# ============================================================
log "Habilitando pam_mkhomedir..."
pam-auth-update --enable mkhomedir
ok "pam_mkhomedir habilitado."

# Alternativa manual si pam-auth-update no funciona
if ! grep -q "pam_mkhomedir" /etc/pam.d/common-session; then
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" >> /etc/pam.d/common-session
    ok "pam_mkhomedir agregado a /etc/pam.d/common-session."
fi

# ============================================================
# PASO 9: Configurar sudoers para usuarios AD
# ============================================================
log "Configurando sudo para usuarios del dominio AD..."

# Crear archivo de sudoers para administradores del dominio
cat > /etc/sudoers.d/ad-admins << EOF
# Sudoers para usuarios de Active Directory - Practica 8
# Los miembros del grupo 'Domain Admins' tienen acceso sudo completo
%domain\ admins ALL=(ALL) ALL

# Los miembros del grupo 'Cuates' tienen sudo limitado (solo comandos seguros)
%cuates ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/systemctl status *

# Descomenta la siguiente linea si quieres que NoCuates tambien tenga sudo:
# %nocuates ALL=(ALL) ALL
EOF

chmod 440 /etc/sudoers.d/ad-admins
ok "/etc/sudoers.d/ad-admins configurado."

# Verificar sintaxis del archivo sudoers
visudo -c -f /etc/sudoers.d/ad-admins && ok "Sintaxis de sudoers correcta." || warn "Revisar sintaxis de sudoers."

# ============================================================
# PASO 10: Reiniciar servicios
# ============================================================
log "Reiniciando servicios sssd y systemd-resolved..."
systemctl enable sssd
systemctl restart sssd
systemctl restart systemd-resolved
ok "Servicios reiniciados."

# ============================================================
# PASO 11: Verificacion
# ============================================================
log "Verificando configuracion..."
sleep 3

echo ""
echo "=== Estado del realm ==="
realm list

echo ""
echo "=== Prueba de resolucion de usuario AD ==="
id "cmendoza@$DOMAIN_LOWER" 2>/dev/null && ok "Usuario cmendoza encontrado en AD." || warn "No se pudo resolver cmendoza. Espera unos segundos y reintenta."

echo ""
echo "=== Estado de SSSD ==="
systemctl status sssd --no-pager | head -15

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Union al dominio completada exitosamente!  ${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Para iniciar sesion con un usuario AD:"
echo "   ssh cmendoza@$HOSTNAME_LINUX"
echo "   o bien al inicio de sesion grafico: cmendoza@$DOMAIN_LOWER"
echo ""
echo "Su home directory se creara automaticamente en: /home/cmendoza@$DOMAIN_LOWER"
