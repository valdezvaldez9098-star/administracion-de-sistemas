# Dockerfile — Servidor FTP (vsftpd)
# Base: Devuan Daedalus 5.0.1 (equivalente a Debian 12 sin systemd)
FROM debian:12-slim

LABEL maintainer="Tarea10-FTP"
LABEL description="vsftpd con jaulas de usuario - Devuan Daedalus 5.0.1"

# Devuan Daedalus es compatible con paquetes Debian 12 (Bookworm).
# Instalamos sysvinit-core para que sea coherente con Devuan (sin systemd).
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        vsftpd \
        passwd \
        procps \
        iproute2 \
        util-linux \
        sysvinit-utils \
        iputils-ping \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Estructura de directorios FTP
RUN mkdir -p /home/ftp/LocalUser /home/ftp/public && \
    chown root:root /home/ftp && chmod 755 /home/ftp && \
    chown root:users /home/ftp/public && chmod 2775 /home/ftp/public

# Crear grupo users si no existe
RUN groupadd -f users

# Configuración vsftpd
RUN cat > /etc/vsftpd.conf << 'EOF'
listen=YES
listen_ipv6=NO

anonymous_enable=NO
local_enable=YES
write_enable=YES

dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES

secure_chroot_dir=/var/run/vsftpd/empty

pam_service_name=vsftpd

ssl_enable=NO

pasv_enable=YES
pasv_min_port=21100
pasv_max_port=21110
pasv_address=127.0.0.1

chroot_local_user=YES
allow_writeable_chroot=YES

user_sub_token=$USER
local_root=/home/ftp/LocalUser/$USER

local_umask=002
EOF

# Directorio requerido por vsftpd para chroot seguro
RUN mkdir -p /var/run/vsftpd/empty

# Copiar scripts de administración
COPY scripts/ /opt/ftp-admin/scripts/
COPY entrypoint.sh /opt/ftp-admin/entrypoint.sh

RUN chmod +x /opt/ftp-admin/scripts/*.sh \
             /opt/ftp-admin/entrypoint.sh

EXPOSE 21 21100-21110

CMD ["/opt/ftp-admin/entrypoint.sh"]
