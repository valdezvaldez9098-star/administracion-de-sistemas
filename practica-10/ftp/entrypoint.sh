#!/bin/bash
# /opt/ftp-admin/entrypoint.sh
# Devuan Daedalus 5.0.1 — SysVinit (sin systemd)
# Restaura bind mounts de las jaulas de usuario y arranca vsftpd.

set -e

echo "[entrypoint] Iniciando restauración de bind mounts..."

PUBLIC="/home/ftp/public"
LOCAL="/home/ftp/LocalUser"

# Esperar a que el volumen Docker esté disponible
sleep 1

# Restaurar permisos del public principal
if mountpoint -q "$PUBLIC" 2>/dev/null; then
    chown root:users "$PUBLIC"
    chmod 2775 "$PUBLIC"
    echo "[entrypoint] Volumen $PUBLIC activo y con permisos correctos."
else
    echo "[entrypoint] AVISO: $PUBLIC no está montado como volumen Docker."
fi

# Restaurar bind mounts de cada usuario en LocalUser
if [ -d "$LOCAL" ]; then
    for jaula in "$LOCAL"/*/; do
        [ -d "$jaula" ] || continue
        usuario=$(basename "$jaula")
        punto="$jaula/public"

        # Solo usuarios reales que existen en /etc/passwd
        if ! id "$usuario" &>/dev/null; then
            continue
        fi

        if [ -d "$punto" ]; then
            if mountpoint -q "$punto" 2>/dev/null; then
                echo "[entrypoint] $punto ya montado, se omite."
            else
                mount --bind "$PUBLIC" "$punto"
                chown root:users "$punto"
                chmod 2775 "$punto"
                echo "[entrypoint] Restaurado bind mount: $punto"
            fi
        fi
    done
fi

echo "[entrypoint] Bind mounts restaurados. Iniciando vsftpd..."

# En Devuan dentro de contenedor arrancamos vsftpd directamente (no hay init.d activo)
vsftpd /etc/vsftpd.conf &

# Mantener el contenedor vivo
tail -f /dev/null
