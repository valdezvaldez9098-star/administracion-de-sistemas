#!/usr/bin/env bash
# =============================================================================
# respaldos.sh — Respaldos automáticos, restauración e integridad
# =============================================================================

BACKUP_DIR="${PROYECTO_DIR}/backups"
CRON_SCRIPT="${PROYECTO_DIR}/scripts/cron_respaldo.sh"

# ─── Respaldo manual ──────────────────────────────────────────────────────────
respaldo_manual() {
    paso 1 "Creando respaldo manual de los buzones"
    mkdir -p "$BACKUP_DIR"

    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_file="${BACKUP_DIR}/mail_backup_${timestamp}.tar.gz"
    local checksum_file="${backup_file}.sha256"

    info "Fuente:  volumen Docker 'mail_data' (/var/mail dentro del contenedor)"
    info "Destino: ${backup_file}"
    echo ""

    # Verificar que el contenedor existe (puede estar detenido)
    if ! docker volume ls --format '{{.Name}}' | grep -q '^mail_data$'; then
        advertencia "El volumen 'mail_data' no existe todavía."
        info "Inicia el stack al menos una vez para crearlo."
        return 1
    fi

    info "Empaquetando volumen mail_data..."
    if docker run --rm \
        -v mail_data:/source:ro \
        -v "${BACKUP_DIR}:/backup" \
        alpine:latest \
        tar czf "/backup/mail_backup_${timestamp}.tar.gz" -C /source . ; then

        exito "Respaldo creado: ${backup_file}"

        # Generar checksum SHA256
        info "Calculando checksum de integridad..."
        sha256sum "$backup_file" > "$checksum_file"
        exito "Checksum: ${checksum_file}"

        local size
        size=$(du -sh "$backup_file" | cut -f1)
        info "Tamaño del respaldo: ${size}"
    else
        error "Error al crear el respaldo."
        return 1
    fi
}

# ─── Instalar cron de respaldo automático ────────────────────────────────────
instalar_cron_respaldo() {
    paso 2 "Instalando tarea cron para respaldo cada 24 horas"
    requerir_root

    # Generar el script de respaldo autónomo
    cat > "$CRON_SCRIPT" << 'CRONSCRIPT'
#!/usr/bin/env bash
# cron_respaldo.sh — Ejecutado por cron cada 24 horas
# Genera una copia comprimida de los buzones de correo

BACKUP_DIR="__BACKUP_DIR__"
LOG_FILE="__LOG_FILE__"
RETENCION_DIAS=7   # mantener respaldos de los últimos 7 días

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
BACKUP_FILE="${BACKUP_DIR}/mail_backup_${TIMESTAMP}.tar.gz"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] [BACKUP] Iniciando respaldo automático..." >> "$LOG_FILE"

# Verificar que el volumen existe
if ! docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q '^mail_data$'; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Volumen mail_data no encontrado" >> "$LOG_FILE"
    exit 1
fi

# Crear respaldo
if docker run --rm \
    -v mail_data:/source:ro \
    -v "${BACKUP_DIR}:/backup" \
    alpine:latest \
    tar czf "/backup/mail_backup_${TIMESTAMP}.tar.gz" -C /source . 2>> "$LOG_FILE"; then

    # Checksum
    sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"

    TAMANIO=$(du -sh "$BACKUP_FILE" | cut -f1)
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] Respaldo: ${BACKUP_FILE} (${TAMANIO})" >> "$LOG_FILE"

    # Limpiar respaldos viejos
    find "$BACKUP_DIR" -name "mail_backup_*.tar.gz" -mtime +${RETENCION_DIAS} -delete
    find "$BACKUP_DIR" -name "*.sha256" -mtime +${RETENCION_DIAS} -delete
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Limpieza de respaldos >$RETENCION_DIAS días" >> "$LOG_FILE"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Falló la creación del respaldo" >> "$LOG_FILE"
    exit 1
fi
CRONSCRIPT

    # Sustituir variables en el script
    sed -i "s|__BACKUP_DIR__|${BACKUP_DIR}|g" "$CRON_SCRIPT"
    sed -i "s|__LOG_FILE__|${LOG_FILE}|g"     "$CRON_SCRIPT"
    chmod +x "$CRON_SCRIPT"
    exito "Script de respaldo generado: ${CRON_SCRIPT}"

    # Instalar en crontab del sistema
    local cron_entry="0 2 * * * root ${CRON_SCRIPT}"
    local cron_file="/etc/cron.d/mailserver_backup"

    cat > "$cron_file" << CRON
# Respaldo automático de buzones de correo — cada día a las 02:00
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root ${CRON_SCRIPT}
CRON

    exito "Tarea cron instalada: ${cron_file}"
    info "Se ejecutará todos los días a las 02:00 AM"
    info "Logs en: ${LOG_FILE}"

    # Reiniciar cron
    service cron restart 2>/dev/null && exito "Servicio cron reiniciado" || \
        advertencia "Reinicia cron manualmente: sudo service cron restart"
}

# ─── Listar respaldos ─────────────────────────────────────────────────────────
listar_respaldos() {
    paso 1 "Respaldos disponibles en ${BACKUP_DIR}"
    echo ""

    if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
        advertencia "No hay respaldos en ${BACKUP_DIR}"
        return 0
    fi

    printf "  %-45s %-10s %s\n" "ARCHIVO" "TAMAÑO" "FECHA"
    echo -e "  ${DIM}────────────────────────────────────────────────────────────────────${RESET}"

    local i=1
    while IFS= read -r archivo; do
        local nombre tamanio fecha
        nombre=$(basename "$archivo")
        tamanio=$(du -sh "$archivo" 2>/dev/null | cut -f1)
        fecha=$(stat -c '%y' "$archivo" 2>/dev/null | cut -d. -f1)
        printf "  ${GREEN}[%-2d]${RESET} %-45s %-10s %s\n" "$i" "$nombre" "$tamanio" "$fecha"
        ((i++))
    done < <(find "$BACKUP_DIR" -name "mail_backup_*.tar.gz" | sort -r)
}

# ─── Restaurar respaldo ───────────────────────────────────────────────────────
restaurar_respaldo() {
    paso 1 "Restaurar un respaldo de buzones"

    listar_respaldos

    echo ""
    echo -ne "  Número de respaldo a restaurar: "
    read -r num

    # Obtener archivo por número
    local archivo
    archivo=$(find "$BACKUP_DIR" -name "mail_backup_*.tar.gz" | sort -r | sed -n "${num}p")

    if [ -z "$archivo" ] || [ ! -f "$archivo" ]; then
        error "Respaldo inválido."
        return 1
    fi

    info "Respaldo seleccionado: $(basename "$archivo")"

    # Verificar checksum
    local checksum_file="${archivo}.sha256"
    if [ -f "$checksum_file" ]; then
        info "Verificando integridad del respaldo..."
        if sha256sum -c "$checksum_file" &>/dev/null; then
            exito "Integridad verificada correctamente"
        else
            error "¡El respaldo está corrupto! No se restaurará."
            return 1
        fi
    else
        advertencia "No hay checksum para verificar — continuando de todas formas"
    fi

    echo ""
    echo -e "  ${RED}${BOLD}⚠  ADVERTENCIA: Esto sobreescribirá los buzones actuales.${RESET}"
    echo -ne "  Escribe 'RESTAURAR' para confirmar: "
    read -r conf
    [ "$conf" = "RESTAURAR" ] || { info "Operación cancelada."; return 0; }

    info "Deteniendo el stack de correo..."
    cd "$PROYECTO_DIR" && docker compose stop mailserver 2>/dev/null || true

    info "Restaurando datos en el volumen mail_data..."
    if docker run --rm \
        -v mail_data:/target \
        -v "${BACKUP_DIR}:/backup:ro" \
        alpine:latest \
        sh -c "rm -rf /target/* && tar xzf /backup/$(basename "$archivo") -C /target"; then
        exito "Restauración completada"
    else
        error "Error durante la restauración."
        info "Reinicia el stack manualmente."
        return 1
    fi

    info "Reiniciando el stack..."
    cd "$PROYECTO_DIR" && docker compose start mailserver
    exito "Servidor de correo restaurado y en línea"
}

# ─── Verificar integridad de respaldos ───────────────────────────────────────
verificar_respaldos() {
    paso 1 "Verificando integridad de todos los respaldos"
    echo ""

    local total=0 ok=0 fail=0

    while IFS= read -r archivo; do
        local nombre checksum_file
        nombre=$(basename "$archivo")
        checksum_file="${archivo}.sha256"
        ((total++))

        if [ ! -f "$checksum_file" ]; then
            advertencia "${nombre} — sin checksum, no verificable"
            continue
        fi

        if sha256sum -c "$checksum_file" &>/dev/null; then
            exito "${nombre} — íntegro"
            ((ok++))
        else
            error "${nombre} — ¡CORRUPTO!"
            ((fail++))
        fi
    done < <(find "$BACKUP_DIR" -name "mail_backup_*.tar.gz" | sort -r)

    echo ""
    echo -e "  ${BOLD}Resultado: ${ok}/${total} respaldos íntegros"
    [ "$fail" -gt 0 ] && error "${fail} respaldo(s) corruptos — elimínalos y crea uno nuevo."
}
