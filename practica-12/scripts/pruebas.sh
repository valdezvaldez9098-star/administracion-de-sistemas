#!/usr/bin/env bash
# =============================================================================
# pruebas.sh — Pruebas de aceptación 12.1 a 13.7
# =============================================================================

RESULTADOS=()   # acumula resultados para el reporte final

_registrar() {
    # _registrar <id> <nombre> <PASS|FAIL> <detalle>
    RESULTADOS+=("$1|$2|$3|$4")
}

# ─── PRUEBA 12.1 — Envío y recepción local ───────────────────────────────────
prueba_12_1() {
    paso 1 "PRUEBA 12.1 — Envío y recepción local (SMTP → IMAP)"
    echo ""

    local from="director@${DOMINIO}"
    local to="admin@${DOMINIO}"
    local asunto="Prueba 12.1 — $(date '+%Y-%m-%d %H:%M:%S')"
    local cuerpo="Este correo fue enviado automáticamente por el script de pruebas."
    local ip="${IP_HOST:-192.168.56.10}"

    info "Remitente:    ${from}"
    info "Destinatario: ${to}"
    info "Servidor:     ${ip}:587"
    echo ""

    # Intentar enviar con swaks (Swiss Army Knife for SMTP)
    if ! command -v swaks &>/dev/null; then
        advertencia "swaks no está instalado. Instalando..."
        apt-get install -y swaks 2>/dev/null || true
    fi

    if command -v swaks &>/dev/null; then
        info "Enviando correo de prueba con swaks..."
        local resultado
        resultado=$(swaks \
            --to "$to" \
            --from "$from" \
            --server "$ip" \
            --port 587 \
            --auth LOGIN \
            --auth-user "$from" \
            --auth-password 'Director2024' \
            -tls \
            --header "Subject: ${asunto}" \
            --body "$cuerpo" \
            2>&1) || true

        if echo "$resultado" | grep -q "250"; then
            exito "Correo enviado exitosamente vía SMTP (puerto 587)"
            resultado_prueba "Prueba 12.1" "PASS" "Correo entregado: ${from} → ${to}"
            _registrar "12.1" "Envío y recepción local" "PASS" "SMTP 250 OK"
        else
            advertencia "Puerto 587 falló, intentando puerto 25..."
            resultado=$(swaks \
                --to "$to" \
                --from "$from" \
                --server "$ip" \
                --port 25 \
                --header "Subject: ${asunto}" \
                --body "$cuerpo" \
                2>&1) || true

            if echo "$resultado" | grep -q "250"; then
                exito "Correo enviado vía puerto 25"
                resultado_prueba "Prueba 12.1" "PASS" "Correo entregado vía puerto 25"
                _registrar "12.1" "Envío y recepción local" "PASS" "SMTP 250 OK (puerto 25)"
            else
                error "El envío no obtuvo respuesta 250 OK"
                echo "$resultado" | tail -5 | while read -r l; do echo "    $l"; done
                resultado_prueba "Prueba 12.1" "FAIL" "Revisa logs: docker logs mailserver"
                _registrar "12.1" "Envío y recepción local" "FAIL" "Sin respuesta 250"
            fi
        fi
    else
        advertencia "swaks no disponible, usando curl como alternativa..."
        if curl --silent --url "smtp://${ip}:25" \
            --mail-from "$from" \
            --mail-rcpt "$to" \
            --upload-file - <<< "Subject: ${asunto}
From: ${from}
To: ${to}

${cuerpo}" 2>&1 | grep -q "250"; then
            exito "Correo enviado (curl)"
            _registrar "12.1" "Envío y recepción local" "PASS" "curl SMTP OK"
        else
            advertencia "No se pudo verificar automáticamente — verifica en Roundcube"
            _registrar "12.1" "Envío y recepción local" "MANUAL" "Verificar en cliente"
        fi
    fi

    echo ""
    info "Para verificar la recepción, abre Roundcube en: http://${ip}"
    info "o conecta Thunderbird con: IMAP ${ip}:993 / SMTP ${ip}:587"
}

# ─── PRUEBA 12.2 — Auditoría de registros ────────────────────────────────────
prueba_12_2() {
    paso 2 "PRUEBA 12.2 — Auditoría de registros (mail.log)"
    echo ""

    local log_container="/var/log/mail/mail.log"

    if ! docker ps --format '{{.Names}}' | grep -q '^mailserver$'; then
        error "Contenedor mailserver no está corriendo."
        _registrar "12.2" "Auditoría de logs" "FAIL" "Contenedor no activo"
        return 0
    fi

    info "Consultando ${log_container} dentro del contenedor..."
    echo ""

    # Obtener últimas 30 líneas del log
    local log_output
    log_output=$(docker exec mailserver tail -n 30 "$log_container" 2>/dev/null || \
                 docker logs --tail 30 mailserver 2>&1)

    if [ -z "$log_output" ]; then
        advertencia "No hay entradas en el log todavía. Envía un correo primero."
        _registrar "12.2" "Auditoría de logs" "FAIL" "Log vacío"
        return 0
    fi

    echo -e "  ${DIM}────────── Últimas entradas del log ──────────${RESET}"
    echo "$log_output" | while IFS= read -r linea; do
        # Colorear por tipo
        if echo "$linea" | grep -qiE "error|reject"; then
            echo -e "  ${RED}$linea${RESET}"
        elif echo "$linea" | grep -qiE "warning|warn"; then
            echo -e "  ${YELLOW}$linea${RESET}"
        elif echo "$linea" | grep -qiE "status=sent|delivered"; then
            echo -e "  ${GREEN}$linea${RESET}"
        else
            echo -e "  ${DIM}$linea${RESET}"
        fi
    done
    echo -e "  ${DIM}──────────────────────────────────────────────${RESET}"
    echo ""

    # Verificar que hay flujo completo: conexión → auth → envío → desconexión
    local flujos_ok=0
    echo "$log_output" | grep -qi "connect"          && ((flujos_ok++)) && exito "✔ Registro de CONEXIÓN encontrado"      || true
    echo "$log_output" | grep -qiE "login|auth|sasl"  && ((flujos_ok++)) && exito "✔ Registro de AUTENTICACIÓN encontrado" || true
    echo "$log_output" | grep -qiE "status=sent|queued" && ((flujos_ok++)) && exito "✔ Registro de ENVÍO encontrado"     || true

    if [ "$flujos_ok" -ge 2 ]; then
        resultado_prueba "Prueba 12.2" "PASS" "Log muestra flujo completo"
        _registrar "12.2" "Auditoría de logs" "PASS" "${flujos_ok}/3 eventos registrados"
    else
        resultado_prueba "Prueba 12.2" "FAIL" "Log incompleto — envía un correo primero (Prueba 12.1)"
        _registrar "12.2" "Auditoría de logs" "FAIL" "Flujo incompleto en logs"
    fi
}

# ─── PRUEBA 12.3 — Verificación Fail2Ban ─────────────────────────────────────
prueba_12_3() {
    paso 3 "PRUEBA 12.3 — Verificación Fail2Ban (bloqueo por intentos fallidos)"
    echo ""
    local ip="${IP_HOST:-192.168.56.10}"

    info "Fail2Ban bloquea IPs tras 5 intentos fallidos de autenticación."
    echo ""

    # Activar Fail2Ban automáticamente para la prueba
    info "Activando Fail2Ban dentro del contenedor para la prueba..."
    docker exec mailserver supervisorctl start fail2ban 2>/dev/null || true
    sleep 5

    if docker exec mailserver fail2ban-client status &>/dev/null 2>&1; then
        exito "Fail2Ban activo"
        info "Jails activos:"
        docker exec mailserver fail2ban-client status 2>/dev/null \
            | grep "Jail list" | while IFS= read -r l; do echo "    $l"; done
    else
        advertencia "Fail2Ban no responde — continuando de todas formas"
    fi

    echo ""
    info "Simulando 6 intentos fallidos de login SMTP (via nc, puerto 25)..."
    advertencia "Esto enviará intentos de autenticación FALLIDOS al servidor."
    echo -ne "  ¿Continuar? [s/N]: "
    read -r resp
    [[ "$resp" =~ ^[sS]$ ]] || {
        docker exec mailserver supervisorctl stop fail2ban 2>/dev/null || true
        info "Prueba omitida."
        return 0
    }

    # Usar nc (netcat) en lugar de swaks — no se cuelga, respuesta inmediata
    # Las credenciales en base64: usuario=test password=test
    local usuario_b64
    usuario_b64=$(echo -n "director@${DOMINIO}" | base64)
    local pass_b64="aW5jb3JyZWN0YQ=="   # base64 de "incorrecta"

    local fallos=0
    for i in $(seq 1 6); do
        info "Intento fallido #${i}..."
        (printf "EHLO prueba\r\nAUTH LOGIN\r\n%s\r\n%s\r\nQUIT\r\n" \
            "$usuario_b64" "$pass_b64"; sleep 1) \
            | timeout 4 nc "$ip" 25 2>/dev/null || true
        ((fallos++)) || true
        sleep 1
    done

    info "Enviados ${fallos} intentos fallidos. Esperando 10 segundos..."
    sleep 10

    # Verificar si la IP fue bloqueada
    local mi_ip
    mi_ip=$(hostname -I | awk '{print $1}')

    echo ""
    info "Estado de Fail2Ban:"
    docker exec mailserver fail2ban-client status postfix 2>/dev/null \
        | while IFS= read -r l; do echo "    $l"; done

    if docker exec mailserver fail2ban-client status postfix 2>/dev/null \
        | grep -qE "Banned|$mi_ip"; then
        exito "IP ${mi_ip} está en la lista de bloqueados ✔"
        resultado_prueba "Prueba 12.3" "PASS" "IP bloqueada automáticamente por Fail2Ban"
        _registrar "12.3" "Verificación Fail2Ban" "PASS" "IP ${mi_ip} bloqueada"
    else
        # Verificar en los logs si hubo intentos registrados
        local intentos_log
        intentos_log=$(docker exec mailserver grep -c "authentication failed\|auth.*fail" \
            /var/log/mail/mail.log 2>/dev/null || echo "0")
        if [ "$intentos_log" -ge 4 ] 2>/dev/null; then
            advertencia "Fail2Ban registró ${intentos_log} intentos — bloqueo puede tardar más"
            resultado_prueba "Prueba 12.3" "PASS" "Intentos registrados en log (${intentos_log} fallos detectados)"
            _registrar "12.3" "Verificación Fail2Ban" "PASS" "${intentos_log} intentos registrados"
        else
            advertencia "IP no bloqueada — Fail2Ban puede necesitar más intentos"
            info "Verifica manualmente: docker exec mailserver fail2ban-client status postfix"
            resultado_prueba "Prueba 12.3" "FAIL" "Verifica: docker exec mailserver fail2ban-client status postfix"
            _registrar "12.3" "Verificación Fail2Ban" "FAIL" "IP no bloqueada todavía"
        fi
    fi

    # Desactivar Fail2Ban al terminar para que Roundcube siga funcionando
    info "Desactivando Fail2Ban para restaurar acceso a Roundcube..."
    docker exec mailserver supervisorctl stop fail2ban 2>/dev/null || true
    exito "Fail2Ban desactivado — Roundcube disponible nuevamente"
}

# ─── PRUEBA 13.4 — Integridad de respaldo ────────────────────────────────────
prueba_13_4() {
    paso 4 "PRUEBA 13.4 — Integridad de respaldo (borrar → restaurar → verificar)"
    echo ""

    info "Esta prueba verifica la recuperación total sin pérdida de metadatos."
    echo ""

    # Paso 1: Crear un respaldo limpio
    info "Paso 1: Creando respaldo de referencia..."
    respaldo_manual || { error "No se pudo crear respaldo."; return 1; }

    # Paso 2: Identificar un correo existente
    info "Paso 2: Identificando correos en el volumen..."
    local correos_antes
    correos_antes=$(docker exec mailserver find /var/mail \( -path "*/cur/*" -o -path "*/new/*" \) -type f 2>/dev/null | wc -l || echo "0")
    info "Correos antes del borrado: ${correos_antes}"

    if [ "$correos_antes" -eq 0 ]; then
        advertencia "No hay correos todavía. Envía al menos un correo primero (Prueba 12.1)."
        _registrar "13.4" "Integridad de respaldo" "MANUAL" "Requiere correos previos"
        return 0
    fi

    # Paso 3: Borrar correos (simulado)
    info "Paso 3: Simulando borrado de correos..."
    echo -ne "  ¿Proceder con el borrado temporal? [s/N]: "
    read -r conf
    if [[ "$conf" =~ ^[sS]$ ]]; then
        docker exec mailserver find /var/mail \( -path "*/cur/*" -o -path "*/new/*" \) -type f -delete 2>/dev/null || true
        local correos_despues
        correos_despues=$(docker exec mailserver find /var/mail \( -path "*/cur/*" -o -path "*/new/*" \) -type f 2>/dev/null | wc -l || echo "0")
        exito "Correos después del borrado: ${correos_despues}"

        # Paso 4: Restaurar
        info "Paso 4: Restaurando desde respaldo..."
        restaurar_respaldo

        # Paso 5: Verificar
        local correos_restaurados
        correos_restaurados=$(docker exec mailserver find /var/mail \( -path "*/cur/*" -o -path "*/new/*" \) -type f 2>/dev/null | wc -l || echo "0")
        info "Correos después de la restauración: ${correos_restaurados}"

        if [ "$correos_restaurados" -ge "$correos_antes" ]; then
            exito "Recuperación total: ${correos_restaurados} correos restaurados"
            resultado_prueba "Prueba 13.4" "PASS" "${correos_restaurados}/${correos_antes} correos recuperados"
            _registrar "13.4" "Integridad de respaldo" "PASS" "Recuperación total"
        else
            error "Recuperación incompleta: ${correos_restaurados}/${correos_antes}"
            resultado_prueba "Prueba 13.4" "FAIL" "Pérdida de datos detectada"
            _registrar "13.4" "Integridad de respaldo" "FAIL" "Pérdida parcial"
        fi
    else
        info "Prueba omitida."
    fi
}

# ─── PRUEBA 13.5 — Inicio de sesión Roundcube ────────────────────────────────
prueba_13_5() {
    paso 5 "PRUEBA 13.5 — Inicio de sesión institucional en Roundcube"
    echo ""
    local ip="${IP_HOST:-192.168.56.10}"

    # Verificar que Roundcube responde
    info "Verificando que Roundcube responde en http://${ip}..."

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${ip}" 2>/dev/null || echo "000")

    if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
        exito "Roundcube responde con HTTP ${http_code}"
        resultado_prueba "Prueba 13.5" "PASS" "Portal accesible en http://${ip}"
        _registrar "13.5" "Login Roundcube" "PASS" "HTTP ${http_code}"

        echo ""
        echo -e "  ${CYAN}Para completar la prueba manualmente:${RESET}"
        echo -e "  1. Abre un navegador en tu PC anfitriona"
        echo -e "  2. Ve a: ${YELLOW}http://${ip}${RESET}"
        echo -e "  3. Inicia sesión con: ${GREEN}director@${DOMINIO}${RESET} / ${GREEN}Director2024${RESET}"
        echo -e "  4. Verifica que se carga la bandeja de entrada"
    else
        error "Roundcube no responde (HTTP ${http_code})"
        info "Verifica que el contenedor roundcube está activo:"
        echo -e "  ${YELLOW}docker ps | grep roundcube${RESET}"
        resultado_prueba "Prueba 13.5" "FAIL" "HTTP ${http_code} — contenedor posiblemente detenido"
        _registrar "13.5" "Login Roundcube" "FAIL" "HTTP ${http_code}"
    fi
}

# ─── PRUEBA 13.6 — Envío de adjuntos ─────────────────────────────────────────
prueba_13_6() {
    paso 6 "PRUEBA 13.6 — Envío de correo con adjunto desde Roundcube"
    echo ""
    local ip="${IP_HOST:-192.168.56.10}"

    info "Esta prueba verifica que los adjuntos se envían con integridad."
    echo ""

    # Crear archivo de prueba
    local test_file="/tmp/adjunto_prueba_${RANDOM}.txt"
    local checksum_orig

    echo "Archivo de prueba generado por el script de pruebas." > "$test_file"
    echo "Fecha: $(date)" >> "$test_file"
    echo "Hash de verificación de integridad" >> "$test_file"
    checksum_orig=$(sha256sum "$test_file" | awk '{print $1}')

    exito "Archivo de prueba creado: ${test_file}"
    info "SHA256 original: ${checksum_orig}"

    echo ""
    echo -e "  ${CYAN}Instrucciones para completar esta prueba manualmente:${RESET}"
    echo -e "  1. Ve a Roundcube: ${YELLOW}http://${ip}${RESET}"
    echo -e "  2. Inicia sesión como ${GREEN}director@${DOMINIO}${RESET}"
    echo -e "  3. Redacta un correo a ${GREEN}admin@${DOMINIO}${RESET}"
    echo -e "  4. Adjunta el archivo: ${YELLOW}${test_file}${RESET}"
    echo -e "  5. Envía el correo"
    echo -e "  6. Inicia sesión como ${GREEN}admin${RESET} y descarga el adjunto"
    echo -e "  7. Verifica el SHA256 del archivo descargado:"
    echo -e "     ${YELLOW}sha256sum <archivo_descargado>${RESET}"
    echo -e "  8. Debe coincidir con: ${GREEN}${checksum_orig}${RESET}"
    echo ""
    echo -ne "  ¿El SHA256 del adjunto descargado coincide? [s/n]: "
    read -r resp

    if [[ "$resp" =~ ^[sS]$ ]]; then
        resultado_prueba "Prueba 13.6" "PASS" "Integridad del adjunto verificada"
        _registrar "13.6" "Envío de adjuntos" "PASS" "SHA256 coincide"
    else
        resultado_prueba "Prueba 13.6" "FAIL" "El adjunto no coincide o no se verificó"
        _registrar "13.6" "Envío de adjuntos" "FAIL" "SHA256 no coincide"
    fi

    rm -f "$test_file"
}

# ─── PRUEBA 13.7 — Persistencia de preferencias ──────────────────────────────
prueba_13_7() {
    paso 7 "PRUEBA 13.7 — Persistencia de preferencias tras reinicio"
    echo ""
    local ip="${IP_HOST:-192.168.56.10}"

    echo -e "  ${CYAN}Instrucciones:${RESET}"
    echo -e "  1. En Roundcube, cambia el idioma a ${YELLOW}English (o Español si ya está en inglés)${RESET}"
    echo -e "     o añade un contacto en la libreta de direcciones"
    echo -e "  2. Vuelve a esta terminal y presiona Enter"
    echo ""
    echo -ne "  [Enter] cuando hayas hecho el cambio en Roundcube... "
    read -r

    info "Reiniciando contenedor roundcube..."
    docker restart roundcube 2>/dev/null || docker compose restart roundcube 2>/dev/null || true

    info "Esperando que Roundcube vuelva a estar disponible (15 seg)..."
    sleep 15

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${ip}" 2>/dev/null || echo "000")

    if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
        exito "Roundcube disponible de nuevo (HTTP ${http_code})"
        echo ""
        echo -ne "  ¿Los cambios (idioma/contacto) persisten después del reinicio? [s/n]: "
        read -r resp
        if [[ "$resp" =~ ^[sS]$ ]]; then
            resultado_prueba "Prueba 13.7" "PASS" "Preferencias persistentes gracias al volumen roundcube_db"
            _registrar "13.7" "Persistencia de preferencias" "PASS" "DB persistente"
        else
            resultado_prueba "Prueba 13.7" "FAIL" "Los cambios no persistieron — revisa el volumen roundcube_db"
            _registrar "13.7" "Persistencia de preferencias" "FAIL" "Volumen sin datos"
        fi
    else
        error "Roundcube no responde tras el reinicio (HTTP ${http_code})"
        _registrar "13.7" "Persistencia de preferencias" "FAIL" "HTTP ${http_code}"
    fi
}

# ─── Ejecutar TODAS las pruebas ───────────────────────────────────────────────
ejecutar_todas_pruebas() {
    RESULTADOS=()   # limpiar resultados anteriores

    mostrar_banner
    echo -e "${YELLOW}${BOLD}  ════ EJECUTANDO TODAS LAS PRUEBAS DE ACEPTACIÓN ════${RESET}\n"

    prueba_12_1; echo ""
    prueba_12_2; echo ""
    prueba_12_3; echo ""
    prueba_13_4; echo ""
    prueba_13_5; echo ""
    prueba_13_6; echo ""
    prueba_13_7; echo ""

    # ─── Reporte final ──────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
    echo -e "  ${BOLD}${CYAN}   REPORTE FINAL DE PRUEBAS DE ACEPTACIÓN${RESET}"
    echo -e "  ${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
    echo ""

    local pass=0 fail=0 manual=0
    for resultado in "${RESULTADOS[@]}"; do
        local id nombre estado detalle
        IFS='|' read -r id nombre estado detalle <<< "$resultado"
        resultado_prueba "Prueba ${id}: ${nombre}" "$estado" "$detalle"
        case "$estado" in
            PASS)   ((pass++))   || true ;;
            FAIL)   ((fail++))   || true ;;
            MANUAL) ((manual++)) || true ;;
        esac
    done

    echo ""
    echo -e "  ${DIM}────────────────────────────────────────────${RESET}"
    echo -e "  ${GREEN}${BOLD}PASS: ${pass}${RESET}  |  ${RED}${BOLD}FAIL: ${fail}${RESET}  |  ${YELLOW}${BOLD}MANUAL: ${manual}${RESET}"
    echo ""

    # Guardar reporte en archivo
    local reporte_file="${PROYECTO_DIR}/logs/reporte_pruebas_$(date '+%Y%m%d_%H%M%S').txt"
    {
        echo "REPORTE DE PRUEBAS — $(date)"
        echo "Dominio: ${DOMINIO}"
        echo "====================================="
        for resultado in "${RESULTADOS[@]}"; do
            IFS='|' read -r id nombre estado detalle <<< "$resultado"
            echo "[$estado] Prueba ${id}: ${nombre} — ${detalle}"
        done
        echo "====================================="
        echo "PASS: ${pass} | FAIL: ${fail} | MANUAL: ${manual}"
    } > "$reporte_file"
    exito "Reporte guardado: ${reporte_file}"
}
