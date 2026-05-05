#!/usr/bin/env bash
# =============================================================================
# cuentas.sh — Gestión de cuentas de correo en docker-mailserver
# =============================================================================

# Helper: ejecutar comando dentro del contenedor mailserver
_dms() {
    docker exec mailserver "$@"
}

# Verificar que el contenedor está corriendo
_verificar_contenedor() {
    if ! docker ps --format '{{.Names}}' | grep -q '^mailserver$'; then
        error "El contenedor 'mailserver' no está corriendo."
        info "Inicia el stack primero (menú → Desplegar Stack → Iniciar)."
        return 1
    fi
    return 0
}

# ─── Crear cuenta ─────────────────────────────────────────────────────────────
crear_cuenta() {
    paso 1 "Crear cuenta de correo en ${DOMINIO}"
    _verificar_contenedor || return 1

    echo -ne "  Usuario (sin @${DOMINIO}): "
    read -r usuario
    usuario=$(echo "$usuario" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]._-')

    if [ -z "$usuario" ]; then
        error "Nombre de usuario vacío."
        return 1
    fi

    local email="${usuario}@${DOMINIO}"

    echo -ne "  Contraseña para ${email}: "
    read -rs password
    echo ""

    if [ ${#password} -lt 8 ]; then
        error "La contraseña debe tener al menos 8 caracteres."
        return 1
    fi

    info "Creando cuenta: ${email}..."
    if _dms setup email add "$email" "$password"; then
        exito "Cuenta creada: ${email}"
        info "Puedes iniciar sesión en Roundcube con usuario '${usuario}' o '${email}'"
    else
        error "No se pudo crear la cuenta. Revisa los logs del contenedor."
    fi
}

# ─── Listar cuentas ───────────────────────────────────────────────────────────
listar_cuentas() {
    paso 1 "Cuentas de correo registradas"
    _verificar_contenedor || return 1

    echo ""
    local cuentas
    cuentas=$(_dms setup email list 2>/dev/null || echo "(sin cuentas)")

    if [ -z "$cuentas" ]; then
        advertencia "No hay cuentas registradas todavía."
    else
        echo -e "  ${BOLD}Email registrado${RESET}"
        echo -e "  ${DIM}────────────────────────────────${RESET}"
        while IFS= read -r linea; do
            echo -e "  ${GREEN}▸${RESET} $linea"
        done <<< "$cuentas"
    fi
}

# ─── Cambiar contraseña ───────────────────────────────────────────────────────
cambiar_password() {
    paso 1 "Cambiar contraseña de cuenta"
    _verificar_contenedor || return 1

    listar_cuentas

    echo ""
    echo -ne "  Email completo (ej: usuario@${DOMINIO}): "
    read -r email

    echo -ne "  Nueva contraseña: "
    read -rs nueva_pass
    echo ""

    if [ ${#nueva_pass} -lt 8 ]; then
        error "La contraseña debe tener al menos 8 caracteres."
        return 1
    fi

    info "Actualizando contraseña para ${email}..."
    if _dms setup email update "$email" "$nueva_pass"; then
        exito "Contraseña actualizada para: ${email}"
    else
        error "No se pudo actualizar la contraseña."
    fi
}

# ─── Eliminar cuenta ──────────────────────────────────────────────────────────
eliminar_cuenta() {
    paso 1 "Eliminar cuenta de correo"
    _verificar_contenedor || return 1

    listar_cuentas
    echo ""
    echo -ne "  Email a eliminar: "
    read -r email

    echo -e "  ${RED}¿Seguro que deseas eliminar ${email}? Esto borrará todos sus correos.${RESET}"
    echo -ne "  Escribe 'ELIMINAR' para confirmar: "
    read -r confirmacion

    if [ "$confirmacion" = "ELIMINAR" ]; then
        if _dms setup email del "$email"; then
            exito "Cuenta ${email} eliminada"
        else
            error "No se pudo eliminar la cuenta."
        fi
    else
        info "Operación cancelada."
    fi
}

# ─── Crear cuentas de práctica ────────────────────────────────────────────────
crear_cuentas_practica() {
    paso 1 "Creando cuentas de práctica requeridas por la tarea"
    _verificar_contenedor || return 1

    local cuentas=(
        "director:Director2024!"
        "admin:Admin2024!"
    )

    echo ""
    for entrada in "${cuentas[@]}"; do
        local usuario="${entrada%%:*}"
        local password="${entrada##*:}"
        local email="${usuario}@${DOMINIO}"

        info "Creando: ${email}..."
        if _dms setup email add "$email" "$password" 2>/dev/null; then
            exito "Cuenta creada: ${email}  |  contraseña: ${password}"
        else
            advertencia "La cuenta ${email} puede ya existir o hubo un error."
        fi
    done

    echo ""
    echo -e "  ${CYAN}${BOLD}Resumen de cuentas de práctica:${RESET}"
    echo -e "  ┌────────────────────────────────────┬─────────────────┐"
    echo -e "  │ Email                              │ Contraseña      │"
    echo -e "  ├────────────────────────────────────┼─────────────────┤"
    echo -e "  │ director@${DOMINIO}           │ Director2024!   │"
    echo -e "  │ admin@${DOMINIO}              │ Admin2024!      │"
    echo -e "  └────────────────────────────────────┴─────────────────┘"
    echo ""
    advertencia "Cambia estas contraseñas en producción real."
}
