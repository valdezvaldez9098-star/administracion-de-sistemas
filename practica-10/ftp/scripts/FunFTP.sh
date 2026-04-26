#!/bin/bash
# FunFTP.sh — Adaptado para Devuan Daedalus 5.0.1 (SysVinit, sin systemd)

source ./FunGENERALES.sh

# ─── Variables globales ───────────────────────────────────────────────────────
_raiz="/home"
_dirFtp="$_raiz/ftp"
_dirLocal="$_dirFtp/LocalUser"
opcion=0

# ─── Funciones ────────────────────────────────────────────────────────────────

registrarGrupo() {
    local _nombreBase="$1"
    CampoRequerido "$_nombreBase" "Nombre del grupo"

    local _etiqueta="${_nombreBase}Alumno"
    local _carpeta="/home/ftp/$_etiqueta"

    if ! getent group "$_etiqueta" >/dev/null 2>&1; then
        groupadd "$_etiqueta"
        echo "Grupo '$_etiqueta' registrado correctamente."
    else
        echo "Aviso: el grupo '$_etiqueta' ya se encuentra registrado."
    fi

    mkdir -p "$_carpeta"
    chown root:"$_etiqueta" "$_carpeta"
    chmod 2775 "$_carpeta"
}

eliminarGrupo() {
    local _nombreBase="$1"
    local _sufijo="Alumno"
    local _etiqueta="${_nombreBase}${_sufijo}"
    local _carpeta="/home/ftp/$_etiqueta"

    echo "Procesando eliminación del grupo: $_etiqueta"

    if [[ ! "$_etiqueta" == *"$_sufijo" ]]; then
        echo -e "\e[31mError: únicamente se permite eliminar grupos con sufijo '$_sufijo'.\e[0m"
        return 1
    fi

    if ! getent group "$_etiqueta" >/dev/null 2>&1; then
        echo -e "\e[33mEl grupo '$_etiqueta' no fue encontrado en el sistema.\e[0m"
        return 1
    fi

    echo "Liberando puntos de montaje asociados..."
    for _jaula in /home/ftp/LocalUser/*/; do
        local _punto="$_jaula/${_etiqueta%$_sufijo}"
        if mountpoint -q "$_punto" 2>/dev/null; then
            umount -f "$_punto" 2>/dev/null
            echo " -> Desmontado: $(basename "$_jaula")"
        fi
        [ -d "$_punto" ] && rmdir "$_punto" 2>/dev/null
    done

    [ -d "$_carpeta" ] && rm -rf "$_carpeta"

    groupdel "$_etiqueta"
    if [ $? -eq 0 ]; then
        echo -e "\e[32mGrupo '$_etiqueta' eliminado sin problemas.\e[0m"
    else
        echo -e "\e[31mOcurrió un error al intentar eliminar el grupo.\e[0m"
    fi
}

consultarGrupos() {
    local _sufijo="Alumno"
    echo -e "\e[34m--------------------------------------------------------\e[0m"
    echo -e "\e[1mGRUPOS ACADÉMICOS ACTIVOS (Sufijo: $_sufijo)\e[0m"
    echo -e "\e[34m--------------------------------------------------------\e[0m"
    printf "%-20s %-8s %s\n" "GRUPO" "GID" "MIEMBROS"
    echo -e "\e[34m--------------------------------------------------------\e[0m"
    getent group | grep "$_sufijo" | awk -F: '{ printf "%-20s %-8s %s\n", $1, $3, $4 }'
    echo -e "\e[34m--------------------------------------------------------\e[0m"
}

registrarUsuarios() {
    local _idx=0
    local _dirLocal="/home/ftp/LocalUser"
    local _dirPublico="/home/ftp/public"

    IFS=',' read -ra _names    <<< "$names"
    IFS=',' read -ra _passwords <<< "$passwords"

    ValidarArregloLleno "${_names[@]}"
    ValidarArregloLleno "${_passwords[@]}"
    ValidarUsuarioNuevo  "${_names[@]}"

    if [ ! -d "$_dirPublico" ]; then
        mkdir -p "$_dirPublico"
        chown root:users "$_dirPublico"
        chmod 2775 "$_dirPublico"
    fi

    while [ $_idx -lt "$no_users" ]; do
        local _nombre="${_names[$_idx]}"
        local _clave="${_passwords[$_idx]}"

        local _jaula="$_dirLocal/$_nombre"
        local _personal="$_jaula/$_nombre"
        local _publico="$_jaula/public"

        echo "Preparando entorno para: $_nombre..."

        useradd "$_nombre" -m -d "$_jaula" -G "users" -c "Alumno" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "Error: no fue posible crear al usuario '$_nombre'."
            exit 1
        fi

        echo "$_nombre:$_clave" | chpasswd

        mkdir -p "$_personal" "$_publico"

        chown root:root "$_jaula"
        chmod 755 "$_jaula"

        chown "$_nombre:$_nombre" "$_personal"
        chmod 700 "$_personal"

        if mountpoint -q "$_publico" 2>/dev/null; then
            echo " -> Aviso: $_publico ya estaba montado, se omite."
        else
            mount --bind "$_dirPublico" "$_publico"
        fi

        chown root:users "$_publico"
        chmod 2775 "$_publico"

        echo " -> Listo: '$_nombre' configurado (jaula y público montados)."
        ((_idx++))
    done

    echo "------------------------------------------"
    echo "Proceso completado: $no_users usuario(s) configurado(s)."
}

eliminarUsuario() {
    local _nombre="$1"
    local _etiqueta="$2"

    CampoRequerido "$_nombre"   "Nombre de usuario"
    CampoRequerido "$_etiqueta" "Etiqueta"

    local _registro
    _registro=$(getent passwd | grep "^$_nombre:" | grep ":$_etiqueta:")

    if [ -z "$_registro" ]; then
        echo -e "\e[33mNo se halló al usuario '$_nombre' con la etiqueta '$_etiqueta'.\e[0m"
        return 1
    fi

    echo "Confirmado: se procederá a eliminar a $_nombre (Etiqueta: $_etiqueta)"

    local _ruta="$_dirLocal/$_nombre"

    # Desmontar todos los bind mounts del usuario
    while IFS= read -r _punto; do
        echo " -> Desmontando: $_punto"
        umount -l "$_punto" 2>/dev/null
    done < <(mount | grep "/home/ftp/LocalUser/$_nombre/" | awk '{print $3}')

    [ -d "$_ruta" ] && rm -rf "$_ruta"

    userdel -f "$_nombre" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "\e[32mUsuario '$_nombre' dado de baja exitosamente.\e[0m"
    else
        echo -e "\e[31mFallo al intentar eliminar al usuario del sistema.\e[0m"
    fi
}

consultarAlumnos() {
    local _desc="$1"
    echo -e "\e[34m--------------------------------------------------------\e[0m"
    echo -e "\e[1mUsuarios registrados con descripción: $_desc\e[0m"
    echo -e "\e[34m--------------------------------------------------------\e[0m"
    getent passwd | awk -F: -v d="$_desc" '$5==d { printf "%-15s %-8s %-15s %s\n", $1, $3, $5, $6 }'
    echo -e "\e[34m--------------------------------------------------------\e[0m"
}

moverGrupoUsuario() {
    CampoRequerido "$names"  "Nombre de usuario"
    CampoRequerido "$groups" "Nombre de grupo"

    local _sufijo="$1"
    local _etiquetaDestino="${groups}Alumno"

    if ! getent group "$_etiquetaDestino" >/dev/null 2>&1; then
        echo "Error: el grupo '$_etiquetaDestino' no se encuentra registrado."
        exit 1
    fi

    if groups "$names" 2>/dev/null | grep -qw "$_etiquetaDestino"; then
        echo "El usuario $names ya pertenece al grupo $_etiquetaDestino."
        exit 1
    fi

    echo "Reasignando a $names hacia el grupo $_etiquetaDestino..."

    local _gruposAnteriores
    _gruposAnteriores=$(getent group | grep "$_sufijo" | grep "\b$names\b" | cut -d: -f1)

    for _ga in $_gruposAnteriores; do
        echo "Quitando del grupo anterior: $_ga"
        gpasswd -d "$names" "$_ga" 2>/dev/null

        local _puntoAnterior="$_dirLocal/$names/${_ga%$_sufijo}"
        if mountpoint -q "$_puntoAnterior" 2>/dev/null; then
            umount -lf "$_puntoAnterior" 2>/dev/null
        fi
        [ -d "$_puntoAnterior" ] && rmdir "$_puntoAnterior" 2>/dev/null
    done

    usermod -aG "$_etiquetaDestino" "$names"

    local _nuevoPunto="$_dirLocal/$names/$groups"
    local _carpetaGrupo="/home/ftp/${groups}Alumno"

    mkdir -p "$_nuevoPunto"
    mount --bind "$_carpetaGrupo" "$_nuevoPunto"
    chown root:"$_etiquetaDestino" "$_nuevoPunto"
    chmod 2775 "$_nuevoPunto"

    echo -e "\e[32mReasignación completada: $names ahora pertenece a $_etiquetaDestino\e[0m"
}

aplicarConfiguracion() {
    if [ "$(dpkg -l "vsftpd" 2>&1 | grep 'ii')" = "" ]; then
        echo -e "\nEl servicio vsftpd no fue detectado en el sistema"
        exit 1
    fi

    if [ -f /etc/vsftpd.conf ]; then
        sed -i 's/^anonymous_enable=NO/anonymous_enable=YES/'         /etc/vsftpd.conf
        sed -i 's/^#chroot_local_user=YES/chroot_local_user=YES/'     /etc/vsftpd.conf
        sed -i 's/^#write_enable=YES/write_enable=YES/'               /etc/vsftpd.conf

        grep -q "user_sub_token=\$USER"       /etc/vsftpd.conf || echo 'user_sub_token=$USER'          >> /etc/vsftpd.conf
        grep -q "local_root=$_dirLocal"       /etc/vsftpd.conf || echo "local_root=$_dirLocal/\$USER"  >> /etc/vsftpd.conf
        grep -q "anon_root="                  /etc/vsftpd.conf || echo "anon_root=$_dirFtp/public"      >> /etc/vsftpd.conf
        grep -q "local_umask=002"             /etc/vsftpd.conf || echo "local_umask=002"                >> /etc/vsftpd.conf
        grep -q "anon_upload_enable=NO"       /etc/vsftpd.conf || echo "anon_upload_enable=NO"          >> /etc/vsftpd.conf
        grep -q "anon_mkdir_write_enable=NO"  /etc/vsftpd.conf || echo "anon_mkdir_write_enable=NO"     >> /etc/vsftpd.conf

        # Pasivo para Docker (Devuan host)
        grep -q "pasv_enable=YES"     /etc/vsftpd.conf || echo "pasv_enable=YES"      >> /etc/vsftpd.conf
        grep -q "pasv_min_port=21100" /etc/vsftpd.conf || echo "pasv_min_port=21100"  >> /etc/vsftpd.conf
        grep -q "pasv_max_port=21110" /etc/vsftpd.conf || echo "pasv_max_port=21110"  >> /etc/vsftpd.conf
    else
        echo "No se encontró /etc/vsftpd.conf, operación cancelada."
        exit 1
    fi

    # Estructura de directorios
    if [ -d "$_raiz" ]; then
        chmod 755 "$_raiz"; chown root:root "$_raiz"

        [ -d "$_dirFtp"   ] || mkdir "$_dirFtp"
        chmod 755 "$_dirFtp"; chown root:root "$_dirFtp"

        [ -d "$_dirLocal" ] || mkdir "$_dirLocal"
        chmod 755 "$_dirLocal"; chown root:root "$_dirLocal"

        if mountpoint -q "$_dirFtp/public" 2>/dev/null; then
            chown root:users "$_dirFtp/public"
            chmod 2775 "$_dirFtp/public"
            echo "Permisos aplicados en $_dirFtp/public (volumen Docker activo)."
        else
            echo "Aviso: $_dirFtp/public no está montado. Verifica el volumen Docker."
        fi
    else
        echo "El directorio base $_raiz no existe, operación cancelada."; exit 1
    fi

    ReiniciarPaquete "vsftpd"
    echo -e "\e[32mConfiguración aplicada. Anonymous: solo lectura. Usuarios: lectura/escritura en public.\e[0m"
}
