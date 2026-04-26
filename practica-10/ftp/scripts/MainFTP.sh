#!/bin/bash
# MainFTP.sh — Adaptado para Devuan Daedalus 5.0.1

source ./FunFTP.sh
source ./FunGENERALES.sh

VerificarRoot

# =====================================
# MENU PRINCIPAL
# =====================================
menu_principal(){
while true; do
    clear
    echo "==========================================="
    echo "         ADMINISTRADOR SERVIDOR FTP"
    echo "      (Devuan Daedalus 5.0.1 / SysVinit)"
    echo "==========================================="
    echo ""
    echo "1) Verificar servicio vsftpd"
    echo "2) Instalar servicio"
    echo "3) Configurar / Crear estructura"
    echo "4) Desinstalar servicio"
    echo "5) Estado del servicio"
    echo ""
    echo "6) Cambiar usuario de grupo"
    echo ""
    echo "7) Administrar usuarios"
    echo "8) Administrar grupos"
    echo ""
    echo "0) Salir"
    echo ""
    read -p "Seleccione una opcion: " opcion

    case $opcion in
    1) VerificarPaquete "vsftpd"; pause ;;
    2) InstalarPaquete "vsftpd"; aplicarConfiguracion; pause ;;
    3) aplicarConfiguracion; pause ;;
    4) DesinstalarPaquete "vsftpd"; pause ;;
    5) EstadoPaquete "vsftpd"; pause ;;
    6)
        read -p "Usuario: " names
        read -p "Grupo (sin sufijo Alumno): " groups
        moverGrupoUsuario "Alumno"
        pause
        ;;
    7) menu_usuarios ;;
    8) menu_grupos ;;
    0) echo "Saliendo..."; exit 0 ;;
    *) echo "Opción inválida"; pause ;;
    esac
done
}

# =====================================
# MENU USUARIOS
# =====================================
menu_usuarios(){
while true; do
    clear
    echo "=================================="
    echo "          ABC USUARIOS FTP"
    echo "=================================="
    echo ""
    echo "1) Alta usuario"
    echo "2) Baja usuario"
    echo "3) Consultar usuarios"
    echo ""
    echo "0) Volver"
    echo ""
    read -p "Seleccione una opcion: " opu

    case $opu in
    1)
        read -p "Numero de usuarios: " no_users
        read -p "Usuarios (separados por coma): " names
        read -p "Passwords (separados por coma): " passwords
        registrarUsuarios
        pause
        ;;
    2)
        read -p "Nombre del usuario: " names
        eliminarUsuario "$names" "Alumno"
        pause
        ;;
    3)
        consultarAlumnos "Alumno"
        pause
        ;;
    0) return ;;
    *) echo "Opción inválida"; pause ;;
    esac
done
}

# =====================================
# MENU GRUPOS
# =====================================
menu_grupos(){
while true; do
    clear
    echo "=================================="
    echo "          ABC GRUPOS FTP"
    echo "=================================="
    echo ""
    echo "1) Alta grupo"
    echo "2) Baja grupo"
    echo "3) Consultar grupos"
    echo ""
    echo "0) Volver"
    echo ""
    read -p "Seleccione una opcion: " opg

    case $opg in
    1)
        read -p "Nombre base del grupo: " groups
        registrarGrupo "$groups"
        pause
        ;;
    2)
        read -p "Nombre base del grupo: " groups
        eliminarGrupo "$groups"
        pause
        ;;
    3)
        consultarGrupos
        pause
        ;;
    0) return ;;
    *) echo "Opción inválida"; pause ;;
    esac
done
}

# =====================================
# EJECUCIÓN PRINCIPAL
# =====================================
menu_principal
