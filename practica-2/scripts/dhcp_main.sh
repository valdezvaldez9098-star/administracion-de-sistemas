#!/bin/bash

# SCRIPT PRINCIPAL DE CONFIGURACION DE SERVIDOR DHCP
# CONTROLA EL MENU Y LLAMA A LAS FUNCIONES
# REQUIERE EL ARCHIVO dhcp_funciones.sh EN LA MISMA RUTA

# CONFIGURACION INICIAL

# VERIFICAR SI SE EJECUTA COMO ROOT
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Debes ejecutar como root (sudo $0)"
    exit 1
fi

# CARGAR ARCHIVO DE FUNCIONES
if [ -f "dhcp-funciones.sh" ]; then
    source "dhcp-funciones.sh"
    echo "OK Archivo de funciones cargado correctamente"
else
    echo "ERROR: No se encontro el archivo dhcp_funciones.sh"
    echo "Asegurese de que este en la misma ruta que este script"
    exit 1
fi

# FUNCION: MOSTRAR MENU PRINCIPAL
mostrar_menu_principal() {
    clear
    echo "   CONFIGURACION DE SERVIDOR DHCP"
    echo ""
    echo "1. Verificar instalacion del servidor DHCP"
    echo "2. Instalar servidor DHCP (isc-dhcp-server)"
    echo "3. Configurar servidor DHCP"
    echo "4. Monitorear estado del servicio"
    echo "5. Mostrar configuracion actual"
    echo "6. Reinstalar servidor DHCP"
    echo "7. Salir"
    echo ""
}

# FUNCION: PROCESAR OPCION DEL MENU
procesar_opcion() {
    local opcion=$1
    
    case $opcion in
        1)
            echo ""
            verificar_instalacion
            echo ""
            read -p "Presione Enter para continuar..." -n 1
            ;;
        2)
            instalar_dhcp
            echo ""
            read -p "Presione Enter para continuar..." -n 1
            ;;
        3)
            if verificar_instalacion; then
                configurar_dhcp
            else
                echo ""
                echo "ERROR: El servidor DHCP no esta instalado."
                echo "Por favor, instaleo primero (opcion 2)."
            fi
            echo ""
            read -p "Presione Enter para continuar..." -n 1
            ;;
        4)
            monitorear_estado
            ;;
        5)
            mostrar_configuracion
            ;;
        6)
            reinstalar_dhcp
            echo ""
            read -p "Presione Enter para continuar..." -n 1
            ;;
        7)
            echo ""
            echo "Saliendo del script..."
            echo ""
            exit 0
            ;;
        *)
            echo ""
            echo "Opcion invalida. Por favor, seleccione 1-7."
            sleep 2
            ;;
    esac
}

# FUNCION PRINCIPAL
main() {
    # MOSTRAR INFORMACION DEL SISTEMA
    echo "Script de configuracion de servidor DHCP"
    echo "Sistema detectado: $(lsb_release -d 2>/dev/null | cut -f2 || uname -a)"
    echo ""
    read -p "Presione Enter para continuar..." -n 1
    
    # BUCLE PRINCIPAL DEL MENU
    while true; do
        mostrar_menu_principal
        read -p "Seleccione una opcion [1-7]: " opcion
        
        procesar_opcion "$opcion"
    done
}

# EJECUTAR PROGRAMA PRINCIPAL
main