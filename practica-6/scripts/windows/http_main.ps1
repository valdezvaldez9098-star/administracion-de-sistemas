# ======================================================
# SCRIPT PRINCIPAL
# Aprovisionamiento Web Automatizado
# Windows Server 2022 | Chocolatey
# ======================================================

Import-Module ServerManager -ErrorAction SilentlyContinue
. "$PSScriptRoot\http_funciones.ps1"

Clear-Host
Verificar-Gestor

function Menu-Principal {
    Clear-Host

    Write-Host ""
    Write-Host "  ====================================================" -ForegroundColor Cyan
    Write-Host "   SISTEMA DE DESPLIEGUE - WINDOWS SERVER 2022        " -ForegroundColor White
    Write-Host "            HTTP MULTI-VERSION DEPLOY                  " -ForegroundColor DarkCyan
    Write-Host "  ====================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "   Servidores disponibles                              " -ForegroundColor Yellow
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "    [1]  Instalar IIS  (Nativo Windows)               " -ForegroundColor White
    Write-Host "    [2]  Instalar Apache  (Seleccionar Version)        " -ForegroundColor White
    Write-Host "    [3]  Instalar Nginx   (Seleccionar Version)        " -ForegroundColor White
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "    [9]  Limpiar servidores (Restaurar estado)         " -ForegroundColor DarkYellow
    Write-Host "    [0]  Salir                                         " -ForegroundColor DarkGray
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""

    $op = Read-Host "  Seleccione una opcion [0-3, 9]"

    switch ($op) {
        "1" {
            $p = Solicitar-Puerto
            Instalar-IIS $p
        }
        "2" {
            $v = Mostrar-Versiones "apache-httpd"
            $p = Solicitar-Puerto
            Instalar-Apache $v $p
        }
        "3" {
            $v = Mostrar-Versiones "nginx"
            $p = Solicitar-Puerto
            Instalar-Nginx $v $p
        }
        "9" { Limpiar-Servidores }
        "0" {
            Write-Host ""
            Write-Host "  Saliendo del sistema. Hasta luego." -ForegroundColor DarkGray
            Write-Host ""
            exit
        }
        default {
            Write-Host "  [ERROR] Opcion invalida. Elige 1, 2, 3, 9 o 0." -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  Proceso completado. Presione ENTER para volver al menu..." -ForegroundColor DarkGray
    Read-Host | Out-Null
    Menu-Principal
}

Menu-Principal