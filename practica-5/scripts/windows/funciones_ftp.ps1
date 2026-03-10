#Requires -RunAsAdministrator

$RutaFTP     = "C:\ServidorFTP"
$RutaGeneral = "$RutaFTP\general"
$SitioNombre = "ServidorFTP"
$SitioPuerto = 21

# Grupos fijos de arranque (siempre se crean con la Opcion A)
$GruposIniciales = @("reprobados", "recursadores")

# ----------------------------------------------------------
# Helpers de salida
# ----------------------------------------------------------
function Escribir-Titulo {
    param([string]$Texto)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Texto" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}
function Escribir-OK    { param([string]$m) Write-Host "  [OK] $m"    -ForegroundColor Green  }
function Escribir-Info  { param([string]$m) Write-Host "  [INFO] $m"  -ForegroundColor Yellow }
function Escribir-Error { param([string]$m) Write-Host "  [ERROR] $m" -ForegroundColor Red    }

# ----------------------------------------------------------
# Obtener lista dinamica de grupos FTP registrados
# (todos los grupos locales cuya carpeta existe en ServidorFTP)
# ----------------------------------------------------------
function Obtener-GruposFTP {
    $grupos = @()
    if (Test-Path $RutaFTP) {
        $carpetas = Get-ChildItem -Path $RutaFTP -Directory |
                    Where-Object { $_.Name -ne "LocalUser" -and $_.Name -ne "general" }
        foreach ($c in $carpetas) {
            if (Get-LocalGroup -Name $c.Name -ErrorAction SilentlyContinue) {
                $grupos += $c.Name
            }
        }
    }
    return $grupos
}

# ----------------------------------------------------------
# Instalar IIS y FTP
# ----------------------------------------------------------
function Instalar-IIS-FTP {
    Escribir-Titulo "INSTALANDO IIS Y SERVICIO FTP"
    $caracteristicas = @(
        "Web-Server",
        "Web-Ftp-Server",
        "Web-Ftp-Service",
        "Web-Mgmt-Console"
    )
    foreach ($f in $caracteristicas) {
        $estado = Get-WindowsFeature -Name $f
        if ($estado.Installed) {
            Escribir-Info "Ya instalada: $f"
        } else {
            Escribir-Info "Instalando: $f ..."
            Install-WindowsFeature -Name $f -IncludeManagementTools | Out-Null
            Escribir-OK "Instalado: $f"
        }
    }
    if (-not (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue)) {
        Import-Module WebAdministration -ErrorAction Stop
    }
    Escribir-OK "Modulo WebAdministration cargado."
}

# ----------------------------------------------------------
# Crear carpeta de grupo y aplicar permisos NTFS
# ----------------------------------------------------------
function Crear-CarpetaGrupo {
    param([string]$NombreGrupo)

    $ruta = "$RutaFTP\$NombreGrupo"
    if (-not (Test-Path $ruta)) {
        New-Item -ItemType Directory -Path $ruta -Force | Out-Null
        Escribir-OK "Carpeta creada: $ruta"
    } else {
        Escribir-Info "Carpeta ya existe: $ruta"
    }

    # Permisos NTFS: el grupo puede modificar su propia carpeta
    $acl = Get-Acl $ruta
    $regla = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $NombreGrupo,"Modify","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($regla)
    Set-Acl -Path $ruta -AclObject $acl
    Escribir-OK "Permisos del grupo $NombreGrupo aplicados en: $ruta"
}

# ----------------------------------------------------------
# Crear estructura base de carpetas
# ----------------------------------------------------------
function Crear-EstructuraCarpetas {
    Escribir-Titulo "CREANDO ESTRUCTURA DE CARPETAS FTP"

    foreach ($c in @($RutaFTP, $RutaGeneral)) {
        if (-not (Test-Path $c)) {
            New-Item -ItemType Directory -Path $c -Force | Out-Null
            Escribir-OK "Carpeta creada: $c"
        } else {
            Escribir-Info "Ya existe: $c"
        }
    }

    # Carpetas de grupos iniciales
    foreach ($g in $GruposIniciales) {
        if (-not (Test-Path "$RutaFTP\$g")) {
            New-Item -ItemType Directory -Path "$RutaFTP\$g" -Force | Out-Null
            Escribir-OK "Carpeta creada: $RutaFTP\$g"
        } else {
            Escribir-Info "Ya existe: $RutaFTP\$g"
        }
    }
}

# ----------------------------------------------------------
# Crear grupos locales
# ----------------------------------------------------------
function Crear-Grupos {
    Escribir-Titulo "CREANDO GRUPOS LOCALES"
    foreach ($grupo in $GruposIniciales) {
        if (-not (Get-LocalGroup -Name $grupo -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $grupo -Description "Grupo FTP $grupo" | Out-Null
            Escribir-OK "Grupo creado: $grupo"
        } else {
            Escribir-Info "Grupo ya existe: $grupo"
        }
    }
}

# ----------------------------------------------------------
# Permisos NTFS carpeta general
# ----------------------------------------------------------
function Configurar-PermisosBase {
    Escribir-Titulo "CONFIGURANDO PERMISOS NTFS BASE"

    $acl = Get-Acl $RutaGeneral
    $sidAuth = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
    $reglaAuth = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidAuth,"Modify","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($reglaAuth)
    $sidIUSR = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-17")
    $reglaAnon = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidIUSR,"ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($reglaAnon)
    Set-Acl -Path $RutaGeneral -AclObject $acl
    Escribir-OK "Permisos aplicados en: $RutaGeneral"

    # Permisos de grupos iniciales
    foreach ($g in $GruposIniciales) {
        $ruta = "$RutaFTP\$g"
        if (Test-Path $ruta) {
            $acl2 = Get-Acl $ruta
            $reglaGrupo = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $g,"Modify","ContainerInherit,ObjectInherit","None","Allow")
            $acl2.AddAccessRule($reglaGrupo)
            Set-Acl -Path $ruta -AclObject $acl2
            Escribir-OK "Permisos del grupo $g en: $ruta"
        }
    }
}

# ----------------------------------------------------------
# Crear sitio FTP en IIS
# ----------------------------------------------------------
function Crear-SitioFTP {
    Escribir-Titulo "CONFIGURANDO SITIO FTP EN IIS"
    Import-Module WebAdministration -ErrorAction Stop

    if (Get-WebSite -Name $SitioNombre -ErrorAction SilentlyContinue) {
        Remove-WebSite -Name $SitioNombre
        Escribir-Info "Sitio FTP anterior eliminado."
    }

    New-WebFtpSite -Name $SitioNombre -Port $SitioPuerto -PhysicalPath $RutaFTP -Force | Out-Null
    Escribir-OK "Sitio FTP $SitioNombre creado en puerto $SitioPuerto."

    Set-ItemProperty "IIS:\Sites\$SitioNombre" `
        -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
    Set-ItemProperty "IIS:\Sites\$SitioNombre" `
        -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    Escribir-OK "Autenticacion anonima y basica habilitadas."

    Set-ItemProperty "IIS:\Sites\$SitioNombre" `
        -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
    Set-ItemProperty "IIS:\Sites\$SitioNombre" `
        -Name ftpServer.security.ssl.dataChannelPolicy -Value 0

    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -PSPath "IIS:\" -Location $SitioNombre `
        -Value @{ accessType = "Allow"; users = "?"; permissions = "Read" } `
        -ErrorAction SilentlyContinue
    Escribir-OK "Regla FTP: anonimo = solo lectura."

    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -PSPath "IIS:\" -Location $SitioNombre `
        -Value @{ accessType = "Allow"; users = "*"; permissions = "Read,Write" } `
        -ErrorAction SilentlyContinue
    Escribir-OK "Regla FTP: autenticados = lectura + escritura."

    Set-ItemProperty "IIS:\Sites\$SitioNombre" `
        -Name ftpServer.userIsolation.mode -Value 3
    Escribir-OK "Aislamiento de usuarios configurado."

    $svc = Get-Service -Name "ftpsvc" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Running") {
        Start-Service -Name "ftpsvc" | Out-Null
        Start-Sleep -Seconds 2
        Escribir-OK "Servicio ftpsvc iniciado."
    }

    Start-WebSite -Name $SitioNombre -ErrorAction SilentlyContinue
    Escribir-OK "Sitio FTP iniciado."

    if (-not (Get-NetFirewallRule -DisplayName "FTP Puerto 21" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "FTP Puerto 21" -Direction Inbound `
            -Protocol TCP -LocalPort 21 -Action Allow | Out-Null
        Escribir-OK "Regla de firewall creada para puerto 21."
    } else {
        Escribir-Info "Regla de firewall ya existente."
    }
}

# ----------------------------------------------------------
# Carpetas y permisos por usuario (junctions a carpetas compartidas)
# ----------------------------------------------------------
function Configurar-CarpetasUsuario {
    param(
        [string]$NombreUsuario,
        [string]$Grupo
    )
    $raizUsuario = "$RutaFTP\LocalUser\$NombreUsuario"

    if (-not (Test-Path $raizUsuario)) {
        New-Item -ItemType Directory -Path $raizUsuario -Force | Out-Null
    }

    # Carpeta personal exclusiva del usuario
    if (-not (Test-Path "$raizUsuario\$NombreUsuario")) {
        New-Item -ItemType Directory -Path "$raizUsuario\$NombreUsuario" -Force | Out-Null
    }

    # Junction: general compartida
    $junctionGeneral = "$raizUsuario\general"
    if (-not (Test-Path $junctionGeneral)) {
        cmd /c "mklink /J `"$junctionGeneral`" `"$RutaGeneral`"" | Out-Null
        Escribir-Info "Junction general creado para: $NombreUsuario"
    }

    # Junction: carpeta de grupo compartida
    $RutaGrupoCompartido = "$RutaFTP\$Grupo"
    $junctionGrupo = "$raizUsuario\$Grupo"
    if (-not (Test-Path $junctionGrupo)) {
        cmd /c "mklink /J `"$junctionGrupo`" `"$RutaGrupoCompartido`"" | Out-Null
        Escribir-Info "Junction de grupo $Grupo creado para: $NombreUsuario"
    }

    # Permisos: control total del usuario sobre su raiz
    $acl = Get-Acl $raizUsuario
    $regla = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $NombreUsuario,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($regla)
    Set-Acl -Path $raizUsuario -AclObject $acl

    # Permisos: el grupo puede modificar su carpeta compartida via junction
    $aclGrupo = Get-Acl "$raizUsuario\$Grupo"
    $reglaGrupo = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Grupo,"Modify","ContainerInherit,ObjectInherit","None","Allow")
    $aclGrupo.AddAccessRule($reglaGrupo)
    Set-Acl -Path "$raizUsuario\$Grupo" -AclObject $aclGrupo

    Escribir-OK "Carpetas configuradas para: $NombreUsuario (grupo: $Grupo)"
}

# ----------------------------------------------------------
# Seleccionar grupo de una lista dinamica
# ----------------------------------------------------------
function Seleccionar-Grupo {
    param([string]$Prompt)

    $grupos = Obtener-GruposFTP
    if ($grupos.Count -eq 0) {
        Escribir-Error "No hay grupos FTP registrados. Usa la Opcion A o la Opcion D."
        return $null
    }

    Write-Host ""
    Write-Host "  Grupos disponibles:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $grupos.Count; $i++) {
        Write-Host "    $($i + 1)) $($grupos[$i])" -ForegroundColor White
    }
    Write-Host ""

    do {
        $selStr = Read-Host "  $Prompt (numero)"
        $valido = $selStr -match '^\d+$' -and [int]$selStr -ge 1 -and [int]$selStr -le $grupos.Count
        if (-not $valido) {
            Escribir-Error "Seleccion invalida. Elige un numero entre 1 y $($grupos.Count)."
        }
    } while (-not $valido)

    return $grupos[[int]$selStr - 1]
}

# ==========================================================
# OPCION A - Instalar y configurar servidor FTP
# ==========================================================
function Opcion-Instalar {
    Instalar-IIS-FTP
    Crear-EstructuraCarpetas
    Crear-Grupos
    Configurar-PermisosBase
    Crear-SitioFTP

    $localUser = "$RutaFTP\LocalUser"
    if (-not (Test-Path $localUser)) {
        New-Item -ItemType Directory -Path $localUser -Force | Out-Null
    }

    $anonimo = "$RutaFTP\LocalUser\Public"
    if (-not (Test-Path $anonimo)) {
        New-Item -ItemType Directory -Path $anonimo -Force | Out-Null
    }

    $junctionGeneral = "$anonimo\general"
    if (-not (Test-Path $junctionGeneral)) {
        cmd /c "mklink /J `"$junctionGeneral`" `"$RutaGeneral`"" | Out-Null
        Escribir-OK "Enlace de directorio general creado para acceso anonimo."
    }

    Write-Host ""
    Escribir-OK "Servidor FTP instalado y configurado exitosamente!"
}

# ==========================================================
# OPCION B - Creacion masiva de usuarios
# ==========================================================
function Opcion-CrearUsuarios {
    Escribir-Titulo "CREACION MASIVA DE USUARIOS FTP"

    $grupos = Obtener-GruposFTP
    if ($grupos.Count -eq 0) {
        Escribir-Error "No hay grupos FTP. Ejecuta primero la Opcion A o crea grupos con la Opcion D."
        return
    }

    $contrasenaComun = Read-Host "  Contrasena comun para todos los usuarios"
    if ([string]::IsNullOrWhiteSpace($contrasenaComun)) {
        Escribir-Error "La contrasena no puede estar vacia."
        return
    }
    $password = ConvertTo-SecureString $contrasenaComun -AsPlainText -Force

    $nStr = Read-Host "  Cuantos usuarios deseas crear"
    if (-not ($nStr -match '^\d+$') -or [int]$nStr -lt 1) {
        Escribir-Error "Numero invalido."
        return
    }
    $n = [int]$nStr

    Write-Host ""
    for ($i = 1; $i -le $n; $i++) {
        Write-Host "  --- Usuario $i de $n ---" -ForegroundColor Magenta

        do {
            $nombre = Read-Host "    Nombre de usuario"
        } while ([string]::IsNullOrWhiteSpace($nombre))

        $grupo = Seleccionar-Grupo -Prompt "Grupo para el usuario $nombre"
        if (-not $grupo) { return }

        if (Get-LocalUser -Name $nombre -ErrorAction SilentlyContinue) {
            Escribir-Info "Usuario $nombre ya existe. Se actualizara su grupo y carpetas."
            foreach ($g in $grupos) {
                try {
                    Remove-LocalGroupMember -Group $g -Member $nombre -ErrorAction SilentlyContinue
                } catch {}
            }
        } else {
            New-LocalUser -Name $nombre -Password $password `
                -FullName $nombre -Description "Usuario FTP" `
                -PasswordNeverExpires | Out-Null
            Escribir-OK "Usuario creado: $nombre"
        }

        Add-LocalGroupMember -Group $grupo -Member $nombre -ErrorAction SilentlyContinue
        Escribir-OK "Usuario $nombre agregado al grupo $grupo."

        Configurar-CarpetasUsuario -NombreUsuario $nombre -Grupo $grupo

        Write-Host ""
    }

    Escribir-OK "Creacion masiva de usuarios completada."
}

# ==========================================================
# OPCION C - Cambiar grupo de usuario
# ==========================================================
function Opcion-CambiarGrupo {
    Escribir-Titulo "CAMBIAR GRUPO DE UN USUARIO"

    $nombre = Read-Host "  Nombre del usuario a modificar"
    if (-not (Get-LocalUser -Name $nombre -ErrorAction SilentlyContinue)) {
        Escribir-Error "El usuario $nombre no existe."
        return
    }

    $grupos = Obtener-GruposFTP
    $grupoActual = ""
    foreach ($g in $grupos) {
        $miembros = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name
        if ($miembros -contains "$env:COMPUTERNAME\$nombre") {
            $grupoActual = $g
            break
        }
    }

    if ($grupoActual -ne "") {
        Escribir-Info "Grupo actual de ${nombre}: $grupoActual"
    } else {
        Escribir-Info "El usuario $nombre no pertenece a ningun grupo FTP."
    }

    $nuevoGrupo = Seleccionar-Grupo -Prompt "Nuevo grupo para $nombre"
    if (-not $nuevoGrupo) { return }

    if ($nuevoGrupo -eq $grupoActual) {
        Escribir-Info "El usuario ya pertenece al grupo $nuevoGrupo. Sin cambios."
        return
    }

    if ($grupoActual -ne "") {
        Remove-LocalGroupMember -Group $grupoActual -Member $nombre -ErrorAction SilentlyContinue
        Escribir-OK "Eliminado del grupo $grupoActual."
    }

    Add-LocalGroupMember -Group $nuevoGrupo -Member $nombre -ErrorAction SilentlyContinue
    Escribir-OK "Agregado al grupo $nuevoGrupo."

    $raizUsuario = "$RutaFTP\LocalUser\$nombre"
    if ($grupoActual -ne "" -and (Test-Path "$raizUsuario\$grupoActual")) {
        cmd /c "rmdir `"$raizUsuario\$grupoActual`"" | Out-Null
        Escribir-Info "Junction de grupo anterior eliminado: $grupoActual"
    }

    Configurar-CarpetasUsuario -NombreUsuario $nombre -Grupo $nuevoGrupo
    Escribir-OK "Grupo del usuario $nombre cambiado a $nuevoGrupo exitosamente."
}

# ==========================================================
# OPCION D - Gestion de grupos (crear / eliminar)
# ==========================================================
function Opcion-GestionGrupos {
    Escribir-Titulo "GESTION DE GRUPOS FTP"

    Write-Host "  1) Agregar nuevo grupo" -ForegroundColor Green
    Write-Host "  2) Eliminar grupo existente" -ForegroundColor Yellow
    Write-Host "  3) Listar grupos actuales" -ForegroundColor Cyan
    Write-Host ""

    $sub = (Read-Host "  Selecciona una opcion").Trim()

    switch ($sub) {

        "1" {
            # ---- Agregar grupo ----
            $nuevoGrupo = (Read-Host "  Nombre del nuevo grupo").Trim()
            if ([string]::IsNullOrWhiteSpace($nuevoGrupo)) {
                Escribir-Error "El nombre no puede estar vacio."
                return
            }
            if ($nuevoGrupo -eq "general" -or $nuevoGrupo -eq "LocalUser") {
                Escribir-Error "Nombre reservado. Elige otro nombre."
                return
            }

            # Crear grupo local
            if (Get-LocalGroup -Name $nuevoGrupo -ErrorAction SilentlyContinue) {
                Escribir-Info "El grupo $nuevoGrupo ya existe."
            } else {
                New-LocalGroup -Name $nuevoGrupo -Description "Grupo FTP $nuevoGrupo" | Out-Null
                Escribir-OK "Grupo local creado: $nuevoGrupo"
            }

            # Crear carpeta compartida y permisos
            Crear-CarpetaGrupo -NombreGrupo $nuevoGrupo
            Escribir-OK "Grupo $nuevoGrupo listo para usarse."
        }

        "2" {
            # ---- Eliminar grupo ----
            $grupos = Obtener-GruposFTP
            if ($grupos.Count -eq 0) {
                Escribir-Error "No hay grupos FTP para eliminar."
                return
            }

            Write-Host ""
            Write-Host "  Grupos disponibles:" -ForegroundColor Yellow
            for ($i = 0; $i -lt $grupos.Count; $i++) {
                Write-Host "    $($i + 1)) $($grupos[$i])" -ForegroundColor White
            }
            Write-Host ""

            do {
                $selStr = Read-Host "  Grupo a eliminar (numero)"
                $valido = $selStr -match '^\d+$' -and [int]$selStr -ge 1 -and [int]$selStr -le $grupos.Count
            } while (-not $valido)

            $grupoEliminar = $grupos[[int]$selStr - 1]

            # Verificar si hay usuarios en ese grupo
            $miembros = Get-LocalGroupMember -Group $grupoEliminar -ErrorAction SilentlyContinue
            if ($miembros -and $miembros.Count -gt 0) {
                Write-Host "  ADVERTENCIA: El grupo $grupoEliminar tiene $($miembros.Count) usuario(s) asignado(s)." -ForegroundColor Red
                $confirm = Read-Host "  Continuar de todas formas? (s/n)"
                if ($confirm -ne "s") {
                    Escribir-Info "Operacion cancelada."
                    return
                }
            }

            # Quitar junctions de los usuarios que tenian ese grupo
            $localUserPath = "$RutaFTP\LocalUser"
            if (Test-Path $localUserPath) {
                Get-ChildItem -Path $localUserPath -Directory | ForEach-Object {
                    $junctionRuta = "$($_.FullName)\$grupoEliminar"
                    if (Test-Path $junctionRuta) {
                        cmd /c "rmdir `"$junctionRuta`"" | Out-Null
                        Escribir-Info "Junction eliminado en carpeta de usuario: $($_.Name)"
                    }
                }
            }

            # Eliminar carpeta compartida del grupo
            $rutaGrupo = "$RutaFTP\$grupoEliminar"
            if (Test-Path $rutaGrupo) {
                Remove-Item -Path $rutaGrupo -Recurse -Force
                Escribir-OK "Carpeta del grupo eliminada: $rutaGrupo"
            }

            # Eliminar grupo local
            if (Get-LocalGroup -Name $grupoEliminar -ErrorAction SilentlyContinue) {
                Remove-LocalGroup -Name $grupoEliminar
                Escribir-OK "Grupo local eliminado: $grupoEliminar"
            }
        }

        "3" {
            # ---- Listar grupos ----
            $grupos = Obtener-GruposFTP
            Write-Host ""
            if ($grupos.Count -eq 0) {
                Escribir-Info "No hay grupos FTP registrados."
            } else {
                Write-Host "  Grupos FTP activos:" -ForegroundColor Cyan
                foreach ($g in $grupos) {
                    $miembros = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
                    $total = if ($miembros) { $miembros.Count } else { 0 }
                    Write-Host "    - $g  ($total usuario(s))" -ForegroundColor White
                }
            }
        }

        default {
            Escribir-Error "Opcion no valida."
        }
    }
}

# ==========================================================
# OPCION R - Reset completo
# ==========================================================
function Opcion-Reset {
    Escribir-Titulo "RESET COMPLETO DEL SERVIDOR FTP"
    Write-Host "  ADVERTENCIA: Se eliminara el sitio FTP, usuarios, grupos y carpetas." -ForegroundColor Red
    Write-Host ""
    $confirmacion = Read-Host "  Escribe CONFIRMAR para continuar"

    if ($confirmacion -ne "CONFIRMAR") {
        Escribir-Info "Reset cancelado."
        return
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    if (Get-WebSite -Name $SitioNombre -ErrorAction SilentlyContinue) {
        Stop-WebSite -Name $SitioNombre -ErrorAction SilentlyContinue
        Remove-WebSite -Name $SitioNombre
        Escribir-OK "Sitio FTP $SitioNombre eliminado."
    } else {
        Escribir-Info "El sitio FTP no existia."
    }

    # Eliminar usuarios FTP
    $localUserPath = "$RutaFTP\LocalUser"
    if (Test-Path $localUserPath) {
        $carpetasUsuario = Get-ChildItem -Path $localUserPath -Directory |
                           Where-Object { $_.Name -ne "Public" }
        foreach ($cu in $carpetasUsuario) {
            $u = $cu.Name
            if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) {
                Remove-LocalUser -Name $u
                Escribir-OK "Usuario eliminado: $u"
            }
        }
    }

    # Eliminar todos los grupos FTP (dinamicos + iniciales)
    $todosGrupos = Obtener-GruposFTP
    foreach ($g in $todosGrupos) {
        if (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue) {
            Remove-LocalGroup -Name $g
            Escribir-OK "Grupo eliminado: $g"
        }
    }
    # Por si quedan grupos iniciales sin carpeta
    foreach ($g in $GruposIniciales) {
        if (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue) {
            Remove-LocalGroup -Name $g
            Escribir-OK "Grupo eliminado: $g"
        }
    }

    if (Test-Path $RutaFTP) {
        Remove-Item -Path $RutaFTP -Recurse -Force
        Escribir-OK "Estructura de carpetas eliminada: $RutaFTP"
    } else {
        Escribir-Info "La carpeta $RutaFTP no existia."
    }

    if (Get-NetFirewallRule -DisplayName "FTP Puerto 21" -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName "FTP Puerto 21"
        Escribir-OK "Regla de firewall eliminada."
    }

    Write-Host ""
    Escribir-OK "Reset completado. Servidor FTP limpio."
}

# ==========================================================
# MENU PRINCIPAL
# ==========================================================
function Mostrar-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |      AUTOMATIZACION SERVIDOR FTP - WINDOWS SERVER        |" -ForegroundColor Cyan
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  A) Instalar y configurar el servidor FTP" -ForegroundColor Green
    Write-Host "  B) Creacion masiva de usuarios FTP"       -ForegroundColor Green
    Write-Host "  C) Cambiar grupo de un usuario existente" -ForegroundColor Green
    Write-Host "  D) Gestion de grupos (agregar / eliminar / listar)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  R) RESET - Limpiar servidor FTP completamente" -ForegroundColor Red
    Write-Host "  S) Salir" -ForegroundColor Gray
    Write-Host ""
}

do {
    Mostrar-Menu
    $opcion = (Read-Host "  Selecciona una opcion").Trim().ToUpper()

    switch ($opcion) {
        "A" { Opcion-Instalar      }
        "B" { Opcion-CrearUsuarios }
        "C" { Opcion-CambiarGrupo  }
        "D" { Opcion-GestionGrupos }
        "R" { Opcion-Reset         }
        "S" { Write-Host "" }
        default { Escribir-Error "Opcion no valida." }
    }

    if ($opcion -ne "S") {
        Write-Host ""
        Read-Host "  Presiona ENTER para volver al menu"
    }

} while ($opcion -ne "S")