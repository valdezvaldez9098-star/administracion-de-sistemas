# ============================================================
# PRACTICA 8 - Script 02: FSRM
# File Server Resource Manager
# Cuotas por grupo y Apantallamiento de archivos
# Ejecutar como Administrador en PowerShell
# ============================================================

param(
    [string]$ShareRoot  = "C:\Perfiles",
    [string]$DomainName = "practica8.local"
)

function Write-Log {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "[FSRM] $Msg" -ForegroundColor $Color
}

Import-Module ActiveDirectory

# Verificar que FSRM este instalado
if (-not (Get-Module -ListAvailable -Name "FSRM")) {
    Write-Log "Instalando rol File Server Resource Manager..." "Yellow"
    Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
}

# ============================================================
# BLOQUE 1: Crear Plantillas de Cuota
# ============================================================
Write-Log "Creando plantillas de cuota (5 MB y 10 MB)..."

# --- Plantilla 5 MB para NoCuates ---
$NombrePlantilla5  = "Cuota_NoCuates_5MB"
$LimiteMB5         = 5MB   # 5,242,880 bytes

if (-not (Get-FsrmQuotaTemplate -Name $NombrePlantilla5 -ErrorAction SilentlyContinue)) {
    # Crear notificacion de advertencia al 80%
    $Notif80 = New-FsrmAction -Type Email `
        -MailTo "[Admin Email]" `
        -Subject "ADVERTENCIA: Usuario [Source Io Owner] alcanzando limite de cuota" `
        -Body "El usuario [Source Io Owner] ha alcanzado el 80% de su cuota de 5 MB en [Quota Path]."

    $Umbral80 = New-FsrmQuotaThreshold -Percentage 80 -Action @($Notif80)

    New-FsrmQuotaTemplate `
        -Name        $NombrePlantilla5 `
        -Size        $LimiteMB5 `
        -SoftLimit   $false `
        -Threshold   @($Umbral80) `
        -Description "Cuota estricta de 5 MB para usuarios NoCuates"

    Write-Log "Plantilla '$NombrePlantilla5' creada." "Green"
} else {
    Write-Log "Plantilla '$NombrePlantilla5' ya existe." "Yellow"
}

# --- Plantilla 10 MB para Cuates ---
$NombrePlantilla10 = "Cuota_Cuates_10MB"
$LimiteMB10        = 10MB  # 10,485,760 bytes

if (-not (Get-FsrmQuotaTemplate -Name $NombrePlantilla10 -ErrorAction SilentlyContinue)) {
    $Notif80b = New-FsrmAction -Type Email `
        -MailTo "[Admin Email]" `
        -Subject "ADVERTENCIA: Usuario [Source Io Owner] alcanzando limite de cuota" `
        -Body "El usuario [Source Io Owner] ha alcanzado el 80% de su cuota de 10 MB en [Quota Path]."

    $Umbral80b = New-FsrmQuotaThreshold -Percentage 80 -Action @($Notif80b)

    New-FsrmQuotaTemplate `
        -Name        $NombrePlantilla10 `
        -Size        $LimiteMB10 `
        -SoftLimit   $false `
        -Threshold   @($Umbral80b) `
        -Description "Cuota estricta de 10 MB para usuarios Cuates"

    Write-Log "Plantilla '$NombrePlantilla10' creada." "Green"
} else {
    Write-Log "Plantilla '$NombrePlantilla10' ya existe." "Yellow"
}

# ============================================================
# BLOQUE 2: Aplicar Cuotas a las carpetas personales
# ============================================================
Write-Log "Aplicando cuotas a las carpetas personales de cada usuario..."

# Obtener miembros de cada grupo
$MiembrosCuates   = Get-ADGroupMember -Identity "Cuates"   | Where-Object {$_.objectClass -eq "user"}
$MiembrosNoCuates = Get-ADGroupMember -Identity "NoCuates" | Where-Object {$_.objectClass -eq "user"}

foreach ($Usuario in $MiembrosCuates) {
    $Carpeta = "$ShareRoot\$($Usuario.SamAccountName)"

    if (-not (Test-Path $Carpeta)) {
        New-Item -ItemType Directory -Path $Carpeta -Force | Out-Null
        Write-Log "  Carpeta creada: $Carpeta" "Yellow"
    }

    # Revisar si ya tiene cuota asignada
    $CuotaExistente = Get-FsrmQuota -Path $Carpeta -ErrorAction SilentlyContinue
    if ($CuotaExistente) {
        Remove-FsrmQuota -Path $Carpeta -Confirm:$false
    }

    New-FsrmQuota -Path $Carpeta -Template $NombrePlantilla10 -Confirm:$false
    Write-Log "  Cuota 10 MB aplicada a: $($Usuario.SamAccountName)" "Green"
}

foreach ($Usuario in $MiembrosNoCuates) {
    $Carpeta = "$ShareRoot\$($Usuario.SamAccountName)"

    if (-not (Test-Path $Carpeta)) {
        New-Item -ItemType Directory -Path $Carpeta -Force | Out-Null
        Write-Log "  Carpeta creada: $Carpeta" "Yellow"
    }

    $CuotaExistente = Get-FsrmQuota -Path $Carpeta -ErrorAction SilentlyContinue
    if ($CuotaExistente) {
        Remove-FsrmQuota -Path $Carpeta -Confirm:$false
    }

    New-FsrmQuota -Path $Carpeta -Template $NombrePlantilla5 -Confirm:$false
    Write-Log "  Cuota 5 MB aplicada a: $($Usuario.SamAccountName)" "Green"
}

# ============================================================
# BLOQUE 3: Crear Grupo de Archivos Prohibidos
# ============================================================
Write-Log "Creando grupo de archivos prohibidos (multimedia y ejecutables)..."

$GrupoArchivoProhibido = "Archivos_Prohibidos_Practica8"

if (-not (Get-FsrmFileGroup -Name $GrupoArchivoProhibido -ErrorAction SilentlyContinue)) {
    New-FsrmFileGroup `
        -Name              $GrupoArchivoProhibido `
        -IncludePattern    @("*.mp3","*.mp4","*.exe","*.msi","*.avi","*.mkv","*.mov","*.wmv","*.flac","*.wav") `
        -Description       "Extensiones multimedia y ejecutables prohibidas en carpetas personales"

    Write-Log "Grupo de archivos '$GrupoArchivoProhibido' creado." "Green"
} else {
    Write-Log "Grupo '$GrupoArchivoProhibido' ya existe." "Yellow"
}

# ============================================================
# BLOQUE 4: Crear Plantilla de Apantallamiento
# ============================================================
Write-Log "Creando plantilla de apantallamiento activo..."

$PlantillaScreen = "Bloqueo_Multimedia_Ejecutables"

if (-not (Get-FsrmFileScreenTemplate -Name $PlantillaScreen -ErrorAction SilentlyContinue)) {
    # Accion: registrar evento en el visor de eventos (evidencia para rubrica)
    $AccionEvento = New-FsrmAction -Type Event `
        -EventType Warning `
        -Body "BLOQUEADO: El usuario [Source Io Owner] intento guardar [Source File Path] (tipo prohibido) en [File Screen Path]."

    # Accion: enviar correo (opcional, requiere SMTP configurado)
    # $AccionEmail = New-FsrmAction -Type Email ...

    New-FsrmFileScreenTemplate `
        -Name             $PlantillaScreen `
        -Active           $true `
        -IncludeGroup     @($GrupoArchivoProhibido) `
        -Notification     @($AccionEvento) `
        -Description      "Bloqueo activo de multimedia y ejecutables"

    Write-Log "Plantilla de apantallamiento '$PlantillaScreen' creada." "Green"
} else {
    Write-Log "Plantilla '$PlantillaScreen' ya existe." "Yellow"
}

# ============================================================
# BLOQUE 5: Aplicar Apantallamiento a TODAS las carpetas personales
# ============================================================
Write-Log "Aplicando apantallamiento a todas las carpetas personales..."

$TodosLosUsuarios = $MiembrosCuates + $MiembrosNoCuates

foreach ($Usuario in $TodosLosUsuarios) {
    $Carpeta = "$ShareRoot\$($Usuario.SamAccountName)"

    if (Test-Path $Carpeta) {
        # Eliminar apantallamiento previo si existe
        $ScreenExistente = Get-FsrmFileScreen -Path $Carpeta -ErrorAction SilentlyContinue
        if ($ScreenExistente) {
            Remove-FsrmFileScreen -Path $Carpeta -Confirm:$false
        }

        New-FsrmFileScreen -Path $Carpeta -Template $PlantillaScreen -Confirm:$false
        Write-Log "  Apantallamiento aplicado a: $($Usuario.SamAccountName)" "Green"
    }
}

# ============================================================
# VERIFICACION FINAL
# ============================================================
Write-Log "=== Verificacion de cuotas ===" "Magenta"
Get-FsrmQuota -Path "$ShareRoot\*" | Select-Object Path, Size, @{N="UsadoMB";E={[math]::Round($_.Usage/1MB,2)}} | Format-Table

Write-Log "=== Verificacion de apantallamientos ===" "Magenta"
Get-FsrmFileScreen -Path "$ShareRoot\*" | Select-Object Path, Active, IncludeGroup | Format-Table

Write-Log "=== Script FSRM completado. Continua con 03_AppLocker.ps1 ===" "Magenta"
