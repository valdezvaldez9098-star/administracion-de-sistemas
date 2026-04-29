# ============================================================
# PRACTICA 9 - Script 04: Monitoreo y Auditoria de Eventos
# Ejecutar en Windows Server 2022 Core como Administrador
# powershell -ExecutionPolicy Bypass -File C:\Scripts\04_Script_Monitoreo_Auditoria.ps1
#
# Este script extrae los ultimos 10 eventos de Acceso Denegado
# (ID 4625 y similares) y los exporta a un archivo .txt y .csv
# ============================================================

# ============== CONFIGURACION - EDITAR AQUI ================
$ReportePath  = "C:\Scripts\Auditoria_Practica9"
$MaxEvents    = 10
$DomainName   = "practica8.local"
$MFALogPath   = "C:\Scripts\mfa_audit.log"
# ===========================================================

function Write-Log  { param($m) Write-Host "[INFO] $m"  -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[OK]   $m"  -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m"  -ForegroundColor Yellow }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportTXT   = "$ReportePath\Reporte_Auditoria_$Timestamp.txt"
$ReportCSV   = "$ReportePath\Reporte_Auditoria_$Timestamp.csv"
$ReportFull  = "$ReportePath\Reporte_Completo_$Timestamp.txt"

# Crear directorio de reportes
if (-not (Test-Path $ReportePath)) {
    New-Item -ItemType Directory -Path $ReportePath -Force | Out-Null
    Write-OK "Directorio de reportes creado: $ReportePath"
}

# ============================================================
# SECCION 1: Eventos de inicio de sesion fallido (ID 4625)
# ============================================================
Write-Log "Extrayendo eventos ID 4625 (Inicio de sesion fallido)..."

$events4625 = @()
try {
    $events4625 = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
    } -MaxEvents $MaxEvents -ErrorAction Stop

    Write-OK "Se encontraron $($events4625.Count) eventos ID 4625."
} catch {
    Write-Warn "No se encontraron eventos 4625 o acceso denegado al log: $_"
}

# ============================================================
# SECCION 2: Eventos de bloqueo de cuenta (ID 4740)
# ============================================================
Write-Log "Extrayendo eventos ID 4740 (Cuenta bloqueada)..."

$events4740 = @()
try {
    $events4740 = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4740
    } -MaxEvents $MaxEvents -ErrorAction Stop
    Write-OK "Se encontraron $($events4740.Count) eventos ID 4740."
} catch {
    Write-Warn "No se encontraron eventos 4740: $_"
}

# ============================================================
# SECCION 3: Eventos de cambio de contrasena (ID 4723, 4724)
# ============================================================
Write-Log "Extrayendo eventos de cambio de contrasena (ID 4723, 4724)..."

$eventsPass = @()
try {
    $eventsPass = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = @(4723, 4724)
    } -MaxEvents $MaxEvents -ErrorAction Stop
    Write-OK "Se encontraron $($eventsPass.Count) eventos de cambio de contrasena."
} catch {
    Write-Warn "No se encontraron eventos de contrasena: $_"
}

# ============================================================
# SECCION 4: Cambios en cuentas de usuario (ID 4720, 4722, 4726)
# ============================================================
Write-Log "Extrayendo eventos de gestion de cuentas (ID 4720, 4722, 4726)..."

$eventsAcct = @()
try {
    $eventsAcct = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = @(4720, 4722, 4726, 4738)
    } -MaxEvents $MaxEvents -ErrorAction Stop
    Write-OK "Se encontraron $($eventsAcct.Count) eventos de cuentas."
} catch {
    Write-Warn "No se encontraron eventos de cuentas: $_"
}

# ============================================================
# SECCION 5: Cambios en GPOs (ID 5136, 5141)
# ============================================================
Write-Log "Extrayendo eventos de cambios en AD/GPO (ID 5136, 5141)..."

$eventsGPO = @()
try {
    $eventsGPO = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = @(5136, 5141, 4670)
    } -MaxEvents $MaxEvents -ErrorAction Stop
    Write-OK "Se encontraron $($eventsGPO.Count) eventos de cambios AD."
} catch {
    Write-Warn "No se encontraron eventos de GPO: $_"
}

# ============================================================
# FUNCION: Parsear evento de seguridad a objeto estructurado
# ============================================================
function ConvertFrom-SecurityEvent {
    param($Event)
    $xml    = [xml]$Event.ToXml()
    $data   = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        if ($d.Name) { $data[$d.Name] = $d.'#text' }
    }
    return [PSCustomObject]@{
        EventID       = $Event.Id
        TimeGenerated = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        MachineName   = $Event.MachineName
        Message       = $Event.Message -replace "`r`n"," " -replace "`n"," "
        TargetUser    = if ($data["TargetUserName"])  { $data["TargetUserName"] }  else { "" }
        SubjectUser   = if ($data["SubjectUserName"]) { $data["SubjectUserName"] } else { "" }
        TargetDomain  = if ($data["TargetDomainName"]){ $data["TargetDomainName"]}else { "" }
        LogonType     = if ($data["LogonType"])        { $data["LogonType"] }       else { "" }
        FailureReason = if ($data["FailureReason"])    { $data["FailureReason"] }   else { "" }
        IPAddress     = if ($data["IpAddress"])        { $data["IpAddress"] }       else { "" }
        WorkStation   = if ($data["WorkstationName"]) { $data["WorkstationName"] } else { "" }
    }
}

# ============================================================
# GENERAR REPORTE TXT
# ============================================================
Write-Log "Generando reporte TXT: $ReportTXT"

$header = @"
============================================================
  REPORTE DE AUDITORIA DE SEGURIDAD - PRACTICA 9
  Dominio : $DomainName
  Servidor: $env:COMPUTERNAME
  Fecha   : $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
============================================================

"@

$header | Set-Content -Path $ReportTXT -Encoding UTF8

# --- Seccion: Accesos Denegados (4625) ---
"" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT
"  SECCION 1: ULTIMOS $MaxEvents INTENTOS DE ACCESO FALLIDO (ID 4625)" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT

if ($events4625.Count -gt 0) {
    foreach ($ev in $events4625) {
        $parsed = ConvertFrom-SecurityEvent $ev
        "[$($parsed.TimeGenerated)] ID:$($parsed.EventID) | Usuario: $($parsed.TargetUser) | Dominio: $($parsed.TargetDomain) | IP: $($parsed.IPAddress) | Workstation: $($parsed.WorkStation) | LogonType: $($parsed.LogonType) | Razon: $($parsed.FailureReason)" | Add-Content $ReportTXT
    }
} else {
    "[SIN EVENTOS] No se encontraron eventos de acceso fallido en el log de seguridad." | Add-Content $ReportTXT
}

# --- Seccion: Bloqueos (4740) ---
"" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT
"  SECCION 2: ULTIMOS $MaxEvents BLOQUEOS DE CUENTA (ID 4740)" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT

if ($events4740.Count -gt 0) {
    foreach ($ev in $events4740) {
        $parsed = ConvertFrom-SecurityEvent $ev
        "[$($parsed.TimeGenerated)] CUENTA BLOQUEADA: $($parsed.TargetUser) | Desde: $($parsed.WorkStation) | IP: $($parsed.IPAddress)" | Add-Content $ReportTXT
    }
} else {
    "[SIN EVENTOS] No se encontraron eventos de bloqueo de cuenta." | Add-Content $ReportTXT
}

# --- Seccion: Cambios de Contrasena ---
"" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT
"  SECCION 3: CAMBIOS DE CONTRASENA (ID 4723/4724)" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT

if ($eventsPass.Count -gt 0) {
    foreach ($ev in $eventsPass) {
        $parsed = ConvertFrom-SecurityEvent $ev
        $accion = if ($ev.Id -eq 4723) { "CAMBIO POR USUARIO" } else { "RESET POR ADMIN" }
        "[$($parsed.TimeGenerated)] ID:$($ev.Id) $accion | Cuenta: $($parsed.TargetUser) | Por: $($parsed.SubjectUser)" | Add-Content $ReportTXT
    }
} else {
    "[SIN EVENTOS] No se encontraron eventos de cambio de contrasena." | Add-Content $ReportTXT
}

# --- Seccion: Gestion de Cuentas ---
"" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT
"  SECCION 4: CAMBIOS EN CUENTAS (ID 4720/4722/4726/4738)" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT

if ($eventsAcct.Count -gt 0) {
    $tipoEvento = @{ 4720 = "CUENTA CREADA"; 4722 = "CUENTA HABILITADA"; 4726 = "CUENTA ELIMINADA"; 4738 = "CUENTA MODIFICADA" }
    foreach ($ev in $eventsAcct) {
        $parsed = ConvertFrom-SecurityEvent $ev
        $tipo   = if ($tipoEvento[$ev.Id]) { $tipoEvento[$ev.Id] } else { "CAMBIO ID:$($ev.Id)" }
        "[$($parsed.TimeGenerated)] $tipo | Cuenta: $($parsed.TargetUser) | Por: $($parsed.SubjectUser)" | Add-Content $ReportTXT
    }
} else {
    "[SIN EVENTOS] No se encontraron eventos de cambios de cuenta." | Add-Content $ReportTXT
}

# --- Seccion: Log MFA ---
"" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT
"  SECCION 5: LOG DE INTENTOS MFA" | Add-Content $ReportTXT
"============================================================" | Add-Content $ReportTXT

if (Test-Path $MFALogPath) {
    $mfaLines = Get-Content $MFALogPath -ErrorAction SilentlyContinue
    if ($mfaLines) {
        $mfaLines | Select-Object -Last $MaxEvents | ForEach-Object { $_ | Add-Content $ReportTXT }
        Write-OK "  Log MFA incluido en el reporte."
    } else {
        "[SIN EVENTOS] El archivo MFA existe pero esta vacio." | Add-Content $ReportTXT
    }
} else {
    "[SIN EVENTOS] No existe log MFA. Ejecuta 03_Configurar_MFA_TOTP.ps1 primero." | Add-Content $ReportTXT
}

# ============================================================
# GENERAR REPORTE CSV
# ============================================================
Write-Log "Generando reporte CSV: $ReportCSV"

$allEvents = @()
foreach ($ev in ($events4625 + $events4740 + $eventsPass + $eventsAcct + $eventsGPO)) {
    try {
        $parsed = ConvertFrom-SecurityEvent $ev
        $allEvents += $parsed
    } catch { }
}

if ($allEvents.Count -gt 0) {
    $allEvents | Export-Csv -Path $ReportCSV -NoTypeInformation -Encoding UTF8
    Write-OK "CSV generado con $($allEvents.Count) registros: $ReportCSV"
} else {
    "EventID,TimeGenerated,MachineName,TargetUser,SubjectUser,TargetDomain,IPAddress,FailureReason" | Set-Content $ReportCSV -Encoding UTF8
    "[SIN DATOS] No se encontraron eventos para exportar." | Add-Content $ReportCSV
    Write-Warn "No se encontraron eventos. CSV vacio generado."
}

# ============================================================
# MOSTRAR RESUMEN EN CONSOLA
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " REPORTE DE AUDITORIA GENERADO                             " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Accesos Fallidos (4625): $($events4625.Count) eventos" -ForegroundColor White
Write-Host "  Bloqueos de Cuenta (4740): $($events4740.Count) eventos" -ForegroundColor White
Write-Host "  Cambios de Contrasena (4723/4724): $($eventsPass.Count) eventos" -ForegroundColor White
Write-Host "  Cambios de Cuentas (4720+): $($eventsAcct.Count) eventos" -ForegroundColor White
Write-Host "  Cambios GPO/AD (5136+): $($eventsGPO.Count) eventos" -ForegroundColor White
Write-Host ""
Write-Host "  Reporte TXT : $ReportTXT" -ForegroundColor Cyan
Write-Host "  Reporte CSV : $ReportCSV" -ForegroundColor Cyan
Write-Host ""
Write-Host "Siguiente paso: Ejecutar 05_Verificacion_Practica9.ps1" -ForegroundColor Yellow
