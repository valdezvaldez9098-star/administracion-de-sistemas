# ============================================================
# PRACTICA 8 - Script 06: Verificacion Completa
# Genera evidencias para el documento formal
# Ejecutar en el DC como Administrador
# ============================================================

param(
    [string]$ShareRoot   = "C:\Perfiles",
    [string]$ReportePath = "C:\Scripts\Reporte_Practica8.txt"
)

function Write-Log {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host $Msg -ForegroundColor $Color
}

function Write-Report {
    param([string]$Line)
    Add-Content -Path $ReportePath -Value $Line
    Write-Host $Line
}

# Iniciar reporte
New-Item -ItemType File -Path $ReportePath -Force | Out-Null
Write-Report "============================================================"
Write-Report " REPORTE DE VERIFICACION - PRACTICA 8"
Write-Report " Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Report " Servidor: $env:COMPUTERNAME"
Write-Report "============================================================"
Write-Report ""

Import-Module ActiveDirectory

# ============================================================
# SECCION 1: Estructura de AD
# ============================================================
Write-Report "=== 1. UNIDADES ORGANIZATIVAS ==="
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName | Format-Table | Out-String | ForEach-Object { Write-Report $_ }

Write-Report "=== 2. GRUPOS DE SEGURIDAD ==="
foreach ($G in @("Cuates","NoCuates")) {
    Write-Report "  Grupo: $G"
    Get-ADGroupMember -Identity $G | Select-Object Name, SamAccountName | Format-Table | Out-String | ForEach-Object { Write-Report "  $_" }
}

# ============================================================
# SECCION 2: Horarios de Logon
# ============================================================
Write-Report "=== 3. HORARIOS DE INICIO DE SESION (muestra primeros 3 usuarios) ==="
$Todos = Get-ADUser -Filter * -Properties LogonHours, MemberOf | Where-Object { $_.DistinguishedName -match "OU=(Cuates|NoCuates)" }
$Todos | Select-Object -First 6 | ForEach-Object {
    $OU = if ($_.DistinguishedName -match "OU=Cuates") { "Cuates (08:00-15:00)" } else { "NoCuates (15:00-02:00)" }
    Write-Report "  $($_.SamAccountName) -> $OU | LogonHours configurados: $(($_.LogonHours -ne $null))"
}

# ============================================================
# SECCION 3: FSRM - Cuotas
# ============================================================
Write-Report ""
Write-Report "=== 4. CUOTAS FSRM ==="
try {
    Get-FsrmQuota -Path "$ShareRoot\*" -ErrorAction Stop |
        Select-Object Path,
                      @{N="LimiteMB"; E={[math]::Round($_.Size/1MB,0)}},
                      @{N="UsadoMB";  E={[math]::Round($_.Usage/1MB,2)}},
                      @{N="% Uso";    E={[math]::Round(($_.Usage/$_.Size)*100,1)}} |
        Format-Table | Out-String | ForEach-Object { Write-Report $_ }
} catch {
    Write-Report "  FSRM no disponible o sin cuotas configuradas: $($_.Exception.Message)"
}

# ============================================================
# SECCION 4: FSRM - Apantallamientos
# ============================================================
Write-Report "=== 5. APANTALLAMIENTOS DE ARCHIVOS (File Screens) ==="
try {
    Get-FsrmFileScreen -Path "$ShareRoot\*" -ErrorAction Stop |
        Select-Object Path, Active, IncludeGroup |
        Format-Table | Out-String | ForEach-Object { Write-Report $_ }
} catch {
    Write-Report "  Sin apantallamientos configurados o FSRM no disponible."
}

# ============================================================
# SECCION 5: GPOs
# ============================================================
Write-Report "=== 6. GROUP POLICY OBJECTS (GPOs) ==="
Get-GPO -All | Select-Object DisplayName, Id, GpoStatus |
    Format-Table | Out-String | ForEach-Object { Write-Report $_ }

Write-Report "=== 7. VINCULOS DE GPOs ==="
Get-GPInheritance -Target (Get-ADDomain).DistinguishedName |
    Select-Object -ExpandProperty GpoLinks |
    Format-Table | Out-String | ForEach-Object { Write-Report $_ }

# ============================================================
# SECCION 6: Eventos FSRM en el Visor de Eventos
# ============================================================
Write-Report ""
Write-Report "=== 8. EVENTOS DE BLOQUEO FSRM (Ultimos 20) ==="
Write-Report "    (Estos eventos se generan cuando un usuario intenta guardar un archivo prohibido)"
try {
    $Eventos = Get-WinEvent -LogName "Microsoft-Windows-SRMSVC/Operational" -MaxEvents 20 -ErrorAction Stop |
               Where-Object { $_.Id -in @(8210, 8215, 12325) }

    if ($Eventos) {
        $Eventos | Select-Object TimeCreated, Id, Message |
            Format-List | Out-String | ForEach-Object { Write-Report $_ }
    } else {
        Write-Report "  No hay eventos de bloqueo FSRM aun. Prueba guardar un .mp3 en una carpeta de usuario."
    }
} catch {
    Write-Report "  No se pudo leer el log FSRM: $($_.Exception.Message)"
    Write-Report "  Ruta alternativa: Visor de eventos -> Registros de aplicaciones y servicios -> Microsoft -> Windows -> SRMSVC"
}

# ============================================================
# SECCION 7: AppLocker
# ============================================================
Write-Report ""
Write-Report "=== 9. POLITICAS APPLOCKER ==="
Write-Report "  GPO Cuates (Permiten notepad):"
Get-GPO -Name "AppLocker_Cuates" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Id, GpoStatus | Format-List |
    Out-String | ForEach-Object { Write-Report "  $_" }

Write-Report "  GPO NoCuates (Bloquean notepad por hash):"
Get-GPO -Name "AppLocker_NoCuates" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Id, GpoStatus | Format-List |
    Out-String | ForEach-Object { Write-Report "  $_" }

Write-Report ""
Write-Report "=== 10. EVENTOS APPLOCKER (Ultimos 10 bloqueos) ==="
try {
    $EventosAL = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 10 -ErrorAction Stop |
                 Where-Object { $_.Id -eq 8004 }  # 8004 = acceso bloqueado

    if ($EventosAL) {
        $EventosAL | Select-Object TimeCreated, Message |
            Format-List | Out-String | ForEach-Object { Write-Report $_ }
    } else {
        Write-Report "  Sin eventos de bloqueo AppLocker aun."
        Write-Report "  Log a revisar en cliente: Visor de eventos -> Registros de aplicaciones -> Microsoft -> Windows -> AppLocker -> EXE and DLL"
    }
} catch {
    Write-Report "  No se encontraron eventos AppLocker en este servidor."
    Write-Report "  Los eventos se generan en los CLIENTES. Revisa el Visor de Eventos en Windows 10."
}

Write-Report ""
Write-Report "============================================================"
Write-Report " FIN DEL REPORTE"
Write-Report "============================================================"

Write-Log ""
Write-Log "Reporte guardado en: $ReportePath" "Green"
Write-Log "Puedes abrirlo con: notepad $ReportePath" "Green"
