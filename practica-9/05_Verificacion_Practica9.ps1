# ============================================================
# PRACTICA 9 - Script 05: Verificacion Completa
# Ejecutar en Windows Server 2022 Core como Administrador
# powershell -ExecutionPolicy Bypass -File C:\Scripts\05_Verificacion_Practica9.ps1
# ============================================================

# ============== CONFIGURACION - EDITAR AQUI ================
$DomainName    = "practica8.local"
$DomainDN      = "DC=practica8,DC=local"
$OUCuates      = "OU=Cuates,$DomainDN"
$OUNoCuates    = "OU=NoCuates,$DomainDN"
$MFASecretFile = "C:\Scripts\mfa_secrets.json"
$MFALogPath    = "C:\Scripts\mfa_audit.log"
$ReportePath   = "C:\Scripts\Reporte_Practica9.txt"
# ===========================================================

Import-Module ActiveDirectory -ErrorAction Stop

function Write-Log  { param($m) Write-Host "[INFO] $m"  -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[OK]   $m"  -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m"  -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "[FAIL] $m"  -ForegroundColor Red }

$report = @()
function Add-Report { param($section, $item, $status, $detail)
    $report += [PSCustomObject]@{ Seccion = $section; Elemento = $item; Estado = $status; Detalle = $detail }
}

# ============================================================
# VERIFICACION 1: Usuarios delegados
# ============================================================
Write-Log "Verificando usuarios delegados..."

$adminUsers = @("admin_identidad","admin_storage","admin_politicas","admin_auditoria")
foreach ($u in $adminUsers) {
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$u'" -Properties Enabled, Description -ErrorAction SilentlyContinue
    if ($adUser -and $adUser.Enabled) {
        Write-OK "  $u : Activo"
        Add-Report "RBAC" "Usuario $u" "OK" "Cuenta activa en OU=AdminDelegados"
    } elseif ($adUser) {
        Write-Warn "  $u : Existe pero DESHABILITADO"
        Add-Report "RBAC" "Usuario $u" "WARN" "Cuenta deshabilitada"
    } else {
        Write-Fail "  $u : NO EXISTE"
        Add-Report "RBAC" "Usuario $u" "FAIL" "Usuario no encontrado en AD"
    }
}

# ============================================================
# VERIFICACION 2: FGPP
# ============================================================
Write-Log "Verificando Fine-Grained Password Policies..."

$fgppAdmin = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Admins_P9'" -ErrorAction SilentlyContinue
if ($fgppAdmin) {
    Write-OK "  FGPP_Admins_P9 : MinLength=$($fgppAdmin.MinPasswordLength), Lockout=$($fgppAdmin.LockoutThreshold) intentos / $($fgppAdmin.LockoutDuration.TotalMinutes) min"
    Add-Report "FGPP" "FGPP_Admins_P9" "OK" "MinLen:$($fgppAdmin.MinPasswordLength) | Lockout:$($fgppAdmin.LockoutThreshold)/$($fgppAdmin.LockoutDuration.TotalMinutes)min"
    # Verificar que admin_identidad tiene la FGPP efectiva
    $resultante = Get-ADUserResultantPasswordPolicy "admin_identidad" -ErrorAction SilentlyContinue
    if ($resultante -and $resultante.MinPasswordLength -ge 12) {
        Write-OK "  admin_identidad FGPP efectiva: MinLen=$($resultante.MinPasswordLength)"
        Add-Report "FGPP" "FGPP efectiva admin_identidad" "OK" "MinLen=$($resultante.MinPasswordLength) (requiere >=12)"
    } else {
        Write-Warn "  admin_identidad FGPP efectiva: $($resultante.MinPasswordLength) (esperado >=12)"
        Add-Report "FGPP" "FGPP efectiva admin_identidad" "WARN" "MinLen=$($resultante.MinPasswordLength) esperado >=12"
    }
} else {
    Write-Fail "  FGPP_Admins_P9 : NO EXISTE"
    Add-Report "FGPP" "FGPP_Admins_P9" "FAIL" "No encontrada"
}

$fgppUser = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Usuarios_P9'" -ErrorAction SilentlyContinue
if ($fgppUser) {
    Write-OK "  FGPP_Usuarios_P9 : MinLength=$($fgppUser.MinPasswordLength)"
    Add-Report "FGPP" "FGPP_Usuarios_P9" "OK" "MinLen:$($fgppUser.MinPasswordLength)"
} else {
    Write-Fail "  FGPP_Usuarios_P9 : NO EXISTE"
    Add-Report "FGPP" "FGPP_Usuarios_P9" "FAIL" "No encontrada"
}

# ============================================================
# VERIFICACION 3: Auditoria (auditpol)
# ============================================================
Write-Log "Verificando politicas de auditoria..."

$auditCheck = @("Logon","Account Lockout","User Account Management","Directory Service Changes","Audit Policy Change")
foreach ($sub in $auditCheck) {
    $result = auditpol /get /subcategory:"$sub" 2>&1
    if ($result -match "Success and Failure") {
        Write-OK "  Auditoria '$sub': Success and Failure habilitados"
        Add-Report "Auditoria" $sub "OK" "Success and Failure"
    } elseif ($result -match "Success") {
        Write-Warn "  Auditoria '$sub': Solo Success (falta Failure)"
        Add-Report "Auditoria" $sub "WARN" "Solo Success habilitado"
    } else {
        Write-Warn "  Auditoria '$sub': No configurada o estado desconocido"
        Add-Report "Auditoria" $sub "WARN" "Estado no confirmado"
    }
}

# ============================================================
# VERIFICACION 4: MFA
# ============================================================
Write-Log "Verificando configuracion MFA..."

if (Test-Path $MFASecretFile) {
    $secrets = Get-Content $MFASecretFile -Raw | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
    if ($secrets -and $secrets.Count -gt 0) {
        Write-OK "  Secretos MFA: $($secrets.Count) usuarios configurados"
        Add-Report "MFA" "Archivo de secretos" "OK" "$($secrets.Count) usuarios con TOTP"
        foreach ($u in $secrets.Keys) {
            $locked = if ($secrets[$u].LockedUntil) { "BLOQUEADO hasta $($secrets[$u].LockedUntil)" } else { "Activo" }
            Write-OK "    $u : $locked | Fallos: $($secrets[$u].FailCount)"
            Add-Report "MFA" "MFA usuario $u" "OK" $locked
        }
    } else {
        Write-Warn "  Archivo MFA existe pero sin secretos"
        Add-Report "MFA" "Archivo de secretos" "WARN" "Sin secretos configurados"
    }
} else {
    Write-Fail "  $MFASecretFile NO EXISTE — ejecuta Script 03"
    Add-Report "MFA" "Archivo de secretos" "FAIL" "Archivo no encontrado"
}

if (Test-Path "C:\Scripts\Validate-MFA.ps1") {
    Write-OK "  Validate-MFA.ps1 existe"
    Add-Report "MFA" "Script Validate-MFA.ps1" "OK" "Presente en C:\Scripts"
} else {
    Write-Fail "  C:\Scripts\Validate-MFA.ps1 NO EXISTE"
    Add-Report "MFA" "Script Validate-MFA.ps1" "FAIL" "No encontrado"
}

if (Test-Path $MFALogPath) {
    $mfaLines = (Get-Content $MFALogPath -ErrorAction SilentlyContinue).Count
    Write-OK "  Log MFA: $mfaLines registros"
    Add-Report "MFA" "Log de auditoría MFA" "OK" "$mfaLines lineas en $MFALogPath"
} else {
    Write-Warn "  Log MFA no existe aun (se crea al primer uso)"
    Add-Report "MFA" "Log de auditoría MFA" "WARN" "No hay logs aun"
}

# ============================================================
# VERIFICACION 5: Politica de bloqueo de cuenta
# ============================================================
Write-Log "Verificando politica de bloqueo de cuenta..."
$domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
if ($domainPolicy) {
    Write-OK "  Lockout Threshold: $($domainPolicy.LockoutThreshold)"
    Write-OK "  Lockout Duration : $($domainPolicy.LockoutDuration.TotalMinutes) min"
    Add-Report "Lockout" "LockoutThreshold" "OK" "$($domainPolicy.LockoutThreshold) intentos"
    Add-Report "Lockout" "LockoutDuration"  "OK" "$($domainPolicy.LockoutDuration.TotalMinutes) minutos"
}

# ============================================================
# VERIFICACION 6: Evento Log Readers
# ============================================================
Write-Log "Verificando membresia en 'Event Log Readers'..."
try {
    $members = Get-ADGroupMember "Event Log Readers" -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
    if ($members -contains "admin_auditoria") {
        Write-OK "  admin_auditoria esta en Event Log Readers"
        Add-Report "RBAC" "admin_auditoria Event Log Readers" "OK" "Miembro del grupo"
    } else {
        Write-Warn "  admin_auditoria NO esta en Event Log Readers"
        Add-Report "RBAC" "admin_auditoria Event Log Readers" "WARN" "No es miembro"
    }
} catch {
    Write-Warn "  No se pudo verificar Event Log Readers: $_"
}

# ============================================================
# VERIFICACION 7: Reportes de auditoria generados
# ============================================================
Write-Log "Verificando reportes de auditoria generados..."
$auditReports = Get-ChildItem "C:\Scripts\Auditoria_Practica9" -ErrorAction SilentlyContinue
if ($auditReports) {
    Write-OK "  $($auditReports.Count) archivos de reporte en C:\Scripts\Auditoria_Practica9"
    Add-Report "Auditoria" "Reportes generados" "OK" "$($auditReports.Count) archivos"
    $auditReports | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor Gray }
} else {
    Write-Warn "  No hay reportes aun. Ejecuta Script 04."
    Add-Report "Auditoria" "Reportes generados" "WARN" "Ejecutar Script 04"
}

# ============================================================
# GENERAR REPORTE FINAL
# ============================================================
Write-Log "Generando reporte final: $ReportePath"

$header = @"
============================================================
  REPORTE DE VERIFICACION - PRACTICA 9
  Seguridad de Identidad, Delegacion y MFA
  Dominio : $DomainName
  Servidor: $env:COMPUTERNAME
  Fecha   : $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
============================================================

"@

$header | Set-Content $ReportePath -Encoding UTF8

$report | Format-Table -AutoSize | Out-String | Add-Content $ReportePath

# Resumen
$ok   = ($report | Where-Object { $_.Estado -eq "OK" }).Count
$warn = ($report | Where-Object { $_.Estado -eq "WARN" }).Count
$fail = ($report | Where-Object { $_.Estado -eq "FAIL" }).Count

$summary = @"

============================================================
  RESUMEN: OK=$ok  WARN=$warn  FAIL=$fail  TOTAL=$($report.Count)
============================================================
"@
$summary | Add-Content $ReportePath

# ============================================================
# MOSTRAR RESUMEN
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " VERIFICACION PRACTICA 9 COMPLETADA                        " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
$report | Format-Table Seccion, Elemento, Estado, Detalle -AutoSize
Write-Host ""
Write-Host "  OK   : $ok" -ForegroundColor Green
Write-Host "  WARN : $warn" -ForegroundColor Yellow
Write-Host "  FAIL : $fail" -ForegroundColor Red
Write-Host ""
Write-Host "Reporte guardado en: $ReportePath" -ForegroundColor Cyan
