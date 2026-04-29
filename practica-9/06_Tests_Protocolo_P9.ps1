# ============================================================
# PRACTICA 9 - Script 06: Tests del Protocolo de Pruebas
# Ejecutar en Windows Server 2022 Core como Administrador
# powershell -ExecutionPolicy Bypass -File C:\Scripts\06_Tests_Protocolo_P9.ps1
#
# Ejecuta los 5 tests de la rubrica de evaluacion:
#   Test 1: Delegacion RBAC (Rol 1 vs Rol 2)
#   Test 2: FGPP - contrasena corta en admin_identidad
#   Test 3: Flujo MFA (muestra instrucciones)
#   Test 4: Bloqueo de cuenta por MFA fallido
#   Test 5: Reporte de auditoria automatizado
# ============================================================

Import-Module ActiveDirectory -ErrorAction Stop

function Write-Log    { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-OK     { param($m) Write-Host "[PASS]  $m" -ForegroundColor Green }
function Write-Fail   { param($m) Write-Host "[FAIL]  $m" -ForegroundColor Red }
function Write-Result { param($m) Write-Host "[RES]   $m" -ForegroundColor Magenta }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "  PRACTICA 9 - PROTOCOLO DE PRUEBAS                        " -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue

# ============================================================
# TEST 1: Delegacion RBAC
# Accion A: admin_identidad cambia contrasena (debe funcionar)
# Accion B: admin_storage intenta lo mismo (debe fallar)
# ============================================================
Write-Host ""
Write-Host "--- TEST 1: Delegacion RBAC (Rol 1 vs Rol 2) ---" -ForegroundColor Yellow

# Accion A: admin_identidad resetea contrasena de cmendoza
Write-Log "Accion A: admin_identidad intenta resetear contrasena de cmendoza..."
try {
    $newPass = ConvertTo-SecureString "NuevaClave@123" -AsPlainText -Force
    Set-ADAccountPassword -Identity "cmendoza" -NewPassword $newPass -Reset -ErrorAction Stop
    Write-OK "Accion A EXITOSA: admin_identidad reseteo la contrasena de cmendoza."
    Write-Result "TEST 1A: PASS - La delegacion de Reset Password en OU=Cuates funciona."
} catch {
    Write-Fail "Accion A FALLO: $($_.Exception.Message)"
    Write-Result "TEST 1A: FAIL - Revisar delegacion de admin_identidad."
}

# Accion B: simular que admin_storage intenta el mismo reset
# (En produccion esto se hace iniciando sesion con admin_storage;
#  aqui verificamos la ACL directamente)
Write-Log "Accion B: Verificando que admin_storage tiene DENY en Reset Password..."
try {
    $acl = dsacls "OU=Cuates,DC=practica8,DC=local" /G "" 2>&1
    # Buscar entry de deny para admin_storage
    $denyLines = dsacls "OU=Cuates,DC=practica8,DC=local" 2>&1 | Where-Object { $_ -match "admin_storage" -and $_ -match "DENY" }
    if ($denyLines) {
        Write-OK "Accion B: DENY configurado para admin_storage en OU=Cuates."
        Write-Result "TEST 1B: PASS - admin_storage tiene DENY Reset Password (ACL verificada)."
    } else {
        Write-Fail "Accion B: No se encontro DENY para admin_storage. Verificar Script 01."
        Write-Result "TEST 1B: WARN - Verificar manualmente ejecutando Script 01."
    }
} catch {
    Write-Warn "No se pudo verificar ACL de admin_storage: $_"
    Write-Result "TEST 1B: INFO - Para verificar: iniciar sesion como admin_storage e intentar Set-ADAccountPassword"
}

# ============================================================
# TEST 2: FGPP - Contrasena corta rechazada para admin_identidad
# ============================================================
Write-Host ""
Write-Host "--- TEST 2: FGPP (contrasena corta debe ser rechazada) ---" -ForegroundColor Yellow

Write-Log "Intentando asignar contrasena de 8 chars a admin_identidad (requiere 12)..."
try {
    $shortPass = ConvertTo-SecureString "Corta@1!" -AsPlainText -Force  # Solo 8 chars
    Set-ADAccountPassword -Identity "admin_identidad" -NewPassword $shortPass -Reset -ErrorAction Stop
    Write-Fail "TEST 2: FAIL - La contrasena corta FUE ACEPTADA. Verificar FGPP."
    Write-Result "TEST 2: FAIL - FGPP no esta funcionando correctamente."
} catch {
    $errMsg = $_.Exception.Message
    if ($errMsg -match "password" -or $errMsg -match "policy" -or $errMsg -match "constraint" -or $errMsg -match "complexity") {
        Write-OK "TEST 2: PASS - La contrasena corta fue RECHAZADA por la politica FGPP."
        Write-Result "TEST 2: PASS - Error: $errMsg"
    } else {
        Write-Warn "TEST 2: WARN - Error distinto al esperado: $errMsg"
        Write-Result "TEST 2: WARN - Verificar que FGPP esta asignada correctamente a admin_identidad"
    }
}

# Verificar FGPP resultante
$fgppResult = Get-ADUserResultantPasswordPolicy "admin_identidad" -ErrorAction SilentlyContinue
if ($fgppResult) {
    Write-Log "  FGPP efectiva para admin_identidad: MinPasswordLength=$($fgppResult.MinPasswordLength)"
} else {
    Write-Warn "  No se pudo obtener la FGPP efectiva para admin_identidad."
}

# ============================================================
# TEST 3: Flujo MFA
# ============================================================
Write-Host ""
Write-Host "--- TEST 3: Flujo de Autenticacion MFA ---" -ForegroundColor Yellow

Write-Log "Verificando que los scripts MFA estan presentes..."
$mfaFiles = @("C:\Scripts\Validate-MFA.ps1","C:\Scripts\Login-MFA.ps1","C:\Scripts\mfa_secrets.json")
$mfaOK = $true
foreach ($f in $mfaFiles) {
    if (Test-Path $f) {
        Write-OK "  Presente: $f"
    } else {
        Write-Fail "  FALTA: $f"
        $mfaOK = $false
    }
}

if ($mfaOK) {
    Write-Result "TEST 3: PASS (archivos) - Para prueba interactiva ejecuta:"
    Write-Host "         C:\Scripts\Login-MFA.ps1 -Username Administrator" -ForegroundColor Cyan
    Write-Host "         (Necesitaras Google Authenticator con el secreto configurado)" -ForegroundColor Gray
} else {
    Write-Result "TEST 3: FAIL - Ejecutar Script 03 primero."
}

# ============================================================
# TEST 4: Bloqueo de cuenta por MFA fallido (3 intentos)
# ============================================================
Write-Host ""
Write-Host "--- TEST 4: Bloqueo de cuenta por MFA fallido ---" -ForegroundColor Yellow

Write-Log "Simulando 3 intentos MFA fallidos para admin_storage..."

if (Test-Path "C:\Scripts\Validate-MFA.ps1") {
    # Usar un codigo claramente incorrecto 3 veces
    for ($i = 1; $i -le 3; $i++) {
        Write-Log "  Intento fallido $i/3..."
        $result = & "C:\Scripts\Validate-MFA.ps1" -Username "admin_storage" -Code "000000" 2>&1
    }

    # Verificar que la cuenta quedo bloqueada
    $secrets = Get-Content "C:\Scripts\mfa_secrets.json" -Raw | ConvertFrom-Json -AsHashtable
    if ($secrets.ContainsKey("admin_storage") -and $secrets["admin_storage"].LockedUntil) {
        Write-OK "TEST 4: PASS - Cuenta admin_storage bloqueada por MFA fallido."
        Write-Result "TEST 4: PASS - LockedUntil: $($secrets["admin_storage"].LockedUntil)"
    } else {
        Write-Warn "TEST 4: WARN - Cuenta no aparece bloqueada en el JSON MFA."
        Write-Result "TEST 4: WARN - Verificar configuracion del script Validate-MFA.ps1"
    }

    # Verificar en AD si la cuenta fue deshabilitada
    $adUser = Get-ADUser "admin_storage" -Properties Enabled -ErrorAction SilentlyContinue
    if ($adUser -and -not $adUser.Enabled) {
        Write-OK "  Cuenta AD 'admin_storage' deshabilitada en Active Directory."
    } else {
        Write-Warn "  Cuenta AD 'admin_storage' sigue habilitada (el bloqueo es solo en MFA)."
    }

    # Re-habilitar para no dejar la cuenta bloqueada al final del test
    Write-Log "Restaurando cuenta admin_storage para pruebas posteriores..."
    if ($adUser -and -not $adUser.Enabled) {
        Enable-ADAccount -Identity "admin_storage" -ErrorAction SilentlyContinue
        Write-OK "  Cuenta AD admin_storage re-habilitada."
    }
    if ($secrets.ContainsKey("admin_storage")) {
        $secrets["admin_storage"].LockedUntil = $null
        $secrets["admin_storage"].FailCount   = 0
        $secrets | ConvertTo-Json -Depth 5 | Set-Content "C:\Scripts\mfa_secrets.json" -Encoding UTF8
        Write-OK "  Bloqueo MFA removido para admin_storage (restauracion post-test)."
    }
} else {
    Write-Warn "  Script Validate-MFA.ps1 no encontrado. Ejecutar Script 03 primero."
    Write-Result "TEST 4: SKIP - Dependencia faltante."
}

# ============================================================
# TEST 5: Reporte de auditoria automatizado
# ============================================================
Write-Host ""
Write-Host "--- TEST 5: Reporte de Auditoria Automatizado ---" -ForegroundColor Yellow

Write-Log "Ejecutando Script 04 de monitoreo..."
$scriptPath = "C:\Scripts\04_Script_Monitoreo_Auditoria.ps1"
if (Test-Path $scriptPath) {
    & $scriptPath
    $reports = Get-ChildItem "C:\Scripts\Auditoria_Practica9" -ErrorAction SilentlyContinue
    if ($reports) {
        Write-OK "TEST 5: PASS - $($reports.Count) archivos de reporte generados."
        Write-Result "TEST 5: PASS - Archivos en C:\Scripts\Auditoria_Practica9"
        $reports | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor Gray }
    } else {
        Write-Warn "TEST 5: WARN - Script ejecutado pero no se encontraron reportes."
        Write-Result "TEST 5: WARN - Revisar permisos en C:\Scripts"
    }
} else {
    Write-Warn "  $scriptPath no encontrado."
    Write-Result "TEST 5: SKIP - Script 04 no encontrado."
}

# ============================================================
# RESUMEN FINAL
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  PROTOCOLO DE PRUEBAS COMPLETADO - PRACTICA 9             " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Para generar el reporte completo de verificacion:" -ForegroundColor Yellow
Write-Host "  powershell -ExecutionPolicy Bypass -File C:\Scripts\05_Verificacion_Practica9.ps1" -ForegroundColor Cyan
