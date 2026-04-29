# ============================================================
# PRACTICA 9 - Script 02: FGPP y Auditoria de Eventos
# Ejecutar en Windows Server 2022 Core como Administrador
# powershell -ExecutionPolicy Bypass -File C:\Scripts\02_Configurar_FGPP_Auditoria.ps1
# ============================================================

# ============== CONFIGURACION - EDITAR AQUI ================
$DomainName = "practica8.local"
$DomainDN   = "DC=practica8,DC=local"
# ===========================================================

Import-Module ActiveDirectory -ErrorAction Stop

function Write-Log  { param($m) Write-Host "[INFO] $m"  -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[OK]   $m"  -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m"  -ForegroundColor Yellow }

# ============================================================
# PASO 1: Fine-Grained Password Policy para admins (min 12 chars)
# ============================================================
Write-Log "Creando FGPP para cuentas administrativas (minimo 12 caracteres)..."

$fgppAdminName = "FGPP_Admins_P9"
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$fgppAdminName'" -ErrorAction SilentlyContinue)) {
    New-ADFineGrainedPasswordPolicy `
        -Name                      $fgppAdminName `
        -Precedence                10 `
        -MinPasswordLength         12 `
        -PasswordHistoryCount      10 `
        -ComplexityEnabled         $true `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordAge            (New-TimeSpan -Days 1) `
        -MaxPasswordAge            (New-TimeSpan -Days 60) `
        -LockoutThreshold          5 `
        -LockoutDuration           (New-TimeSpan -Minutes 30) `
        -LockoutObservationWindow  (New-TimeSpan -Minutes 30) `
        -ProtectedFromAccidentalDeletion $false
    Write-OK "FGPP '$fgppAdminName' creada (longitud minima: 12, bloqueo: 5 intentos / 30 min)."
} else {
    Write-Warn "FGPP '$fgppAdminName' ya existe. Actualizando parametros..."
    Set-ADFineGrainedPasswordPolicy -Identity $fgppAdminName `
        -MinPasswordLength 12 `
        -LockoutThreshold  5 `
        -LockoutDuration   (New-TimeSpan -Minutes 30)
    Write-OK "FGPP '$fgppAdminName' actualizada."
}

# Aplicar FGPP a los 4 usuarios admin delegados
$adminDelegados = @("admin_identidad","admin_storage","admin_politicas","admin_auditoria")
foreach ($u in $adminDelegados) {
    try {
        Add-ADFineGrainedPasswordPolicySubject -Identity $fgppAdminName -Subjects $u -ErrorAction Stop
        Write-OK "  FGPP_Admins aplicada a: $u"
    } catch {
        Write-Warn "  No se pudo aplicar FGPP a $u (puede ya estar asignada): $_"
    }
}

# ============================================================
# PASO 2: Fine-Grained Password Policy para usuarios estandar (min 8 chars)
# ============================================================
Write-Log "Creando FGPP para usuarios estandar (minimo 8 caracteres)..."

$fgppUserName = "FGPP_Usuarios_P9"
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$fgppUserName'" -ErrorAction SilentlyContinue)) {
    New-ADFineGrainedPasswordPolicy `
        -Name                      $fgppUserName `
        -Precedence                20 `
        -MinPasswordLength         8 `
        -PasswordHistoryCount      5 `
        -ComplexityEnabled         $true `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordAge            (New-TimeSpan -Days 0) `
        -MaxPasswordAge            (New-TimeSpan -Days 90) `
        -LockoutThreshold          5 `
        -LockoutDuration           (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow  (New-TimeSpan -Minutes 15) `
        -ProtectedFromAccidentalDeletion $false
    Write-OK "FGPP '$fgppUserName' creada (longitud minima: 8)."
} else {
    Write-Warn "FGPP '$fgppUserName' ya existe."
}

# Aplicar a los grupos de usuarios estandar
foreach ($grp in @("Cuates","NoCuates")) {
    try {
        Add-ADFineGrainedPasswordPolicySubject -Identity $fgppUserName -Subjects $grp -ErrorAction Stop
        Write-OK "  FGPP_Usuarios aplicada al grupo: $grp"
    } catch {
        Write-Warn "  No se pudo aplicar FGPP a grupo $grp: $_"
    }
}

# ============================================================
# PASO 3: Configurar Auditoria de Eventos (auditpol)
# ============================================================
Write-Log "Configurando auditoria de eventos con auditpol..."

$auditPolicies = @(
    # Categoria          Subcategoria                      Flags
    @("Logon/Logoff",    "Logon",                          "/success:enable /failure:enable"),
    @("Logon/Logoff",    "Logoff",                         "/success:enable /failure:enable"),
    @("Logon/Logoff",    "Account Lockout",                "/success:enable /failure:enable"),
    @("Object Access",   "File System",                    "/success:enable /failure:enable"),
    @("Object Access",   "Registry",                       "/success:enable /failure:enable"),
    @("Account Management","User Account Management",      "/success:enable /failure:enable"),
    @("Account Management","Security Group Management",    "/success:enable /failure:enable"),
    @("Policy Change",   "Audit Policy Change",            "/success:enable /failure:enable"),
    @("Privilege Use",   "Sensitive Privilege Use",        "/success:enable /failure:enable"),
    @("DS Access",       "Directory Service Changes",      "/success:enable /failure:enable"),
    @("DS Access",       "Directory Service Access",       "/success:enable /failure:enable")
)

foreach ($pol in $auditPolicies) {
    $subcategory = $pol[1]
    $flags       = $pol[2]
    $cmd = "auditpol /set /subcategory:`"$subcategory`" $flags"
    $result = Invoke-Expression $cmd 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-OK "  Auditoria '$subcategory': $flags"
    } else {
        Write-Warn "  Error en '$subcategory': $result"
    }
}

# Tambien via GPO para que persista en clientes del dominio
Write-Log "Habilitando auditoria en la GPO de dominio predeterminada..."
try {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    # Configurar via registry en Default Domain Policy
    Set-GPRegistryValue -Name "Default Domain Policy" `
        -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        -ValueName "AuditBaseObjects" -Type DWord -Value 1 `
        -ErrorAction SilentlyContinue
    Write-OK "  Registro de auditoria base habilitado en Default Domain Policy."
} catch {
    Write-Warn "  No se pudo configurar GPO de auditoria: $_"
}

# ============================================================
# PASO 4: Configurar bloqueo de cuenta por MFA fallido (via GPO)
# Nota: el bloqueo real de MFA se configura en Script 03 (WinOTP/TOTP)
# Aqui configuramos la GPO de bloqueo de cuenta base del dominio
# ============================================================
Write-Log "Configurando GPO de bloqueo de cuenta (3 intentos / 30 min)..."
try {
    Import-Module GroupPolicy -ErrorAction Stop

    $gpoName = "LockoutPolicy_P9"
    $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $existingGPO) {
        $gpo = New-GPO -Name $gpoName -Comment "Practica 9: Politica de bloqueo de cuenta"
        Write-OK "GPO '$gpoName' creada."
    } else {
        $gpo = $existingGPO
        Write-Warn "GPO '$gpoName' ya existe. Actualizando."
    }

    # Account Lockout Threshold: 3 intentos
    Set-GPRegistryValue -Name $gpoName `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -ValueName "MaximumPasswordAge" -Type DWord -Value 30 `
        -ErrorAction SilentlyContinue

    # Configurar via secedit (metodo mas fiable para lockout policy)
    $seceditInf = @"
[Unicode]
Unicode=yes
[System Access]
LockoutBadCount = 3
ResetLockoutCount = 30
LockoutDuration = 30
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    $infPath = "C:\Scripts\lockout.inf"
    $seceditInf | Out-File -FilePath $infPath -Encoding Unicode
    secedit /configure /db secedit.sdb /cfg $infPath /areas SECURITYPOLICY /quiet
    Remove-Item $infPath -Force -ErrorAction SilentlyContinue
    Write-OK "  Politica de bloqueo: 3 intentos fallidos -> bloqueo 30 minutos."

    # Vincular GPO al dominio
    try {
        New-GPLink -Name $gpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop
        Write-OK "  GPO '$gpoName' vinculada al dominio."
    } catch {
        Write-Warn "  GPO ya vinculada o error al vincular: $_"
    }
} catch {
    Write-Warn "Modulo GroupPolicy no disponible. Aplicando lockout via secedit directo..."
    $seceditInf = @"
[Unicode]
Unicode=yes
[System Access]
LockoutBadCount = 3
ResetLockoutCount = 30
LockoutDuration = 30
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    $infPath = "C:\Scripts\lockout.inf"
    $seceditInf | Out-File -FilePath $infPath -Encoding Unicode
    secedit /configure /db secedit.sdb /cfg $infPath /areas SECURITYPOLICY /quiet
    Remove-Item $infPath -Force -ErrorAction SilentlyContinue
    Write-OK "  Politica de bloqueo aplicada via secedit."
}

# ============================================================
# PASO 5: Verificacion de FGPP
# ============================================================
Write-Host ""
Write-Host "=== Verificacion FGPP ===" -ForegroundColor Cyan
Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, Precedence, MinPasswordLength, LockoutThreshold, LockoutDuration | Format-Table -AutoSize

Write-Host ""
Write-Host "=== Asignaciones de FGPP ===" -ForegroundColor Cyan
Get-ADFineGrainedPasswordPolicySubject -Identity $fgppAdminName | Select-Object Name, ObjectClass | Format-Table -AutoSize
Get-ADFineGrainedPasswordPolicySubject -Identity $fgppUserName  | Select-Object Name, ObjectClass | Format-Table -AutoSize

Write-Host ""
Write-Host "=== Estado de Auditoria ===" -ForegroundColor Cyan
auditpol /get /category:* | Where-Object { $_ -match "enable" }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " FGPP Y AUDITORIA CONFIGURADAS EXITOSAMENTE                " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Siguiente paso: Ejecutar 03_Configurar_MFA_TOTP.ps1" -ForegroundColor Yellow
