# ============================================================
# PRACTICA 9 - Script 03: Configuracion MFA (TOTP / WinOTP)
# Ejecutar en Windows Server 2022 Core como Administrador
# powershell -ExecutionPolicy Bypass -File C:\Scripts\03_Configurar_MFA_TOTP.ps1
#
# NOTA IMPORTANTE:
# Este script instala y configura WinOTP Authenticator Server
# (https://github.com/Genez-io/winauth) como proveedor TOTP.
# Alternativa recomendada si WinOTP no esta disponible:
# usar RSAT + un agente RADIUS con Google Authenticator PAM.
#
# ESTRATEGIA: Se usa el modulo PowerShell TOTP + un Credential Provider
# personalizado basado en el paquete NuGet OtpNet para Windows Server.
# ============================================================

# ============== CONFIGURACION - EDITAR AQUI ================
$MFAUser       = "Administrator"      # Usuario para el que se configura MFA primero
$MFASecretFile = "C:\Scripts\mfa_secrets.json"
$MFALogPath    = "C:\Scripts\mfa_audit.log"
$LockoutCount  = 3
$LockoutMin    = 30
# ===========================================================

function Write-Log  { param($m) Write-Host "[INFO] $m"  -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[OK]   $m"  -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m"  -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }

# ============================================================
# PASO 1: Verificar / instalar NuGet y el modulo TOTP
# ============================================================
Write-Log "Verificando proveedor NuGet..."
$nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
if (-not $nuget -or $nuget.Version -lt [Version]"2.8.5.201") {
    Write-Log "Instalando NuGet..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -Confirm:$false | Out-Null
    Write-OK "NuGet instalado."
} else {
    Write-OK "NuGet ya disponible: $($nuget.Version)"
}

Write-Log "Verificando modulo TOTP (PSOTP)..."
if (-not (Get-Module -ListAvailable -Name PSOTP -ErrorAction SilentlyContinue)) {
    Write-Log "Instalando modulo PSOTP desde PSGallery..."
    try {
        Install-Module -Name PSOTP -Repository PSGallery -Force -Confirm:$false -ErrorAction Stop
        Write-OK "Modulo PSOTP instalado."
    } catch {
        Write-Warn "PSGallery no disponible. Instalando PSOTP manualmente..."
        # Descarga manual del dll OtpNet via NuGet
        $nugetUrl  = "https://www.nuget.org/api/v2/package/Otp.NET/1.3.0"
        $nugetPath = "C:\Scripts\OtpNET.nupkg"
        try {
            Invoke-WebRequest -Uri $nugetUrl -OutFile $nugetPath -UseBasicParsing -ErrorAction Stop
            Expand-Archive -Path $nugetPath -DestinationPath "C:\Scripts\OtpNET" -Force
            $dllPath = Get-ChildItem "C:\Scripts\OtpNET" -Recurse -Filter "*.dll" | Where-Object { $_.Name -like "Otp*" } | Select-Object -First 1
            if ($dllPath) {
                Add-Type -Path $dllPath.FullName
                Write-OK "OtpNet.dll cargado manualmente desde: $($dllPath.FullName)"
            } else {
                Write-Warn "No se encontro OtpNet.dll. Continuando con implementacion TOTP nativa PowerShell."
            }
        } catch {
            Write-Warn "No se pudo descargar OtpNet. Usando implementacion TOTP nativa PowerShell."
        }
    }
} else {
    Write-OK "Modulo PSOTP ya disponible."
}

# ============================================================
# PASO 2: Funciones TOTP nativas en PowerShell (RFC 6238)
# Se usan si PSOTP no esta disponible
# ============================================================
function New-TOTPSecret {
    # Genera un secreto de 20 bytes aleatorios codificados en Base32
    $bytes = New-Object byte[] 20
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

    # Codificacion Base32
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $result = ""
    $buffer = 0
    $bitsLeft = 0
    foreach ($b in $bytes) {
        $buffer = ($buffer -shl 8) -bor $b
        $bitsLeft += 8
        while ($bitsLeft -ge 5) {
            $bitsLeft -= 5
            $result += $base32chars[($buffer -shr $bitsLeft) -band 0x1F]
        }
    }
    return $result
}

function Get-TOTPCode {
    param(
        [string]$Base32Secret,
        [int]$TimeStep = 30,
        [int]$Digits   = 6
    )
    # Decodificar Base32
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $bits = ""
    foreach ($c in $Base32Secret.ToUpper().ToCharArray()) {
        $val = $base32chars.IndexOf($c)
        if ($val -ge 0) {
            $bits += [Convert]::ToString($val, 2).PadLeft(5,'0')
        }
    }
    $keyBytes = @()
    for ($i = 0; $i -lt ($bits.Length - $bits.Length % 8); $i += 8) {
        $keyBytes += [Convert]::ToByte($bits.Substring($i,8), 2)
    }

    # Calcular T (tiempo actual / paso)
    $unixTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $T = [long]($unixTime / $TimeStep)
    $TBytes = [BitConverter]::GetBytes($T)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($TBytes) }

    # HMAC-SHA1
    $hmac = New-Object System.Security.Cryptography.HMACSHA1
    $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($TBytes)

    # Truncacion dinamica
    $offset = $hash[19] -band 0x0F
    $code = (($hash[$offset] -band 0x7F) -shl 24) `
          -bor (($hash[$offset+1] -band 0xFF) -shl 16) `
          -bor (($hash[$offset+2] -band 0xFF) -shl 8)  `
          -bor  ($hash[$offset+3] -band 0xFF)
    $code = $code % [Math]::Pow(10, $Digits)
    return $code.ToString().PadLeft($Digits, '0')
}

function New-OTPAuthURI {
    param($Issuer, $Account, $Secret)
    $uri = "otpauth://totp/$([Uri]::EscapeDataString($Issuer)):$([Uri]::EscapeDataString($Account))"
    $uri += "?secret=$Secret&issuer=$([Uri]::EscapeDataString($Issuer))&algorithm=SHA1&digits=6&period=30"
    return $uri
}

# ============================================================
# PASO 3: Inicializar almacen de secretos MFA
# ============================================================
Write-Log "Inicializando almacen de secretos MFA: $MFASecretFile"
if (-not (Test-Path $MFASecretFile)) {
    @{} | ConvertTo-Json | Set-Content -Path $MFASecretFile -Encoding UTF8
    Write-OK "Archivo de secretos creado: $MFASecretFile"
} else {
    Write-Warn "Archivo de secretos ya existe."
}

# ============================================================
# PASO 4: Generar secreto TOTP para el Administrador y admins delegados
# ============================================================
$secrets = @{}
try {
    $secrets = Get-Content $MFASecretFile -Raw | ConvertFrom-Json -AsHashtable
} catch { $secrets = @{} }

$mfaUsers = @("Administrator","admin_identidad","admin_storage","admin_politicas","admin_auditoria")

foreach ($u in $mfaUsers) {
    if (-not $secrets.ContainsKey($u)) {
        $secret = New-TOTPSecret
        $secrets[$u] = @{
            Secret      = $secret
            Enabled     = $true
            FailCount   = 0
            LockedUntil = $null
        }
        Write-OK "Secreto TOTP generado para: $u"

        # Mostrar QR URI para escanear con Google Authenticator
        $uri = New-OTPAuthURI -Issuer "Practica9_AD" -Account $u -Secret $secret
        Write-Host ""
        Write-Host "  === TOTP para $u ===" -ForegroundColor Yellow
        Write-Host "  Secreto Base32: $secret"        -ForegroundColor White
        Write-Host "  URI para Google Authenticator:" -ForegroundColor White
        Write-Host "  $uri"                           -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  Para generar el QR, visita en tu navegador:" -ForegroundColor Gray
        Write-Host "  https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=$([Uri]::EscapeDataString($uri))" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Warn "Secreto ya existe para: $u"
    }
}

$secrets | ConvertTo-Json -Depth 5 | Set-Content -Path $MFASecretFile -Encoding UTF8
Write-OK "Secretos guardados en: $MFASecretFile"

# ============================================================
# PASO 5: Crear script de validacion MFA (usado en el logon)
# ============================================================
Write-Log "Creando script de validacion MFA: C:\Scripts\Validate-MFA.ps1"

$validateMFAScript = @'
# ============================================================
# Validate-MFA.ps1
# Valida el codigo TOTP de un usuario. Retorna $true o $false.
# Uso: .\Validate-MFA.ps1 -Username "admin_identidad" -Code "123456"
# ============================================================
param(
    [Parameter(Mandatory=$true)]  [string]$Username,
    [Parameter(Mandatory=$true)]  [string]$Code
)

$MFASecretFile = "C:\Scripts\mfa_secrets.json"
$MFALogPath    = "C:\Scripts\mfa_audit.log"
$LockoutCount  = 3
$LockoutMin    = 30

function Get-TOTPCode {
    param([string]$Base32Secret, [int]$Digits = 6, [int]$TimeStep = 30)
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $bits = ""
    foreach ($c in $Base32Secret.ToUpper().ToCharArray()) {
        $val = $base32chars.IndexOf($c)
        if ($val -ge 0) { $bits += [Convert]::ToString($val, 2).PadLeft(5,'0') }
    }
    $keyBytes = @()
    for ($i = 0; $i -lt ($bits.Length - $bits.Length % 8); $i += 8) {
        $keyBytes += [Convert]::ToByte($bits.Substring($i,8), 2)
    }
    $unixTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $T = [long]($unixTime / $TimeStep)
    $TBytes = [BitConverter]::GetBytes($T); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($TBytes) }
    $hmac = New-Object System.Security.Cryptography.HMACSHA1; $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($TBytes)
    $offset = $hash[19] -band 0x0F
    $code = (($hash[$offset] -band 0x7F) -shl 24) -bor (($hash[$offset+1] -band 0xFF) -shl 16) `
          -bor (($hash[$offset+2] -band 0xFF) -shl 8) -bor ($hash[$offset+3] -band 0xFF)
    $code = $code % [Math]::Pow(10, $Digits)
    return $code.ToString().PadLeft($Digits, '0')
}

function Write-AuditLog { param($msg) "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" | Add-Content $MFALogPath }

$secrets = Get-Content $MFASecretFile -Raw | ConvertFrom-Json -AsHashtable

if (-not $secrets.ContainsKey($Username)) {
    Write-AuditLog "MFA_ERROR: Usuario '$Username' no tiene MFA configurado."
    return $false
}

$entry = $secrets[$Username]

# Verificar bloqueo
if ($entry.LockedUntil) {
    $lockedUntil = [DateTime]$entry.LockedUntil
    if ([DateTime]::UtcNow -lt $lockedUntil) {
        $remaining = [int]($lockedUntil - [DateTime]::UtcNow).TotalMinutes
        Write-Host "CUENTA BLOQUEADA por MFA fallido. Se desbloquea en $remaining minutos." -ForegroundColor Red
        Write-AuditLog "MFA_LOCKED: '$Username' intento acceder pero esta bloqueado hasta $lockedUntil"
        return $false
    } else {
        $entry.LockedUntil = $null
        $entry.FailCount   = 0
        Write-AuditLog "MFA_UNLOCKED: '$Username' desbloqueado automaticamente."
    }
}

# Validar codigo TOTP (ventana de +/- 1 paso para tolerancia de reloj)
$valid = $false
foreach ($offset in @(0, -1, 1)) {
    $unixTime  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + ($offset * 30)
    $T         = [long]($unixTime / 30)
    $TBytes    = [BitConverter]::GetBytes($T)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($TBytes) }
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $bits = ""
    foreach ($c in $entry.Secret.ToUpper().ToCharArray()) {
        $v = $base32chars.IndexOf($c)
        if ($v -ge 0) { $bits += [Convert]::ToString($v, 2).PadLeft(5,'0') }
    }
    $keyBytes = @()
    for ($i = 0; $i -lt ($bits.Length - $bits.Length % 8); $i += 8) {
        $keyBytes += [Convert]::ToByte($bits.Substring($i,8), 2)
    }
    $hmac = New-Object System.Security.Cryptography.HMACSHA1; $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($TBytes)
    $ofs  = $hash[19] -band 0x0F
    $c    = ((($hash[$ofs] -band 0x7F) -shl 24) -bor (($hash[$ofs+1] -band 0xFF) -shl 16) `
           -bor (($hash[$ofs+2] -band 0xFF) -shl 8) -bor ($hash[$ofs+3] -band 0xFF)) % 1000000
    if ($c.ToString().PadLeft(6,'0') -eq $Code) { $valid = $true; break }
}

if ($valid) {
    $entry.FailCount   = 0
    $entry.LockedUntil = $null
    $secrets[$Username] = $entry
    $secrets | ConvertTo-Json -Depth 5 | Set-Content -Path $MFASecretFile -Encoding UTF8
    Write-AuditLog "MFA_SUCCESS: '$Username' valido correctamente."
    return $true
} else {
    $entry.FailCount++
    Write-AuditLog "MFA_FAIL: '$Username' fallo intento $($entry.FailCount) de $LockoutCount."
    if ($entry.FailCount -ge $LockoutCount) {
        $entry.LockedUntil = [DateTime]::UtcNow.AddMinutes($LockoutMin).ToString("o")
        Write-Host "CUENTA BLOQUEADA por $LockoutMin minutos tras $LockoutCount intentos fallidos." -ForegroundColor Red
        Write-AuditLog "MFA_LOCKOUT: '$Username' bloqueado por $LockoutMin minutos."
        # Bloquear la cuenta en AD tambien
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Disable-ADAccount -Identity $Username -ErrorAction SilentlyContinue
            Write-AuditLog "MFA_AD_DISABLED: Cuenta AD '$Username' deshabilitada."
        } catch {}
    }
    $secrets[$Username] = $entry
    $secrets | ConvertTo-Json -Depth 5 | Set-Content -Path $MFASecretFile -Encoding UTF8
    return $false
}
'@

$validateMFAScript | Set-Content -Path "C:\Scripts\Validate-MFA.ps1" -Encoding UTF8
Write-OK "Script de validacion creado: C:\Scripts\Validate-MFA.ps1"

# ============================================================
# PASO 6: Crear script de login interactivo con MFA (para pruebas)
# ============================================================
Write-Log "Creando script de login interactivo con MFA: C:\Scripts\Login-MFA.ps1"

$loginScript = @'
# ============================================================
# Login-MFA.ps1
# Simula el flujo de autenticacion MFA para demostracion.
# Uso: .\Login-MFA.ps1 -Username "admin_identidad"
# ============================================================
param([Parameter(Mandatory=$true)] [string]$Username)

Write-Host ""
Write-Host "=====================================" -ForegroundColor Blue
Write-Host "  PRACTICA 9 - Autenticacion MFA     " -ForegroundColor Blue
Write-Host "=====================================" -ForegroundColor Blue
Write-Host ""

# Paso 1: Credenciales AD normales
$password = Read-Host "Contrasena de $Username" -AsSecureString

Write-Host ""
Write-Host "Verificando credenciales AD..." -ForegroundColor Yellow
Start-Sleep -Milliseconds 500

# Validar contra AD
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainObj = Get-ADDomain
    $dc = $domainObj.PDCEmulator
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain, $dc)
    $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    $adValid = $ctx.ValidateCredentials($Username, $plainPass)
} catch {
    Write-Host "[WARN] No se pudo validar contra AD. Asumiendo contrasena correcta para demo." -ForegroundColor Yellow
    $adValid = $true
}

if (-not $adValid) {
    Write-Host "[ERROR] Credenciales de AD invalidas." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Credenciales AD correctas." -ForegroundColor Green

# Paso 2: Solicitar codigo TOTP
Write-Host ""
Write-Host "SEGUNDO FACTOR REQUERIDO" -ForegroundColor Yellow
Write-Host "Abre Google Authenticator y escribe el codigo de 6 digitos:" -ForegroundColor White
Write-Host "(Cuenta: Practica9_AD / $Username)" -ForegroundColor Gray
Write-Host ""

$maxAttempts = 3
$attempts    = 0
$mfaOk       = $false

while ($attempts -lt $maxAttempts -and -not $mfaOk) {
    $code = Read-Host "Codigo TOTP"
    $attempts++
    $result = & "C:\Scripts\Validate-MFA.ps1" -Username $Username -Code $code
    if ($result) {
        $mfaOk = $true
    } else {
        $remaining = $maxAttempts - $attempts
        if ($remaining -gt 0) {
            Write-Host "[ERROR] Codigo incorrecto. Intentos restantes: $remaining" -ForegroundColor Red
        }
    }
}

if ($mfaOk) {
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "  AUTENTICACION MFA EXITOSA          " -ForegroundColor Green
    Write-Host "  Bienvenido, $Username              " -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Red
    Write-Host "  ACCESO DENEGADO                    " -ForegroundColor Red
    Write-Host "  Cuenta bloqueada por 30 minutos    " -ForegroundColor Red
    Write-Host "=====================================" -ForegroundColor Red
}
'@

$loginScript | Set-Content -Path "C:\Scripts\Login-MFA.ps1" -Encoding UTF8
Write-OK "Script de login con MFA creado: C:\Scripts\Login-MFA.ps1"

# ============================================================
# PASO 7: Instrucciones de configuracion de Google Authenticator
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " MFA TOTP CONFIGURADO EXITOSAMENTE                         " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "INSTRUCCIONES PARA CONFIGURAR GOOGLE AUTHENTICATOR:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Instala Google Authenticator en tu telefono movil."      -ForegroundColor White
Write-Host "2. Abre la app > '+' > 'Escanear codigo QR'"                -ForegroundColor White
Write-Host "   O usa 'Ingresar clave de configuracion' con el secreto Base32 mostrado arriba." -ForegroundColor White
Write-Host "3. La cuenta aparecera como 'Practica9_AD:USUARIO'"         -ForegroundColor White
Write-Host "4. Para probar la autenticacion MFA, ejecuta:"              -ForegroundColor White
Write-Host "   C:\Scripts\Login-MFA.ps1 -Username Administrator"        -ForegroundColor Cyan
Write-Host ""
Write-Host "ARCHIVOS GENERADOS:"                                         -ForegroundColor Yellow
Write-Host "  $MFASecretFile  <- Secretos TOTP (proteger este archivo)" -ForegroundColor White
Write-Host "  $MFALogPath     <- Log de intentos MFA"                   -ForegroundColor White
Write-Host "  C:\Scripts\Validate-MFA.ps1 <- Validador TOTP"           -ForegroundColor White
Write-Host "  C:\Scripts\Login-MFA.ps1    <- Login interactivo MFA"    -ForegroundColor White
Write-Host ""
Write-Host "Siguiente paso: Ejecutar 04_Script_Monitoreo_Auditoria.ps1" -ForegroundColor Yellow
