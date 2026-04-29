# ============================================================
# PRACTICA 9 - Script 01: Delegacion RBAC y Usuarios Admin
# Ejecutar en Windows Server 2022 Core como Administrador
# powershell -ExecutionPolicy Bypass -File C:\Scripts\01_Configurar_Delegacion_RBAC.ps1
# ============================================================

# ============== CONFIGURACION - EDITAR AQUI ================
$DomainName    = "practica8.local"
$DomainDN      = "DC=practica8,DC=local"
$OUCuates      = "OU=Cuates,$DomainDN"
$OUNoCuates    = "OU=NoCuates,$DomainDN"
$AdminPass     = ConvertTo-SecureString "Admin@Practica9!" -AsPlainText -Force
# ===========================================================

Import-Module ActiveDirectory -ErrorAction Stop

function Write-Log  { param($m) Write-Host "[INFO] $m"  -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[OK]   $m"  -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m"  -ForegroundColor Yellow }

# ============================================================
# PASO 1: Crear OU de Administracion Delegada
# ============================================================
Write-Log "Creando OU=AdminDelegados..."
$ouAdmin = "OU=AdminDelegados,$DomainDN"
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouAdmin'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "AdminDelegados" -Path $DomainDN -ProtectedFromAccidentalDeletion $false
    Write-OK "OU=AdminDelegados creada."
} else {
    Write-Warn "OU=AdminDelegados ya existe."
}

# ============================================================
# PASO 2: Crear los 4 usuarios de administracion delegada
# ============================================================
$adminUsers = @(
    @{ Sam = "admin_identidad"; Display = "IAM Operator";             Desc = "Rol 1: Operador de Identidad y Acceso" },
    @{ Sam = "admin_storage";   Display = "Storage Operator";         Desc = "Rol 2: Operador de Almacenamiento" },
    @{ Sam = "admin_politicas"; Display = "GPO Compliance Admin";     Desc = "Rol 3: Admin de Cumplimiento y Directivas" },
    @{ Sam = "admin_auditoria"; Display = "Security Auditor";         Desc = "Rol 4: Auditor de Seguridad y Eventos" }
)

foreach ($u in $adminUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -SamAccountName   $u.Sam `
            -UserPrincipalName "$($u.Sam)@$DomainName" `
            -Name              $u.Display `
            -DisplayName       $u.Display `
            -Description       $u.Desc `
            -Path              $ouAdmin `
            -AccountPassword   $AdminPass `
            -PasswordNeverExpires $true `
            -Enabled           $true
        Write-OK "Usuario creado: $($u.Sam)"
    } else {
        Write-Warn "Usuario ya existe: $($u.Sam)"
    }
}

# ============================================================
# PASO 3: Crear grupo para auditores (Event Log Readers)
# ============================================================
Write-Log "Agregando admin_auditoria al grupo 'Event Log Readers'..."
try {
    Add-ADGroupMember -Identity "Event Log Readers" -Members "admin_auditoria" -ErrorAction Stop
    Write-OK "admin_auditoria agregado a Event Log Readers."
} catch {
    Write-Warn "No se pudo agregar al grupo Event Log Readers: $_"
}

# ============================================================
# PASO 4: ROL 1 - admin_identidad: Delegacion en OU Cuates y NoCuates
# Permisos: Create/Delete User, Reset Password, Write basic attributes
# ============================================================
Write-Log "Configurando delegacion ROL 1 (admin_identidad) en OU Cuates y NoCuates..."

$identidadSID = (Get-ADUser "admin_identidad").SID.Value

foreach ($ou in @($OUCuates, $OUNoCuates)) {
    $ouShort = ($ou -split ",")[0] -replace "OU=",""
    Write-Log "  -> Delegando en OU=$ouShort"

    # Crear usuario
    dsacls $ou /G "${identidadSID}:CCDC;user" | Out-Null
    # Borrar usuario
    dsacls $ou /G "${identidadSID}:DCDT;user" | Out-Null
    # Reset Password
    dsacls $ou /G "${identidadSID}:CA;Reset Password;user" | Out-Null
    # Desbloqueo de cuenta (lockoutTime write)
    dsacls $ou /G "${identidadSID}:WP;lockoutTime;user" | Out-Null
    # Atributos basicos: telefono, oficina, correo
    dsacls $ou /G "${identidadSID}:WP;telephoneNumber;user" | Out-Null
    dsacls $ou /G "${identidadSID}:WP;physicalDeliveryOfficeName;user" | Out-Null
    dsacls $ou /G "${identidadSID}:WP;mail;user" | Out-Null
    # pwdLastSet (forzar cambio de contrasena en proximo inicio)
    dsacls $ou /G "${identidadSID}:WP;pwdLastSet;user" | Out-Null

    Write-OK "  Delegacion ROL 1 aplicada en OU=$ouShort"
}

# ============================================================
# PASO 5: ROL 2 - admin_storage: Solo FSRM (sin permisos AD)
# Restriccion: Denegar Reset Password explicitamente en todo el dominio
# ============================================================
Write-Log "Configurando restriccion ROL 2 (admin_storage) - DENEGAR Reset Password..."

$storageSID = (Get-ADUser "admin_storage").SID.Value

# Agregar admin_storage al grupo local de FSRM (para gestion de cuotas via WMI)
# Se hace via GPO o directamente en el servidor (Script 02 lo complementa)

# Denegar Reset Password en las OUs de usuarios
foreach ($ou in @($OUCuates, $OUNoCuates)) {
    $ouShort = ($ou -split ",")[0] -replace "OU=",""
    # DENY Reset Password
    dsacls $ou /D "${storageSID}:CA;Reset Password;user" | Out-Null
    Write-OK "  DENY Reset Password aplicado para admin_storage en OU=$ouShort"
}

# ============================================================
# PASO 6: ROL 3 - admin_politicas: Lectura en dominio + Escritura en GPOs
# ============================================================
Write-Log "Configurando delegacion ROL 3 (admin_politicas)..."

$politicasSID = (Get-ADUser "admin_politicas").SID.Value

# Lectura general en el dominio
dsacls $DomainDN /G "${politicasSID}:GR" | Out-Null
Write-OK "  Permiso de Lectura General concedido en el dominio a admin_politicas"

# Delegar gestion de GPOs (Link/Unlink) en las OUs
foreach ($ou in @($OUCuates, $OUNoCuates, $DomainDN)) {
    $ouLabel = ($ou -split ",")[0]
    # GP-Link (vincular/desvincular GPOs)
    dsacls $ou /G "${politicasSID}:WP;gPLink" | Out-Null
    dsacls $ou /G "${politicasSID}:WP;gPOptions" | Out-Null
    Write-OK "  Permisos gPLink/gPOptions para admin_politicas en $ouLabel"
}

# Delegar escritura en el contenedor de Group Policy Objects
$gpContainerDN = "CN=Policies,CN=System,$DomainDN"
try {
    dsacls $gpContainerDN /G "${politicasSID}:CCDC;groupPolicyContainer" | Out-Null
    dsacls $gpContainerDN /G "${politicasSID}:WD;groupPolicyContainer"   | Out-Null
    Write-OK "  Permisos sobre GPO Container concedidos a admin_politicas"
} catch {
    Write-Warn "  No se pudo configurar permisos en CN=Policies: $_"
}

# ============================================================
# PASO 7: ROL 4 - admin_auditoria: Solo lectura en todo el dominio
# ============================================================
Write-Log "Configurando delegacion ROL 4 (admin_auditoria) - Solo lectura..."

$auditoriaSID = (Get-ADUser "admin_auditoria").SID.Value

# Lectura en todo el dominio
dsacls $DomainDN /G "${auditoriaSID}:GR" | Out-Null
Write-OK "  Permiso de Lectura General concedido en el dominio a admin_auditoria"

# Asegurar que NO tenga permisos de escritura en ninguna OU
foreach ($ou in @($OUCuates, $OUNoCuates)) {
    $ouShort = ($ou -split ",")[0] -replace "OU=",""
    dsacls $ou /D "${auditoriaSID}:GW" | Out-Null
    Write-OK "  DENY Write aplicado para admin_auditoria en OU=$ouShort"
}

# ============================================================
# PASO 8: Resumen de delegaciones
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " DELEGACION RBAC CONFIGURADA EXITOSAMENTE                  " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "ROL 1 admin_identidad : Crear/Eliminar/Modificar usuarios en Cuates y NoCuates" -ForegroundColor White
Write-Host "ROL 2 admin_storage   : DENEGADO Reset Password en todas las OUs de usuarios"   -ForegroundColor White
Write-Host "ROL 3 admin_politicas : Lectura global + Escritura en GPOs y gPLink"            -ForegroundColor White
Write-Host "ROL 4 admin_auditoria : Lectura global solamente (Event Log Readers)"           -ForegroundColor White
Write-Host ""
Write-Host "Siguiente paso: Ejecutar 02_Configurar_FGPP_Auditoria.ps1"  -ForegroundColor Yellow
