# ============================================================
# PRACTICA 8 - Script Principal
# Windows Server 2022 Core
# Ejecutar como Administrador en PowerShell
# ============================================================
# PASO 0: Instalar AD DS y promover el servidor a controlador de dominio
# Ejecuta esto PRIMERO si el servidor aun no es DC
# ============================================================

param(
    [string]$DomainName    = "practica8.local",
    [string]$NetbiosName   = "PRACTICA8",
    [string]$SafeModePass  = "P@ssw0rd123",
    [string]$CsvPath       = "C:\Scripts\usuarios.csv",
    [string]$ShareRoot     = "C:\Perfiles"
)

# ----------------------------------------------------------
# FUNCION: Escribir mensajes con color
# ----------------------------------------------------------
function Write-Log {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "[INFO] $Msg" -ForegroundColor $Color
}

# ============================================================
# BLOQUE 1: Instalar roles necesarios
# ============================================================
Write-Log "Instalando roles: AD-Domain-Services, RSAT-AD-PowerShell, FS-Resource-Manager..."

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop
Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools -ErrorAction Stop
Install-WindowsFeature -Name AppLocker -ErrorAction SilentlyContinue

Write-Log "Roles instalados correctamente." "Green"

# ============================================================
# BLOQUE 2: Promover el servidor a DC (solo si aun no lo es)
# ============================================================
$IsDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

if (-not $IsDC) {
    Write-Log "Promoviendo servidor a Controlador de Dominio para $DomainName ..."

    $SecurePass = ConvertTo-SecureString $SafeModePass -AsPlainText -Force

    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -SafeModeAdministratorPassword $SecurePass `
        -InstallDns:$true `
        -Force:$true `
        -NoRebootOnCompletion:$false

    Write-Log "El servidor se reiniciara. Ejecuta este script de nuevo tras el reinicio." "Yellow"
    exit
}

Write-Log "El servidor ya es DC. Continuando configuracion..." "Green"

# Importar modulo de AD
Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName   # ej. DC=practica8,DC=local

# ============================================================
# BLOQUE 3: Crear Unidades Organizativas
# ============================================================
Write-Log "Creando Unidades Organizativas Cuates y NoCuates..."

foreach ($OU in @("Cuates","NoCuates")) {
    $OUPath = "OU=$OU,$DomainDN"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $OU -Path $DomainDN -ProtectedFromAccidentalDeletion $false
        Write-Log "OU '$OU' creada." "Green"
    } else {
        Write-Log "OU '$OU' ya existe." "Yellow"
    }
}

# ============================================================
# BLOQUE 4: Crear Grupos de Seguridad
# ============================================================
Write-Log "Creando grupos de seguridad Cuates y NoCuates..."

foreach ($Grupo in @("Cuates","NoCuates")) {
    $OUPath = "OU=$Grupo,$DomainDN"
    if (-not (Get-ADGroup -Filter "Name -eq '$Grupo'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $Grupo -GroupScope Global -GroupCategory Security -Path $OUPath
        Write-Log "Grupo '$Grupo' creado." "Green"
    }
}

# ============================================================
# BLOQUE 5: Crear carpeta raiz de perfiles y compartirla
# ============================================================
Write-Log "Configurando carpeta raiz de perfiles en $ShareRoot ..."

if (-not (Test-Path $ShareRoot)) {
    New-Item -ItemType Directory -Path $ShareRoot | Out-Null
}

# Compartir solo si no esta compartida
if (-not (Get-SmbShare -Name "Perfiles" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "Perfiles" -Path $ShareRoot -FullAccess "Authenticated Users"
    Write-Log "Carpeta compartida como \\<servidor>\Perfiles" "Green"
}

# ============================================================
# BLOQUE 6: Leer CSV y crear usuarios
# ============================================================
Write-Log "Leyendo CSV desde $CsvPath ..."

if (-not (Test-Path $CsvPath)) {
    Write-Log "ERROR: No se encontro el archivo CSV en $CsvPath" "Red"
    exit 1
}

$Usuarios = Import-Csv -Path $CsvPath

foreach ($U in $Usuarios) {
    $UPN        = "$($U.Usuario)@$DomainName"
    $SecPass    = ConvertTo-SecureString $U.Contrasena -AsPlainText -Force
    $OUPath     = "OU=$($U.Departamento),$DomainDN"
    $HomePath   = "$ShareRoot\$($U.Usuario)"

    # Crear carpeta personal
    if (-not (Test-Path $HomePath)) {
        New-Item -ItemType Directory -Path $HomePath | Out-Null
        # Dar permisos al usuario sobre su carpeta
        $Acl  = Get-Acl $HomePath
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $UPN, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.SetAccessRule($Rule)
        Set-Acl -Path $HomePath -AclObject $Acl
    }

    # Crear usuario en AD si no existe
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($U.Usuario)'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name               "$($U.Nombre) $($U.Apellido)" `
            -GivenName          $U.Nombre `
            -Surname            $U.Apellido `
            -SamAccountName     $U.Usuario `
            -UserPrincipalName  $UPN `
            -AccountPassword    $SecPass `
            -Enabled            $true `
            -Path               $OUPath `
            -HomeDirectory      "\\$env:COMPUTERNAME\Perfiles\$($U.Usuario)" `
            -HomeDrive          "H:"

        Write-Log "Usuario '$($U.Usuario)' creado en OU $($U.Departamento)." "Green"
    } else {
        Write-Log "Usuario '$($U.Usuario)' ya existe. Actualizando OU..." "Yellow"
        Move-ADObject -Identity (Get-ADUser $U.Usuario).DistinguishedName -TargetPath $OUPath -ErrorAction SilentlyContinue
    }

    # Agregar al grupo correspondiente
    Add-ADGroupMember -Identity $U.Departamento -Members $U.Usuario -ErrorAction SilentlyContinue
}

Write-Log "Usuarios creados y asignados a sus grupos." "Green"

# ============================================================
# BLOQUE 7: Configurar Logon Hours
# ============================================================
# Active Directory usa un arreglo de 21 bytes (168 bits = horas de la semana)
# Bit 0 = Domingo 00:00, bit 1 = Domingo 01:00, etc.
# El servidor almacena en UTC; si tu zona es UTC-6, suma 6 horas

Write-Log "Configurando horarios de inicio de sesion (Logon Hours)..."

# Funcion que crea el arreglo de bytes para un rango de horas
# $StartHour y $EndHour en formato 24h local; se convierte a UTC-6 -> UTC sumando 6
function New-LogonHoursArray {
    param(
        [int]$StartHour,   # hora inicio local (0-23)
        [int]$EndHour,     # hora fin local (0-23), si EndHour < StartHour cruza medianoche
        [int]$UTCOffset = 6  # offset positivo = zona oeste (UTC-6 -> sumar 6)
    )
    $bytes = New-Object byte[] 21
    # Iterar los 7 dias
    for ($dia = 0; $dia -lt 7; $dia++) {
        for ($hora = 0; $hora -lt 24; $hora++) {
            # Determinar si la hora esta en el rango permitido
            $permitido = $false
            if ($StartHour -le $EndHour) {
                $permitido = ($hora -ge $StartHour -and $hora -lt $EndHour)
            } else {
                # Rango cruza medianoche
                $permitido = ($hora -ge $StartHour -or $hora -lt $EndHour)
            }
            if ($permitido) {
                # Convertir a UTC
                $horaUTC = ($hora + $UTCOffset) % 24
                $diaUTC  = $dia
                if (($hora + $UTCOffset) -ge 24) { $diaUTC = ($dia + 1) % 7 }
                $bitPos  = $diaUTC * 24 + $horaUTC
                $byteIdx = [math]::Floor($bitPos / 8)
                $bitIdx  = $bitPos % 8
                $bytes[$byteIdx] = $bytes[$byteIdx] -bor (1 -shl $bitIdx)
            }
        }
    }
    return $bytes
}

# Cuates: 08:00 - 15:00 (local)
$HoraCuates   = New-LogonHoursArray -StartHour 8 -EndHour 15
# NoCuates: 15:00 - 02:00 (cruza medianoche)
$HoraNoCuates = New-LogonHoursArray -StartHour 15 -EndHour 2

# Aplicar a todos los usuarios del grupo Cuates
$MiembrosCuates = Get-ADGroupMember -Identity "Cuates" -Recursive
foreach ($M in $MiembrosCuates) {
    Set-ADUser -Identity $M.SamAccountName -LogonHours $HoraCuates
    Write-Log "  Horario Cuates aplicado a $($M.SamAccountName)" "Green"
}

# Aplicar a todos los usuarios del grupo NoCuates
$MiembrosNoCuates = Get-ADGroupMember -Identity "NoCuates" -Recursive
foreach ($M in $MiembrosNoCuates) {
    Set-ADUser -Identity $M.SamAccountName -LogonHours $HoraNoCuates
    Write-Log "  Horario NoCuates aplicado a $($M.SamAccountName)" "Green"
}

Write-Log "Horarios configurados." "Green"

# ============================================================
# BLOQUE 8: GPO - Forzar cierre de sesion al expirar logon hours
# ============================================================
Write-Log "Creando GPO para forzar cierre de sesion al expirar horario..."

$GPOName = "ForzarLogoff_AlExpirar"

if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
    $GPO = New-GPO -Name $GPOName
    Write-Log "GPO '$GPOName' creada." "Green"
} else {
    $GPO = Get-GPO -Name $GPOName
    Write-Log "GPO '$GPOName' ya existe." "Yellow"
}

# Configurar la politica "Network security: Force logoff when logon hours expire"
# GUID del nodo de seguridad de cuenta
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -ValueName "EnableForcedLogOff" `
    -Type DWord `
    -Value 1

# Vincular GPO al dominio completo
$DomainGPOPath = $DomainDN -replace "DC=","" -replace ",","."
New-GPLink -Name $GPOName -Target $DomainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Log "GPO vinculada al dominio." "Green"

Write-Log "=== BLOQUE AD completado. Continua con el script 02_FSRM.ps1 ===" "Magenta"
