# ============================================================
# PRACTICA 8 - Script 04: Union al Dominio (Cliente Windows 10)
# Ejecutar como Administrador en el cliente Windows 10
# ============================================================

param(
    [string]$DomainName    = "practica8.local",
    [string]$DCIpAddress   = "192.168.10.10",    # <-- IP de tu Windows Server
    [string]$DomainUser    = "PRACTICA8\Administrator",
    [string]$DomainPass    = "P@ssw0rd123"
)

function Write-Log {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "[Win10] $Msg" -ForegroundColor $Color
}

# ============================================================
# PASO 1: Configurar DNS para apuntar al DC
# ============================================================
Write-Log "Configurando DNS del cliente para apuntar al DC ($DCIpAddress)..."

$Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($Adapter in $Adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $DCIpAddress
    Write-Log "  DNS configurado en adaptador: $($Adapter.Name)" "Green"
}

# Verificar conectividad con el DC
Write-Log "Probando conectividad con el DC..."
if (Test-Connection -ComputerName $DCIpAddress -Count 2 -Quiet) {
    Write-Log "El DC responde correctamente." "Green"
} else {
    Write-Log "ERROR: No se puede alcanzar el DC en $DCIpAddress. Verifica la red." "Red"
    exit 1
}

# Verificar resolucion DNS del dominio
try {
    Resolve-DnsName $DomainName -ErrorAction Stop | Out-Null
    Write-Log "Resolucion DNS correcta para '$DomainName'." "Green"
} catch {
    Write-Log "ADVERTENCIA: No se pudo resolver '$DomainName'. Verifica DNS en el servidor." "Yellow"
}

# ============================================================
# PASO 2: Verificar si ya esta en el dominio
# ============================================================
$CurrentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($CurrentDomain -eq $DomainName) {
    Write-Log "La maquina ya pertenece al dominio '$DomainName'." "Yellow"
    exit 0
}

# ============================================================
# PASO 3: Unir al dominio con Add-Computer
# ============================================================
Write-Log "Uniendo la maquina al dominio '$DomainName'..."

$SecPass = ConvertTo-SecureString $DomainPass -AsPlainText -Force
$Credencial = New-Object System.Management.Automation.PSCredential($DomainUser, $SecPass)

try {
    Add-Computer `
        -DomainName   $DomainName `
        -Credential   $Credencial `
        -OUPath       "OU=Computers,DC=practica8,DC=local" `
        -Force

    Write-Log "Union al dominio exitosa. Se reiniciara en 10 segundos..." "Green"
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} catch {
    Write-Log "Error al unir al dominio: $($_.Exception.Message)" "Red"

    # Intento alternativo sin especificar OU (por si la OU Computers no existe)
    Write-Log "Intentando sin especificar OU..." "Yellow"
    Add-Computer -DomainName $DomainName -Credential $Credencial -Force
    Restart-Computer -Force
}
