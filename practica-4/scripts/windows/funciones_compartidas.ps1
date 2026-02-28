# ==============================================================================
# FUNCIONES COMPARTIDAS - VERSION WINDOWS SERVER 2022
# ==============================================================================

# =========================
# VARIABLES GLOBALES
# =========================
$global:INTERFAZ = ""
$global:IPS_VIRTUALES = @()

# =========================
# FUNCIONES DE VALIDACION
# =========================

function Check-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[ERROR] ESTE SCRIPT DEBE EJECUTARSE COMO ADMINISTRADOR" -ForegroundColor Red
        exit 1
    }
}

function Validar-IPSintaxis {
    param([string]$ip)
    
    if ($ip -match "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") {
        return $true
    }
    return $false
}

function Es-IPProhibida {
    param([string]$ip)
    
    if ($ip -eq "0.0.0.0" -or $ip -eq "255.255.255.255") { return $true }
    if ($ip -like "127.*") { return $true }
    
    $firstOctet = [int]($ip -split '\.')[0]
    if ($firstOctet -ge 224) { return $true }
    
    return $false
}

function Validar-IPCompleta {
    param([string]$ip)
    
    if (Validar-IPSintaxis $ip) {
        if (-not (Es-IPProhibida $ip)) {
            return 0
        } else {
            return 2
        }
    } else {
        return 1
    }
}

# =========================
# FUNCIONES DE RED
# =========================

function Seleccionar-Interfaz {
    Clear-Host
    Write-Host "=== SELECCION DE INTERFAZ DE RED ===" -ForegroundColor Cyan
    Write-Host "[INFO] INTERFACES DISPONIBLES:" -ForegroundColor Yellow
    
    $adapters = Get-NetAdapter | Where-Object {$_.Name -notlike "*Loopback*"} | Select-Object Name, Status, InterfaceDescription
    $adapters | ForEach-Object { Write-Host "  $($_.Name) - $($_.Status) - $($_.InterfaceDescription)" }
    
    Write-Host ""
    $inputInterfaz = Read-Host "[?] NOMBRE DE LA INTERFAZ"
    $global:INTERFAZ = $inputInterfaz

    $adapter = Get-NetAdapter -Name $global:INTERFAZ -ErrorAction SilentlyContinue
    if (-not $adapter) {
        Write-Host "[ERROR] LA INTERFAZ $global:INTERFAZ NO EXISTE" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] TRABAJANDO SOBRE: $global:INTERFAZ" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

function Obtener-IPActual {
    if ([string]::IsNullOrEmpty($global:INTERFAZ)) {
        return $null
    }
    $adapter = Get-NetAdapter -Name $global:INTERFAZ -ErrorAction SilentlyContinue
    if ($adapter) {
        $ip = Get-NetIPAddress -InterfaceAlias $global:INTERFAZ -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ip) {
            return $ip.IPAddress
        }
    }
    return $null
}

function Activar-InterfacesRed {
    Write-Host ""
    Write-Host "=== ACTIVANDO INTERFACES DE RED ===" -ForegroundColor Cyan
    
    $interfaces = @("Ethernet2", "Ethernet3")
    foreach ($iface in $interfaces) {
        $adapter = Get-NetAdapter -Name $iface -ErrorAction SilentlyContinue
        if ($adapter) {
            Write-Host "[INFO] ACTIVANDO $iface..." -ForegroundColor Yellow
            Enable-NetAdapter -Name $iface -Confirm:$false
            Write-Host "  [OK] $iface ACTIVADA" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host "[INFO] ESTADO ACTUAL DE INTERFACES:" -ForegroundColor Cyan
    Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object { Write-Host "  $($_.Name)" }
}

function Configurar-FirewallPing {
    Write-Host ""
    Write-Host "=== CONFIGURANDO FIREWALL PARA PERMITIR PING ===" -ForegroundColor Yellow
    
    # PERMITIR ICMP EN FIREWALL DE WINDOWS
    New-NetFirewallRule -DisplayName "PERMITIR PING" -Protocol ICMPv4 -Enabled True -Profile Any -Action Allow -ErrorAction SilentlyContinue
    
    Write-Host "[OK] REGLAS ICMP APLICADAS" -ForegroundColor Green
}

# =========================
# FUNCIONES DE IP VIRTUAL
# =========================

function Crear-IPVirtual {
    param([string]$ip, [string]$interfaz)
    
    Write-Host ""
    Write-Host "=== VERIFICANDO IP VIRTUAL: $ip ===" -ForegroundColor Cyan
    
    $ipExistente = Get-NetIPAddress -InterfaceAlias $interfaz -IPAddress $ip -ErrorAction SilentlyContinue
    if ($ipExistente) {
        Write-Host "[AVISO] LA IP $ip YA ESTA CONFIGURADA EN $interfaz" -ForegroundColor Yellow
        return 0
    }
    
    $ipPrincipal = Obtener-IPActual
    if ($ip -eq $ipPrincipal) {
        Write-Host "[ERROR] NO PUEDES USAR LA IP PRINCIPAL COMO VIRTUAL" -ForegroundColor Red
        return 1
    }
    
    Write-Host "[INFO] CREANDO IP VIRTUAL: $ip EN $interfaz..." -ForegroundColor Yellow
    
    try {
        New-NetIPAddress -InterfaceAlias $interfaz -IPAddress $ip -PrefixLength 24 -ErrorAction Stop
        
        Start-Sleep -Seconds 1
        
        $ipVerificada = Get-NetIPAddress -InterfaceAlias $interfaz -IPAddress $ip -ErrorAction SilentlyContinue
        if ($ipVerificada) {
            Write-Host "[OK] IP VIRTUAL $ip CREADA EXITOSAMENTE" -ForegroundColor Green
            
            $global:IPS_VIRTUALES += $ip
            
            Write-Host ""
            Write-Host "[INFO] ESTADO ACTUAL DE ${interfaz}:" -ForegroundColor Cyan
            Get-NetIPAddress -InterfaceAlias $interfaz | Where-Object {$_.AddressFamily -eq "IPv4"} | ForEach-Object { Write-Host "  $($_.IPAddress)" }
            
            return 0
        } else {
            Write-Host "[ERROR] LA IP $ip NO APARECE DESPUES DE CREARLA" -ForegroundColor Red
            return 1
        }
    } catch {
        Write-Host "[ERROR] AL CREAR IP VIRTUAL: $_" -ForegroundColor Red
        return 1
    }
}

function Eliminar-IPVirtual {
    param([string]$ip, [string]$interfaz)
    
    Write-Host ""
    Write-Host "=== ELIMINANDO IP VIRTUAL: $ip ===" -ForegroundColor Cyan
    
    $ipExistente = Get-NetIPAddress -InterfaceAlias $interfaz -IPAddress $ip -ErrorAction SilentlyContinue
    if ($ipExistente) {
        Write-Host "[INFO] ELIMINANDO IP VIRTUAL: $ip DE $interfaz..." -ForegroundColor Yellow
        
        try {
            Remove-NetIPAddress -InterfaceAlias $interfaz -IPAddress $ip -Confirm:$false -ErrorAction Stop
            Write-Host "[OK] IP VIRTUAL $ip ELIMINADA" -ForegroundColor Green
            
            Write-Host ""
            Write-Host "[INFO] ESTADO ACTUAL DE ${interfaz}:" -ForegroundColor Cyan
            Get-NetIPAddress -InterfaceAlias $interfaz | Where-Object {$_.AddressFamily -eq "IPv4"} | ForEach-Object { Write-Host "  $($_.IPAddress)" }
            
            return 0
        } catch {
            Write-Host "[ERROR] AL ELIMINAR IP VIRTUAL $ip" -ForegroundColor Red
            return 1
        }
    } else {
        Write-Host "[AVISO] LA IP $ip NO EXISTE EN $interfaz" -ForegroundColor Yellow
        return 0
    }
}