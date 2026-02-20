# Script para Windows Server 2022 - VERSION CON ELIMINACION CORREGIDA

$global:INTERFACE = ""
$global:DOMINIOS = @{}

function Pause-Message {
    Read-Host "Presiona Enter para continuar"
}

function Seleccionar-Interfaz {
    Clear-Host
    Write-Host "--- SELECCION DE INTERFAZ DE RED ---"
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notlike "*Loopback*" }
    
    if ($adapters.Count -eq 0) {
        Write-Host "ERROR: No hay interfaces de red activas."
        exit 1
    }
    
    Write-Host "`nInterfaces disponibles:"
    $i = 1
    foreach ($adapter in $adapters) {
        $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $ip = if ($ipInfo) { $ipInfo.IPAddress } else { "Sin IP" }
        Write-Host "  $i. $($adapter.Name) - IP: $ip"
        $i++
    }
    
    $selection = Read-Host "`nSelecciona el numero de la interfaz de RED INTERNA"
    
    if ($selection -match '^\d+$') {
        $num = [int]$selection
        if ($num -ge 1 -and $num -le $adapters.Count) {
            $selectedAdapter = $adapters[$num - 1]
            $global:INTERFACE = $selectedAdapter.Name
            Write-Host "Trabajando sobre: $global:INTERFACE"
            
            $ipInfo = Get-NetIPAddress -InterfaceIndex $selectedAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ipInfo) {
                Write-Host "IP actual: $($ipInfo.IPAddress)"
            } else {
                Write-Host "La interfaz no tiene IP asignada"
            }
        } else {
            Write-Host "Numero fuera de rango"
            exit 1
        }
    } else {
        Write-Host "Seleccion invalida"
        exit 1
    }
    
    Write-Host "`nInterfaz seleccionada: $global:INTERFACE"
    Pause-Message
}

function Configurar-FirewallPing {
    Write-Host "`nConfigurando Firewall para permitir PING (ICMP)..."
    
    try {
        New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4 -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Allow ICMPv4-Out" -Protocol ICMPv4 -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
        Write-Host "Reglas ICMP aplicadas correctamente"
    }
    catch {
        Write-Host "Error al configurar firewall: $_"
    }
}

function Validar-IPSintaxis {
    param([string]$ip)
    
    if ($ip -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        $octets = $ip.Split('.')
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
                return $false
            }
        }
        return $true
    }
    return $false
}

function Es-IPProhibida {
    param([string]$ip)
    
    if ($ip -eq "0.0.0.0" -or $ip -eq "255.255.255.255") { return $true }
    if ($ip -like "127.*") { return $true }
    
    $firstOctet = [int]($ip.Split('.')[0])
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

function Obtener-IPActual {
    if ([string]::IsNullOrEmpty($global:INTERFACE)) {
        return $null
    }
    $adapter = Get-NetAdapter -Name $global:INTERFACE -ErrorAction SilentlyContinue
    if ($adapter) {
        $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipInfo) {
            return $ipInfo.IPAddress
        }
    }
    return $null
}

function Configurar-DNSLocal {
    Write-Host "`n--- CONFIGURANDO DNS PARA RESOLUCION LOCAL ---"
    
    $options = Get-DnsServerForwarder -ErrorAction SilentlyContinue
    if ($options) {
        Write-Host "Forwarders actuales: $($options.IPAddress)"
    }
    
    Clear-DnsServerCache -ErrorAction SilentlyContinue
    Write-Host "Cache del servidor DNS limpiado"
    Write-Host "Servidor DNS configurado para responder con autoridad"
}

function Crear-IPVirtual {
    param([string]$ip, [string]$interfaz)
    
    Write-Host "`n--- VERIFICANDO IP VIRTUAL: $ip ---"
    
    $existingIP = Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue
    if ($existingIP) {
        Write-Host "La IP $ip ya esta configurada en $($existingIP.InterfaceAlias)"
        return $true
    }
    
    $ip_principal = Obtener-IPActual
    if ($ip_principal -and $ip -eq $ip_principal) {
        Write-Host "Error: No puedes usar la IP principal ($ip_principal) como virtual"
        return $false
    }
    
    Write-Host "Creando IP virtual: $ip en interfaz $interfaz..."
    
    try {
        New-NetIPAddress -InterfaceAlias $interfaz -IPAddress $ip -PrefixLength 24 -ErrorAction Stop
        Write-Host "IP virtual $ip creada exitosamente en $interfaz"
    }
    catch {
        Write-Host "PowerShell fallo, usando netsh..."
        netsh interface ip add address $interfaz $ip 255.255.255.0
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "IP virtual $ip creada con netsh"
        } else {
            Write-Host "ERROR: No se pudo crear la IP virtual"
            return $false
        }
    }
    
    Start-Sleep -Seconds 2
    $verificacion = Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue
    if ($verificacion) {
        Write-Host "IP virtual $ip verificada correctamente"
        return $true
    } else {
        Write-Host "ERROR: No se pudo verificar la IP $ip"
        return $false
    }
}

function Eliminar-IPVirtual {
    param([string]$ip, [string]$interfaz)
    
    Write-Host "`n--- ELIMINANDO IP VIRTUAL: $ip ---"
    
    $ipInfo = Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue
    
    if ($ipInfo) {
        Write-Host "Eliminando IP virtual: $ip de $($ipInfo.InterfaceAlias)..."
        try {
            Remove-NetIPAddress -IPAddress $ip -Confirm:$false -ErrorAction Stop
            Write-Host "IP virtual $ip eliminada"
            return $true
        }
        catch {
            Write-Host "Error al eliminar IP virtual: $_"
            return $false
        }
    }
    else {
        Write-Host "La IP $ip no existe"
        return $true
    }
}

function Instalar-Roles {
    Write-Host "`n--- INSTALANDO ROLES EN WINDOWS SERVER 2022 ---"
    
    try {
        Write-Host "Instalando DHCP Server..."
        Install-WindowsFeature -Name DHCP -IncludeManagementTools
        
        Write-Host "Instalando DNS Server..."
        Install-WindowsFeature -Name DNS -IncludeManagementTools
        
        Write-Host "Roles instalados correctamente"
        Configurar-DNSLocal
    }
    catch {
        Write-Host "Error al instalar roles: $_"
    }
    
    Configurar-FirewallPing
    Pause-Message
}

function Configurar-IPEstatica {
    if ([string]::IsNullOrEmpty($global:INTERFACE)) {
        Write-Host "ERROR: No hay interfaz seleccionada."
        Pause-Message
        return
    }
    
    Write-Host "`n--- CONFIGURACION IP ESTATICA ($global:INTERFACE) ---"
    
    $ipActual = Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ipActual) {
        Write-Host "IP Actual: $($ipActual.IPAddress)"
    } else {
        Write-Host "IP Actual: No configurada"
    }
    
    $resp = Read-Host "`n¿Configurar IP ESTATICA nueva? (s/n)"
    if ($resp -eq "s") {
        $nueva_ip = ""
        
        while ($true) {
            $nueva_ip = Read-Host "Ingrese IP Estatica (ej. 10.0.0.5)"
            $res = Validar-IPCompleta $nueva_ip
            if ($res -eq 0) {
                break
            } elseif ($res -eq 2) {
                Write-Host "Error: IP Prohibida o Reservada."
            } else {
                Write-Host "Error: Formato invalido."
            }
        }
        
        Write-Host "`nAplicando configuracion..."
        
        try {
            $adapter = Get-NetAdapter -Name $global:INTERFACE -ErrorAction Stop
            if (-not $adapter) {
                Write-Host "Error: No se encontro el adaptador $global:INTERFACE"
                Pause-Message
                return
            }
            
            $ifIndex = $adapter.ifIndex
            
            $existingIPs = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($existingIPs) {
                foreach ($ip in $existingIPs) {
                    Remove-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $ip.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
            
            New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $nueva_ip -PrefixLength 24 -ErrorAction Stop
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses "127.0.0.1" -ErrorAction SilentlyContinue
            
            Write-Host "IP $nueva_ip asignada correctamente a $global:INTERFACE"
        }
        catch {
            Write-Host "Error al configurar IP: $_"
        }
        
        Pause-Message
    }
}

function Configurar-DHCP {
    if ([string]::IsNullOrEmpty($global:INTERFACE)) {
        Write-Host "ERROR: No hay interfaz seleccionada."
        Pause-Message
        return
    }
    
    $ipActual = Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $ipActual) {
        Write-Host "`nALERTA: No hay IP configurada en $global:INTERFACE"
        Write-Host "Primero configura una IP Estatica (opcion 3)"
        Pause-Message
        return
    }
    
    $SERVER_IP = $ipActual.IPAddress
    Write-Host "`n--- CONFIGURAR SERVIDOR DHCP (PARA CLIENTES WINDOWS) ---"
    Write-Host "IP del servidor: $SERVER_IP"
    
    $scope_name = Read-Host "`nNombre del Ambito DHCP (ej. Red_Windows)"
    
    $ip_ini = ""
    while ($true) {
        $ip_ini = Read-Host "IP Inicial del rango"
        $res = Validar-IPCompleta $ip_ini
        if ($res -eq 0) { break }
        Write-Host "IP invalida o prohibida."
    }
    
    $ip_fin = ""
    while ($true) {
        $ip_fin = Read-Host "IP Final del rango"
        $res = Validar-IPCompleta $ip_fin
        if ($res -eq 0) { break }
        Write-Host "IP invalida o prohibida."
    }
    
    $gateway = ""
    while ($true) {
        $input_gw = Read-Host "Gateway para clientes (Enter para omitir)"
        if ([string]::IsNullOrEmpty($input_gw)) {
            $gateway = ""
            break
        }
        $res = Validar-IPCompleta $input_gw
        if ($res -eq 0) {
            $gateway = $input_gw
            break
        }
        Write-Host "IP invalida o prohibida."
    }
    
    $lease_time = ""
    while ($true) {
        $input_lease = Read-Host "Tiempo concesion (segundos) [Enter=86400]"
        if ([string]::IsNullOrEmpty($input_lease)) {
            $lease_time = 86400
            break
        }
        if ($input_lease -match '^\d+$' -and [int]$input_lease -gt 0) {
            $lease_time = [int]$input_lease
            break
        }
        Write-Host "Error: Debe ser un numero entero positivo."
    }
    
    $octetos = $SERVER_IP.Split('.')
    $subnet = $octetos[0] + "." + $octetos[1] + "." + $octetos[2] + ".0"
    Write-Host "Subred calculada: $subnet"
    
    Write-Host "`nGenerando configuracion DHCP..."
    
    try {
        $existingScope = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.ScopeId -eq $subnet }
        
        if ($existingScope) {
            Write-Host "El ambito $subnet ya existe. Eliminandolo para recrearlo..."
            Remove-DhcpServerv4Scope -ScopeId $subnet -Force
        }
        
        Add-DhcpServerv4Scope -Name $scope_name -StartRange $ip_ini -EndRange $ip_fin -SubnetMask "255.255.255.0"
        Write-Host "Ambito DHCP creado correctamente"
        
        Set-DhcpServerv4Scope -ScopeId $subnet -State Active
        Write-Host "Ambito activado"
        
        if ($gateway) {
            Set-DhcpServerv4OptionValue -ScopeId $subnet -Router $gateway
            Write-Host "Gateway configurado: $gateway"
        }
        
        Set-DhcpServerv4OptionValue -ScopeId $subnet -DnsServer $SERVER_IP
        Write-Host "Servidor DNS configurado: $SERVER_IP"
        
        Write-Host "`nSERVIDOR DHCP CONFIGURADO CORRECTAMENTE"
        
        Write-Host "`nInstrucciones para cliente Windows:"
        Write-Host "  1. En Windows: ipconfig /release"
        Write-Host "  2. En Windows: ipconfig /renew"
        Write-Host "  3. Verificar con: ipconfig /all (DNS debe ser $SERVER_IP)"
    }
    catch {
        Write-Host "Error al configurar DHCP: $_"
    }
    
    Pause-Message
}

function Agregar-Zona {
    if ([string]::IsNullOrEmpty($global:INTERFACE)) {
        Write-Host "ERROR: No hay interfaz seleccionada."
        Pause-Message
        return
    }
    
    $ipActual = Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ipActual) {
        $SERVER_IP = $ipActual.IPAddress
    } else {
        $SERVER_IP = "10.0.0.1"
        Write-Host "`nNo hay IP configurada, usando $SERVER_IP como servidor DNS"
    }
    
    Write-Host "`n--- AGREGAR ZONA DNS (CON IP VIRTUAL EN $global:INTERFACE) ---"
    
    $dominio = Read-Host "Nombre del Dominio (ej. reprobados.com)"
    if ([string]::IsNullOrEmpty($dominio)) { return }
    
    $virtual_ip = ""
    while ($true) {
        $virtual_ip = Read-Host "IP virtual para $dominio (ej. 10.0.0.6)"
        $res = Validar-IPCompleta $virtual_ip
        if ($res -eq 0) {
            if ($virtual_ip -eq $SERVER_IP) {
                Write-Host "Error: No puedes usar la IP del servidor ($SERVER_IP) como IP virtual"
                continue
            }
            break
        } else {
            Write-Host "IP invalida o prohibida."
        }
    }
    
    Write-Host "`nPASO 1: Creando IP virtual en $global:INTERFACE"
    if (-not (Crear-IPVirtual $virtual_ip $global:INTERFACE)) {
        Write-Host "ERROR: No se pudo crear la IP virtual. Abortando."
        Pause-Message
        return
    }
    
    Write-Host "`nPASO 2: Configurando zona DNS"
    
    try {
        Add-DnsServerPrimaryZone -Name $dominio -ZoneFile "$dominio.dns"
        Add-DnsServerResourceRecordA -Name "@" -ZoneName $dominio -IPv4Address $virtual_ip
        Add-DnsServerResourceRecordA -Name "ns1" -ZoneName $dominio -IPv4Address $SERVER_IP
        Add-DnsServerResourceRecordA -Name "ns2" -ZoneName $dominio -IPv4Address $SERVER_IP
        Add-DnsServerResourceRecordA -Name "www" -ZoneName $dominio -IPv4Address $virtual_ip
        Add-DnsServerResourceRecordA -Name "mail" -ZoneName $dominio -IPv4Address $virtual_ip
        Add-DnsServerResourceRecordA -Name "ftp" -ZoneName $dominio -IPv4Address $virtual_ip
        Add-DnsServerResourceRecordMX -Name "." -ZoneName $dominio -MailExchange "mail.$dominio" -Preference 10
        Write-Host "Zona DNS configurada correctamente"
        $global:DOMINIOS[$dominio] = $virtual_ip
        Configurar-DNSLocal
    }
    catch {
        Write-Host "Error al configurar DNS: $_"
    }
    
    Write-Host "`nCONFIGURACION COMPLETADA"
    Write-Host "  Dominio:        $dominio"
    Write-Host "  IP Virtual:     $virtual_ip (en interfaz $global:INTERFACE)"
    Write-Host "  Servidor DNS:   $SERVER_IP"
    
    Write-Host "`nVerificando conectividad con ping..."
    ping -n 2 $virtual_ip
    
    Pause-Message
}

# =========================
# FUNCION ELIMINAR-ZONA CORREGIDA
# =========================
function Eliminar-Zona {
    Write-Host "`n--- ELIMINAR ZONA DNS ---"
    
    do {
        $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneName -notlike "*in-addr.arpa" -and $_.ZoneName -notlike "*msdcs*" }
        
        if ($zonas.Count -eq 0) {
            Write-Host "No hay zonas configuradas."
            Pause-Message
            return
        }
        
        Write-Host "`nZonas actuales:"
        $i = 1
        foreach ($zona in $zonas) {
            Write-Host "  $i. $($zona.ZoneName)"
            $i++
        }
        Write-Host "  0. Volver al menu anterior"
        
        $selection = Read-Host "`nSelecciona el numero de la zona a eliminar"
        
        if ($selection -eq "0") {
            return
        }
        
        if ($selection -match '^\d+$') {
            $num = [int]$selection
            if ($num -ge 1 -and $num -le $zonas.Count) {
                $zona_del = $zonas[$num - 1].ZoneName
                $virtual_ip = $global:DOMINIOS[$zona_del]
                
                Write-Host "`n¿Estas seguro de eliminar la zona '$zona_del'? (s/n)"
                $confirm = Read-Host
                
                if ($confirm -eq "s") {
                    if ($virtual_ip) {
                        Write-Host "Eliminando IP virtual asociada: $virtual_ip"
                        Eliminar-IPVirtual $virtual_ip $global:INTERFACE
                    }
                    
                    Remove-DnsServerZone -Name $zona_del -Force
                    Write-Host "Zona $zona_del eliminada"
                    $global:DOMINIOS.Remove($zona_del)
                    
                    Write-Host "Limpiando cache del servidor DNS..."
                    Clear-DnsServerCache -ErrorAction SilentlyContinue
                    
                    Write-Host "`n=================================================="
                    Write-Host "IMPORTANTE: En el cliente Windows 10, ejecuta:"
                    Write-Host "  ipconfig /flushdns"
                    Write-Host "  nslookup $zona_del 10.0.0.5"
                    Write-Host "=================================================="
                    
                    Write-Host "`nZona eliminada correctamente. Mostrando lista actualizada..."
                    Start-Sleep -Seconds 2
                } else {
                    Write-Host "Operacion cancelada"
                }
            } else {
                Write-Host "Numero fuera de rango. Intenta de nuevo."
                Start-Sleep -Seconds 2
            }
        } else {
            Write-Host "Seleccion invalida. Intenta de nuevo."
            Start-Sleep -Seconds 2
        }
    } while ($true)
}

function Listar-Zonas {
    Write-Host "`n--- DOMINIOS CONFIGURADOS ---"
    
    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneName -notlike "*in-addr.arpa" -and $_.ZoneName -notlike "*msdcs*" }
    
    if ($zonas.Count -gt 0) {
        foreach ($zona in $zonas) {
            $virtual_ip = $global:DOMINIOS[$zona.ZoneName]
            if ($virtual_ip) {
                Write-Host "  - $($zona.ZoneName) -> $virtual_ip (IP virtual)"
            } else {
                Write-Host "  - $($zona.ZoneName)"
            }
        }
    } else {
        Write-Host "No hay zonas configuradas."
    }
    
    Write-Host "`nTodas las IPs en $global:INTERFACE:"
    Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 | Format-Table IPAddress, PrefixLength -AutoSize
    
    Pause-Message
}

function Submenu-DNS {
    do {
        Clear-Host
        Write-Host "`n=== GESTION DE DOMINIOS DNS (CON IPS VIRTUALES) ==="
        Write-Host "1) Agregar Dominio (crea IP virtual en $global:INTERFACE)"
        Write-Host "2) Eliminar Dominio (elimina IP virtual asociada)"
        Write-Host "3) Ver Dominios e IPs Virtuales"
        Write-Host "4) Volver al Menu Principal"
        
        $subopc = Read-Host "`nSeleccione opcion"
        
        switch ($subopc) {
            "1" { Agregar-Zona }
            "2" { Eliminar-Zona }
            "3" { Listar-Zonas }
            "4" { return }
            default { Write-Host "Opcion invalida"; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Ejecutar-Pruebas {
    Write-Host "`n--- PRUEBAS DE RESOLUCION ---"
    $dom = Read-Host "Dominio a probar (ej. reprobados.com)"
    if ([string]::IsNullOrEmpty($dom)) { return }
    
    Write-Host "`n[PRUEBA 1: NSLOOKUP desde el servidor]"
    nslookup $dom 127.0.0.1
    
    Write-Host "`n[PRUEBA 2: PING desde el servidor al dominio]"
    ping -n 2 $dom
    
    Write-Host "`n[PRUEBA 3: Verificar IP virtual]"
    Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 | Format-Table IPAddress, PrefixLength -AutoSize
    
    Write-Host "`n--- INSTRUCCIONES PARA CLIENTE WINDOWS 10 ---"
    Write-Host "1. Abre CMD como administrador"
    Write-Host "2. Ejecuta: ipconfig /flushdns (para limpiar cache)"
    Write-Host "3. Prueba: ping $dom"
    Write-Host "4. Prueba: nslookup $dom"
    
    Pause-Message
}

function Verificar-Instalacion {
    Write-Host "`n--- VERIFICANDO ROLES INSTALADOS ---"
    
    $dhcp = Get-WindowsFeature -Name DHCP
    if ($dhcp.Installed) {
        Write-Host "[OK] DHCP Server"
    } else {
        Write-Host "[X] DHCP Server NO instalado"
    }
    
    $dns = Get-WindowsFeature -Name DNS
    if ($dns.Installed) {
        Write-Host "[OK] DNS Server"
    } else {
        Write-Host "[X] DNS Server NO instalado"
    }
    
    Write-Host "`nIPs configuradas en $global:INTERFACE:"
    Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 | Format-Table IPAddress, PrefixLength -AutoSize
    
    Pause-Message
}

# Verificar ejecución como administrador
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script debe ejecutarse como Administrador."
    exit 1
}

# Inicio del script
Seleccionar-Interfaz
Configurar-FirewallPing

Write-Host "`nSistema detectado: Windows Server 2022"
Write-Host "Interfaz interna: $global:INTERFACE"

$ipInicial = Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue
if ($ipInicial) {
    Write-Host "IP principal: $($ipInicial.IPAddress)"
} else {
    Write-Host "IP principal: No configurada - Usa opcion 3 para configurar"
}

Start-Sleep -Seconds 2

do {
    Clear-Host
    Write-Host "`n============================================="
    Write-Host "   GESTOR WINDOWS SERVER 2022 - IPS EN $global:INTERFACE"
    Write-Host "============================================="
    Write-Host "Interfaz: $global:INTERFACE"
    
    $currentIP = Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($currentIP) {
        Write-Host "IP principal: $($currentIP.IPAddress)"
    } else {
        Write-Host "IP principal: No configurada (Usa opcion 3)"
    }
    
    $allIPs = Get-NetIPAddress -InterfaceAlias $global:INTERFACE -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $virtualCount = ($allIPs | Where-Object { $_.IPAddress -ne $currentIP.IPAddress }).Count
    Write-Host "IPs virtuales: $virtualCount"
    Write-Host ""
    Write-Host "1) Verificar Instalacion"
    Write-Host "2) Instalar Roles (DHCP + DNS)"
    Write-Host "3) Configurar IP Estatica (principal)"
    Write-Host "4) Configurar DHCP"
    Write-Host "5) Gestion de Dominios DNS (con IPs virtuales)"
    Write-Host "6) Pruebas de Resolucion"
    Write-Host "7) Salir"
    
    $MAIN_OPC = Read-Host "`nSeleccione opcion"
    
    switch ($MAIN_OPC) {
        "1" { Verificar-Instalacion }
        "2" { Instalar-Roles }
        "3" { Configurar-IPEstatica }
        "4" { Configurar-DHCP }
        "5" { Submenu-DNS }
        "6" { Ejecutar-Pruebas }
        "7" { exit }
        default { Write-Host "Opcion invalida"; Start-Sleep -Seconds 1 }
    }
} while ($true)