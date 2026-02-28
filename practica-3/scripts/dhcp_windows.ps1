# ==============================================
#        DHCP AUTOMATIZADO - RED_SISTEMAS
#        Windows Server 2022
#        CON DNS PRIMARIO Y SECUNDARIO
# ==============================================

$Adaptador = "Ethernet 2"

function Pause {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar"
}

# ---------------- VALIDACIONES ----------------

function Validar-IP {
    param($ip)

    if ($ip -match "^([0-9]{1,3}\.){3}[0-9]{1,3}$") {
        $octetos = $ip.Split(".")
        foreach ($o in $octetos) {
            if ([int]$o -gt 255) { return $false }
        }
        if ($ip -eq "0.0.0.0" -or $ip -like "127.*") { return $false }
        return $true
    }
    return $false
}

function Obtener-Mascara-Sugerida {
    param($ip)

    $primerOcteto = [int]($ip.Split(".")[0])

    if ($primerOcteto -ge 1 -and $primerOcteto -le 126) { return "255.0.0.0" }
    elseif ($primerOcteto -ge 128 -and $primerOcteto -le 191) { return "255.255.0.0" }
    elseif ($primerOcteto -ge 192 -and $primerOcteto -le 223) { return "255.255.255.0" }
    else { return "255.255.255.0" }
}

# ---------------- ESTADO ----------------

function Estado-DHCP {
    Write-Host "===== ESTADO DHCP ====="

    $feature = Get-WindowsFeature -Name DHCP
    if ($feature.Installed) { Write-Host "Rol DHCP: INSTALADO" }
    else { Write-Host "Rol DHCP: NO instalado" }

    $service = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "Servicio DHCP: ACTIVO"
    } else {
        Write-Host "Servicio DHCP: INACTIVO"
    }

    Pause
}

# ---------------- INSTALAR ----------------

function Instalar-DHCP {
    Write-Host "===== INSTALAR / REINSTALAR DHCP ====="

    Install-WindowsFeature DHCP -IncludeManagementTools
    netsh dhcp add securitygroups
    Restart-Service DHCPServer -ErrorAction SilentlyContinue

    Write-Host "DHCP instalado correctamente."
    Pause
}

# ---------------- CONFIGURAR ----------------

function Configurar-DHCP {
    Write-Host "===== CONFIGURAR DHCP ====="

    $ScopeName = Read-Host "Nombre del Scope"

    while ($true) {
        $IPInicio = Read-Host "IP inicial (sera IP del servidor)"
        if (Validar-IP $IPInicio) { break }
        Write-Host "IP invalida"
    }

    while ($true) {
        $IPFin = Read-Host "IP final del rango"
        if (Validar-IP $IPFin) { break }
        Write-Host "IP invalida"
    }

    $MascaraSugerida = Obtener-Mascara-Sugerida $IPInicio
    $Mascara = Read-Host "Mascara de red (Enter=$MascaraSugerida)"
    if ([string]::IsNullOrWhiteSpace($Mascara)) { $Mascara = $MascaraSugerida }

    $Gateway = Read-Host "Gateway (opcional, Enter vacio)"
    $Lease = Read-Host "Tiempo de concesion (segundos)"

    # SOLICITAR DNS PRIMARIO Y SECUNDARIO
    Write-Host ""
    Write-Host "--- CONFIGURACION DE DNS ---"
    
    while ($true) {
        $DNSPrimario = Read-Host "DNS Primario (obligatorio)"
        if (Validar-IP $DNSPrimario) { break }
        Write-Host "IP invalida"
    }
    
    $DNSSecundario = Read-Host "DNS Secundario (opcional, Enter vacio)"
    if ([string]::IsNullOrWhiteSpace($DNSSecundario)) {
        $DNSSecundario = $null
        Write-Host "DNS Secundario no configurado"
    } else {
        while ($true) {
            if (Validar-IP $DNSSecundario) { break }
            Write-Host "IP invalida para DNS Secundario"
            $DNSSecundario = Read-Host "DNS Secundario (opcional, Enter vacio)"
            if ([string]::IsNullOrWhiteSpace($DNSSecundario)) {
                $DNSSecundario = $null
                break
            }
        }
    }

    try {
        Write-Host "Configurando IP fija al servidor..."

        # PREFIJO SEGUN MASCARA
        switch ($Mascara) {
            "255.0.0.0"       { $prefijo = 8 }
            "255.255.0.0"     { $prefijo = 16 }
            "255.255.255.0"   { $prefijo = 24 }
            default {
                Write-Host "Mascara no soportada automaticamente."
                return
            }
        }

        # Eliminar IPs anteriores
        $ipsExistentes = Get-NetIPAddress -InterfaceAlias $Adaptador -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipsExistentes) {
            $ipsExistentes | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }

        # Asignar nueva IP
        if (![string]::IsNullOrWhiteSpace($Gateway)) {
            New-NetIPAddress `
                -InterfaceAlias $Adaptador `
                -IPAddress $IPInicio `
                -PrefixLength $prefijo `
                -DefaultGateway $Gateway `
                -ErrorAction Stop
        } else {
            New-NetIPAddress `
                -InterfaceAlias $Adaptador `
                -IPAddress $IPInicio `
                -PrefixLength $prefijo `
                -ErrorAction Stop
        }

        # CONFIGURAR DNS DEL SERVIDOR
        if ($DNSSecundario) {
            Set-DnsClientServerAddress `
                -InterfaceAlias $Adaptador `
                -ServerAddresses $DNSPrimario, $DNSSecundario
            Write-Host "DNS configurado: Primario=$DNSPrimario, Secundario=$DNSSecundario"
        } else {
            Set-DnsClientServerAddress `
                -InterfaceAlias $Adaptador `
                -ServerAddresses $DNSPrimario
            Write-Host "DNS configurado: Primario=$DNSPrimario"
        }

        Restart-Service DHCPServer -ErrorAction SilentlyContinue

        # BINDING DHCP
        Set-DhcpServerv4Binding `
            -InterfaceAlias $Adaptador `
            -BindingState $true `
            -ErrorAction SilentlyContinue

        # ELIMINAR SCOPES ANTERIORES
        $Scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
        if ($Scopes) {
            foreach ($s in $Scopes) {
                Remove-DhcpServerv4Scope -ScopeId $s.ScopeId -Force -ErrorAction SilentlyContinue
            }
        }

        # CALCULAR RANGO
        $octetos = $IPInicio.Split(".")
        $ultimoOcteto = [int]$octetos[3]
        $RangoInicio = "$($octetos[0]).$($octetos[1]).$($octetos[2]).$($ultimoOcteto + 1)"

        # CREAR SCOPE
        Add-DhcpServerv4Scope `
            -Name $ScopeName `
            -StartRange $RangoInicio `
            -EndRange $IPFin `
            -SubnetMask $Mascara `
            -State Active `
            -ErrorAction Stop

        $ScopeCreado = Get-DhcpServerv4Scope | Where-Object { $_.Name -eq $ScopeName }
        $ScopeId = $ScopeCreado.ScopeId

        # CONFIGURAR OPCIONES DNS EN DHCP
        if ($DNSSecundario) {
            Set-DhcpServerv4OptionValue `
                -ScopeId $ScopeId `
                -DnsServer $DNSPrimario, $DNSSecundario `
                -Force
            Write-Host "Opciones DNS configuradas en DHCP: Primario=$DNSPrimario, Secundario=$DNSSecundario"
        } else {
            Set-DhcpServerv4OptionValue `
                -ScopeId $ScopeId `
                -DnsServer $DNSPrimario `
                -Force
            Write-Host "Opciones DNS configuradas en DHCP: Primario=$DNSPrimario"
        }

        if ($Gateway) {
            Set-DhcpServerv4OptionValue `
                -ScopeId $ScopeId `
                -Router $Gateway
        }

        Set-DhcpServerv4Scope `
            -ScopeId $ScopeId `
            -LeaseDuration (New-TimeSpan -Seconds $Lease)

        Write-Host ""
        Write-Host "========================================="
        Write-Host "DHCP configurado correctamente."
        Write-Host "========================================="
        Write-Host ""
        Write-Host "Resumen de configuracion:"
        Write-Host "-------------------------"
        Write-Host "IP Servidor: $IPInicio"
        Write-Host "Mascara: $Mascara"
        Write-Host "Rango DHCP: $RangoInicio - $IPFin"
        Write-Host "Gateway: $(if($Gateway){$Gateway}else{'No configurado'})"
        Write-Host "DNS Primario: $DNSPrimario"
        Write-Host "DNS Secundario: $(if($DNSSecundario){$DNSSecundario}else{'No configurado'})"
        Write-Host "Tiempo concesion: $Lease segundos"
    }
    catch {
        Write-Host ""
        Write-Host "ERROR durante la configuracion:"
        Write-Host $_.Exception.Message
    }

    Pause
}

# ---------------- MONITOREO ----------------

function Monitorear-DHCP {
    Write-Host "===== MONITOREO DHCP ====="

    if ((Get-Service DHCPServer).Status -ne "Running") {
        Start-Service DHCPServer
    }

    $scope = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue

    if ($scope) {
        Write-Host ""
        Write-Host "Scopes activos:"
        $scope | Format-Table ScopeId, Name, State -AutoSize

        # MOSTRAR OPCIONES DNS
        Write-Host ""
        Write-Host "Opciones de DNS configuradas:"
        $dnsOptions = Get-DhcpServerv4OptionValue -ScopeId $scope.ScopeId | Where-Object { $_.OptionId -eq 6 }
        if ($dnsOptions) {
            Write-Host "Servidores DNS: $($dnsOptions.Value -join ', ')"
        } else {
            Write-Host "No hay servidores DNS configurados"
        }

        Write-Host ""
        Write-Host "Concesiones activas:"
        Get-DhcpServerv4Lease -ScopeId $scope.ScopeId |
            Format-Table IPAddress, HostName, ClientId, LeaseExpiryTime -AutoSize
    }
    else {
        Write-Host "No hay scopes configurados."
    }

    Pause
}

# ---------------- MENU ----------------

while ($true) {
    Clear-Host
    Write-Host "====== MENU DHCP (Windows Server 2022) ======"
    Write-Host "1) Ver estado del servicio"
    Write-Host "2) Instalar / Reinstalar DHCP"
    Write-Host "3) Configurar DHCP"
    Write-Host "4) Monitorear"
    Write-Host "5) Salir"

    $op = Read-Host "Opcion"

    switch ($op) {
        "1" { Estado-DHCP }
        "2" { Instalar-DHCP }
        "3" { Configurar-DHCP }
        "4" { Monitorear-DHCP }
        "5" { exit }
        default { 
            Write-Host "Opcion invalida"
            Pause 
        }
    }
}