# ==============================================================================
# FUNCIONES DHCP - VERSION WINDOWS SERVER 2022
# ==============================================================================

. .\funciones_compartidas.ps1

function Verificar-InstalacionDHCP {
    Write-Host ""
    Write-Host "=== VERIFICANDO ROL DHCP ===" -ForegroundColor Cyan
    
    $dhcp = Get-WindowsFeature -Name DHCP
    if ($dhcp.Installed) {
        Write-Host "[OK] DHCP SERVER INSTALADO" -ForegroundColor Green
    } else {
        Write-Host "[X] DHCP SERVER NO INSTALADO" -ForegroundColor Red
    }
}

function Instalar-DHCP {
    Write-Host ""
    Write-Host "=== INSTALANDO SERVIDOR DHCP ===" -ForegroundColor Yellow
    
    try {
        Install-WindowsFeature -Name DHCP -IncludeManagementTools
        
        if ($?) {
            Write-Host "[OK] INSTALACION DHCP COMPLETADA" -ForegroundColor Green
            
            # CONFIGURAR SERVICIO PARA INICIO AUTOMATICO
            Set-Service -Name DHCPServer -StartupType Automatic
            
            # AUTORIZAR DHCP EN EL DOMINIO (MODO STANDALONE)
            Write-Host "--- AUTORIZANDO SERVIDOR DHCP ---" -ForegroundColor Yellow
            netsh dhcp add securitygroups
            Restart-Service -Name DHCPServer -Force
            
            Write-Host "[OK] SERVICIO CONFIGURADO PARA INICIO AUTOMATICO" -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] EN LA INSTALACION DHCP: $_" -ForegroundColor Red
    }
}

function Validar-IPDNS {
    param([string]$ip)
    
    # NO PERMITIR 0.0.0.0
    if ($ip -eq "0.0.0.0") {
        return $false
    }
    
    # NO PERMITIR 255.255.255.255
    if ($ip -eq "255.255.255.255") {
        return $false
    }
    
    # NO PERMITIR 127.0.0.1
    if ($ip -eq "127.0.0.1") {
        return $false
    }
    
    # VALIDAR SINTAXIS
    $resultado = Validar-IPCompleta $ip
    if ($resultado -ne 0) {
        return $false
    }
    
    return $true
}

function Validar-RangoDHCP {
    param([string]$ipIni, [string]$ipFin, [string]$serverIP)
    
    $redServer = ($serverIP -split '\.')[0..2] -join '.'
    $redIni = ($ipIni -split '\.')[0..2] -join '.'
    $redFin = ($ipFin -split '\.')[0..2] -join '.'
    
    if ($redServer -ne $redIni -or $redServer -ne $redFin) {
        Write-Host "[ERROR] LAS IPS DEBEN ESTAR EN LA MISMA RED QUE EL SERVIDOR" -ForegroundColor Red
        return $false
    }
    
    $numIni = [int](($ipIni -split '\.')[3])
    $numFin = [int](($ipFin -split '\.')[3])
    
    if ($numIni -ge $numFin) {
        Write-Host "[ERROR] LA IP INICIAL DEBE SER MENOR QUE LA IP FINAL" -ForegroundColor Red
        return $false
    }
    
    if ($ipIni -eq $serverIP -or $ipFin -eq $serverIP) {
        Write-Host "[ERROR] NO PUEDES USAR LA IP DEL SERVIDOR EN EL RANGO" -ForegroundColor Red
        return $false
    }
    
    return $true
}

function Configurar-DHCP {
    $SERVER_IP = Obtener-IPActual
    if ([string]::IsNullOrEmpty($SERVER_IP)) {
        Write-Host "[ALERTA] CONFIGURA LA IP ESTATICA PRIMERO" -ForegroundColor Red
        return
    }

    # VERIFICAR QUE LA IP NO TERMINE EN .0 (DIRECCION DE RED)
    $ultimoOcteto = [int]($SERVER_IP -split '\.')[3]
    if ($ultimoOcteto -eq 0) {
        Write-Host "[ERROR] LA IP DEL SERVIDOR NO PUEDE SER $SERVER_IP (DIRECCION DE RED)" -ForegroundColor Red
        Write-Host "[AVISO] DEBE SER UNA IP VALIDA COMO 10.10.10.1, 192.168.1.1, ETC." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "=== CONFIGURAR SERVIDOR DHCP ===" -ForegroundColor Cyan
    Write-Host "[INFO] IP DEL SERVIDOR: $SERVER_IP" -ForegroundColor Yellow
    $scopeName = Read-Host "[?] NOMBRE DEL AMBITO DHCP"
    
    $ipIni = ""
    while ($true) {
        $ipIni = Read-Host "[?] IP INICIAL DEL RANGO"
        $resultado = Validar-IPCompleta $ipIni
        if ($resultado -eq 0) { break }
        Write-Host "[ERROR] IP INVALIDA" -ForegroundColor Red
    }

    $ipFin = ""
    while ($true) {
        $ipFin = Read-Host "[?] IP FINAL DEL RANGO"
        $resultado = Validar-IPCompleta $ipFin
        if ($resultado -eq 0) { break }
        Write-Host "[ERROR] IP INVALIDA" -ForegroundColor Red
    }
    
    if (-not (Validar-RangoDHCP $ipIni $ipFin $SERVER_IP)) {
        Write-Host "[ERROR] RANGO INVALIDO" -ForegroundColor Red
        Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR"
        return
    }
    
    $gateway = ""
    while ($true) {
        $inputGw = Read-Host "[?] GATEWAY (ENTER PARA OMITIR)"
        if ([string]::IsNullOrEmpty($inputGw)) {
            $gateway = ""; break
        }
        $resultado = Validar-IPCompleta $inputGw
        if ($resultado -eq 0) {
            $redGw = ($inputGw -split '\.')[0..2] -join '.'
            $redServer = ($SERVER_IP -split '\.')[0..2] -join '.'
            if ($redGw -eq $redServer) {
                $gateway = $inputGw; break
            } else {
                Write-Host "[ERROR] EL GATEWAY DEBE ESTAR EN LA MISMA RED" -ForegroundColor Red
            }
        } else {
            Write-Host "[ERROR] IP INVALIDA" -ForegroundColor Red
        }
    }

    # SOLICITAR DNS CON VALIDACION ESTRICTA
    $dnsServer = ""
    while ($true) {
        $inputDns = Read-Host "[?] SERVIDOR DNS (ENTER PARA USAR $SERVER_IP)"
        if ([string]::IsNullOrEmpty($inputDns)) {
            $dnsServer = $SERVER_IP
            break
        }
        if (Validar-IPDNS $inputDns) {
            $dnsServer = $inputDns
            break
        } else {
            Write-Host "[ERROR] DNS INVALIDO (NO PUEDE SER 0.0.0.0, 255.255.255.255, 127.0.0.1 O IP MAL FORMADA)" -ForegroundColor Red
        }
    }

    $leaseTime = ""
    while ($true) {
        $inputLease = Read-Host "[?] TIEMPO CONCESION (SEGUNDOS) (ENTER=86400)"
        if ([string]::IsNullOrEmpty($inputLease)) {
            $leaseTime = 86400; break
        }
        if ($inputLease -match '^\d+$' -and $inputLease -gt 0) {
            $leaseTime = $inputLease; break
        } else {
            Write-Host "[ERROR] DEBE SER UN NUMERO ENTERO POSITIVO" -ForegroundColor Red
        }
    }
    
    $subnetBase = ($SERVER_IP -split '\.')[0..2] -join '.'
    $SUBNET = "$subnetBase.0"
    
    Write-Host ""
    Write-Host "=== CONFIGURANDO DHCP EN WINDOWS SERVER ===" -ForegroundColor Yellow
    
    try {
        # PASO 1: DETENER SERVICIO DHCP
        Write-Host "[PASO 1] DETENIENDO SERVICIO DHCP..." -ForegroundColor Yellow
        Stop-Service -Name DHCPServer -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # PASO 2: AUTORIZAR DHCP (MODO STANDALONE - SIN DOMINIO)
        Write-Host "[PASO 2] AUTORIZANDO SERVIDOR DHCP..." -ForegroundColor Yellow
        netsh dhcp add securitygroups
        Start-Sleep -Seconds 2
        
        # PASO 3: INICIAR SERVICIO DHCP
        Write-Host "[PASO 3] INICIANDO SERVICIO DHCP..." -ForegroundColor Yellow
        Start-Service -Name DHCPServer
        Start-Sleep -Seconds 3
        
        # PASO 4: VERIFICAR QUE EL SERVICIO ESTE CORRIENDO
        $service = Get-Service -Name DHCPServer
        if ($service.Status -ne "Running") {
            Write-Host "[ERROR] EL SERVICIO DHCP NO PUDO INICIARSE" -ForegroundColor Red
            return
        }
        
        # PASO 5: AGREGAR SERVIDOR DHCP AL DIRECTORIO (OPCIONAL, PUEDE FALLAR Y NO ES CRITICO)
        Write-Host "[PASO 5] REGISTRANDO SERVIDOR DHCP..." -ForegroundColor Yellow
        try {
            Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $SERVER_IP -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  [AVISO] NO SE PUDO REGISTRAR EN DC (NO CRITICO)" -ForegroundColor Yellow
        }
        
        # PASO 6: ELIMINAR SCOPE EXISTENTE (SI EXISTE)
        Write-Host "[PASO 6] LIMPIANDO CONFIGURACION EXISTENTE..." -ForegroundColor Yellow
        try {
            Remove-DhcpServerv4Scope -ScopeId $SUBNET -Force -ErrorAction SilentlyContinue
        } catch {
            # IGNORAR ERRORES
        }
        
        # PASO 7: CREAR NUEVO SCOPE
        Write-Host "[PASO 7] CREANDO NUEVO SCOPE DHCP..." -ForegroundColor Yellow
        Add-DhcpServerv4Scope -Name $scopeName -StartRange $ipIni -EndRange $ipFin -SubnetMask 255.255.255.0 -State Active
        
        # PASO 8: CONFIGURAR OPCIONES DEL SCOPE
        Write-Host "[PASO 8] CONFIGURANDO OPCIONES DEL SCOPE..." -ForegroundColor Yellow
        Set-DhcpServerv4OptionValue -ScopeId $SUBNET -DnsServer $dnsServer -DnsDomain "lab.local"
        
        if (-not [string]::IsNullOrEmpty($gateway)) {
            Set-DhcpServerv4OptionValue -ScopeId $SUBNET -Router $gateway
        }
        
        # PASO 9: CONFIGURAR TIEMPO DE CONCESION
        Write-Host "[PASO 9] CONFIGURANDO TIEMPO DE CONCESION..." -ForegroundColor Yellow
        Set-DhcpServerv4Scope -ScopeId $SUBNET -LeaseDuration $leaseTime
        
        # PASO 10: ACTIVAR SCOPE
        Write-Host "[PASO 10] ACTIVANDO SCOPE..." -ForegroundColor Yellow
        Set-DhcpServerv4Scope -ScopeId $SUBNET -State Active
        
        # PASO 11: REINICIAR SERVICIO DHCP
        Write-Host "[PASO 11] REINICIANDO SERVICIO DHCP..." -ForegroundColor Yellow
        Restart-Service -Name DHCPServer -Force
        
        Start-Sleep -Seconds 3
        
        # VERIFICACION FINAL
        $service = Get-Service -Name DHCPServer
        if ($service.Status -eq "Running") {
            Write-Host ""
            Write-Host "=======================================================" -ForegroundColor Green
            Write-Host "[OK] SERVIDOR DHCP CONFIGURADO CORRECTAMENTE" -ForegroundColor Green
            Write-Host "=======================================================" -ForegroundColor Green
            Write-Host "[INFO] AMBITO: $scopeName" -ForegroundColor Green
            Write-Host "[INFO] RANGO: $ipIni - $ipFin" -ForegroundColor Green
            Write-Host "[INFO] DNS CONFIGURADO: $dnsServer" -ForegroundColor Green
            if (-not [string]::IsNullOrEmpty($gateway)) {
                Write-Host "[INFO] GATEWAY: $gateway" -ForegroundColor Green
            }
            Write-Host "=======================================================" -ForegroundColor Green
        } else {
            Write-Host "[FALLO] EL SERVICIO DHCP NO ARRANCO" -ForegroundColor Red
        }
    } catch {
        Write-Host "[ERROR] AL CONFIGURAR DHCP: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "=== POSIBLES SOLUCIONES ===" -ForegroundColor Yellow
        Write-Host "1. EJECUTA ESTOS COMANDOS MANUALMENTE:" -ForegroundColor Yellow
        Write-Host "   netsh dhcp add securitygroups" -ForegroundColor Yellow
        Write-Host "   Restart-Service -Name DHCPServer -Force" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "2. VERIFICA QUE LA IP DEL SERVIDOR SEA VALIDA (NO TERMINE EN .0)" -ForegroundColor Yellow
        Write-Host "   IP ACTUAL: $SERVER_IP" -ForegroundColor Yellow
    }
}