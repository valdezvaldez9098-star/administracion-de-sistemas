# ==============================================================================
# FUNCIONES DNS - VERSION CORREGIDA PARA SSH
# ==============================================================================

. .\funciones_compartidas.ps1

function Verificar-InstalacionDNS {
    Write-Host ""
    Write-Host "=== VERIFICANDO ROL DNS ===" -ForegroundColor Cyan
    
    $dns = Get-WindowsFeature -Name DNS
    if ($dns.Installed) {
        Write-Host "[OK] DNS SERVER INSTALADO" -ForegroundColor Green
    } else {
        Write-Host "[X] DNS SERVER NO INSTALADO" -ForegroundColor Red
    }
    
    # VERIFICAR SERVICIO
    $service = Get-Service -Name DNS -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "[OK] SERVICIO DNS ACTIVO" -ForegroundColor Green
    } else {
        Write-Host "[X] SERVICIO DNS INACTIVO" -ForegroundColor Red
    }
}

function Instalar-DNS {
    Write-Host ""
    Write-Host "=== INSTALANDO SERVIDOR DNS ===" -ForegroundColor Yellow
    
    try {
        Install-WindowsFeature -Name DNS -IncludeManagementTools
        
        if ($?) {
            Write-Host "[OK] INSTALACION DNS COMPLETADA" -ForegroundColor Green
            
            # CONFIGURAR SERVICIO PARA INICIO AUTOMATICO
            Set-Service -Name DNS -StartupType Automatic
            Write-Host "[OK] SERVICIO DNS CONFIGURADO PARA INICIO AUTOMATICO" -ForegroundColor Green
            
            # CONFIGURAR DNS INICIAL
            Configurar-DNSLocal
        }
    } catch {
        Write-Host "[ERROR] EN LA INSTALACION DNS: $_" -ForegroundColor Red
    }
}

function Reiniciar-ServicioDNS {
    Write-Host ""
    Write-Host "=== REINICIANDO SERVICIO DNS ===" -ForegroundColor Yellow
    
    try {
        Restart-Service -Name DNS -Force
        Start-Sleep -Seconds 3
        Write-Host "[OK] SERVICIO DNS REINICIADO" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[ERROR] AL REINICIAR DNS: $_" -ForegroundColor Red
        return $false
    }
}

function Configurar-DNSLocal {
    Write-Host ""
    Write-Host "=== CONFIGURANDO DNS LOCAL ===" -ForegroundColor Cyan
    
    # OBTENER IP DEL SERVIDOR
    $SERVER_IP = Obtener-IPActual
    if ([string]::IsNullOrEmpty($SERVER_IP)) {
        Write-Host "[ERROR] NO SE PUDO OBTENER IP DEL SERVIDOR" -ForegroundColor Red
        return
    }
    
    Write-Host "[INFO] IP DEL SERVIDOR: $SERVER_IP" -ForegroundColor Yellow
    
    # IDENTIFICAR INTERFAZ ACTIVA
    $adaptador = Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Name -notlike "*Loopback*"} | Select-Object -First 1
    if (-not $adaptador) {
        Write-Host "[ERROR] NO HAY INTERFACES ACTIVAS" -ForegroundColor Red
        return
    }
    
    $nombreIf = $adaptador.Name
    Write-Host "[INFO] INTERFAZ ACTIVA: $nombreIf" -ForegroundColor Yellow
    
    # CONFIGURAR DNS A SI MISMO
    try {
        Set-DnsClientServerAddress -InterfaceAlias $nombreIf -ServerAddresses $SERVER_IP
        Write-Host "[OK] DNS CONFIGURADO A $SERVER_IP EN $nombreIf" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] AL CONFIGURAR DNS: $_" -ForegroundColor Red
    }
    
    # CONFIGURAR FORWARDERS
    try {
        Add-DnsServerForwarder -IPAddress "8.8.8.8" -Force -ErrorAction SilentlyContinue
        Add-DnsServerForwarder -IPAddress "8.8.4.4" -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] FORWARDERS CONFIGURADOS (8.8.8.8, 8.8.4.4)" -ForegroundColor Green
    } catch {
        Write-Host "[AVISO] NO SE PUDO CONFIGURAR FORWARDERS" -ForegroundColor Yellow
    }
    
    # LIMPIAR CACHE
    ipconfig /flushdns | Out-Null
    ipconfig /registerdns | Out-Null
    
    Write-Host "[OK] CONFIGURACION DNS LOCAL COMPLETADA" -ForegroundColor Green
}

function Configurar-Forwarders {
    Write-Host ""
    Write-Host "=== CONFIGURANDO FORWARDERS DNS ===" -ForegroundColor Yellow
    
    try {
        Add-DnsServerForwarder -IPAddress "8.8.8.8" -Force -ErrorAction SilentlyContinue
        Add-DnsServerForwarder -IPAddress "8.8.4.4" -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] FORWARDERS CONFIGURADOS" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] AL CONFIGURAR FORWARDERS" -ForegroundColor Red
    }
}

function Crear-ZonaInversa {
    param([string]$ip)
    
    $octetos = $ip -split '\.'
    $redInversa = "$($octetos[2]).$($octetos[1]).$($octetos[0]).in-addr.arpa"
    
    Write-Host "[INFO] CREANDO ZONA INVERSA: $redInversa" -ForegroundColor Yellow
    
    try {
        $zonaInversa = Get-DnsServerZone -Name $redInversa -ErrorAction SilentlyContinue
        if (-not $zonaInversa) {
            Add-DnsServerPrimaryZone -Name $redInversa -ZoneFile "$redInversa.dns" -DynamicUpdate None
            Write-Host "[OK] ZONA INVERSA CREADA" -ForegroundColor Green
        }
    } catch {
        Write-Host "[AVISO] NO SE PUDO CREAR ZONA INVERSA" -ForegroundColor Yellow
    }
}

function Agregar-Zona {
    # OBTENER IP DEL SERVIDOR
    $SERVER_IP = Obtener-IPActual
    if ([string]::IsNullOrEmpty($SERVER_IP)) {
        $SERVER_IP = "10.10.10.1"
        Write-Host "[AVISO] USANDO IP POR DEFECTO: $SERVER_IP" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "=== AGREGAR ZONA DNS ===" -ForegroundColor Cyan
    
    $dominio = Read-Host "[?] NOMBRE DEL DOMINIO"
    if ([string]::IsNullOrEmpty($dominio)) { return }
    
    $virtualIP = ""
    while ($true) {
        $virtualIP = Read-Host "[?] IP VIRTUAL PARA $dominio"
        $resultado = Validar-IPCompleta $virtualIP
        if ($resultado -eq 0) { break }
        Write-Host "[ERROR] IP INVALIDA" -ForegroundColor Red
    }
    
    if ($virtualIP -eq $SERVER_IP) {
        Write-Host "[AVISO] USANDO LA MISMA IP DEL SERVIDOR" -ForegroundColor Yellow
    }
    
    # VERIFICAR INTERFAZ
    if ([string]::IsNullOrEmpty($global:INTERFAZ)) {
        Write-Host "[ERROR] PRIMERO DEBES SELECCIONAR UNA INTERFAZ" -ForegroundColor Red
        return
    }
    
    Write-Host ""
    Write-Host "=== CREANDO IP VIRTUAL ===" -ForegroundColor Yellow
    Crear-IPVirtual -ip $virtualIP -interfaz $global:INTERFAZ
    
    try {
        Write-Host ""
        Write-Host "=== CONFIGURANDO ZONA DNS ===" -ForegroundColor Yellow
        
        # ELIMINAR ZONA SI EXISTE
        $zonaExistente = Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue
        if ($zonaExistente) {
            Write-Host "[INFO] ZONA EXISTENTE ENCONTRADA, ELIMINANDO..." -ForegroundColor Yellow
            Remove-DnsServerZone -Name $dominio -Force
            Start-Sleep -Seconds 2
        }
        
        # CREAR ZONA DIRECTA
        Write-Host "[PASO 1] CREANDO ZONA DIRECTA: $dominio" -ForegroundColor Yellow
        Add-DnsServerPrimaryZone -Name $dominio -ZoneFile "$dominio.dns" -DynamicUpdate None
        
        # CREAR ZONA INVERSA (OPCIONAL)
        Crear-ZonaInversa -ip $virtualIP
        
        # AGREGAR REGISTROS A
        Write-Host "[PASO 2] AGREGANDO REGISTROS DNS..." -ForegroundColor Yellow
        
        Add-DnsServerResourceRecordA -Name "@" -ZoneName $dominio -IPv4Address $virtualIP -ErrorAction SilentlyContinue
        Write-Host "  [OK] REGISTRO @ -> $virtualIP" -ForegroundColor Green
        
        Add-DnsServerResourceRecordA -Name "www" -ZoneName $dominio -IPv4Address $virtualIP -ErrorAction SilentlyContinue
        Write-Host "  [OK] REGISTRO www -> $virtualIP" -ForegroundColor Green
        
        Add-DnsServerResourceRecordA -Name "mail" -ZoneName $dominio -IPv4Address $virtualIP -ErrorAction SilentlyContinue
        Write-Host "  [OK] REGISTRO mail -> $virtualIP" -ForegroundColor Green
        
        Add-DnsServerResourceRecordA -Name "ftp" -ZoneName $dominio -IPv4Address $virtualIP -ErrorAction SilentlyContinue
        Write-Host "  [OK] REGISTRO ftp -> $virtualIP" -ForegroundColor Green
        
        Add-DnsServerResourceRecordA -Name "ns1" -ZoneName $dominio -IPv4Address $SERVER_IP -ErrorAction SilentlyContinue
        Write-Host "  [OK] REGISTRO ns1 -> $SERVER_IP" -ForegroundColor Green
        
        Add-DnsServerResourceRecordA -Name "ns2" -ZoneName $dominio -IPv4Address $SERVER_IP -ErrorAction SilentlyContinue
        Write-Host "  [OK] REGISTRO ns2 -> $SERVER_IP" -ForegroundColor Green
        
        # AGREGAR REGISTRO MX
        try {
            Add-DnsServerResourceRecordMX -Name "." -ZoneName $dominio -MailExchange "mail.$dominio" -Preference 10 -ErrorAction SilentlyContinue
            Write-Host "  [OK] REGISTRO MX" -ForegroundColor Green
        } catch {
            Write-Host "  [AVISO] NO SE PUDO CREAR REGISTRO MX" -ForegroundColor Yellow
        }
        
        # AGREGAR REGISTROS NS
        try {
            Add-DnsServerResourceRecordNS -ZoneName $dominio -Name "." -NameServer "ns1.$dominio" -ErrorAction SilentlyContinue
            Add-DnsServerResourceRecordNS -ZoneName $dominio -Name "." -NameServer "ns2.$dominio" -ErrorAction SilentlyContinue
            Write-Host "  [OK] REGISTROS NS" -ForegroundColor Green
        } catch {
            Write-Host "  [AVISO] NO SE PUDO CREAR REGISTROS NS" -ForegroundColor Yellow
        }
        
        # CONFIGURAR DNS LOCAL (CRITICO PARA RESOLUCION)
        Configurar-DNSLocal
        
        # REINICIAR DNS
        Write-Host "[PASO 3] REINICIANDO SERVICIO DNS..." -ForegroundColor Yellow
        Restart-Service -Name DNS -Force
        Start-Sleep -Seconds 3
        
        Write-Host ""
        Write-Host "========================================================" -ForegroundColor Green
        Write-Host "[OK] DOMINIO CONFIGURADO: $dominio" -ForegroundColor Green
        Write-Host "[OK] IP VIRTUAL: $virtualIP" -ForegroundColor Green
        Write-Host "[OK] SERVIDOR DNS: $SERVER_IP" -ForegroundColor Green
        Write-Host "========================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "=== PRUEBAS DESDE SSH ===" -ForegroundColor Yellow
        Write-Host "  nslookup $dominio 127.0.0.1"
        Write-Host "  nslookup $dominio $SERVER_IP"
        Write-Host "  ping $dominio"
        Write-Host "========================================================" -ForegroundColor Yellow
        
    } catch {
        Write-Host "[ERROR] AL CREAR ZONA DNS: $_" -ForegroundColor Red
    }
}

function Eliminar-Zona {
    Write-Host ""
    Write-Host "=== ELIMINAR ZONA DNS ===" -ForegroundColor Cyan
    
    Write-Host "[INFO] ZONAS ACTUALES:" -ForegroundColor Yellow
    Get-DnsServerZone | Where-Object {$_.ZoneName -notlike "*msdcs*" -and $_.ZoneName -notlike "*RootHints*" -and $_.ZoneName -notlike "*in-addr.arpa*"} | 
        ForEach-Object { Write-Host "  $($_.ZoneName)" }
    
    $zonaDel = Read-Host "[?] NOMBRE DE LA ZONA A BORRAR"
    if ([string]::IsNullOrEmpty($zonaDel)) { return }
    
    $zona = Get-DnsServerZone -Name $zonaDel -ErrorAction SilentlyContinue
    if ($zona) {
        try {
            Remove-DnsServerZone -Name $zonaDel -Force
            Write-Host "[OK] ZONA ELIMINADA" -ForegroundColor Green
            Restart-Service -Name DNS -Force
        } catch {
            Write-Host "[ERROR] AL ELIMINAR ZONA: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[ERROR] ZONA NO ENCONTRADA" -ForegroundColor Red
    }
}

function Listar-Zonas {
    Write-Host ""
    Write-Host "=== DOMINIOS CONFIGURADOS ===" -ForegroundColor Cyan
    
    $zonas = Get-DnsServerZone | Where-Object {$_.ZoneName -notlike "*msdcs*" -and $_.ZoneName -notlike "*RootHints*" -and $_.ZoneName -notlike "*in-addr.arpa*"}
    if ($zonas) {
        $zonas | ForEach-Object { Write-Host "  $($_.ZoneName)" }
    } else {
        Write-Host "[AVISO] NO HAY ZONAS CONFIGURADAS" -ForegroundColor Yellow
    }
}

function Probar-DNS {
    Write-Host ""
    Write-Host "=== PRUEBA DE RESOLUCION DNS ===" -ForegroundColor Cyan
    
    $SERVER_IP = Obtener-IPActual
    if ([string]::IsNullOrEmpty($SERVER_IP)) {
        $SERVER_IP = "10.10.10.1"
    }
    
    Write-Host "[INFO] SERVIDOR DNS: $SERVER_IP" -ForegroundColor Yellow
    Write-Host ""
    
    $zonas = Get-DnsServerZone | Where-Object {$_.ZoneName -notlike "*msdcs*" -and $_.ZoneName -notlike "*RootHints*" -and $_.ZoneName -notlike "*in-addr.arpa*"}
    
    if ($zonas) {
        foreach ($zona in $zonas) {
            Write-Host "[INFO] PROBANDO: $($zona.ZoneName)" -ForegroundColor Yellow
            try {
                $resultado = Resolve-DnsName -Name $zona.ZoneName -Server $SERVER_IP -ErrorAction Stop
                Write-Host "  [OK] $($zona.ZoneName) -> $($resultado.IPAddress)" -ForegroundColor Green
            } catch {
                Write-Host "  [ERROR] NO RESUELVE" -ForegroundColor Red
            }
            
            # PROBAR www
            try {
                $resultado = Resolve-DnsName -Name "www.$($zona.ZoneName)" -Server $SERVER_IP -ErrorAction Stop
                Write-Host "  [OK] www.$($zona.ZoneName) -> $($resultado.IPAddress)" -ForegroundColor Green
            } catch {
                Write-Host "  [ERROR] www NO RESUELVE" -ForegroundColor Red
            }
            Write-Host ""
        }
    } else {
        Write-Host "[AVISO] NO HAY ZONAS PARA PROBAR" -ForegroundColor Yellow
    }
}

function Submenu-DNS {
    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "         GESTION DE DNS                " -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "1) VERIFICAR INSTALACION DNS"
        Write-Host "2) INSTALAR SERVIDOR DNS"
        Write-Host "3) AGREGAR ZONA"
        Write-Host "4) ELIMINAR ZONA"
        Write-Host "5) LISTAR ZONAS"
        Write-Host "6) REINICIAR DNS"
        Write-Host "7) CONFIGURAR DNS LOCAL"
        Write-Host "8) PROBAR RESOLUCION"
        Write-Host "9) VOLVER"
        Write-Host "========================================" -ForegroundColor Cyan
        
        $subopc = Read-Host "[?] SELECCIONE OPCION"
        switch ($subopc) {
            "1" { Verificar-InstalacionDNS; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "2" { Instalar-DNS; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "3" { Agregar-Zona; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "4" { Eliminar-Zona; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "5" { Listar-Zonas; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "6" { Reiniciar-ServicioDNS; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "7" { Configurar-DNSLocal; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "8" { Probar-DNS; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "9" { return }
            default { Write-Host "[ERROR] OPCION INVALIDA" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }
}