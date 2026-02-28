# ==============================================================================
# FUNCIONES SSH - VERSION WINDOWS SERVER 2022
# ==============================================================================

. .\funciones_compartidas.ps1

function Buscar-InterfazHostOnly {
    Write-Host ""
    Write-Host "=== BUSCANDO INTERFAZ HOST-ONLY ===" -ForegroundColor Yellow
    
    # BUSCAR POR NOMBRES COMUNES EN VIRTUALBOX
    $posiblesNombres = @(
        "Ethernet 3",
        "Ethernet3",
        "Ethernet 2",
        "Ethernet2",
        "Host-Only",
        "VirtualBox Host-Only Ethernet Adapter"
    )
    
    foreach ($nombre in $posiblesNombres) {
        $adapter = Get-NetAdapter -Name $nombre -ErrorAction SilentlyContinue
        if ($adapter) {
            Write-Host "[OK] ENCONTRADA INTERFAZ: $nombre" -ForegroundColor Green
            return $adapter
        }
    }
    
    # SI NO ENCUENTRA POR NOMBRE, BUSCAR POR DESCRIPCION
    Write-Host "[INFO] BUSCANDO POR DESCRIPCION DE ADAPTADOR..." -ForegroundColor Yellow
    $adapters = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*VirtualBox*" -or $_.InterfaceDescription -like "*Host-Only*"}
    
    if ($adapters) {
        Write-Host "[OK] INTERFACES VIRTUALBOX ENCONTRADAS:" -ForegroundColor Green
        $adapters | ForEach-Object { Write-Host "  $($_.Name) - $($_.InterfaceDescription)" }
        
        # USAR LA PRIMERA ENCONTRADA
        return $adapters[0]
    }
    
    # MOSTRAR TODAS LAS INTERFACES DISPONIBLES
    Write-Host "[AVISO] NO SE ENCONTRO INTERFAZ HOST-ONLY. INTERFACES DISPONIBLES:" -ForegroundColor Yellow
    Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object { 
        Write-Host "  $($_.Name) - $($_.InterfaceDescription)" 
    }
    
    # PREGUNTAR AL USUARIO
    $nombreManual = Read-Host "[?] INGRESE EL NOMBRE EXACTO DE LA INTERFAZ HOST-ONLY"
    if (-not [string]::IsNullOrEmpty($nombreManual)) {
        $adapter = Get-NetAdapter -Name $nombreManual -ErrorAction SilentlyContinue
        if ($adapter) {
            return $adapter
        }
    }
    
    return $null
}

function Verificar-InstalacionSSH {
    Write-Host ""
    Write-Host "=== VERIFICANDO SERVICIO SSH ===" -ForegroundColor Cyan
    
    $ssh = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    
    if ($ssh.State -eq "Installed") {
        Write-Host "[OK] OPENSSH SERVER INSTALADO" -ForegroundColor Green
    } else {
        Write-Host "[X] OPENSSH SERVER NO INSTALADO" -ForegroundColor Red
        return $false
    }
    
    $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($sshService) {
        if ($sshService.Status -eq "Running") {
            Write-Host "[OK] SERVICIO SSH ACTIVO" -ForegroundColor Green
        } else {
            Write-Host "[X] SERVICIO SSH INACTIVO" -ForegroundColor Red
        }
    } else {
        Write-Host "[X] SERVICIO SSH NO DISPONIBLE" -ForegroundColor Red
    }
    
    return $true
}

function Activar-InterfazHostOnly {
    Write-Host ""
    Write-Host "=== ACTIVANDO INTERFAZ HOST-ONLY (MODO FORZADO) ===" -ForegroundColor Cyan
    
    $adapter = Buscar-InterfazHostOnly
    if (-not $adapter) {
        Write-Host "[ERROR] NO SE ENCONTRO INTERFAZ HOST-ONLY" -ForegroundColor Red
        return $false
    }
    
    $nombreInterfaz = $adapter.Name
    Write-Host "[INFO] TRABAJANDO CON INTERFAZ: $nombreInterfaz" -ForegroundColor Green
    
    Write-Host "[PASO 1] DERRIBANDO ${nombreInterfaz}..." -ForegroundColor Yellow
    Disable-NetAdapter -Name $nombreInterfaz -Confirm:$false
    Start-Sleep -Seconds 2
    
    Write-Host "[PASO 2] ACTIVANDO ${nombreInterfaz}..." -ForegroundColor Yellow
    Enable-NetAdapter -Name $nombreInterfaz -Confirm:$false
    Start-Sleep -Seconds 2
    
    Write-Host "[PASO 3] REACTIVANDO ${nombreInterfaz}..." -ForegroundColor Yellow
    Enable-NetAdapter -Name $nombreInterfaz -Confirm:$false
    Start-Sleep -Seconds 2
    
    Write-Host "[PASO 4] ASIGNANDO IP 192.168.56.69..." -ForegroundColor Yellow
    Remove-NetIPAddress -InterfaceAlias $nombreInterfaz -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $nombreInterfaz -IPAddress 192.168.56.69 -PrefixLength 24 -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    Write-Host "[PASO 5] VERIFICANDO ESTADO..." -ForegroundColor Yellow
    $adapter = Get-NetAdapter -Name $nombreInterfaz
    if ($adapter.Status -eq "Up") {
        Write-Host "[OK] ${nombreInterfaz} ACTIVADA" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] NO SE PUDO ACTIVAR ${nombreInterfaz}" -ForegroundColor Red
        return $false
    }
    
    Write-Host "[PASO 6] VERIFICANDO IP..." -ForegroundColor Yellow
    $ip = Get-NetIPAddress -InterfaceAlias $nombreInterfaz -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ip -and $ip.IPAddress -eq "192.168.56.69") {
        Write-Host "[OK] IP 192.168.56.69 ASIGNADA" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] IP NO ASIGNADA" -ForegroundColor Red
        return $false
    }
    
    Write-Host "[PASO 7] VERIFICANDO RUTAS..." -ForegroundColor Yellow
    $route = Get-NetRoute -InterfaceAlias $nombreInterfaz -DestinationPrefix "192.168.56.0/24" -ErrorAction SilentlyContinue
    if ($route) {
        Write-Host "[OK] RUTA CONFIGURADA" -ForegroundColor Green
    } else {
        Write-Host "[AVISO] RUTA NO CONFIGURADA, AGREGANDO..." -ForegroundColor Yellow
        New-NetRoute -DestinationPrefix "192.168.56.0/24" -InterfaceAlias $nombreInterfaz -NextHop "0.0.0.0" -ErrorAction SilentlyContinue
    }
    
    return $true
}

function Verificar-InterfazHostOnly {
    Write-Host ""
    Write-Host "=== VERIFICACION COMPLETA DE INTERFAZ HOST-ONLY ===" -ForegroundColor Cyan
    
    $adapter = Buscar-InterfazHostOnly
    if (-not $adapter) {
        Write-Host "[ERROR] NO SE ENCONTRO INTERFAZ HOST-ONLY" -ForegroundColor Red
        return
    }
    
    $nombreInterfaz = $adapter.Name
    Write-Host ""
    Write-Host "[INFO] ESTADO DE LA INTERFAZ ${nombreInterfaz}:" -ForegroundColor Yellow
    $adapterInfo = Get-NetAdapter -Name $nombreInterfaz
    if ($adapterInfo) {
        Write-Host "  NOMBRE: $($adapterInfo.Name)"
        Write-Host "  ESTADO: $($adapterInfo.Status)"
        Write-Host "  DESCRIPCION: $($adapterInfo.InterfaceDescription)"
        Write-Host "  VELOCIDAD: $($adapterInfo.LinkSpeed)"
    }
    
    Write-Host ""
    Write-Host "[INFO] DIRECCIONES IP:" -ForegroundColor Yellow
    $ips = Get-NetIPAddress -InterfaceAlias $nombreInterfaz -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ips) {
        $ips | ForEach-Object { Write-Host "  $($_.IPAddress)" }
    } else {
        Write-Host "  [ERROR] SIN IP ASIGNADA" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "[INFO] RUTAS:" -ForegroundColor Yellow
    $routes = Get-NetRoute -InterfaceAlias $nombreInterfaz -ErrorAction SilentlyContinue
    if ($routes) {
        $routes | ForEach-Object { Write-Host "  $($_.DestinationPrefix)" }
    } else {
        Write-Host "  [AVISO] SIN RUTAS" -ForegroundColor Yellow
    }
}

function Instalar-SSH {
    Write-Host ""
    Write-Host "=== INSTALANDO OPENSSH SERVER ===" -ForegroundColor Yellow
    
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        
        if ($?) {
            Write-Host "[OK] INSTALACION SSH COMPLETADA" -ForegroundColor Green
            
            # CONFIGURAR SERVICIO PARA INICIO AUTOMATICO
            Set-Service -Name sshd -StartupType Automatic
            Start-Service -Name sshd
            Write-Host "[OK] SERVICIO SSH CONFIGURADO Y INICIADO" -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] EN LA INSTALACION SSH: $_" -ForegroundColor Red
    }
}

function Configurar-SSHHostOnly {
    Write-Host ""
    Write-Host "=== CONFIGURACION DE SSH EN INTERFAZ HOST-ONLY ===" -ForegroundColor Cyan
    
    $adapter = Buscar-InterfazHostOnly
    if (-not $adapter) {
        Write-Host "[ERROR] NO SE ENCONTRO INTERFAZ HOST-ONLY" -ForegroundColor Red
        Write-Host "[AVISO] VERIFICA QUE EN VIRTUALBOX TENGAS UN ADAPTADOR CONFIGURADO COMO 'SOLO ANFITRION'" -ForegroundColor Yellow
        return $false
    }
    
    $nombreInterfaz = $adapter.Name
    Write-Host "[OK] INTERFAZ ENCONTRADA: $nombreInterfaz" -ForegroundColor Green
    
    Activar-InterfazHostOnly
    if (-not $?) {
        Write-Host "[ERROR] NO SE PUDO ACTIVAR LA INTERFAZ" -ForegroundColor Red
        return $false
    }
    
    Write-Host "[INFO] VERIFICANDO INSTALACION SSH..." -ForegroundColor Yellow
    $ssh = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($ssh.State -ne "Installed") {
        Instalar-SSH
    }
    
    Write-Host "[INFO] CONFIGURANDO SSHD..." -ForegroundColor Yellow
    
    # CONFIGURAR REGLAS DE FIREWALL
    New-NetFirewallRule -DisplayName "OpenSSH Server (sshd)" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -ErrorAction SilentlyContinue
    
    # CONFIGURAR SSH PARA PERMITIR ACCESO
    $sshdConfig = "$env:ProgramData\ssh\sshd_config"
    if (Test-Path $sshdConfig) {
        $config = Get-Content $sshdConfig
        $config = $config -replace '#PermitRootLogin .*', 'PermitRootLogin yes'
        $config = $config -replace '#PasswordAuthentication .*', 'PasswordAuthentication yes'
        $config | Set-Content $sshdConfig
    }
    
    Write-Host "[INFO] CONFIGURACION PERMANENTE EN RED..." -ForegroundColor Yellow
    
    Write-Host "[INFO] REINICIANDO SERVICIO SSH..." -ForegroundColor Yellow
    Restart-Service -Name sshd -Force
    Start-Sleep -Seconds 3
    
    Activar-InterfazHostOnly
    
    Write-Host ""
    Write-Host "=== VERIFICACION FINAL ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[INFO] ESTADO INTERFAZ HOST-ONLY:" -ForegroundColor Yellow
    $adapter = Get-NetAdapter -Name $nombreInterfaz
    if ($adapter.Status -eq "Up") { 
        Write-Host "  [OK] INTERFAZ ACTIVA" -ForegroundColor Green
    } else { 
        Write-Host "  [ERROR] INTERFAZ INACTIVA" -ForegroundColor Red
    }
    
    $ip = Get-NetIPAddress -InterfaceAlias $nombreInterfaz -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($ip -and $ip.IPAddress -eq "192.168.56.69") { 
        Write-Host "  [OK] IP CORRECTA (192.168.56.69)" -ForegroundColor Green
    } else { 
        if ($ip) {
            Write-Host "  [AVISO] IP ASIGNADA: $($ip.IPAddress) (SE ESPERABA 192.168.56.69)" -ForegroundColor Yellow
        } else {
            Write-Host "  [ERROR] IP NO ASIGNADA" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "[INFO] ESTADO SSH:" -ForegroundColor Yellow
    $sshService = Get-Service -Name sshd
    if ($sshService.Status -eq "Running") { 
        Write-Host "  [OK] SERVICIO SSH ACTIVO" -ForegroundColor Green
    } else { 
        Write-Host "  [ERROR] SERVICIO SSH INACTIVO" -ForegroundColor Red
    }
    
    $listening = Get-NetTCPConnection -LocalPort 22 -ErrorAction SilentlyContinue
    if ($listening) { 
        Write-Host "  [OK] PUERTO 22 ESCUCHANDO" -ForegroundColor Green
    } else { 
        Write-Host "  [ERROR] PUERTO 22 NO ESCUCHA" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "[OK] SSH CONFIGURADO EN INTERFAZ HOST-ONLY" -ForegroundColor Green
    Write-Host "[INFO] INTERFAZ: $nombreInterfaz" -ForegroundColor Green
    Write-Host "[INFO] IP: 192.168.56.69" -ForegroundColor Green
    Write-Host "[INFO] USUARIO: $env:USERNAME" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "=== PRUEBA DESDE POWERSHELL (HOST) ===" -ForegroundColor Yellow
    Write-Host "  ssh $env:USERNAME@192.168.56.69"
    Write-Host ""
    Write-Host "=== SI NO FUNCIONA, VERIFICA ===" -ForegroundColor Yellow
    Write-Host "  1. LA IP DEL ADAPTADOR HOST-ONLY EN VIRTUALBOX DEBE SER 192.168.56.1" -ForegroundColor Yellow
    Write-Host "  2. EJECUTA: ipconfig EN WINDOWS PARA VER LA IP DE VIRTUALBOX HOST-ONLY" -ForegroundColor Yellow
    Write-Host "  3. PRUEBA: ping 192.168.56.69 DESDE EL HOST" -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Submenu-SSH {
    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "         GESTION DE SSH                 " -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "1) VERIFICAR ESTADO DE SSH"
        Write-Host "2) ACTIVAR INTERFAZ HOST-ONLY (MODO FORZADO)"
        Write-Host "3) VERIFICAR ESTADO DE INTERFAZ HOST-ONLY"
        Write-Host "4) CONFIGURAR SSH EN HOST-ONLY"
        Write-Host "5) VOLVER"
        Write-Host "========================================" -ForegroundColor Cyan
        
        $subopc = Read-Host "[?] SELECCIONE OPCION"
        switch ($subopc) {
            "1" { Verificar-InstalacionSSH; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "2" { Activar-InterfazHostOnly; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "3" { Verificar-InterfazHostOnly; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "4" { Configurar-SSHHostOnly; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
            "5" { return }
            default { Write-Host "[ERROR] OPCION INVALIDA" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }
}