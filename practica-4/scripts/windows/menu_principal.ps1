# ==============================================================================
# MENU PRINCIPAL - VERSION WINDOWS SERVER 2022
# ==============================================================================

Write-Host ""
Write-Host "=== CARGANDO MODULOS ===" -ForegroundColor Yellow

. .\funciones_compartidas.ps1
. .\funciones_dhcp.ps1
. .\funciones_dns.ps1
. .\funciones_ssh.ps1

Write-Host "[OK] TODOS LOS MODULOS CARGADOS CORRECTAMENTE" -ForegroundColor Green
Start-Sleep -Seconds 2

# =========================
# FUNCIONES ADICIONALES
# =========================

function Instalar-TodosRoles {
    Write-Host ""
    Write-Host "=== INSTALANDO TODOS LOS ROLES ===" -ForegroundColor Cyan
    
    Instalar-DHCP
    Instalar-DNS
    
    Write-Host ""
    Write-Host "[OK] INSTALACION COMPLETADA" -ForegroundColor Green
    Write-Host "[AVISO] USA LA OPCION 6 PARA CONFIGURAR SSH EN INTERFAZ HOST-ONLY" -ForegroundColor Yellow
}

function Activar-TodasInterfaces {
    Write-Host ""
    Write-Host "=== ACTIVANDO TODAS LAS INTERFACES ===" -ForegroundColor Cyan
    Activar-InterfacesRed
    Activar-InterfazHostOnly
}

function Configurar-IPEstatica {
    if ([string]::IsNullOrEmpty($global:INTERFAZ) -or $global:INTERFAZ -eq "PENDIENTE") {
        Write-Host ""
        Write-Host "[ERROR] PRIMERO DEBES SELECCIONAR UNA INTERFAZ" -ForegroundColor Red
        Seleccionar-Interfaz
    }
    
    $CURRENT_IP = Obtener-IPActual
    Write-Host ""
    Write-Host "=== CONFIGURACION IP ESTATICA ($global:INTERFAZ) ===" -ForegroundColor Cyan
    if ($CURRENT_IP) {
        Write-Host "[INFO] IP ACTUAL: $CURRENT_IP" -ForegroundColor Yellow
    } else {
        Write-Host "[INFO] IP ACTUAL: NINGUNA" -ForegroundColor Yellow
    }
    Write-Host ""
    
    $nuevaIP = Read-Host "[?] INGRESE IP ESTATICA"
    $resultado = Validar-IPCompleta $nuevaIP
    if ($resultado -ne 0) {
        Write-Host "[ERROR] IP INVALIDA" -ForegroundColor Red
        return
    }
    
    # VALIDAR QUE NO SEA DIRECCION DE RED (TERMINE EN .0)
    $ultimoOcteto = [int]($nuevaIP -split '\.')[3]
    if ($ultimoOcteto -eq 0) {
        Write-Host "[ERROR] LA IP $nuevaIP ES DIRECCION DE RED (TERMINA EN .0)" -ForegroundColor Red
        Write-Host "[AVISO] USA UNA IP VALIDA COMO 10.10.10.1, 192.168.1.1, ETC." -ForegroundColor Yellow
        return
    }
    
    # VALIDAR QUE NO SEA DIRECCION DE BROADCAST (TERMINE EN .255)
    if ($ultimoOcteto -eq 255) {
        Write-Host "[ERROR] LA IP $nuevaIP ES DIRECCION DE BROADCAST (TERMINA EN .255)" -ForegroundColor Red
        return
    }
    
    Write-Host "[INFO] APLICANDO CONFIGURACION..." -ForegroundColor Yellow
    
    try {
        # ELIMINAR CONFIGURACION IP EXISTENTE
        Remove-NetIPAddress -InterfaceAlias $global:INTERFAZ -Confirm:$false -ErrorAction SilentlyContinue
        
        # ASIGNAR NUEVA IP
        New-NetIPAddress -InterfaceAlias $global:INTERFAZ -IPAddress $nuevaIP -PrefixLength 24 -ErrorAction Stop
        
        # ACTIVAR INTERFAZ
        Enable-NetAdapter -Name $global:INTERFAZ -Confirm:$false
        
        Write-Host "[OK] IP $nuevaIP ASIGNADA A $global:INTERFAZ" -ForegroundColor Green
        
        # CONFIGURAR DNS LOCAL DESPUES DE ASIGNAR IP
        Write-Host ""
        Write-Host "[INFO] CONFIGURANDO DNS LOCAL..." -ForegroundColor Yellow
        Set-DnsClientServerAddress -InterfaceAlias $global:INTERFAZ -ServerAddresses $nuevaIP -ErrorAction SilentlyContinue
        Write-Host "[OK] DNS CONFIGURADO A $nuevaIP" -ForegroundColor Green
        
    } catch {
        Write-Host "[ERROR] AL CONFIGURAR IP: $_" -ForegroundColor Red
    }
}

function Verificar-Instalacion {
    Write-Host ""
    Write-Host "=== VERIFICACION COMPLETA ===" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "[INFO] INTERFACES DE RED:" -ForegroundColor Yellow
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*"} | 
        ForEach-Object { Write-Host "  $($_.InterfaceAlias): $($_.IPAddress)" }
    
    Write-Host ""
    Write-Host "[INFO] CONFIGURACION DNS:" -ForegroundColor Yellow
    Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses -ne $null} | 
        ForEach-Object { Write-Host "  $($_.InterfaceAlias): $($_.ServerAddresses)" }
    
    Write-Host ""
    Write-Host "[INFO] ROLES INSTALADOS:" -ForegroundColor Yellow
    $dhcp = Get-WindowsFeature -Name DHCP
    if ($dhcp.Installed) { Write-Host "  DHCP: [OK] INSTALADO" -ForegroundColor Green } else { Write-Host "  DHCP: [X] NO" -ForegroundColor Red }
    
    $dns = Get-WindowsFeature -Name DNS
    if ($dns.Installed) { Write-Host "  DNS: [OK] INSTALADO" -ForegroundColor Green } else { Write-Host "  DNS: [X] NO" -ForegroundColor Red }
    
    $ssh = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($ssh.State -eq "Installed") { Write-Host "  SSH: [OK] INSTALADO" -ForegroundColor Green } else { Write-Host "  SSH: [X] NO" -ForegroundColor Red }
    
    Write-Host ""
    Write-Host "[INFO] ESTADO DE SERVICIOS:" -ForegroundColor Yellow
    $dhcpService = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($dhcpService -and $dhcpService.Status -eq "Running") { Write-Host "  DHCP: [OK] ACTIVO" -ForegroundColor Green } else { Write-Host "  DHCP: [X] INACTIVO" -ForegroundColor Red }
    
    $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
    if ($dnsService -and $dnsService.Status -eq "Running") { Write-Host "  DNS: [OK] ACTIVO" -ForegroundColor Green } else { Write-Host "  DNS: [X] INACTIVO" -ForegroundColor Red }
    
    $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($sshService -and $sshService.Status -eq "Running") { Write-Host "  SSH: [OK] ACTIVO" -ForegroundColor Green } else { Write-Host "  SSH: [X] INACTIVO" -ForegroundColor Red }
}

function Mostrar-Instrucciones {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "               INSTRUCCIONES FINALES                     " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. CONFIGURA EL ADAPTADOR 3 EN VIRTUALBOX COMO 'SOLO ANFITRION'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "2. USA OPCION 2a PARA ACTIVAR TODAS LAS INTERFACES" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "3. USA OPCION 6 PARA CONFIGURAR SSH EN INTERFAZ HOST-ONLY" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "4. CONECTATE DESDE WINDOWS: ssh USUARIO@192.168.56.10" -ForegroundColor Green
    Write-Host ""
    Write-Host "5. CONFIGURA IP ESTATICA EN INTERFAZ INTERNA (EJ. 10.10.10.1)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "6. INSTALA DHCP Y DNS CON OPCION 2" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "7. CONFIGURA DHCP CON OPCION 4" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "8. AGREGA DOMINIOS CON OPCION 5" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "9. SI HAY PROBLEMAS CON DNS USA OPCION 8a" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "10. PRUEBAS DESDE SSH:" -ForegroundColor Yellow
    Write-Host "    nslookup midominio.com"
    Write-Host "    ping midominio.com"
    Write-Host "==========================================================" -ForegroundColor Cyan
}

function Reparar-DNS {
    Write-Host ""
    Write-Host "=== REPARANDO CONFIGURACION DNS ===" -ForegroundColor Cyan
    
    $SERVER_IP = Obtener-IPActual
    if ([string]::IsNullOrEmpty($SERVER_IP)) {
        # INTENTAR OBTENER IP DE INTERFAZ INTERNA
        if (-not [string]::IsNullOrEmpty($global:INTERFAZ) -and $global:INTERFAZ -ne "PENDIENTE") {
            $ip = Get-NetIPAddress -InterfaceAlias $global:INTERFAZ -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ip) {
                $SERVER_IP = $ip.IPAddress
            }
        }
    }
    
    if ([string]::IsNullOrEmpty($SERVER_IP)) {
        $SERVER_IP = "10.10.10.1"
        Write-Host "[AVISO] USANDO IP POR DEFECTO: $SERVER_IP" -ForegroundColor Yellow
    }
    
    Write-Host "[INFO] IP DEL SERVIDOR: $SERVER_IP" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "[PASO 1] IDENTIFICANDO INTERFAZ ACTIVA..." -ForegroundColor Yellow
    $adaptador = Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Name -notlike "*Loopback*"} | Select-Object -First 1
    if ($adaptador) {
        $nombreIf = $adaptador.Name
        Write-Host "   [OK] INTERFAZ ENCONTRADA: $nombreIf" -ForegroundColor Green
        
        Write-Host "[PASO 2] CONFIGURANDO DNS LOCAL EN $nombreIf..." -ForegroundColor Yellow
        Set-DnsClientServerAddress -InterfaceAlias $nombreIf -ServerAddresses $SERVER_IP -ErrorAction SilentlyContinue
        Write-Host "   [OK] DNS CONFIGURADO A $SERVER_IP" -ForegroundColor Green
    } else {
        Write-Host "   [ERROR] NO HAY INTERFACES ACTIVAS" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "[PASO 3] CONFIGURANDO FORWARDERS DNS..." -ForegroundColor Yellow
    try {
        Add-DnsServerForwarder -IPAddress "8.8.8.8" -Force -ErrorAction SilentlyContinue
        Add-DnsServerForwarder -IPAddress "8.8.4.4" -Force -ErrorAction SilentlyContinue
        Write-Host "   [OK] FORWARDERS CONFIGURADOS (8.8.8.8, 8.8.4.4)" -ForegroundColor Green
    } catch {
        Write-Host "   [AVISO] NO SE PUDO CONFIGURAR FORWARDERS" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "[PASO 4] LIMPIANDO CACHE DNS..." -ForegroundColor Yellow
    ipconfig /flushdns | Out-Null
    ipconfig /registerdns | Out-Null
    Write-Host "   [OK] CACHE LIMPIO" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "[PASO 5] REINICIANDO SERVICIO DNS..." -ForegroundColor Yellow
    Restart-Service -Name DNS -Force
    Start-Sleep -Seconds 5
    Write-Host "   [OK] DNS REINICIADO" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "[PASO 6] VERIFICANDO SERVICIO DNS..." -ForegroundColor Yellow
    $service = Get-Service -Name DNS
    if ($service.Status -eq "Running") {
        Write-Host "   [OK] SERVICIO DNS ACTIVO" -ForegroundColor Green
    } else {
        Write-Host "   [ERROR] SERVICIO DNS INACTIVO" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "[INFO] PRUEBA DE RESOLUCION:" -ForegroundColor Yellow
    
    try {
        $zonas = Get-DnsServerZone | Where-Object {$_.ZoneName -notlike "*msdcs*" -and $_.ZoneName -notlike "*RootHints*" -and $_.ZoneName -notlike "*in-addr.arpa*"}
        if ($zonas) {
            foreach ($zona in $zonas) {
                try {
                    $resultado = Resolve-DnsName -Name $zona.ZoneName -Server $SERVER_IP -ErrorAction SilentlyContinue
                    if ($resultado) {
                        Write-Host "  $($zona.ZoneName): [OK] $($resultado.IPAddress)" -ForegroundColor Green
                    } else {
                        Write-Host "  $($zona.ZoneName): [ERROR] NO RESUELVE" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "  $($zona.ZoneName): [ERROR] NO RESUELVE" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "  [AVISO] NO HAY ZONAS CONFIGURADAS" -ForegroundColor Yellow
            Write-Host "  [INFO] USA OPCION 5 PARA AGREGAR UN DOMINIO" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [ERROR] AL VERIFICAR ZONAS: $_" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "[INFO] PRUEBA MANUAL DESDE SSH:" -ForegroundColor Cyan
    Write-Host "  nslookup midominio.com $SERVER_IP" -ForegroundColor Green
    Write-Host "  ping midominio.com" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Cyan
}

# =========================
# VERIFICACION INICIAL
# =========================

Check-Admin

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   GESTOR DE INFRAESTRUCTURA - WINDOWS SERVER            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$selInterfaz = Read-Host "[?] SELECCIONAR INTERFAZ INTERNA AHORA? (S/N)"
if ($selInterfaz -eq "S" -or $selInterfaz -eq "s") {
    Seleccionar-Interfaz
} else {
    $global:INTERFAZ = "PENDIENTE"
}

while ($true) {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "               MENU PRINCIPAL                            " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    if ($global:INTERFAZ -and $global:INTERFAZ -ne "PENDIENTE") {
        Write-Host "[INFO] INTERFAZ INTERNA: $global:INTERFAZ" -ForegroundColor Yellow
    } else {
        Write-Host "[INFO] INTERFAZ INTERNA: NO DEFINIDA" -ForegroundColor Red
    }
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1)  VERIFICAR INSTALACION"
    Write-Host "  2)  INSTALAR TODOS LOS ROLES (DHCP Y DNS)"
    Write-Host "  2a) ACTIVAR TODAS LAS INTERFACES (ETHERNET2 Y HOST-ONLY)"
    Write-Host ""
    Write-Host "  3)  CONFIGURAR IP ESTATICA"
    Write-Host "  4)  CONFIGURAR SERVIDOR DHCP"
    Write-Host "  5)  GESTION DE DOMINIOS DNS"
    Write-Host "  6)  CONFIGURAR SSH EN HOST-ONLY"
    Write-Host ""
    Write-Host "  7)  VER INSTRUCCIONES FINALES"
    Write-Host "  8)  SELECCIONAR INTERFAZ"
    Write-Host "  8a) REPARAR CONFIGURACION DNS"
    Write-Host "  9)  SALIR"
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    
    $MAIN_OPC = Read-Host "[?] SELECCIONE OPCION"
    
    switch ($MAIN_OPC) {
        "1" { Verificar-Instalacion; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "2" { Instalar-TodosRoles; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "2a" { Activar-TodasInterfaces; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "3" { Configurar-IPEstatica; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "4" { Configurar-DHCP; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "5" { Submenu-DNS }
        "6" { Submenu-SSH }
        "7" { Mostrar-Instrucciones; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "8" { Seleccionar-Interfaz; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "8a" { Reparar-DNS; Read-Host "[INFO] PRESIONE ENTER PARA CONTINUAR..." }
        "9" { Write-Host "[OK] HASTA LUEGO" -ForegroundColor Green; exit 0 }
        default { Write-Host "[ERROR] OPCION INVALIDA" -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}