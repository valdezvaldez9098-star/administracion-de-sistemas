# ==============================================
#        DNS AUTOMATIZADO - RED_SISTEMAS
#        Windows Server 2022
# ==============================================

$Adaptador = "Ethernet 2"

function Pause {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar"
}

# ---------------- VALIDAR IP ----------------

function Validar-IP {
    param($ip)

    if ($ip -match "^([0-9]{1,3}\.){3}[0-9]{1,3}$") {
        $octetos = $ip.Split(".")
        foreach ($o in $octetos) {
            if ([int]$o -gt 255) { return $false }
        }
        return $true
    }
    return $false
}

# ---------------- OBTENER IP SERVIDOR ----------------

function Obtener-IPServidor {

    $config = Get-NetIPAddress -InterfaceAlias $Adaptador -AddressFamily IPv4 |
              Where-Object { $_.PrefixOrigin -eq "Manual" }

    if (!$config) {
        Write-Host "ERROR: El servidor no tiene IP fija configurada."
        Pause
        return $null
    }

    return $config.IPAddress
}

# ---------------- ESTADO DNS ----------------

function Estado-DNS {

    Write-Host "===== ESTADO DNS ====="

    $feature = Get-WindowsFeature DNS
    if ($feature.Installed) {
        Write-Host "Rol DNS: INSTALADO"
    } else {
        Write-Host "Rol DNS: NO instalado"
    }

    $service = Get-Service DNS -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "Servicio DNS: ACTIVO"
    } else {
        Write-Host "Servicio DNS: INACTIVO"
    }

    Pause
}

# ---------------- INSTALAR / REINSTALAR DNS ----------------

function Instalar-DNS {

    Write-Host "===== INSTALAR / REINSTALAR DNS ====="

    $feature = Get-WindowsFeature DNS

    if ($feature.Installed) {
        Write-Host "DNS ya está instalado. Reinstalando silenciosamente..."
        Uninstall-WindowsFeature DNS -Remove -ErrorAction SilentlyContinue
    }

    Install-WindowsFeature DNS -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
    Restart-Service DNS -ErrorAction SilentlyContinue

    Write-Host "Proceso completado."
    Pause
}

# ---------------- RECONFIGURAR REPROBADOS.COM ----------------

function Configurar-Reprobados {

    $Dominio = "reprobados.com"
    $IPServidor = Obtener-IPServidor

    if (!$IPServidor) { return }

    if (!(Validar-IP $IPServidor)) {
        Write-Host "IP inválida."
        Pause
        return
    }

    if (!(Get-DnsServerZone -Name $Dominio -ErrorAction SilentlyContinue)) {

        Add-DnsServerPrimaryZone `
            -Name $Dominio `
            -ZoneFile "$Dominio.dns" `
            -DynamicUpdate None

        Write-Host "Zona creada."
    }

    # Eliminar registros A existentes
    Get-DnsServerResourceRecord -ZoneName $Dominio -RRType "A" -ErrorAction SilentlyContinue |
        Remove-DnsServerResourceRecord -ZoneName $Dominio -Force -ErrorAction SilentlyContinue

    # Crear registros actualizados
    Add-DnsServerResourceRecordA -ZoneName $Dominio -Name "@" -IPv4Address $IPServidor
    Add-DnsServerResourceRecordA -ZoneName $Dominio -Name "www" -IPv4Address $IPServidor

    Restart-Service DNS

    Write-Host "reprobados.com configurado con IP $IPServidor"
    Pause
}

# ---------------- ADMINISTRAR DOMINIOS ----------------

function Administrar-Dominios {

    Write-Host "===== ADMINISTRAR DOMINIOS ====="
    Write-Host "A) Agregar dominio"
    Write-Host "B) Eliminar dominio"
    Write-Host "C) Listar dominios"
    Write-Host "D) Reconfigurar reprobados.com (IP automática del servidor)"

    $op = Read-Host "Opción"

    switch ($op.ToUpper()) {

        # -------- AGREGAR --------
        "A" {

            $Dominio = Read-Host "Nombre del dominio (ej: empresa.com o empresa.local)"
            $IPAsignada = Read-Host "IP que se asignará al dominio"

            if (!(Validar-IP $IPAsignada)) {
                Write-Host "IP inválida."
                Pause
                return
            }

            if (Get-DnsServerZone -Name $Dominio -ErrorAction SilentlyContinue) {
                Write-Host "La zona ya existe."
                Pause
                return
            }

            Add-DnsServerPrimaryZone `
                -Name $Dominio `
                -ZoneFile "$Dominio.dns" `
                -DynamicUpdate None

            Add-DnsServerResourceRecordA `
                -ZoneName $Dominio `
                -Name "@" `
                -IPv4Address $IPAsignada

            Add-DnsServerResourceRecordA `
                -ZoneName $Dominio `
                -Name "www" `
                -IPv4Address $IPAsignada

            Restart-Service DNS

            Write-Host "Dominio $Dominio creado correctamente."
            Pause
        }

        # -------- ELIMINAR --------
        "B" {

            $DominioEliminar = Read-Host "Nombre del dominio a eliminar (.com o .local)"

            if (Get-DnsServerZone -Name $DominioEliminar -ErrorAction SilentlyContinue) {
                Remove-DnsServerZone -Name $DominioEliminar -Force
                Write-Host "Dominio eliminado correctamente."
            }
            else {
                Write-Host "El dominio no existe."
            }

            Pause
        }

        # -------- LISTAR --------
        "C" {

            Write-Host ""
            Write-Host "Zonas configuradas:"
            Get-DnsServerZone | Format-Table ZoneName, ZoneType -AutoSize
            Pause
        }

        # -------- REPROBADOS --------
        "D" {
            Configurar-Reprobados
        }

        default {
            Write-Host "Opción inválida."
            Pause
        }
    }
}

# ---------------- MONITOREO ----------------

function Monitorear-DNS {

    Write-Host "===== MONITOREO DNS ====="

    if ((Get-Service DNS).Status -ne "Running") {
        Start-Service DNS
    }

    Write-Host ""
    Write-Host "Zonas configuradas:"
    Get-DnsServerZone | Format-Table -AutoSize

    Pause
}

# ---------------- MENU ----------------

while ($true) {

    Clear-Host
    Write-Host "====== MENU DNS (Windows Server 2022) ======"
    Write-Host "1) Ver estado del servicio"
    Write-Host "2) Instalar / Reinstalar DNS"
    Write-Host "3) Administrar dominios (ABC)"
    Write-Host "4) Monitorear"
    Write-Host "5) Salir"

    $op = Read-Host "Opción"

    switch ($op) {
        1 { Estado-DNS }
        2 { Instalar-DNS }
        3 { Administrar-Dominios }
        4 { Monitorear-DNS }
        5 { exit }
        default { Write-Host "Opción inválida"; Pause }
    }
}# ==============================================
#        DNS AUTOMATIZADO - RED_SISTEMAS
#        Windows Server 2022
# ==============================================

$Adaptador = "Ethernet 2"

function Pause {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar"
}

# ---------------- VALIDAR IP ----------------

function Validar-IP {
    param($ip)

    if ($ip -match "^([0-9]{1,3}\.){3}[0-9]{1,3}$") {
        $octetos = $ip.Split(".")
        foreach ($o in $octetos) {
            if ([int]$o -gt 255) { return $false }
        }
        return $true
    }
    return $false
}

# ---------------- OBTENER IP SERVIDOR ----------------

function Obtener-IPServidor {

    $config = Get-NetIPAddress -InterfaceAlias $Adaptador -AddressFamily IPv4 |
              Where-Object { $_.PrefixOrigin -eq "Manual" }

    if (!$config) {
        Write-Host "ERROR: El servidor no tiene IP fija configurada."
        Pause
        return $null
    }

    return $config.IPAddress
}

# ---------------- ESTADO DNS ----------------

function Estado-DNS {

    Write-Host "===== ESTADO DNS ====="

    $feature = Get-WindowsFeature DNS
    if ($feature.Installed) {
        Write-Host "Rol DNS: INSTALADO"
    } else {
        Write-Host "Rol DNS: NO instalado"
    }

    $service = Get-Service DNS -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "Servicio DNS: ACTIVO"
    } else {
        Write-Host "Servicio DNS: INACTIVO"
    }

    Pause
}

# ---------------- INSTALAR / REINSTALAR DNS ----------------

function Instalar-DNS {

    Write-Host "===== INSTALAR / REINSTALAR DNS ====="

    $feature = Get-WindowsFeature DNS

    if ($feature.Installed) {
        Write-Host "DNS ya está instalado. Reinstalando silenciosamente..."
        Uninstall-WindowsFeature DNS -Remove -ErrorAction SilentlyContinue
    }

    Install-WindowsFeature DNS -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
    Restart-Service DNS -ErrorAction SilentlyContinue

    Write-Host "Proceso completado."
    Pause
}

# ---------------- RECONFIGURAR REPROBADOS.COM ----------------

function Configurar-Reprobados {

    $Dominio = "reprobados.com"
    $IPServidor = Obtener-IPServidor

    if (!$IPServidor) { return }

    if (!(Validar-IP $IPServidor)) {
        Write-Host "IP inválida."
        Pause
        return
    }

    if (!(Get-DnsServerZone -Name $Dominio -ErrorAction SilentlyContinue)) {

        Add-DnsServerPrimaryZone `
            -Name $Dominio `
            -ZoneFile "$Dominio.dns" `
            -DynamicUpdate None

        Write-Host "Zona creada."
    }

    # Eliminar registros A existentes
    Get-DnsServerResourceRecord -ZoneName $Dominio -RRType "A" -ErrorAction SilentlyContinue |
        Remove-DnsServerResourceRecord -ZoneName $Dominio -Force -ErrorAction SilentlyContinue

    # Crear registros actualizados
    Add-DnsServerResourceRecordA -ZoneName $Dominio -Name "@" -IPv4Address $IPServidor
    Add-DnsServerResourceRecordA -ZoneName $Dominio -Name "www" -IPv4Address $IPServidor

    Restart-Service DNS

    Write-Host "reprobados.com configurado con IP $IPServidor"
    Pause
}

# ---------------- ADMINISTRAR DOMINIOS ----------------

function Administrar-Dominios {

    Write-Host "===== ADMINISTRAR DOMINIOS ====="
    Write-Host "A) Agregar dominio"
    Write-Host "B) Eliminar dominio"
    Write-Host "C) Listar dominios"
    Write-Host "D) Reconfigurar reprobados.com (IP automática del servidor)"

    $op = Read-Host "Opción"

    switch ($op.ToUpper()) {

        # -------- AGREGAR --------
        "A" {

            $Dominio = Read-Host "Nombre del dominio (ej: empresa.com o empresa.local)"
            $IPAsignada = Read-Host "IP que se asignará al dominio"

            if (!(Validar-IP $IPAsignada)) {
                Write-Host "IP inválida."
                Pause
                return
            }

            if (Get-DnsServerZone -Name $Dominio -ErrorAction SilentlyContinue) {
                Write-Host "La zona ya existe."
                Pause
                return
            }

            Add-DnsServerPrimaryZone `
                -Name $Dominio `
                -ZoneFile "$Dominio.dns" `
                -DynamicUpdate None

            Add-DnsServerResourceRecordA `
                -ZoneName $Dominio `
                -Name "@" `
                -IPv4Address $IPAsignada

            Add-DnsServerResourceRecordA `
                -ZoneName $Dominio `
                -Name "www" `
                -IPv4Address $IPAsignada

            Restart-Service DNS

            Write-Host "Dominio $Dominio creado correctamente."
            Pause
        }

        # -------- ELIMINAR --------
        "B" {

            $DominioEliminar = Read-Host "Nombre del dominio a eliminar (.com o .local)"

            if (Get-DnsServerZone -Name $DominioEliminar -ErrorAction SilentlyContinue) {
                Remove-DnsServerZone -Name $DominioEliminar -Force
                Write-Host "Dominio eliminado correctamente."
            }
            else {
                Write-Host "El dominio no existe."
            }

            Pause
        }

        # -------- LISTAR --------
        "C" {

            Write-Host ""
            Write-Host "Zonas configuradas:"
            Get-DnsServerZone | Format-Table ZoneName, ZoneType -AutoSize
            Pause
        }

        # -------- REPROBADOS --------
        "D" {
            Configurar-Reprobados
        }

        default {
            Write-Host "Opción inválida."
            Pause
        }
    }
}

# ---------------- MONITOREO ----------------

function Monitorear-DNS {

    Write-Host "===== MONITOREO DNS ====="

    if ((Get-Service DNS).Status -ne "Running") {
        Start-Service DNS
    }

    Write-Host ""
    Write-Host "Zonas configuradas:"
    Get-DnsServerZone | Format-Table -AutoSize

    Pause
}

# ---------------- MENU ----------------

while ($true) {

    Clear-Host
    Write-Host "====== MENU DNS (Windows Server 2022) ======"
    Write-Host "1) Ver estado del servicio"
    Write-Host "2) Instalar / Reinstalar DNS"
    Write-Host "3) Administrar dominios (ABC)"
    Write-Host "4) Monitorear"
    Write-Host "5) Salir"

    $op = Read-Host "Opción"

    switch ($op) {
        1 { Estado-DNS }
        2 { Instalar-DNS }
        3 { Administrar-Dominios }
        4 { Monitorear-DNS }
        5 { exit }
        default { Write-Host "Opción inválida"; Pause }
    }
}