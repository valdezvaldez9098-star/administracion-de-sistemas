# ======================================================
# http_funciones.ps1 - Aprovisionamiento Dual Dinamico (Modo Cirujano Apache)
# ======================================================

function Generar-Resumen-Instalacion($pHTTP, $pHTTPS) {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "       RESUMEN Y VERIFICACION AUTOMATIZADA             " -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "Esperando a que los servicios estabilicen..." -ForegroundColor Gray
    Start-Sleep -Seconds 4
    
    $ok80 = (Test-NetConnection localhost -Port $pHTTP -WarningAction SilentlyContinue).TcpTestSucceeded
    $ok443 = (Test-NetConnection localhost -Port $pHTTPS -WarningAction SilentlyContinue).TcpTestSucceeded
    
    Write-Host "[Puerto $pHTTP - HTTP ] Activo: $ok80" -ForegroundColor $(if($ok80){"Green"}else{"Red"})
    Write-Host "[Puerto $pHTTPS - HTTPS] Activo: $ok443" -ForegroundColor $(if($ok443){"Green"}else{"Red"})
    
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -NotMatch 'Loopback' | Select-Object -First 1).IPAddress
    Write-Host "URL: https://$ip`:$pHTTPS/p7/index.html" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "NOTA: Presiona CTRL+F5 o usa Modo Incognito en tu navegador host." -ForegroundColor Yellow
}

function Crear-Index-Rubrica($ruta, $serv, $modo, $pHTTP, $pHTTPS) {
    $p7Path = Join-Path $ruta "p7"
    if(!(Test-Path $p7Path)){ New-Item -ItemType Directory -Path $p7Path -Force | Out-Null }
    $hora = Get-Date -Format "HH:mm:ss"
    "<h1>Sitio Dual Practica 7 - $serv</h1><p>Metodo: $modo</p><p>Puertos: HTTP ($pHTTP) | HTTPS ($pHTTPS)</p><p>Generado a las: $hora</p>" | Out-File "$p7Path\index.html" -Encoding utf8 -Force
}

function Instalar-Servicio-Web {
    param([string]$Nombre, [string]$Modo, [int]$pHTTP, [int]$pHTTPS)
    
    Liberar-Puertos
    $choco = "C:\ProgramData\chocolatey\bin\choco.exe"

    Write-Host "--- Aprovisionando $Nombre en Puertos $pHTTP / $pHTTPS ---" -ForegroundColor Cyan

    if ($Nombre -eq "IIS") {
        if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
            Set-Service W3SVC -StartupType Automatic -ErrorAction SilentlyContinue
        }
        Install-WindowsFeature Web-Server -IncludeManagementTools | Out-Null
        Start-Service WAS, W3SVC -ErrorAction SilentlyContinue
        Import-Module WebAdministration
        
        Get-WebBinding -Name "Default Web Site" | Remove-WebBinding -ErrorAction SilentlyContinue
        New-WebBinding -Name "Default Web Site" -IPAddress "*" -Port $pHTTP -Protocol "http" | Out-Null
        New-WebBinding -Name "Default Web Site" -IPAddress "*" -Port $pHTTPS -Protocol "https" | Out-Null
        
        $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "Cert:\LocalMachine\My"
        $b = Get-WebBinding -Name "Default Web Site" -Protocol "https"
        $b.AddSslCertificate($cert.GetCertHashString(), "My")
        
        Crear-Index-Rubrica "C:\inetpub\wwwroot" "IIS" $Modo $pHTTP $pHTTPS
    }
    else {
        if (!(Test-Path "C:\Program Files\OpenSSL-Win64\bin\openssl.exe") -and !(Get-Command openssl -ErrorAction SilentlyContinue)) {
            Write-Host "Instalando motor OpenSSL para generar certificados..." -ForegroundColor Yellow
            & $choco install openssl -y --force | Out-Null
            $env:Path += ";C:\Program Files\OpenSSL-Win64\bin"
        }

        $certDir = "C:\CertificadosP7"
        if (!(Test-Path $certDir)) { New-Item $certDir -ItemType Directory -Force | Out-Null }
        $crt = "$certDir\server.crt"
        $key = "$certDir\server.key"

        if (!(Test-Path $crt) -or !(Test-Path $key)) {
            Write-Host "Creando llaves RSA..." -ForegroundColor Yellow
            $opensslBin = if (Test-Path "C:\Program Files\OpenSSL-Win64\bin\openssl.exe") {"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"} else {"openssl"}
            & $opensslBin req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $key -out $crt -subj "/CN=localhost" 2>&1 | Out-Null
        }

        if ($Nombre -eq "Apache") {
            & $choco install vcredist140 apache-httpd -y --force --params "/installDir:C:\Apache24" | Out-Null
            
            Stop-Service Apache* -Force -ErrorAction SilentlyContinue
            Get-Process httpd -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            
            if (Test-Path "$env:APPDATA\Apache24") { 
                if (!(Test-Path "C:\Apache24")) { New-Item "C:\Apache24" -ItemType Directory -Force | Out-Null }
                Copy-Item "$env:APPDATA\Apache24\*" "C:\Apache24" -Recurse -Force
                Remove-Item "$env:APPDATA\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            $conf = "C:\Apache24\conf\httpd.conf"
            $c = Get-Content $conf
            $nuevoConf = @()
            
            $crtApache = "C:/CertificadosP7/server.crt"
            $keyApache = "C:/CertificadosP7/server.key"
            
            foreach ($line in $c) {
                # 1. Extirpar cualquier puerto o nombre predeterminado que estorbe
                if ($line -match '(?i)^\s*Listen\s+') { continue }
                if ($line -match '(?i)^\s*ServerName\s+') { continue }
                
                # 2. Extirpar los archivos SSL fantasma de Chocolatey que causan el error de sintaxis
                if ($line -match '(?i)^\s*Include\s+conf/extra/.*ssl\.conf') { continue }
                
                # 3. Activar modulos base sin tocar el resto del archivo
                $l = $line -replace '(?i)^\s*#\s*LoadModule\s+ssl_module', 'LoadModule ssl_module'
                $l = $l -replace '(?i)^\s*#\s*LoadModule\s+socache_shmcb_module', 'LoadModule socache_shmcb_module'
                $l = $l -replace '(?i)^Define SRVROOT .*', 'Define SRVROOT "C:/Apache24"'
                
                $nuevoConf += $l
            }
            
            # 4. Inyectar nuestra configuracion inmaculada al final del archivo (en lineas separadas para Windows)
            $nuevoConf += "Listen $pHTTP"
            $nuevoConf += "Listen $pHTTPS"
            $nuevoConf += "ServerName localhost:$pHTTP"
            $nuevoConf += "<VirtualHost *:$pHTTPS>"
            $nuevoConf += "    ServerName localhost"
            $nuevoConf += "    SSLEngine on"
            $nuevoConf += "    SSLCertificateFile `"$crtApache`""
            $nuevoConf += "    SSLCertificateKeyFile `"$keyApache`""
            $nuevoConf += "</VirtualHost>"
            
            $nuevoConf | Set-Content $conf -Encoding Ascii
            
            & sc.exe delete Apache2.4 | Out-Null
            & "C:\Apache24\bin\httpd.exe" -k install -n "Apache2.4" | Out-Null
            Start-Service Apache2.4
            Crear-Index-Rubrica "C:\Apache24\htdocs" "Apache" $Modo $pHTTP $pHTTPS
        }
        elseif ($Nombre -eq "Nginx") {
            & $choco install nginx -y --force | Out-Null
            $nginxDir = (Get-ChildItem "C:\tools\nginx*" -Directory | Select-Object -First 1).FullName
            $nconf = "$nginxDir\conf\nginx.conf"
            
            $nginxConfigLimpia = @"
worker_processes  1;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       $pHTTP;
        server_name  localhost;
        location / {
            root   html;
            index  index.html index.htm;
        }
    }

    server {
        listen       $pHTTPS ssl;
        server_name  localhost;
        ssl_certificate      C:/CertificadosP7/server.crt;
        ssl_certificate_key  C:/CertificadosP7/server.key;
        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
"@
            $nginxConfigLimpia | Set-Content $nconf -Encoding Ascii
            Start-Process "$nginxDir\nginx.exe" -WorkingDirectory $nginxDir
            Crear-Index-Rubrica "$nginxDir\html" "Nginx" $Modo $pHTTP $pHTTPS
        }
    }
    
    Write-Host "Aplicando reglas de Firewall..." -ForegroundColor Yellow
    New-NetFirewallRule -DisplayName "HTTP-HTTPS-Hibrido" -Direction Inbound -Protocol TCP -LocalPort $pHTTP,$pHTTPS -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Generar-Resumen-Instalacion $pHTTP $pHTTPS
}

function Liberar-Puertos {
    Write-Host "-> Limpiando entorno y previniendo secuestro de procesos..." -ForegroundColor Yellow
    
    if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
        Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
        Set-Service W3SVC -StartupType Manual -ErrorAction SilentlyContinue
        Stop-Process -Name w3wp -Force -ErrorAction SilentlyContinue
    }
    
    Stop-Service WAS, Apache*, nginx* -Force -ErrorAction SilentlyContinue
    Get-Process httpd, nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $servs = Get-Service Apache*, nginx* -ErrorAction SilentlyContinue
    foreach($s in $servs) { & sc.exe delete $($s.Name) | Out-Null }
    @("C:\Apache24", "$env:APPDATA\Apache24", "C:\tools\nginx*") | ForEach-Object { if(Test-Path $_){ Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue } }
    
    Remove-NetFirewallRule -DisplayName "HTTP-HTTPS-Hibrido" -ErrorAction SilentlyContinue | Out-Null
}