# ======================================================
# conf_ftp.ps1 - Preparacion de Entorno y FTP (Fix Auth Warning)
# ======================================================

function Configurar-Repositorio-FTPS {
    Write-Host "--- Instalando Roles y Chocolatey ---" -ForegroundColor Cyan
    
    if (!(Test-Path "C:\ProgramData\chocolatey\bin\choco.exe")) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $inst = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
        Invoke-Expression $inst
        $env:Path += ";C:\ProgramData\chocolatey\bin"
    }

    # 1. Agregamos Web-FTP-Ext para asegurar todos los modulos de seguridad
    $features = @("WAS-Process-Model", "Web-Server", "Web-FTP-Server", "Web-FTP-Service", "Web-FTP-Ext", "Web-Mgmt-Tools")
    foreach ($f in $features) { Install-WindowsFeature $f -IncludeManagementTools | Out-Null }

    # 2. Reiniciamos IIS para que reconozca la configuracion de Autenticacion FTP
    Write-Host "Recargando esquema de IIS..." -ForegroundColor Yellow
    iisreset /restart | Out-Null
    
    Import-Module WebAdministration -ErrorAction SilentlyContinue

    $base = "C:\FTP\http\Windows"
    foreach ($s in @("IIS", "Apache", "Nginx")) {
        $path = "$base\$s"
        if (!(Test-Path $path)) { New-Item $path -ItemType Directory -Force | Out-Null }
        "BINARIO-$s-V1" | Out-File "$path\setup_$s.msi" -Encoding ascii
        (Get-FileHash "$path\setup_$s.msi" -Algorithm SHA256).Hash | Out-File "$path\setup_$s.msi.sha256" -Encoding ascii
    }

    Restart-Service ftpsvc -Force -ErrorAction SilentlyContinue
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
    & $appcmd unlock config -section:system.ftpServer/security/authorization | Out-Null
    
    if (Test-Path "IIS:\Sites\FTPServer") { Remove-Website -Name "FTPServer" }
    New-WebFtpSite -Name "FTPServer" -Port 21 -PhysicalPath "C:\FTP" -Force | Out-Null
    
    $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "Cert:\LocalMachine\My"
    
    Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name='FTPServer']/ftpServer/security/ssl" -Name serverCertHash -Value $cert.GetCertHashString() -PSPath IIS:\
    Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name='FTPServer']/ftpServer/security/ssl" -Name controlChannelPolicy -Value SslRequire -PSPath IIS:\
    Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name='FTPServer']/ftpServer/security/ssl" -Name dataChannelPolicy -Value SslRequire -PSPath IIS:\

    # 3. Activamos Autenticacion Basica directo en el Sitio (Previene el WARNING)
    Set-ItemProperty "IIS:\Sites\FTPServer" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    
    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -Value @{accessType="Allow"; roles="Administrators"; permissions="Read, Write"} -PSPath IIS:\ -Location "FTPServer"
    
    icacls "C:\FTP" /grant "Administrators:(OI)(CI)F" /T /C /Q | Out-Null
    Restart-Service ftpsvc -Force
    Write-Host "[OK] Infraestructura FTP lista." -ForegroundColor Green
}