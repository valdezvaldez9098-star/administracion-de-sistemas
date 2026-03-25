# ======================================================
# orquestador.ps1 - Orquestador Híbrido Final (Automático con Puertos)
# ======================================================

. .\conf_ftp.ps1
. .\http_funciones.ps1

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

function Solicitar-Puertos {
    $pHTTP = Read-Host "Ingresa el Puerto HTTP (Ej. 80 o 8080) [Enter para 80]"
    if ([string]::IsNullOrWhiteSpace($pHTTP)) { $pHTTP = 80 }
    
    $pHTTPS = Read-Host "Ingresa el Puerto HTTPS (Ej. 443 o 8443) [Enter para 443]"
    if ([string]::IsNullOrWhiteSpace($pHTTPS)) { $pHTTPS = 443 }
    
    return $pHTTP, $pHTTPS
}

function Descargar-Binario-FTPS {
    param($url, $cred, $destino)
    $request = [System.Net.FtpWebRequest]::Create($url)
    $request.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
    $request.Credentials = $cred
    $request.EnableSsl = $true
    $request.UsePassive = $true
    
    $res = $request.GetResponse()
    $stream = $res.GetResponseStream()
    $file = [System.IO.File]::Create($destino)
    $stream.CopyTo($file)
    $file.Close(); $stream.Close(); $res.Close()
}

function Navegar-FTP-Dinamico {
    $urlBase = "ftp://localhost/http/Windows/"
    
    # === AUTENTICACIÓN AUTOMÁTICA (SIN VENTANAS) ===
    $usuario = "Administrator"
    $password = "XnightX321456"  # <-- Contraseña actualizada
    
    Write-Host "`nConectando automáticamente al FTP como $usuario..." -ForegroundColor Gray
    $cred = New-Object System.Net.NetworkCredential($usuario, $password, $env:COMPUTERNAME)
    # ===============================================
    
    try {
        $req = [System.Net.FtpWebRequest]::Create($urlBase)
        $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $req.EnableSsl = $true
        $req.Credentials = $cred
        
        $res = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($res.GetResponseStream())
        $dirs = $reader.ReadToEnd().Split("`r`n", [System.StringSplitOptions]::RemoveEmptyEntries)
        $reader.Close(); $res.Close()

        Write-Host "`nRepositorio FTP:" -ForegroundColor Cyan
        for($i=0; $i -lt $dirs.Count; $i++){ Write-Host "$($i+1). $($dirs[$i])" }
        $sel = Read-Host "Seleccione software"
        $servNom = $dirs[$sel-1]
        
        $puertos = Solicitar-Puertos
        $localFile = "$env:TEMP\setup_$servNom.msi"
        
        Write-Host "Descargando binario seguro desde FTP..." -ForegroundColor Yellow
        Descargar-Binario-FTPS "$urlBase$servNom/setup_$servNom.msi" $cred $localFile
        
        Write-Host "Instalando desde repositorio local..." -ForegroundColor Green
        Instalar-Servicio-Web $servNom "REPOSITORIO-FTP-PRIVADO" $puertos[0] $puertos[1]
    } catch {
        Write-Error "Fallo: $($_.Exception.Message)"
    }
}

do {
    Write-Host "`n======== PRACTICA 7: DESPLIEGUE HIBRIDO ========" -ForegroundColor Yellow
    Write-Host "1. Instalar via WEB (Oficial / Chocolatey)"
    Write-Host "2. Instalar via FTP (Privado)"
    Write-Host "3. Preparar Servidor (Roles e Infraestructura)"
    Write-Host "4. Liberar Puertos"
    Write-Host "0. Salir"
    $op = Read-Host "Opcion"
    switch ($op) {
        "1" { 
            $serv = Read-Host "Servicio (IIS/Apache/Nginx)"
            $puertos = Solicitar-Puertos
            Instalar-Servicio-Web $serv "WEB-CHOCO" $puertos[0] $puertos[1]
        }
        "2" { Navegar-FTP-Dinamico }
        "3" { Configurar-Repositorio-FTPS }
        "4" { Liberar-Puertos }
    }
} while ($op -ne "0")