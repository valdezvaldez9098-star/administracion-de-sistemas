Write-Host "=== Estado del Sistema ==="
Write-Host "Hostname: $env:COMPUTERNAME"
Write-Host "IPs:"
Get-NetIPAddress -AddressFamily IPv4
Write-Host "Espacio en disco C:\"
Get-PSDrive C