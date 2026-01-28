$TrustIps = @("192.168.128.4")

$Ports = @("135", "445", "49152-65535")

New-NetFireWallRule -DisplayName "Secured RPC on trusted IPs" -Direction Inbound ` -LocalPort $Ports ` -Protocol TCP ` -RemoteAddress $TrustedIPs ` -Action Allow ` -Profile Any ` -Description "Allows RPC and SMB only from specific Domain Controllers and Admin Workstations."

Write-Host "Firewall rule created. Only the listed IPs are explicitly allowed on ports 135, 445, and RPC Range."
