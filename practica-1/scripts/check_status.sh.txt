#!/bin/bash

echo "=== Estado del Sistema ==="
echo "Nombre del Equipo: $(cat /etc/hostname 2>/dev/null || uname -n)"
echo "IPs Actuales:"
ip -brief addr show | awk '{print $1": "$3}'
echo "Espacio en disco:"
df -h --output=source,size,used,avail,pcent /