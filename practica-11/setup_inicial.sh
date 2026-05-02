#!/usr/bin/env bash
# =============================================================================
#  setup_inicial.sh
#  Copia la estructura al servidor y prepara permisos
#  Ejecutar UNA SOLA VEZ después de transferir los archivos al servidor
# =============================================================================
set -e

echo "=============================================="
echo "  Setup inicial - Práctica 11"
echo "=============================================="

# Permisos de ejecución
chmod +x menu.sh
chmod +x lib/*.sh

# Crear directorio de trabajo Docker
mkdir -p docker/nginx/conf.d
mkdir -p docker/app-interna

echo ""
echo "[OK] Permisos establecidos."
echo ""
echo "Pasos siguientes:"
echo "  1. Ejecuta: sudo bash menu.sh"
echo "  2. Opción 1 → Instalar Docker y prerequisitos"
echo "  3. Opción 2 → Generar .env"
echo "  4. Opción 3 → Crear archivos de configuración"
echo "  5. Opción 8 → Configurar firewall"
echo "  6. Opción 4 → Iniciar stack"
echo "  7. Opción 15 → Ejecutar todas las pruebas"
echo ""
echo "Para las capturas del reporte, ejecuta cada prueba por separado"
echo "(opciones 11-14) y toma screenshot de la terminal."
