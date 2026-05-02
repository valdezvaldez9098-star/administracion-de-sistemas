# Práctica 11 — Orquestación de Microservicios
## Devuan Daedalus 5.0.1 · VirtualBox · Docker Compose

---

## 1. Configuración de la Máquina Virtual en VirtualBox

Antes de encender la VM necesitas **dos adaptadores de red**:

### Adaptador 1 — NAT (internet para la VM)
| Campo | Valor |
|---|---|
| Tipo de adaptador | NAT |
| Cable conectado | ✓ |

Sirve para que la VM pueda hacer `apt-get install`, descargar Docker, etc.

### Adaptador 2 — Solo anfitrión / Host-Only (comunicación PC ↔ VM)
| Campo | Valor |
|---|---|
| Tipo de adaptador | Adaptador de solo anfitrión |
| Nombre | `vboxnet0` (créalo si no existe en Archivo → Herramientas → Administrador de red) |
| Cable conectado | ✓ |

Sirve para que tu PC física pueda hacer SSH a la VM y ejecutar la prueba 11.3.

#### Cómo configurarlo en VirtualBox:
1. Selecciona la VM → **Configuración** → **Red**
2. **Adaptador 1**: habilitado, conectado a **NAT**
3. **Adaptador 2**: habilitado, conectado a **Adaptador de solo anfitrión** → vboxnet0
4. Aceptar y encender la VM

#### Dentro de Devuan — configurar la interfaz host-only:
```bash
# Ver las interfaces disponibles
ip link show

# La interfaz host-only suele llamarse eth1 o enp0s8
# Asignar IP estática (editar /etc/network/interfaces):
sudo nano /etc/network/interfaces
```

Agrega al final del archivo:
```
# Adaptador 2 - Host-Only
auto eth1
iface eth1 inet static
    address 192.168.56.10
    netmask 255.255.255.0
```

```bash
sudo ifup eth1
# Verificar:
ip addr show eth1
```

---

## 2. Estructura de Archivos del Proyecto

```
practica11/
├── menu.sh                  ← PUNTO DE ENTRADA (menú principal)
├── setup_inicial.sh         ← Ejecutar una sola vez para permisos
├── lib/
│   ├── colores.sh           ← Constantes ANSI
│   ├── prerequisitos.sh     ← Instala Docker, genera .env y archivos
│   ├── infraestructura.sh   ← Gestión del stack Docker Compose
│   ├── firewall.sh          ← Configuración UFW
│   └── pruebas.sh           ← Las 4 pruebas de aceptación
└── docker/                  ← Generado por el menú (opción 3)
    ├── .env                 ← Credenciales (generado por opción 2)
    ├── docker-compose.yml
    ├── nginx/
    │   └── conf.d/
    │       └── default.conf
    └── app-interna/
        ├── Dockerfile
        └── server.py
```

---

## 3. Flujo de Trabajo Recomendado

```
sudo bash setup_inicial.sh   ← solo la primera vez
sudo bash menu.sh
  → Opción 1   Instalar prerequisitos
  → Opción 2   Generar .env
  → Opción 3   Crear archivos de configuración
  → Opción 8   Configurar firewall
  → Opción 4   Iniciar stack
  → Opciones 11-15  Ejecutar pruebas y tomar capturas
```

---

## 4. Diagrama de Arquitectura (para el reporte)

```
MÁQUINA FÍSICA (estudiante)
│
│  (petición web normal)
│  http://192.168.56.10:80
│                          ┌─────────────────────────────────────┐
│  ──────────────────────► │  SERVIDOR DEVUAN (VirtualBox)       │
│                          │                                     │
│                          │  ┌─────────────────────────────┐   │
│                          │  │  red_publica (bridge)       │   │
│                          │  │  ┌──────────────────────┐   │   │
│                          │  │  │  p11_nginx (80:80)   │   │   │
│                          │  │  │  Balanceador + LB    │   │   │
│                          │  │  └──────────┬───────────┘   │   │
│                          │  │             │               │   │
│                          │  │  ┌──────────▼───────────┐   │   │
│                          │  │  │  p11_app (sin ports) │   │   │
│                          │  │  │  App interna :8080   │   │   │
│                          │  │  └──────────────────────┘   │   │
│                          │  └─────────────────────────────┘   │
│                          │                                     │
│                          │  ┌─────────────────────────────┐   │
│                          │  │  red_datos (internal:true)  │   │
│                          │  │  ┌──────────────────────┐   │   │
│                          │  │  │  p11_postgres        │   │   │
│                          │  │  │  (sin ports expuesto)│   │   │
│                          │  │  └──────────────────────┘   │   │
│                          │  │  ┌──────────────────────┐   │   │
│                          │  │  │  p11_pgadmin         │   │   │
│                          │  │  │  (sin ports expuesto)│   │   │
│  (túnel SSH cifrado)     │  │  └──────────────────────┘   │   │
│  ssh -L 8080:pgadmin:80  │  └─────────────────────────────┘   │
│  ──────────────────────► │                                     │
│  localhost:8080          └─────────────────────────────────────┘
│  ◄── pgAdmin UI
```

---

## 5. Prueba 11.3 — Comando exacto del túnel SSH

Desde tu **máquina física**:
```bash
ssh -L 8080:<IP_interna_pgadmin>:80 tu_usuario@192.168.56.10
```

Con el túnel activo, abre: **http://localhost:8080**

---

## 6. Archivo .env de ejemplo (sin datos reales)

```env
POSTGRES_DB=practica11db
POSTGRES_USER=admin_db
POSTGRES_PASSWORD=CAMBIAR_ESTO
PGADMIN_DEFAULT_EMAIL=admin@practica11.local
PGADMIN_DEFAULT_PASSWORD=CAMBIAR_ESTO
PGADMIN_LISTEN_PORT=80
APP_INTERNAL_PORT=8080
NGINX_PUBLIC_PORT=80
RED_PUBLICA=red_publica
RED_DATOS=red_datos
```
