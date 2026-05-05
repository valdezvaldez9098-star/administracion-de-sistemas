# 📬 Servidor de Correo Privado Corporativo
### Tarea 12 & 13 — Devuan Daedalus 5.0.1 + Docker + VirtualBox

---

## Estructura del proyecto

```
mailserver-proyecto/
├── menu.sh                  ← PUNTO DE ENTRADA — menú maestro
├── scripts/
│   ├── colores.sh           ← Utilidades de color y logging
│   ├── red.sh               ← Configuración de red y VirtualBox
│   ├── docker_stack.sh      ← Instalación de Docker y gestión del stack
│   ├── seguridad.sh         ← Certificados TLS/SSL y DKIM
│   ├── cuentas.sh           ← Gestión de cuentas de correo
│   ├── respaldos.sh         ← Respaldos automáticos y restauración
│   └── pruebas.sh           ← Pruebas de aceptación 12.1 – 13.7
├── config/
│   ├── mailserver.env       ← Variables de entorno (generado)
│   └── roundcube/
│       └── config.inc.php   ← Configuración de Roundcube (generado)
├── data/
│   ├── certs/               ← Certificados TLS autofirmados
│   └── dkim/                ← Claves DKIM
├── backups/                 ← Respaldos comprimidos
└── logs/                    ← Logs de instalación y pruebas
```

---

## Configuración de VirtualBox (PRIMERO)

### Adaptadores de red necesarios

| Adaptador | Tipo              | IP en la VM       | Para qué sirve              |
|-----------|-------------------|-------------------|-----------------------------|
| eth0      | NAT               | 10.0.2.15 (DHCP)  | Acceso a Internet / apt     |
| eth1      | Red Solo-Anfitrión| 192.168.56.10     | Comunicación PC ↔ VM        |

### Pasos en VirtualBox

1. **Crear la red Host-Only** (una sola vez):
   - Archivo → Administrador de Red de Host → **Crear**
   - IP del adaptador del host: `192.168.56.1` / Máscara: `255.255.255.0`
   - **Deshabilitar** el servidor DHCP

2. **Configurar la VM**:
   - Clic derecho en la VM → Configuración → Red
   - **Adaptador 1**: NAT ✓
   - **Adaptador 2**: Red solo-anfitrión → `vboxnet0` ✓

3. **Iniciar la VM** en Devuan.

---

## Uso del menú

```bash
# En la VM Devuan, como root:
sudo bash menu.sh
```

### Flujo de trabajo recomendado (orden de opciones)

```
1. Red [1] → Detectar adaptadores
2. Red [2] → Ver guía VirtualBox
3. Red [3] → Configurar IP estática (192.168.56.10)
4. Docker [1] → Instalar dependencias
5. Docker [2] → Instalar Docker
6. Docker [4] → Crear estructura de directorios
7. Docker [5] → Generar archivos de configuración
8. Certificados [1] → Generar cert autofirmado
9. Certificados [2] → Generar claves DKIM
10. Stack [1] → Generar docker-compose.yml
11. Stack [2] → Iniciar el stack
12. Cuentas [5] → Crear cuentas director + admin
13. Pruebas [8] → Ejecutar todas las pruebas
```

---

## Puertos del servidor

| Puerto | Protocolo | Uso                                  |
|--------|-----------|--------------------------------------|
| 25     | SMTP      | Recepción entre servidores de correo |
| 587    | Submission| Envío con STARTTLS (clientes)        |
| 465    | SMTPS     | Envío con SSL/TLS directo            |
| 143    | IMAP      | Recepción (sin TLS, solo interna)    |
| 993    | IMAPS     | Recepción con SSL/TLS                |
| 80     | HTTP      | Roundcube webmail                    |
| 443    | HTTPS     | Roundcube webmail (cifrado)          |

---

## Acceso a Roundcube desde tu PC

1. Agrega en `/etc/hosts` de tu **PC anfitriona**:
   ```
   192.168.56.10  reprobados.com mail.reprobados.com
   ```
2. Abre: `http://192.168.56.10` o `http://reprobados.com`
3. Login: `director` / `Director2024!`

---

## Configuración Thunderbird

| Campo        | Valor                  |
|--------------|------------------------|
| Servidor IMAP| 192.168.56.10          |
| Puerto IMAP  | 993 (SSL/TLS)          |
| Servidor SMTP| 192.168.56.10          |
| Puerto SMTP  | 587 (STARTTLS)         |
| Usuario      | director@reprobados.com|

> Acepta la excepción del certificado autofirmado cuando Thunderbird la solicite.

---

## Componentes del Stack

| Contenedor  | Imagen                            | Función                    |
|-------------|-----------------------------------|----------------------------|
| mailserver  | docker-mailserver/docker-mailserver | Postfix + Dovecot + Rspamd + Fail2Ban + OpenDKIM |
| roundcube   | roundcube/roundcubemail           | Webmail PHP                |

---

## Notas sobre Devuan Daedalus

- Devuan Daedalus equivale a **Debian Bookworm** sin systemd.
- Usa **SysVinit**: los servicios se gestionan con `service nombre start/stop/status`.
- El repositorio de Docker para Debian Bookworm es compatible directamente.
- Para reiniciar Docker: `sudo service docker restart`
