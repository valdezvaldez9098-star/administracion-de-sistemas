#!/usr/bin/env bash
# =============================================================================
#  lib/prerequisitos.sh
#  Verifica e instala Docker, Docker Compose y genera los archivos base
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --------------------------------------------------------------------------- #
#  verificar_prerequisitos
# --------------------------------------------------------------------------- #
verificar_prerequisitos() {
    echo -e "\n${BOLD}=== Verificación e instalación de prerequisitos ===${RESET}\n"

    # ── apt update ──────────────────────────────────────────────────────── #
    echo -e "${INFO} Actualizando lista de paquetes..."
    apt-get update -qq

    # ── curl ────────────────────────────────────────────────────────────── #
    if ! command -v curl &>/dev/null; then
        echo -e "${WARN} curl no encontrado. Instalando..."
        apt-get install -y -qq curl
    else
        echo -e "${OK} curl disponible."
    fi

    # ── Docker Engine ────────────────────────────────────────────────────── #
    if ! command -v docker &>/dev/null; then
        echo -e "${WARN} Docker no encontrado. Instalando via script oficial..."
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        sh /tmp/get-docker.sh
        # En Devuan el servicio se llama igual pero usa sysvinit
        update-rc.d docker defaults 2>/dev/null || true
        service docker start 2>/dev/null || true
        echo -e "${OK} Docker instalado."
    else
        echo -e "${OK} Docker $(docker --version | cut -d' ' -f3 | tr -d ',') disponible."
    fi

    # ── Docker Compose (plugin v2 o binario standalone) ──────────────────── #
    if docker compose version &>/dev/null 2>&1; then
        echo -e "${OK} Docker Compose plugin v2 disponible."
    elif command -v docker-compose &>/dev/null; then
        echo -e "${OK} docker-compose standalone disponible."
    else
        echo -e "${WARN} Docker Compose no encontrado. Instalando plugin v2..."
        # Instala el plugin oficial de compose
        DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}"
        mkdir -p "$DOCKER_CONFIG/cli-plugins"
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest \
            | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
        curl -SL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
            -o "$DOCKER_CONFIG/cli-plugins/docker-compose"
        chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
        echo -e "${OK} Docker Compose v${COMPOSE_VERSION} instalado."
    fi

    # ── iputils-ping (para prueba 11.2) ─────────────────────────────────── #
    if ! command -v ping &>/dev/null; then
        echo -e "${WARN} ping no encontrado. Instalando iputils-ping..."
        apt-get install -y -qq iputils-ping
    else
        echo -e "${OK} ping disponible."
    fi

    # ── ufw / iptables ───────────────────────────────────────────────────── #
    if ! command -v ufw &>/dev/null; then
        echo -e "${WARN} ufw no encontrado. Instalando..."
        apt-get install -y -qq ufw
    else
        echo -e "${OK} ufw disponible."
    fi

    echo -e "\n${GREEN}${BOLD}Prerequisitos listos.${RESET}\n"
}

# --------------------------------------------------------------------------- #
#  generar_env
# --------------------------------------------------------------------------- #
generar_env() {
    ENV_FILE="$SCRIPT_DIR/docker/.env"
    echo -e "\n${BOLD}=== Generando archivo .env ===${RESET}\n"

    if [[ -f "$ENV_FILE" ]]; then
        echo -e "${WARN} Ya existe un archivo .env en docker/.env"
        echo -ne "¿Deseas sobreescribirlo? [s/N]: "
        read -r resp
        [[ "$resp" != "s" && "$resp" != "S" ]] && echo "Cancelado." && return
    fi

    # Genera una contraseña aleatoria segura
    PG_PASS=$(tr -dc 'A-Za-z0-9@#%^&*' </dev/urandom | head -c 20)
    PGADMIN_PASS=$(tr -dc 'A-Za-z0-9@#%^&*' </dev/urandom | head -c 20)

    mkdir -p "$SCRIPT_DIR/docker"
    cat > "$ENV_FILE" <<EOF
# ============================================================
#  Variables de entorno - Práctica 11
#  NUNCA subir este archivo a repositorios públicos
# ============================================================

# ── PostgreSQL ──────────────────────────────────────────────
POSTGRES_DB=practica11db
POSTGRES_USER=admin_db
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_PORT=5432

# ── pgAdmin ─────────────────────────────────────────────────
PGADMIN_DEFAULT_EMAIL=admin@practica11.local
PGADMIN_DEFAULT_PASSWORD=${PGADMIN_PASS}
PGADMIN_LISTEN_PORT=80

# ── App secundaria (nginx interno) ──────────────────────────
APP_INTERNAL_PORT=8080

# ── Red pública - nginx balanceador ─────────────────────────
NGINX_PUBLIC_PORT=80

# ── Redes Docker ────────────────────────────────────────────
RED_PUBLICA=red_publica
RED_DATOS=red_datos
EOF

    echo -e "${OK} Archivo .env generado en: ${CYAN}$ENV_FILE${RESET}"
    echo -e "${YELLOW}Contraseña PostgreSQL : ${PG_PASS}${RESET}"
    echo -e "${YELLOW}Contraseña pgAdmin    : ${PGADMIN_PASS}${RESET}"
    echo -e "${DIM}(guarda estas contraseñas en un lugar seguro)${RESET}"
}

# --------------------------------------------------------------------------- #
#  crear_estructura
# --------------------------------------------------------------------------- #
crear_estructura() {
    echo -e "\n${BOLD}=== Creando estructura de archivos ===${RESET}\n"

    mkdir -p "$SCRIPT_DIR/docker/nginx/conf.d"
    mkdir -p "$SCRIPT_DIR/docker/app-interna"

    # ── docker-compose.yml ───────────────────────────────────────────────── #
    cat > "$SCRIPT_DIR/docker/docker-compose.yml" <<'COMPOSE'
# =============================================================
#  docker-compose.yml · Práctica 11
#  Stack: nginx (LB) + app-interna + postgresql + pgadmin
# =============================================================
version: "3.9"

# ─── Redes multicapa ──────────────────────────────────────────
networks:
  red_publica:
    name: ${RED_PUBLICA}
    driver: bridge
  red_datos:
    name: ${RED_DATOS}
    driver: bridge
    internal: true          # Totalmente aislada del exterior

# ─── Volúmenes persistentes ───────────────────────────────────
volumes:
  postgres_data:
    name: practica11_postgres_data

# ─── Servicios ────────────────────────────────────────────────
services:

  # ── 1. Balanceador / frontend (único punto de entrada) ──── #
  nginx-balanceador:
    image: nginx:1.25-alpine
    container_name: p11_nginx
    restart: always
    ports:
      - "${NGINX_PUBLIC_PORT}:80"      # ÚNICO puerto expuesto al host
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
    networks:
      - red_publica
    depends_on:
      - app-interna
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost/health"]
      interval: 15s
      timeout: 5s
      retries: 3

  # ── 2. Servidor de aplicaciones interno (sin puertos expuestos) ─ #
  app-interna:
    build:
      context: ./app-interna
    container_name: p11_app
    restart: always
    # Sin 'ports:' → invisible para el host, solo accesible via nginx
    networks:
      - red_publica
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:${APP_INTERNAL_PORT}/"]
      interval: 15s
      timeout: 5s
      retries: 3

  # ── 3. Base de datos PostgreSQL con persistencia ─────────── #
  postgres:
    image: postgres:15-alpine
    container_name: p11_postgres
    restart: always
    environment:
      POSTGRES_DB:       ${POSTGRES_DB}
      POSTGRES_USER:     ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    # Sin 'ports:' → invisible fuera de Docker
    networks:
      - red_datos
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 20s

  # ── 4. Panel administrativo pgAdmin (red_datos únicamente) ─ #
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: p11_pgadmin
    restart: always
    environment:
      PGADMIN_DEFAULT_EMAIL:    ${PGADMIN_DEFAULT_EMAIL}
      PGADMIN_DEFAULT_PASSWORD: ${PGADMIN_DEFAULT_PASSWORD}
      PGADMIN_LISTEN_PORT:      ${PGADMIN_LISTEN_PORT}
    volumes:
      - /tmp/pgadmin_sessions:/var/lib/pgadmin  # sesiones efímeras
    # Sin 'ports:' → acceso SOLO via túnel SSH
    networks:
      - red_datos
    depends_on:
      postgres:
        condition: service_healthy   # espera healthcheck de postgres
COMPOSE

    # ── nginx.conf ───────────────────────────────────────────────────────── #
    cat > "$SCRIPT_DIR/docker/nginx/conf.d/default.conf" <<'NGINX'
# Oculta la versión del servidor (hardening)
server_tokens off;

# ── Upstream: app-interna ────────────────────────────────────
upstream app_backend {
    server app-interna:8080;
}

# ── Servidor principal ───────────────────────────────────────
server {
    listen 80;
    server_name _;

    # Elimina cabecera X-Powered-By
    more_clear_headers 'X-Powered-By';

    # Endpoint de health para el propio healthcheck de nginx
    location /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }

    # Todo el tráfico se redirige a la app interna
    location / {
        proxy_pass         http://app_backend;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_hide_header  Server;
        proxy_hide_header  X-Powered-By;
    }
}
NGINX

    # ── app-interna/Dockerfile ───────────────────────────────────────────── #
    cat > "$SCRIPT_DIR/docker/app-interna/Dockerfile" <<'DOCKERFILE'
FROM python:3.11-alpine
WORKDIR /app
COPY server.py .
EXPOSE 8080
CMD ["python", "server.py"]
DOCKERFILE

    # ── app-interna/server.py (servidor mínimo de demostración) ──────────── #
    cat > "$SCRIPT_DIR/docker/app-interna/server.py" <<'PYSERVER'
#!/usr/bin/env python3
"""
Servidor HTTP mínimo - simula aplicación interna
Solo accesible a través del balanceador nginx
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, socket, os, datetime

class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silenciar logs internos

    def do_GET(self):
        payload = {
            "status":    "running",
            "service":   "app-interna",
            "hostname":  socket.gethostname(),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "path":      self.path,
        }
        body = json.dumps(payload, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    port = int(os.environ.get("APP_INTERNAL_PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), AppHandler)
    print(f"app-interna escuchando en :{port}")
    server.serve_forever()
PYSERVER

    echo -e "${OK} Estructura creada en: ${CYAN}$SCRIPT_DIR/docker/${RESET}"
    echo -e "
  docker/
  ├── docker-compose.yml
  ├── .env
  ├── nginx/
  │   └── conf.d/
  │       └── default.conf
  └── app-interna/
      ├── Dockerfile
      └── server.py
"
}
