# Dockerfile — Servidor Web Apache
# Base: Devuan Daedalus 5.0.1 (debian:12-slim compatible)
FROM debian:12-slim

LABEL maintainer="Tarea10-Web"
LABEL description="Apache2 personalizado - usuario no-root, ServerTokens Off"

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        apache2 \
        iputils-ping \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Seguridad: ocultar firma del servidor ──────────────────────────────────
RUN echo 'ServerTokens Prod'    >> /etc/apache2/apache2.conf && \
    echo 'ServerSignature Off'  >> /etc/apache2/apache2.conf

# ── Usuario no-root para Apache ────────────────────────────────────────────
RUN useradd -r -s /bin/false webuser && \
    chown -R webuser:webuser /var/www/html /var/log/apache2

RUN sed -i 's/APACHE_RUN_USER=www-data/APACHE_RUN_USER=webuser/'   /etc/apache2/envvars && \
    sed -i 's/APACHE_RUN_GROUP=www-data/APACHE_RUN_GROUP=webuser/' /etc/apache2/envvars

# ── Módulo autoindex para listar /ftp-files/ ───────────────────────────────
RUN a2enmod autoindex

# ── Alias /ftp-files/ → volumen compartido ────────────────────────────────
RUN printf 'Alias /ftp-files /var/www/html/ftp-files\n\
<Directory /var/www/html/ftp-files>\n\
    Options Indexes FollowSymLinks\n\
    AllowOverride None\n\
    Require all granted\n\
    IndexOptions FancyIndexing NameWidth=* HTMLTable\n\
</Directory>\n' > /etc/apache2/conf-available/ftp-files.conf && \
    a2enconf ftp-files

# ── Copiar contenido web ───────────────────────────────────────────────────
COPY html/ /var/www/html/
RUN chown -R webuser:webuser /var/www/html

EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]
