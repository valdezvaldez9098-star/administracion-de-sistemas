#!/usr/bin/env bash
# =============================================================================
#  lib/colores.sh · Constantes de color y formato ANSI
# =============================================================================

RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
WHITE="\033[0;37m"

OK="${GREEN}[OK]${RESET}"
WARN="${YELLOW}[WARN]${RESET}"
ERR="${RED}[ERROR]${RESET}"
INFO="${CYAN}[INFO]${RESET}"
