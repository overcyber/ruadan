#!/bin/bash
# ==============================================================================
# Ruadan - Importação em lote dos XMLs do Nmap para o banco do Metasploit
# ==============================================================================
# Uso: msf_import_nmap.sh <workspace> <output_folder>
#
# Por que este script existe: o Metasploit `db_import` NÃO expande globs
# (ex: /ruadan/output/Nmap/**/*.xml). O template antigo do config.ini passava
# o glob literal entre aspas e o import falhava silenciosamente.
# Este script monta os comandos db_import (um por XML) e executa TODOS em uma
# única sessão msfconsole — evitando o custo de inicializar o framework a cada
# arquivo (cada msfconsole demora ~30-60s para carregar).
# ==============================================================================

set -u

WORKSPACE="${1:-hosts}"
OUTPUT_FOLDER="${2:-/ruadan/output}"
NMAP_DIR="${OUTPUT_FOLDER}/Nmap"

CMD="workspace -a ${WORKSPACE}"
COUNT=0

if [ -d "${NMAP_DIR}" ]; then
    for f in "${NMAP_DIR}"/*.xml; do
        if [ -f "$f" ]; then
            CMD="${CMD}; db_import $f"
            COUNT=$((COUNT + 1))
        fi
    done
fi

if [ "$COUNT" -eq 0 ]; then
    echo "[msf_import_nmap] Nenhum XML encontrado em ${NMAP_DIR} — nada a importar."
    exit 0
fi

echo "[msf_import_nmap] Importando ${COUNT} XML(s) do Nmap para o workspace '${WORKSPACE}'..."
msfconsole -q -x "${CMD}; exit"
