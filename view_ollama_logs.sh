#!/usr/bin/env bash
# ==============================================================================
# Ruadan - Visualizador Unificado de Logs do Ollama
# ==============================================================================
# Detecta automaticamente o backend do Ollama:
# - Contêiner Docker (ruadan-ollama)
# - Serviço Host Systemd (ollama.service)
# - Arquivo de log persistido (output/ollama.log)
# - Interações do cliente LLM (output/ai_evidence/ollama_interactions.log)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"
OUTPUT_DIR="${ROOT_DIR}/output"
EVIDENCE_DIR="${OUTPUT_DIR}/ai_evidence"

# Cores ANSI para formatação
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

FOLLOW=0
LINES=50
MODE="server" # "server", "client", "all"

usage() {
    echo -e "${BOLD}Uso:${NC} $0 [opções]"
    echo ""
    echo "Opções:"
    echo "  -f, --follow       Acompanha os logs em tempo real (streaming contínuo)"
    echo "  -n, --lines <num>  Número de linhas a exibir (padrão: 50)"
    echo "  --client           Exibe logs de interações Ruadan <-> Ollama (prompts e respostas)"
    echo "  --server           Exibe apenas logs do daemon do Ollama (padrão)"
    echo "  --all              Exibe logs do servidor e interações do cliente"
    echo "  -h, --help         Exibe esta mensagem de ajuda"
    echo ""
    echo "Exemplos:"
    echo "  $0                  # Últimas 50 linhas do servidor Ollama"
    echo "  $0 -f               # Streaming ao vivo do servidor"
    echo "  $0 --client         # Interações enviadas pelo Ruadan ao Ollama"
    echo "  $0 --all -n 20      # 20 linhas do servidor e 20 interações do cliente"
    exit 0
}

# Parse de argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--follow)
            FOLLOW=1
            shift
            ;;
        -n|--lines)
            LINES="$2"
            shift 2
            ;;
        --client)
            MODE="client"
            shift
            ;;
        --server)
            MODE="server"
            shift
            ;;
        --all)
            MODE="all"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}[!] Opção desconhecida: $1${NC}"
            usage
            ;;
    esac
done

print_header() {
    echo -e "${CYAN}==================================================================${NC}"
    echo -e "${BOLD} RUADAN - MONITORAMENTO DE LOGS DO OLLAMA${NC}"
    echo -e "${CYAN}==================================================================${NC}"

    # Status em tempo real do contêiner Docker ruadan-ollama
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^ruadan-ollama$"; then
        local model_info
        model_info=$(docker exec ruadan-ollama ollama ps 2>/dev/null | awk 'NR>1 {print $1, "(" $3 ", " $4 ")"}' | head -n 1)
        [ -z "$model_info" ] && model_info="Ollama pronto (modelo qwen3:8b disponível em disco)"
        echo -e "${GREEN}[+] Contêiner 'ruadan-ollama':${NC} ${BOLD}ATIVO (Docker)${NC} | Memória: ${CYAN}${model_info}${NC}"
    else
        echo -e "${YELLOW}[!] Contêiner 'ruadan-ollama':${NC} NÃO DETECTADO"
    fi

    # Status de execução do Ruadan
    if docker ps --format '{{.Image}}' 2>/dev/null | grep -q "ruadan:kali"; then
        echo -e "${CYAN}[*] Ruadan (Kali Container):${NC} ${BOLD}EM EXECUÇÃO${NC}"
    else
        echo -e "${YELLOW}[*] Ruadan (Kali Container):${NC} Inativo no momento"
    fi
    echo -e "${CYAN}------------------------------------------------------------------${NC}"
}

detect_server_source() {
    # 1. Verifica se contêiner Docker ruadan-ollama está ativo
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^ruadan-ollama$"; then
        echo "docker"
        return
    fi

    # 2. Verifica se systemd ollama.service está ativo
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ollama 2>/dev/null; then
        echo "systemd"
        return
    fi

    # 3. Verifica se arquivo output/ollama.log existe
    if [ -f "${OUTPUT_DIR}/ollama.log" ] || [ -f "${ROOT_DIR}/ruadan/output/ollama.log" ]; then
        echo "file"
        return
    fi

    # 4. Verifica se processo ollama está rodando
    if pgrep -x ollama >/dev/null 2>&1; then
        echo "systemd" # Provável gerenciado por journald
        return
    fi

    echo "none"
}

show_server_logs() {
    local source
    source=$(detect_server_source)

    echo -e "${YELLOW}[*] Fonte dos Logs do Servidor:${NC} ${BOLD}${source}${NC}"

    case "$source" in
        docker)
            echo -e "${GREEN}[+] Contêiner 'ruadan-ollama' ativo no Docker.${NC}"
            if [ "$FOLLOW" -eq 1 ]; then
                echo -e "${CYAN}[*] Iniciando streaming dos logs do contêiner Docker (Ctrl+C para sair)...${NC}\n"
                exec docker logs -f --tail "${LINES}" ruadan-ollama
            else
                echo -e "${CYAN}[*] Exibindo últimas ${LINES} linhas de logs do Docker:${NC}\n"
                docker logs --tail "${LINES}" ruadan-ollama 2>&1
            fi
            ;;
        systemd)
            echo -e "${GREEN}[+] Serviço 'ollama.service' ativo no host via Systemd/Journald.${NC}"
            if [ "$FOLLOW" -eq 1 ]; then
                echo -e "${CYAN}[*] Iniciando streaming dos logs via journalctl (Ctrl+C para sair)...${NC}\n"
                exec journalctl -u ollama -f -n "${LINES}" --no-pager
            else
                echo -e "${CYAN}[*] Exibindo últimas ${LINES} linhas via journalctl:${NC}\n"
                journalctl -u ollama -n "${LINES}" --no-pager
            fi
            ;;
        file)
            local log_path="${OUTPUT_DIR}/ollama.log"
            if [ ! -f "$log_path" ]; then
                log_path="${ROOT_DIR}/ruadan/output/ollama.log"
            fi
            echo -e "${GREEN}[+] Lendo arquivo persistido: ${log_path}${NC}"
            if [ "$FOLLOW" -eq 1 ]; then
                echo -e "${CYAN}[*] Acompanhando arquivo em tempo real (Ctrl+C para sair)...${NC}\n"
                exec tail -n "${LINES}" -f "${log_path}"
            else
                echo -e "${CYAN}[*] Exibindo últimas ${LINES} linhas de ${log_path}:${NC}\n"
                tail -n "${LINES}" "${log_path}"
            fi
            ;;
        none)
            echo -e "${RED}[!] Nenhum serviço Ollama ativo ou arquivo 'output/ollama.log' localizado.${NC}"
            echo -e "    Dica: Inicie o serviço com ${BOLD}./start.sh${NC} ou ${BOLD}systemctl start ollama${NC}."
            ;;
    esac
}

show_client_logs() {
    # Busca dinâmica pelo log de interações mais recente em todo o workspace
    local client_log=""
    local best_mtime=0

    # Candidatos prioritários
    local candidates=(
        "${ROOT_DIR}/ruadan/output/ai_evidence/ollama_interactions.log"
        "${ROOT_DIR}/output/ai_evidence/ollama_interactions.log"
        "${ROOT_DIR}/ruadan/output/ollama_client.log"
        "${ROOT_DIR}/output/ollama_client.log"
    )

    # Busca arquivos adicionais dinamicamente (subdiretórios de campanhas)
    while IFS= read -r f; do
        if [ -n "$f" ]; then
            candidates+=("$f")
        fi
    done < <(find "${ROOT_DIR}" -maxdepth 4 -type f \( -name "ollama_interactions.log" -o -name "ollama_client.log" \) 2>/dev/null || true)

    for cand in "${candidates[@]}"; do
        if [ -f "$cand" ]; then
            local sz; sz=$(stat -c %s "$cand" 2>/dev/null || echo 0)
            if [ "$sz" -gt 0 ]; then
                local m; m=$(stat -c %Y "$cand" 2>/dev/null || echo 0)
                if [ "$m" -gt "$best_mtime" ]; then
                    best_mtime="$m"
                    client_log="$cand"
                fi
            fi
        fi
    done

    # Se nenhum tiver conteúdo ainda, usa o caminho padrão do Ruadan
    if [ -z "$client_log" ]; then
        client_log="${ROOT_DIR}/ruadan/output/ai_evidence/ollama_interactions.log"
        mkdir -p "$(dirname "$client_log")"
        touch "$client_log" 2>/dev/null || true
    fi

    echo -e "\n${YELLOW}[*] Interações do Cliente LLM Ruadan <-> Ollama:${NC}"
    echo -e "${GREEN}[+] Arquivo monitorado:${NC} ${BOLD}${client_log}${NC}"

    local cur_sz; cur_sz=$(stat -c %s "$client_log" 2>/dev/null || echo 0)
    if [ "$cur_sz" -eq 0 ]; then
        echo -e "${YELLOW}[i] O arquivo está aguardando novas interações do Ruadan...${NC}"
        echo -e "    Dica: Dispare um pentest com IA via ${BOLD}./start.sh${NC} para ver os prompts e respostas."
    fi

    if [ "$FOLLOW" -eq 1 ]; then
        echo -e "${CYAN}[*] Acompanhando interações e prompts em tempo real com tail -F (Ctrl+C para sair)...${NC}\n"
        exec tail -n "${LINES}" -F "${client_log}"
    else
        echo -e "${CYAN}[*] Exibindo últimas ${LINES} linhas de interações:${NC}\n"
        tail -n "${LINES}" "${client_log}"
    fi
}

print_header

if [ "$MODE" == "server" ]; then
    show_server_logs
elif [ "$MODE" == "client" ]; then
    show_client_logs
elif [ "$MODE" == "all" ]; then
    show_server_logs
    show_client_logs
fi
