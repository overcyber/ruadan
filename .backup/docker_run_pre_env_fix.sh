#!/usr/bin/env bash
# ==============================================================================
# Ruadan - Kali Linux Docker Execution Helper Script
# Integrado com red-MPPO (RL Server .pt) e Ollama (Multi-LLM)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "${SCRIPT_DIR}")"
IMAGE_NAME="ruadan:kali"

# Ensure directories for persistence exist locally on host
mkdir -p "${SCRIPT_DIR}/output"
mkdir -p "${SCRIPT_DIR}/targets"
mkdir -p "${ROOT_DIR}/targets"
mkdir -p "${ROOT_DIR}/output"

# Mirror all target files between ROOT_DIR and SCRIPT_DIR
cp -u "${ROOT_DIR}/targets/"* "${SCRIPT_DIR}/targets/" 2>/dev/null || true
cp -u "${SCRIPT_DIR}/targets/"* "${ROOT_DIR}/targets/" 2>/dev/null || true

# Detect OS for network mode
NET_ARG="--network host"
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS Docker Desktop does not support --network host
    NET_ARG=""
fi

# ==============================================================================
# Replica as entradas do /etc/hosts do host no container via --add-host.
# POR QUÊ: o bind mount de arquivo único (-v /etc/hosts) fica STALE quando o
# /etc/hosts do host é recriado (vim/sed -i usam rename → novo inode) DEPOIS
# que o container/subprocesso já subiu. Com --add-host, cada docker run captura
# o /etc/hosts ATUAL do host no momento da execução — e o container resolve
# os hostnames do laboratório (ex: juice.octopux → 192.168.50.160) mesmo em
# redes bridge (macOS, onde --network host não existe).
# ==============================================================================
HOST_EXTRA_ARGS=()
while IFS= read -r _hline; do
    _hline="${_hline%%#*}"
    [ -z "${_hline//[$' \t']/ }" ] && continue
    _hip="$(echo "${_hline}" | awk '{print $1}')"
    case "${_hip}" in
        127.*|::1|0.0.0.0) continue ;;
    esac
    for _hname in $(echo "${_hline}" | awk '{ $1=""; print }'); do
        case "${_hname}" in
            localhost*|ip6-*|broadcasthost) continue ;;
        esac
        HOST_EXTRA_ARGS+=(--add-host "${_hname}:${_hip}")
    done
done < /etc/hosts

export NO_PROXY="localhost,127.0.0.1,::1,ruadan-ollama,ruadan-red-mppo"
export no_proxy="localhost,127.0.0.1,::1,ruadan-ollama,ruadan-red-mppo"

# ==============================================================================
# Proteção anti-runs-paralelos: dois scans simultâneos no mesmo outputFolder
# intercalam logs, sobrescrevem evidências de IA e corrompem o nmap_dict.
# Bypass consciente: RUADAN_ALLOW_PARALLEL=1 ./docker-run.sh ...
# ==============================================================================
check_parallel_run() {
    if [ "${RUADAN_ALLOW_PARALLEL:-0}" = "1" ]; then
        echo "[!] RUADAN_ALLOW_PARALLEL=1 — proteção anti-paralelo desativada (por sua conta e risco)."
        return 0
    fi
    local running
    running=$(docker ps --filter "ancestor=${IMAGE_NAME}" --format "{{.ID}} {{.RunningFor}}" | head -3)
    if [ -n "$running" ]; then
        echo "[!] ERRO: já existe um run do Ruadan ativo (imagem ${IMAGE_NAME}):"
        echo "$running" | sed 's/^/      /'
        echo ""
        echo "    Runs paralelos no mesmo outputFolder intercalam logs, sobrescrevem"
        echo "    evidências de IA e corrompem o estado compartilhado."
        echo "    Finalize o run atual (docker stop <ID>) ou, se REALMENTE quiser"
        echo "    paralelizar com pastas distintas: RUADAN_ALLOW_PARALLEL=1 ./start.sh ..."
        exit 1
    fi
}

# Function to ensure Ollama container is running (local or via Docker) with host models
ensure_ollama() {
    TARGET_MODEL="${LLM_MODEL:-qwen3:8b}"
    echo "[*] [1/2] Verificando serviço Ollama (porta 11434)..."

    # Detecta pasta de modelos local do host
    HOST_OLLAMA_DIR=""
    if [ -d "/usr/share/ollama/.ollama/models" ]; then
        HOST_OLLAMA_DIR="/usr/share/ollama/.ollama"
    elif [ -d "${HOME}/.ollama/models" ]; then
        HOST_OLLAMA_DIR="${HOME}/.ollama"
    fi

    OLLAMA_MOUNT="-v ollama_models:/root/.ollama"
    if [ -n "${HOST_OLLAMA_DIR}" ]; then
        OLLAMA_MOUNT="-v ${HOST_OLLAMA_DIR}:/root/.ollama"
        echo "[+] Pasta local de modelos Ollama detectada no host: ${HOST_OLLAMA_DIR}"
    fi

    OLLAMA_IS_DOCKER=0
    # Se contêiner ruadan-ollama existir, verifica se possui o modelo desejado
    if docker ps -a --format '{{.Names}}' | grep -q "^ruadan-ollama$"; then
        OLLAMA_IS_DOCKER=1
        if ! docker exec ruadan-ollama ollama list 2>/dev/null | grep -q "${TARGET_MODEL}"; then
            echo "[*] Contêiner ruadan-ollama existente não possui o modelo '${TARGET_MODEL}' ou está com volume desatualizado."
            echo "[*] Recriando contêiner ruadan-ollama com a montagem da pasta de modelos do host..."
            docker rm -f ruadan-ollama >/dev/null 2>&1 || true
        fi
    fi

    if curl -s -f --noproxy '*' --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1 && ! docker ps -a --format '{{.Names}}' | grep -q "^ruadan-ollama$"; then
        echo "[+] Serviço Ollama nativo detectado no host e respondendo na porta 11434."
    else
        OLLAMA_IS_DOCKER=1

        if docker ps -a --format '{{.Names}}' | grep -q "^ruadan-ollama$"; then
            if ! docker ps --format '{{.Names}}' | grep -q "^ruadan-ollama$"; then
                echo "[*] Iniciando contêiner ruadan-ollama existente..."
                docker start ruadan-ollama >/dev/null 2>&1 || true
            fi
        else
            # Detecta suporte a GPU NVIDIA
            GPU_OPTS=""
            if command -v nvidia-smi >/dev/null 2>&1 && docker info 2>/dev/null | grep -iq "nvidia\|cdi"; then
                GPU_OPTS="--gpus all"
                echo "[+] GPU NVIDIA detectada! Ativando aceleração de hardware (--gpus all)..."
            fi

            PORT_OR_NET="${NET_ARG}"
            if [ -z "${PORT_OR_NET}" ]; then
                PORT_OR_NET="-p 11434:11434"
            fi

            echo "[*] Criando contêiner ruadan-ollama com imagem ollama/ollama:latest e montagem de modelos..."
            docker run -d --name ruadan-ollama \
                ${GPU_OPTS} \
                ${PORT_OR_NET} \
                ${OLLAMA_MOUNT} \
                -e OLLAMA_KEEP_ALIVE=24h \
                --restart unless-stopped \
                ollama/ollama:latest >/dev/null 2>&1
        fi

        echo "[*] Aguardando prontidão do Ollama na porta 11434..."
        OLLAMA_READY=0
        for i in {1..30}; do
            if docker exec ruadan-ollama ollama list >/dev/null 2>&1 || curl -s -f --noproxy '*' --max-time 1 http://localhost:11434/api/tags >/dev/null 2>&1; then
                OLLAMA_READY=1
                echo "[+] Contêiner ruadan-ollama ativo e respondendo na porta 11434!"
                break
            fi
            sleep 1
        done

        if [ "$OLLAMA_READY" -eq 0 ]; then
            echo "[!] Aviso: Timeout aguardando inicialização do Ollama via Docker."
        fi
    fi

    # Garante que o modelo esteja disponível no Ollama
    echo "[*] Verificando modelo '${TARGET_MODEL}' no Ollama..."
    if (curl -s -f --noproxy '*' http://localhost:11434/api/tags 2>/dev/null || true) | grep -q "${TARGET_MODEL}" || (docker exec ruadan-ollama ollama list 2>/dev/null | grep -q "${TARGET_MODEL}") || (command -v ollama >/dev/null 2>&1 && ollama list 2>/dev/null | grep -q "${TARGET_MODEL}"); then
        echo "[+] Modelo '${TARGET_MODEL}' confirmado e pronto no Ollama!"
    else
        echo "[*] Modelo '${TARGET_MODEL}' não encontrado no Ollama. Baixando modelo agora..."
        if [ "$OLLAMA_IS_DOCKER" -eq 1 ] || docker ps --format '{{.Names}}' | grep -q "^ruadan-ollama$"; then
            docker exec -i ruadan-ollama ollama pull "${TARGET_MODEL}" || {
                echo "[!] ERRO CRÍTICO: Falha ao obter o modelo '${TARGET_MODEL}' no contêiner ruadan-ollama."
                exit 1
            }
        elif command -v ollama >/dev/null 2>&1; then
            ollama pull "${TARGET_MODEL}" || {
                echo "[!] ERRO CRÍTICO: Falha ao obter o modelo '${TARGET_MODEL}' via ollama CLI."
                exit 1
            }
        else
            echo "[!] ERRO CRÍTICO: Não foi possível obter o modelo '${TARGET_MODEL}' automaticamente."
            exit 1
        fi
        echo "[+] Modelo '${TARGET_MODEL}' pronto para uso!"
    fi
}

# Function to ensure red-MPPO RL container is running
ensure_red_mppo() {
    echo "[*] [2/2] Verificando serviço red-MPPO RL Server..."
    RL_PORT=8000
    if curl -s -f --noproxy '*' --max-time 2 http://localhost:8000/health 2>/dev/null | grep -q "red-mppo-rl-policy-server"; then
        echo "[+] red-MPPO RL Server já está em execução na porta 8000."
    elif curl -s -f --noproxy '*' --max-time 2 http://localhost:8008/health 2>/dev/null | grep -q "red-mppo-rl-policy-server"; then
        RL_PORT=8008
        echo "[+] red-MPPO RL Server já está em execução na porta 8008."
    elif docker ps --format '{{.Names}}' | grep -q "^ruadan-red-mppo$"; then
        RL_PORT=8008
        echo "[+] Contêiner ruadan-red-mppo ativo confirmado via Docker (porta ${RL_PORT})."
    else
        # Verifica se porta 8000 está ocupada por outro processo no host
        if curl -s --noproxy '*' --max-time 1 http://localhost:8000/ >/dev/null 2>&1; then
            echo "[!] Porta 8000 ocupada por outro serviço no host. Usando porta 8008 para red-MPPO..."
            RL_PORT=8008
        fi

        echo "[*] red-MPPO RL Server não está ativo. Iniciando contêiner ruadan-red-mppo na porta ${RL_PORT}..."
        docker rm -f ruadan-red-mppo >/dev/null 2>&1 || true

        # Constrói imagem red-mppo caso não exista
        if ! docker image inspect red-mppo:latest >/dev/null 2>&1; then
            echo "[*] Construindo imagem Docker do red-mppo..."
            docker build -t red-mppo:latest -f "${ROOT_DIR}/red-MPPO-testing_model/docker/pentest/Dockerfile" "${ROOT_DIR}/red-MPPO-testing_model"
        fi

        docker run -d --name ruadan-red-mppo \
            -p ${RL_PORT}:${RL_PORT} \
            -v "${ROOT_DIR}/red-MPPO-testing_model:/repo" \
            -v "${ROOT_DIR}/red-MPPO-testing_model/data/checkpoints:/repo/data/checkpoints:ro" \
            -v "${ROOT_DIR}/data/runs:/repo/data/pentest_runs:rw" \
            -v "${ROOT_DIR}/bridge:/repo/bridge:ro" \
            -e PYTHONUNBUFFERED=1 \
            -e PYTHONPATH=/repo \
            --entrypoint python \
            --restart unless-stopped \
            red-mppo:latest \
            -m services.pentest.app.rl_server \
                --checkpoint /repo/data/checkpoints/maestro_red_ep1246800.pt \
                --port ${RL_PORT} --host 0.0.0.0 >/dev/null 2>&1

        echo "[*] Aguardando inicialização do red-MPPO RL Server..."
        for i in {1..25}; do
            if curl -s -f --noproxy '*' --max-time 1 "http://localhost:${RL_PORT}/health" | grep -q "red-mppo-rl-policy-server"; then
                echo "[+] red-MPPO RL Server ativo e respondendo na porta ${RL_PORT}!"
                break
            fi
            sleep 1
        done
    fi
    export RED_MPPO_URL="http://localhost:${RL_PORT}"
}

# Function to stream Ollama server logs to output/ollama.log
start_ollama_streamer() {
    mkdir -p "${ROOT_DIR}/output" "${SCRIPT_DIR}/output"
    local host_log="${ROOT_DIR}/output/ollama.log"
    local script_log="${SCRIPT_DIR}/output/ollama.log"
    touch "${host_log}" "${script_log}" 2>/dev/null || true

    OLLAMA_STREAM_PID=""
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^ruadan-ollama$"; then
        docker logs --tail 30 ruadan-ollama 2>&1 | tee -a "${host_log}" "${script_log}" >/dev/null || true
        docker logs -f ruadan-ollama 2>&1 | tee -a "${host_log}" "${script_log}" >/dev/null &
        OLLAMA_STREAM_PID=$!
    elif command -v journalctl >/dev/null 2>&1 && systemctl is-active --quiet ollama 2>/dev/null; then
        journalctl -u ollama -n 30 --no-pager 2>&1 | tee -a "${host_log}" "${script_log}" >/dev/null || true
        journalctl -u ollama -f --no-pager 2>&1 | tee -a "${host_log}" "${script_log}" >/dev/null &
        OLLAMA_STREAM_PID=$!
    fi

    if [ -n "$OLLAMA_STREAM_PID" ]; then
        trap 'kill -9 '"$OLLAMA_STREAM_PID"' 2>/dev/null || true; cp -u "'"${ROOT_DIR}/output/ollama"*'" "'"${SCRIPT_DIR}/output/"'" 2>/dev/null || true; cp -u "'"${SCRIPT_DIR}/output/ollama"*'" "'"${ROOT_DIR}/output/"'" 2>/dev/null || true' EXIT INT TERM
    fi
}

# Check if image exists and has required AI dependencies (numpy, yaml, requests)
NEED_BUILD=0
if [[ "$1" == "--build" ]]; then
    NEED_BUILD=1
    shift
elif ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[*] Imagem '${IMAGE_NAME}' não encontrada no Docker. Construindo pela primeira vez..."
    NEED_BUILD=1
elif ! docker run --rm --entrypoint python3 "${IMAGE_NAME}" -c "import numpy, yaml, requests" >/dev/null 2>&1; then
    echo "[!] A imagem Docker '${IMAGE_NAME}' existente está desatualizada (sem numpy/yaml)."
    echo "[*] Iniciando reconstrução automática da imagem com todas as dependências de IA..."
    NEED_BUILD=1
fi

if [ "$NEED_BUILD" -eq 1 ]; then
    echo "[*] Construindo / atualizando imagem Docker '${IMAGE_NAME}' a partir de ${SCRIPT_DIR}..."
    docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}"
fi

# Handle logs option
if [[ "$1" == "--logs" || "$1" == "-logs" || "$1" == "--logs-ollama" ]]; then
    shift
    if [ -x "${ROOT_DIR}/view_ollama_logs.sh" ]; then
        exec "${ROOT_DIR}/view_ollama_logs.sh" "$@"
    else
        echo "[!] Script view_ollama_logs.sh não encontrado em ${ROOT_DIR}."
        exit 1
    fi
fi

# Handle summary option
if [[ "$1" == "--summary" ]]; then
    echo "[*] Executing forensic analysis on artifacts in output/..."
    if command -v python3 >/dev/null 2>&1; then
        python3 "${SCRIPT_DIR}/verify_run_artifacts.py" "${SCRIPT_DIR}/output"
    else
        docker run --rm -t \
            --entrypoint python3 \
            -w /ruadan \
            -v "${SCRIPT_DIR}:/ruadan" \
            -v "${SCRIPT_DIR}/output:/ruadan/output" \
            "${IMAGE_NAME}" /ruadan/verify_run_artifacts.py /ruadan/output
    fi
    exit 0
fi

# Handle interactive shell option
if [[ "$1" == "--shell" || "$1" == "bash" ]]; then
    echo "[*] Launching interactive Kali bash shell..."
    exec docker run --rm -it \
        ${NET_ARG} \
        "${HOST_EXTRA_ARGS[@]}" \
        -w /ruadan \
        -v /etc/hosts:/etc/hosts:ro \
        -v "${SCRIPT_DIR}:/ruadan" \
        -v "${SCRIPT_DIR}/targets:/ruadan/targets" \
        -v "${SCRIPT_DIR}/targets:/targets" \
        -v "${ROOT_DIR}/targets:/root_targets" \
        -v "${SCRIPT_DIR}/output:/ruadan/output" \
        -v "${SCRIPT_DIR}/output:/output" \
        -v "${ROOT_DIR}/bridge:/bridge" \
        -v "${ROOT_DIR}/configs:/configs" \
        -v "${ROOT_DIR}/red-MPPO-testing_model:/app/red-mppo" \
        -v "${ROOT_DIR}/red-MPPO-testing_model/data/checkpoints:/app/checkpoints" \
        -e PYTHONPATH="/:/app/red-mppo:/ruadan:/bridge" \
        -e RED_MPPO_URL="${RED_MPPO_URL:-http://localhost:${RL_PORT:-8008}}" \
        -e OLLAMA_API_BASE="http://localhost:11434/v1" \
        --entrypoint /bin/bash \
        "${IMAGE_NAME}"
fi

# Check if AI mode is requested in any arguments
for arg in "$@"; do
    if [[ "$arg" == "-ai" || "$arg" == "--ai" || "$arg" == "-llmProvider" ]]; then
        ensure_ollama
        ensure_red_mppo
        break
    fi
done

# Handle default validated scan against targets/hosts.txt
if [[ "$1" == "--default" || "$1" == "-default" ]]; then
    echo "[*] Running default scan against targets/hosts.txt (including filtered ports)..."
    check_parallel_run
    ensure_ollama
    ensure_red_mppo
    start_ollama_streamer
    exec docker run --rm -t \
        ${NET_ARG} \
        "${HOST_EXTRA_ARGS[@]}" \
        -w /ruadan \
        -v /etc/hosts:/etc/hosts:ro \
        -v "${SCRIPT_DIR}:/ruadan" \
        -v "${SCRIPT_DIR}/targets:/ruadan/targets" \
        -v "${SCRIPT_DIR}/targets:/targets" \
        -v "${SCRIPT_DIR}/output:/ruadan/output" \
        -v "${SCRIPT_DIR}/output:/output" \
        -v "${ROOT_DIR}/output:/root_output" \
        -v "${ROOT_DIR}/bridge:/bridge" \
        -v "${ROOT_DIR}/configs:/configs" \
        -v "${ROOT_DIR}/red-MPPO-testing_model:/app/red-mppo" \
        -v "${ROOT_DIR}/red-MPPO-testing_model/data/checkpoints:/app/checkpoints" \
        -e PYTHONPATH="/:/app/red-mppo:/ruadan:/bridge" \
        -e RED_MPPO_URL="${RED_MPPO_URL:-http://localhost:${RL_PORT:-8008}}" \
        -e OLLAMA_API_BASE="http://localhost:11434/v1" \
        -e NO_PROXY="localhost,127.0.0.1,::1,ruadan-ollama,host.docker.internal" \
        -e no_proxy="localhost,127.0.0.1,::1,ruadan-ollama,host.docker.internal" \
        -e RUADAN_OUTPUT_DIR="/ruadan/output" \
        "${IMAGE_NAME}" \
        -hostFile /ruadan/targets/hosts.txt -outputFolder /ruadan/output -noColor -noResume -ai -llmProvider ollama -llmModel qwen3:8b -logging -verbose
fi

# If no arguments provided, display usage guide
if [ $# -eq 0 ]; then
    echo "=================================================================="
    echo " Ruadan - Kali Linux Docker Execution Helper"
    echo "=================================================================="
    echo " Uso:"
    echo "   ./docker-run.sh --default       # Escaneamento com IA (Ollama + red-MPPO + Ruadan)"
    echo "   ./docker-run.sh --summary       # Analisa e resume os relatórios em output/"
    echo "   ./docker-run.sh --logs          # Visualiza e acompanha logs do Ollama ao vivo"
    echo "   ./docker-run.sh --shell         # Abre terminal Bash interativo no Kali"
    echo "   ./docker-run.sh --build         # Reconstrói a imagem Docker"
    echo "   ./docker-run.sh [opções]        # Passa argumentos customizados para o Ruadan2.py"
    echo ""
    echo " Exemplos:"
    echo "   # Modo Tradicional (Enumeração completa de portas abertas e filtradas):"
    echo "   ./docker-run.sh -hostFile targets/hosts.txt -outputFolder output -noColor -noResume -logging"
    echo ""
    echo "   # Modo Inteligência Artificial (Inicia Ollama + red-MPPO .pt + Canários):"
    echo "   ./docker-run.sh -hostFile targets/hosts.txt -outputFolder output -noColor -noResume -ai -llmProvider ollama -llmModel qwen3:8b -logging"
    echo "=================================================================="
    exit 0
fi

# Inicia coletor de logs se estiver em modo IA
for arg in "$@"; do
    if [[ "$arg" == "-ai" || "$arg" == "--ai" || "$arg" == "-llmProvider" ]]; then
        start_ollama_streamer
        break
    fi
done

check_parallel_run

# Execute Ruadan with custom user arguments, mounting live code, bridge, red-mppo and configs
exec docker run --rm -t \
    ${NET_ARG} \
    "${HOST_EXTRA_ARGS[@]}" \
    -w /ruadan \
    -v /etc/hosts:/etc/hosts:ro \
    -v "${SCRIPT_DIR}:/ruadan" \
    -v "${SCRIPT_DIR}/targets:/ruadan/targets" \
    -v "${SCRIPT_DIR}/targets:/targets" \
    -v "${ROOT_DIR}/targets:/root_targets" \
    -v "${SCRIPT_DIR}/output:/ruadan/output" \
    -v "${SCRIPT_DIR}/output:/output" \
    -v "${ROOT_DIR}/output:/root_output" \
    -v "${ROOT_DIR}/bridge:/bridge" \
    -v "${ROOT_DIR}/configs:/configs" \
    -v "${ROOT_DIR}/red-MPPO-testing_model:/app/red-mppo" \
    -v "${ROOT_DIR}/red-MPPO-testing_model/data/checkpoints:/app/checkpoints" \
    -e PYTHONPATH="/:/app/red-mppo:/ruadan:/bridge" \
    -e RED_MPPO_URL="${RED_MPPO_URL:-http://localhost:${RL_PORT:-8008}}" \
    -e OLLAMA_API_BASE="http://localhost:11434/v1" \
    -e NO_PROXY="localhost,127.0.0.1,::1,ruadan-ollama,host.docker.internal" \
    -e no_proxy="localhost,127.0.0.1,::1,ruadan-ollama,host.docker.internal" \
    -e RUADAN_OUTPUT_DIR="/ruadan/output" \
    "${IMAGE_NAME}" "$@"
