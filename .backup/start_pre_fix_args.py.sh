#!/usr/bin/env bash
# ==============================================================================
# Ruadan + red-MPPO + Ollama - Inicializador Unificado Multi-Container
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

export NO_PROXY="localhost,127.0.0.1,::1,ruadan-ollama,ruadan-red-mppo"
export no_proxy="localhost,127.0.0.1,::1,ruadan-ollama,ruadan-red-mppo"

# Atalhos rápidos de gerenciamento e logs
if [[ "$1" == "--logs" || "$1" == "-logs" || "$1" == "--logs-ollama" ]]; then
    shift
    exec "${SCRIPT_DIR}/view_ollama_logs.sh" "$@"
fi

if [[ "$1" == "--summary" || "$1" == "-summary" ]]; then
    shift
    exec "${SCRIPT_DIR}/ruadan/docker-run.sh" --summary "$@"
fi

echo "=================================================================="
echo " RUADAN + RED-MPPO + OLLAMA - INICIALIZADOR OPERACIONAL"
echo "=================================================================="

# 1. Garante que o serviço Ollama esteja ativo com os modelos do host montados
TARGET_MODEL="${LLM_MODEL:-qwen3:8b}"
echo "[*] [1/3] Verificando serviço Ollama (porta 11434)..."

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
    # Verifica se o contêiner está rodando com o volume correto e tem o modelo
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

        echo "[*] Criando contêiner ruadan-ollama com imagem ollama/ollama:latest e montagem de modelos..."
        docker run -d --name ruadan-ollama \
            ${GPU_OPTS} \
            --network host \
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

# 2. Garante que o modelo qwen3:8b esteja disponível no Ollama
echo "[*] [2/3] Verificando modelo '${TARGET_MODEL}' no Ollama..."
if (curl -s -f --noproxy '*' http://localhost:11434/api/tags 2>/dev/null || true) | grep -q "${TARGET_MODEL}" || (docker exec ruadan-ollama ollama list 2>/dev/null | grep -q "${TARGET_MODEL}") || (command -v ollama >/dev/null 2>&1 && ollama list 2>/dev/null | grep -q "${TARGET_MODEL}"); then
    echo "[+] Modelo '${TARGET_MODEL}' confirmado e pronto para inferência no Ollama!"
else
    echo "[*] Modelo '${TARGET_MODEL}' não encontrado no Ollama. Tentando download..."
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

# 3. Garante que o microserviço red-MPPO (RL Server .pt) esteja ativo
echo "[*] [3/3] Verificando serviço red-MPPO RL Server..."
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

    if ! docker image inspect red-mppo:latest >/dev/null 2>&1; then
        echo "[*] Construindo imagem Docker do red-mppo..."
        docker build -t red-mppo:latest -f "${SCRIPT_DIR}/red-MPPO-testing_model/docker/pentest/Dockerfile" "${SCRIPT_DIR}/red-MPPO-testing_model"
    fi

    docker run -d --name ruadan-red-mppo \
        -p ${RL_PORT}:${RL_PORT} \
        -v "${SCRIPT_DIR}/red-MPPO-testing_model:/repo" \
        -v "${SCRIPT_DIR}/red-MPPO-testing_model/data/checkpoints:/repo/data/checkpoints:ro" \
        -v "${SCRIPT_DIR}/data/runs:/repo/data/pentest_runs:rw" \
        -v "${SCRIPT_DIR}/bridge:/repo/bridge:ro" \
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
            echo "[+] red-MPPO RL Server ativo com sucesso na porta ${RL_PORT}!"
            break
        fi
        sleep 1
    done
fi
export RED_MPPO_URL="http://localhost:${RL_PORT}"


# 4. Executa Ruadan conectado aos dois serviços
echo "=================================================================="
echo " DISPARANDO RUADAN COM IA (RL + LLM) E AUDITORIA COMPLETA"
echo "=================================================================="

# Sincroniza alvos entre raiz e ruadan/targets
mkdir -p "${SCRIPT_DIR}/targets" "${SCRIPT_DIR}/ruadan/targets"
cp -u "${SCRIPT_DIR}/targets/"* "${SCRIPT_DIR}/ruadan/targets/" 2>/dev/null || true
cp -u "${SCRIPT_DIR}/ruadan/targets/"* "${SCRIPT_DIR}/targets/" 2>/dev/null || true

if [ $# -eq 0 ]; then
    echo "[*] Executando escaneamento autônomo com IA contra targets/hosts.txt..."
    exec bash "${SCRIPT_DIR}/ruadan/docker-run.sh" \
        -hostFile /ruadan/targets/hosts.txt \
        -outputFolder /ruadan/output \
        -noColor \
        -noResume \
        -ai \
        -llmProvider "${LLM_PROVIDER:-ollama}" \
        -llmModel "${LLM_MODEL:-qwen3:8b}" \
        -logging \
        -verbose
else
    # Processa argumentos fornecidos garantindo que o modo IA seja ativado
    ARGS=()
    HAS_AI=0
    HAS_PROVIDER=0
    HAS_MODEL=0
    HAS_OUTPUT=0
    HAS_NOCOLOR=0
    HAS_NORESUME=0
    HAS_LOGGING=0
    HAS_VERBOSE=0

    for arg in "$@"; do
        if [[ "$arg" == "-ai" || "$arg" == "--ai" ]]; then HAS_AI=1; fi
        if [[ "$arg" == "-llmProvider" ]]; then HAS_PROVIDER=1; fi
        if [[ "$arg" == "-llmModel" ]]; then HAS_MODEL=1; fi
        if [[ "$arg" == "-outputFolder" ]]; then HAS_OUTPUT=1; fi
        if [[ "$arg" == "-noColor" ]]; then HAS_NOCOLOR=1; fi
        if [[ "$arg" == "-noResume" ]]; then HAS_NORESUME=1; fi
        if [[ "$arg" == "-logging" ]]; then HAS_LOGGING=1; fi
        if [[ "$arg" == "-verbose" ]]; then HAS_VERBOSE=1; fi
        ARGS+=("$arg")
    done

    # Injeta flags de IA e logging caso não tenham sido especificadas
    if [ "$HAS_AI" -eq 0 ]; then ARGS+=("-ai"); fi
    if [ "$HAS_PROVIDER" -eq 0 ]; then ARGS+=("-llmProvider" "${LLM_PROVIDER:-ollama}"); fi
    if [ "$HAS_MODEL" -eq 0 ]; then ARGS+=("-llmModel" "${LLM_MODEL:-qwen3:8b}"); fi
    if [ "$HAS_OUTPUT" -eq 0 ]; then ARGS+=("-outputFolder" "/ruadan/output"); fi
    if [ "$HAS_NOCOLOR" -eq 0 ]; then ARGS+=("-noColor"); fi
    if [ "$HAS_NORESUME" -eq 0 ]; then ARGS+=("-noResume"); fi
    if [ "$HAS_LOGGING" -eq 0 ]; then ARGS+=("-logging"); fi
    if [ "$HAS_VERBOSE" -eq 0 ]; then ARGS+=("-verbose"); fi

    echo "[*] Disparando Ruadan com parâmetros customizados e Modo IA ativado..."
    echo "[*] Argumentos finais: ${ARGS[*]}"
    exec bash "${SCRIPT_DIR}/ruadan/docker-run.sh" "${ARGS[@]}"
fi
