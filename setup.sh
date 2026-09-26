#!/bin/bash
# ==============================================================================
# Ruadan — Setup para nova máquina (com ou sem GPU)
# ==============================================================================
# Uso: ./setup.sh
#
# Detecta automaticamente:
#   - Docker + Docker Compose
#   - GPU NVIDIA (passa --gpus all para Ollama)
#   - Modelos Ollama (baixa se necessário)
#   - Constrói imagens Docker
#   - Cria estrutura de diretórios
# ==============================================================================
set -e

echo "═══════════════════════════════════════════════════════════════"
echo "  RUADAN — Setup de Nova Máquina"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# 1. Verifica Docker
if ! command -v docker &>/dev/null; then
    echo "[ERRO] Docker não instalado. Instale com:"
    echo "  curl -fsSL https://get.docker.com | sh"
    exit 1
fi
echo "[✓] Docker: $(docker --version)"

# 2. Verifica Docker Compose
if docker compose version &>/dev/null; then
    echo "[✓] Docker Compose: $(docker compose version --short)"
elif command -v docker-compose &>/dev/null; then
    echo "[✓] Docker Compose (legacy): $(docker-compose --version)"
else
    echo "[ERRO] Docker Compose não instalado"
    exit 1
fi

# 3. Detecta GPU NVIDIA
GPU_INFO=""
GPU_COUNT=0
if command -v nvidia-smi &>/dev/null; then
    GPU_COUNT=$(nvidia-smi --list-gpus 2>/dev/null | wc -l)
    if [ "$GPU_COUNT" -gt 0 ]; then
        GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null | head -1)
        echo "[✓] GPU NVIDIA detectada: ${GPU_COUNT}x ${GPU_INFO}"

        # Verifica se o runtime NVIDIA está configurado no Docker
        if docker info 2>/dev/null | grep -iq "nvidia\|cdi"; then
            echo "[✓] NVIDIA Container Runtime configurado no Docker"
        else
            echo "[!] NVIDIA Container Runtime NÃO configurado. Instale:"
            echo "    sudo apt-get install nvidia-container-toolkit nvidia-container-runtime"
            echo "    sudo systemctl restart docker"
        fi
    else
        echo "[i] nvidia-smi existe mas nenhuma GPU encontrada"
    fi
else
    echo "[i] Sem GPU NVIDIA (CPU inference)"
fi

# 4. Cria estrutura de diretórios
mkdir -p ruadan/output ruadan/targets ruadan/_archive .backup contexto
echo "[✓] Diretórios criados"

# 5. Copia .env
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[✓] .env criado (edite para configurar chaves de API se necessário)"
fi

# 6. Baixa modelos Ollama
echo ""
echo "─── Modelos Ollama ───"
MODELS_NEEDED=("qwen3:8b" "gpt-oss:20b")

for MODEL in "${MODELS_NEEDED[@]}"; do
    if curl -s --max-time 3 --noproxy '*' http://localhost:11434/api/tags | grep -q "\"$MODEL\""; then
        echo "[✓] $MODEL já disponível"
    else
        echo "[*] Baixando $MODEL..."
        if [ "$GPU_COUNT" -gt 0 ]; then
            # Com GPU: usa docker run com --gpus all
            if docker ps -a --format '{{.Names}}' | grep -q "^ruadan-ollama$"; then
                docker rm -f ruadan-ollama 2>/dev/null || true
            fi
            docker run -d --name ruadan-ollama \
                --gpus all \
                -p 11434:11434 \
                -v ollama_models:/root/.ollama \
                -e OLLAMA_KEEP_ALIVE=24h \
                --restart unless-stopped \
                ollama/ollama:latest
            sleep 5
            docker exec ruadan-ollama ollama pull "$MODEL"
        else
            # Sem GPU: docker run normal
            if docker ps -a --format '{{.Names}}' | grep -q "^ruadan-ollama$"; then
                docker rm -f ruadan-ollama 2>/dev/null || true
            fi
            docker run -d --name ruadan-ollama \
                -p 11434:11434 \
                -v ollama_models:/root/.ollama \
                -e OLLAMA_KEEP_ALIVE=24h \
                --restart unless-stopped \
                ollama/ollama:latest
            sleep 5
            docker exec ruadan-ollama ollama pull "$MODEL"
        fi
        echo "[✓] $MODEL baixado"
    fi
done

# 7. Constrói imagem do red-MPPO
echo ""
echo "─── Construção de imagens ───"
if ! docker image inspect red-mppo:latest &>/dev/null; then
    echo "[*] Construindo imagem red-mppo (PyTorch CPU)..."
    docker build -t red-mppo:latest \
        -f red-MPPO-testing_model/docker/pentest/Dockerfile \
        red-MPPO-testing_model
    echo "[✓] red-mppo construída"
else
    echo "[✓] red-mppo já existe"
fi

# 8. Constrói imagem do Ruadan
if ! docker image inspect ruadan:kali &>/dev/null; then
    echo "[*] Construindo imagem ruadan:kali (Kali + arsenal)..."
    docker build -t ruadan:kali ruadan/
    echo "[✓] ruadan:kali construída"
else
    echo "[✓] ruadan:kali já existe"
fi

# 9. Inicia red-MPPO RL Server
if ! curl -s --max-time 2 --noproxy '*' http://localhost:8008/health | grep -q "red-mppo"; then
    echo "[*] Iniciando red-MPPO RL Server..."
    if docker ps -a --format '{{.Names}}' | grep -q "^ruadan-red-mppo$"; then
        docker start ruadan-red-mppo
    else
        docker run -d --name ruadan-red-mppo \
            -p 8008:8008 \
            -v "$(pwd)/red-MPPO-testing_model:/repo" \
            -v "$(pwd)/red-MPPO-testing_model/data/checkpoints:/repo/data/checkpoints:ro" \
            -v "$(pwd)/data/runs:/repo/data/pentest_runs:rw" \
            -v "$(pwd)/bridge:/repo/bridge:ro" \
            -e PYTHONUNBUFFERED=1 \
            -e PYTHONPATH=/repo \
            --entrypoint python \
            --restart unless-stopped \
            red-mppo:latest \
            -m services.pentest.app.rl_server \
                --checkpoint /repo/data/checkpoints/maestro_red_ep1246800.pt \
                --port 8008 --host 0.0.0.0
    fi
    sleep 5
    echo "[✓] red-MPPO ativo"
else
    echo "[✓] red-MPPO já ativo"
fi

# 10. Resumo
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  SETUP COMPLETO!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "GPU: ${GPU_INFO:-CPU (sem GPU)}"
echo "Ollama: $(curl -s --noproxy '*' http://localhost:11434/api/tags 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d.get("models",[])), "modelos")' 2>/dev/null || echo 'verificar')"
echo "red-MPPO: $(curl -s --noproxy '*' http://localhost:8008/health 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo 'verificar')"
echo ""
echo "Para rodar:"
echo "  ./start.sh -hostFile /ruadan/targets/meu_lab.txt"
echo ""
echo "Para monitorar:"
echo "  ./start.sh --logs --client -f"
echo ""
echo "Alvos disponíveis em ruadan/targets/"
ls -1 ruadan/targets/ 2>/dev/null | sed 's/^/  - /'
