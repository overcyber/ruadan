# Análise Completa: Canário + RL Policy + GPU Setup

**Data:** 2026-09-26 | **Repo:** https://github.com/overcyber/ruadan (branch: `main`)

## 1. Por que "canário não confirmado" no LLM Exploit Modifier

### O código que o LLM gerou:
```python
s.connect(('192.168.50.222', 3128))          # conecta no Squid proxy
s.sendall(b'CONNECT 127.0.0.1:80 ...')      # tenta túnel para host interno
resp = s.recv(4096)
if b'200' not in resp.splitlines()[0]:      # ← SQUID RESPONDEU 403/407
    return                                    # ← sai SEM imprimir canário
```

### Diagnóstico:
O Squid proxy no 222 **NÃO é vulnerável** a este bypass específico:
- O `CONNECT` para `127.0.0.1:80` foi **negado** (403 Forbidden ou 407 Auth Required)
- O exploit Python executou sem erros (exit code 0)
- Mas a condição de sucesso (`b'200' in resp`) nunca foi atingida
- O canário `RUADAN_PWNED_<hex>` nunca foi impresso

### Por que isso é CORRETO:
O sistema reportou honestamente `EXPLOIT_MODIFIED_PARTIAL` (executou sem erro mas
canário não confirmado) em vez de falsamente afirmar sucesso. **O Squid está
configurado corretamente** e não permite CONNECT para hosts internos.

---

## 2. Por que o RL NUNCA escolhe DISCOVER_SERVICES

### Action probabilities (do checkpoint .pt):
```
Ação                   Probabilidade
DISCOVER_REMOTE        0.082 (8.2%)
DISCOVER_SERVICES      0.038 (3.8%)   ← QUASE ZERO
EXPLOIT_REMOTE         0.880 (88%)    ← DOMINANTE
PRIVILEGE_ESCALATE     0.958 (95.8%)  (quando aplicável)
```

### Diagnóstico:
O modelo RL **foi treinado** com uma política que prefere EXPLOIT_REMOTE.
Ele aprendeu que:
1. O nmap preliminar (que o AI Brain SEMPRE roda) já descobre portas e serviços
2. DISCOVER_SERVICES é redundante depois do nmap preliminar
3. EXPLOIT_REMOTE maximiza reward (avança na kill chain)

### Solução aplicada:
`"Information Gathering"` foi adicionado ao EXPLOIT_REMOTE no dispatcher.
Agora, mesmo quando o RL escolhe EXPLOIT_REMOTE (88% das vezes), a enumeração
de SSH/NFS/RDP/VNC/DNS/SNMP/SMB acontece automaticamente como parte da ação.

---

## 3. Setup para Máquina com GPU

### Repo completo:
```
https://github.com/overcyber/ruadan
branch: main
```

### Clone e setup na nova máquina:
```bash
git clone https://github.com/overcyber/ruadan
cd ruadan

# Setup automático (detecta GPU, baixa modelos, constrói imagens)
./setup.sh
```

### O que o setup.sh faz:
1. Verifica Docker + Docker Compose
2. Detecta GPU NVIDIA (nvidia-smi)
3. Configura NVIDIA Container Runtime (se necessário)
4. Baixa modelos Ollama (qwen3:8b + gpt-oss:20b) COM GPU se disponível
5. Constrói imagem red-mppo (PyTorch)
6. Constrói imagem ruadan:kali (Kali + arsenal + metasploit)
7. Inicia red-MPPO RL Server
8. Cria estrutura de diretórios

### GPU config:
- `start.sh`: auto-detecta GPU via nvidia-smi → `docker run --gpus all`
- `docker-compose.gpu.yml`: override para `docker compose` com GPU
- `setup.sh`: baixa modelos com GPU acelerada

### Para rodar:
```bash
# Alvos em ruadan/targets/
./start.sh -hostFile /ruadan/targets/meu_lab.txt

# Monitorar
./start.sh --logs --client -f

# Sumário forense
./start.sh --summary
```

### Requisitos da máquina GPU:
1. Docker instalado: `curl -fsSL https://get.docker.com | sh`
2. NVIDIA driver: `sudo apt install nvidia-driver-535`
3. NVIDIA Container Toolkit: `sudo apt install nvidia-container-toolkit`
4. Restart Docker: `sudo systemctl restart docker`
5. Verificar: `nvidia-smi` (deve listar GPUs)

### Com GPU, o que melhora:
| Componente | CPU | GPU |
|---|---|---|
| qwen3:8b | ~2min/decisão | ~2s/decisão |
| gpt-oss:20b | ~5-10min/caça | ~30s/caça |
| LLM Exploit Modifier | ~3-5min/exploit | ~15-30s/exploit |
| Total do ciclo IA | ~2-4h | ~30-60min |
