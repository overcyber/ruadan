# Guia de Execução do Ruadan em Docker: Da Enumeração Clássica à Orquestração Autônoma com IA

Este manual documenta a arquitetura de execução do **Ruadan** em contêineres Docker, detalhando o funcionamento de rede, montagem de volumes, análise forense dos relatórios gerados e transição para o modo autônomo com IA (red-MPPO e Multi-LLM).

---

## 1. Modo Standalone (`docker run`): Execução Clássica de Enumeração

### O Comando Executado

```bash
docker run --rm -t \
  --network host \
  -v /system/ruadan-new/ruadan/output:/ruadan/output \
  -v /system/ruadan-new/ruadan/targets:/ruadan/targets \
  ruadan:kali \
  -hostFile targets/hosts.txt -outputFolder output -noColor -logging
```

### Anatomia Técnica dos Parâmetros:

| Parâmetro | Tipo | Descrição e Justificativa Técnica |
| :--- | :--- | :--- |
| `docker run --rm` | Docker Flag | Garante a remoção do contêiner assim que o processo terminar, mantendo o ambiente limpo. |
| `-t` | Docker Flag | Aloca um pseudo-TTY para manter o flush de logs e barras de progresso do terminal em tempo real. |
| `--network host` | Docker Flag | **Fundamental para pentest**: Remove o isolamento de rede do Docker, permitindo que ferramentas como `nmap` enviem pacotes RAW diretos pelas interfaces físicas (`eth0`, `wlan0`, etc.) sem quebrar TCP SYN scans, fragmentação ou detecção de SO. |
| `-v .../output:/ruadan/output` | Docker Volume | Monta o diretório de relatórios do host dentro do container para persistência permanente. |
| `-v .../targets:/ruadan/targets` | Docker Volume | Monta o arquivo `hosts.txt` contendo os IPs de escopo (`192.168.50.210`). |
| `ruadan:kali` | Imagem Docker | Imagem construída a partir do `kalilinux/kali-rolling` com o arsenal do Ruadan. |
| `-hostFile targets/hosts.txt` | Ruadan CLI | Caminho do arquivo de alvos relativo ao container. |
| `-outputFolder output` | Ruadan CLI | Diretório onde os artefatos de cada host serão estruturados. |
| `-noColor` | Ruadan CLI | Desativa códigos de escape ANSI nos arquivos de saída para logs legíveis. |
| `-logging` | Ruadan CLI | Habilita a escrita contínua de `debuglog.txt` e `verboselog.txt`. |

---

## 2. Análise dos Logs e Artefatos Produzidos

Abaixo está o mapa de artefatos gerados pelo Ruadan contra o alvo `192.168.50.210`:

```
output/
├── 192_168_50_210/
│   ├── always/
│   │   ├── Nmap_Fast_TCP_0.txt                # 22, 7070, 8080 abertas
│   │   ├── Nmap_All_TCP_0.txt                 # Varredura completa 1-65535
│   │   └── Nmap_Vulnerability_Scan_*.txt     # NSE scripts de vuln
│   ├── unknown/
│   │   ├── HTTP_What_Web_8080.txt             # Identificação de llama.cpp
│   │   ├── HTTP_Nikto_Fast_8080.txt           # 6 alertas de segurança web
│   │   ├── HTTP_Nikto_Tests_8080.txt          # Testes aprofundados Nikto
│   │   ├── HTTP_Cewl_Password_List_8080.txt   # Palavras-chave extraídas da página
│   │   ├── SSH_Nmap_Hostkey_22.txt            # Fingerprints de chaves SSH
│   │   └── SSLScan_22.txt                     # Cifras TLS
│   ├── passwordlist.txt                       # Dicionário consolidado CeWL
│   └── services.txt                           # Resumo de serviços identificados
├── report.txt                                 # Dicionário bruto nmap_dict
└── riskscores.csv                             # Matriz consolidada de risco
```

### Principais Diagnósticos da Análise:

1. **Superfície de Rede (`report.txt`)**:
   - `22/tcp` (OpenSSH 9.2p1 Debian)
   - `7070/tcp` (Serviço ativo, resposta SYN-ACK)
   - `8080/tcp` (Serviço HTTP ativo)
   - Portas filtradas: `123, 137, 138, 161, 162` (UDP/TCP de infraestrutura).

2. **Detecção Tecnológica Web (`HTTP_What_Web_8080.txt`)**:
   - Servidor HTTP: **`llama.cpp`** (servidor local de inferência LLM).
   - Cabeçalhos CORS permissivos detectados (`access-control-allow-origin`).

3. **Auditoria Nikto (`HTTP_Nikto_Fast_8080.txt`)**:
   - 1.741 requisições em 12 segundos.
   - 6 itens de conformidade reportados: ausência de cabeçalhos de segurança essenciais (`x-content-type-options`, `content-security-policy`, `referrer-policy`, `permissions-policy`, `strict-transport-security`).

4. **Dicionário Contextual (`passwordlist.txt`)**:
   - O `cewl` extraiu automaticamente palavras-chave da interface do `llama.cpp` (`frontend`, `generated`, `process`, `section`, `static`), gerando wordlists personalizadas para brute force.

5. **Pontuação de Risco (`riskscores.csv`)**:
   - Host `192.168.50.210` classificado com **Risk Score 3** (serviços expostos e headers inseguros, sem RCE crítico direto).

---

## 3. Utilitário de Sumarização Automática

Para inspecionar rapidamente os artefatos de qualquer execução sem abrir dezenas de arquivos de texto:

```bash
python3 /system/ruadan-new/ruadan/verify_run_artifacts.py /system/ruadan-new/ruadan/output
```

Ele exibe um relatório estruturado no terminal e grava o sumário consolidado em `output/resumo_execucao.md`.

---

## 4. Modo Orquestrado com IA (`docker compose`): Multi-LLM e Canários

Quando executado com a flag `-ai`, o Ruadan deixa de seguir uma lista estática de fases e passa a ser guiado pela Kill Chain autônoma:

```
[Ruadan nmap_dict + findings]
         │
         ▼
[RuadanStateAdapter] ──► Gera Tensores (obs: 8d, hf: Nx7, adj: NxN, máscaras)
         │
         ▼
[RuadanAIBrain]      ──► Decide Ação via RL ou Multi-LLM
         │
         ▼
[ActionDispatcher]   ──► Injeta Token Canário (PENTEST_CANARY_...) e dispara ferramenta
         │
         ▼
[CanaryVerifier]     ──► Valida execução real, checa UID 0 e grava Hash SHA256 no Manifest
```

### Como Executar com Docker Compose:

#### Passo 1: Configurar Variáveis de Ambiente
```bash
cp /system/ruadan-new/.env.example /system/ruadan-new/.env
nano /system/ruadan-new/.env
```

#### Passo 2: Subir os Serviços (Ollama + Kali Ruadan)
```bash
cd /system/ruadan-new
docker compose up -d
```

#### Passo 3: Executar a Campanha de IA

* **Com Ollama Local (`qwen3:8b`)**:
```bash
docker compose exec kali-ruadan python3 /app/ruadan/Ruadan2.py \
  -hostFile targets/hosts.txt \
  -outputFolder output \
  -ai \
  -llmProvider ollama \
  -llmModel qwen3:8b
```

* **Com Google Gemini (`gemini-2.5-flash`)**:
```bash
docker compose exec kali-ruadan python3 /app/ruadan/Ruadan2.py \
  -hostFile targets/hosts.txt \
  -outputFolder output \
  -ai \
  -llmProvider google \
  -llmModel gemini-2.5-flash
```

* **Com NVIDIA NIM (Modelos Gratuitos LLaMA 3.1 70B)**:
```bash
docker compose exec kali-ruadan python3 /app/ruadan/Ruadan2.py \
  -hostFile targets/hosts.txt \
  -outputFolder output \
  -ai \
  -llmProvider nvidia \
  -llmModel meta/llama-3.1-70b-instruct
```

* **Com DeepSeek / OpenAI / Anthropic**:
Substitua `-llmProvider` por `deepseek`, `openai` ou `anthropic`.

---

## 5. Auditoria de Canários e Evidências Criptográficas

Durante o modo IA, todas as ações confirmadas geram evidências na pasta `output/ai_evidence/`:
- `canary_<acao>_<timestamp>.txt`: Saída bruta do comando comprovando o token injetado.
- `root_confirmed_<timestamp>.txt`: Evidência de UID 0 para escalações de privilégio.
- `evidence_manifest.json`: Manifesto assinado com hashes SHA256 de todas as evidências coletadas, eliminando qualquer risco de falso positivo.
