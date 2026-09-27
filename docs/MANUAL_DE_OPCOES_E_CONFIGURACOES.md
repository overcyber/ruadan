# Manual Completo de Opções, Configurações e Arquitetura do Ruadan

Este documento é a referência exaustiva para operação, configuração e customização do **Ruadan**, contemplando desde a enumeração determinística tradicional até o motor autônomo de inteligência artificial (**red-MPPO** e **Multi-LLM**).

---

## 1. Todas as Opções de Linha de Comando (CLI Flags)

O comando principal aceita opções através da sintaxe `python3 Ruadan2.py [flags]` ou via Docker:

### 1.1 Configuração de Alvos, Escopo e Redirecionamento

| Opção | Argumento | Padrão | Descrição Técnica Detalhada |
| :--- | :--- | :--- | :--- |
| `-hostFile` | `<arquivo>` | `hosts.txt` | Arquivo contendo a lista de hosts/IPs de escopo (um por linha). Suporta comentários iniciando com `#`. |
| `-outputFolder` | `<pasta>` | `.<hostFile_basename>` | Diretório base de persistência onde serão gravados os relatórios, XMLs, capturas e evidências. |
| `-configFile` | `<arquivo>` | `config.ini` | Arquivo INI contendo os templates de comandos para cada serviço, portas conhecidas e definições de regex para extração de achados. |
| `-attackPlanFile`| `<arquivo>` | `attackplan.ini` | Arquivo INI que rege a ordem de execução das fases de varredura e enumeração. |
| `-workspace` | `<nome>` | `<hostFile_basename>` | Nome da workspace do Metasploit para onde os dados serão importados (caso integrado com banco MSF). |
| `-domain` | `<dominio>` | `megacorpone.com` | Domínio utilizado nas consultas de enumeração DNS e ataques de transferência de zona (AXFR). |
| `-dnsServer` | `<ip:porta>` | `""` | Servidor DNS específico a ser forçado nas consultas do Nmap (`--dns-server <ip>`). |
| `-proxy` | `<ip:porta>` | `""` | Proxy HTTP/SOCKS a ser utilizado pelas ferramentas de varredura que suportam proxy. |
| `-reportFile` | `<arquivo>` | `report.txt` | Nome do arquivo principal serializado com a estrutura do `nmap_dict` de todos os hosts. |

---

### 1.2 Controle de Execução e Otimização

| Opção | Tipo | Descrição Técnica Detalhada |
| :--- | :--- | :--- |
| `-noResume` | Booleano (flag) | Desativa o mecanismo de retomada. Por padrão, o Ruadan pula comandos cujos arquivos de saída já existam no disco; com `-noResume`, todos os comandos são reexecutados. |
| `-noColor` | Booleano (flag) | Desativa as cores ANSI na saída do console, facilitando pipes, scripts e redirecionamento limpo para arquivos. |
| `-threadPool` | Inteiro (`8`) | Número de threads concorrentes para a execução paralela de comandos do plano de ataque. |
| `-phase` | String | Restringe a execução a uma única fase específica do plano (ex: `-phase "Information Gathering"`). |
| `-noExploitSearch`| Booleano (flag) | Desativa as buscas automáticas de exploits locais no SearchSploit (Exploit-DB). |
| `-install` | Booleano (flag) | Modo de auto-instalação: utiliza `install.ini` e `installplan.ini` para instalar dependências do sistema. |

---

### 1.3 Logging, Debug e Auditoria

| Opção | Tipo | Descrição Técnica Detalhada |
| :--- | :--- | :--- |
| `-logging` | Booleano (flag) | Habilita a escrita detalhada contínua nos arquivos `debuglog.txt` e `verboselog.txt` dentro da pasta de saída. |
| `-verbose` | Booleano (flag) | Exibe no terminal detalhes intermediários de cada comando e status de portas. |
| `-debug` | Booleano (flag) | Ativa o modo de depuração profunda, exibindo comandos brutos antes da interpolação e chamadas de sistema. |
| `-benchmarking`| Booleano (flag) | Registra o tempo exato de execução de cada comando em um arquivo `benchmark.csv`. |

---

### 1.4 Motor Autônomo de Inteligência Artificial (`-ai`)

| Opção | Argumento | Padrão | Descrição Técnica Detalhada |
| :--- | :--- | :--- | :--- |
| `-ai` | Booleano (flag) | `False` | **Ativa o Ruadan AI Brain**: substitui o plano linear estático pelo ciclo autônomo baseado no MDP do red-MPPO e inferência por Multi-LLM. |
| `-llmProvider` | Enum | `ollama` | Provedor de LLM para raciocínio tático: `ollama`, `google`, `openai`, `anthropic`, `deepseek`, `nvidia`. |
| `-llmModel` | String | Padrão do provedor | Nome do modelo específico a ser invocado (ex: `qwen3:8b`, `gemini-2.5-flash`, `gpt-4o`, `meta/llama-3.1-70b-instruct`). |
| `-checkpoint` | Caminho | `.../maestro_red_*.pt` | Caminho para os pesos da rede neural de Red Teaming treinada com RL (MADDPG/MPPO). |
| `-aiSteps` | Inteiro | `40` | Número máximo de passos táticos autônomos por campanha antes do encerramento e geração de relatório. |

---

## 2. Matriz de Provedores Multi-LLM e Configuração

O arquivo central de rotas e modelos é [`configs/llm_config.yaml`](file:///system/ruadan-new/configs/llm_config.yaml).

### 2.1 Provedores Homologados

| Provedor | Variável de Ambiente | Modelos Recomendados | Endpoint Padrão |
| :--- | :--- | :--- | :--- |
| **Ollama** | `OLLAMA_BASE_URL` | `qwen3:8b`, `qwen2.5-coder:7b`, `llama3.1:8b` | `http://ollama:11434` ou `http://localhost:11434` |
| **Google Gemini** | `GEMINI_API_KEY` | `gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-1.5-pro` | `https://generativelanguage.googleapis.com/v1beta/openai` |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o`, `gpt-4o-mini`, `o1-mini` | `https://api.openai.com/v1` |
| **Anthropic** | `ANTHROPIC_API_KEY` | `claude-3-7-sonnet`, `claude-3-5-sonnet-20241022` | `https://api.anthropic.com/v1/messages` (Nativa) |
| **DeepSeek** | `DEEPSEEK_API_KEY` | `deepseek-chat`, `deepseek-coder`, `deepseek-reasoner` | `https://api.deepseek.com/v1` |
| **NVIDIA NIM** | `NVIDIA_NIM_API_KEY` | `meta/llama-3.1-70b-instruct`, `mistralai/mixtral-8x22b` | `https://integrate.api.nvidia.com/v1` |

### 2.2 Template de Ambiente (`.env`)

```ini
# Provedor ativo por padrão
LLM_PROVIDER=ollama
LLM_MODEL=qwen3:8b

# URLs e Chaves
OLLAMA_BASE_URL=http://localhost:11434
GEMINI_API_KEY=sua_chave_gemini_aqui
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
DEEPSEEK_API_KEY=sk-...
NVIDIA_NIM_API_KEY=nvapi-...
```

---

## 3. O Mecanismo de Canários e Auditoria Criptográfica

Para eliminar falsos positivos em operações automatizadas, o Ruadan utiliza **Canários Determinísticos**:

```
[Decisão da IA]
       │
       ▼
Geração de Token: PENTEST_CANARY_<acao>_<hash>
       │
       ▼ Injeção no comando
Execução: whoami && echo PENTEST_CANARY_privesc_f1a2b3c4
       │
       ▼ Retorno do alvo
CanaryVerifier:
   ├── 1. Procura o token exato no stdout
   ├── 2. Se for PRIV_ESC: Checa estritamente se UID == 0 (root)
   ├── 3. Salva a evidência em output/ai_evidence/
   └── 4. Calcula SHA256 e grava em evidence_manifest.json
```

### Arquivos Gerados na Pasta `ai_evidence/`:
- `evidence_manifest.json`: Registro indexado de todas as evidências com timestamps UTC, hashes SHA256 e tamanho em bytes.
- `canary_*.txt`: Saída bruta do comando com o token confirmado.
- `root_confirmed_*.txt`: Comprovação estrita de privilégio UID=0.
- `ai_campaign_report.json`: Log da trajetória com cada ação, alvo, sucesso e justificativa da IA.

---

## 4. Como Analisar se a Execução Deu Certo Sem Ler o Log Inteiro

Em varreduras e pentests, logs brutos (`debuglog.txt`, `verboselog.txt`, Nmap XMLs) podem ter centenas de milhares de linhas. Para verificar se a execução foi bem-sucedida de forma **rápida, precisa e automatizada**:

### Método 1: Utilitário de Sumarização Forense
```bash
python3 /system/ruadan-new/ruadan/verify_run_artifacts.py /caminho/do/output
```
*Extrai em menos de 1 segundo:*
- Portas abertas e filtradas.
- Tecnologias e servidores web (ex: `llama.cpp`).
- Alertas e falhas do Nikto.
- Palavras-chave extraídas pelo CeWL.
- Pontuação de risco consolidada (`riskscores.csv`).

### Método 2: Verificação do Manifesto de IA (`evidence_manifest.json`)
```bash
jq '.[] | {token: .token, acao: .label, sha256: .sha256[:16]}' output/ai_evidence/evidence_manifest.json
```
Se o array contiver entradas com hashes SHA256, as ações foram confirmadas na prática no alvo.

### Método 3: Checagem Rápida via Linha de Comando (One-Liners)
* **Verificar se houve erros críticos no Ruadan**:
  ```bash
  wc -l output/commanderrorlog.txt
  ```
  *(Se tiver 0 bytes ou poucas linhas, nenhum comando falhou).*

* **Conferir serviços descobertos**:
  ```bash
  cat output/*/services.txt
  ```

* **Conferir pontuação de risco**:
  ```bash
  cat output/riskscores.csv
  ```

---

## 5. Exemplos Práticos de Invocação

### 5.1 Modo Clássico Determinístico
```bash
docker run --rm -t --network host \
  -v $(pwd)/output:/ruadan/output \
  -v $(pwd)/targets:/ruadan/targets \
  ruadan:kali \
  -hostFile targets/hosts.txt -outputFolder output -noColor -logging
```

### 5.2 Modo IA Autônomo com Ollama (Docker Compose)
```bash
docker compose exec kali-ruadan python3 /app/ruadan/Ruadan2.py \
  -hostFile targets/hosts.txt \
  -outputFolder output \
  -ai \
  -llmProvider ollama \
  -llmModel qwen3:8b \
  -aiSteps 30
```

### 5.3 Modo IA com Google Gemini
```bash
docker compose exec kali-ruadan python3 /app/ruadan/Ruadan2.py \
  -hostFile targets/hosts.txt \
  -outputFolder output \
  -ai \
  -llmProvider google \
  -llmModel gemini-2.5-flash \
  -aiSteps 30
```

### 5.4 Modo IA com NVIDIA NIM (Modelos Gratuitos)
```bash
docker compose exec kali-ruadan python3 /app/ruadan/Ruadan2.py \
  -hostFile targets/hosts.txt \
  -outputFolder output \
  -ai \
  -llmProvider nvidia \
  -llmModel meta/llama-3.1-70b-instruct \
  -aiSteps 30
```
