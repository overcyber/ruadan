# Teste de Correção e Validação: Modo IA via `./start.sh` com argumentos

**Data:** 2026-09-24 12:24–12:31 (UTC-3)
**Comando testado:** `./start.sh -hostFile /ruadan/targets/meu_lab.txt`
**Veredito:** ✅ **CORRIGIDO E VALIDADO — IA (RL + LLM) agora ativa automaticamente com argumentos customizados**

---

## 1. Correções aplicadas

### 1.1 `start.sh` — injeção automática das flags de IA (linhas 147-196)
O modo com argumentos agora detecta o que o usuário já passou e **injeta o que falta**:

```
Argumentos finais detectados no teste:
-hostFile /ruadan/targets/meu_lab.txt -ai -llmProvider ollama -llmModel qwen3:8b \
-outputFolder /ruadan/output -noColor -noResume -logging -verbose
```

Flags injetadas automaticamente: `-ai -llmProvider ollama -llmModel qwen3:8b -outputFolder /ruadan/output -noColor -noResume -logging -verbose` (somente as ausentes; flags do usuário têm prioridade).

### 1.2 `ruadan/Ruadan2.py` — fim do fallback silencioso do hostFile (linhas 370-379)
```python
if resolved is None:
    print("[-] ERRO: arquivo de alvos '%s' não encontrado em nenhum caminho conhecido. Abortando.")
    sys.exit(2)   # ANTES: seguia com hosts.txt sem avisar NADA
if resolved != hf_raw:
    print("[!] AVISO: hostFile '%s' não encontrado. Usando fallback: '%s'")
```
- **Arquivo inexistente → ABORTA com erro claro** (antes: escaneava outro alvo em silêncio)
- **Fallback usado (hosts.txt) → AVISO visível** (antes: invisível)
- Sintaxe validada com `ast.parse` ✓

### 1.3 Limpeza de estado contaminado
- Output antigo movido para: `ruadan/output_backup_20260924_pre_teste/` (continha XMLs de runs contra `127.0.0.1`, `localhost`, `192.168.50.210` que contaminavam o `nmap_dict`)
- Output novo criado limpo → `parse_nmap_xml()` agora só enxerga os alvos do `meu_lab.txt`

---

## 2. Resultado do teste (comprovação passo a passo)

| # | Verificação | Resultado | Evidência |
|---|---|---|---|
| 1 | IA ativada automaticamente | ✅ | stdout: `[+] Ruadan AI Engine ativado (red-MPPO Reinforcement Learning + Multi-LLM)` |
| 2 | Alvos corretos do `meu_lab.txt` | ✅ | `Hosts=['juice.octopux', '192.168.50.160']` — **nenhum host antigo** |
| 3 | RL (red-MPPO .pt) consultado | ✅ | `[RL INIT] Microserviço red-MPPO (.pt) conectado em http://localhost:8008` |
| 4 | **LLM consultado E respondendo** | ✅ | Rationale real do qwen3:8b (ver §3 abaixo) — não é o texto de fallback |
| 5 | Ciclo de 40 passos ativo | ✅ | `>>> [Passo 1/40] DECISÃO IA` (antes aparecia `[PASSO 1/1]`) |
| 6 | Dispatcher executando fases REAIS | ✅ | searchsploit, davtest, nmap SQL injection, web scans contra juice.octopux e 192.168.50.160 |
| 7 | Kill Chain progredindo | ✅ | `[KILL CHAIN] Host juice.octopux promovido para EXPLOITED_USER` (15:29:37 UTC) |
| 8 | Evidências de IA gravando | ✅ | `ai_decisions.log`, `rl_policy.ndjson`, `llm_transcripts/`, `ollama_interactions.log`, `executed_commands.log` |

### Timeline real do teste (UTC)
```
15:24:32  [RL INIT] red-MPPO conectado (porta 8008, checkpoint maestro_red_ep1246800.pt)
15:24:32  INICIANDO CAMPANHA: RL=MICROSERVICE | LLM=ollama:qwen3:8b | Hosts=['juice.octopux', '192.168.50.160']
15:24:33  nmap TCP+UDP contra juice.octopux e 192.168.50.160 (varredura preliminar)
15:28:07  [PASSO 1/40] Ação=EXPLOIT_REMOTE | Alvo=juice.octopux ← LLM rationale REAL
15:28:07+ Dispatcher: searchsploit + 8 fases de exploit contra os alvos
15:29:37  [KILL CHAIN] juice.octopux → EXPLOITED_USER
15:30:57+ Fases continuando (davtest, nmap SQLi, web scans)
```

### LLM rationale real (prova de que o qwen3:8b respondeu — não é o fallback genérico)
> **[PASSO 1/40]** *"A ação EXPLOIT_REMOTE é selecionada para explorar vulnerabilidades em serviços remotos de juice.octopux, que possui múltiplos serviços ativos, incluindo SSH, HTTP e SNMP, aumentando a superfície de ataque."*

**Comparação com o fallback** (o que aparecia quando o LLM não era usado):
> *"Ação EXPLOIT_REMOTE validada para avanço da Kill Chain contra {alvo}."* ← texto genérico, sem análise

O rationale do teste menciona **SSH, HTTP e SNMP** — serviços realmente descobertos pelo nmap preliminar. O LLM está analisando a topologia real dos alvos.

---

## 3. ⚠️ Achado operacional: segunda instância em paralelo

Durante o teste, foi detectado um **segundo container ruadan:kali** rodando simultaneamente (provável execução manual com `-aiSteps 1`):

```
docker ps --filter "ancestor=ruadan:kali":
  4a1165fc89cd  (meu teste via ./start.sh — ciclo 1/40)
  1badefe8883e  (segunda instância — ciclo 1/1, -aiSteps 1)
```

Evidência da intercalação no `ai_decisions.log`:
```
15:26:37  INICIANDO CAMPANHA (2ª instância) | Hosts=['juice.octopux', '192.168.50.160']
15:29:27  [PASSO 1/1] EXPLOIT_REMOTE | Alvo=juice.octopux  ← 2ª instância
15:28:07  [PASSO 1/40] EXPLOIT_REMOTE | Alvo=juice.octopux ← meu teste
```

**Problemas causados por runs paralelos no mesmo outputFolder:**
1. `llm_transcripts/step_1_EXPLOIT_REMOTE.json` é **sobrescrito** (mesmo nome de arquivo entre campanhas)
2. `command_execution_history.log`, `ai_decisions.log` e `rl_policy.ndjson` intercalados (dificulta auditoria)
3. O `nmap_dict` compartilhado faz o dispatcher enumerar hosts de ambas as campanhas

**Recomendações:**
- Rodar **uma instância por vez**, OU usar `-outputFolder` distinto por campanha
- Incluir timestamp no nome dos transcripts em `bridge/ai_orchestrator.py` (linha ~421):
  `step_{step+1}_{action}_{timestamp}.json` em vez de `step_{step+1}_{action}.json`
- Considerar um lockfile no `evidence_dir` para detectar campanha duplicada

---

## 4. Estado ao encerrar o monitoramento

- Ciclo IA de 40 passos **continua em execução** (cada passo tem chamada LLM de ~90-120s + fases de exploit)
- Tempo estimado do ciclo completo: **>1h30** (40 passos × LLM lento em CPU + ferramentas)
- `ai_campaign_report.json` é gerado apenas no **fim** do ciclo (aos 40 passos ou no EXFILTRATE)
- Metas de alvo: `juice.octopux` (EXPLOITED_USER ✓) e `192.168.50.160` (em enumeração)

---

## 5. Resumo das mudanças em produção

| Arquivo | Mudança | Status |
|---|---|---|
| `start.sh` | Injeção automática de `-ai -llmProvider -llmModel -outputFolder -noResume -logging -verbose` no modo com args | ✅ Aplicada e testada |
| `ruadan/Ruadan2.py` | Aborta com erro se hostFile não existe; avisa quando usa fallback | ✅ Aplicada e testada (sintaxe OK) |
| `ruadan/output/` | Backup do estado antigo → `output_backup_20260924_pre_teste/` | ✅ Feito |
| `ruadan/targets/meu_lab.txt` | Criado pelo usuário com `juice.octopux` + `192.168.50.160` | ✅ Em uso |

**Comando validado (use este daqui pra frente):**
```bash
./start.sh -hostFile /ruadan/targets/meu_lab.txt
```

---

## 6. ✅ RESULTADO FINAL: CICLO IA COMPLETO EXECUTADO COM SUCESSO TOTAL

**O run terminou às 12:45 local (15:45 UTC) — tempo total: 00:20:50**

### Relatório da campanha (`ai_campaign_report.json`):
| Métrica | Valor |
|---|---|
| Passos executados | **9 de 40** (encerrou no EXFILTRATE, como projetado) |
| Sucesso por passo | **9/9 = 100%** |
| Motor RL | MICROSERVICE (red-MPPO, checkpoint maestro_red_ep1246800.pt) |
| LLM | ollama / qwen3:8b — **consultado em TODOS os 9 passos** |
| Transcripts do LLM gravados | **9 arquivos** (step_1 a step_9) |
| Registros RL (ndjson) | 10 |
| Hosts finais | juice.octopux: status 4 (BACKDOORED) · 192.168.50.160: status 4 (BACKDOORED) |

### Kill Chain executada (sequência perfeita em AMBOS os alvos):
```
PASSO 1  EXPLOIT_REMOTE      → juice.octopux     ✓ EXPLOITED_USER
PASSO 2  PRIVILEGE_ESCALATE  → juice.octopux     ✓ EXPLOITED_ROOT
PASSO 3  PERSIST_BACKDOOR    → juice.octopux     ✓ BACKDOORED
PASSO 4  C2_ESTABLISH        → juice.octopux     ✓ canal C2
PASSO 5  EXPLOIT_REMOTE      → 192.168.50.160    ✓ EXPLOITED_USER
PASSO 6  PRIVILEGE_ESCALATE  → 192.168.50.160    ✓ EXPLOITED_ROOT
PASSO 7  PERSIST_BACKDOOR    → 192.168.50.160    ✓ BACKDOORED
PASSO 8  C2_ESTABLISH        → 192.168.50.160    ✓ canal C2
PASSO 9  EXFILTRATE          → juice.octopux     ✓ OBJETIVO ALCANÇADO
```

### Evidência de exfiltração com canário SHA256:
```json
{"label": "exfil", "file": "crown_jewel_juice_octopux.txt",
 "sha256": "9ef68f1d4d3d7eb59c7344b4f1d67899b675da9947e395367d40684791c41960",
 "bytes": 32, "ts": "2026-09-24T15:45:22.762689+00:00"}
```

### Rationales do LLM (todos específicos ao contexto real dos alvos — nenhum fallback):
- Passo 1: *"...juice.octopux, que possui múltiplos serviços ativos, incluindo SSH, HTTP e SNMP..."*
- Passo 5: *"...192.168.50.160 possui serviços críticos como SSH, HTTP/HTTPS e SNMP..."*
- Passo 6: *"...presença de serviços como 137/138 sugere possíveis vulnerabilidades em redes SMB..."* ← menciona portas NetBIOS reais do nmap
- Passo 9: *"...utilizando serviços já identificados no alvo (juice.octopux) para transferir dados de forma oculta, priorizando canais como DNS ou HTTP..."*

### Performance do LLM
- Latência média por passo: **~90-140s** (qwen3:8b em CPU)
- Nenhum timeout nesta campanha (no run anterior, 3 de 5 chamadas falhavam — desta vez 9/9 responderam)

---

## 7. Conclusão

**O problema original está 100% resolvido e validado ponta-a-ponta:**

1. ❌ **ANTES:** `./start.sh -hostFile X` → Modo Tradicional sem IA, sem LLM, sem RL, alvos errados (fallback silencioso + nmap_dict contaminado)
2. ✅ **AGORA:** `./start.sh -hostFile X` → IA automática (RL + LLM), alvos corretos do arquivo especificado, Kill Chain completa, evidências auditáveis com SHA256, transcripts do LLM por passo

**Fluxo validado:** `start.sh` → injeção das flags IA → `docker-run.sh` (ensure_ollama + ensure_red_mppo) → `Ruadan2.py` com `-ai` → `RuadanAIBrain` → RL microservice (porta 8008) + LLM ollama (qwen3:8b) → dispatcher executa fases reais → Kill Chain → EXFILTRATE com canário → `ai_campaign_report.json`
