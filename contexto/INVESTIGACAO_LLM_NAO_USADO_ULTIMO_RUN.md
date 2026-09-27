# Investigação: Por que o LLM e a IA não foram usados no último run

**Comando executado:** `./start.sh -hostFile /ruadan/targets/meu_lab.txt`
**Data da investigação:** 2026-09-24 12:07 (UTC-3)
**Veredito:** CAUSA RAIZ ENCONTRADA NO CÓDIGO — `start.sh` não injeta a flag `-ai` quando recebe argumentos.

---

## 1. Causa Raiz (comprovada no código)

### `start.sh` — linhas 105-118:

```bash
if [ $# -eq 0 ]; then
    # ✅ SÓ AQUI (sem nenhum argumento) as flags de IA são injetadas:
    exec bash "${SCRIPT_DIR}/ruadan/docker-run.sh" \
        -hostFile /ruadan/targets/hosts.txt \
        -outputFolder /ruadan/output \
        -noColor \
        -noResume \
        -ai \                      # ← FLAG DA IA
        -llmProvider ollama \      # ← PROVEDOR LLM
        -llmModel qwen3:8b \        # ← MODELO LLM
        -logging \
        -verbose
else
    # ❌ COM QUALQUER ARGUMENTO: repassa os args crus, SEM IA!
    exec bash "${SCRIPT_DIR}/ruadan/docker-run.sh" "$@"
fi
```

**Ao executar `./start.sh -hostFile /ruadan/targets/meu_lab.txt`:**
1. `$#` = 2 (não zero) → cai no `else`
2. `docker-run.sh` recebe **apenas** `-hostFile /ruadan/targets/meu_lab.txt`
3. As flags `-ai -llmProvider ollama -llmModel qwen3:8b -logging -verbose -noResume` **NUNCA são adicionadas**

### `ruadan/Ruadan2.py` — linha 1068 (ponto de decisão):

```python
if getattr(self.args, 'ai', False):     # ← False, pois -ai não foi passado!
    ... RuadanAIBrain (RL + LLM) ...    # NUNCA EXECUTADO
```

**Linha 1100 — o que realmente rodou:**
```python
print("[*] Modo Tradicional legado (sem IA). Para ativar IA autônoma, execute via ./start.sh ou passe a flag -ai.")
```

Resultado: `RuadanAIBrain` jamais é instanciado → **ZERO consultas ao red-MPPO (RL), ZERO consultas ao LLM, ZERO evidências de IA.**

### Agravante — `ruadan/docker-run.sh` linhas 169-176:

```bash
for arg in "$@"; do
    if [[ "$arg" == "-ai" || "$arg" == "--ai" || "$arg" == "-llmProvider" ]]; then
        ensure_ollama      # NEM VERIFICA Ollama
        ensure_red_mppo    # NEM VERIFICA red-MPPO
        break
    fi
done
```
Sem `-ai` nos argumentos, **nem o Ollama nem o red-MPPO são verificados/iniciados** para o run.

---

## 2. Provas nos logs do último run

| Evidência | Resultado |
|---|---|
| `output/ai_evidence/ai_decisions.log` | **Nenhuma entrada nova** do run com `meu_lab.txt` — as campanhas registradas (14:51 e 14:52 UTC) são de invocações anteriores feitas COM `-ai` (ex.: `./start.sh` sem args), contra `127.0.0.1` |
| `output/ai_evidence/llm_transcripts/` | Último transcript às 11:54 local — anterior ao run do usuário; **nenhum transcript novo** |
| `output/ai_evidence/rl_policy.ndjson` | Último registro às 14:54:10 UTC — **nenhum registro novo** do run do usuário |
| `output/command_execution_history.log` | Últimas entradas (15:00 UTC) = fases tradicionais em paralelo (ThreadPool multi-host), sem qualquer marca do ciclo IA |
| `output/verboselog.txt` | Só foi atualizado por runs anteriores com `-verbose` (start.sh com args não injeta `-verbose`) |

**Detalhe curioso confirmado nos logs:** a campanha IA registrada às 14:52:27 UTC usou `max_steps=1` (`[PASSO 1/1]`), ou seja, foi invocada manualmente com `-aiSteps 1` — não pelo caminho padrão do `start.sh` (que usa default 40). Isso confirma que os runs com IA nos logs são invocações separadas, feitas com flags explícitas.

---

## 3. Problemas secundários descobertos

### 3.1 `meu_lab.txt` NÃO EXISTE
```
ruadan/targets/:
  hosts.txt    (juice.octopux + 192.168.50.160)  ← alvos ATUAIS
  juicer.txt   (juice.octopux)
  # meu_lab.txt: AUSENTE!
```
O `Ruadan2.py` (linhas 348-373) faz **fallback silencioso** para `/ruadan/targets/hosts.txt` quando o arquivo pedido não existe:
```python
candidates = [hf_raw, ..., "/ruadan/targets/hosts.txt", ...]  # fallback escondido
```
Ou seja: mesmo que a IA fosse ativada, o scan rodaria contra `hosts.txt` sem nenhum aviso de que `meu_lab.txt` não foi encontrado.

### 3.2 Sem `-noResume`, o scan enumerou hosts ANTIGOS
- `grep juice|192.168.50.160` no `command_execution_history.log` → **0 resultados**
- As últimas execuções foram contra `127.0.0.1`, `localhost` e `192.168.50.210` — todos vêm do **nmap_dict acumulado de XMLs antigos** em `output/Nmap/` (runs anteriores)
- O `parse_nmap_xml()` lê **TODOS** os XMLs da pasta; sem `-noResume`, o run "novo" reprocessa a topologia de runs antigos em vez dos alvos atuais

### 3.3 LLM lento instável (run da manhã, com IA ativa)
No run com IA das 12:23-12:48 UTC, **3 de 5 chamadas ao LLM falharam por timeout**:
```
[LLM ERROR] Falha na consulta ao LLM (Falha ao consultar ollama (qwen3:8b) após 3 tentativas: timed out)
```
- A única chamada bem-sucedida do último ciclo IA levou **208 segundos** (qwen3:8b em CPU)
- `configs/llm_config.yaml`: timeout=300s para Ollama, 3 retries com backoff
- Com timeouts, o sistema usa rationale de fallback genérico — a IA "funciona" mas sem a análise tática real do LLM

---

## 4. Correções

### 4.1 Imediata (sem alterar código)
Criar o arquivo de alvos em `ruadan/targets/meu_lab.txt` e passar TODAS as flags de IA explicitamente:
```bash
./start.sh -hostFile /ruadan/targets/meu_lab.txt \
  -outputFolder /ruadan/output \
  -noColor -noResume \
  -ai \
  -llmProvider ollama \
  -llmModel qwen3:8b \
  -logging -verbose
```
Ou simplesmente editar `ruadan/targets/hosts.txt` com os alvos desejados e rodar `./start.sh` **sem argumentos** (modo padrão com IA).

### 4.2 Estrutural (patch recomendado no `start.sh`)
Fazer o modo com argumentos herdar as flags de IA automaticamente, adicionando apenas o que faltar:
```bash
else
    AI_ARGS=()
    for a in "$@"; do
        case "$a" in
            -ai|--ai) AI_HAVE_AI=1 ;;
            -llmProvider) AI_HAVE_PROV=1 ;;
            -llmModel) AI_HAVE_MODEL=1 ;;
            -outputFolder) AI_HAVE_OUT=1 ;;
            -noResume) AI_HAVE_NR=1 ;;
        esac
    done
    [[ -z "${AI_HAVE_AI:-}" ]] && AI_ARGS+=(-ai -llmProvider ollama -llmModel qwen3:8b)
    [[ -z "${AI_HAVE_OUT:-}" ]] && AI_ARGS+=(-outputFolder /ruadan/output)
    [[ -z "${AI_HAVE_NR:-}" ]] && AI_ARGS+=(-noResume)
    exec bash "${SCRIPT_DIR}/ruadan/docker-run.sh" "$@" "${AI_ARGS[@]}"
fi
```

### 4.3 Recomendações adicionais
1. **Falhar alto e claro quando o hostFile não existe** — remover/limitar o fallback silencioso do `Ruadan2.py` (linhas 348-373), ou imprimir um warning explícito
2. **Considerar `-noResume` padrão** no modo IA para não contaminar a topologia com XMLs de runs antigos (ou limpar `output/Nmap/` entre campanhas)
3. **Ajustar timeout do Ollama** (`configs/llm_config.yaml`) ou usar modelo menor (ex.: `qwen3:4b`) se rodando em CPU — 208s por passo torna o ciclo IA de 40 passos inviável (>2h só de LLM)
4. Documentar no `--help` do start.sh que `./start.sh <args>` NÃO ativa IA (comportamento surpreendente)

---

## 5. Resumo em uma frase

> `./start.sh` só injeta `-ai -llmProvider ollama -llmModel qwen3:8b` quando chamado **sem nenhum argumento**; qualquer argumento passado (como `-hostFile meu_lab.txt`) é repassado cru ao Ruadan2.py, que cai no **"Modo Tradicional legado (sem IA)"** — e, agravando, `meu_lab.txt` nem existe (fallback silencioso para `hosts.txt`) e a ausência de `-noResume` fez o scan reprocessar hosts de XMLs antigos.
