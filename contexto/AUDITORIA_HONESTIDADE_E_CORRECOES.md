# Auditoria de Honestidade do Sistema + Correções Aplicadas

**Data:** 2026-09-24 ~13:00 (UTC-3)
**Contexto:** Usuário reportou "tudo aparentemente está fake e mentiroso", arquivos Metasploit vazios, nenhuma ferramenta executada, LLM "não usado", num sistema completamente vulnerável (OWASP Juice Shop em juice.octopux → 192.168.50.160).

---

## 1. AUDITORIA DAS ACUSAÇÕES — o que é real, o que é fake

### 1.1 ✅ ACUSAÇÃO PROCEDENTE: Kill Chain "fake e mentirosa"
**CONFIRMADO NO CÓDIGO** (`bridge/action_dispatcher.py`):
```python
res.success = True   # ← INCONDICIONAL em EXPLOIT_REMOTE, PRIVILEGE_ESCALATE,
                     #   LATERAL_MOVE, PERSIST_BACKDOOR, C2_ESTABLISH, IMPACT_DEGRADE
```
- As promoções EXPLOITED_USER → EXPLOITED_ROOT → BACKDOORED → C2 eram baseadas apenas em "fases de enumeração rodaram" — **sem NENHUM shell, sessão ou exploit real verificado**
- O "EXFILTRATE" gera um arquivo LOCAL com hash SHA256 (canário por design) — não é exfiltração real
- O relatório da campanha rotulava tudo como `success: true` sem distinguir enumeração de exploração

### 1.2 ✅ ACUSAÇÃO PROCEDENTE: Arquivos Metasploit/SQLMap/Screenshot vazios
**CONFIRMADO** — todos os comandos abaixo retornaram **EXIT_127 (comando não encontrado)**:
| Ferramenta | Comando no config.ini | Situação no container |
|---|---|---|
| Metasploit | `msfconsole -x "..."` | **NÃO INSTALADO** (pacote metasploit-framework ausente no Dockerfile) |
| PostgreSQL | `systemctl start postgresql` | **DOBLEMENTE QUEBRADO**: postgresql não instalado + systemctl não existe em container |
| SQLMap | `sqlmap -u ...` | **NÃO INSTALADO** |
| Screenshots | `cutycapt --url=...` | **NÃO INSTALADO** (cutycapt foi removido dos repositórios Kali) |
| Gobuster | `gobuster dir -e -r -t 5 -U username -P password` | **ARGS INVÁLIDOS** — flags `-r -U -P` não existem no gobuster 3.x → EXIT_1 |

**Resultado**: arquivos de saída de 0 bytes — o Ruadan criava o arquivo, o comando falhava, e ninguém percebia.

### 1.3 ✅ ACUSAÇÃO PARCIALMENTE PROCEDENTE: "host completamente vulnerável e não encontrou nada"
**BUG GRAVE DESCOBERTO — HOST FANTASMA**:
- `juice.octopux` e `192.168.50.160` são **O MESMO HOST** (`getent hosts` confirma: 192.168.50.160)
- O `meu_lab.txt` listava ambos; o `parse_nmap_xml()` keyeia resultados **por IP**
- Resultado: `nmap_dict["juice.octopux"]` = FANTASMA vazio (só o serviço fake "Ruadan Added Always Service", portid 0) e `nmap_dict["192.168.50.160"]` = com todas as portas 22/80/443
- **O nmap ACHOU as portas de verdade** (XML comprova: 22, 80, 443 abertas) — mas o ciclo IA agia sobre o FANTASMA
- O LLM recebeu estado errado e **ALUCINOU**: disse que juice.octopux tinha "SSH, HTTP e SNMP" quando o estado dele tinha ZERO serviços reais

### 1.4 ❌ ACUSAÇÃO IMPROCEDENTE: "não usou modelo LLM"
**O LLM FOI CHAMADO DE VERDADE** — provas:
1. `ruadan/output/ai_evidence/ollama_interactions.log`: prompt completo + resposta + **latência de 213.589ms** por chamada
2. 9 transcripts em `llm_transcripts/` com respostas específicas do qwen3:8b
3. `rl_policy.ndjson` com action_probs do microserviço red-MPPO

**POR QUE PARECIA QUE NÃO**: o `view_ollama_logs.sh` buscava o log em `output/ai_evidence/` (que só tinha um teste manual "LOG_TEST_SUCESSO") em vez de `ruadan/output/ai_evidence/` (com as 9 interações reais das campanhas) → **o comando de verificação mostrava a resposta errada**.

---

## 2. CORREÇÕES APLICADAS

| # | Arquivo | Correção |
|---|---|---|
| 1 | `bridge/ai_orchestrator.py` | **Transcripts com timestamp único** (`step_1_EXPLOIT_REMOTE_20260924_152807_123456.json`) — elimina sobrescrita entre campanhas paralelas |
| 2 | `bridge/action_dispatcher.py` | **Dispatcher honesto**: novo campo `evidence_level` (`credential` > `finding` > `enum_only`) avaliado por ação; print explícito "NÍVEL DE EVIDÊNCIA REAL"; `_assess_evidence()` compara findings antes/depois |
| 3 | `bridge/ai_orchestrator.py` | **Kill chain auditável**: toda promoção loga `evidência real: enum_only — somente enumeração executada, nenhum shell confirmado`; report inclui `evidence_level`/`evidence_detail` por passo |
| 4 | `ruadan/Ruadan2.py` | **Fim do host fantasma**: canonicalização hostname→IP via `socket.gethostbyname` + deduplicação com aviso ("Alvo 'juice.octopux' resolve para 192.168.50.160 — unificado") |
| 5 | `ruadan/Ruadan2.py` | **hostFile inexistente aborta** (exit 2) + aviso em fallback (correção anterior, mantida) |
| 6 | `ruadan/Dockerfile` | **Instalados**: `sqlmap`, `metasploit-framework`, `postgresql`, `postgresql-client`, `chromium`, `xvfb` |
| 7 | `ruadan/config.ini` | **Metasploit Start Database**: `systemctl start postgresql` → `msfdb init; msfdb start` (funciona em container sem systemd) |
| 8 | `ruadan/config.ini` | **Screenshots**: `cutycapt` (removido do Kali) → `chromium --headless --no-sandbox --screenshot` |
| 9 | `ruadan/config.ini` | **Gobuster**: args 3.x válidos (`-e -t 5 --no-error`), removidos `-r -U -P` inexistentes |
| 10 | `view_ollama_logs.sh` | **Prioriza o log de interações MAIS RECENTE** entre os caminhos (antes: mostrava arquivo antigo/errado) |

## 3. Situação do `start.sh`/`docker-run.sh` (já corrigidos antes desta rodada)
- `./start.sh <args>` injeta `-ai -llmProvider ollama -llmModel qwen3:8b -outputFolder -noResume -logging -verbose` automaticamente
- `./start.sh --logs [-f]` → view_ollama_logs.sh
- `./start.sh --summary` → verify_run_artifacts.py

---

## 4. Teste pós-correção
(em andamento — resultado será anexado abaixo após o rebuild da imagem e a nova execução)
