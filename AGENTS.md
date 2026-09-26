# AGENTS.md — Ruadan + red-MPPO + Ollama

## ⚠️ REGRA IMUTÁVEL (JAMAIS ESQUECER)
**ANTES de alterar QUALQUER código ou arquivo já existente, SEMPRE faça backup em `.backup/` (na raiz do repo) com timestamp se houver conflito de nome:**
```bash
cp -a <arquivo> .backup/          # antes de QUALQUER edição em arquivo existente
```
Sem exceção. Isso vale para: código (.py/.sh), configs (.ini/.yml), Dockerfile, scripts e documentos.

## Quick Start
```bash
# Alvos em ruadan/targets/ (hostname OU IP — dedup automático hostname↔IP)
./start.sh -hostFile /ruadan/targets/meu_lab.txt      # ciclo IA completo (RL + LLM + arsenal)
./start.sh                                            # modo padrão com hosts.txt
./start.sh --logs --client -f                         # interações LLM em tempo real
./start.sh --summary                                  # sumário forense pós-run
```

## Arquitetura
| Serviço | Porta | Papel |
|---|---|---|
| `ruadan-ollama` (container, host network) | 11434 | Fonte ÚNICA do LLM (qwen3:8b) — serviço systemd `disable`d |
| `ruadan-red-mppo` (container) | 8008 | Política RL (checkpoint .pt) via HTTP /act |
| `ruadan:kali` (image) | — | Arsenal Kali + Ruadan2.py + ciclo IA (docker run --rm) |

## Regras de operação
1. **Nunca rode 2 instâncias** no mesmo outputFolder (lock automático aborta o 2º; bypass consciente: `RUADAN_ALLOW_PARALLEL=1`)
2. **Output único**: `ruadan/output/` — históricos em `ruadan/_archive/`
3. **Sem hardcode de IPs/alvos** em qualquer config — fontes de verdade: `ruadan/targets/*` e `/etc/hosts` (o docker-run.sh replica via `--add-host` dinâmico)
4. **Imagem sem dados**: `.dockerignore` cobre `output*`, `_archive`, `targets*`, `hosts*` — o `COPY .` nunca leva outputs para dentro da imagem; Dockerfile SEM instrução `VOLUME` (volume anônimo mascara mounts)
5. **Build rápido**: layers separadas (arsenal pesado cached; fuzzers/gcc em layer própria) — mudanças de script NÃO exigem rebuild (mount `-v ruadan:/ruadan` serve o código vivo)

## Convenções essenciais (aprendidas a duras penas)
- `configparser` lowerifica labels: findings são buscados case-insensitive (ex: `sqliloginbypass`)
- Container sem systemd: PostgreSQL via `service postgresql start` (nunca `systemctl`); Metasploit via `msf_start_db.sh` (idempotente — o `msfdb init` NÃO é)
- gobuster 3.x: usa `--no-tls-validation`, `--status-codes-blacklist ''`; wordlists em `/usr/share/dirb/wordlists/`
- Alvos SPA (rotas `#/...`): `spa_route_extract.sh` lê o bundle JS — fuzzers de servidor NÃO acham
- Fuzzing em alvos com wildcard/soft-403: `ffuf -ac` (auto-calibração) — gobuster aborta por design
- Exploração real: SQLi login probe (`sqlmap_login_probe.sh`) → `SQLI_LOGIN_BYPASS_CONFIRMED` = `evidence_level=credential`; PoCs testados por `exploit_runner.sh` (módulos .rb = MSF, carregam em `~/.msf4/modules`)

## Entradas do sistema
| Arquivo | Papel |
|---|---|
| `start.sh` / `ruadan/docker-run.sh` | Lançamento + locks + add-host dinâmico |
| `ruadan/Ruadan2.py` | Núcleo (fases, findings, dedup hostname↔IP) |
| `ruadan/config.ini` + `ruadan/attackplan.ini` | Arsenal e fases (fase attackplan → comando config: nomes DIFERENTES!) |
| `bridge/ai_orchestrator.py` | Ciclo IA (RL→LLM→dispatcher), transcripts com timestamp |
| `bridge/action_dispatcher.py` | Kill Chain com `evidence_level` honesto (credential/finding/enum_only) |
| `ruadan/msf_*.sh`, `ruadan/sqlmap_login_probe.sh`, `ruadan/spa_route_extract.sh`, `ruadan/web_fuzz.sh`, `ruadan/exploit_runner.sh` | Fases de exploração |

## Relatórios de sessão
Toda investigação/correção documentada em `./contexto/*.md` (em português).
