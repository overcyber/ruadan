# 2026-10-01 — Repo unificado `red-MPPO-testing_full` (deploy do zero + Ollama GPU)

> **Regra do dono atendida**: toda a saída desta sessão está neste .md (em `./contexto/`).
> Repo: https://github.com/overcyber/red-MPPO-testing_full (privado, branch `main`)
> Commits: `78950de` (inicial, 334 arquivos) → `5562d6f` (ajustes de deploy novo)

## 1. Correção da análise (o que o dono apontou)

A primeira análise do plano ERROU ao considerar só o qwen3:8b. A análise correta
do código revelou **DOIS cérebros LLM** servidos pelo MESMO Ollama (o container
kali é `--network host` → brain caça via `localhost:11434`):

| Componente | Modelo | Evidência no código |
|---|---|---|
| **Pentest Brain** (`red-MPPO-testing_model/services/pentest/app/llm_orchestrator.py`) | **`gpt-oss:20b`** (13.8GB) | `DEFAULT_MODEL = "gpt-oss:20b"` + handler para raciocínio sem content |
| **Campanha** (`bridge/ai_orchestrator.py` + `Ruadan2.py -llmModel`) | `qwen3:8b` (5.2GB) | `TARGET_MODEL="${LLM_MODEL:-qwen3:8b}"` em start.sh e docker-run.sh |
| Pentest-lab standalone (`docker/pentest/compose`, profile `ollama`) | gpt-oss:20b | `LLM_MODEL: ${LLM_MODEL:-gpt-oss:20b}` |

Modelos instalados no host (verificado): `gpt-oss:20b 13.8GB` + `qwen3:8b 5.2GB`.
O `setup.sh` antigo puxava SÓ o qwen3 — o brain morreria. Corrigido.

## 2. Descoberta estrutural

O projeto tinha **3 repos git aninhados** no mesmo remote-base:
- externo (`main`, overcyber/ruadan) + `ruadan/.git` (`2025`) + `red-MPPO-testing_model/.git` (`main`, remote próprio overcyber/red-MPPO-testing_model)
- O repo do red-MPPO tinha 16 arquivos não-commitados (trabalho desta sessão: cve_validate, arsenal, exploit_search, fingerprint, harness) — a cópia usou o **estado do DISCO** (mais novo)

## 3. O que entrou no repo (334 arquivos, ~17MB)

```
red-MPPO-testing_full/
├── README.md                 ← guia do zero (prereqs GPU, 2 modelos, ip_pool, start)
├── setup.sh                  ← Docker→GPU(nvidia-container-toolkit)→ollama(gpus=all)
│                                →pull qwen3:8b + gpt-oss:20b→red-mPPO(checkpoint)
│                                →build ruadan:kali→smoke tests (tags + geração + /health)
├── docker-compose.yml        ← CPU: ollama + red-mppo (RL /act :8008, checkpoint ro)
├── docker-compose.gpu.yml    ← GPU: ollama deploy.resources nvidia count:all
├── ruadan/                   ← scanner + arsenal + EVASÃO COMPLETA
│     evasion_lib.sh, trap_census.sh, trap_probe.py, nmap_ev.sh, sqlmap_login_probe.sh,
│     defense_matrix.sh, evasion_pool.sh, evasion_socks.py, 6 fuzzers, test/ (baterias)
├── red-MPPO-testing_model/   ← brain (llm_orchestrator gpt-oss:20b, hunt_suite,
│     exploit chains) + data/checkpoints/maestro_red_ep1246800.pt (12MB COMMITADO)
│     + docker/pentest (stack standalone pentest-lab) + docs/
├── bridge/ knowledge/ skills-red/ configs/ docs/ contexto/
└── targets/EXAMPLE.txt       ← alvos reais JAMAIS commitados (infra é dado)
```

## 4. Excludes (ficam na máquina, nunca no repo)
`_archive/` (4.5GB histórico), `garbage/` (169M), `output/` (runtime),
`.backup/`, `__pycache__`, `.git` aninhados, alvos reais
(hosts.txt, meu_lab.txt, juicer.txt, test_url.txt — os dois targets/ limpos,
só EXAMPLE), `data/runs`.

## 5. Saída dos comandos (registro integral)

**Cópia**: `rsync` com excludes → `17M` total
(`red-MPPO-testing_model 13M` | `ruadan 2,2M` | `skills-red 696K` | `contexto 324K`)

**Checkpoint no commit**: `12188336 bytes red-MPPO-testing_model/data/checkpoints/maestro_red_ep1246800.pt` ✓

**Cérebros no clone**:
```
DEFAULT_MODEL = "gpt-oss:20b"          (llm_orchestrator.py)
TARGET_MODEL="${LLM_MODEL:-qwen3:8b}"  (start.sh + docker-run.sh)
```

**Smoke test do clone fresco** (`git clone` → validações):
- Estrutura completa ✓ (20 itens na raiz)
- Compose CPU: `config --quiet` OK; Compose GPU: OK (warning `version` obsoleta → corrigida no 5562d6f)
- Scripts: `bash -n` OK (setup.sh, start.sh, docker-run.sh, evasion_lib.sh)
- Gitignore eficaz: nenhum alvo real; 1 hit de "192.168.50" no config.ini →
  era o `ip_pool` do ATACANTE → marcado com ⚠️ "TROCAR pela faixa da nova infra"

**Push**: `main -> main` (repo novo) → commits `78950de`, `5562d6f`

## 6. Deploy do zero na nova infra (fluxo validado pelo README/setup)

```bash
git clone https://github.com/overcyber/red-MPPO-testing_full.git && cd red-MPPO-testing_full
./setup.sh        # detecta GPU NVIDIA → valida nvidia-container-toolkit → ollama com gpus=all
                   # → pull qwen3:8b (5.2GB, campanha) + gpt-oss:20b (13.8GB, brain) [skip se presentes]
                   # → red-MPPO com checkpoint do repo → build ruadan:kali (~2GB) → smoke tests
cp ruadan/targets/EXAMPLE.txt ruadan/targets/hosts.txt  # editar com os ALVOS
$EDITOR ruadan/config.ini                               # [EVASION] ip_pool → faixa da NOVA subnet
./start.sh -hostFile /ruadan/targets/hosts.txt
```

Sem GPU: setup usa o compose CPU (funciona; gpt-oss:20b lento — GPU recomendada).
Overrides: `LLM_MODEL` (campanha), `LLM_BRAIN_MODEL` (brain), `LLM_API_BASE`.

## 7. Estado dos repos antigos (história preservada, não deletada)
- `overcyber/ruadan` (branches main + 2025): intocados no GitHub — são o arquivo histórico
- `overcyber/red-MPPO-testing_model`: idem (16 arquivos não-commitados viviam só no disco — agora estão commitados no full)
- Projeto de trabalho em `/system/ruadan-new` continua operacional (runs seguem nele)
- Repo novo local: `/system/red-MPPO-testing_full` (fonte do push)
