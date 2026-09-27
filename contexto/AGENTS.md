# AGENTS.md — Ruadan + red-MPPO + Ollama (Merged)

## Quick Start
```bash
# 1. Copy .env.example to .env, fill API keys if using cloud LLMs
cp .env.example .env

# 2. Start all services (Ollama + red-MPPO RL server + Kali-Ruadan)
./start.sh
# Or with Docker Compose:
docker compose up -d

# 3. Run Ruadan manually inside kali-ruadan:
docker exec -it kali-ruadan bash
cd /ruadan && python3 Ruadan2.py -hostFile targets/hosts.txt -ai -llmProvider ollama -llmModel qwen3:8b
```

## Architecture (3 Containers + Host Ollama)
| Service | Port | Role |
|---------|------|------|
| `ruadan-ollama` | 11434 | Local LLM (qwen3:8b, gpt-oss:20b, etc.) |
| `ruadan-red-mppo` | 8008 | RL Policy Server (MADDPG/MPPO `.pt` checkpoint) |
| `kali-ruadan` | host net | Ruadan + AI Brain (bridge/ai_orchestrator.py) |

**Network:** `kali-ruadan` uses `network_mode: host` → reaches Ollama/RL on `localhost`.

## Key Entry Points
- `start.sh` — unified startup (health checks, model pull, RL server build/run)
- `bridge/ai_orchestrator.py` — main AI loop (RL action → LLM tactics → Ruadan dispatch)
- `bridge/action_dispatcher.py` — maps `RedAction` (0-9) → Ruadan attackplan phases
- `bridge/state_adapter.py` — Ruadan `nmap_dict`/`findings` → RL tensors (obs, masks)
- `bridge/llm_client.py` — multi-provider LLM client (Ollama, Gemini, OpenAI, Anthropic, DeepSeek, NVIDIA NIM)
- `ruadan/Ruadan2.py` — core enumeration orchestrator (phases, findings, config.ini, attackplan.ini)
- `ruadan/config.ini` — tool commands, findings regex, Metasploit DB phases
- `ruadan/attackplan.ini` — phase definitions and service-to-command mappings

## RL Kill Chain Actions (RedAction enum)
```
0 NOOP | 1 DISCOVER_REMOTE | 2 DISCOVER_SERVICES | 3 EXPLOIT_REMOTE
4 PRIVILEGE_ESCALATE | 5 LATERAL_MOVE | 6 PERSIST_BACKDOOR
7 EXFILTRATE | 8 C2_ESTABLISH | 9 IMPACT_DEGRADE
```
Preconditions enforced in `state_adapter.py:build_masks()`.

## Current Metasploit Integration (config.ini:686-695)
- **Only DB operations:** `msfdb start`, `db_import *.xml`, `hosts/services -o csv`
- **No exploit modules**, **no meterpreter handlers**, **no session automation**

## Testing
```bash
# red-MPPO tests (90 tests):
docker compose run --rm --entrypoint python pentest-brain -m pytest /repo/services/pentest/tests -q

# Ruadan manual test:
docker exec -it kali-ruadan python3 /ruadan/Ruadan2.py -hostFile /ruadan/targets/hosts.txt -phase "Nmap Scan Fast TCP" -verbose
```

## Environment Variables (from .env / docker-compose.yml)
| Var | Default | Purpose |
|-----|---------|---------|
| `LLM_PROVIDER` | `ollama` | `ollama\|google\|openai\|anthropic\|deepseek\|nvidia` |
| `LLM_MODEL` | `qwen3:8b` | Model name for active provider |
| `OLLAMA_API_BASE` | `http://localhost:11434/v1` | Ollama endpoint |
| `RED_MPPO_URL` | `http://localhost:8008` | RL policy server |
| `GEMINI_API_KEY` etc. | (empty) | Cloud provider keys |

## Operational Gotchas
1. **RL Server port fallback:** `start.sh` tries 8000, falls back to 8008 if occupied
2. **Checkpoint path:** `/repo/data/checkpoints/maestro_red_ep1246800.pt` (mounted read-only)
3. **Evidence dir:** `/ruadan/output/ai_evidence/` — contains `ai_campaign_report.json`, `rl_policy.ndjson`, `executed_commands.log`, LLM transcripts
4. **Canary verification:** Every exploit step generates a canary token; success requires executable canary
5. **No resume by default:** `start.sh` passes `-noResume` to Ruadan
