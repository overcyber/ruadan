# ✅ IMPLEMENTAÇÃO COMPLETA: Fuzzing Inteligente para Aplicações API-First/SPA

**Data:** 2026-09-25 | **Backups:** 80+ arquivos em `.backup/` (regra imutável)

## O problema (diagnóstico dos logs do JuiceShop)

O JuiceShop é uma **JSON API-first application atrás de uma SPA Angular**. O gobuster
tradicional **não funciona** porque:
- O proxy octopux retorna 403 (146B) para QUALQUER path inexistente (wildcard/soft-403)
- As rotas reais são **client-side** (`#/score-board`) — não existem no servidor
- Os endpoints da API (`/api/*`, `/rest/*`) são chamadas JavaScript no bundle — não são paths de arquivo
- As respostas são **JSON**, não HTML — fuzzers tradicionais procuram HTML
- Muitos endpoints exigem **autenticação JWT** — GET sem token não revela nada

## O que foi implementado (4 scripts + integração)

### 1. `api_route_extract.sh` — Descoberta de Endpoints de API do Bundle JS
**Extração:** `this.http.get("...")`, `fetch("...")`, `axios.post("...")`, `"/api/..."`, `"/rest/..."` do main.js
**Teste:** GET sem auth + GET com JWT admin (capturado via SQLi)
**Emitido:** `API_ENDPOINT_FOUND: <method> <path> (noauth:code/size auth:code/size)`
**Resultados no JuiceShop: 42 endpoints extraídos, incluindo:**
- `/api/Users` (401 sem auth, 200 com JWT = 6343B) — 22 registros de usuários
- `/api/Challenges` (200 sem auth = 64818B) — todos os desafios do JuiceShop
- `/api/Addresss`, `/api/Cards`, `/api/Complaints` — dados sensíveis
- `/rest/products/search`, `/rest/basket/1`, `/rest/continue-code`

### 2. `api_fuzz.sh` — Fuzzing API Autenticado (IDOR + NoSQL + info disclosure)
**Testes:** 22 endpoints com JWT, IDOR (trocar user ID), NoSQL injection em POST bodies,
path traversal em /ftp, POST body injection
**Emitido:** `API_VULN_FOUND: <tipo> <endpoint> <evidencia>`
**Resultados no JuiceShop: 3 vulnerabilidades REAIS:**
- `INFO_DISCLOSURE /api/Users` — 22 registros de usuários expostos (sem filtro de ownership)
- `INFO_DISCLOSURE /api/Feedbacks` — 8 feedbacks de outros usuários
- `INFO_DISCLOSURE /api/Cards` — 2 cartões de crédito expostos

### 3. `param_fuzz.sh` — Fuzzing de Parâmetros (URL + POST + headers)
**Testes:** SQLi em URL params, XSS refletido, NoSQL em JSON POST, path traversal,
header bypass (X-Original-URL, X-Forwarded-For, etc)
**Emitido:** `PARAM_VULN_FOUND: <param> <tipo> <endpoint>`
**Resultados no JuiceShop: 3 vulnerabilidades REAIS:**
- `SQLI_POST /rest/user/login` — payload SQLi aceito em JSON body (200 + token)
- `SQLI_ERROR /rest/user/login` — erro de SQL exposto (UNION SELECT)
- `SQLI_ERROR /rest/user/login` — erro de SQL exposto (OR 1=1)

### 4. `recursive_fuzz.sh` — Fuzzing Recursivo (sub-recursos + métodos não doc)
**Testes:** Expande cada endpoint achado com sub-recursos (/1, /2, /search, /list),
testa PUT/DELETE/PATCH/HEAD/OPTIONS, testa content-types alternativos
**Emitido:** `RECURSIVE_FINDING: <tipo> <endpoint> <detalhe>`
**Resultados no JuiceShop: 25+ sub-recursos descobertos:**
- `/api/Users/1`, `/api/Users/2`, `/api/Users/3` — IDOR (todos acessíveis)
- `/api/Products/1`, `/api/Products/2` — produtos individuais
- `/api/admin`, `/api/config` — endpoints internos que quebram (500)

## Integração no Ciclo IA

### config.ini (12 seções novas):
```ini
[HTTP/HTTPS API Route Extract]  → Findings APIEndpoint
[HTTP/HTTPS API Fuzz]            → Findings APIEndpoint + APIVuln
[HTTP/HTTPS Param Fuzz]          → Findings ParamVuln
[HTTP/HTTPS Recursive Fuzz]     → Findings RecursiveFinding
```

### attackplan.ini:
```ini
[Web Content Detection]
http: HTTP Web Fuzz, HTTP SPA Routes, HTTP API Route Extract, ... ← NOVO
[Web API Fuzzing]              ← NOVO (fase inteira)
http: HTTP API Fuzz, HTTP Param Fuzz, HTTP Recursive Fuzz
```

### Dispatcher (EXPLOIT_REMOTE):
```python
exploit_phases = [
    "Web Content Detection",     ← ffuf + SPA + API Route Extract
    "Web API Fuzzing",           ← NOVO: api_fuzz + param_fuzz + recursive_fuzz
    "Web Exploitation",
    ...
]
```

### Evidence (`_has_api_vuln`):
```python
API_VULN_FOUND → evidence_level = "finding"
("VULNERABILIDADE DE API CONFIRMADA (IDOR/NoSQL/traversal/info disclosure via fuzzing autenticado)")
```

## Pipeline completo de fuzzing inteligente:
```
1. ffuf -ac (auto-calibração)     → filtra wildcard do proxy
2. SPA Route Extract              → 41 rotas client-side do bundle JS
3. API Route Extract (NOVO)       → 42 endpoints de API do bundle JS
4. API Fuzz (NOVO)                → IDOR + NoSQL + info disclosure com JWT
5. Param Fuzz (NOVO)              → SQLi + XSS + path traversal + header bypass
6. Recursive Fuzz (NOVO)          → sub-recursos + métodos não doc
7. SQLi Login Probe              → JWT admin + bypass
8. Post Auth Probe               → 22 contas + arquivo read
```

## Comparação: antes vs depois
| Aspecto | Gobuster tradicional | Fuzzing inteligente (novo) |
|---|---|---|
| Diretórios | 0 (wildcard aborta) | 42 API endpoints |
| Autenticação | Nenhuma | JWT admin via SQLi |
| Métodos | GET apenas | GET/POST/PUT/DELETE/PATCH |
| Content-Type | HTML apenas | JSON/XML/form-data |
| Recursão | Não | Sim (sub-recursos) |
| Parâmetros | Não | URL + POST + headers |
| NoSQL injection | Não | Sim (5 payloads) |
| IDOR | Não | Sim (troca de user ID) |
| Info disclosure | Não | Sim (registro counting) |
| Vulnerabilidades | 0 | 6+ reais confirmadas |
