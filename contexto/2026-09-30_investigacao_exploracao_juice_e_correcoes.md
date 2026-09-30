# 2026-09-30 — Por que o JuiceShop não foi explorado (investigação + correções)

## A resposta curta

**Foi explorado — mas a defesa adaptativa matou a CONFIRMAÇÃO, e o que sobrou não
foi registrado como evidência.** E a cadeia CVE (F2.6) atirou em alvos falsos.

## A linha do tempo forense (run 3)

| Hora | Evento |
|---|---|
| 20:32 | `api_fuzz` (invocado na porta 80) → **segue redirect pro 443 real** → payload SQLi no login → **JWT ADMIN capturado (732 chars)** ✓ exploração REAL aconteceu |
| 20:36-37 | Fuzzing queima 7 identidades (camada HTTP do octopux, threshold 139) |
| 22:42 | `sqlmap_login_probe` no 443 → baseline=401 ✓ / bypass=**502** ← **WAF do octopux matou o payload** |
| Fim | Sem `SQLI_LOGIN_BYPASS_CONFIRMED` → dispatcher registra **ENUM_ONLY** em vez de **credential** |

## Diagnóstico das 3 camadas

1. **Defesa adaptativa de PAYLOAD** (novo intel p/ matriz): o mesmo `' OR 1=1--`
   passou às 20:32 (primeiro uso, identidade limpa) e levou **502 do proxy** às
   22:42 — o "depois de X tentativas" do sistema de defesa se aplica a PADRÕES
   de payload, não só a IPs. O WAF ARMA contra o padrão após uso repetido.
2. **Exploração real sem registro**: JWT admin + findings autenticados
   (authentication-details auth:200/16993B = exposição de dados) existem no
   output, mas nada promovia a evidência → ENUM_ONLY.
3. **Cadeia CVE atirando em fantasmas**: as "39 CVEs candidatas" do F2.6 vêm dos
   **banners das TRAPS** (nginx 1.24/Apache 2.4.57 falsos do Potemkin, lidos pelo
   vulscan) — exploits contra tarpits. O 443 real (nginx sem versão → sem vulners
   match) não gerou CVE real. JuiceShop não tem RCE por design: o teto é
   credential/data-exposure.

## Bugs críticos descobertos na investigação (e corrigidos)

1. **FALSO-POSITIVO GRAVE no census**: `tp_443=trap` no run 3 — o **443 REAL**
   foi classificado como armadilha! Causa: o probe HTTP/1.0 ganha uma página
   boilerplate path-independente (393B) do proxy → teste "canned" falso-positiva.
   Idem `.222:3389` (RDP real = swallow falso-positivo). Se o F1 (excluir traps
   do resgate) tivesse sido implementado sem isso, **excluiria o alvo real**.
   **Fix (semântica revisada, genérica)**: só **CLUSTER** (≥2 portas com resposta
   byte-idêntica) é forte o bastante para excluir. Canned/swallow singleton →
   **SUSPECT** (não exclui, não pula — a camada HTTP com requests reais decide).
2. **Probe sem identidade**: `sqlmap_login_probe` morria na checagem de
   existência (000 do .210 bloqueado) antes de acumular zeros para rotacionar.
   **Fix**: rotação na própria checagem de existência.

## Correções implementadas (esta sessão)

| Fix | Arquivo | Efeito |
|---|---|---|
| Probe evasion-aware + WAF-aware | `sqlmap_login_probe.sh` | rotação de identidade, 1 request por teste (sem request-duplo), retry 502/503 com identidade nova (3×), **5 variantes de payload** (clássico, `#`, `admin'--`, `\|\|`, NoSQL `$ne`) que dobram pattern-matching, `WAF_CONTENT_KILL` finding quando o kill é por conteúdo |
| JWT → evidência credential | `api_fuzz.sh`, `api_route_extract.sh` | emitem `JWT_ADMIN_CAPTURED:` no momento da captura (não dependem mais do probe 2h depois) |
| Dispatcher credential por JWT | `action_dispatcher.py` | `_has_jwt_admin()` → `evidence_level=credential` |
| Findings patterns | `config.ini` | `JwtAdminCaptured` + `WafContentKill` em TODAS as seções que os emitem (HTTP/HTTPS SQLMap, API Fuzz, API Route Extract) |
| Census suspect-semantics | `trap_census.sh` | singleton canned/swallow = SUSPECT (não trap); só cluster exclui |
| F1: traps fora do resgate | `nmap_ev.sh` | FOUND_PORTS = live+suspect → Ruadan só cria fases contra superfície real |
| F2: resgate UDP | `nmap_ev.sh` | scan -sU cego → re-executa o comando ORIGINAL com -S do pool (anti-portscan não conta UDP) |
| F3: scripts NSE preservados | `nmap_ev.sh` | FASE 2 usa args ORIGINAIS + `-p` do lote → **o vulscan roda o vulners de verdade** contra as portas reais (era -sV genérico que jogava fora o `--script=vulners`) |
| F4: parser | `nmap_ev.sh` | `--script-args`, `--exclude-ports`, `-oG`, `--max-scan-delay` na lista de opções-que-consomem-valor (fim dos targets-lixo "http-put.url=...") |
| F5: cache de resgate | `nmap_ev.sh` | md5(comando) → repetições do mesmo scan custam 0 requests (eram 83×) |
| count_open limpo | `nmap_ev.sh` | `open|filtered` de fonte banida não conta como "achou portas" (era a fonte dos ~100 fantasmas UDP) |

## Validação ao vivo do novo probe (contra o lab real)

```
[probe] Existência de /rest/user/login morta (HTTP 000) — rotacionando identidade
IP_ROTATED: juice.octopux:443 identity 0 -> 1 (192.168.50.240) probe=HTTP 200
[probe] /rest/user/login → baseline=401 bypass=200
SQLI_LOGIN_BYPASS_CONFIRMED: https://juice.octopux:443/rest/user/login
JWT_ADMIN_CAPTURED: https://juice.octopux:443/rest/user/login (token 742 chars)
EVIDÊNCIA: {"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
```

Identidade morta → rotação → bypass 200 → **JWT admin de 742 chars com
role:admin** — a cadeia completa, no lab real, com o WAF já armado do run 3.

## Próximo run esperado (run 4)

1. Juice: fases só contra superfície real (sem fases-junk de trap)
2. vulscan com vulners REAL no 443 (sem 39 CVEs fantasmas)
3. SQLi probe com rotação + variantes → bypass confirmado → **evidence credential**
4. JWT capturado pelo api_fuzz → **evidence credential imediato** (independente do probe)
5. UDP resgatado do pool (sem fantasmas do IP banido)
6. Cache: scans repetidos custam 0 requests
