# ✅ ETAPA 4 — Pivô Automático: vizinhos da session viram alvos do ciclo IA

**Data:** 2026-09-25 ~01:40 UTC | **Regra imutável:** backups em `.backup/` (49 arquivos) antes de cada alteração

## O mecanismo (implementado no `bridge/action_dispatcher.py`)

```
[Metasploit Session Pivot]           findings 'msfpivot' (MSF_PIVOT_NEIGHBOR — IPs reais do arp)
        ↓  LATERAL_MOVE (dispatcher)
_inject_pivot_targets(res):
  1. Extrai IPs dos findings msfpivot
  2. FILTRA: apenas vizinhos na MESMA /24 dos alvos declarados no hostFile
     (ex: 192.168.50.x) — bridges docker/172.x ficam como findings (sem injeção)
  3. Injeta em ruadan.nmap_dict[ip] = {"ports": []}
        ↓
  (a) próximo sync_from_ruadan → vizinhos entram no MDP do RL (escolhíveis!)
  (b) TODOS os scans subsequentes os incluem (enumerate itera nmap_dict)
  (c) PIVOT_NEW_TARGET gravado em ai_evidence/pivot_targets.log (auditoria)
Gate: RUADAN_AUTO_PIVOT=0 desliga o pivô automático
```

## Prova (unit test — saída real)
```
PIVOT_NEW_TARGET: 192.168.50.222 injetado no escopo (vizinho descoberto pela session)
PIVOT_NEW_TARGET: 192.168.50.221 injetado no escopo (vizinho descoberto pela session)
PASSOU: pivô injeta apenas vizinhos da mesma /24 — 172.x ignorados
PASSOU: vizinhos injetados visíveis no MDP do RL — ['192.168.50.160', '192.168.50.222', '192.168.50.221']
```

## O que isso significa na campanha IA
O **LATERAL_MOVE deixa de ser simbólico**: com uma session ativa, a IA descobre vizinhos REAIS
da rede (arp), expande o escopo automaticamente (com filtro de subnet + gate), e o RL passa a
ter novos alvos legítimos para DISCOVER_REMOTE → EXPLOIT_REMOTE → ... — a kill chain se
propaga pela rede interna de verdade, com cada alvo novo nascendo do comprometimento anterior.

## Segurança do escopo
- Subnet /24 dos alvos DECLARADOS no hostFile (fonte de verdade — nunca escopo arbitrário)
- Gate RUADAN_AUTO_PIVOT=0 para ambientes onde expansão automática não é desejada
- 172.x (bridges docker do host) reportados como findings, NÃO injetados

## Teste final em andamento
`./start.sh -hostFile /ruadan/targets/meu_lab.txt` — run completo do zero com TODAS as etapas:
nmap 65535 + ffuf/SPA + SQLi probe (credential) + exploit runner + MSF (session/C2/pivot) + LLM.
(Contra o Juice Shop não há session/RCE — a fase MSF roda honesta; o pivô será exercitado
na primeira oportunidade com alvo vulnerável real no lab.)
