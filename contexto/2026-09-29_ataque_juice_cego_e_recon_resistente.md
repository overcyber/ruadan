# 2026-09-29 — Por que o ataque ao juice não terminou + recon resistente (nmap_ev)

## A pergunta

"Porque o ataque ao juicer nao terminou?" — o run com evasão (8h06, PASSO 13/40
= kill chain completo de 3 alvos + exfiltrate) atacou o juice.octopux **cego**.

## Diagnóstico (evidências)

1. **O juice REAL está vivo**: de um IP limpo do pool, `https://juice.octopux/`
   → HTTP 200, 9903B, SPA completo do OWASP Juice Shop.
2. **A campanha o viu como buraco negro**: TODOS os nmaps saíram do IP fixo
   `.210` → `Nmap: All 1000 scanned ports are in ignored states (no-response)`
   → **0 portas abertas** → Ruadan não disparou NENHUMA fase HTTP (sem
   web_fuzz/api_fuzz/param_fuzz/sqlmap no juice — o output dele só tem fases
   smb/snmp/ntp contra portas filtered). Os 16 XSS do run vieram do .222.
3. **Causa: bloqueio por PAR (origem→destino) persistente**. O run forense
   (10h martelando o juice com os fuzzers velhos) queimou .210→.160 e a defesa
   **nunca desbloqueou** (≥12h). Enquanto isso .210→.222 funcionava normal
   (20 portas, campanha inteira) — o bloqueio é por par, não global.
4. **A fita confirmada**: as "portas web" 8000/8080/8081/8888/5800 do juice
   servem corpo IDÊNTICO ("Apache2 FreeBSD Default Page" — combinação suspeita,
   default page de Apache2 é de Debian; "FreeBSD" é assinatura de emulação
   barata). O front real está no 443 (hostname/SNI obrigatório).

## Intel nova sobre a defesa (alimenta a matriz)

| Sinal | Valor observado |
|---|---|
| Bloqueio | por PAR origem→destino, silent drop |
| Persistência do bloqueio | ≥12h (nunca viu desbloqueio) |
| Reputação agregada | IPs muito ciclados contra um alvo amanheceram queimados contra OUTRO (.240/.241/.242 bloqueadas rumo ao juice sem nunca o ter tocado) |
| Limite de conexões rumo ao .160 | **~12-15 TCP/IP** (bem menor que o .222: ~58-72 HTTP requests) — o juice é o alvo endurecido |
| Fita | mesma página em 5+ portas; front real exige SNI |

Consequência operacional: o pool de 10 IPs × ~13 conexões = **~130 conexões
por janela de cooldown rumo ao juice**. Campanha precisa ser cirúrgica lá:
1 resgate + fuzz só na porta real (443), nunca nas fitas (emulation_check
pula automaticamente).

## Correção: `nmap_ev.sh` (recon resistente a bloqueio de par)

Drop-in nos 71 comandos nmap do config.ini (`bash /ruadan/nmap_ev.sh ...`):
1. Roda o nmap original; se **0 portas abertas** → resgate:
2. **FASE 1**: sonda 12 portas-chave de IPs limpos do pool com source-bind
   (python `create_connection(source_address=)`) — distingue **recusado**
   (porta fechada, IP vivo) de **timeout** (IP bloqueado → marca burned_pair
   e troca de IP mid-sweep)
3. **FASE 2**: `nmap -sV --version-light` em **lotes de 3 portas por IP vivo**
   (o limite ~12-15/IP mata um -sV de 10+ portas de um IP só)
4. Repara os `-oN/-oX` originais + emite `NMAP_IDENTITY_RESCUED` (finding novo
   no config.ini) → o Ruadan segue o fluxo normal de fases com as portas reais

## O bug-raiz da sessão (honestidade total)

A primeira versão tinha a **regex invertida**: `(tcp|udp)/[0-9]+ ... open`
casava o formato `tcp/3000 open` — **que não existe** (o certo é
`[0-9]+/(tcp|udp)`). Efeito: `count_open` sempre 0 → resgate disparava até em
host sadio, os chunks -sV escreviam c.nmap perfeitos mas o merge via 0 →
**todos os resgates falhavam silenciosamente** em todas as iterações. Foram
necessários: instrumentador de nmap, simulação fiel com iptables (DROP por
origem), e o compare lado-a-lado do c.nmap real vs. a regex para achar.
Bugs menores da jornada: env-clobber na lib, pkill casando com a própria
sessão do shell (auto-kill), instrumentador escrevendo no /tmp do container
efêmero.

## Validação final (simulação fiel — iptables DROP por origem)

```
NMAP_IDENTITY_RESCUED: 127.0.0.1 (5 portas resgatadas via 2 identidade(s) do pool;
                       scan original saiu cego por bloqueio de par origem->destino)
s.nmap reparado: 3000/open Golang | 8000/open Uvicorn | 22/open OpenSSH |
                 5900/open BaseHTTPServer (o alvo atrás do DROP)
```

Não validável contra o juice AGORA: **meus testes queimaram o pool inteiro
rumo ao .160** (cada validação consumia ~13 conexões/IP — o próprio recurso
que o resgate precisa). Lição registrada: até validação consome budget contra
uma defesa contadora. A validação real acontece no próximo run quando o pool
esfriar rumo ao .160.

## Estado

- Commit `702d56d` (origin/2025): nmap_ev.sh + config findings + tudo
- Run com evasão: terminado (8h06, PASSO 13/40 — kill chain completo dos 3
  alvos). Output preservado em `output/` (relatório: matriz em
  `output/defense_matrix.md`)
- Próximo run: nmap_ev resgata o scan do juice automaticamente (quando o pool
  estiver frio rumo ao .160) → fases HTTP disparam → emulation_check marca as
  fitas → fuzzers concentram o budget no 443 real
