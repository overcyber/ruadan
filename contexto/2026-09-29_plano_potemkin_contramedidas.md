# 2026-09-29 — Plano Potemkin: contramedidas Red + teste de eficácia máximo

> Código da defesa analisado: https://github.com/Maarckz/Potemkin (v3.0.1, Apache-2.0)
> Fonte completa salva em: `ruadan/test/potemkin_lab/potemkin.py`

## 1. Mecânica exata (do código-fonte)

| Componente | Comportamento |
|---|---|
| Escuta | Bind em TODAS as 65535 portas (`range(1,65536)` → NullResp); portas com serviço real falham no bind e são **puladas** (`_in_use()` testa bind 0.0.0.0) |
| Detector | `ports_seen[ip]` = SET de portas únicas; **threshold 10 portas únicas / janela 60s** → ban iptables DROP (chain POTEMKIN) |
| Semântica do set | **NUNCA encolhe com o IP ativo** (novo hit é anexado antes do prune); só zera com ~120s de silêncio (cleanup window×2) ou no ban |
| Escalonamento | 1ª=10min, 2ª=30min, 3ª+=1h; **`offenses[ip]` NUNCA expira** |
| RateLimiter | 2º gatilho: **30 conexões/10s por IP** (qualquer porta) → ban 300s; repetir a MESMA porta 1000x NÃO conta pro Detector |
| IPv6 | `if ':' in ip: return False` + AF_INET → **CEGO TOTAL** |
| Whitelist | `cfg whitelist` (hosts confiáveis) |
| Fita | Responders literais no código: HTTP=`Apache2 FreeBSD Default Page` + `Server: Apache/2.4.57 (Ubuntu)` (contradição determinística), `/robots.txt`=`Disallow: /` em toda trap HTTP, banners SSH/MySQL/FTP/SMTP/Telnet exatos |

## 2. Reconciliação com o lab (com RETRAÇÃO)

- ✅ ".210 viu 1000 portas filtered" = ban iptables após o forense tocar >10 traps
- ✅ "~12-15 con/IP" = threshold 10 portas únicas + retries
- ✅ "bloqueio ≥12h" = escalonamento eterno de ofensas + re-triggers a cada run
- ✅ Fita em 8000/8080/8081/8888/5800/9090 = HTTPResp literal do código
- ⚠️ **RETRAÇÃO**: a "reputação agregada entre destinos" do doc anterior estava **ERRADA** — .240/.241/.242 foram queimadas pelos meus sweeps de teste (52 portas round-robin em 3 IPs ≈ 17 únicas cada > 10). Potemkin é por-host, por-IP, SEM agregação
- 🔍 **Gap de instância**: vimos porta 3000 refused no lab, mas o código 3.0.1 cobre range completo → a instância deployada é menor/mais antiga → census empírico é OBRIGATÓRIO (fingerprint só do código não basta)

## 3. Bypass fundamentais que emergem

1. Portas REAIS e FECHADAS são invisíveis ao detector (só aceitação de trap conta) → fuzar o 443 real é ilimitado
2. Set nunca encolhe → pacing **9 traps → 120s silêncio → 9 traps** por IP; ×10 pool = sustentado
3. Ban não re-escala com hammering (conexão de banido é ignorada) → expira na agenda
4. IPv6 = bypass total
5. Ofensas eternas → IP que triggerou 2x nunca mais vale a pena (aposentar ofensores)

## 4. Implementação — REDESIGN ADAPTATIVO (zero hardcode, por exigência do dono)

> ⚠️ **DECISÃO ARQUITETURAL**: a primeira versão usava assinaturas literais do
> Potemkin (banners, portas, thresholds) — **REJEITADA**. Qualquer patch na
> defesa invalidaria o sistema. Refeito 100% adaptativo: qualquer mudança no
> Potemkin (ou troca por outra defesa anti-portscan) só muda o que o sistema
> **APRENDE**, nunca o que ele **ESPERA**.

- **F1** `trap_probe.py` — probe com source-bind que devolve OBSERVAÇÕES BRUTAS
  (connect/refused/timeout + hash do CORPO + tempos). Hash só do body
  (headers têm Date/Server rotativos → ruído). Zero interpretação.
- **F1** `trap_census.sh` — census adaptativo por alvo com 3 sinais GENÉRICOS:
  1. **Clustering**: ≥2 portas com corpo byte-idêntico = mesmo backend emulador
  2. **Insensibilidade a request**: paths distintos → resposta idêntica = canned
  3. **Oráculo do bloqueio**: ban no meio do census (connect→timeout) → aprende
     o threshold REAL (portas aceitas até ali) e aposenta o IP (ofensor)
- **F2** Governor na `evasion_lib`: `ptouch_<ident>` (portas únicas aceitas),
  cap por IP (config `port_touch_cap`, substituído pelo aprendido-2),
  **aposentadoria de ofensores** (ofensas não expiram), rotação proativa,
  ev_init troca de identidade ofensora antes do 1º request
- **F3** `nmap_ev` retrofit: FASE 1 = census adaptativo (não sabe nada da
  defesa); FASE 2 = -sV em lotes com headroom de ptouch por IP
- **F4** `test/potemkin_lab.sh` — bateria de eficácia contra o Potemkin REAL
  (deploy do .deb/código em container isolado 127.0.0.2, iptables REAL para os
  drops): C1-C6 (abaixo). A defesa é real; o agente vermelho é o genérico.
- **F5** Relatório de melhorias da defesa (seção 6)

## 5. Bateria de eficácia (F4) — RESULTADO FINAL: **6/6 PASS**

Executada contra o Potemkin real (código do repo, container isolado 127.0.0.2,
iptables real com drops efetivos — logs em `ruadan/test/results_potemkin_*/`):

| Teste | Resultado | Evidência |
|---|---|---|
| C1 eficácia da defesa | **PASS** | scan ingênuo → `SCAN ip=… portas=3 ban=10s` (a defesa funciona contra scan sem evasão) |
| C2 census adaptativo | **PASS** | `TRAP_CLUSTER: 143,993 (resposta_idêntica)` + 2 `TRAP_CANNED` + `TRAP_SWALLOW` (engole HTTP) + `LIVE_PORT: 7777` — **5 traps + porta real, ZERO bans do pool** |
| C3 porta real ilimitada | **PASS** | 30 requests ao serviço real → zero eventos (defesa cega em porta legítima) |
| C4 IPv6 cego | **PASS** | 20 conexões v6 → zero eventos; traps inalcançáveis via ::1 (sockets v4-only) — **gap confirmado** |
| C5 escalonamento | **PASS** | curva empírica `ban=10s → 30s → 60s` capturada do blocks.log |
| C6 oráculo do threshold | **PASS** | census de 1 IP → ban no meio → **`DEFENSE_PORT_THRESHOLD_LEARNED: 3` (exato!)** + ofensor aposentado no estado |

Bugs de teste corrigidos no caminho (registrar a lição): mock v4 derrubado
por race da thread v6 mutando `address_family` da classe compartilhada
(Potemkin capturou a 7777 do mock morto); container sem `--cap-add NET_ADMIN`
(iptables falhava silencioso → oráculo cego); asserções `grep -c \|\| echo 0`
imprimindo "0\n0"; probes http em traps NullResp lentos vs ban de teste de 10s.

**Limitação conhecida (documentada, não-blocking)**: portas de banner
singletons (ftp/pop3-like) podem ser classificadas LIVE por fragmentação
TCP não-determinística no probe http (falso-negativo conservador — não pula
porta real, não causa ban). Os sinais fortes (clustering, swallow, oráculo)
são determinísticos.

**Estado do lab**: pool .240-.249 ESFRIOU rumo ao .160 (verificado: 200 do
juice via .246/.248/.249 + `https://juice.octopux/` 200). O próximo run real
pode atacar o juice com census + governor do zero.

## 6. Melhorias recomendadas na defesa (Blue, por severidade)

1. **IPv6 cego** (CRÍTICO): AF_INET-only + rejeição de v6 no detector → atacante v6 é invisível
2. **Ofensas nunca expiram**: escalonamento eterno pune IP legítimo reincidente; decay de 24h limpo
3. **Contagem por IP permite pool bypass**: nosso pool de 10 IPs × 9 traps = bypass sustentado → **agregar por subnet** fecharia o pool inteiro (o atacante está todo numa /24)
4. **Mapa de portas estático e público** (código aberto): fingerprint determinístico → randomizar traps por host/dia
5. **Banners contraditórios**: `Server: Apache/2.4.57 (Ubuntu)` + corpo "FreeBSD Default Page" → assinatura de 1 request
6. **Sem correlação entre hosts**: ban no .160 não protege .222 → propagar via Wazuh active response
7. **Hammering de banido é ignorado**: sem re-escala/sinal de persistência do atacante
8. **Census barato**: aceitação de trap É a assinatura; portas refused mapeiam a superfície de graça

## 7. Estado ao salvar este plano

- Pool .240-.249 **queimado rumo ao .160** pelos testes anteriores (threshold 10; bans escalonados 10min/30min/1h) — aguardar expiração (≤1h da última ofensa 3ª+) antes do próximo run real
- O run com evasão anterior terminou (8h06); output preservado; matriz em `output/defense_matrix.md`
- Próximo run real: governor ativo desde o primeiro request → meta **zero bans** no Potemkin
