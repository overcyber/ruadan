# Correções: Args Inválidos + Uso Profundo da Falha da Página

**Data:** 2026-09-25 ~10:40 local | **Backups:** 60+ arquivos em `.backup/` (regra imutável)

## 1. ✅ Fix: comandos inválidos JAMAIS mais disparam alvos genéricos

**Problema:** um comando com hostFile inexistente/typo fazia o sistema cair no fallback
`hosts.txt` e rodar contra ALVOS GENÉRICOS silenciosamente.

**Correção (2 camadas):**

### Camada 1 — `start.sh` (validação ANTES de qualquer container):
```
$ ./start.sh -hostFile /ruadan/targets/ARQUIVO_QUE_NAO_EXISTE.txt
[x] ERRO: o hostFile '...' especificado NÃO existe (procurado em targets/ do repo).
    Alvos disponíveis em /system/ruadan-new/targets/:
      - hosts.txt
      - juicer.txt
      - meu_lab.txt
    Abortando — refusing alvos genéricos silenciosos.
EXIT CODE: 2  ✓ validado
```

### Camada 2 — `Ruadan2.py` (fallback genérico só sem -hostFile explícito):
- hostFile ESPECIFICADO + inexistente → **ERRO FATAL + exit 2** (sem fallback)
- Sem -hostFile no comando → fallback hosts.txt legítimo

## 2. ✅ Uso profundo da falha da página: `web_post_auth_probe.sh`

**Problema:** "o sistema não soube usar a falha na página" — o SQLi probe parava no bypass.

**Agora** (após o SQLMap Login no [Exploitation], com o JWT admin capturado):
```
WEB_ADMIN_ACCESS: JWT admin obtido via SQLi (login bypass) — 732 chars
WEB_USERS_DUMP: 22 conta(s) enumerada(s) da base real via API admin
                — admin@juice-sh.op, jim@juice-sh.op, bender@juice-sh.op...
[post-auth] Path traversal /ftp: app segura quanto a LFI (honesto)
[post-auth] /ftp/legal.md: HTTP 403 (145B) — bloqueio do proxy/servidor (honesto)
```
**Critério honesto de FILE_READ:** só HTTP 200 + conteúdo real (o 403/146B do proxy
nginx era reportado como leitura — corrigido; validado contra o alvo real).

## 3. 🎯 O caminho REAL do shell (honestidade técnica)

O **Juice Shop é seguro por design quanto a RCE** (não executa uploads como código,
sem eval, sem sandbox escape) — a "falha da página" entrega no máximo:
- ✔ autenticação admin (JWT via SQLi) — FEITO
- ✔ dump de dados da base (22 contas reais) — FEITO
- ✔ leitura do /ftp com encoding tricks (bloqueada pelo proxy octopux 403 aqui)
- ✖ RCE de host — NÃO EXISTE no Juice Shop (by design)

**Onde há shell de verdade no lab:** os vizinhos detectados pelo pivot
(**192.168.50.221/222** — VMware, reais, vistos no arp do host comprometido).
Qualquer serviço com RCE conhecido neles (ex: Samba/vsftpd/FTP antigões, Tomcat,
serviços expostos) → o pipeline MSF (Etapas 1-4) abre session, escala e pivota.
**Basta adicionar 192.168.50.221 e/ou 192.168.50.222 ao `meu_lab.txt`** e rodar
`./start.sh -hostFile /ruadan/targets/meu_lab.txt` — o ciclo IA + MSF procura
RCE real e, se existir, o `MSF_SESSION_OPENED` vira `evidence=credential` de verdade.

## 4. Teste final em andamento
Run completo do zero com o probe pós-auth integrado — validação: o passo 2
(PRIVILEGE_ESCALATE → [Exploitation]) agora executa SQLi probe → **post-auth probe**
(JWT + 22 contas) → evidence=finding/credential com dados REAIS da falha explorada.

---

## ✅ 5. RESULTADO DO RUN FINAL V2 (validação completa)

**Run:** `./start.sh -hostFile /ruadan/targets/meu_lab.txt` — **Elapsed 15:34** | **LLM 5/5 SUCCESS**

```
passo 1 EXPLOIT_REMOTE    : finding    | 126 achados (ffuf + SPA routes + probes)
passo 2 PRIVILEGE_ESCALATE: credential | ★ BYPASS DE AUTENTICAÇÃO CONFIRMADO via SQLi ★
passo 3 PERSIST_BACKDOOR  : enum_only  | honesto
passo 4 C2_ESTABLISH      : enum_only  | honesto (juice sem RCE)
passo 5 EXFILTRATE        : enum_only  | canário SHA256
```

### As marcas da falha da página DENTRO do ciclo (saída real do run):
```
SQLI_LOGIN_BYPASS_CONFIRMED: https://juice.octopux/rest/user/login (401 → 200)
WEB_ADMIN_ACCESS: JWT admin obtido via SQLi (login bypass) — 732 chars
WEB_USERS_DUMP: 22 conta(s) enumerada(s) da base real via API admin
                — admin@juice-sh.op, jim@juice-sh.op, bender@juice-sh.op
```

**Conclusão:** o sistema agora (a) aborta em comandos inválidos sem cair em alvos
genéricos, (b) usa a falha da página até a profundidade real disponível — do bypass
SQLi ao JWT admin ao dump de 22 contas reais — com tudo virando evidence da kill chain.
O shell de host no Juice Shop não existe por design; o caminho real são os vizinhos
192.168.50.221/222 (basta adicioná-los ao meu_lab.txt e rodar novamente).
