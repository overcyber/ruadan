# Correção: hostname do laboratório (juice.octopux) não resolvia dentro do Docker

**Data:** 2026-09-24 ~13:30 (UTC-3)
**Problema reportado:** "dentro do docker não está vinculando o https://juice.octopux/ ao IP real que está dentro do meu /etc/hosts no host"
**Status:** ✅ **CORRIGIDO E VALIDADO — https://juice.octopux/ retorna HTTP 200 de dentro do container (0.14s)**

---

## 1. Causa raiz

O `docker-run.sh` usava **bind mount de arquivo único**:
```bash
-v /etc/hosts:/etc/hosts:ro
```

Bind mounts de arquivo único referenciam o **inode** do arquivo, não o caminho. Quando você edita o `/etc/hosts` do host com `vim`, `sed -i` ou qualquer editor que faz *atomic replace* (cria arquivo novo + rename), o **inode muda** — e qualquer container que já estava rodando (ou subprocesso de um run em andamento) **continua vendo a versão ANTIGA do arquivo**, sem a entrada nova.

Resultado: dentro do container, `juice.octopux` não vinculava a `192.168.50.160` → `curl https://juice.octopux/`, nmap, sqlmap, chromium, davtest etc. falhavam ou iam para o lugar errado, enquanto no host tudo funcionava.

**Comprovação do teste:**
| Cenário | Resolvia? |
|---|---|
| Container novo (qualquer modo) | ✅ sim — pega o /etc/hosts atual |
| Container em execução + /etc/hosts recriado no host | ❌ **não — bind stale (o bug)** |
| macOS / bridge network (sem `--network host`) | ❌ não — /etc/hosts do container só tem localhost |

## 2. Correção aplicada — `--add-host` dinâmico

### `ruadan/docker-run.sh` (todos os 3 modos: custom, `--default`, `--shell`)
Novo bloco logo após a detecção de OS:
```bash
HOST_EXTRA_ARGS=()
while IFS= read -r _hline; do
    _hline="${_hline%%#*}"                      # remove comentários
    _hip="$(echo "${_hline}" | awk '{print $1}')"
    case "${_hip}" in 127.*|::1|0.0.0.0) continue ;; esac   # ignora loopback
    for _hname in $(echo "${_hline}" | awk '{ $1=""; print }'); do
        case "${_hname}" in localhost*|ip6-*|broadcasthost) continue ;; esac
        HOST_EXTRA_ARGS+=(--add-host "${_hname}:${_hip}")
    done
done < /etc/hosts
```
E cada `docker run` recebe `"${HOST_EXTRA_ARGS[@]}"`.

**Por que é robusto:**
- Cada `docker run` **lê o /etc/hosts ATUAL do host no momento da execução** — imune a inode/stale
- Funciona também **sem** `--network host` (macOS/bridge) — antes quebrava totalmente
- O mount `-v /etc/hosts:ro` foi mantido como redundância (comprovado que não conflita com --add-host)

### `docker-compose.yml` (serviço kali-ruadan) — SEM hardcode
O serviço já usa `network_mode: host`, que **compartilha automaticamente o /etc/hosts do host** com o container (comprovado em teste: container com host network, sem mount e sem add-host, resolve `juice.octopux` → `192.168.50.160`).

**Decisão explícita: NENHUM `extra_hosts` hardcoded.** IP de alvo NUNCA fica fixo em arquivo de configuração — a fonte da verdade é sempre o `/etc/hosts` do host:
- Fluxo `./start.sh` / `docker-run.sh` → `--add-host` gerado dinamicamente do `/etc/hosts` a cada execução
- Fluxo `docker compose` → `network_mode: host` usa o `/etc/hosts` do host diretamente

## 3. Validação executada

```
ARGS GERADOS: --add-host juice.octopux:192.168.50.160

dentro do container:
$ getent hosts juice.octopux
192.168.50.160  juice.octopux

$ curl -sk https://juice.octopux/
HTTPS juice.octopux: HTTP 200 em 0.144188s   ← ALVO RESPONDENDO DE DENTRO DO DOCKER
```

## 4. Regra de ouro para o laboratório

1. Hostnames do lab (ex: `juice.octopux`) → sempre no `/etc/hosts` do host
2. Preferência: usar **IPs diretos** no `ruadan/targets/meu_lab.txt` (ex: só `192.168.50.160`) — evita toda a classe de problemas de resolução; o novo código do Ruadan2.py deduplica hostname+IP automaticamente quando ambos apontam pro mesmo host
3. Se usar hostname E mudar o IP do alvo: **reinicie o container/run** (o --add-host é capturado no início de cada docker run)
4. Fluxo preferencial: `./start.sh -hostFile /ruadan/targets/meu_lab.txt` (usa docker-run.sh com --add-host dinâmico)
