"""Validacao de CVEs por PoC INOFENSIVO — transforma citacao em veredito.

Ideia do autor (2026-09-14): "pesquisa de CVE e exploits reais ou criados
para validar as CVEs". Hoje o nmap NSE CITA CVEs por assinatura e o
fingerprint sugere versoes — nada PROVA que a CVE se aplica aquele alvo.
Este modulo fecha esse burco com o mesmo invariante do resto do harness:

  confirmed_precondicao  — um PoC inofensivo EXECUTADO no alvo provou a
                           pre-condicao da CVE (ex.: sandbox Lua do Redis
                           contem 'package' -> packaging vulneravel a
                           CVE-2022-0543), com evidencia + sha256
  candidata_version      — versao do banner esta na faixa afetada MAS
                           versao nao prova presenca (distros fazem
                           backport SEM mudar a string de versao — ex.:
                           Ubuntu/OpenSSH); jamais e confirmed
  refutada_versao        — versao >= fix (a CVE nao se aplica)
  refutada_precondicao   — o PoC inofensivo mostrou a pre-condicao AUSENTE
  nao_aplicavel          — servico exige auth / sem como testar

Base de CVEs CURADA OFFLINE (reprodutibilidade da tese: sem chamada a
APIs externas). Cada entrada tem fonte (NVD/debian tracker) e os PoCs
inofensivos sao "exploits criados" no sentido honesto: provam a
pre-condicao sem executar o escape/estouro (nada destrutivo, nada de
carga util real).

Integrado ao cacador (zeroday_hunt) e rodavel standalone:

  python -m services.pentest.app.cve_validate \
      --inventory /inventory/inventory.yaml --i-am-authorized [--target-ip X]

Referencias verificadas em 2026-09-14:
  CVE-2024-6387 regreSSHion: OpenSSH 8.5p1..9.7p1, fix 9.8p1
    (Qualys/NVD; explora~o real exige vencer race ~10k tentativas —
     fora de escopo, validacao e apenas version_match + ressalva backport)
  CVE-2022-0543 Redis Lua sandbox escape (packaging Debian/Ubuntu):
    deteccao segura = EVAL "return type(package)" 0 -> "table" (vulneravel)
    vs "nil" (imune) (Debian tracker DSA-5081; divulgacao ubercomp 2022)
  CVE-2022-0934 dnsmasq < 2.86: fix 2.86 (version_match)
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------------------- base curada
# produto_re: casa no banner do nmap/net_probe
# faixa: (min_inclusivo, fix_exclusivo) sobre a versao parseada, ou None
# quando a condicao depende de empacotamento (so safe_probe decide)
# safe_probe: nome do PoC inofensivo registrado em _SAFE_PROBES
LOCAL_CVE_BASE: list[dict] = [
    {
        "cve": "CVE-2024-6387", "produto_re": r"openssh[\s_\-]?v?(?P<v>\d+\.\d+)p\d+",
        "faixa": ((8, 5), (9, 8)), "metodo": "version_match",
        "cwes": ["CWE-364"], "class": "ssh_login",
        "titulo": "regreSSHion: race no signal handler do sshd (RCE)",
        "ressalva": "distros (Ubuntu/Debian) fazem BACKPORT do fix sem "
                    "mudar a string de versao — versao na faixa e apenas "
                    "CANDIDATA; confirmar com 'apt changelog openssh-server'"
                    " no alvo. PoC real exige ~10k tentativas de race "
                    "(destrutivo/DoS) — fora de escopo deste framework.",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2024-6387",
    },
    {
        "cve": "CVE-2022-0543", "produto_re": r"redis\b(?:[\s:.-]*(?:v)?(?P<v>[\d.]+))?",
        "faixa": None, "metodo": "safe_probe", "safe_probe": "redis_eval_package",
        "cwes": ["CWE-694"], "class": "redis_unauth",
        "titulo": "Redis: escape do sandbox Lua (empacotamento Debian/Ubuntu)",
        "ressalva": "afeta pacotes Debian/Ubuntu com liblua dinâmica; "
                    "upstream (tarball/container) NAO afetado. O PoC "
                    "inofensivo checa APENAS a presenca da biblioteca "
                    "'package' no sandbox (pre-condicao), sem executa-la.",
        "fonte": "Debian tracker CVE-2022-0543 / DSA-5081",
    },
    {
        "cve": "CVE-2022-0934", "produto_re": r"dnsmasq[\s:.-]*(?:v)?(?P<v>[\d.]+)",
        "faixa": ((2, 0), (2, 86)), "metodo": "version_match",
        "cwes": ["CWE-125"], "class": "dns_version_disclosure",
        "titulo": "dnsmasq: leitura fora do limite em DNSSEC",
        "ressalva": "versao >= 2.86 refuta; exigiria DNSSEC habilitado",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2022-0934",
    },
    {
        # Metasploitable-class: vsftpd 2.3.4 backdoor (porta 21)
        "cve": "CVE-2011-2523", "produto_re": r"vsftpd[\s:.-]*(?:v)?(?P<v>[\d.]+)",
        "faixa": ((2, 3, 4), (2, 3, 5)), "metodo": "version_match",
        "cwes": ["CWE-912"], "class": "ftp_anonymous",
        "titulo": "vsftpd 2.3.4 backdoor (versao comprometida)",
        "ressalva": "afeta exatamente 2.3.4 (tarball comprometido 2011); "
                    "verificacao por versao apenas — nunca conectar na "
                    "porta do backdoor (destrutivo)",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2011-2523",
    },
    {
        "cve": "CVE-2021-41773", "produto_re": r"apache\b.*?(?P<v>2\.4\.\d+)",
        "faixa": ((2, 4, 49), (2, 4, 51)), "metodo": "version_match",
        "cwes": ["CWE-22"], "class": "traversal",
        "titulo": "Apache 2.4.49/50: path traversal em alias (RCE c/ cgi)",
        "ressalva": "afeta 2.4.49–2.4.50 (42013 na .50 c/ cgi); fix 2.4.51. "
                    "Verificavel por http_probe /icons/..%2f — a bateria "
                    "traversal ja cobre o vetor com assinatura passwd.",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2021-41773",
    },
    {
        "cve": "CVE-2020-11950", "produto_re": r"squid\b.*?(?P<v>\d+\.\d+[\d.]*)",
        "faixa": ((4, 0), (5, 1)), "metodo": "version_match",
        "cwes": ["CWE-20"], "class": "header_bypass",
        "titulo": "Squid 4.x: bypass/improper input validation",
        "ressalva": "faixa ampla 4.0–5.0 (fix 5.1): CANDIDATA fraca por "
                    "versao — confirmar com o vetor da reflexao/proxy "
                    "aberto ja detectado pela bateria na :3128",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2020-11950",
    },
    # ---------------- rev13: curadoria por CLASSE (qualquer superficie) ----
    # traversal: Apache 2.4.50 (bypass do fix parcial da 41773)
    {
        "cve": "CVE-2021-42013", "produto_re": r"apache\b.*?(?P<v>2\.4\.\d+)",
        "faixa": ((2, 4, 50), (2, 4, 51)), "metodo": "version_match",
        "cwes": ["CWE-22"], "class": "traversal",
        "titulo": "Apache 2.4.50: path traversal (bypass do fix da 41773; "
                  "RCE com cgi habilitado)",
        "ressalva": "afeta exatamente 2.4.50 (fix 2.4.51); a bateria "
                    "traversal ja cobre o vetor com assinatura passwd",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2021-42013",
    },
    # ssh: Terrapin (prefix truncation) — qualquer versao < 9.6p1
    {
        "cve": "CVE-2023-48795", "produto_re": r"openssh[\s_\-]?v?(?P<v>\d+\.\d+)p\d+",
        "faixa": ((0, 0), (9, 6)), "metodo": "version_match",
        "cwes": ["CWE-354"], "class": "ssh_login",
        "titulo": "Terrapin: truncamento de prefixo no protocolo SSH "
                  "(MitM downgrade/integridade)",
        "ressalva": "afeta TODO OpenSSH < 9.6p1 quando usa ChaCha20-"
                    "Poly1305/CBC — versao e apenas CANDIDATA; mitigacao "
                    "real e config do sshd",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2023-48795",
    },
    # ssh: enumeracao de usuarios por timing (qualquer < 7.8)
    {
        "cve": "CVE-2018-15473", "produto_re": r"openssh[\s_\-]?v?(?P<v>\d+\.\d+)p\d+",
        "faixa": ((0, 0), (7, 8)), "metodo": "version_match",
        "cwes": ["CWE-203"], "class": "user_enum",
        "titulo": "OpenSSH < 7.8: enumeracao de usuarios por timing "
                  "do auth",
        "ressalva": "versao apenas CANDIDATA (backport nao muda string); "
                    "impacto e enumeracao, nao acesso",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2018-15473",
    },
    # info-disclosure: Heartbleed (OpenSSL 1.0.1.x)
    {
        "cve": "CVE-2014-0160", "produto_re": r"openssl[\s:.\-]*(?:v)?(?P<v>\d+\.\d+\.\d+)",
        "faixa": ((1, 0, 1), (1, 0, 2)), "metodo": "version_match",
        "cwes": ["CWE-125"], "class": "info_disclosure",
        "titulo": "Heartbleed: leitura fora do limite no TLS heartbeat",
        "ressalva": "vulneravel 1.0.1a–1.0.1f (fix 1.0.1g); versao "
                    "1.0.1 generica e apenas CANDIDATA — confirmar com "
                    "nmap NSE ssl-heartbleed (inofensivo, so detecta)",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2014-0160",
    },
    # ftp: ProFTPD mod_copy
    {
        "cve": "CVE-2015-3306", "produto_re": r"proftpd[\s:.\-]*(?:v)?(?P<v>\d+\.\d+\.\d+)",
        "faixa": ((1, 3, 5), (1, 3, 6)), "metodo": "version_match",
        "cwes": ["CWE-284"], "class": "ftp_copy_rce",
        "titulo": "ProFTPD 1.3.5: mod_copy permite copiar arquivos sem "
                  "auth (RCE indireto)",
        "ressalva": "afeta 1.3.5–1.3.5a com mod_copy carregado (fix "
                    "1.3.5b/1.3.6); modulo nem sempre ativo",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2015-3306",
    },
    # rce_cgi: php-cgi query string injection (classico em CGI)
    {
        "cve": "CVE-2012-1823", "produto_re": r"php[\s:/.\-]*(?:v)?(?P<v>5\.\d+\.\d+)",
        "faixa": ((5, 0), (5, 4, 2)), "metodo": "version_match",
        "cwes": ["CWE-78"], "class": "rce_cgi",
        "titulo": "PHP CGI: argumentos de query string interpretados como "
                  "opcoes do php-cgi (code disclosure/RCE)",
        "ressalva": "so quando rodando como CGI (php-cgi/handler), nao "
                    "mod_php/fpm — versao e pre-condicao incompleta",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2012-1823",
    },
    # info-disclosure: nginx range integer overflow
    {
        "cve": "CVE-2017-7529", "produto_re": r"nginx[\s:/.\-]*(?:v)?(?P<v>\d+\.\d+\.\d+)",
        "faixa": ((0, 5, 6), (1, 13, 3)), "metodo": "version_match",
        "cwes": ["CWE-190"], "class": "info_disclosure",
        "titulo": "nginx: overflow de inteiro no filtro range (vazamento "
                  "de cache/ memoria)",
        "ressalva": "requer proxy_cache/fastcgi_cache em uso; versao "
                    "apenas CANDIDATA",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2017-7529",
    },
    # dns/DoS: nginx resolver off-by-one
    {
        "cve": "CVE-2021-23017", "produto_re": r"nginx[\s:/.\-]*(?:v)?(?P<v>\d+\.\d+\.\d+)",
        "faixa": ((0, 6, 18), (1, 21, 0)), "metodo": "version_match",
        "cwes": ["CWE-193"], "class": "dns_resolver",
        "titulo": "nginx: off-by-one no resolver DNS (1-byte overwrite)",
        "ressalva": "requer diretiva resolver configurada; versao apenas "
                    "CANDIDATA",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2021-23017",
    },
    # blind-OOB (classe generica JNDI/lookup): Log4Shell — o PoC e o
    # proprio canario OOB do harness: prova a PRE-CONDICAO (lookup de
    # endereco externo) sem carregar objeto remoto algum
    {
        "cve": "CVE-2021-44228", "produto_re": r"\b(log4j|solr)\b",
        "faixa": None, "metodo": "safe_probe",
        "safe_probe": "log4shell_jndi",
        "cwes": ["CWE-502", "CWE-917"], "class": "blind_oob_jndi",
        "titulo": "Log4Shell: lookup JNDI em campo logado (prova por "
                  "canario OOB, carga zero)",
        "ressalva": "o PoC inofensivo prova APENAS a pre-condicao — o "
                    "alvo BUSCA o endereco canario por conta propria; "
                    "nenhum objeto remoto e carregado. Sem callback NAO "
                    "refuta saidas bloqueadas por firewall; produto_re "
                    "casa banners que exponham log4j/solr",
        "fonte": "NVD nvd.nist.gov/vuln/detail/CVE-2021-44228",
    },
]

# PoCs inofensivos: (comando texto, interpretador do rx_text -> veredito)
# Todos leem apenas estado global do servico — nada de escape executado.
# rev13: probes de classe blind-OOB ("kind": "jndi_http") usam o listener
# C2 do harness como prova — o alvo BUSCA o endereco canario por conta
# propria (SSRF/fetch/JNDI); sem callback em oob_wait = pre-condicao
# ausente (resposta honesta).
_SAFE_PROBES: dict[str, dict] = {
    "redis_eval_package": {
        "payload": 'EVAL "return type(package)" 0\r\n',
        "interpreta": "redis_package",
        "descricao": "Lua sandbox contem a biblioteca 'package'? "
                     "(pre-condicao do escape; sem loadlib/popen)",
        # marcas na ordem: resposta real do Redis hardened e um ERR
        # explicito dizendo que 'package' nao existe = pre-condicao AUSENTE
        "espera": {"table": "confirmed_precondicao",
                   "nonexistent global variable": "refutada_precondicao",
                   "nil": "refutada_precondicao",
                   "NOAUTH": "nao_aplicavel"},
    },
    "log4shell_jndi": {
        "kind": "jndi_http",          # rev13: blind-OOB via listener C2
        "header": "X-Api-Version",    # campo tipicamente LOGADO pelo backend
        "path": "/",
        "oob_wait": 25,
        "descricao": "JNDI/lookup de endereco canario (classe blind-OOB): "
                     "o alvo BUSCA ldap://canario por conta propria — "
                     "pre-condicao de lookup remoto, sem carga util",
    },
}

_VERDICTOS = {"confirmed_precondicao", "candidata_version",
              "refutada_versao", "refutada_precondicao", "nao_aplicavel",
              "candidata_searchsploit"}


def _fallback_searchsploit(tb, banners: dict[int, str],
                           portas_ja: set[int]) -> list[CveResultado]:
    """rev9: produto SEM entrada curada -> busca exploits no Exploit-DB
    local (searchsploit) e registra como candidata_searchsploit com a
    lista real de exploits (evidencia gravada)."""
    out: list[CveResultado] = []
    if tb.dry_run:
        return out
    from .exploit_search import ss_busca
    for porta, banner in (banners or {}).items():
        if porta in portas_ja:
            continue
        texto = str(banner)
        if not texto or texto.startswith("port/"):
            continue
        produto = texto.split()[0]
        versao = ""
        for tok in texto.split()[1:3]:
            if re.fullmatch(r"[0-9][0-9a-zA-Z.\-]*", tok):
                versao = tok
                break
        if not produto.isalpha():
            continue
        r = ss_busca(termo=f"{produto} {versao}".strip())
        if not r.get("ok") or not [
                l for l in r.get("stdout", "").splitlines()
                if "|" in l and "Exploit Title" not in l]:
            # retry SEM a versao exata (titulos do Exploit-DB raramente a
            # trazem; a lista ampla e filtrada depois pelo leitor)
            r = ss_busca(termo=produto)
        if not r.get("ok") or not r.get("stdout", "").strip():
            continue
        linhas = [l for l in r["stdout"].splitlines()
                  if "|" in l and "Exploit Title" not in l
                  and "---" not in l][:6]
        if not linhas:
            continue
        ev = tb._save_evidence(
            "cve_validate", f"searchsploit_{produto}_{porta}.txt",
            f"$ {r.get('comando','')}\n\n{r['stdout'][:8000]}")
        out.append(CveResultado(
            cve="—(Exploit-DB)", veredito="candidata_searchsploit",
            produto=produto, porta=porta, versao=versao,
            metodo="searchsploit", evidencia=ev,
            detalhe="; ".join(l.strip()[:110] for l in linhas[:3]),
            cross_ref={"fonte": "Exploit-DB local (searchsploit)"}))
        portas_ja.add(porta)
    return out


def _versao_tuple(txt: str):
    m = re.search(r"(?P<v>\d+(?:\.\d+)+)", txt or "")
    if not m:
        return None
    return tuple(int(x) for x in m.group("v").split("."))


def _cmp_faixa(v: tuple, faixa) -> str | None:
    """None se in comparavel; 'dentro'/'antes'/'depois' senao.

    rev13 (bug fix): antes truncava v para 2 componentes — versoes de 3+
    componentes quebravam (Apache 2.4.49 vs faixa (2,4,49)-(2,4,51) era
    REFUTADO erradamente como 'abaixo da faixa'; idem vsftpd 2.3.4).
    Comparacao por prefixo componente-a-componente, sem truncar."""
    lo, fix = faixa
    if not v:
        return None

    def _cmp(a: tuple, b: tuple) -> int:
        for x, y in zip(a, b):
            if x != y:
                return -1 if x < y else 1
        # prefixo igual: menor comprimento < maior comprimento
        return 0 if len(a) == len(b) else (-1 if len(a) < len(b) else 1)

    if _cmp(v, fix) < 0:
        return "antes" if _cmp(v, lo) >= 0 else None
    return "depois"


@dataclass
class CveResultado:
    cve: str
    veredito: str
    produto: str
    porta: int
    versao: str = ""
    metodo: str = ""
    evidencia: str = ""
    detalhe: str = ""
    cross_ref: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ---------------------------------------------------------------- nucleo
def _procura_candidatos(banners: dict[int, str]) -> list[tuple[dict, int, tuple | None]]:
    """Cruza banners (porta->texto) com a base curada."""
    out = []
    for porta, banner in (banners or {}).items():
        texto = str(banner)
        for entrada in LOCAL_CVE_BASE:
            m = re.search(entrada["produto_re"], texto, re.IGNORECASE)
            if m:
                v = _versao_tuple(m.group("v")) if m.groupdict().get("v") else None
                out.append((entrada, int(porta), v))
    return out


def _roda_safe_probe(tb, host_ip: str, port: int, nome: str) -> tuple[str, str]:
    """Executa o PoC inofensivo pelas primitivas do harness, que ja grava
    evidencia com sha256. Retorna (veredito, evidencia).

    rev13: probes de classe blind-OOB (kind=jndi_http) injetam endereco
    canario (${jndi:ldap://listener/token}) em header tipicamente logado e
    esperam o CALLBACK no listener C2 — prova de pre-condicao sem carga
    util (o alvo busca o endereco; nada e carregado dele)."""
    spec = _SAFE_PROBES[nome]
    if spec.get("kind") == "jndi_http":
        from .arsenal import http_probe
        src = tb._local_source_ip(host_ip)
        if not src:
            return "nao_aplicavel", ""
        token = "PENTEST_CANARY_" + secrets.token_hex(8)
        listener = tb.channels.ensure_listener()
        if listener.sock is None:
            return "nao_aplicavel", ""
        http_probe(tb, host_ip, port, "GET", spec.get("path", "/"),
                   headers={spec.get("header", "X-Api-Version"):
                            f"${{jndi:ldap://{src}:{tb.inv.listener_port}/{token}}}"},
                   oob_wait=0)  # nao usa o canario generico do http_probe
        res = listener.wait_for_token(
            token, wait_seconds=int(spec.get("oob_wait", 25)))
        ev = tb._save_evidence(
            "cve_validate",
            f"jndi_{port}_{abs(hash(token)) % 10**8}.log", res["log"])
        return ("confirmed_precondicao" if res["verified"]
                else "refutada_precondicao"), ev["file"]
    from .arsenal import net_probe
    r = net_probe(tb, host_ip, port, "tcp",
                  send_text=spec["payload"], read_timeout=6.0)
    rx = (r.get("rx_text") or "") + (r.get("error") or "")
    ev = r.get("evidence", "")
    for marca, veredito in spec["espera"].items():
        if marca in rx:
            return veredito, ev
    return "nao_aplicavel", ev


def validate_host(tb, host_ip: str, banners: dict[int, str],
                  max_candidatas: int = 10) -> list[CveResultado]:
    """Valida as CVEs candidatas de UM host. Tudo inofensivo e evidenciado."""
    resultados: list[CveResultado] = []
    for entrada, porta, versao in _procura_candidatos(banners)[:max_candidatas]:
        res = CveResultado(cve=entrada["cve"], veredito="nao_aplicavel",
                           produto=entrada["produto_re"][:24], porta=porta,
                           versao=".".join(map(str, versao)) if versao else "",
                           metodo=entrada["metodo"],
                           cross_ref={"cwes": entrada["cwes"],
                                      "class": entrada["class"],
                                      "fonte": entrada["fonte"]})
        if entrada["metodo"] == "safe_probe" and not tb.dry_run:
            verd, ev = _roda_safe_probe(tb, host_ip, porta,
                                        entrada["safe_probe"])
            res.veredito = verd
            res.evidencia = ev
            res.detalhe = (f"PoC inofensivo: "
                           f"{_SAFE_PROBES[entrada['safe_probe']]['descricao']}")
        elif entrada["metodo"] == "version_match" and versao:
            pos = _cmp_faixa(versao, entrada["faixa"])
            if pos == "antes":
                res.veredito = "candidata_version"
                res.detalhe = (f"versao {'.'.join(map(str, versao))} na faixa "
                               f"afetada {entrada['faixa']} — {entrada['ressalva']}")
            elif pos is None:
                res.veredito = "refutada_versao"
                res.detalhe = (f"versao {'.'.join(map(str, versao))} ABAIXO da "
                               f"faixa afetada {entrada['faixa']} — nao se aplica")
            else:
                res.veredito = "refutada_versao"
                res.detalhe = (f"versao {'.'.join(map(str, versao))} >= fix "
                               f"{entrada['faixa'][1]} — CVE nao se aplica")
        resultados.append(res)
    # rev9: fallback Exploit-DB para produtos sem entrada curada
    portas_ja = {r.porta for r in resultados}
    resultados.extend(_fallback_searchsploit(tb, banners, portas_ja))
    return [r for r in resultados if r.veredito in _VERDICTOS]


def validate_host_to_events(hunter, hh) -> None:
    """Integracao com o cacador: valida, registra eventos e anexa ao host."""
    banners = {int(p): str(v) for p, v in (hh.products or {}).items()}
    if not banners or hunter.dry_run:
        return
    resultados = validate_host(hunter.tb, hh.ip, banners)
    hh.cve_validations = [r.to_dict() for r in resultados]
    for r in resultados:
        hunter._ev(kind="cve_validation", host=hh.ip, **r.to_dict())
        print(f"[cve] {hh.ip}:{r.porta} {r.cve} -> {r.veredito} "
              f"({r.metodo})")
    if resultados:
        hunter._flush_manifest()


# ------------------------------------------------------------------ CLI
def _parse(argv=None):
    ap = argparse.ArgumentParser(prog="cve-validate")
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--target-ip", default=None)
    ap.add_argument("--i-am-authorized", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--runs-root", default="data/pentest_runs")
    return ap.parse_args(argv)


def main(argv=None) -> None:
    args = _parse(argv)
    from .cli import _apply_target_overrides
    from .hunt_suite import hunt_suite_proto
    from .inventory import load_inventory
    from .safety import SafetyGate
    from .session import ChannelPool
    from .state import PentestState
    from .tools import ToolBox

    inv = load_inventory(args.inventory)
    if args.target_ip:
        inv = _apply_target_overrides(
            inv, argparse.Namespace(target_ip=args.target_ip, subnet=None,
                                    ssh_user=None, ssh_pass=None))
    if not args.dry_run and not args.i_am_authorized:
        raise SystemExit("validacao real exige --i-am-authorized ou --dry-run")
    if not inv.ip_allowed(inv.seed_host_ip):
        raise SystemExit(f"alvo {inv.seed_host_ip} fora dos CIDRs autorizados")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.runs_root) / f"{stamp}_cveval"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "evidence").mkdir()
    state = PentestState(max_steps=100)
    state.add_host(inv.seed_host_ip)
    safety = SafetyGate(inv, authorized_flag=not args.dry_run)
    tb = ToolBox(state, inv, safety, ChannelPool(inv),
                 evidence_root=run_dir / "evidence", dry_run=args.dry_run)

    host = inv.seed_host_ip
    print(f"[cve] validando CVEs de {host} (base curada offline: "
          f"{len(LOCAL_CVE_BASE)} entradas)")
    banners: dict[int, str] = {}
    if not args.dry_run:
        # mini-fingerprint: -sV nas portas dos produtos da base
        r = tb.tool_service_scan(
            host, extra_args=["-p", "21,22,25,53,80,443,1080,1337,1524,"
                              "1883,2121,3128,3306,5432,5900,6379,6380,"
                              "6667,8000,8080,8180,11211,27017"], timeout=300)
        for p, banner in (r.get("services") or {}).items():
            banners[int(p)] = str(banner)
    resultados = validate_host(tb, host, banners) if not args.dry_run else []
    doc = {"host": host, "gerado": datetime.now(timezone.utc).isoformat(),
           "base": [e["cve"] for e in LOCAL_CVE_BASE],
           "banners": {str(k): v for k, v in banners.items()},
           "resultados": [r.to_dict() for r in resultados]}
    (run_dir / "cve_validation.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    (run_dir / "evidence_manifest.json").write_text(
        json.dumps(tb.evidence_manifest, ensure_ascii=False, indent=1),
        encoding="utf-8")
    L = ["# Validacao de CVEs por PoC inofensivo", "",
         f"- Host: {host} | base curada offline", "",
         "| CVE | porta | veredito | metodo | detalhe |", "|---|---|---|---|---|"]
    for r in resultados:
        L.append(f"| {r.cve} | {r.porta} | **{r.veredito}** | {r.metodo} "
                 f"| {r.detalhe[:110]} |")
    L += ["", "Vereditos: confirmed_precondicao = PoC inofensivo PROVOU a "
              "pre-condicao; candidata_version = versao na faixa (backport "
              "nao muda string — nao confirma); refutada_* = nao se aplica."]
    (run_dir / "cve_validation.md").write_text("\n".join(L), encoding="utf-8")
    print(f"[cve] resultados: {len(resultados)} | "
          f"{run_dir / 'cve_validation.md'}")


if __name__ == "__main__":
    main()
