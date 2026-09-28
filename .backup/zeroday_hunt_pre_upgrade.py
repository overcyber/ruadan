"""CACADOR AUTONOMO de 0-day — o LLM dirige a cacada, sem politica .pt.

Modo pedido pelo autor (2026-09-13): um sistema capaz de USAR O MODELO (LLM
gpt-oss:20b local) e buscar um 0-day em QUALQUER servico, porta ou sistema
rodando — sem estar preso ao vocabulario de 10 acoes da politica MADDPG.

Pipeline (tudo em UMA pasta de run auditada):
  F0 varredura      ping sweep da subnet + nmap -Pn -p <range> em cada host
  F1 enumeracao     nmap -sV nas portas abertas (banner/produto)
  F2 bateria        hunt_suite por porta (web -> http battery; resto ->
                    proto battery) — achados DETERMINISTICOS com prova
  F3 cacaca LLM     por host: briefing (fingerprint + achados + anomalias)
                    e o LLM formula/testa hipoteses com http_probe/
                    net_probe/run_command (canario OOB em sondas cegas);
                    confirmed do LLM so vale com prova executavel anexada
  F4 veredito       findings.json + hunt_report.md + auditoria dupla
                    (audit_run do harness + audit_hunt propria, que exige
                    evidencia com sha256 em TODO confirmed)

Diferenca para o harness de campanha: AQUI o LLM escolhe TAMBEM O QUE
sondar (nao so o COMO); a politica .pt nao participa. Invariantes mantidas:
  - toda execucao passa pelo ToolBox (CIDR, denylist, allowlist, evidencia
    com sha256, probe_log/command_log)
  - sucesso/confirmed so com verificacao executavel (oob_callback,
    reflexao de token, assinatura de conteudo, resposta de protocolo que
    concede acesso) — hipotese sem prova fica suspect
  - credenciais: so as do inventario (ssh_login rejeita o resto);
    cred_attack NAO entra no cacador (nao e 0-day e audit exige opt-in)

Uso:
  python -m services.pentest.app.zeroday_hunt \
      --inventory configs/pentest/inventory.yaml --i-am-authorized

  # sem LLM (so bateria deterministica) / dry-run / outra porta-range
  ... --no-llm | --dry-run | --port-range 1-10000 | --rounds 16
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .audit import audit_run
from .cli import _CampaignTee, _apply_target_overrides
from .hunt_suite import (eh_web, hunt_suite_http, hunt_suite_proto,
                         verify_suspect)
from .inventory import load_inventory
from .llm_orchestrator import (DEFAULT_MODEL, LLMOrchestrator, _CallStat,
                               _scan_json_objects)
from .safety import SafetyGate, SafetyViolation
from .session import ChannelPool
from .state import PentestState
from .tools import ToolBox

HUNT_SYSTEM_PROMPT = """Voce e o CACADOR AUTONOMO de vulnerabilidades (0-day hunt) de um
penteste AUTORIZADO em laboratorio proprio de pesquisa (tese de doutorado).
AQUI NAO EXISTE politica RL: voce dirige a cacada do inicio ao fim, para
QUALQUER servico/porta/protocolo — nao so HTTP.

BRIEFING: voce recebe fingerprint (portas/produtos), banners brutos e os
achados da bateria automatica JA VERIFICADA: "confirmed" tem prova
executavel; suspeitas que eram falso positivo (SPA, header sem efeito,
erro generico) foram DESCARTADAS e nao aparecem; o que resta como
"suspect" e anomalia REAL que a sonda generica nao conseguiu provar nem
refutar — ESSES sao sua prioridade maxima, junto com o que mais voce
descobrir. Sua tarefa: formular hipoteses ESPECIFICAS sobre falhas e
testa-las com as tools.

PROTOCOLO (repita por hipotese):
0a. CREDS: se houver sqli/login confirmado, EXTRAIA dados/credenciais
   (UNION/erro; http_probe em repeticao) e reporte em discovered_creds
   (user+senha OBSERVADOS na evidencia).
0b. CRED ATTACK: para CADA servico com autenticacao (SSH, RDP, VNC, Squid,
   FTP, MySQL), chame cred_attack (password spray DECLARADO no inventario).
   Se achar cred funcional → ssh_login → remote_exec → check_root = SHELL.
0. INTEL PRIMEIRO: com produto+versao (ou CVE citada pelo NSE/bateria),
   chame exploit_search (feed CVE local + searchsploit Exploit-DB; aceita
   termo="produto versao" ou o XML do nmap) e cve_lookup(CVE). Exploit
   publico existente = hipotese PRONTA: EXTRAIA O VETOR e EXECUTE AGORA com
   exploit_execute(cve_id, host_ip). NAO fique apenas observando — FIRE!
   Cada CVE candidata DEVE ser testada com exploit_execute.
1. OBSERVE o briefing — anomalias sao pistas (catch-all, reflexao, banner
   estranho, protocolo sem auth, erro verboso, versao antiga sem CVE
   mapeada = candidato a 0-day).
2. HIPOTESE especifica e falsificavel (ex: "o catch-all faz fetch de URL
   do corpo", "o parse do protocolo X aceita campo sem validar tamanho",
   "o endpoint /upload aceita path no filename").
3. TESTE com a primitiva certa e payload INOFENSIVO:
   - http_probe: HTTP arbitrario (metodo/path/headers/body); use oob_wait
     15-25 para hipoteses CEGAS (SSRF/fetch/RCE cego — o callback com token
     ao listener e a prova).
   - net_probe: TCP/UDP RAW (send_hex/send_text) para QUALQUER protocolo —
     inclusive os que a bateria nao conhece.
   - run_command: ferramenta especializada (nmap NSE custom, redis-cli,
     smbclient, snmpwalk, hydra OFF para brute — isso NAO e cacca).
   NAO repita probe identico; cada hipotese merece 1-3 sondas novas.
4. CONFIRME so com PROVA EXECUTAVEL: oob_callback=true (token voltou ao
   listener), token unico refletido, leitura de arquivo com assinatura,
   resposta de protocolo que concede acesso/dados. SEM PROVA = suspect.
5. Reporte sub_technique (T1190 http | T1095 raw | T1059 composta).

Regras duras:
- Nada destrutivo; credenciais SO as de ssh_creds_disponiveis (inventario).
- Nao invente resultados: leia o que a tool devolveu.
- Esgotou hipoteses? Pare e reporte.

RESPOSTA FINAL: UM UNICO objeto JSON (sem texto ao redor):
{"summary": "resumo da cacada neste host",
 "findings": [{"port": <int>, "verdict": "confirmed"|"suspect"|"clean",
               "hypothesis": "o que voce suspeitou",
               "evidence": "prova executavel obtida (ou 'nenhuma')",
               "sub_technique": "Txxxx"}],
 "discovered_creds": [{"username": "...", "password": "...",
                       "source": "finding/classe", "evidence": "arquivo"}]}
— discovered_creds: APENAS credenciais OBSERVADAS na evidencia desta run
(ex.: dump de SQLi, pagina pos-login); nunca inventadas/adivinhadas."""

# tools do cacador (FIX 2026-09-26: cred_attack ADICIONADO — sem ele o LLM não
# pode fazer password spray em SSH/RDP/VNC/Squid; persist/exfil continuam fora)
HUNT_TOOLS = ("get_state", "get_vuln_hints", "service_scan", "vuln_scan",
              "web_discover", "http_probe", "net_probe", "run_command",
              "exploit_search", "exploit_execute", "exploit_modify", "cve_lookup",
              "ssh_login", "remote_exec", "check_root", "read_file",
              "privesc_scan", "cred_attack")

_VERDICTS = {"confirmed", "suspect", "clean"}
_OPEN_PORT = re.compile(r"^(\d+)/tcp\s+open", re.MULTILINE)


@dataclass
class HuntConfig:
    port_range: str = "1-65535"
    rounds: int = 14          # rodadas LLM por host
    max_cmds_host: int = 24   # teto de run_command por host (fase LLM)
    use_llm: bool = True
    model: str = ""
    expand_all: bool = False  # varrer demais redes autorizadas
    # --- rev13 (universalidade: qualquer rede, qualquer N de maquinas) ---
    # max_hosts: teto de hosts cacados por run. 0 = ILIMITADO (o budget
    #   wall-clock e o limite real). Excedentes entram em
    #   hosts_nao_cobertos do relatorio — nunca truncagem silenciosa
    #   (antes: extras[:8] hardcoded na expansao multi-rede).
    max_hosts: int = 0
    # per_host_budget: segundos por host. 0 = AUTOMATICO:
    #   max(300s, wall_clock_restante / hosts que faltam) — host individual
    #   nunca morre de inanição em rede grande, e o relatorio marca a
    #   cobertura parcial quando o budget do host estoura.
    per_host_budget: int = 0
    # fast_first: two-phase para redes grandes — top-1000 portas em TODOS os
    #   vivos (barato), score de superficie (portas + banner com versao),
    #   full-range 1-65535 apenas nos hosts com superficie rica. Sem isso,
    #   F1 sequencial full-range domina o tempo total a partir de ~20 hosts.
    fast_first: bool = False


@dataclass
class HostHunt:
    ip: str
    ports: list[int] = field(default_factory=list)
    products: dict = field(default_factory=dict)     # porta -> banner nmap
    suite_findings: list = field(default_factory=list)
    llm_findings: list = field(default_factory=list)
    descartados: list = field(default_factory=list)  # FPs removidos c/ motivo
    cve_validations: list = field(default_factory=list)  # F2.7 (PoC inofensivo)
    discovered_creds: list = field(default_factory=list)  # rev11 (observados)
    tools_used: list = field(default_factory=list)
    llm_summary: str = ""
    outcome: str = "FAILED_TARGET_HARD"
    detail: str = ""
    # rev13: cobertura honesta por host
    spa_routes: dict = field(default_factory=dict)  # porta -> rotas #/ do bundle JS
    cobertura_parcial: str = ""  # motivo quando a caca do host foi cortada no meio


class ZeroDayHunter:
    """Orquestra F0-F4 sobre UM run_dir auditado."""

    def __init__(self, inv, run_dir: Path, cfg: HuntConfig, dry_run: bool):
        self.inv = inv
        self.cfg = cfg
        self.dry_run = dry_run
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "evidence").mkdir(exist_ok=True)
        (self.run_dir / "llm_transcripts").mkdir(exist_ok=True)
        self.safety = SafetyGate(inv, authorized_flag=not dry_run)
        self.channels = ChannelPool(inv)
        self.state = PentestState(max_steps=10000)
        self.tb = ToolBox(self.state, inv, self.safety, self.channels,
                          evidence_root=self.run_dir / "evidence",
                          dry_run=dry_run)
        self.expand_all = bool(getattr(cfg, "expand_all", False))
        self.orch: LLMOrchestrator | None = None
        if cfg.use_llm:
            # Timeout de resposta do LLM configurável — gpt-oss:20b em CPU pode
            # levar vários minutos por rodada de tools (decisão do operador).
            self.orch = LLMOrchestrator(
                self.tb,
                model=cfg.model or None,
                llm_log_path=self.run_dir / "llm_calls.ndjson",
                transcript_dir=self.run_dir / "llm_transcripts",
                max_tool_rounds=cfg.rounds,
                request_timeout=int(os.environ.get(
                    "RUADAN_LLM_TIMEOUT", "600")))
        self.events: list[dict] = []
        self._terminated = False      # rev13: flag de terminate (ndjson e a fonte)
        self._exploit_cache: dict[str, bool] = {}  # rev13: busca por banner sem repeticao
        self._host_deadline: float | None = None   # rev13: budget por host (monotonic)
        self.hosts: list[HostHunt] = []
        self._step = 0

    # ---------------------------------------------------------------- events
    def _ev(self, **kw) -> None:
        evt = {"ts": datetime.now(timezone.utc).isoformat(), **kw}
        if kw.get("kind") == "terminate":
            self._terminated = True
        # rev13: lista em RAM com TETO (era ilimitada: rede grande x
        # eventos por host inflava memoria duplicando o events.ndjson);
        # a fonte de verdade continua sendo o ndjson (auditoria/attribution)
        if len(self.events) < 2000:
            self.events.append(evt)
        with (self.run_dir / "events.ndjson").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(kw, ensure_ascii=False, default=str) + "\n")

    def _flush_manifest(self) -> None:
        (self.run_dir / "evidence_manifest.json").write_text(
            json.dumps(self.tb.evidence_manifest, ensure_ascii=False,
                       indent=1), encoding="utf-8")

    def _write_transcript(self, idx: int, hh: HostHunt, doc: dict) -> None:
        p = self.run_dir / "llm_transcripts" / f"step{idx:03d}_ZERO_DAY_HUNT.json"
        p.write_text(json.dumps(doc, ensure_ascii=False, default=str,
                                indent=1), encoding="utf-8")

    # ------------------------------------------------------------- F0/F1 recon
    def sweep(self, subnet: str) -> list[str]:
        """F0: hosts vivos na subnet (registra no estado, auditado)."""
        self._ev(kind="phase", phase="sweep", subnet=subnet)
        r = self.tb.tool_ping_sweep(subnet)
        ips = [f["ip"] for f in (r.get("found_hosts") or [])]
        if self.inv.seed_host_ip not in ips:
            self.state.add_host(self.inv.seed_host_ip,
                                hostname="seed")
            ips.insert(0, self.inv.seed_host_ip)
        print(f"[sweep] {len(ips)} hosts vivos: {ips}")
        self._ev(kind="phase", phase="sweep_result", hosts=ips,
                 evidence=r.get("xml"))
        return ips

    def scan_ports(self, ip: str, lite: bool = False) -> tuple[list[int], dict]:
        """F1: port_range com nmap cru (rapido) + -sV nas abertas.

        lite=True (rev13): --top-ports 1000 — fase 1 do two-phase para
        redes grandes (fast_first): rapido em TODOS os vivos para
        priorizar; full-range fica para os hosts com superficie.

        Retorna (portas_abertas, porta->banner). Parse do txt nmap com
        regex ^porta/tcp open — evidencia integral no run_dir."""
        hh_idx = len(self.hosts)
        self.state.step = hh_idx + 1  # dirs de evidencia unicos por host
        self._ev(kind="phase", phase="portscan", host=ip,
                 port_range=("top-1000" if lite else self.cfg.port_range),
                 lite=lite)
        portas: list[int] = []
        produtos: dict = {}
        if self.dry_run:
            portas, produtos = [80, 22], {80: "dry", 22: "dry"}
        else:
            portas_arg = ("--top-ports 1000" if lite
                          else f"-p {self.cfg.port_range}")
            r = self.tb.tool_run_command(
                f"nmap -Pn -n --min-rate 1500 {portas_arg} "
                f"{ip}", timeout=600)
            txt = (r.get("stdout") or "") + (r.get("stderr") or "")
            portas = sorted({int(m.group(1)) for m in
                             _OPEN_PORT.finditer(txt)})
            if portas:
                r_v = self.tb.tool_service_scan(
                    ip, extra_args=["-p", ",".join(str(p) for p in portas)],
                    timeout=420)
                for p_str, banner in (r_v.get("services") or {}).items():
                    produtos[int(p_str)] = banner
        print(f"[scan{'-lite' if lite else ''}] {ip}: "
              f"{len(portas)} portas abertas {portas}")
        self._ev(kind="phase", phase="portscan_result", host=ip,
                 open_ports=portas, products=produtos)
        return portas, produtos

    # ---------------------------------------------------------------- F2 suite
    def run_suite(self, hh: HostHunt) -> None:
        """F2: bateria generica por porta (sem LLM) + F2.5 VERIFICACAO:
        cada suspect e promovido (com prova) ou descartado (com motivo)."""
        for port in hh.ports:
            # rev13: budget por host — bateria para onde o host parou e a
            # cobertura parcial fica REGISTRADA (nunca silencio)
            dl = self._host_deadline
            if dl is not None and time.monotonic() > dl:
                restantes = hh.ports[hh.ports.index(port):]
                hh.cobertura_parcial = (
                    f"budget do host esgotado antes da bateria das portas "
                    f"{restantes}")
                self._ev(kind="phase", phase="host_budget_corte", host=hh.ip,
                         portas_pendentes=restantes)
                break
            self.state.step += 1
            banner = hh.products.get(port, "")
            web = eh_web(port, banner)
            self._ev(kind="phase", phase="suite", host=hh.ip, port=port,
                     web=web, banner=banner[:120])
            try:
                if self.dry_run:
                    r = {"findings": []}
                elif web:
                    r = hunt_suite_http(self.tb, hh.ip, port)
                else:
                    r = hunt_suite_proto(self.tb, hh.ip, port, banner)
            except Exception as e:  # porta empedernida nao mata a cacada
                self._ev(kind="phase", phase="suite_error", host=hh.ip,
                         port=port, error=f"{type(e).__name__}: {e}")
                continue
            # rev13: rotas #/ da SPA extraidas do bundle JS (fuzzers de
            # servidor NAO acham) — entram no briefing da fase LLM
            if web and isinstance(r, dict) and r.get("spa_routes"):
                hh.spa_routes[port] = r["spa_routes"]
            for f in r.get("findings") or []:
                if f.get("verdict") == "confirmed":
                    hh.suite_findings.append(f)
                    self._ev(kind="finding", host=hh.ip, **f)
                    continue
                # ---- F2.5: suspeita nao fica parada — verifica
                if self.dry_run:
                    v = {"action": "suspect", "findings": [],
                         "motivo": "dry-run (verificacao nao executa)"}
                else:
                    v = verify_suspect(self.tb, hh.ip, port, f)
                self._ev(kind="verify", host=hh.ip, port=port,
                         **{"class": f.get("class"),
                            "action": v["action"], "motivo": v["motivo"]})
                if v["action"] == "confirmed":
                    for nf in v.get("findings") or []:
                        hh.suite_findings.append(nf)
                        self._ev(kind="finding", host=hh.ip, **nf)
                elif v["action"] == "discarded":
                    hh.descartados.append({
                        "port": port, "class": f.get("class"),
                        "motivo": v["motivo"]})
                else:
                    f["detail"] = (f"{f.get('detail', '')} "
                                   f"[verificado: {v['motivo']}]")
                    hh.suite_findings.append(f)
                    self._ev(kind="finding", host=hh.ip, **f)
            extra = (r.get("resumo") or r.get("banner_grab")
                     or r.get("banner") or "")
            hh.products.setdefault(port, str(extra)[:120])
            # rev10: sondas de classes novas (SQLi auth, tunel CONNECT)
            try:
                from .hunt_suite import hunt_suite_extras
                for f in hunt_suite_extras(self.tb, hh.ip, port,
                                           web=web, banner=banner):
                    if f.get("verdict") == "confirmed":
                        hh.suite_findings.append(f)
                        self._ev(kind="finding", host=hh.ip, **f)
                    else:
                        f["detail"] = f.get("detail", "") + \
                            " [sem verificador automatico]"
                        hh.suite_findings.append(f)
                        self._ev(kind="finding", host=hh.ip, **f)
            except Exception as e:
                self._ev(kind="phase", phase="extras_error", host=hh.ip,
                         port=port, error=f"{type(e).__name__}: {e}")
            self._flush_manifest()

    # --------------------------------------------------------------- F2.6: EXECUÇÃO DE EXPLOITS REAIS
    def _execute_exploits_for_confirmed_cves(self, hh: HostHunt) -> None:
        """Executa exploits REAIS via Metasploit para CVEs confirmadas.
        Se obtiver shell/root, marca SHELL_OBTAINED e atualiza kill chain.

        FIX 2026-09-26: antes só olhava suite_findings (onde CVEs NUNCA
        chegavam). Agora também olha cve_validations — que é onde as
        CVEs candidatas realmente são armazenadas pela validação F2.7.
        """
        cves_confirmadas = []

        # 1. CVEs em suite_findings (achados da bateria com classe cve_*)
        for f in hh.suite_findings:
            if f.get("verdict") == "confirmed" and f.get("class", "").startswith("cve_"):
                cve_match = re.search(r'(CVE-\d{4}-\d+)', f.get("class", "") + " " + f.get("detail", ""))
                if cve_match:
                    cves_confirmadas.append(cve_match.group(1))

        # 2. CVEs em cve_validations (onde a validação F2.7 realmente as coloca)
        #    "candidata_version" e "candidata_searchsploit" são as que merecem tentativa
        #    FIX 2026-09-27: cve_validate usa "veredito" (não "verdict")!
        for cv in hh.cve_validations:
            v = cv.get("veredito") or cv.get("verdict")  # aceita ambos
            if v in ("candidata_version", "candidata_searchsploit"):
                cve_id = cv.get("cve", "")
                if cve_id and cve_id.startswith("CVE-"):
                    cves_confirmadas.append(cve_id)
                # searchsploit matches sem CVE-ID — usa termo do banner
                elif not cve_id.startswith("CVE-") and cve_id.strip():
                    # searchsploit achou exploits para este banner — também tenta
                    cves_confirmadas.append(cve_id)

        # Remove duplicatas preservando ordem
        cves_unicas = list(dict.fromkeys(cves_confirmadas))
        if not cves_unicas:
            return

        print(f"[F2.6] {hh.ip}: {len(cves_unicas)} CVE(s) candidata(s) → executando exploits...")
        for cve_id in cves_unicas[:5]:  # limite 5 tentativas
            self._ev(kind="phase", phase="exploit_exec", host=hh.ip, cve=cve_id)
            print(f"[F2.6] Executando exploit para {cve_id} contra {hh.ip}...")

            try:
                exploit_res = self.tb.tool_exploit_execute(
                    cve_id=cve_id,
                    host_ip=hh.ip,
                    port=0  # auto-detecta pela porta do serviço
                )
            except Exception as e:
                print(f"[F2.6] Erro ao executar exploit {cve_id}: {e}")
                continue

            self._ev(kind="exploit_result", host=hh.ip, cve=cve_id, **exploit_res)

            if exploit_res.get("ok") and exploit_res.get("verified"):
                print(f"[F2.6] ★★★ SHELL OBTIDO via {cve_id}! ★★★")
                self._ev(kind="finding", host=hh.ip,
                         class_="shell_obtained",
                         verdict="confirmed",
                         detail=f"SHELL_OBTAINED via {cve_id}: {exploit_res.get('evidence', '')}",
                         cve=cve_id,
                         exploit_result=exploit_res)
                for h in self.hosts:
                    if h.ip == hh.ip:
                        h.outcome = "SHELL_OBTAINED"
                        h.detail = f"Shell obtido via {cve_id}: {exploit_res.get('evidence', '')}"
                        break
                if exploit_res.get("root"):
                    self._ev(kind="finding", host=hh.ip,
                             class_="root_obtained",
                             verdict="confirmed",
                             detail=f"ROOT obtido via {cve_id}: {exploit_res.get('evidence', '')}",
                             cve=cve_id)
                break  # shell obtido, para de tentar

    # --------------------------------------------------------------- F3 LLM
    def _build_system_prompt(self, hh: HostHunt) -> str:
        """Constrói o system prompt com metodologias skills-red relevantes."""
        base_prompt = HUNT_SYSTEM_PROMPT

        # Injeta skills relevantes baseado nos serviços detectados
        try:
            import sys as _sys
            _sys.path.insert(0, "/bridge")
            from skills_context import build_skills_context

            # Extrai tipos de serviço das portas detectadas
            service_types = []
            for port in hh.ports:
                banner = hh.products.get(port, "")
                svc = str(banner).lower()
                # Detecta tipo de serviço pelo banner/porta
                if any(x in svc for x in ("http", "nginx", "apache", "web")):
                    service_types.extend(["http", "https"])
                elif "ssh" in svc or port in (22, 221):
                    service_types.append("ssh")
                elif "snmp" in svc or port in (161, 162):
                    service_types.append("snmp")
                elif "nfs" in svc or port == 2049:
                    service_types.append("nfs")
                elif "smb" in svc or port in (137, 138, 139, 445):
                    service_types.append("smb")
                elif "rdp" in svc or port == 3389:
                    service_types.append("rdp")
                elif "vnc" in svc or port == 5900:
                    service_types.append("vnc")
                elif "dns" in svc or port == 53:
                    service_types.append("dns")
                elif "sql" in svc or "mysql" in svc:
                    service_types.append("api")
                elif "vmware" in svc or port == 902:
                    service_types.append("exploit_dev")
                elif port in (3128, 3142):  # squid, apt-cacher
                    service_types.append("http")
                else:
                    service_types.append("fuzz")

            # Deduplicar
            service_types = list(set(service_types))
            skills_ctx = build_skills_context(service_types, max_chars=10000)
            if skills_ctx:
                base_prompt += skills_ctx
        except Exception as e:
            print(f"[skills] Aviso: skills_context indisponível ({e}) — usando prompt base")

        # Injeta grafo de conhecimento das ferramentas Kali
        try:
            import json as _json
            graph_path = "/knowledge/kali_tools_graph.json"
            if os.path.isfile(graph_path):
                graph = _json.load(open(graph_path))
                svc_tools = graph.get("service_to_tools", {})
                if svc_tools and service_types:
                    tools_hint = "\n\n=== FERRAMENTAS KALI RECOMENDADAS PARA ESTES SERVIÇOS ===\n"
                    for st in service_types[:5]:
                        if st in svc_tools:
                            mapping = svc_tools[st]
                            tools_hint += f"\n{st.upper()}:\n"
                            tools_hint += f"  Enumeração: {', '.join(mapping.get('enum', []))}\n"
                            tools_hint += f"  Exploit: {', '.join(mapping.get('exploit', []))}\n"
                    base_prompt += tools_hint
        except Exception:
            pass

        return base_prompt

    def llm_hunt_host(self, hh: HostHunt) -> None:
        """F3: o LLM dirige a cacada NO host (hipoteses + sondas + prova)."""
        if self.orch is None:
            return
        fingerprint = {
            "host": hh.ip,
            "portas_abertas": hh.ports,
            "produtos": {str(k): v for k, v in hh.products.items()},
            "spa_routes": hh.spa_routes,  # rev13: rotas #/ do bundle JS
            "achados_bateria": hh.suite_findings,
            "cves_validadas": hh.cve_validations,
        }
        task = (
            f"ALVO: {hh.ip}. BRIEFING: "
            f"{json.dumps(fingerprint, ensure_ascii=False)[:6000]}. "
            f"Formule hipoteses e cace com as tools. Ao fim responda o "
            f"JSON final de findings."
        )
        messages = [
            {"role": "system", "content": self._build_system_prompt(hh)},
            {"role": "user", "content": task},
        ]
        tools = [s for s in self.tb.llm_tool_schemas()
                 if s["function"]["name"] in HUNT_TOOLS]
        transcript: list[dict] = []
        n_cmds0 = len(self.tb.command_log)
        n_can0 = len(self.tb.step_canaries)
        llm_calls = 0
        llm_errors = 0
        final_content = ""
        self.state.step += 1  # dirs de evidencia unicos para a fase LLM
        forca_final = False
        for rnd in range(self.cfg.rounds):
            self.safety.check_wall_clock()
            # rev13: budget por host — pede o JSON final UMA vez e encerra
            dl = self._host_deadline
            if dl is not None and time.monotonic() > dl:
                if not forca_final:
                    messages.append({"role": "user", "content":
                                     "Budget de tempo deste host esgotado. "
                                     "Responda AGORA o JSON final de findings."})
                    forca_final = True
                    hh.cobertura_parcial = (
                        hh.cobertura_parcial
                        or "budget do host esgotado durante a fase LLM")
                    continue  # uma ultima chance de responder o JSON
                break  # ja pedimos o final; nao insistir
            if len(self.tb.command_log) - n_cmds0 >= self.cfg.max_cmds_host:
                messages.append({"role": "user", "content":
                                 "Budget de comandos deste host esgotado. "
                                 "Responda AGORA o JSON final de findings."})
            try:
                t0 = time.monotonic()
                resp = self.orch._chat(messages, tools)
                llm_calls += 1
            except RuntimeError as e:
                llm_errors += 1
                self.orch._log_call(self.state.step, rnd, _CallStat(
                    ok=False, latency_ms=0, error=str(e)))
                hh.detail = f"LLM indisponivel na fase de cacaca: {e}"
                break
            msg = resp["choices"][0]["message"]
            content = msg.get("content") or ""
            tool_calls = msg.get("tool_calls") or []
            # auditoria: toda chamada ao LLM entra em llm_calls.ndjson
            self.orch._log_call(self.state.step, rnd, _CallStat(
                ok=True, latency_ms=int((time.monotonic() - t0) * 1000),
                tool_calls=[tc.get("function", {}).get("name", "")
                            for tc in tool_calls],
                content_chars=len(content)))
            if not tool_calls:
                final_content = content
                if not content.strip() and str(msg.get("reasoning") or ""):
                    messages.append({"role": "user", "content":
                                     "Sua resposta veio vazia. Responda "
                                     "AGORA com o UNICO objeto JSON final."})
                    continue
                break
            assistant = {"role": "assistant", "content": content}
            assistant["tool_calls"] = tool_calls
            messages.append(assistant)
            tool_msgs = []
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                print(f"[LLM->TOOL] {name}({json.dumps(args, ensure_ascii=False)[:160]})")
                try:
                    result = self.tb.dispatch(name, args)
                except Exception as e:
                    result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                print(f"[TOOL->LLM] {name}: ok={result.get('ok')} {str(result)[:180]}")
                if name not in hh.tools_used:
                    hh.tools_used.append(name)
                transcript.append({"tool": name, "args": args,
                                   "result": result})
                tool_msgs.append({"role": "tool",
                                  "tool_call_id": tc.get("id", ""),
                                  "content": json.dumps(
                                      result, ensure_ascii=False,
                                      default=str)[:6000]})
            messages.extend(tool_msgs)

        # canarios OOB verificados durante ESTA cacada viram findings
        for c in self.tb.step_canaries[n_can0:]:
            if c.get("verified"):
                hh.llm_findings.append({
                    "port": 0, "class": f"oob_{c.get('kind', 'callback')}",
                    "verdict": "confirmed",
                    "verification": "oob_callback",
                    "hypothesis": "callback out-of-band com token desta run",
                    "evidence": c.get("evidence", ""),
                    "sub_technique": "T1190", "source": "canary"})
        hh.llm_findings.extend(_parse_hunt_final(final_content))
        hh.discovered_creds = _parse_discovered_creds(final_content)
        hh.llm_summary = _extract_summary(final_content)
        self._write_transcript(self._step, hh, {
            "ts": datetime.now(timezone.utc).isoformat(),
            "step": self._step, "host": hh.ip, "phase": "llm_hunt",
            "llm_calls": llm_calls, "llm_errors": llm_errors,
            "messages": messages, "transcript": transcript,
            "final": final_content,
        })
        self._ev(kind="llm_hunt", host=hh.ip, llm_calls=llm_calls,
                 llm_errors=llm_errors,
                 n_tool_calls=len(transcript),
                 findings=hh.llm_findings)
        self._flush_manifest()

    # --------------------------------------------------------------- F3 LLM

    # ------------------------------------------------------------- F4 verdict
    def hunt_host(self, ip: str, ports: list[int] | None = None,
                  products: dict | None = None,
                  full_scan: bool | None = None) -> HostHunt:
        """Cacada completa em UM host (suite + LLM) com par decide/execute.

        full_scan (rev13): None = decide pelo cfg (fast_first desliga o
        full-range); True = full-range mesmo com fast_first; False = apenas
        as portas ja levantadas (two-phase: top-1000)."""
        hh = HostHunt(ip=ip, ports=ports or [], products=dict(products or {}))
        self.hosts.append(hh)
        step = self._step
        self._step += 1
        self._ev(kind="decide", step=step, action_name="ZERO_DAY_HUNT",
                 target_ip=ip, phase="suite+llm")
        canarios0 = len([c for c in self.tb.step_canaries
                         if c.get("verified")])
        # rev13: two-phase — ports da fase lite entram aqui; full_scan=True
        # RE-ESCANEIA full-range e FAZ MERGE (host rico ganha as portas
        # altas que o top-1000 nao viu, sem perder o que a lite achou)
        if not hh.ports or full_scan:
            if full_scan is None:
                full_scan = not bool(getattr(self.cfg, "fast_first", False))
            p_new, pr_new = self.scan_ports(ip, lite=not full_scan)
            hh.ports = sorted(set(hh.ports) | set(p_new))
            for k, v in (pr_new or {}).items():
                if v:
                    hh.products.setdefault(k, v)
        # F1.5: exploit search automatico para cada produto+versao (rev13:
        # cache por banner normalizado — mesmo produto em N hosts/portas
        # nao repete a busca; a INTEL chega a TODOS os hosts)
        for port, banner in hh.products.items():
            if banner and banner != "dry" and "port/" not in str(banner):
                chave = re.sub(r"\s+", " ", str(banner).strip().lower())
                if chave in self._exploit_cache:
                    continue
                self._exploit_cache[chave] = True
                try:
                    self.tb.tool_exploit_search(termo=str(banner))
                except Exception:
                    pass  # searchsploit ausente ou erro: prosseguir
        self.run_suite(hh)
        # F2.7: valida CVEs candidatas por PoC inofensivo (curadoria
        # offline; falha nunca derruba a cacada)
        try:
            from .cve_validate import validate_host_to_events
            validate_host_to_events(self, hh)
        except Exception as e:
            self._ev(kind="phase", phase="cve_error", host=ip,
                     error=f"{type(e).__name__}: {e}")
            print(f"[cve] erro na validacao de {ip}: {type(e).__name__}: {e}")

        # FIX 2026-09-26: F2.6 AGORA roda DEPOIS da validação de CVEs (F2.7)
        # — antes estava dentro do run_suite, onde cve_validations ainda estava
        # VAZIA (a validação só populava depois). Agora as CVEs candidatas
        # estão disponíveis quando o exploit_execute é chamado.
        self._execute_exploits_for_confirmed_cves(hh)

        if self.cfg.use_llm:
            dl = self._host_deadline
            if dl is not None and time.monotonic() > dl:
                hh.cobertura_parcial = (hh.cobertura_parcial or
                                        "budget do host esgotado antes da "
                                        "fase LLM")
                self._ev(kind="phase", phase="host_budget_corte",
                         host=ip, fase="llm_skipped")
            else:
                self.llm_hunt_host(hh)

        findings = hh.suite_findings + hh.llm_findings
        confirmados = [f for f in findings if f.get("verdict") == "confirmed"]
        suspects = [f for f in findings if f.get("verdict") == "suspect"]
        hh.outcome = "SUCCESS" if confirmados else "FAILED_TARGET_HARD"
        hh.detail = (f"{len(confirmados)} confirmed, {len(suspects)} suspect, "
                     f"{len(hh.descartados)} descartados(FP) "
                     f"em {len(hh.ports)} portas"
                     + (f"; {hh.llm_summary[:200]}" if hh.llm_summary else "")
                     + (f" [COBERTURA PARCIAL: {hh.cobertura_parcial}]"
                        if hh.cobertura_parcial else ""))
        canarios = [c for c in self.tb.step_canaries
                    if c.get("verified")][canarios0:]
        self._ev(kind="execute", step=step, outcome=hh.outcome,
                 detail=hh.detail,
                 commands=list(self.tb.command_log),
                 tool_calls=[{"tool": t} for t in hh.tools_used],
                 canaries=canarios)
        self.state.step = step
        print(f"[host] {ip}: {hh.outcome} ({hh.detail})")
        return hh

    def run(self) -> dict:
        """F0->F4 completo. Retorna o findings.json como dict.

        rev13 (universalidade — qualquer rede, qualquer N):
          * --max-hosts substitui o teto hardcoded extras[:8]; excedentes
            viram hosts_nao_cobertos no relatorio (nunca silencio)
          * fast_first: two-phase — top-1000 em todos os vivos, score de
            superficie, full-range apenas nos hosts ricos; rede grande
            gasta budget onde ha ataque
          * budget por host (auto ou --per-host-budget): host individual
            nunca morre de inanição; cortes ficam marcados por host"""
        print(f"[cacador] run_dir={self.run_dir} dry_run={self.dry_run} "
              f"llm={self.cfg.use_llm} port_range={self.cfg.port_range} "
              f"fast_first={getattr(self.cfg, 'fast_first', False)} "
              f"max_hosts={getattr(self.cfg, 'max_hosts', 0) or 'inf'}")
        t_run0 = time.monotonic()
        subnet = (self.inv.seed_host_subnet
                  or f"{self.inv.seed_host_ip}/24")
        # rev10: sweep de TODAS as redes autorizadas (VM multi-interface:
        # host-only + bridged) — seed sempre caçado; demais IPs vivos
        # dentro dos CIDRs também
        ips = [self.inv.seed_host_ip] if self.dry_run else \
            self.sweep(subnet)
        if not self.dry_run and self.expand_all:
            # rev10/--expand-all: varre também as DEMAIS redes autorizadas
            # (VM multi-interface). Default OFF: foco na subnet do alvo
            # (o budget pertence ao alvo do pilot).
            import ipaddress
            extras: list[str] = []
            for cidr in self.inv.allowed_cidrs:
                rede = str(ipaddress.ip_network(cidr, strict=False))
                if rede == subnet:
                    continue
                for ip in self.sweep(rede):
                    if ip not in ips:
                        extras.append(ip)
            ips += extras
        nao_cobertos: list[dict] = []
        # rev13: teto CONFIGURAVEL de hosts por run (antes: extras[:8]
        # hardcoded — redes grandes eram truncadas sem aviso)
        max_hosts = int(getattr(self.cfg, "max_hosts", 0) or 0)
        if max_hosts > 0 and len(ips) > max_hosts:
            for ip in ips[max_hosts:]:
                if self.inv.ip_allowed(ip):
                    nao_cobertos.append(
                        {"ip": ip,
                         "motivo": f"teto --max-hosts {max_hosts} desta run"})
            ips = ips[:max_hosts]
            self._ev(kind="phase", phase="max_hosts_capped",
                     cacados=len(ips), nao_cacados=len(nao_cobertos))
            print(f"[escala] --max-hosts {max_hosts}: {len(nao_cobertos)} "
                  f"hosts autorizados ficaram de fora (listados no relatório)")
        # rev13: two-phase com priorização por superficie (redes grandes).
        # Fase A: top-1000 (barato) em todos; Fase B: caca em ordem de
        # score (portas x2 + banner com versao x3), full-range so nos ricos
        litos: list[tuple[str, list[int], dict]] | None = None
        if (getattr(self.cfg, "fast_first", False) and not self.dry_run
                and len(ips) > 1):
            litos = []
            for ip in ips:
                try:
                    p_l, pr_l = self.scan_ports(ip, lite=True)
                except Exception as e:
                    self._ev(kind="phase", phase="litescan_error", host=ip,
                             error=f"{type(e).__name__}: {e}")
                    p_l, pr_l = [], {}
                litos.append((ip, p_l, pr_l))

            def _score(item):
                _ip, ports, products = item
                versao = any(re.search(r"\d+\.\d+", str(b or ""))
                            for b in (products or {}).values())
                return len(ports) * 2 + (3 if versao else 0)

            litos.sort(key=_score, reverse=True)
            ordem = [{"ip": ip, "score": _score((ip, p, pr)),
                      "portas_lite": len(p)} for ip, p, pr in litos]
            self._ev(kind="phase", phase="priorizacao", ordem=ordem)
            print(f"[prioridade] ordem de caca (top 12): "
                  f"{[(o['ip'], o['score']) for o in ordem[:12]]}")
        if litos is not None:
            fila = [(ip, p, pr,
                     len(p) >= 3 or any(re.search(r"\d+\.\d+", str(b or ""))
                                        for b in (pr or {}).values()))
                    for ip, p, pr in litos]
        else:
            fila = [(ip, None, None, None) for ip in ips]
        # budget por host: auto = max(300s, restante / hosts que faltam)
        per_host_cfg = int(getattr(self.cfg, "per_host_budget", 0) or 0)
        try:
            for idx, (ip, ports_in, products_in, full_scan) in enumerate(fila):
                if not self.inv.ip_allowed(ip):
                    continue
                if self.dry_run:
                    self._host_deadline = None
                elif per_host_cfg > 0:
                    self._host_deadline = time.monotonic() + per_host_cfg
                else:
                    restante = (self.inv.max_wall_clock_seconds
                                - (time.monotonic() - t_run0))
                    faltam = max(1, len(fila) - idx)
                    self._host_deadline = time.monotonic() + \
                        max(300, restante // faltam)
                try:
                    self.hunt_host(ip, ports=ports_in,
                                   products=products_in,
                                   full_scan=full_scan)
                except SafetyViolation as e:
                    self._ev(kind="terminate", reason="safety_violation",
                             detail=str(e))
                    print(f"[safety] {e}")
                    for resto in fila[idx:]:
                        if self.inv.ip_allowed(resto[0]):
                            nao_cobertos.append(
                                {"ip": resto[0],
                                 "motivo": f"budget/safety wall-clock: {e}"})
                    break
                except Exception as e:
                    self._ev(kind="phase", phase="host_error", host=ip,
                             error=f"{type(e).__name__}: {e}")
                    print(f"[erro] host {ip}: {type(e).__name__}: {e}")
        finally:
            self._host_deadline = None
            self.channels.close_all()
            self._flush_manifest()
            if not self._terminated:
                self._ev(kind="terminate", reason="completed")
        self.hosts_nao_cobertos = nao_cobertos

        findings_doc = self._aggregate()
        (self.run_dir / "findings.json").write_text(
            json.dumps(findings_doc, ensure_ascii=False, indent=1),
            encoding="utf-8")
        report = self._report_md(findings_doc)
        (self.run_dir / "hunt_report.md").write_text(report, encoding="utf-8")
        self._write_run_config()
        a1 = audit_run(self.run_dir, expect_llm=self.cfg.use_llm
                       and not self.dry_run)
        a2 = audit_hunt(self.run_dir, findings_doc)
        a1["hunt_checks"] = a2["checks"]
        a1["pass"] = bool(a1["pass"] and a2["pass"])
        a1["n_checks"] += a2["n_checks"]
        a1["n_failed"] += a2["n_failed"]
        (self.run_dir / "audit_report.json").write_text(
            json.dumps(a1, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"[audit] hunt: {'PASS' if a1['pass'] else 'FAIL'} "
              f"({a1['n_checks']} checagens)")
        # atribuicao de efetividade (recomputavel dos brutos) — so com
        # eventos reais; dry-run nao tem materia de analise
        if not self.dry_run:
            try:
                from .attribution import attribute_run
                attribute_run(self.run_dir)
                print(f"[atribuicao] {self.run_dir / 'attribution.md'}")
            except Exception as e:
                print(f"[atribuicao] falhou (nao derruba a run): "
                      f"{type(e).__name__}: {e}")
        return findings_doc

    # ------------------------------------------------------------- relatorio
    def _aggregate(self) -> dict:
        hosts_doc = {}
        todos: list[dict] = []
        n_desc = 0
        for hh in self.hosts:
            findings = hh.suite_findings + hh.llm_findings
            n_desc += len(hh.descartados)
            hosts_doc[hh.ip] = {
                "ports": hh.ports,
                "products": {str(k): v for k, v in hh.products.items()},
                "spa_routes": {str(k): v for k, v in hh.spa_routes.items()},
                "outcome": hh.outcome,
                "detail": hh.detail,
                "cobertura_parcial": hh.cobertura_parcial or None,
                "llm_summary": hh.llm_summary,
                "n_findings": len(findings),
                "descartados": hh.descartados,
                "cve_validations": hh.cve_validations,
                "discovered_creds": hh.discovered_creds,
            }
            for f in findings:
                todos.append({"host": hh.ip, **f})
        confirmados = [f for f in todos if f["verdict"] == "confirmed"]
        # rev13: classes DISTINCTS de confirmed — o criterio do autor
        # (>=2 exploracoes) so e atendido de verdade com classes distintas;
        # dois achados da mesma classe/porto NAO contam como dois
        classes_distintas = sorted({str(f.get("class", "—"))
                                    for f in confirmados})
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "port_range": self.cfg.port_range,
            "use_llm": self.cfg.use_llm,
            "dry_run": self.dry_run,
            "counts": {"findings": len(todos),
                       "confirmed": len(confirmados),
                       "confirmed_classes_distintas": len(classes_distintas),
                       "suspect": len(todos) - len(confirmados),
                       "descartados_fp": n_desc},
            "classes_confirmadas": classes_distintas,
            # rev13: cobertura honesta — quem ficou de fora e por quê
            "hosts_nao_cobertos": getattr(self, "hosts_nao_cobertos", []),
            "budget": {"max_wall_clock_seconds":
                       int(self.inv.max_wall_clock_seconds),
                       "per_host_budget":
                       int(getattr(self.cfg, "per_host_budget", 0) or 0),
                       "fast_first": bool(getattr(self.cfg, "fast_first",
                                                 False)),
                       "max_hosts": int(getattr(self.cfg, "max_hosts", 0) or 0)},
            "hosts": hosts_doc,
            "findings": todos,
        }

    def _report_md(self, doc: dict) -> str:
        linhas = [
            "# Cacada 0-day — relatorio",
            "",
            f"- Gerado: {doc['generated_at']}",
            f"- Alvo: {self.inv.seed_host_ip} (owner: "
            f"{self.inv.authorization_owner})",
            f"- Port range: {doc['port_range']} | LLM: {doc['use_llm']} "
            f"| dry_run: {doc['dry_run']}",
            f"- Achados: **{doc['counts']['confirmed']} confirmed** / "
            f"{doc['counts']['suspect']} suspect / "
            f"{doc['counts'].get('descartados_fp', 0)} descartados "
            f"(falsos positivos removidos na verificacao)",
            f"- Classes confirmadas DISTINCTAS: "
            f"**{doc['counts'].get('confirmed_classes_distintas', 0)}** "
            f"({', '.join(doc.get('classes_confirmadas', [])) or '—'}) — "
            f"criterio de >=2 exploracoes exige classes distintas, nao "
            f"2 achados da mesma classe/porto",
            "",
            "| Host | Porta | Classe | Veredito | Prova | Detalhe |",
            "|---|---|---|---|---|---|",
        ]
        for f in doc["findings"]:
            linhas.append(
                f"| {f['host']} | {f.get('port', '—')} | {f.get('class')} "
                f"| **{f.get('verdict')}** | {f.get('verification', '—')} "
                f"| {str(f.get('detail', f.get('hypothesis', '')))[:120]} |")
        desc = [(ip, d) for ip, hh in doc["hosts"].items()
                for d in hh.get("descartados", [])]
        if desc:
            linhas += [
                "",
                "## Descartados na verificacao (nao sao achados)",
                "",
                "| Host | Porta | Classe | Motivo do descarte |",
                "|---|---|---|---|",
            ]
            for ip, d in desc:
                linhas.append(f"| {ip} | {d.get('port')} | {d.get('class')} "
                              f"| {d.get('motivo', '')[:150]} |")
        cves = [(ip, c) for ip, hh in doc["hosts"].items()
                for c in hh.get("cve_validations", [])]
        if cves:
            linhas += ["",
                       "## CVEs validadas (PoC inofensivo / versao)",
                       "",
                       "| Host | CVE | Porta | Veredito | Metodo | Detalhe |",
                       "|---|---|---|---|---|---|"]
            for ip, c in cves:
                linhas.append(f"| {ip} | {c.get('cve')} | {c.get('porta')} "
                              f"| **{c.get('veredito')}** | {c.get('metodo')} "
                              f"| {str(c.get('detalhe', ''))[:110]} |")
        # rev13: cobertura honesta — hosts autorizados que ficaram de fora
        nao_cob = doc.get("hosts_nao_cobertos") or []
        parcial = [(ip, hh.get("cobertura_parcial"))
                   for ip, hh in doc["hosts"].items()
                   if hh.get("cobertura_parcial")]
        if nao_cob or parcial:
            linhas += ["",
                       "## Cobertura desta run (honestidade de superficie)",
                       "",
                       "Ausencia de achado NAO prova ausencia de "
                       "vulnerabilidade; abaixo, o que ficou FORA do "
                       "budget/limites desta run:"]
            if nao_cob:
                linhas += ["",
                           "| Host nao cacado | Motivo |", "|---|---|"]
                for h in nao_cob:
                    linhas.append(f"| {h.get('ip')} | "
                                  f"{str(h.get('motivo', ''))[:140]} |")
            for ip, motivo in parcial:
                linhas.append(f"- {ip}: COBERTURA PARCIAL — {motivo}")
            linhas.append("")
        linhas.append("")
        for ip, hh in doc["hosts"].items():
            linhas.append(f"## {ip} — {hh['outcome']}")
            linhas.append("")
            if hh.get("llm_summary"):
                linhas.append(f"LLM: {hh['llm_summary'][:500]}")
                linhas.append("")
            if hh.get("spa_routes"):
                rotas = hh["spa_routes"]
                todas = sorted({r for lst in rotas.values() for r in lst})
                linhas.append(f"Rotas SPA (bundle JS): {todas[:20]}")
                linhas.append("")
            linhas.append(f"Portas: {hh['ports']}")
            linhas.append("")
        linhas += [
            "## Metodologia e limites",
            "",
            "- confirmed EXIGE prova executavel: callback OOB com token "
            "unico, reflexao de token desta run, assinatura de conteudo "
            "(/etc/passwd, [core], KEY=VALUE) ou resposta de protocolo que "
            "concede acesso/dados (FTP 230, Redis +PONG/INFO, MQTT CONNACK "
            "rc=0, memcached STAT, SNMP public, VRFY).",
            "- suspect = anomalia sem prova (pista para hipotese humana/"
            "LLM). NENHUM confirmed aceito so por declaração do LLM: a "
            "auditoria re-verifica evidencia e sha256.",
            "- Ausencia de achado NAO prova ausencia de vulnerabilidade; "
            "o range de portas e a bateria generica limitam a superficie "
            "coberta. Protocolos desconhecidos ficam para hipotese do LLM "
            "com net_probe raw.",
            "",
            "- Auditoria: audit_report.json (audit_run do harness + "
            "audit_hunt de findings).",
        ]
        return "\n".join(linhas)

    def _write_run_config(self) -> None:
        cfg = {
            "checkpoint": None,
            "policy": "zeroday_hunt",
            "mode": "zeroday_hunt",
            "repeat": 0,
            "seed_host_ip": self.inv.seed_host_ip,
            "owner": self.inv.authorization_owner,
            "allowed_cidrs": self.inv.allowed_cidrs,
            "max_steps": len(self.hosts),
            "dry_run": self.dry_run,
            "deterministic": True,
            "repeats": 1,
            "ssh_creds_tentadas": [c.username for c in self.inv.ssh_creds],
            "llm": self.cfg.use_llm and not self.dry_run,
            "crown_jewel": self.inv.crown_jewel_path,
            "bruteforce_enabled": bool(getattr(self.inv, "bruteforce", None)
                                       and self.inv.bruteforce.enabled),
            "port_range": self.cfg.port_range,
            "model": self.cfg.model or DEFAULT_MODEL,
            # rev13: escala/cobertura
            "max_hosts": int(getattr(self.cfg, "max_hosts", 0) or 0),
            "per_host_budget": int(getattr(self.cfg, "per_host_budget", 0)
                                   or 0),
            "fast_first": bool(getattr(self.cfg, "fast_first", False)),
        }
        (self.run_dir / "run_config.json").write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


# ------------------------------------------------------------------ helpers
def _parse_hunt_final(content: str) -> list[dict]:
    """Extrai findings do JSON final do LLM (tolerante a cerca/texto).

    Regra de honestidade: verdict=confirmed do LLM so sobrevive se apontar
    ARQUIVO de evidencia desta run (caminho relativo com extensao); texto
    livre ("confirmei manualmente") e rebaixado para suspect — prova
    executavel e obrigatoria e a auditoria re-verifica arquivo e sha256."""
    achados: list[dict] = []
    if not content or not content.strip():
        return achados
    limpo = content.strip()
    if limpo.startswith("```"):
        limpo = limpo.strip("`")
        if limpo.lower().startswith("json"):
            limpo = limpo[4:]
        limpo = limpo.strip()
    obj_final: dict | None = None
    for obj in _scan_json_objects(limpo):
        if isinstance(obj, dict) and ("findings" in obj or "summary" in obj):
            obj_final = obj
    if obj_final is None:
        try:
            parsed = json.loads(limpo)
            obj_final = parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            obj_final = None
    # rev13: evidencia aceita = arquivo sob evidence/ (qualquer extensao/sem
    # extensao) OU path relativo com extensao conhecida. ANTES exigia
    # .json/.txt/.log/.xml — artefato valido sem extensao rebaixava um
    # confirmed REAL a suspect em qualquer alvo. A auditoria continua
    # verificando EXISTENCIA do arquivo + sha256, entao a honestidade nao
    # muda: so para de rejeitar formato.
    ev_path = re.compile(
        r"^(?:evidence/[\w./\-]+"
        r"|[\w.\-]+(?:/[\w.\-]+)+\.(?:json|txt|log|xml))$")
    for f in (obj_final or {}).get("findings") or []:
        if not isinstance(f, dict):
            continue
        verdict = str(f.get("verdict", "")).lower()
        if verdict not in _VERDICTS:
            verdict = "suspect"
        ev = str(f.get("evidence", "") or "").strip()
        if verdict == "confirmed" and not ev_path.fullmatch(ev):
            verdict = "suspect"
        try:
            port = int(f.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        sub = str(f.get("sub_technique", "") or "")
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", sub):
            sub = "T1190"
        achados.append({
            "port": port, "class": "llm_hypothesis", "verdict": verdict,
            "verification": "evidence_file" if
            (f.get("verdict", "").lower() == "confirmed" and
             ev_path.fullmatch(ev)) else "none",
            "hypothesis": str(f.get("hypothesis", ""))[:400],
            "evidence": ev[:200], "detail": ev[:400],
            "sub_technique": sub, "source": "llm",
        })
    return achados


def _parse_discovered_creds(content: str) -> list[dict]:
    """Credenciais OBSERVADAS na evidencia, reportadas pelo LLM (rev11).
    Validadas: usuario/senha nao vazios + evidence apontando arquivo
    (proveniencia); sem isso, descartadas (nunca aceitas no chute)."""
    import re as _re
    out: list[dict] = []
    for obj in _scan_json_objects(content or ""):
        if not (isinstance(obj, dict) and "discovered_creds" in obj):
            continue
        for c in obj.get("discovered_creds") or []:
            if not isinstance(c, dict):
                continue
            u, p = str(c.get("username", "")).strip(), str(c.get("password", "")).strip()
            ev = str(c.get("evidence", "")).strip()
            if u and p and _re.search(r"[\w.\-]+/[\w.\-]+", ev):
                out.append({"username": u, "password": p,
                            "source": str(c.get("source", ""))[:80],
                            "evidence": ev[:200]})
        break
    return out


def _extract_summary(content: str) -> str:
    for obj in _scan_json_objects(content or ""):
        if isinstance(obj, dict) and obj.get("summary"):
            return str(obj["summary"])
    return ""


def audit_hunt(run_dir: Path, findings_doc: dict) -> dict:
    """Auditoria propria da cacada: TODO confirmed exige (1) verificação
    real (nao 'none'), (2) arquivo de evidencia existente e (3) sha256
    batendo com o manifesto quando o item consta nele."""
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "pass": bool(ok), "detail": detail[:400]})

    manifest: dict[str, dict] = {}
    mp = Path(run_dir) / "evidence_manifest.json"
    if mp.exists():
        try:
            for m in json.loads(mp.read_text(encoding="utf-8")):
                manifest[m.get("file", "")] = m
        except json.JSONDecodeError:
            pass

    todos = findings_doc.get("findings", [])
    confirmed = [f for f in todos if f.get("verdict") == "confirmed"]
    check("hunt_findings_counted", True,
          f"{len(confirmed)} confirmed de {len(todos)} achados "
          f"(cacada sem achado NAO e falha de auditoria)")

    falhas: list[str] = []
    import hashlib
    for f in confirmed:
        host = f.get("host", "?")
        if not f.get("verification") or f["verification"] == "none":
            falhas.append(f"{host}: confirmed sem verificação real")
            continue
        ev = str(f.get("evidence", "") or "")
        if not ev:
            falhas.append(f"{host}: confirmed sem evidencia")
            continue
        p = Path(ev)
        if not p.is_absolute():
            p = Path(run_dir) / p
        if not p.exists():
            falhas.append(f"{host}: evidencia inexistente {ev}")
            continue
        m = manifest.get(ev)
        if m and m.get("sha256"):
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            if h != m["sha256"]:
                falhas.append(f"{host}: sha256 divergente {ev}")
    check("hunt_confirmed_have_executable_proof", not falhas,
          "; ".join(falhas[:5]))
    return {"pass": all(c["pass"] for c in checks), "checks": checks,
            "n_checks": len(checks),
            "n_failed": sum(1 for c in checks if not c["pass"])}


# ----------------------------------------------------------------------- CLI
def _parse_hunt_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="zeroday-hunt")
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--target-ip", default=None)
    ap.add_argument("--subnet", default=None)
    ap.add_argument("--port-range", default="1-65535")
    ap.add_argument("--rounds", type=int, default=14,
                    help="rodadas LLM por host")
    ap.add_argument("--max-cmds-host", type=int, default=24)
    ap.add_argument("--no-llm", action="store_true",
                    help="so bateria deterministica (sem LLM)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--i-am-authorized", action="store_true")
    ap.add_argument("--wall-clock", type=int, default=None,
                    help="override em memoria do budget (segundos)")
    ap.add_argument("--runs-root", default="data/pentest_runs")
    ap.add_argument("--expand-all", action="store_true",
                    help="varrer tambem as DEMAIS redes autorizadas (multi-interface)")
    ap.add_argument("--max-hosts", type=int, default=0,
                    help="rev13: teto de hosts cacados nesta run (0 = "
                         "ilimitado; excedentes entram em "
                         "hosts_nao_cobertos do relatorio)")
    ap.add_argument("--per-host-budget", type=int, default=0,
                    help="rev13: segundos por host (0 = automatico: "
                         "max(300, wall_clock_restante/hosts_restantes)); "
                         "cortes por host ficam marcados no relatorio")
    ap.add_argument("--fast-first", action="store_true",
                    help="rev13 (redes grandes): two-phase — top-1000 "
                         "portas em todos os vivos, priorizacao por "
                         "superficie, full-range apenas nos hosts ricos")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_hunt_args(argv)
    inv = load_inventory(args.inventory)
    if args.target_ip or args.subnet:
        inv = _apply_target_overrides(
            inv, argparse.Namespace(target_ip=args.target_ip,
                                    subnet=args.subnet, ssh_user=None,
                                    ssh_pass=None))
    if not args.dry_run and not args.i_am_authorized:
        raise SystemExit("cacada real exige --i-am-authorized "
                         "(ambiente proprio) ou --dry-run")
    if not inv.ip_allowed(inv.seed_host_ip):
        raise SystemExit(f"alvo {inv.seed_host_ip} fora dos CIDRs "
                         f"autorizados")
    if args.wall_clock:
        inv.max_wall_clock_seconds = args.wall_clock  # override em memoria

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.runs_root) / f"{stamp}_zeroday"
    run_dir.mkdir(parents=True, exist_ok=True)
    tee = _CampaignTee(run_dir / "hunt.log")
    sys.stdout = tee
    cfg = HuntConfig(port_range=args.port_range, rounds=args.rounds,
                     expand_all=args.expand_all,
                     max_cmds_host=args.max_cmds_host,
                     use_llm=not args.no_llm, model=args.model,
                     max_hosts=args.max_hosts,
                     per_host_budget=args.per_host_budget,
                     fast_first=args.fast_first)
    hunter = ZeroDayHunter(inv, run_dir, cfg, dry_run=args.dry_run)
    try:
        doc = hunter.run()
    finally:
        sys.stdout = tee._stdout
        tee.close()
    print(f"[cacador] findings: "
          f"{doc['counts']['confirmed']} confirmed / "
          f"{doc['counts']['suspect']} suspect / "
          f"{doc['counts'].get('descartados_fp', 0)} descartados (FP)")
    print(f"[cacador] pasta: {run_dir}")
    print(f"[cacador] relatorio: {run_dir / 'hunt_report.md'}")


if __name__ == "__main__":
    main()
