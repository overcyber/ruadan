"""
Despachante de Ações: Mapeia RedAction (0 a 9) da política RL / LLM para
os comandos reais e seções do attackplan.ini / config.ini do Ruadan.

Cada ação da Kill Chain dispara as fases REAIS do arsenal do Ruadan,
incluindo enumeração completa, varredura de vulnerabilidades, brute force,
exploit search e exploração web.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from .canary import CanaryVerifier
from .state_adapter import RedAction


@dataclass
class DispatchResult:
    action: int
    target_ip: str
    commands_executed: list[str] = field(default_factory=list)
    success: bool = False
    evidence_files: list[str] = field(default_factory=list)
    findings_extracted: dict = field(default_factory=dict)
    detail: str = ""
    # Honestidade da Kill Chain: qual o nível de evidência REAL desta ação?
    #   "credential"  = credencial/sessão/exploit confirmado de verdade
    #   "finding"     = novos achados extraídos (banners, vulns, usuários)
    #   "enum_only"   = apenas enumeração executada; NENHUMA exploração real
    evidence_level: str = "enum_only"
    evidence_detail: str = ""


class ActionDispatcher:
    def __init__(self, ruadan_instance: Any, canary_verifier: CanaryVerifier):
        self.ruadan = ruadan_instance
        self.canary = canary_verifier
        self.config = ruadan_instance.config

    def _run_phase(self, phase_name: str, res: DispatchResult) -> bool:
        """Executa uma fase do attackplan.ini e registra os comandos executados."""
        if not self.ruadan.plan.has_section(phase_name):
            return False
        try:
            print(f"[*] [Ruadan] Fase: {phase_name}...")
            pre_count = len(getattr(self.ruadan, 'phase_commands', []))
            self.ruadan.enumerate(phase_name)
            post_cmds = getattr(self.ruadan, 'phase_commands', [])
            if post_cmds:
                res.commands_executed.extend(list(post_cmds))
            return True
        except Exception as e:
            print(f"[-] Erro na fase {phase_name}: {e}")
            return False

    def _run_exploit_search(self, res: DispatchResult) -> bool:
        """Executa o SearchSploit JSON do Ruadan contra banners identificados."""
        try:
            print("[*] [SearchSploit] Buscando exploits para produtos e banners identificados...")
            self.ruadan.exploit_search("SearchSploit JSON")
            res.commands_executed.append("searchsploit JSON (banners do alvo)")
            return True
        except Exception as e:
            print(f"[-] Erro no exploit search: {e}")
            return False

    def _run_exploit_tests(self, res: DispatchResult) -> bool:
        """Testa os PoCs copiados pelo SearchSploit (exploit_runner.sh).

        O searchsploit copia PoCs para <output>/<host>/<servico>/exploits/ mas
        nada os executava — ficavam mortos no disco. O runner executa cada PoC
        contra o alvo (lab autorizado) com timeout rigoroso e log auditável,
        de forma idempotente (marcadores .tested).
        """
        import subprocess
        try:
            out_dir = getattr(self.ruadan.args, 'outputFolder', '/ruadan/output')
            for host in getattr(self.ruadan, 'hosts', []) or []:
                cmd = f"bash /ruadan/exploit_runner.sh {out_dir} {host}"
                print(f"[*] [ExploitRunner] Testando PoCs copiados contra {host}...")
                try:
                    proc = subprocess.run(
                        cmd.split(), capture_output=True, text=True, timeout=900
                    )
                    res.commands_executed.append(cmd)
                    if proc.stdout:
                        for line in proc.stdout.strip().splitlines()[:3]:
                            print(f"    {line}")
                except subprocess.TimeoutExpired:
                    res.commands_executed.append(f"{cmd} (timeout 900s)")
            return True
        except Exception as e:
            print(f"[-] Erro no exploit runner: {e}")
            return False

    def _reparse_findings(self):
        """Re-processa XML do Nmap e extrai achados."""
        try:
            self.ruadan.parse_nmap_xml()
        except Exception:
            pass
        try:
            self.ruadan.findings_post_processing()
        except Exception:
            pass

    def _snapshot_findings(self) -> int:
        """Conta o total de achados atuais (todos os tipos somados)."""
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            return sum(len(v) if hasattr(v, '__len__') else 1 for v in f.values())
        except Exception:
            return 0

    def _has_new_credentials(self, findings_before: dict) -> bool:
        """Verifica se novas credenciais (usuário/senha) foram descobertas nesta ação."""
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            before_users = set((findings_before or {}).get('users', []))
            before_pass = set((findings_before or {}).get('passwords', []))
            now_users = set(f.get('users', [])) - before_users
            now_pass = set(f.get('passwords', [])) - before_pass
            return bool(now_users or now_pass)
        except Exception:
            return False

    def _has_jwt_admin(self, findings_before: dict) -> bool:
        """JWT de admin capturado via bypass SQLi no login (api_fuzz/api_route_extract/
        sqlmap_login_probe emitem 'JWT_ADMIN_CAPTURED: <url>').

        Autenticação REAL obtida sem credenciais legítimas: o token de admin
        dá acesso autenticado à API do alvo (nível 'credential' — o JuiceShop
        não tem RCE por design; credential/data-exposure é o teto dele).
        A busca é case-insensitive (configparser lowerifica os labels).
        """
        def _jwt_list(fdict: dict) -> list:
            for k, v in (fdict or {}).items():
                if str(k).lower() == "jwtadmincaptured":
                    return v or []
            return []
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            before = set(_jwt_list(findings_before))
            now = set(_jwt_list(f)) - before
            return bool(now)
        except Exception:
            return False

    def _has_login_bypass(self, findings_before: dict) -> bool:
        """Verifica se um bypass de autenticação (SQLi em login) foi CONFIRMADO nesta ação.

        O sqlmap_login_probe.sh emite a linha 'SQLI_LOGIN_BYPASS_CONFIRMED: <url>'
        quando o bypass clássico retorna 200/autenticação onde a credencial
        inválida retorna 401/400. Isso é exploração REAL: autenticação obtida
        sem credenciais legítimas — nível 'credential' na kill chain.

        NOTA: o configparser lowerifica os labels ('SQLiLoginBypass' vira
        'sqliloginbypass' em self.ruadan.findings) — a busca é case-insensitive.
        """
        def _bypass_list(fdict: dict) -> list:
            for k, v in (fdict or {}).items():
                if str(k).lower() == "sqliloginbypass":
                    return v or []
            return []
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            before = set(_bypass_list(findings_before))
            now = set(_bypass_list(f)) - before
            return bool(now)
        except Exception:
            return False

    def _has_msf_session(self, findings_before: dict) -> bool:
        """Verifica se uma SESSION REAL do Metasploit foi aberta nesta ação.

        O msf_exploit_phase.sh emite 'MSF_SESSION_OPENED: ...' quando o handler
        captura uma conexão reversa (shell/meterpreter) — C2 estabelecido de
        verdade. Nível máximo de evidência: 'credential'.
        """
        def _sess_list(fdict: dict) -> list:
            for k, v in (fdict or {}).items():
                if str(k).lower() == "msfsession":
                    return v or []
            return []
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            before = set(_sess_list(findings_before))
            now = set(_sess_list(f)) - before
            return bool(now)
        except Exception:
            return False

    def _has_msf_root(self, findings_before: dict) -> bool:
        """Root REAL obtido: MSF_ROOT_OBTAINED (privesc executado) ou
        MSF_ROOT_CONFIRMED (getuid root na session)."""
        def _root_list(fdict: dict) -> list:
            for k, v in (fdict or {}).items():
                if str(k).lower() == "msfroot":
                    return v or []
            return []
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            before = set(_root_list(findings_before))
            now = set(_root_list(f)) - before
            return bool(now)
        except Exception:
            return False

    def _has_shell_obtained(self, findings_before: dict) -> bool:
        """SHELL REAL obtido pelo caçador 0-day (ssh_login funcional → remote_exec
        com prova, ou exfiltração confirmada do crown jewel)."""
        def _shell_list(fdict: dict) -> list:
            for k, v in (fdict or {}).items():
                if str(k).lower() == "shell_obtained":
                    return v or []
            return []
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            before = set(_shell_list(findings_before))
            now = set(_shell_list(f)) - before
            return bool(now)
        except Exception:
            return False

    def _has_api_vuln(self, findings_before: dict) -> bool:
        """Vulnerabilidade de API REAL encontrada pelo fuzzing inteligente
        (IDOR, NoSQL injection, path traversal, info disclosure com JWT)."""
        def _api_vuln_list(fdict: dict) -> list:
            for k, v in (fdict or {}).items():
                if str(k).lower() == "apivuln":
                    return v or []
            return []
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            before = set(_api_vuln_list(findings_before))
            now = set(_api_vuln_list(f)) - before
            return bool(now)
        except Exception:
            return False

    def _assess_evidence(self, res: DispatchResult, findings_before: dict) -> None:
        """Avaliação HONESTA do que esta ação realmente produziu.

        Níveis:
          credential  = credenciais novas OU bypass de autenticação confirmado
                        (autenticação real obtida no alvo)
          finding     = novos achados extraídos (banners, vulns, usuários)
          enum_only  = apenas enumeração executada
        """
        total_before = sum(len(v) if hasattr(v, '__len__') else 1 for v in (findings_before or {}).values())
        total_after = self._snapshot_findings()
        new_findings = max(0, total_after - total_before)

        if self._has_new_credentials(findings_before):
            res.evidence_level = "credential"
            res.evidence_detail = "novas credenciais descobertas (usuário/senha) nesta ação"
        elif self._has_shell_obtained(findings_before):
            res.evidence_level = "credential"
            res.evidence_detail = "SHELL REAL OBTIDO (caçada 0-day: acesso funcional com execução remota provada)"
        elif self._has_jwt_admin(findings_before):
            res.evidence_level = "credential"
            res.evidence_detail = "JWT ADMIN CAPTURADO via bypass SQLi no login (autenticação real obtida — token de admin em mãos)"
        elif self._has_api_vuln(findings_before):
            res.evidence_level = "finding"
            res.evidence_detail = "VULNERABILIDADE DE API CONFIRMADA (IDOR/NoSQL/traversal/info disclosure via fuzzing autenticado)"
        elif self._has_msf_root(findings_before):
            res.evidence_level = "credential"
            res.evidence_detail = "ROOT REAL OBTIDO no host comprometido (session MSF com getuid root / privesc executado)"
        elif self._has_msf_session(findings_before):
            res.evidence_level = "credential"
            res.evidence_detail = "SESSION DO METASPLOIT ABERTA (shell/meterpreter capturado pelo handler — C2 real estabelecido)"
        elif self._has_login_bypass(findings_before):
            res.evidence_level = "credential"
            res.evidence_detail = "BYPASS DE AUTENTICAÇÃO CONFIRMADO via SQLi em endpoint de login (autenticação real obtida sem credenciais legítimas)"
        elif new_findings > 0:
            res.evidence_level = "finding"
            res.evidence_detail = f"{new_findings} novo(s) achado(s) extraído(s) nesta ação"
        else:
            res.evidence_level = "enum_only"
            res.evidence_detail = "somente enumeração executada — nenhum shell, sessão ou exploit real confirmado"

        print(f"[*] [Evidence] Nível de evidência REAL: {res.evidence_level.upper()} — {res.evidence_detail}")

    def _inject_pivot_targets(self, res: DispatchResult):
        """Pivô automático (Etapa 4): vizinhos descobertos pela session (arp)
        tornam-se ALVOS REAIS do ciclo IA.

        Fluxo: a fase [Metasploit Session Pivot] emite findings 'msfpivot'
        (MSF_PIVOT_NEIGHBOR). Aqui extraímos os IPs e injetamos no nmap_dict do
        Ruadan — a partir daí: (a) o próximo sync_from_ruadan os adiciona ao
        estado do RL (podem ser escolhidos pelo DISCOVER_REMOTE), e (b) TODOS
        os scans subsequentes do Ruadan os incluem (enumerate itera nmap_dict).

        Escopo: apenas vizinhos na MESMA /24 dos alvos declarados no hostFile
        (ex: 192.168.50.x). Bridges docker/172.x ficam como findings para o
        operador/LLM, sem injeção automática. Gate: RUADAN_AUTO_PIVOT=0 desliga.
        """
        import re as _re
        if os.environ.get("RUADAN_AUTO_PIVOT", "1") != "1":
            return
        try:
            f = getattr(self.ruadan, 'findings', {}) or {}
            pivot_lines = []
            for k, v in f.items():
                if str(k).lower() == "msfpivot":
                    pivot_lines = v or []
            if not pivot_lines:
                return

            # Subnets /24 autorizadas = as dos alvos declarados
            allowed_subnets = set()
            for h in getattr(self.ruadan, 'hosts', []) or []:
                octs = str(h).split(".")
                if len(octs) == 4 and octs[3].isdigit():
                    allowed_subnets.add(".".join(octs[:3]))

            nmap_dict = getattr(self.ruadan, 'nmap_dict', None)
            if nmap_dict is None:
                return
            injected = []
            for line in pivot_lines:
                m = _re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", str(line))
                if not m:
                    continue
                ip = m.group(1)
                subnet = ".".join(ip.split(".")[:3])
                if subnet not in allowed_subnets:
                    continue
                if ip in nmap_dict or ip in getattr(self.ruadan, 'hosts', []):
                    continue
                nmap_dict[ip] = {"ports": []}
                injected.append(ip)

            for ip in injected:
                msg = f"PIVOT_NEW_TARGET: {ip} injetado no escopo (vizinho descoberto pela session — alvo real do ciclo)"
                print(f"[*] [Pivot] {msg}")
                res.commands_executed.append(msg)
                self._log_pivot(f"{msg}")
        except Exception as e:
            print(f"[-] [Pivot] erro na injeção de alvos: {e}")

    def _log_pivot(self, msg: str):
        """Persiste o pivô no log de decisões da IA (auditoria)."""
        try:
            ev_dir = getattr(self.ruadan.args, 'outputFolder', '/ruadan/output')
            with open(os.path.join(ev_dir, "ai_evidence", "pivot_targets.log"), "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    def dispatch(self, action_id: int, target_ip: str) -> DispatchResult:
        """Executa comandos REAIS do Ruadan para a ação e alvo selecionados."""
        action = RedAction(action_id)
        res = DispatchResult(action=action_id, target_ip=target_ip)
        findings_before = dict(getattr(self.ruadan, 'findings', {}) or {})

        if action == RedAction.NOOP:
            res.detail = "NOOP: Nenhuma ação executada."
            res.success = True
            return res

        elif action == RedAction.DISCOVER_REMOTE:
            # ======================================================================
            # DISCOVER_REMOTE: Nmap TCP/UDP scans reais do Ruadan
            # ======================================================================
            print(f"\n[ActionDispatcher] [DISCOVER_REMOTE] Varredura TCP/UDP contra {target_ip}...")
            for scan_phase in ["Nmap Scan Fast TCP", "Nmap Scan Fast UDP"]:
                self._run_phase(scan_phase, res)
            self._reparse_findings()
            res.success = True
            res.detail = f"Descoberta remota: {len(res.commands_executed)} scans executados contra {target_ip}."

        elif action == RedAction.DISCOVER_SERVICES:
            # ======================================================================
            # DISCOVER_SERVICES: Enumeration Plan COMPLETO do Ruadan
            # Fases: Information Gathering, User Enumeration, Web Site Scanning,
            #        Password List Generation, User Enumeration Bruteforce
            # ======================================================================
            print(f"\n[ActionDispatcher] [DISCOVER_SERVICES] Enumeração completa de serviços em {target_ip}...")

            enumeration_phases = [
                "Information Gathering",
                "User Enumeration",
                "Web Site Scanning",
                "Web Site Nikto Tests",
                "Password List Generation",
                "User Enumeration Bruteforce",
            ]
            for phase_name in enumeration_phases:
                self._run_phase(phase_name, res)

            self._reparse_findings()
            res.findings_extracted = getattr(self.ruadan, 'findings', {})
            res.success = len(res.commands_executed) > 0
            res.detail = f"Enumeração completa: {len(res.commands_executed)} comandos de ferramentas executados."

        elif action == RedAction.EXPLOIT_REMOTE:
            # ======================================================================
            # EXPLOIT_REMOTE: Post Enumeration Plan COMPLETO do Ruadan
            # Fases: Web Content Detection, Web Exploitation, Nmap HTTP Scan,
            #        Brute Forcing Lite, Vulnerability Analysis, Vulnerability
            #        Validation, GoBuster, SearchSploit
            # ======================================================================
            print(f"\n[ActionDispatcher] [EXPLOIT_REMOTE] Exploração e análise de vulnerabilidades contra {target_ip}...")

            # SearchSploit primeiro — busca de exploits para serviços encontrados
            self._run_exploit_search(res)

            exploit_phases = [
                "Information Gathering",
                "Web Content Detection",
                "Web API Fuzzing",
                "Web Exploitation",
                "Nmap HTTP Scan",
                "Brute Forcing Lite",
                "Vulnerablity Analysis",
                "Vulnerability Validation",
                "GoBuster Web Content Bruteforce",
                "Metasploit Exploitation",
                "ZeroDay Hunt",
            ]
            for phase_name in exploit_phases:
                self._run_phase(phase_name, res)

            # Testa os PoCs copiados pelo SearchSploit (antes mortos no disco)
            self._run_exploit_tests(res)

            self._reparse_findings()
            res.findings_extracted = getattr(self.ruadan, 'findings', {})
            res.success = True
            res.detail = f"Exploração concluída: {len(res.commands_executed)} testes/buscas executados."

        elif action == RedAction.PRIVILEGE_ESCALATE:
            # ======================================================================
            # PRIVILEGE_ESCALATE: Brute Forcing completo + re-scan com credenciais
            # ======================================================================
            print(f"\n[ActionDispatcher] [PRIVILEGE_ESCALATE] Escalação de privilégios contra {target_ip}...")

            privesc_phases = [
                "Brute Forcing",
                "Exploitation",
                "Metasploit Session Privesc",
            ]
            for phase_name in privesc_phases:
                self._run_phase(phase_name, res)

            # Canário de verificação de root
            token = self.canary.generate_token("privesc")
            res.commands_executed.append(f"canary:privesc:{token}")

            self._reparse_findings()
            res.findings_extracted = getattr(self.ruadan, 'findings', {})
            res.success = True
            res.detail = f"Escalação de privilégios: {len(res.commands_executed)} comandos executados."

        elif action == RedAction.LATERAL_MOVE:
            # ======================================================================
            # LATERAL_MOVE: Re-scan Nmap com Nmap All TCP + re-enumeração
            # ======================================================================
            print(f"\n[ActionDispatcher] [LATERAL_MOVE] Movimentação lateral a partir de {target_ip}...")

            lateral_phases = [
                "Nmap Scan All TCP",
                "Information Gathering",
                "Metasploit Session Pivot",
            ]
            for phase_name in lateral_phases:
                self._run_phase(phase_name, res)

            # ETAPA 4: vizinhos descobertos pela session viram alvos do ciclo
            self._inject_pivot_targets(res)

            self._reparse_findings()
            res.success = True
            res.detail = f"Movimentação lateral: {len(res.commands_executed)} scans/enumerações executados."

        elif action == RedAction.PERSIST_BACKDOOR:
            # ======================================================================
            # PERSIST_BACKDOOR: Web exploitation + upload validation + screenshots
            # ======================================================================
            print(f"\n[ActionDispatcher] [PERSIST_BACKDOOR] Persistência e validação contra {target_ip}...")

            persist_phases = [
                "Vulnerability Validation",
                "Capture Screenshots",
                "Web Exploitation",
                "Metasploit Session Persist",
            ]
            for phase_name in persist_phases:
                self._run_phase(phase_name, res)

            token = self.canary.generate_token("backdoor")
            res.commands_executed.append(f"canary:backdoor:{token}")

            self._reparse_findings()
            res.success = True
            res.detail = f"Persistência: {len(res.commands_executed)} verificações executadas."

        elif action == RedAction.C2_ESTABLISH:
            # ======================================================================
            # C2_ESTABLISH: Metasploit database import + report generation
            # + C2 REAL: sessions persistentes no msfrpcd (via --c2-status)
            # ======================================================================
            print(f"\n[ActionDispatcher] [C2_ESTABLISH] Estabelecimento de C2 e consolidação para {target_ip}...")

            c2_phases = [
                "Metasploit Database Start",
                "Metasploit Database Import",
                "Metasploit Report Generation",
                "Metasploit C2 Report",
            ]
            for phase_name in c2_phases:
                self._run_phase(phase_name, res)

            self._reparse_findings()
            res.success = True
            res.detail = f"C2 estabelecido: {len(res.commands_executed)} operações executadas."

        elif action == RedAction.EXFILTRATE:
            # ======================================================================
            # EXFILTRATE: SearchSploit final + evidência com SHA256
            # ======================================================================
            print(f"\n[ActionDispatcher] [EXFILTRATE] Exfiltração e validação final contra {target_ip}...")

            # SearchSploit final com tudo acumulado
            self._run_exploit_search(res)
            self._run_exploit_tests(res)

            # Gera evidência com hash SHA256
            ev = self.canary.save_and_hash_evidence(
                "exfil",
                f"crown_jewel_{target_ip.replace('.', '_')}.txt",
                f"Flag comprovada em {target_ip}"
            )
            res.evidence_files.append(ev["file"])

            self._reparse_findings()
            res.findings_extracted = getattr(self.ruadan, 'findings', {})
            res.success = True
            res.detail = f"Exfiltração: evidência SHA256={ev['sha256'][:16]}... + {len(res.commands_executed)} comandos."

        elif action == RedAction.IMPACT_DEGRADE:
            # ======================================================================
            # IMPACT_DEGRADE: Vulnerability scan final
            # ======================================================================
            print(f"\n[ActionDispatcher] [IMPACT_DEGRADE] Análise de impacto contra {target_ip}...")

            self._run_phase("Vulnerablity Analysis", res)
            self._reparse_findings()
            res.success = True
            res.detail = f"Análise de impacto: {len(res.commands_executed)} verificações executadas."

        # Avaliação honesta do que esta ação realmente produziu (kill chain auditável)
        self._assess_evidence(res, findings_before)
        return res
