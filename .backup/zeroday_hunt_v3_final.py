def _execute_exploits_for_confirmed_cves(self, hh: HostHunt) -> None:
        """Executa exploits REAIS via Metasploit para CVEs confirmadas.
        Se obtiver shell/root, marca SHELL_OBTAINED e atualiza kill chain.
        """
        # Coleta CVEs confirmadas das findings
        cves_confirmadas = []
        for f in hh.suite_findings:
            if f.get("verdict") == "confirmed" and f.get("class", "").startswith("cve_"):
                cve_match = re.search(r'(CVE-\d{4}-\d+)', f.get("class", "") + " " + f.get("detail", ""))
                if cve_match:
                    cves_confirmadas.append(cve_match.group(1))
        
        # Remove duplicatas
        cves_unicas = list(dict.fromkeys(cves_confirmadas))
        
        for cve_id in cves_unicas:
            self._ev(kind="phase", phase="exploit_exec", host=hh.ip, cve=cve_id)
            
            # Executa exploit via tool
            exploit_res = self.tb.tool_exploit_execute(
                cve_id=cve_id,
                host_ip=hh.ip,
                port=0  # auto-detecta pela porta do serviço
            )
            
            self._ev(kind="exploit_result", host=hh.ip, cve=cve_id, **exploit_res)
            
            if exploit_res.get("ok") and exploit_res.get("verified"):
                # Shell/root obtido!
                self._ev(kind="finding", host=hh.ip,
                         class_="shell_obtained",
                         verdict="confirmed",
                         detail=f"SHELL_OBTAINED via {cve_id}: {exploit_res.get('evidence', '')}",
                         cve=cve_id,
                         exploit_result=exploit_res)
                # Marca que conseguiu shell real
                for h in self.hosts:
                    if h.ip == hh.ip:
                        h.outcome = "SHELL_OBTAINED"
                        h.detail = f"Shell obtido via {cve_id}: {exploit_res.get('evidence', '')}"
                        break
                # Se conseguiu root, marca
                if exploit_res.get("root"):
                    self._ev(kind="finding", host=hh.ip,
                             class_="root_obtained",
                             verdict="confirmed",
                             detail=f"ROOT obtido via {cve_id}: {exploit_res.get('evidence', '')}",
                             cve=cve_id)
                # Para de testar outros exploits se já conseguiu shell
                break

    # --------------------------------------------------------------- F3 LLM