"""
Orquestrador Principal de IA: Integra Ruadan, o modelo RL (MADDPG/MPPO)
e o cliente Multi-LLM (Ollama, Gemini, OpenAI, Claude, DeepSeek, NVIDIA NIM).
Garante auditoria completa e transparente de todas as decisões e comandos.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from .action_dispatcher import ActionDispatcher
from .canary import CanaryVerifier
from .llm_client import MultiLLMClient
from .state_adapter import RuadanStateAdapter, RedAction, HostStatus

# Tenta carregar suporte a PyTorch local caso disponível no ambiente
try:
    from services.pentest.app.policy_loader import load_red_policy, policy_act
    HAS_LOCAL_TORCH = True
except Exception:
    HAS_LOCAL_TORCH = False


class RuadanAIBrain:
    def __init__(self, ruadan_instance: Any, checkpoint_path: str | None = None,
                 llm_provider: str | None = None, llm_model: str | None = None,
                 max_steps: int = 40, evidence_dir: str | Path | None = None,
                 red_mppo_url: str | None = None):
        self.ruadan = ruadan_instance
        self.max_steps = max_steps
        self.evidence_dir = Path(evidence_dir or os.path.join(ruadan_instance.args.outputFolder, "ai_evidence"))
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self.transcripts_dir = self.evidence_dir / "llm_transcripts"
        self.transcripts_dir.mkdir(parents=True, exist_ok=True)

        self.decision_log_path = self.evidence_dir / "ai_decisions.log"
        self.rl_ndjson_path = self.evidence_dir / "rl_policy.ndjson"
        self.commands_log_path = self.evidence_dir / "executed_commands.log"

        self.canary = CanaryVerifier(self.evidence_dir)
        self.adapter = RuadanStateAdapter(max_steps=max_steps)
        self.dispatcher = ActionDispatcher(self.ruadan, self.canary)
        self.llm = MultiLLMClient(provider=llm_provider, model=llm_model)

        # Configuração do serviço red-MPPO (HTTP ou local)
        self.red_mppo_url = red_mppo_url or os.environ.get("RED_MPPO_URL", "http://localhost:8000").rstrip("/")
        self.checkpoint_path = checkpoint_path or os.environ.get("CHECKPOINT_PATH", "/app/checkpoints/maestro_red_ep1246800.pt")
        self.local_policy = None
        self.rl_source = "NONE"

        self._init_rl_engine()
        self.step_history: list[dict] = []

    def _init_rl_engine(self):
        """Verifica a conectividade com o microserviço red-MPPO ou carrega localmente."""
        candidates = [
            self.red_mppo_url,
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:8008",
            "http://127.0.0.1:8008",
            "http://host.docker.internal:8000",
            "http://ruadan-red-mppo:8000",
        ]
        checked = set()
        for cand in candidates:
            if not cand or cand in checked:
                continue
            checked.add(cand)
            cand_clean = cand.rstrip("/")
            for endpoint in ["/health", "/"]:
                try:
                    req = urllib.request.Request(f"{cand_clean}{endpoint}", method="GET")
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode("utf-8"))
                            if data.get("service") == "red-mppo-rl-policy-server" or data.get("status") == "ok":
                                self.red_mppo_url = cand_clean
                                self.rl_source = f"MICROSERVICE ({cand_clean})"
                                self._log_decision(f"[RL INIT] Microserviço red-MPPO (.pt) conectado com sucesso em {cand_clean}: {data}")
                                print(f"[AI Brain] Microserviço red-MPPO (.pt) conectado com sucesso ({cand_clean})!")
                                return
                except Exception:
                    pass

        self._log_decision(f"[RL INIT] Nenhum microserviço HTTP red-MPPO respondeu adequadamente ({self.red_mppo_url}). Tentando PyTorch local...")

        # 2. Tenta carregar o checkpoint localmente com PyTorch
        if HAS_LOCAL_TORCH and self.checkpoint_path and os.path.isfile(self.checkpoint_path):
            try:
                self.local_policy = load_red_policy(self.checkpoint_path, device="cpu")
                self.rl_source = f"LOCAL_TORCH ({self.checkpoint_path})"
                self._log_decision(f"[RL INIT] Checkpoint RL .pt carregado via PyTorch local: {self.checkpoint_path}")
                print(f"[AI Brain] Checkpoint RL carregado com sucesso no PyTorch local: {self.checkpoint_path}")
                return
            except Exception as e:
                self._log_decision(f"[RL INIT] Falha ao carregar checkpoint local {self.checkpoint_path}: {e}")
                print(f"[AI Brain] Aviso: Falha ao carregar checkpoint local ({e}).")

        self.rl_source = "FALLBACK_HEURISTIC"
        print(f"[AI Brain] Aviso: Modelo RL não disponível diretamente. Usando seleção heurística supervisionada por LLM.")
        self._log_decision("[RL INIT] Nenhum backend RL ativo. Modo heurístico supervisionado ativado.")

    def _log_decision(self, msg: str):
        timestamp = datetime.now().isoformat()
        entry = f"[{timestamp}] {msg}\n"
        try:
            with open(self.decision_log_path, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception:
            pass

    def run_ai_cycle(self) -> dict:
        """Executa o ciclo autônomo de pentest guiado por IA (RL + LLM)."""
        print(f"\n==================================================================")
        print(f" RUADAN AI ORCHESTRATION CYCLE")
        print(f" - Motor RL:    {self.rl_source}")
        print(f" - Provedor LLM: {self.llm.provider.upper()} (Modelo: {self.llm.model})")
        print(f" - Alvo(s):     {self.ruadan.hosts}")
        print(f" - Logs IA:     {self.evidence_dir}")
        print(f"==================================================================\n")

        self._log_decision(
            f"INICIANDO CAMPANHA: RL={self.rl_source} | LLM={self.llm.provider}:{self.llm.model} | "
            f"Hosts={self.ruadan.hosts}"
        )

        # 1. Reconhecimento inicial com Ruadan (TCP + UDP incluindo portas filtradas)
        print("[AI Brain] 1/3 Executando varredura preliminar TCP e UDP...")
        self.ruadan.enumerate("Nmap Scan Fast TCP")
        self.ruadan.enumerate("Nmap Scan Fast UDP")
        # Varredura TCP COMPLETA (1-65535): o Fast cobre apenas o top-100 — sem
        # isto, serviços em portas altas (3000, 8080, 8443...) ficam invisíveis
        # para todo o resto da campanha. Primeiro output completo do run.
        # ATENÇÃO: o enumerate espera a FASE do attackplan ("Nmap Scan All TCP"),
        # não o comando do config ("Nmap All TCP").
        print("[AI Brain] Executando varredura TCP completa (1-65535)...")
        self.ruadan.enumerate("Nmap Scan All TCP")
        self.ruadan.parse_nmap_xml()

        state = self.adapter.sync_from_ruadan(
            self.ruadan.nmap_dict,
            self.ruadan.findings,
            getattr(self.ruadan, "risk_score", {})
        )

        # 2. Loop de decisões orientadas por IA
        for step in range(self.max_steps):
            state.step = step
            obs, hf, adj, am, tm = self.adapter.get_tensors()

            if not state.hosts:
                print("[AI Brain] Nenhum host identificado na topologia. Encerrando ciclo.")
                self._log_decision("Nenhum host encontrado. Fim da execução.")
                break

            # Consulta o Modelo RL (.pt)
            action_type, target_id, rl_metadata = self._query_rl_policy(obs, hf, adj, am, tm, state)
            target_rec = state.hosts[target_id] if target_id < len(state.hosts) else state.hosts[0]
            target_host = target_rec.hostname or target_rec.ip
            action_name = RedAction(action_type).name

            # Consulta o LLM para Estratégia Tática e Justificativa
            llm_rationale, llm_meta = self._query_llm_tactics(step, action_name, action_type, target_host, state)

            print(f"\n>>> [Passo {step + 1}/{self.max_steps}] DECISÃO IA:")
            print(f"    - Ação RL (.pt):     {action_name} (ID: {action_type})")
            print(f"    - Alvo:              {target_host}")
            print(f"    - Racional Tático:   {llm_rationale}")

            self._log_decision(
                f"[PASSO {step + 1}/{self.max_steps}] Ação={action_name} | Alvo={target_host} | "
                f"RL_Backend={rl_metadata.get('source')} | LLM_Rationale={llm_rationale}"
            )

            # Grava entrada em rl_policy.ndjson
            rl_record = {
                "step": step,
                "timestamp": time.time(),
                "action_type": action_type,
                "action_name": action_name,
                "target_id": target_id,
                "target_host": target_host,
                "rl_metadata": rl_metadata,
                "llm_summary": llm_rationale
            }
            with open(self.rl_ndjson_path, "a", encoding="utf-8") as f_nd:
                f_nd.write(json.dumps(rl_record, ensure_ascii=False) + "\n")

            # Executa a ação no Ruadan através do Dispatcher
            res = self.dispatcher.dispatch(action_type, target_host)

            # Grava comandos executados em executed_commands.log
            for cmd in res.commands_executed:
                with open(self.commands_log_path, "a", encoding="utf-8") as f_cmd:
                    f_cmd.write(f"[{datetime.now().isoformat()}] [STEP {step + 1}] [{action_name}] {cmd}\n")

            step_log = {
                "step": step,
                "action": action_name,
                "action_id": action_type,
                "target": target_host,
                "commands": res.commands_executed,
                "success": res.success,
                "evidence_level": getattr(res, "evidence_level", "enum_only"),
                "evidence_detail": getattr(res, "evidence_detail", ""),
                "detail": res.detail,
                "llm_rationale": llm_rationale,
                "timestamp": time.time()
            }
            self.step_history.append(step_log)

            # Atualiza flags de avanço no HostRecord — PROMOVE STATUS NA KILL CHAIN
            if target_id < len(state.hosts):
                target_rec = state.hosts[target_id]
                if action_type == int(RedAction.DISCOVER_REMOTE):
                    target_rec.status = max(target_rec.status, int(HostStatus.SCANNED))
                elif action_type == int(RedAction.DISCOVER_SERVICES):
                    target_rec.services_enumerated = True
                    target_rec.status = max(target_rec.status, int(HostStatus.SCANNED))
                elif action_type == int(RedAction.EXPLOIT_REMOTE):
                    target_rec.exploit_attempts = getattr(target_rec, "exploit_attempts", 0) + 1
                    # Após exploit, promove para EXPLOITED_USER para habilitar PRIVILEGE_ESCALATE
                    if res.success and target_rec.status < int(HostStatus.EXPLOITED_USER):
                        target_rec.status = int(HostStatus.EXPLOITED_USER)
                        target_rec.user_verified = True
                        self._log_decision(f"[KILL CHAIN] Host {target_host} promovido para EXPLOITED_USER após EXPLOIT_REMOTE (evidência real: {getattr(res, 'evidence_level', 'enum_only')} — {getattr(res, 'evidence_detail', '')}).")
                        print(f"[AI Brain] [KILL CHAIN] {target_host} → EXPLOITED_USER | evidência: {getattr(res, 'evidence_level', 'enum_only')}")
                    if target_rec.exploit_attempts >= 2:
                        target_rec.exploit_exhausted = True
                elif action_type == int(RedAction.PRIVILEGE_ESCALATE):
                    if res.success and target_rec.status < int(HostStatus.EXPLOITED_ROOT):
                        target_rec.status = int(HostStatus.EXPLOITED_ROOT)
                        target_rec.root_verified = True
                        self._log_decision(f"[KILL CHAIN] Host {target_host} promovido para EXPLOITED_ROOT após PRIVILEGE_ESCALATE (evidência real: {getattr(res, 'evidence_level', 'enum_only')} — {getattr(res, 'evidence_detail', '')}).")
                elif action_type == int(RedAction.PERSIST_BACKDOOR):
                    if res.success and target_rec.status < int(HostStatus.BACKDOORED):
                        target_rec.status = int(HostStatus.BACKDOORED)
                        self._log_decision(f"[KILL CHAIN] Host {target_host} promovido para BACKDOORED após PERSIST_BACKDOOR (evidência real: {getattr(res, 'evidence_level', 'enum_only')} — {getattr(res, 'evidence_detail', '')}).")
                elif action_type == int(RedAction.C2_ESTABLISH):
                    if res.success:
                        state.c2_hosts.add(target_id)
                        self._log_decision(f"[KILL CHAIN] Host {target_host} adicionado ao canal C2.")
                elif action_type == int(RedAction.LATERAL_MOVE):
                    if res.success:
                        # Descobre novos hosts na mesma subnet
                        for h in state.hosts:
                            if h.subnet == target_rec.subnet and h.status < int(HostStatus.SCANNED):
                                h.status = int(HostStatus.SCANNED)

            # Anti-loop tático: se a mesma ação for repetida consecutivamente contra o mesmo alvo, força progressão
            if len(self.step_history) >= 2:
                prev = self.step_history[-2]
                if prev["action_id"] == action_type and prev["target"] == target_host:
                    if target_id < len(state.hosts):
                        h_rec = state.hosts[target_id]
                        if action_type == int(RedAction.DISCOVER_REMOTE):
                            h_rec.status = max(h_rec.status, int(HostStatus.SCANNED))
                        elif action_type == int(RedAction.DISCOVER_SERVICES):
                            h_rec.services_enumerated = True
                        elif action_type == int(RedAction.EXPLOIT_REMOTE):
                            h_rec.exploit_exhausted = True
                            # Força promoção mesmo se exploit foi "exaurido"
                            if h_rec.status < int(HostStatus.EXPLOITED_USER):
                                h_rec.status = int(HostStatus.EXPLOITED_USER)
                                h_rec.user_verified = True
                                self._log_decision(f"[ANTI-LOOP] Forçando promoção de {target_host} para EXPLOITED_USER após 2 EXPLOIT_REMOTE consecutivos.")

            # Sincroniza novo estado do Ruadan
            state = self.adapter.sync_from_ruadan(
                self.ruadan.nmap_dict,
                self.ruadan.findings,
                getattr(self.ruadan, "risk_score", {})
            )

            # Se a exfiltração foi realizada e validada por canário, atinge o objetivo
            if action_type == int(RedAction.EXFILTRATE) and res.success:
                print(f"[AI Brain] Objetivo de exfiltração alcançado com evidência validada!")
                self._log_decision("Objetivo de exfiltração alcançado com sucesso.")
                break

        # 3. Consolidação de relatório de evidências com manifesto sha256
        report_path = self.evidence_dir / "ai_campaign_report.json"
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "max_steps": self.max_steps,
            "steps_executed": len(self.step_history),
            "rl_source": self.rl_source,
            "llm_provider": self.llm.provider,
            "llm_model": self.llm.model,
            "history": self.step_history,
            "canary_manifest": self.canary.manifest,
            "hosts_final_state": [
                {
                    "ip": h.ip,
                    "status": h.status,
                    "vuln": h.vuln,
                    "services": list(h.services.keys())
                }
                for h in state.hosts
            ]
        }
        report_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[AI Brain] Relatório da campanha gravado em: {report_path}")
        print(f"[AI Brain] Registro detalhado em: {self.decision_log_path}")
        return report_data

    def _query_rl_policy(self, obs: np.ndarray, hf: np.ndarray, adj: np.ndarray,
                         am: np.ndarray, tm: np.ndarray, state: Any) -> tuple[int, int, dict]:
        """Consulta o modelo RL red-MPPO (.pt) via HTTP microservice ou via PyTorch local."""
        # 1. Consulta ao microserviço HTTP
        if "MICROSERVICE" in self.rl_source:
            try:
                payload = {
                    "obs": obs.tolist(),
                    "host_features": hf.tolist(),
                    "adjacency": adj.tolist(),
                    "action_mask": am.tolist() if am is not None else None,
                    "target_mask": tm.tolist() if tm is not None else None,
                    "agent_id": 0,
                    "deterministic": True
                }
                req_data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    f"{self.red_mppo_url}/act",
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        action = int(data.get("action", 0))
                        target = int(data.get("target_id", 0))
                        meta = {
                            "source": "red-mppo-http-microservice",
                            "checkpoint": data.get("checkpoint"),
                            "action_probs": data.get("action_probs", []),
                            "target_probs": data.get("target_probs", [])
                        }
                        return action, target, meta
            except Exception as e:
                self._log_decision(f"[RL QUERY ERROR] Falha no microserviço HTTP ({e}). Tentando fallback local.")

        # 2. Consulta ao PyTorch local se disponível
        if self.local_policy is not None:
            try:
                action, target, extra = policy_act(
                    self.local_policy.agent, obs=obs, agent_id=0,
                    host_features=hf, adjacency=adj,
                    action_mask=am, target_mask=tm, deterministic=True
                )
                meta = {
                    "source": "local-pytorch-checkpoint",
                    "checkpoint": self.checkpoint_path,
                    "action_probs": extra.get("action_probs", []),
                    "target_probs": extra.get("target_probs", [])
                }
                return int(action), int(target), meta
            except Exception as e:
                self._log_decision(f"[RL QUERY ERROR] Erro na inferência do PyTorch local: {e}")

        # 3. Fallback heurístico caso RL não esteja acessível
        valid_indices = [i for i in range(len(am)) if am[i] > 0 and i != int(RedAction.NOOP)]
        if not valid_indices:
            return int(RedAction.NOOP), 0, {"source": "heuristic_fallback", "action_probs": []}

        # Priorização heurística rigorosa da Kill Chain
        priority_order = [
            int(RedAction.EXFILTRATE),
            int(RedAction.C2_ESTABLISH),
            int(RedAction.PERSIST_BACKDOOR),
            int(RedAction.PRIVILEGE_ESCALATE),
            int(RedAction.LATERAL_MOVE),
            int(RedAction.EXPLOIT_REMOTE),
            int(RedAction.DISCOVER_SERVICES),
            int(RedAction.DISCOVER_REMOTE),
            int(RedAction.IMPACT_DEGRADE),
        ]
        chosen_action = valid_indices[0]
        for p_act in priority_order:
            if p_act in valid_indices:
                chosen_action = p_act
                break

        # Determina o melhor alvo para a ação escolhida
        valid_targets = np.where(tm[chosen_action] > 0)[0]
        chosen_target = int(valid_targets[0]) if len(valid_targets) > 0 else 0
        return chosen_action, chosen_target, {"source": "heuristic_fallback", "action_probs": []}

    def _query_llm_tactics(self, step: int, action_name: str, action_id: int,
                           target_host: str, state: Any) -> tuple[str, dict]:
        """Consulta o LLM para obter o racional tático, parâmetros e sugestões de ferramentas."""
        hosts_info = [
            {"id": h.host_id, "ip": h.ip, "status": h.status, "services": list(h.services.keys())}
            for h in state.hosts
        ]

        prompt = (
            f"Você é o estrategista de pentest do Ruadan integrado com red-MPPO.\n"
            f"O modelo de Reinforcement Learning (.pt) selecionou a seguinte ação da Kill Chain:\n"
            f"  - Ação: {action_name} (ID: {action_id})\n"
            f"  - Alvo: {target_host}\n\n"
            f"Topologia e serviços identificados até o momento:\n{json.dumps(hosts_info, indent=2)}\n\n"
            f"Forneça uma análise tática sucinta em formato JSON:\n"
            f"{{\n"
            f'  "rationale": "<justificativa técnica objetiva em 1-2 frases>",\n'
            f'  "tool_focus": ["<ferramentas mais relevantes do arsenal para esta fase>"],\n'
            f'  "risk_assessment": "<baixo | médio | alto>"\n'
            f"}}"
        )

        try:
            start_t = time.time()
            resp = self.llm.chat([
                {"role": "system", "content": "Você é um especialista tático em segurança ofensiva e orquestração de testes de penetração."},
                {"role": "user", "content": prompt}
            ])
            latency = int((time.time() - start_t) * 1000)

            # Grava transcript completo do LLM (timestamp único p/ evitar sobrescrita entre campanhas paralelas)
            ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            transcript_file = self.transcripts_dir / f"step_{step + 1}_{action_name}_{ts_tag}.json"
            transcript_data = {
                "step": step + 1,
                "action": action_name,
                "target": target_host,
                "prompt": prompt,
                "response": resp.content,
                "model": self.llm.model,
                "provider": self.llm.provider,
                "latency_ms": latency
            }
            transcript_file.write_text(json.dumps(transcript_data, indent=2, ensure_ascii=False), encoding="utf-8")

            # Parse da resposta JSON do LLM
            clean_content = resp.content.strip()
            data = None
            if "```" in clean_content:
                parts = clean_content.split("```")
                for p in parts[1:]:
                    cand = p.strip()
                    if cand.startswith("json"):
                        cand = cand[4:].strip()
                    try:
                        data = json.loads(cand)
                        break
                    except Exception:
                        pass

            if data is None:
                try:
                    data = json.loads(clean_content)
                except Exception:
                    m = re.search(r'\{[\s\S]*\}', clean_content)
                    if m:
                        data = json.loads(m.group(0))
                    else:
                        raise ValueError(f"Não foi possível extrair JSON da resposta: {clean_content[:100]}")

            rationale = data.get("rationale", f"Executando {action_name} contra {target_host}.")
            return rationale, data

        except Exception as e:
            fallback_rationale = f"Ação {action_name} validada para avanço da Kill Chain contra {target_host}."
            self._log_decision(f"[LLM ERROR] Falha na consulta ao LLM ({e}). Usando fallback: {fallback_rationale}")
            return fallback_rationale, {"error": str(e)}
