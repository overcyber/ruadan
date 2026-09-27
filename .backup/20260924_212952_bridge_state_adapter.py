"""
Adaptador de Estado: Traduz nmap_dict e findings do Ruadan para o MDP do red-MPPO.

Gera:
- obs: Vetor de 8 dimensões (discovered_frac, scanned_frac, user_frac, root_frac, etc.)
- host_features: Matriz (N, 7) de características normalizadas por host
- adjacency: Matriz (N, N) de vizinhança da topologia de rede
- action_masks: Máscaras de pré-condição da Kill Chain (10 ações)
- target_masks: Máscaras de alvos válidos por ação (10, N)
"""
from __future__ import annotations

import os
import sys
import re
import socket
from pathlib import Path
from typing import Any

import numpy as np

# Tenta importar do red-MPPO se disponível no path
try:
    from shared.constants import HostStatus, N_RED_ACTIONS, RedAction
    from services.pentest.app.state import HostRecord, PentestState
    from services.pentest.app.sensor import build_obs, build_host_features, build_adjacency
    from services.pentest.app.masks import build_masks
except ImportError:
    # Definições autônomas caso executando isolado
    from enum import IntEnum

    class HostStatus(IntEnum):
        CLEAN = 0
        SCANNED = 1
        EXPLOITED_USER = 2
        EXPLOITED_ROOT = 3
        BACKDOORED = 4
        EXFILTRATED = 5

    class RedAction(IntEnum):
        NOOP = 0
        DISCOVER_REMOTE = 1
        DISCOVER_SERVICES = 2
        EXPLOIT_REMOTE = 3
        PRIVILEGE_ESCALATE = 4
        LATERAL_MOVE = 5
        PERSIST_BACKDOOR = 6
        EXFILTRATE = 7
        C2_ESTABLISH = 8
        IMPACT_DEGRADE = 9

    N_RED_ACTIONS = 10

    class HostRecord:
        def __init__(self, host_id: int, ip: str, hostname: str | None = None, subnet: int = 0):
            self.host_id = host_id
            self.ip = ip
            self.hostname = hostname
            self.subnet = subnet
            self.status = int(HostStatus.CLEAN)
            self.discovered = True
            self.detected = False
            self.vuln = 0.0
            self.services = {}
            self.services_enumerated = False
            self.exploit_attempts = 0
            self.exploit_exhausted = False
            self.root_verified = False
            self.user_verified = False
            self.notes = []

        @property
        def is_patched_equivalent(self) -> bool:
            return self.exploit_exhausted

    class PentestState:
        def __init__(self, max_steps: int = 60):
            self.hosts: list[HostRecord] = []
            self.ip_to_id: dict[str, int] = {}
            self.c2_hosts: set[int] = set()
            self.red_action_log: list[int] = []
            self.records: list[Any] = []
            self.step: int = 0
            self.max_steps: int = max_steps
            self.noop_streak: int = 0
            self.exfil_verified: bool = False
            self.edges: set[tuple[str, str]] = set()

        def add_host(self, ip: str, subnet: int = 0, hostname: str | None = None) -> HostRecord:
            if ip in self.ip_to_id:
                rec = self.hosts[self.ip_to_id[ip]]
                if hostname and not rec.hostname:
                    rec.hostname = hostname
                    self.ip_to_id[hostname] = rec.host_id
                return rec
            if hostname and hostname in self.ip_to_id:
                rec = self.hosts[self.ip_to_id[hostname]]
                self.ip_to_id[ip] = rec.host_id
                if not rec.hostname:
                    rec.hostname = hostname
                return rec
            rec = HostRecord(host_id=len(self.hosts), ip=ip, hostname=hostname, subnet=subnet)
            self.hosts.append(rec)
            self.ip_to_id[ip] = rec.host_id
            if hostname:
                self.ip_to_id[hostname] = rec.host_id
            return rec

        @property
        def n_hosts(self) -> int:
            return len(self.hosts)

        def discovered_ids(self) -> list[int]:
            return [h.host_id for h in self.hosts if h.discovered]

        def neighbors_of(self, host_id: int) -> list[int]:
            ip = self.hosts[host_id].ip
            nbs = {self.ip_to_id[dst] for src, dst in self.edges if src == ip and dst in self.ip_to_id}
            nbs |= {self.ip_to_id[src] for src, dst in self.edges if dst == ip and src in self.ip_to_id}
            return sorted(nbs)

        def status_array(self) -> np.ndarray:
            if not self.hosts:
                return np.zeros(0, dtype=np.int64)
            return np.array([h.status for h in self.hosts], dtype=np.int64)

        def c2_ids(self) -> set[int]:
            return set(self.c2_hosts)

    MAX_STATUS = float(HostStatus.EXFILTRATED)

    def build_host_features(state: PentestState) -> np.ndarray:
        n = state.n_hosts
        if n == 0:
            return np.zeros((0, 7), dtype=np.float32)
        n_subnets = max(1, len({h.subnet for h in state.hosts}))
        deg = np.zeros(n, dtype=np.float32)
        for h in state.hosts:
            deg[h.host_id] = len(state.neighbors_of(h.host_id))
        deg_norm = deg / max(1.0, float(deg.max())) if deg.max() > 0 else deg

        feats = np.column_stack((
            np.array([h.vuln for h in state.hosts], dtype=np.float32),
            state.status_array().astype(np.float32) / MAX_STATUS,
            (state.status_array() >= int(HostStatus.EXPLOITED_USER)).astype(np.float32),
            np.zeros(n, dtype=np.float32),
            np.array([1.0 if h.discovered else 0.0 for h in state.hosts], dtype=np.float32),
            np.array([h.subnet for h in state.hosts], dtype=np.float32) / float(n_subnets),
            deg_norm,
        ))
        return feats.astype(np.float32, copy=False)

    def build_adjacency(state: PentestState) -> np.ndarray:
        n = state.n_hosts
        adj = np.eye(n, dtype=np.float32)
        for h in state.hosts:
            for nb in state.neighbors_of(h.host_id):
                adj[h.host_id, nb] = 1.0
                adj[nb, h.host_id] = 1.0
        return adj

    def build_obs(state: PentestState, max_steps: int) -> np.ndarray:
        n = max(1, state.n_hosts)
        status = state.status_array()
        counts = np.bincount(status, minlength=6) if status.size else np.zeros(6, dtype=np.int64)
        nd = max(1, len(state.discovered_ids()))
        return np.array(
            [
                len(state.discovered_ids()) / n,
                counts[1] / nd,
                counts[2] / nd,
                counts[3] / nd,
                counts[4] / nd,
                counts[5] / nd,
                len(state.c2_ids()) / n,
                state.step / max(1, max_steps),
            ],
            dtype=np.float32,
        )

    def build_masks(state: PentestState) -> tuple[np.ndarray, np.ndarray]:
        n = state.n_hosts
        if n == 0:
            am = np.zeros(N_RED_ACTIONS, dtype=np.float32)
            am[RedAction.NOOP] = 1.0
            return am, np.zeros((N_RED_ACTIONS, 0), dtype=np.float32)

        host_idx = np.arange(n, dtype=np.int64)
        discovered = np.array(state.discovered_ids(), dtype=np.int64)
        discovered_mask = np.zeros(n, dtype=np.float32)
        discovered_mask[discovered] = 1.0

        tm = np.zeros((N_RED_ACTIONS, n), dtype=np.float32)
        tm[RedAction.NOOP, :] = 1.0

        # DISCOVER_REMOTE: apenas hosts nao escaneados ou que possuam vizinhos nao descobertos na topologia
        unscanned_hosts = [
            int(h) for h in discovered
            if state.hosts[int(h)].status < int(HostStatus.SCANNED)
            or any(nb not in set(state.discovered_ids()) for nb in state.neighbors_of(int(h)))
        ]
        if unscanned_hosts:
            tm[RedAction.DISCOVER_REMOTE, unscanned_hosts] = 1.0

        status = state.status_array()

        # DISCOVER_SERVICES: hosts escaneados que ainda nao tiveram servicos totalmente enumerados
        # Caso todos ja tenham sido enumerados, mantem ativo apenas se nao houver exploit pendente
        services_to_scan = [
            int(h) for h in discovered
            if not getattr(state.hosts[int(h)], "services_enumerated", False)
            and status[int(h)] >= int(HostStatus.SCANNED)
        ]
        if services_to_scan:
            tm[RedAction.DISCOVER_SERVICES, services_to_scan] = 1.0
        elif not unscanned_hosts:
            # Se tudo foi escaneado e enumerado, permite re-scan se nenhum outro estagio estiver disponivel
            tm[RedAction.DISCOVER_SERVICES] = discovered_mask

        # EXPLOIT_REMOTE: hosts escaneados com servicos, nao esgotados e status < EXPLOITED_USER
        exploit_hosts = np.array(
            [
                int(h) for h in discovered
                if not state.hosts[int(h)].exploit_exhausted
                and status[int(h)] >= int(HostStatus.SCANNED)
                and status[int(h)] < int(HostStatus.EXPLOITED_USER)
            ],
            dtype=np.int64
        )
        if exploit_hosts.size:
            tm[RedAction.EXPLOIT_REMOTE, exploit_hosts] = 1.0
            # Se ja enumerou servicos do host e ele pode ser explorado, desliga redundancia de DISCOVER_SERVICES
            for eh in exploit_hosts:
                if getattr(state.hosts[int(eh)], "services_enumerated", False):
                    tm[RedAction.DISCOVER_SERVICES, int(eh)] = 0.0

        escalate = host_idx[status == int(HostStatus.EXPLOITED_USER)]
        if escalate.size:
            tm[RedAction.PRIVILEGE_ESCALATE, escalate] = 1.0

        root_hosts = host_idx[status >= int(HostStatus.EXPLOITED_ROOT)]
        exact_root = host_idx[status == int(HostStatus.EXPLOITED_ROOT)]
        if root_hosts.size:
            tm[RedAction.LATERAL_MOVE, root_hosts] = 1.0
            tm[RedAction.IMPACT_DEGRADE, root_hosts] = 1.0
        if exact_root.size:
            tm[RedAction.PERSIST_BACKDOOR, exact_root] = 1.0

        c2 = state.c2_ids()
        c2_hosts = np.array([int(h) for h in host_idx if status[int(h)] >= int(HostStatus.BACKDOORED) and int(h) not in c2], dtype=np.int64)
        if c2_hosts.size:
            tm[RedAction.C2_ESTABLISH, c2_hosts] = 1.0

        exfil_hosts = np.array([int(h) for h in host_idx if status[int(h)] == int(HostStatus.BACKDOORED) and int(h) in c2], dtype=np.int64)
        if exfil_hosts.size:
            tm[RedAction.EXFILTRATE, exfil_hosts] = 1.0

        am = (tm.sum(axis=1) > 0).astype(np.float32)
        am[RedAction.NOOP] = 0.0 if np.any(am[1:] > 0) else 1.0
        return am, tm


class RuadanStateAdapter:
    def __init__(self, max_steps: int = 60):
        self.state = PentestState(max_steps=max_steps)

    def sync_from_ruadan(self, nmap_dict: dict, findings: dict | None = None,
                          risk_scores: dict | None = None) -> PentestState:
        """Sincroniza o estado a partir das estruturas nmap_dict e findings do Ruadan."""
        findings = findings or {}
        risk_scores = risk_scores or {}

        for host_key, data in nmap_dict.items():
            if not host_key or host_key.startswith("#"):
                continue

            # Identifica se a chave é IP ou Hostname
            is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host_key))
            host_ip = data.get("ip") or (host_key if is_ip else "")
            hostname = data.get("hostname") or (None if is_ip else host_key)

            if not host_ip and hostname:
                try:
                    host_ip = socket.gethostbyname(hostname)
                except Exception:
                    host_ip = hostname

            # Extrai subnet simples (ex: 192.168.10.x -> subnet hash)
            octets = host_ip.split(".")
            subnet_idx = int(octets[2]) if len(octets) == 4 and octets[2].isdigit() else 0

            rec = self.state.add_host(host_ip, subnet=subnet_idx, hostname=hostname)

            # Atualiza portas e serviços
            ports = data.get("ports", [])
            for p in ports:
                port_id = str(p.get("portid", ""))
                if port_id:
                    rec.services[port_id] = {
                        "name": p.get("name", "unknown"),
                        "product": p.get("product", ""),
                        "version": p.get("version", ""),
                        "state": p.get("state", "open"),
                    }

            # Atualiza vulnerabilidade / risk score (normalizado 0.0 a 1.0)
            raw_risk = risk_scores.get(host_ip, 0.0)
            rec.vuln = min(1.0, float(raw_risk) / 100.0) if raw_risk > 0 else (0.4 if ports else 0.0)

            # Atualiza status da Kill Chain
            if rec.status < int(HostStatus.SCANNED) and ports:
                rec.status = int(HostStatus.SCANNED)

            # Se houver credenciais encontradas para o host em findings
            if rec.user_verified or (findings.get("users") and findings.get("passwords")):
                if rec.status < int(HostStatus.EXPLOITED_USER):
                    rec.status = int(HostStatus.EXPLOITED_USER)

            if rec.root_verified:
                if rec.status < int(HostStatus.EXPLOITED_ROOT):
                    rec.status = int(HostStatus.EXPLOITED_ROOT)

        # Adiciona arestas na mesma subnet
        all_hosts = self.state.hosts
        for i in range(len(all_hosts)):
            for j in range(i + 1, len(all_hosts)):
                if all_hosts[i].subnet == all_hosts[j].subnet:
                    self.state.edges.add((all_hosts[i].ip, all_hosts[j].ip))
                    self.state.edges.add((all_hosts[j].ip, all_hosts[i].ip))

        return self.state

    def get_tensors(self) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Retorna (obs, host_features, adjacency, action_mask, target_mask) para a política RL."""
        obs = build_obs(self.state, self.state.max_steps)
        hf = build_host_features(self.state)
        adj = build_adjacency(self.state)
        am, tm = build_masks(self.state)
        return obs, hf, adj, am, tm
