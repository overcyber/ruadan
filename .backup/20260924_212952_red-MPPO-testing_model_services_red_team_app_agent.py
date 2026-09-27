"""
MADDPG multi-agente com action space FATORADO (Lowe et al. 2017 NeurIPS).

v4.2: Ação fatorada — π(action_type | obs) × π(target | obs, host_embeddings).
  - Actor produz logits de action_type (10 categorias) + query para PointerHead.
  - PointerHead seleciona host-alvo via atenção sobre embeddings dos hosts.
  - Invariante a n_hosts: funciona com 13, 30, 40 ou 50 hosts sem retraining.
  - HostEncoder usa GAT para codificar topologia de rede em host embeddings.

Referências:
  Lowe et al. (2017) "MADDPG" — NeurIPS
  Vinyals et al. (2015) "Pointer Networks" — NeurIPS
  Veličković et al. (2018) "GAT" — ICLR
"""
from __future__ import annotations
# OLD: import copy, numpy as np, torch, torch.nn as nn, torch.nn.functional as F
import copy, math, numpy as np, torch, torch.nn as nn, torch.nn.functional as F
from dataclasses import dataclass
from shared.constants import N_RED_ACTIONS, MAX_AGENTS, HOST_FEAT_DIM
from shared.networks.gat_encoder import GATEncoder
from shared.networks.host_encoder import HostEncoder
from shared.networks.pointer_head import PointerHead
from shared.utils.numerical_integrity import fail_if_confirmatory_numerical_event

try:
    from shared.utils.logging import setup_logging
except Exception:
    import logging

    def setup_logging(service_name: str):
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(service_name)


log = setup_logging("red_team.agent")


def _log_warning_event(event: str, **kwargs) -> None:
    fail_if_confirmatory_numerical_event(event, **kwargs)
    try:
        log.warning(event, **kwargs)
    except TypeError:
        # OLD: red_team.agent nao tinha logger estruturado proprio.
        log.warning("%s %s", event, kwargs)


class FactoredActor(nn.Module):
    """Ator descentralizado com ação fatorada: action_type + pointer target."""
    def __init__(self, obs_dim: int, n_action_types: int = N_RED_ACTIONS,
                 hidden: int = 256, emb_dim: int = 16, key_dim: int = 64):
        super().__init__()
        assert MAX_AGENTS > 0, f"MAX_AGENTS must be > 0, got {MAX_AGENTS}"
        self.emb = nn.Embedding(MAX_AGENTS, emb_dim)
        self.trunk = nn.Sequential(
            nn.Linear(obs_dim + emb_dim, hidden), nn.ReLU(),
            nn.Linear(hidden, hidden), nn.ReLU())
        self.type_head = nn.Linear(hidden, n_action_types)
        self.pointer = PointerHead(hidden, key_dim)
        self.n_action_types = n_action_types
        self._init_weights()

    def _init_weights(self):
        for m in self.trunk.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=1.41421)
                nn.init.zeros_(m.bias)
        nn.init.xavier_uniform_(self.type_head.weight, gain=0.01)
        nn.init.zeros_(self.type_head.bias)

    def forward(self, obs, agent_id, host_keys):
        """
        obs: (B, obs_dim), agent_id: (B,), host_keys: (B, N, key_dim)
        Returns: (type_logits (B, n_types), target_logits (B, N))
        """
        # v1.4.0 FIX: Blindagem de Dimensão
        if obs.dim() == 1: obs = obs.unsqueeze(0)
        if agent_id.dim() == 0: agent_id = agent_id.unsqueeze(0)
        if host_keys.dim() == 2: host_keys = host_keys.unsqueeze(0)
        
        assert agent_id.max() < MAX_AGENTS, \
            f"agent_id {agent_id.max()} >= MAX_AGENTS {MAX_AGENTS}"
        e = self.emb(agent_id)
        h = self.trunk(torch.cat([obs, e], dim=-1))
        return self.type_head(h), self.pointer(h, host_keys)


class FactoredCritic(nn.Module):
    """Critic centralizado para ações fatoradas.
    Input: global_obs + per-agent (type_onehot + target_embedding).
    MAX_AGENTS slots com padding zero para agentes ausentes."""
    def __init__(self, global_obs_dim: int, n_action_types: int = N_RED_ACTIONS,
                 key_dim: int = 64, hidden: int = 256):
        super().__init__()
        per_agent = n_action_types + key_dim
        input_dim = global_obs_dim + MAX_AGENTS * per_agent
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden), nn.ReLU(),
            nn.Linear(hidden, hidden), nn.ReLU(),
            nn.Linear(hidden, 1))
        self.per_agent_dim = per_agent

    def forward(self, global_obs, joint_action_repr):
        return self.net(torch.cat([global_obs, joint_action_repr], dim=-1))


@dataclass
class RCfg:
    obs_dim: int
    n_action_types: int = N_RED_ACTIONS
    hidden_dim: int = 256
    key_dim: int = 64
    lr_actor: float = 1e-4
    lr_critic: float = 1e-3
    gamma: float = 0.99
    tau: float = 0.01
    n_agents: int = 1
    global_obs_dim: int = 9
    use_gat: bool = False
    gat_node_dim: int = 4
    gat_out: int = 32
    # --- rev8 (auditoria 15/09): contrato da política e modos de treino ---
    # development: permissivo (repeat/resize p/ resiliência) + warning quando
    #              update() rodar SEM máscaras (contrato violado em treino).
    # confirmatory: fail-fast — shapes exatos obrigatórios e máscaras
    #              obrigatórias no update() (erro de contrato vira erro).
    training_mode: str = "development"
    # host_encoder target (E_{psi^-}): consistência do bootstrap; default
    # False p/ compatibilidade com checkpoints existentes (sem pesos novos).
    use_target_host_encoder: bool = False
    # Backward compat (ignored in v4.2)
    action_dim: int = 0
    n_targets: int = 1


class MADDPGAgent:
    """MADDPG com ação fatorada: action_type × pointer(target)."""

    def __init__(self, cfg: RCfg, device: str = "cpu"):
        self.cfg = cfg; self.dev = torch.device(device)
        actor_in = cfg.obs_dim + (cfg.gat_out if cfg.use_gat else 0)
        self.actor = FactoredActor(
            actor_in, cfg.n_action_types, cfg.hidden_dim,
            key_dim=cfg.key_dim).to(self.dev)
        self.actor_t = copy.deepcopy(self.actor)
        self.critic = FactoredCritic(
            cfg.global_obs_dim, cfg.n_action_types,
            cfg.key_dim, cfg.hidden_dim).to(self.dev)
        self.critic_t = copy.deepcopy(self.critic)
        self.host_encoder = HostEncoder(
            HOST_FEAT_DIM, hidden_dim=64, output_dim=cfg.key_dim).to(self.dev)
        self.opt_a = torch.optim.Adam(
            list(self.actor.parameters()) + list(self.host_encoder.parameters()),
            lr=cfg.lr_actor)
        self.opt_c = torch.optim.Adam(self.critic.parameters(), lr=cfg.lr_critic)
        self.gat = None
        if cfg.use_gat:
            self.gat = GATEncoder(cfg.gat_node_dim, 64, cfg.gat_out).to(self.dev)
            self.opt_a.add_param_group({"params": self.gat.parameters()})
        # rev8: encoder de hosts TARGET (opcional; soft-update junto com
        # actor/critic quando habilitado — ver #10 da auditoria)
        self.host_encoder_t = (
            copy.deepcopy(self.host_encoder)
            if cfg.use_target_host_encoder else None)
        self.steps = 0
        self._masks_missing_warned = False

    def _as_float32_array(self, value):
        if isinstance(value, (list, tuple)):
            value = np.stack([np.asarray(v, np.float32) for v in value])
        else:
            value = np.asarray(value, np.float32)
        return np.ascontiguousarray(value)

    def _as_int64_array(self, value):
        arr = np.asarray(value, np.int64)
        return np.ascontiguousarray(np.atleast_1d(arr))

    def _safe_mask_floor(self, dtype: torch.dtype) -> float:
        if dtype in (torch.float16, torch.bfloat16):
            return -1e4
        return -1e8

    def _sanitize_tensor(self, tensor: torch.Tensor, name: str, *, clamp_abs: float | None = None) -> torch.Tensor:
        if torch.isfinite(tensor).all():
            if clamp_abs is not None:
                return tensor.clamp(min=-clamp_abs, max=clamp_abs)
            return tensor
        finite_ratio = float(torch.isfinite(tensor).float().mean().item())
        _log_warning_event(
            "red_nonfinite_tensor_sanitized",
            name=name,
            shape=tuple(tensor.shape),
            finite_ratio=round(finite_ratio, 6),
        )
        # OLD: return tensor
        tensor = torch.nan_to_num(tensor, nan=0.0, posinf=1e4, neginf=-1e4)
        if clamp_abs is not None:
            tensor = tensor.clamp(min=-clamp_abs, max=clamp_abs)
        return tensor

    def _repair_nonfinite_parameters(self) -> int:
        repaired = 0
        modules = [self.actor, self.actor_t, self.critic, self.critic_t, self.host_encoder]
        if self.gat is not None:
            modules.append(self.gat)
        for module in modules:
            for param in module.parameters():
                if torch.isfinite(param).all():
                    continue
                # OLD: parametros Red nao eram reparados apos um update toxico.
                param.data = torch.nan_to_num(param.data, nan=0.0, posinf=1.0, neginf=-1.0)
                repaired += 1
        if repaired:
            _log_warning_event("red_nonfinite_parameters_repaired", repaired_tensors=repaired)
        return repaired

    def _encode_obs(self, obs, adj=None):
        if self.gat is not None and adj is not None:
            B = obs.shape[0]; N = adj.shape[-1]
            nf = torch.zeros(B, N, self.cfg.gat_node_dim, device=self.dev)
            nf[:, :, 0] = 1.0
            return torch.cat([obs, self.gat(nf, adj)], dim=-1)
        return obs

    def _encode_hosts(self, host_features, adjacency):
        """Host features → keys for pointer (B, N, key_dim)."""
        # OLD: hf = torch.tensor(host_features, dtype=torch.float32, device=self.dev)
        hf = torch.from_numpy(self._as_float32_array(host_features)).to(self.dev)
        if hf.dim() == 2: hf = hf.unsqueeze(0)
        # OLD: adj = torch.tensor(adjacency, dtype=torch.float32, device=self.dev)
        adj = torch.from_numpy(self._as_float32_array(adjacency)).to(self.dev)
        if adj.dim() == 2: adj = adj.unsqueeze(0)
        return self.host_encoder(hf, adj)

    def _mask_logits(self, logits: torch.Tensor, mask) -> torch.Tensor:
        if mask is None:
            return logits
        if isinstance(mask, torch.Tensor):
            mask_t = mask.to(device=logits.device)
        else:
            if isinstance(mask, (list, tuple)):
                mask = self._as_float32_array(mask)
            # OLD: mask_t = torch.as_tensor(mask, device=logits.device)
            mask_t = torch.from_numpy(np.asarray(mask, np.float32)).to(logits.device)
        if mask_t.dtype != torch.bool:
            mask_t = mask_t > 0
        if mask_t.dim() == logits.dim() - 1:
            mask_t = mask_t.unsqueeze(0)
        if mask_t.shape != logits.shape:
            raise ValueError(f"mask shape {tuple(mask_t.shape)} incompatible with logits {tuple(logits.shape)}")
        if logits.dim() == 1:
            if not bool(mask_t.any()):
                mask_t = torch.ones_like(mask_t, dtype=torch.bool)
        else:
            empty_rows = ~mask_t.any(dim=-1)
            if empty_rows.any():
                mask_t = mask_t.clone()
                mask_t[empty_rows] = True
        # OLD: floor = torch.finfo(logits.dtype).min
        floor = self._safe_mask_floor(logits.dtype)
        return logits.masked_fill(~mask_t, floor)

    def _select_target_masks(self, target_masks, action_types, batch_size: int):
        if target_masks is None:
            return None
        if isinstance(target_masks, torch.Tensor):
            tm = target_masks.to(self.dev)
        else:
            if isinstance(target_masks, (list, tuple)):
                target_masks = self._as_float32_array(target_masks)
            # OLD: tm = torch.as_tensor(target_masks, device=self.dev)
            tm = torch.from_numpy(np.asarray(target_masks, np.float32)).to(self.dev)
        if tm.dtype != torch.bool:
            tm = tm > 0
        if tm.dim() == 1:
            tm = tm.unsqueeze(0)
        if tm.dim() == 3:
            acts = torch.as_tensor(action_types, dtype=torch.long, device=self.dev).view(-1)
            if tm.shape[0] != batch_size:
                raise ValueError(
                    f"target_masks batch {tuple(tm.shape)} incompatible with batch_size={batch_size}"
                )
            return tm[torch.arange(batch_size, device=self.dev), acts]
        if tm.dim() == 2:
            if tm.shape[0] == 1 and batch_size > 1:
                tm = tm.expand(batch_size, -1)
            if tm.shape[0] != batch_size:
                raise ValueError(
                    f"target_masks shape {tuple(tm.shape)} incompatible with batch_size={batch_size}"
                )
            return tm
        raise ValueError(f"target_masks shape {tuple(tm.shape)} invalida")

    @torch.no_grad()
    def act(self, obs, agent_id, explore=True, eps=0.1, adj=None,
            host_features=None, adjacency=None):
        """Returns (action_type, target_id, info_dict)."""
        # OLD: o = torch.tensor(obs, dtype=torch.float32, device=self.dev).unsqueeze(0)
        o = torch.from_numpy(self._as_float32_array(obs)).unsqueeze(0).to(self.dev)
        a_t = None
        if adj is not None:
            # OLD: a_t = torch.tensor(adj, dtype=torch.float32, device=self.dev).unsqueeze(0)
            a_t = torch.from_numpy(self._as_float32_array(adj)).unsqueeze(0).to(self.dev)
        enc = self._encode_obs(o, a_t)
        # OLD: aid = torch.tensor([agent_id], dtype=torch.long, device=self.dev)
        aid = torch.from_numpy(self._as_int64_array([agent_id])).to(self.dev)

        if host_features is not None and adjacency is not None:
            host_keys = self._encode_hosts(host_features, adjacency)
        else:
            host_keys = torch.zeros(1, 1, self.cfg.key_dim, device=self.dev)

        type_logits, target_logits = self.actor(enc, aid, host_keys)
        type_probs = torch.softmax(type_logits, -1).squeeze(0)
        target_probs = torch.softmax(target_logits, -1).squeeze(0)

        if explore and torch.rand(()).item() < eps:
            action_type = int(torch.randint(self.cfg.n_action_types, (1,)).item())
            target_id = int(torch.randint(target_probs.shape[0], (1,)).item())
        else:
            action_type = int(torch.distributions.Categorical(type_probs).sample())
            target_id = int(torch.distributions.Categorical(target_probs).sample())

        return action_type, target_id, {
            "action_probs": type_probs.cpu().tolist(),
            "target_probs": target_probs.cpu().tolist(),
        }

    @torch.no_grad()
    def batch_act(self, obs_batch, agent_ids, explore=True, eps=0.1, adj_batch=None,
                  host_features=None, adjacency=None, action_masks=None, target_masks=None):
        """Returns action_types, target_ids, info_dict for a batch of agents."""
        # OLD: import numpy as np
        # Usa from_numpy para máxima velocidade
        # OLD: o_t = torch.from_numpy(np.asarray(obs_batch, dtype=np.float32)).to(self.dev)
        o_t = torch.from_numpy(self._as_float32_array(obs_batch)).to(self.dev)
        # OLD: aid_t = torch.from_numpy(np.asarray(agent_ids, dtype=np.int64)).to(self.dev)
        aid_t = torch.from_numpy(self._as_int64_array(agent_ids)).to(self.dev)

        a_t = None
        if adj_batch is not None:
            # OLD: a_t = torch.from_numpy(np.asarray(adj_batch, dtype=np.float32)).to(self.dev)
            a_t = torch.from_numpy(self._as_float32_array(adj_batch)).to(self.dev)
        enc = self._encode_obs(o_t, a_t)

        if host_features is not None and adjacency is not None:
            # OLD: hf_t = torch.from_numpy(np.asarray(host_features, dtype=np.float32)).to(self.dev)
            # OLD: adj_t = torch.from_numpy(np.asarray(adjacency, dtype=np.float32)).to(self.dev)
            # OLD: host_keys = self.host_encoder(hf_t, adj_t)
            host_keys = self._encode_hosts(host_features, adjacency)
        else:
            host_keys = torch.zeros(len(obs_batch), 1, self.cfg.key_dim, device=self.dev)

        type_logits, target_logits = self.actor(enc, aid_t, host_keys)
        # OLD: type_probs = torch.softmax(type_logits, -1)
        # OLD: target_probs = torch.softmax(target_logits, -1)
        action_masks_np = self._as_float32_array(action_masks) if action_masks is not None and not isinstance(action_masks, torch.Tensor) else action_masks
        target_masks_np = self._as_float32_array(target_masks) if target_masks is not None and not isinstance(target_masks, torch.Tensor) else target_masks
        type_logits = self._mask_logits(type_logits, action_masks_np)
        type_probs = torch.softmax(type_logits, -1)

        # v5.0: SEMPRE usar Categorical sampling (exploração por incerteza)
        # Categorical sampling permite explorar baseado nas probabilidades aprendidas
        action_types = torch.distributions.Categorical(type_probs).sample()
        chosen_target_masks = self._select_target_masks(target_masks_np, action_types, len(obs_batch))
        target_logits = self._mask_logits(target_logits, chosen_target_masks)
        target_probs = torch.softmax(target_logits, -1)
        target_ids = torch.distributions.Categorical(target_probs).sample()

        # OLD v4.x: Epsilon-greedy com torch.randint (aleatoriedade pura)
        # B = len(obs_batch)
        # if explore and eps > 0.0:
        #     rand_mask = torch.rand(B, device=self.dev) < eps
        #     rand_types = torch.randint(self.cfg.n_action_types, (B,), device=self.dev)
        #     rand_targets = torch.randint(target_probs.shape[-1], (B,), device=self.dev)
        #     greedy_types = torch.argmax(type_probs, dim=-1)
        #     greedy_targets = torch.argmax(target_probs, dim=-1)
        #     action_types = torch.where(rand_mask, rand_types, greedy_types)
        #     target_ids = torch.where(rand_mask, rand_targets, greedy_targets)
        # else:
        #     action_types = torch.distributions.Categorical(type_probs).sample()
        #     target_ids = torch.distributions.Categorical(target_probs).sample()

        info = {
            "valid_actions": (
                np.asarray(action_masks_np, dtype=np.float32).sum(axis=-1).astype(int).tolist()
                if action_masks_np is not None else [self.cfg.n_action_types] * len(obs_batch)
            ),
            "valid_targets": (
                chosen_target_masks.sum(dim=-1).detach().cpu().numpy().astype(int).tolist()
                if chosen_target_masks is not None else [int(target_logits.shape[-1])] * len(obs_batch)
            ),
        }
        return action_types.cpu().numpy(), target_ids.cpu().numpy(), info

    def update(self, obs_all, nobs_all, global_obs, next_global_obs,
               action_types_all, target_ids_all, rewards, dones,
               host_features, adjacency,
               next_host_features=None, next_adjacency=None,
               weights=None, clip=0.5,
               behavior_clone_coef: float = 0.0,
               behavior_clone_weights=None,
               # OLD: behavior cloning usava sempre action_types_all/target_ids_all como alvo.
               behavior_clone_action_types=None,
               behavior_clone_target_ids=None,
               # OLD: behavior cloning avaliava os labels teacher sempre no estado RL corrente.
               behavior_clone_obs_all=None,
               behavior_clone_host_features=None,
               behavior_clone_adjacency=None,
               # --- rev8 (auditoria #5): mesmo operador de masking do
               # comportamento no update — sem isso o gradiente aproxima
               # pi(a|s) enquanto o comportamento e pi(a|s,M). Formas:
               #   action_masks      (B, NAT)  ou (NAT,)
               #   target_masks      (B, NAT, H) ou (NAT, H)
               #   next_*            idem para s_{t+1}
               action_masks=None, target_masks=None,
               next_action_masks=None, next_target_masks=None):
        """Train with factored actions (v1.4.2 - Blindagem Industrial Robusta)."""
        B = obs_all.shape[0]; N = self.cfg.n_agents
        NAT = self.cfg.n_action_types

        # --- rev8 (#5/#11): máscaras no update + modo confirmatório ---
        confirmatorio = self.cfg.training_mode == "confirmatory"

        def _norm_am(m):
            if m is None:
                return None
            a = self._as_float32_array(m)
            if a.ndim == 1:
                a = np.ascontiguousarray(np.broadcast_to(a, (B, NAT)))
            return torch.from_numpy(a).to(self.dev) > 0

        def _norm_tm(m):
            if m is None:
                return None
            a = self._as_float32_array(m)
            if a.ndim == 2:
                a = np.ascontiguousarray(
                    np.broadcast_to(a, (B, NAT, a.shape[-1])))
            return torch.from_numpy(a).to(self.dev) > 0

        am_b = _norm_am(action_masks)
        tm_b = _norm_tm(target_masks)
        nam_b = _norm_am(next_action_masks)
        nntm_b = _norm_tm(next_target_masks)
        if am_b is None or tm_b is None or nam_b is None or nntm_b is None:
            if confirmatorio:
                raise ValueError(
                    "modo confirmatory exige action/target/next_*_masks no "
                    "update() — o contrato e pi(a|s,M); o replay precisa "
                    "armazena-las")
            if not self._masks_missing_warned:
                self._masks_missing_warned = True
                _log_warning_event(
                    "red_update_without_action_masks",
                    nota="update() sem máscaras: gradiente aproximando "
                         "pi(a|s) enquanto o comportamento e pi(a|s,M); "
                         "passe action_masks/target_masks/next_* quando o "
                         "replay armazenar")
        
        # --- FIX OVERCYBER: NORMALIZAÇÃO MANDATÓRIA (B, N, D) ---
        # Garantir que observações tenham sempre 3 dimensões (Batch, Agentes, Features)
        if obs_all.ndim == 2:
            # Caso tenha colapsado para (B, D), assumimos que todas as observações são do primeiro agente
            # ou que o batch veio de um único agente. Ajustamos para (B, N, D) via reshape/repeat
            obs_all = obs_all[:, np.newaxis, :]
        if nobs_all.ndim == 2:
            nobs_all = nobs_all[:, np.newaxis, :]
            
        # Se após o ajuste o número de agentes não bater, forçamos o preenchimento ou trigger de erro
        if obs_all.shape[1] != N:
            # v1.4.2: Resiliência MARL - Se o motor enviou menos agentes, repetimos a obs (placeholder seguro)
            if obs_all.shape[1] == 1:
                if confirmatorio:
                    # rev8 (#11): erro de contrato NAO vira dado sintetico
                    raise ValueError(
                        f"[confirmatory] obs_all {obs_all.shape} != (B,{N},D)"
                        " — repeat desativado no modo confirmatorio")
                obs_all = np.repeat(obs_all, N, axis=1)
                nobs_all = np.repeat(nobs_all, N, axis=1)
            else:
                raise ValueError(f"Shape de obs_all {obs_all.shape} incompatível com n_agents={N}")

        # Garantir que action_types e target_ids tenham formato (B, N)
        if action_types_all.ndim == 1:
            action_types_all = action_types_all[:, np.newaxis]
        if target_ids_all.ndim == 1:
            target_ids_all = target_ids_all[:, np.newaxis]
        
        if action_types_all.shape[1] != N:
            action_types_all = np.repeat(action_types_all, N, axis=1)
            target_ids_all = np.repeat(target_ids_all, N, axis=1)

        obs_all_np = self._as_float32_array(obs_all)
        nobs_all_np = self._as_float32_array(nobs_all)
        # OLD: bc_obs_all_np = obs_all_np
        bc_obs_all_np = self._as_float32_array(
            behavior_clone_obs_all if behavior_clone_obs_all is not None else obs_all
        )
        if bc_obs_all_np.ndim == 2:
            bc_obs_all_np = bc_obs_all_np[:, np.newaxis, :]
        if bc_obs_all_np.shape[1] != N:
            if bc_obs_all_np.shape[1] == 1:
                bc_obs_all_np = np.repeat(bc_obs_all_np, N, axis=1)
            else:
                raise ValueError(
                    f"Shape de behavior_clone_obs_all {bc_obs_all_np.shape} incompatível com n_agents={N}"
                )
        global_obs_np = self._as_float32_array(global_obs)
        next_global_obs_np = self._as_float32_array(next_global_obs)
        action_types_np = self._as_int64_array(action_types_all)
        target_ids_np = self._as_int64_array(target_ids_all)
        # OLD: bc_action_types_np = action_types_np
        # OLD: bc_target_ids_np = target_ids_np
        bc_action_types_np = self._as_int64_array(
            behavior_clone_action_types if behavior_clone_action_types is not None else action_types_all
        )
        bc_target_ids_np = self._as_int64_array(
            behavior_clone_target_ids if behavior_clone_target_ids is not None else target_ids_all
        )
        if bc_action_types_np.ndim == 1:
            bc_action_types_np = bc_action_types_np[:, np.newaxis]
        if bc_target_ids_np.ndim == 1:
            bc_target_ids_np = bc_target_ids_np[:, np.newaxis]
        if bc_action_types_np.shape[1] != N:
            bc_action_types_np = np.repeat(bc_action_types_np, N, axis=1)
            bc_target_ids_np = np.repeat(bc_target_ids_np, N, axis=1)
        rewards_np = self._as_float32_array(rewards)
        dones_np = self._as_float32_array(dones)
        behavior_clone_coef_f = max(0.0, float(behavior_clone_coef or 0.0))
        if behavior_clone_weights is None:
            behavior_clone_weights_np = np.ones((B,), dtype=np.float32)
        else:
            behavior_clone_weights_np = self._as_float32_array(behavior_clone_weights).reshape(-1)
            if behavior_clone_weights_np.shape[0] != B:
                if confirmatorio:
                    # rev8 (#11): sem resize silencioso no modo confirmatorio
                    raise ValueError(
                        f"[confirmatory] behavior_clone_weights "
                        f"{behavior_clone_weights_np.shape[0]} != batch {B}")
                behavior_clone_weights_np = np.resize(behavior_clone_weights_np, B).astype(np.float32, copy=False)


        # OLD: o_all = torch.tensor(obs_all, dtype=torch.float32, device=self.dev)
        o_all = torch.from_numpy(obs_all_np).to(self.dev)
        # OLD: no_all = torch.tensor(nobs_all, dtype=torch.float32, device=self.dev)
        no_all = torch.from_numpy(nobs_all_np).to(self.dev)
        # OLD: BC reutilizava o_all mesmo quando o teacher descrevia o estado pos-transicao.
        bc_o_all = torch.from_numpy(bc_obs_all_np).to(self.dev)
        # OLD: go = torch.tensor(global_obs, dtype=torch.float32, device=self.dev)
        go = torch.from_numpy(global_obs_np).to(self.dev)
        # OLD: ngo = torch.tensor(next_global_obs, dtype=torch.float32, device=self.dev)
        ngo = torch.from_numpy(next_global_obs_np).to(self.dev)
        # OLD: at_all = torch.tensor(action_types_all, dtype=torch.int64, device=self.dev)
        at_all = torch.from_numpy(action_types_np).to(self.dev)
        # OLD: tgt_all = torch.tensor(target_ids_all, dtype=torch.int64, device=self.dev)
        tgt_all = torch.from_numpy(target_ids_np).to(self.dev)
        # OLD: behavior cloning reutilizava at_all/tgt_all, impossibilitando demonstracao teacher sem alterar critic.
        bc_at_all = torch.from_numpy(bc_action_types_np).to(self.dev)
        bc_tgt_all = torch.from_numpy(bc_target_ids_np).to(self.dev)
        # OLD: r = torch.tensor(rewards, dtype=torch.float32, device=self.dev).unsqueeze(-1)
        r = torch.from_numpy(rewards_np).to(self.dev).unsqueeze(-1)
        r = self._sanitize_tensor(r, "red_rewards", clamp_abs=1e6)
        # OLD: d = torch.tensor(dones, dtype=torch.float32, device=self.dev).unsqueeze(-1)
        d = torch.from_numpy(dones_np).to(self.dev).unsqueeze(-1)
        d = self._sanitize_tensor(d, "red_dones", clamp_abs=1.0)

        # Encode host features — BATCHED (B, NH, key_dim)
        # Critic path: detached (no gradient through encoder for critic update)
        host_keys_det = self._encode_hosts(host_features, adjacency).detach()
        # v1.4.0 FIX: Blindagem do expand para lotes unitários
        if host_keys_det.shape[0] == 1 and B > 1: host_keys_det = host_keys_det.expand(B, -1, -1)
        elif host_keys_det.shape[0] != B: host_keys_det = host_keys_det.expand(B, -1, -1)

        # PATCH 3: Encode NEXT state host features for target bootstrap (always detached)
        if next_host_features is not None and next_adjacency is not None:
            if self.host_encoder_t is not None:
                # rev8 (#10): bootstrap com encoder TARGET E_{psi^-}
                nhf = torch.from_numpy(self._as_float32_array(next_host_features)).to(self.dev)
                if nhf.dim() == 2:
                    nhf = nhf.unsqueeze(0)
                nadj = torch.from_numpy(self._as_float32_array(next_adjacency)).to(self.dev)
                if nadj.dim() == 2:
                    nadj = nadj.unsqueeze(0)
                next_host_keys = self.host_encoder_t(nhf, nadj).detach()
            else:
                next_host_keys = self._encode_hosts(next_host_features, next_adjacency).detach()
            # v1.4.0 FIX: Blindagem do expand para lotes unitários (Next State)
            if next_host_keys.shape[0] == 1 and B > 1: next_host_keys = next_host_keys.expand(B, -1, -1)
            elif next_host_keys.shape[0] != B: next_host_keys = next_host_keys.expand(B, -1, -1)
        else:
            next_host_keys = host_keys_det

        # rev8 (#9): encoding GAT do estado TAMBÉM no update — antes o actor
        # recebia obs CRUA com use_gat=True (erro latente de dimensão)
        def _adj_b(adj):
            if self.gat is None:
                return None
            a = torch.from_numpy(self._as_float32_array(
                adj if adj is not None else adjacency)).to(self.dev)
            if a.dim() == 2:
                a = a.unsqueeze(0)
            if a.shape[0] == 1 and B > 1:
                a = a.expand(B, -1, -1)
            return a

        def _enc(o, adj_b):
            return self._encode_obs(o, adj_b) if adj_b is not None else o

        adj_next_b = _adj_b(next_adjacency)
        adj_cur_b = _adj_b(adjacency)
        adj_bc_b = _adj_b(
            behavior_clone_adjacency
            if behavior_clone_adjacency is not None else adjacency)

        def _joint(type_idx, tgt_idx, hk):
            parts = []
            for i in range(MAX_AGENTS):
                if i < N:
                    t_oh = F.one_hot(type_idx[:, i], NAT).float()
                    ti = tgt_idx[:, i].unsqueeze(-1).unsqueeze(-1).expand(-1, -1, hk.shape[-1])
                    t_emb = hk.gather(1, ti).squeeze(1)
                    parts.append(torch.cat([t_oh, t_emb], dim=-1))
                else:
                    parts.append(torch.zeros(B, NAT + self.cfg.key_dim, device=self.dev))
            return torch.cat(parts, dim=-1)

        joint_repr = _joint(at_all, tgt_all, host_keys_det)

        # Critic update — target uses NEXT host_keys (detached)
        with torch.no_grad():
            nat_l, ntgt_l = [], []
            for i in range(N):
                aid_t = torch.full((B,), i, dtype=torch.long, device=self.dev)
                tl, ptl = self.actor_t(_enc(no_all[:, i], adj_next_b), aid_t,
                                       next_host_keys)
                # rev8 (#5): MESMO operador de masking do comportamento no
                # bootstrap — a' = argmax Mask(pi_theta^-(s'), M')
                tl = self._mask_logits(tl, nam_b)
                nat = torch.argmax(tl, -1)
                nat_l.append(nat)
                sel_tm = (self._select_target_masks(nntm_b, nat, B)
                          if nntm_b is not None else None)
                ptl = self._mask_logits(ptl, sel_tm)
                ntgt_l.append(torch.argmax(ptl, -1))
            nj = _joint(torch.stack(nat_l, 1), torch.stack(ntgt_l, 1), next_host_keys)
            target = r + self.cfg.gamma * (1 - d) * self.critic_t(ngo, nj)
            target = self._sanitize_tensor(target, "red_critic_target", clamp_abs=1e6)

        qp = self.critic(go, joint_repr)
        qp = self._sanitize_tensor(qp, "red_critic_prediction", clamp_abs=1e6)
        td = torch.nan_to_num((qp - target).abs().detach(), nan=0.0, posinf=1e6, neginf=1e6).cpu().numpy().flatten()
        # OLD: cl = F.mse_loss(qp, target) if weights is None else \
        # OLD:     (torch.tensor(weights, dtype=torch.float32, device=self.dev).unsqueeze(-1) * (qp - target)**2).mean()
        # OLD: cl = F.mse_loss(qp, target) if weights is None else \
        # OLD:     (torch.from_numpy(self._as_float32_array(weights)).to(self.dev).unsqueeze(-1) * (qp - target)**2).mean()
        if weights is None:
            cl = F.mse_loss(qp, target)
        else:
            w_t = torch.from_numpy(self._as_float32_array(weights)).to(self.dev).unsqueeze(-1)
            w_t = self._sanitize_tensor(w_t, "red_importance_weights", clamp_abs=1e4).clamp_min(0.0)
            cl = (w_t * (qp - target).pow(2)).mean()

        critic_grad_norm = 0.0
        red_nonfinite_update_skips = 0
        if not torch.isfinite(cl):
            _log_warning_event("red_critic_nonfinite_loss_skipped", critic_loss=float(torch.nan_to_num(cl.detach(), nan=0.0).item()))
            self.opt_c.zero_grad(set_to_none=True)
            red_nonfinite_update_skips += 1
        else:
            # OLD: self.opt_c.zero_grad(); cl.backward()
            self.opt_c.zero_grad(); cl.backward()
            critic_grad_norm = float(nn.utils.clip_grad_norm_(self.critic.parameters(), clip))
            if not math.isfinite(critic_grad_norm):
                _log_warning_event("red_critic_nonfinite_grad_norm_skipped")
                self.opt_c.zero_grad(set_to_none=True)
                red_nonfinite_update_skips += 1
            else:
                # OLD: nn.utils.clip_grad_norm_(self.critic.parameters(), clip); self.opt_c.step()
                self.opt_c.step()

        # Actor update — RE-ENCODE with live graph for gradient flow into HostEncoder
        host_keys_live = self._encode_hosts(host_features, adjacency)
        if host_keys_live.shape[0] == 1: host_keys_live = host_keys_live.expand(B, -1, -1)
        # OLD: host_keys_live tambem era usado para labels teacher gerados no next_state.
        if behavior_clone_host_features is not None and behavior_clone_adjacency is not None:
            bc_host_keys_live = self._encode_hosts(
                behavior_clone_host_features,
                behavior_clone_adjacency,
            )
            if bc_host_keys_live.shape[0] == 1:
                bc_host_keys_live = bc_host_keys_live.expand(B, -1, -1)
            elif bc_host_keys_live.shape[0] != B:
                bc_host_keys_live = bc_host_keys_live.expand(B, -1, -1)
        else:
            bc_host_keys_live = host_keys_live
        total_al = 0.0
        total_bc = torch.zeros((), device=self.dev)
        bc_w = torch.from_numpy(behavior_clone_weights_np).to(self.dev).clamp_min(0.0)
        bc_norm = bc_w.sum().clamp_min(1e-6)
        bc_enabled = bool(behavior_clone_coef_f > 0.0 and float(bc_w.sum().detach().cpu()) > 0.0)
        for i in range(N):
            aid_t = torch.full((B,), i, dtype=torch.long, device=self.dev)
            tl, ptl = self.actor(_enc(o_all[:, i], adj_cur_b), aid_t,
                                 host_keys_live)
            # rev8 (#5): GumbelSoftmax sobre logits MASCARADOS — mesmo
            # operador do comportamento; linha de alvo selecionada pela
            # ação hard do straight-through gumbel
            tl = self._mask_logits(tl, am_b)
            tg = F.gumbel_softmax(tl, tau=1.0, hard=True)
            sel_tm = (self._select_target_masks(tm_b, tg.argmax(-1), B)
                      if tm_b is not None else None)
            ptl = self._mask_logits(ptl, sel_tm)
            pg = F.gumbel_softmax(ptl, tau=1.0, hard=True)
            te = torch.bmm(pg.unsqueeze(1), host_keys_live).squeeze(1)
            parts = []
            for j in range(MAX_AGENTS):
                if j == i:
                    parts.append(torch.cat([tg, te], dim=-1))
                elif j < N:
                    s, e = j*(NAT+self.cfg.key_dim), (j+1)*(NAT+self.cfg.key_dim)
                    parts.append(joint_repr[:, s:e].detach())
                else:
                    parts.append(torch.zeros(B, NAT+self.cfg.key_dim, device=self.dev))
            total_al += -self.critic(go.detach(), torch.cat(parts, -1)).mean()
            if bc_enabled:
                # OLD: o ator Red aprendia apenas via critic; guidance/option ficava no replay sem loss direto de imitacao.
                # OLD: type_ce e target_ce usavam tl/ptl calculados sobre o estado RL corrente.
                bc_tl, bc_ptl = self.actor(_enc(bc_o_all[:, i], adj_bc_b),
                                           aid_t, bc_host_keys_live)
                bc_tl = self._mask_logits(bc_tl, am_b)
                bc_sel = (self._select_target_masks(tm_b, bc_at_all[:, i], B)
                          if tm_b is not None else None)
                bc_ptl = self._mask_logits(bc_ptl, bc_sel)
                # OLD: bc_type_targets = at_all[:, i].clamp(min=0, max=NAT - 1)
                # OLD: bc_target_targets = tgt_all[:, i].clamp(min=0, max=ptl.shape[-1] - 1)
                bc_type_targets = bc_at_all[:, i].clamp(min=0, max=NAT - 1)
                bc_target_targets = bc_tgt_all[:, i].clamp(min=0, max=bc_ptl.shape[-1] - 1)
                type_ce = F.cross_entropy(bc_tl, bc_type_targets, reduction="none")
                target_ce = F.cross_entropy(bc_ptl, bc_target_targets, reduction="none")
                total_bc = total_bc + ((type_ce + target_ce) * bc_w).sum() / bc_norm

        # OLD: self.opt_a.zero_grad(); total_al.backward()
        total_actor_loss = total_al + (behavior_clone_coef_f * total_bc)
        actor_grad_norm = 0.0
        if not torch.isfinite(total_actor_loss):
            _log_warning_event(
                "red_actor_nonfinite_loss_skipped",
                actor_loss=float(torch.nan_to_num(total_actor_loss.detach(), nan=0.0).item()),
                behavior_clone_loss=float(torch.nan_to_num(total_bc.detach(), nan=0.0).item()),
            )
            self.opt_a.zero_grad(set_to_none=True)
            red_nonfinite_update_skips += 1
        else:
            # OLD: self.opt_a.zero_grad(); total_actor_loss.backward()
            self.opt_a.zero_grad(); total_actor_loss.backward()
            actor_params = list(self.actor.parameters()) + list(self.host_encoder.parameters())
            if self.gat is not None:
                actor_params.extend(self.gat.parameters())
            actor_grad_norm = float(nn.utils.clip_grad_norm_(actor_params, clip))
            if not math.isfinite(actor_grad_norm):
                _log_warning_event("red_actor_nonfinite_grad_norm_skipped")
                self.opt_a.zero_grad(set_to_none=True)
                red_nonfinite_update_skips += 1
            else:
                # OLD: nn.utils.clip_grad_norm_(self.actor.parameters(), clip)
                # OLD: nn.utils.clip_grad_norm_(self.host_encoder.parameters(), clip)
                self.opt_a.step()

        # Soft update
        for p, pt in zip(self.actor.parameters(), self.actor_t.parameters()):
            pt.data.copy_(self.cfg.tau * p.data + (1 - self.cfg.tau) * pt.data)
        for p, pt in zip(self.critic.parameters(), self.critic_t.parameters()):
            pt.data.copy_(self.cfg.tau * p.data + (1 - self.cfg.tau) * pt.data)
        if self.host_encoder_t is not None:
            # rev8 (#10): E_{psi^-} acompanha o soft update
            for p, pt in zip(self.host_encoder.parameters(),
                             self.host_encoder_t.parameters()):
                pt.data.copy_(self.cfg.tau * p.data + (1 - self.cfg.tau) * pt.data)
        repaired_param_tensors = self._repair_nonfinite_parameters()
        self.steps += 1
        result = {
            "critic_loss": float(torch.nan_to_num(cl.detach(), nan=0.0).item()),
            "actor_loss": float(torch.nan_to_num((total_al.detach() / N), nan=0.0).item()),
            "critic_grad_norm": float(critic_grad_norm),
            "actor_grad_norm": float(actor_grad_norm),
            "red_nonfinite_update_skips": int(red_nonfinite_update_skips),
            "red_repaired_param_tensors": int(repaired_param_tensors),
        }
        if behavior_clone_coef_f > 0.0:
            result["behavior_clone_loss"] = float(total_bc.detach() / max(1, N))
            result["behavior_clone_coef"] = float(behavior_clone_coef_f)
        return result, td
