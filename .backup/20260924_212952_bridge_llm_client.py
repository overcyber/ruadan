"""
Cliente Multi-LLM Plugável para Ruadan + red-MPPO.

Suporta de forma transparente:
- Ollama local (qwen3:8b, gpt-oss:20b)
- Google Gemini (gemini-2.5-pro, gemini-2.5-flash, gemini-1.5-pro)
- OpenAI (gpt-4o, gpt-4o-mini, o3-mini)
- Anthropic Claude (claude-3-7-sonnet, claude-3-5-sonnet, claude-3-5-haiku)
- DeepSeek (deepseek-chat, deepseek-reasoner)
- NVIDIA NIM (meta/llama-3.3-70b-instruct, mistralai/mistral-large-2-instruct, nemotron)
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path("/app/configs/llm_config.yaml")
LOCAL_CONFIG_PATH = Path(__file__).resolve().parent.parent / "configs" / "llm_config.yaml"


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[dict] = field(default_factory=list)
    raw_response: dict = field(default_factory=dict)
    provider: str = ""
    model: str = ""
    latency_ms: int = 0


class MultiLLMClient:
    def __init__(self, provider: str | None = None, model: str | None = None,
                 config_path: Path | str | None = None, timeout: int = 90):
        self.config = self._load_config(config_path)
        self.provider = (provider or os.environ.get("LLM_PROVIDER") or self.config.get("active_provider", "ollama")).lower()

        prov_cfg = self.config.get("providers", {}).get(self.provider, {})
        default_model = prov_cfg.get("default_model", "qwen3:8b")
        self.model = model or os.environ.get("LLM_MODEL") or default_model
        self.timeout = prov_cfg.get("timeout", timeout)

        self.api_base = self._resolve_api_base(prov_cfg)
        self.api_key = self._resolve_api_key(prov_cfg)

    def _load_config(self, config_path: Path | str | None) -> dict:
        candidates = []
        if config_path:
            candidates.append(Path(config_path))
        candidates.extend([LOCAL_CONFIG_PATH, DEFAULT_CONFIG_PATH])

        for p in candidates:
            if p.is_file():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        return yaml.safe_load(f) or {}
                except Exception:
                    pass
        return {}

    def _resolve_api_base(self, prov_cfg: dict) -> str:
        # Prioriza variável de ambiente específica do provedor
        env_base_var = f"{self.provider.upper()}_API_BASE"
        if os.environ.get(env_base_var):
            return os.environ[env_base_var].rstrip("/")

        if self.provider == "ollama" and os.environ.get("OLLAMA_API_BASE"):
            return os.environ["OLLAMA_API_BASE"].rstrip("/")

        return prov_cfg.get("base_url", "http://localhost:11434/v1").rstrip("/")

    def _resolve_api_key(self, prov_cfg: dict) -> str:
        env_key_var = prov_cfg.get("api_key_env")
        if env_key_var and os.environ.get(env_key_var):
            return os.environ[env_key_var]

        # Checagens diretas
        direct_env = f"{self.provider.upper()}_API_KEY"
        if os.environ.get(direct_env):
            return os.environ[direct_env]

        return prov_cfg.get("api_key_default", "ollama")

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             temperature: float = 0.2, max_retries: int = 3) -> LLMResponse:
        """Envia mensagem ao provedor ativo e retorna resposta padronizada."""
        if self.provider == "anthropic":
            return self._call_anthropic(messages, tools, temperature, max_retries)
        return self._call_openai_compatible(messages, tools, temperature, max_retries)

    def _base_resolvable(self, base: str) -> bool:
        """Verifica se o hostname da base URL resolve neste contexto de rede.

        Em --network host (Linux), o DNS interno do Docker (127.0.0.11) não
        existe — hostnames como 'ruadan-ollama' ou 'host.docker.internal' não
        resolvem, mesmo que o serviço esteja acessível via localhost (porta
        publicada). Bases não-resolvíveis são puladas no failover.
        """
        try:
            hn = urllib.parse.urlparse(base).hostname
            if not hn:
                return False
            if hn == "localhost" or hn in ("127.0.0.1", "::1") or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hn):
                return True  # loopback/IP literal: sempre resolvível
            socket.getaddrinfo(hn, None)
            return True
        except Exception:
            return False

    def _call_openai_compatible(self, messages: list[dict], tools: list[dict] | None,
                                temperature: float, max_retries: int) -> LLMResponse:
        """Interface padrão OpenAI (utilizada por Ollama, OpenAI, DeepSeek, Google e NVIDIA NIM)."""
        raw_candidates = [self.api_base]
        if self.provider == "ollama":
            for fallback in [
                "http://localhost:11434/v1",
                "http://127.0.0.1:11434/v1",
                "http://ruadan-ollama:11434/v1",
                "http://host.docker.internal:11434/v1",
            ]:
                if fallback not in raw_candidates:
                    raw_candidates.append(fallback)

        # Filtra candidatos resolvíveis para evitar falhas falsas de DNS ([Errno -2])
        candidate_bases = [b for b in raw_candidates if self._base_resolvable(b)]
        if not candidate_bases:
            candidate_bases = [self.api_base]

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False
        }
        if tools:
            payload["tools"] = tools

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        last_error = None
        last_endpoint = candidate_bases[0]
        total_attempts = max(max_retries, len(candidate_bases)) if self.provider == "ollama" else max_retries

        for attempt in range(total_attempts):
            current_base = candidate_bases[attempt % len(candidate_bases)]
            last_endpoint = current_base

            url = f"{current_base}/chat/completions"
            t0 = time.monotonic()
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )

            # Para loopback/localhost, isola o proxy para evitar que proxies de ambiente bloqueiem a porta 11434
            hn = urllib.parse.urlparse(current_base).hostname or ""
            is_local = hn in ("localhost", "127.0.0.1", "::1")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if is_local else urllib.request.build_opener()

            # Notifica imediatamente o envio do prompt para streaming em tempo real no visualizador de logs
            self._log_request_start(current_base, messages)

            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    latency = int((time.monotonic() - t0) * 1000)
                    body = json.loads(resp.read().decode("utf-8"))

                choices = body.get("choices", [])
                if not choices:
                    raise ValueError(f"Resposta de {self.provider} sem 'choices'")

                msg = choices[0].get("message", {})
                content = msg.get("content") or ""
                # Suporte para modelos de raciocínio (qwen3:8b) que entregam pensamento em 'reasoning'
                if not content and msg.get("reasoning"):
                    content = msg.get("reasoning")
                elif not content and msg.get("reasoning_content"):
                    content = msg.get("reasoning_content")

                tool_calls = msg.get("tool_calls") or []

                if self.provider == "ollama":
                    self.api_base = current_base

                self._log_interaction(
                    endpoint=current_base,
                    messages=messages,
                    response_content=content,
                    latency_ms=latency,
                    status="SUCCESS"
                )

                return LLMResponse(
                    content=content,
                    tool_calls=tool_calls,
                    raw_response=body,
                    provider=self.provider,
                    model=self.model,
                    latency_ms=latency
                )
            except urllib.error.HTTPError as he:
                try:
                    err_body = he.read().decode("utf-8")
                    err_json = json.loads(err_body)
                    err_msg = err_json.get("error") or err_body
                except Exception:
                    err_msg = str(he)
                last_error = RuntimeError(f"HTTP {he.code} de {current_base}: {err_msg}")
                # 404 significa que o endpoint existe mas o modelo não está carregado no Ollama
                if he.code == 404:
                    break
                time.sleep(1 + (attempt % 3))
            except Exception as e:
                last_error = e
                time.sleep(1 + (attempt % 3))

        self._log_interaction(
            endpoint=last_endpoint,
            messages=messages,
            response_content="",
            latency_ms=0,
            status="FAILED",
            error=str(last_error)
        )

        raise RuntimeError(f"Falha ao consultar {self.provider} ({self.model}) em {last_endpoint}: {last_error}")

    def _write_log_entry(self, entry: str):
        """Grava uma entrada de log imediatamente com flush e sync em todos os diretórios conhecidos."""
        target_dirs = []
        if os.environ.get("RUADAN_OUTPUT_DIR"):
            p = Path(os.environ["RUADAN_OUTPUT_DIR"])
            target_dirs.extend([p, p / "ai_evidence"])

        for base in [
            "/ruadan/output",
            "/output",
            "/root_output",
            "/system/ruadan-new/output",
            "/system/ruadan-new/ruadan/output",
            "output",
            "ruadan/output",
        ]:
            p = Path(base)
            if p.exists() or p.parent.exists():
                target_dirs.extend([p, p / "ai_evidence"])

        written = set()
        for d in target_dirs:
            try:
                d.mkdir(parents=True, exist_ok=True)
                for fname in ["ollama_interactions.log", "ollama_client.log"]:
                    log_file = d / fname
                    res_path = str(log_file.resolve())
                    if res_path not in written:
                        written.add(res_path)
                        with open(log_file, "a", encoding="utf-8") as f:
                            f.write(entry)
                            f.flush()
                            try:
                                os.fsync(f.fileno())
                            except Exception:
                                pass
            except Exception:
                pass

    def _log_request_start(self, endpoint: str, messages: list[dict]):
        """Grava imediatamente o envio do prompt no log para streaming em tempo real com tail -F."""
        now = datetime.now().isoformat()
        msg_lines = []
        for m in messages:
            role = m.get("role", "unknown").upper()
            txt = (m.get("content") or "").strip()
            msg_lines.append(f"[{role}]:\n{txt}")
        full_prompt = "\n\n".join(msg_lines)

        entry = (
            f"================================================================================\n"
            f"TIMESTAMP: {now} | STATUS: ENVIANDO_PROMPT... | PROVEDOR: {self.provider} | MODELO: {self.model}\n"
            f"ENDPOINT:  {endpoint}\n"
            f"-------------------------------- [PROMPT ENVIADO] ------------------------------\n"
            f"{full_prompt}\n"
            f"------------------------------- [STATUS DO MODELO] ----------------------------\n"
            f"[*] Requisição enviada. Aguardando geração de resposta pelo modelo {self.model}...\n"
            f"================================================================================\n\n"
        )
        self._write_log_entry(entry)

    def _log_interaction(self, endpoint: str, messages: list[dict], response_content: str,
                         latency_ms: int, status: str = "SUCCESS", error: str | None = None):
        """Grava log contínuo e legível da conclusão da interação com o LLM."""
        now = datetime.now().isoformat()
        entry = (
            f"================================================================================\n"
            f"TIMESTAMP: {now} | STATUS: {status} | PROVEDOR: {self.provider} | MODELO: {self.model}\n"
            f"ENDPOINT:  {endpoint} | LATÊNCIA: {latency_ms}ms\n"
            f"------------------------------- [RESPOSTA RECEBIDA] ----------------------------\n"
            f"{response_content if status == 'SUCCESS' else f'ERRO: {error}'}\n"
            f"================================================================================\n\n"
        )
        self._write_log_entry(entry)

    def _call_anthropic(self, messages: list[dict], tools: list[dict] | None,
                        temperature: float, max_retries: int) -> LLMResponse:
        """Adaptador para a API nativa da Anthropic (/v1/messages)."""
        url = f"{self.api_base}/messages"

        # Separa a mensagem de sistema
        system_content = ""
        user_assistant_msgs = []
        for m in messages:
            if m.get("role") == "system":
                system_content = m.get("content", "")
            else:
                user_assistant_msgs.append({"role": m.get("role"), "content": m.get("content")})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": user_assistant_msgs,
            "max_tokens": 4096,
            "temperature": temperature
        }
        if system_content:
            payload["system"] = system_content

        if tools:
            # Converte formato OpenAI tool -> Anthropic tool
            anthropic_tools = []
            for t in tools:
                fn = t.get("function", {})
                anthropic_tools.append({
                    "name": fn.get("name"),
                    "description": fn.get("description", ""),
                    "input_schema": fn.get("parameters", {"type": "object", "properties": {}})
                })
            payload["tools"] = anthropic_tools

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }

        last_error = None
        for attempt in range(max_retries):
            t0 = time.monotonic()
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    latency = int((time.monotonic() - t0) * 1000)
                    body = json.loads(resp.read().decode("utf-8"))

                content_blocks = body.get("content", [])
                text_content = ""
                tool_calls = []

                for block in content_blocks:
                    if block.get("type") == "text":
                        text_content += block.get("text", "")
                    elif block.get("type") == "tool_use":
                        tool_calls.append({
                            "id": block.get("id"),
                            "type": "function",
                            "function": {
                                "name": block.get("name"),
                                "arguments": json.dumps(block.get("input", {}))
                            }
                        })

                return LLMResponse(
                    content=text_content,
                    tool_calls=tool_calls,
                    raw_response=body,
                    provider="anthropic",
                    model=self.model,
                    latency_ms=latency
                )
            except Exception as e:
                last_error = e
                time.sleep(2 * (attempt + 1))

        raise RuntimeError(f"Falha na API da Anthropic ({self.model}) após {max_retries} tentativas: {last_error}")
