"""
Módulo de Verificação por Canários e Auditoria Criptográfica SHA256.

Garante que ações de teste e enumeração do Ruadan só sejam consideradas bem-sucedidas
mediante evidência executável inequívoca (canários), prevenindo falsos positivos.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

CANARY_PREFIX = "PENTEST_CANARY_"


@dataclass
class CanaryEvidence:
    token: str
    verified: bool
    evidence_file: str | None = None
    sha256: str | None = None
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CanaryVerifier:
    def __init__(self, evidence_dir: Path | str):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.evidence_dir / "evidence_manifest.json"
        self.manifest: list[dict] = []
        if self.manifest_path.is_file():
            try:
                self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            except Exception:
                self.manifest = []

    def generate_token(self, label: str = "") -> str:
        """Gera um token canário único com prefixo identificador."""
        hex_suffix = secrets.token_hex(8)
        clean_label = f"_{label}" if label else ""
        return f"{CANARY_PREFIX}{clean_label}_{hex_suffix}"

    def verify_token_in_output(self, token: str, output: str, action_label: str = "generic") -> CanaryEvidence:
        """Verifica se o token canário retornou exatamente na saída do comando."""
        verified = token in output
        evidence_file = None
        digest = None

        if verified:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            evidence_filename = f"canary_{action_label}_{timestamp}.txt"
            p = self.evidence_dir / evidence_filename
            p.write_text(output, encoding="utf-8")
            digest = hashlib.sha256(output.encode("utf-8")).hexdigest()
            evidence_file = str(p)

            manifest_entry = {
                "token": token,
                "label": action_label,
                "file": str(p.name),
                "sha256": digest,
                "bytes": len(output.encode("utf-8")),
                "ts": datetime.now(timezone.utc).isoformat(),
            }
            self.manifest.append(manifest_entry)
            self._save_manifest()

        return CanaryEvidence(
            token=token,
            verified=verified,
            evidence_file=evidence_file,
            sha256=digest,
            detail="Token confirmado na saída de execução" if verified else "Token ausente na resposta (falso positivo descartado)"
        )

    def verify_root_privilege(self, uid_output: str, action_label: str = "privesc_check") -> CanaryEvidence:
        """Verifica se o retorno de id -u é estritamente 0 (root)."""
        clean = uid_output.strip()
        lines = [line.strip() for line in clean.splitlines() if line.strip()]
        verified = False
        for line in lines:
            if line == "0" or "uid=0(root)" in line:
                verified = True
                break

        token = self.generate_token("root_verify")
        evidence_file = None
        digest = None

        if verified:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            evidence_filename = f"root_confirmed_{timestamp}.txt"
            p = self.evidence_dir / evidence_filename
            p.write_text(uid_output, encoding="utf-8")
            digest = hashlib.sha256(uid_output.encode("utf-8")).hexdigest()
            evidence_file = str(p)

            manifest_entry = {
                "token": token,
                "label": action_label,
                "file": str(p.name),
                "sha256": digest,
                "bytes": len(uid_output.encode("utf-8")),
                "ts": datetime.now(timezone.utc).isoformat(),
                "root_confirmed": True
            }
            self.manifest.append(manifest_entry)
            self._save_manifest()

        return CanaryEvidence(
            token=token,
            verified=verified,
            evidence_file=evidence_file,
            sha256=digest,
            detail="Acesso root (UID=0) confirmado executavelmente" if verified else "Acesso root não confirmado"
        )

    def save_and_hash_evidence(self, label: str, filename: str, content: str) -> dict:
        """Registra e calcula hash SHA256 de qualquer evidência relevante."""
        p = self.evidence_dir / filename
        p.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

        entry = {
            "label": label,
            "file": filename,
            "sha256": digest,
            "bytes": len(content.encode("utf-8")),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        self.manifest.append(entry)
        self._save_manifest()
        return entry

    def _save_manifest(self) -> None:
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
