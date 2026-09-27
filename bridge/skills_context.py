#!/usr/bin/env python3
"""
Ruadan — Skills Context Injector: injeta metodologias skills-red no LLM

Lê os SKILL.md do skills-red/ e seleciona os relevantes baseado nos
serviços detectados. Injeta no HUNT_SYSTEM_PROMPT para o LLM saber
QUAL técnica usar para CADA tipo de serviço.
"""
from __future__ import annotations

import os
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills-red" / "Skills"

# Mapeamento: tipo de serviço/vulnerabilidade → skills relevantes
# (apenas skills que TÊM conteúdo real em SKILL.md)
SERVICE_TO_SKILLS = {
    "http": ["offensive-sqli", "offensive-xss", "offensive-rce", "offensive-ssti",
             "offensive-ssrf", "offensive-xxe", "offensive-idor", "offensive-file-upload",
             "offensive-waf-bypass", "offensive-business-logic", "offensive-graphql",
             "offensive-deserialization", "offensive-race-condition",
             "offensive-request-smuggling", "offensive-open-redirect",
             "offensive-parameter-pollution"],
    "https": ["offensive-sqli", "offensive-xss", "offensive-rce", "offensive-ssti",
              "offensive-ssrf", "offensive-xxe", "offensive-waf-bypass"],
    "ssh": ["offensive-rce", "offensive-idor"],  # SSH pode dar acesso → usar skills de exploit
    "snmp": [],
    "nfs": [],
    "smb": ["offensive-active-directory", "offensive-netexec"],
    "rdp": ["offensive-active-directory"],
    "vnc": ["offensive-rce"],
    "dns": [],
    "api": ["offensive-graphql", "offensive-business-logic",
            "offensive-parameter-pollution", "offensive-idor",
            "offensive-race-condition", "offensive-request-smuggling"],
    "jwt": [],
    "ad": ["offensive-active-directory", "offensive-netexec"],
    "docker": [],
    "privesc": [],
    "webdav": ["offensive-rce", "offensive-file-upload"],
    "proxy": ["offensive-ssrf", "offensive-request-smuggling"],
}

# Skills que SEMPRE fazem parte do contexto
ALWAYS_INCLUDE = ["offensive-reporting", "offensive-fast-checking"]


def load_skill(name: str) -> str:
    """Carrega o conteúdo de um SKILL.md pelo nome."""
    # Busca recursiva
    for path in SKILLS_DIR.rglob("SKILL.md"):
        if path.parent.name == name:
            content = path.read_text(encoding="utf-8", errors="replace")
            # Remove frontmatter YAML
            if content.startswith("---"):
                parts = content.split("---", 2)
                content = parts[2].strip() if len(parts) > 2 else content
            # Trunca para não estourar o contexto do LLM
            return content[:3000]  # 3KB por skill é suficiente
    return ""


def get_relevant_skills(services: list[str]) -> list[tuple[str, str]]:
    """Retorna uma lista ordenada de (skill_name, conteúdo), priorizando os mais relevantes."""
    PRIORITY = ["offensive-sqli", "offensive-xss", "offensive-rce",
                "offensive-ssrf", "offensive-ssti", "offensive-xxe",
                "offensive-idor", "offensive-file-upload",
                "offensive-waf-bypass", "offensive-business-logic",
                "offensive-active-directory", "offensive-netexec",
                "offensive-graphql", "offensive-deserialization",
                "offensive-race-condition", "offensive-request-smuggling",
                "offensive-open-redirect", "offensive-parameter-pollution"]

    skills_to_load = set()
    for svc in services:
        svc_lower = svc.lower().strip()
        if svc_lower in SERVICE_TO_SKILLS:
            skills_to_load.update(SERVICE_TO_SKILLS[svc_lower])

    ordered = []
    for name in PRIORITY:
        if name in skills_to_load:
            content = load_skill(name)
            if content:
                ordered.append((name, content))
            skills_to_load.discard(name)

    for name in skills_to_load:
        content = load_skill(name)
        if content:
            ordered.append((name, content))

    return ordered


def build_skills_context(services: list[str], max_chars: int = 20000) -> str:
    """Constrói um bloco de contexto com as skills relevantes para o prompt do LLM."""
    skills = get_relevant_skills(services)
    if not skills:
        return ""

    parts = ["\n\n=== METODOLOGIAS DE ATAQUE (use como guia de técnicas) ===\n"]
    total = 0
    for name, content in skills:
        # Trunca cada skill se o total estourar
        if total + len(content) > max_chars:
            content = content[:max_chars - total - 100] + "\n...[truncado]"
        parts.append(f"--- {name.upper()} ---\n{content}\n")
        total += len(content)
        if total >= max_chars:
            break

    return "\n".join(parts)


if __name__ == "__main__":
    # Teste
    test_services = ["http", "https", "ssh", "snmp", "nfs"]
    ctx = build_skills_context(test_services)
    print(f"Skills carregadas para {test_services}: {len(ctx)} chars")
    print(f"Preview: {ctx[:300]}...")
