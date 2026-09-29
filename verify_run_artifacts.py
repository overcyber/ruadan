#!/usr/bin/env python3
"""
Utilitário de Verificação e Sumarização Forense dos Relatórios do Ruadan.
Analisa a estrutura da pasta de output, extrai achados de WhatWeb, Nikto, Nmap,
CeWL e matriz de risco, gerando relatório de auditoria no terminal e em Markdown.
"""
from __future__ import annotations

import ast
import csv
import os
import re
import sys
from pathlib import Path


def parse_whatweb(file_path: Path) -> dict:
    info = {"server": "Desconhecido", "plugins": [], "uncommon_headers": [], "status": ""}
    if not file_path.is_file():
        return info
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    m_status = re.search(r"Status\s*:\s*(\d+[^\n]*)", text)
    if m_status:
        info["status"] = m_status.group(1).strip()
    m_server = re.search(r"HTTPServer\[([^\]]+)\]", text)
    if m_server:
        info["server"] = m_server.group(1).strip()
    m_headers = re.search(r"UncommonHeaders\[([^\]]+)\]", text)
    if m_headers:
        info["uncommon_headers"] = [h.strip() for h in m_headers.group(1).split(",")]
    m_plugins = re.findall(r"\[\s*([^\]\n]+)\s*\]\n\s*([^\n]+)", text)
    for p_name, p_desc in m_plugins:
        info["plugins"].append(f"{p_name}: {p_desc.strip()}")
    return info


def parse_nikto(file_path: Path) -> dict:
    info = {"missing_headers": [], "items_reported": 0, "server": ""}
    if not file_path.is_file():
        return info
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    for line in text.splitlines():
        if "Suggested security header missing:" in line:
            header = line.split("missing:")[-1].split(".")[0].strip()
            info["missing_headers"].append(header)
        elif "Server:" in line and not info["server"]:
            info["server"] = line.split("Server:")[-1].strip()
        elif "items reported on the remote host" in line:
            m = re.search(r"(\d+)\s+items reported", line)
            if m:
                info["items_reported"] = int(m.group(1))
    return info


def parse_riskscores(file_path: Path) -> dict[str, str]:
    scores = {}
    if not file_path.is_file():
        return scores
    with file_path.open(encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2 and row[0] != "Host":
                scores[row[0].strip()] = row[1].strip()
    return scores


def parse_report_dict(file_path: Path) -> dict:
    if not file_path.is_file():
        return {}
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        # Ruadan salva como pprint de dicionário Python
        return ast.literal_eval(content)
    except Exception:
        return {}


def analyze_output(output_dir: str | Path) -> dict:
    output_path = Path(output_dir).resolve()
    if not output_path.is_dir():
        print(f"[!] Diretório de saída não encontrado: {output_path}")
        sys.exit(1)

    analysis = {
        "output_path": str(output_path),
        "hosts": {},
        "risk_scores": parse_riskscores(output_path / "riskscores.csv"),
        "raw_report": parse_report_dict(output_path / "report.txt")
    }

    # Análise de logs do Ollama
    ollama_server_log = output_path / "ollama.log"
    ollama_client_log = output_path / "ai_evidence" / "ollama_interactions.log"
    if not ollama_client_log.is_file():
        ollama_client_log = output_path / "ollama_client.log"

    ollama_info = {
        "server_log_present": ollama_server_log.is_file() and ollama_server_log.stat().st_size > 0,
        "server_log_lines": sum(1 for _ in ollama_server_log.open(encoding="utf-8", errors="ignore")) if ollama_server_log.is_file() else 0,
        "client_log_present": ollama_client_log.is_file() and ollama_client_log.stat().st_size > 0,
        "interactions_count": 0
    }
    if ollama_client_log.is_file():
        content = ollama_client_log.read_text(encoding="utf-8", errors="ignore")
        ollama_info["interactions_count"] = content.count("TIMESTAMP:")
    analysis["ollama"] = ollama_info

    # Busca diretórios com formato de IP (ex: 192_168_50_210)
    for host_dir in output_path.iterdir():
        if not host_dir.is_dir() or host_dir.name in ("Nmap", "ai_evidence"):
            continue
        host_ip = host_dir.name.replace("_", ".")
        host_data = {
            "dir_name": host_dir.name,
            "ip": host_ip,
            "risk_score": analysis["risk_scores"].get(host_ip, "N/A"),
            "open_ports": [],
            "filtered_ports": [],
            "services": [],
            "web_findings": {},
            "wordlist_count": 0,
            "wordlist_sample": []
        }

        # Extrai serviços e portas do raw_report se disponível
        if host_ip in analysis["raw_report"]:
            ports_raw = analysis["raw_report"][host_ip].get("ports", [])
            for p in ports_raw:
                p_id = str(p.get("portid", ""))
                p_state = p.get("state", "")
                p_name = p.get("name", "")
                p_prod = p.get("product", "")
                if p_id in ("0", "-1"):
                    continue
                if p_state == "open" and p_id not in host_data["open_ports"]:
                    host_data["open_ports"].append(p_id)
                elif p_state == "filtered" and p_id not in host_data["filtered_ports"]:
                    host_data["filtered_ports"].append(p_id)

        # Lê services.txt se existir
        services_file = host_dir / "services.txt"
        if services_file.is_file():
            host_data["services"] = [
                line.strip() for line in services_file.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()
            ]

        # Lê passwordlist.txt se existir
        pw_file = host_dir / "passwordlist.txt"
        if pw_file.is_file():
            words = [line.strip() for line in pw_file.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
            host_data["wordlist_count"] = len(words)
            host_data["wordlist_sample"] = words[1:8] if len(words) > 1 else words

        # Analisa pasta unknown ou serviços específicos
        for sub in host_dir.iterdir():
            if sub.is_dir():
                for whatweb_file in sub.glob("HTTP_What_Web_*.txt"):
                    port = whatweb_file.stem.split("_")[-1]
                    host_data["web_findings"][port] = host_data["web_findings"].get(port, {})
                    host_data["web_findings"][port]["whatweb"] = parse_whatweb(whatweb_file)

                for nikto_file in sub.glob("HTTP_Nikto_Fast_*.txt"):
                    port = nikto_file.stem.split("_")[-1]
                    host_data["web_findings"][port] = host_data["web_findings"].get(port, {})
                    host_data["web_findings"][port]["nikto"] = parse_nikto(nikto_file)

        analysis["hosts"][host_ip] = host_data

    return analysis


def print_terminal_summary(analysis: dict) -> None:
    print("\n" + "=" * 70)
    print(" RUADAN - RELATÓRIO FORENSE DE EXECUÇÃO EM DOCKER")
    print("=" * 70)
    print(f"[*] Diretório de Artefatos : {analysis['output_path']}")
    print(f"[*] Hosts Analisados       : {len(analysis['hosts'])}")

    for ip, data in analysis["hosts"].items():
        print("\n" + "-" * 70)
        print(f" ALVO: {ip} | Risk Score: {data['risk_score']}")
        print("-" * 70)
        print(f" [+] Portas Abertas   : {', '.join(data['open_ports']) if data['open_ports'] else 'Nenhuma'}")
        print(f" [+] Portas Filtradas : {', '.join(data['filtered_ports']) if data['filtered_ports'] else 'Nenhuma'}")

        if data["services"]:
            print(" [+] Serviços Detectados:")
            for s in data["services"]:
                print(f"     • {s}")

        if data["web_findings"]:
            print(" [+] Achados Web:")
            for port, findings in data["web_findings"].items():
                print(f"     [Porta {port}]:")
                if "whatweb" in findings:
                    ww = findings["whatweb"]
                    print(f"       - Servidor Web : {ww.get('server')}")
                    if ww.get("uncommon_headers"):
                        print(f"       - Headers Incomuns: {', '.join(ww['uncommon_headers'])}")
                if "nikto" in findings:
                    nk = findings["nikto"]
                    print(f"       - Nikto Alertas: {nk.get('items_reported')} achados reportados")
                    if nk.get("missing_headers"):
                        print(f"       - Headers de Segurança Faltantes:")
                        for mh in nk["missing_headers"]:
                            print(f"         * {mh}")

        if data["wordlist_count"] > 0:
            print(f" [+] Dicionário Contextual (CeWL): {data['wordlist_count']} palavras extraídas")
            print(f"     Amostra: {', '.join(data['wordlist_sample'])}")

    if "ollama" in analysis:
        o = analysis["ollama"]
        print("-" * 70)
        print(" AUDITORIA DE LOGS DO OLLAMA / INTELIGÊNCIA ARTIFICIAL")
        print("-" * 70)
        srv_status = f"Presente ({o['server_log_lines']} linhas gravadas)" if o['server_log_present'] else "Não gerado / offline"
        cli_status = f"Presente ({o['interactions_count']} chamadas registradas)" if o['client_log_present'] else "Nenhuma interação registrada"
        print(f" [+] Log do Servidor (ollama.log)             : {srv_status}")
        print(f" [+] Log de Interações (ollama_interactions) : {cli_status}")
        print(f"     (Para visualizar ao vivo: ./start.sh --logs ou ./view_ollama_logs.sh -f)")

    print("\n" + "=" * 70 + "\n")


def export_markdown_summary(analysis: dict, output_file: Path) -> None:
    md = [
        "# Ruadan - Sumário Executivo de Execução em Docker\n",
        f"**Diretório Base**: `{analysis['output_path']}`  ",
        f"**Total de Hosts Processados**: {len(analysis['hosts'])}\n",
        "## 1. Matriz de Superfície de Ataque e Risco\n",
        "| Host Alvo | Risk Score | Portas Abertas | Portas Filtradas | Principais Serviços |",
        "| :--- | :---: | :--- | :--- | :--- |"
    ]

    for ip, data in analysis["hosts"].items():
        open_p = ", ".join(data["open_ports"]) or "Nenhuma"
        filt_p = ", ".join(data["filtered_ports"]) or "Nenhuma"
        main_svc = data["services"][0] if data["services"] else "N/A"
        md.append(f"| `{ip}` | **{data['risk_score']}** | `{open_p}` | `{filt_p}` | {main_svc} |")

    md.append("\n## 2. Detalhamento Técnico por Alvo\n")
    for ip, data in analysis["hosts"].items():
        md.append(f"### Alvo: `{ip}`\n")
        md.append(f"- **Risk Score Consolidado**: `{data['risk_score']}`")
        md.append(f"- **Portas Abertas**: `{', '.join(data['open_ports'])}`")
        md.append(f"- **Portas Filtradas**: `{', '.join(data['filtered_ports'])}`\n")

        if data["services"]:
            md.append("#### Serviços Identificados:")
            for s in data["services"]:
                md.append(f"- `{s}`")
            md.append("")

        if data["web_findings"]:
            md.append("#### Auditoria de Aplicação Web:")
            for port, findings in data["web_findings"].items():
                md.append(f"**Porta {port}**:")
                if "whatweb" in findings:
                    ww = findings["whatweb"]
                    md.append(f"- **Servidor Web**: `{ww.get('server')}`")
                    if ww.get("uncommon_headers"):
                        md.append(f"- **Cabeçalhos Anômalos/CORS**: `{', '.join(ww['uncommon_headers'])}`")
                if "nikto" in findings:
                    nk = findings["nikto"]
                    md.append(f"- **Vulnerabilidades/Inconformidades Nikto**: `{nk.get('items_reported')}` itens detectados")
                    if nk.get("missing_headers"):
                        md.append("- **Headers de Segurança Ausentes**:")
                        for mh in nk["missing_headers"]:
                            md.append(f"  - `{mh}`")
                md.append("")

        if data["wordlist_count"] > 0:
            md.append(f"#### Wordlist Contextual Extraída (CeWL):")
            md.append(f"- **Total de Palavras**: {data['wordlist_count']}")
            md.append(f"- **Amostra**: `{', '.join(data['wordlist_sample'])}`\n")

    if "ollama" in analysis:
        o = analysis["ollama"]
        srv_status = f"Presente ({o['server_log_lines']} linhas)" if o['server_log_present'] else "Não gerado"
        cli_status = f"Presente ({o['interactions_count']} chamadas)" if o['client_log_present'] else "Nenhuma interação"
        md.append("## 3. Auditoria de Logs do Ollama e IA\n")
        md.append(f"- **Log do Servidor (`output/ollama.log`)**: `{srv_status}`")
        md.append(f"- **Log de Interações (`output/ai_evidence/ollama_interactions.log`)**: `{cli_status}`\n")

    try:
        output_file.write_text("\n".join(md), encoding="utf-8")
        print(f"[+] Relatório Markdown consolidado gerado com sucesso em: {output_file}")
    except OSError as e:
        print(f"[*] Aviso: Não foi possível salvar o arquivo Markdown devido a permissões de escrita ({e}).")


def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "/system/ruadan-new/ruadan/output"
    analysis = analyze_output(target_dir)
    print_terminal_summary(analysis)
    md_output = Path(target_dir) / "resumo_execucao.md"
    export_markdown_summary(analysis, md_output)


if __name__ == "__main__":
    main()
