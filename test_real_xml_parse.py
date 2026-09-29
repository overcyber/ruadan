#!/usr/bin/env python3
"""
Script de Prova Real: Executa a função parse_nmap_xml corrigida contra o XML
real gerado durante a varredura de 192.168.50.210 e exibe a estrutura final exata.
"""
import configparser
import os
import pprint
import sys
import xml.etree.ElementTree as ET

# Importa a classe Ruadan com o código corrigido
from Ruadan2 import Ruadan

def run_proof():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, "output")
    xml_path = os.path.join(output_dir, "Nmap", "Nmap_All_TCP_192_168_50_210.xml")

    if not os.path.exists(xml_path):
        print(f"[-] Arquivo XML real não encontrado: {xml_path}")
        return

    # Instancia mock com os caminhos reais
    mock_ruadan = type("MockRuadan", (), {
        "args": type("Args", (), {"outputFolder": output_dir, "noResume": True, "noExploitSearch": False})(),
        "nmap_dict": {},
        "config": configparser.ConfigParser(),
        "find_files": Ruadan.find_files,
        "get_enumeration_path": Ruadan.get_enumeration_path
    })()
    
    # Carrega config.ini real
    mock_ruadan.config.read(os.path.join(base_dir, "config.ini"), encoding="utf-8")
    
    # Associa os métodos corrigidos
    mock_ruadan.xml_to_dict = Ruadan.xml_to_dict.__get__(mock_ruadan)
    mock_ruadan.parse_nmap_xml = Ruadan.parse_nmap_xml.__get__(mock_ruadan)
    mock_ruadan.exploit_search = Ruadan.exploit_search.__get__(mock_ruadan)

    print("[*] Executando parse_nmap_xml corrigido no XML real de 192.168.50.210...")
    mock_ruadan.parse_nmap_xml()

    print("\n" + "=" * 70)
    print(" RESULTADO REAL DA ESTRUTURA nmap_dict APÓS A CORREÇÃO")
    print("=" * 70)
    pprint.pprint(mock_ruadan.nmap_dict)

    # Grava o resultado para conferência direta
    out_file = os.path.join(output_dir, "parsed_nmap_dict_fixed.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        pprint.pprint(mock_ruadan.nmap_dict, stream=f, indent=4, width=1)
    print(f"\n[+] Relatório corrigido gravado em: {out_file}")

if __name__ == "__main__":
    run_proof()
