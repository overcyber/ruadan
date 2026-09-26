#!/usr/bin/env python3
"""
Test suite for Ruadan - red-MPPO - Multi-LLM Bridge Components:
- CanaryVerifier (token validation, root privilege checking, audit manifests)
- RuadanStateAdapter (nmap dict -> RL state tensors & action masks)
- MultiLLMClient (multi-provider configuration & message dispatching)
- ActionDispatcher (action mapping & canary injection)
"""
import os
import sys
import json
import shutil
import tempfile
import configparser
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from bridge.canary import CanaryVerifier, CanaryEvidence, CANARY_PREFIX
from bridge.state_adapter import RuadanStateAdapter, RedAction
from bridge.llm_client import MultiLLMClient, LLMResponse
from bridge.action_dispatcher import ActionDispatcher, DispatchResult


class TestCanaryVerifier(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="canary_test_")
        self.verifier = CanaryVerifier(evidence_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_token_creation(self):
        token = self.verifier.generate_token(label="EXPLOIT_HOST")
        self.assertTrue(token.startswith(CANARY_PREFIX))
        self.assertIn("EXPLOIT_HOST", token)

    def test_verify_output_success(self):
        token = self.verifier.generate_token(label="DISCOVER")
        output = f"Scanning started...\n{token}\nHost is up."
        evidence = self.verifier.verify_token_in_output(token, output, action_label="discover_test")
        self.assertTrue(evidence.verified)
        self.assertIsNotNone(evidence.evidence_file)
        self.assertIsNotNone(evidence.sha256)
        self.assertTrue(os.path.isfile(evidence.evidence_file))

    def test_verify_output_failure(self):
        token = self.verifier.generate_token(label="DISCOVER")
        output = "Scanning failed. Connection refused."
        evidence = self.verifier.verify_token_in_output(token, output, action_label="discover_test")
        self.assertFalse(evidence.verified)
        self.assertIsNone(evidence.evidence_file)
        self.assertIsNone(evidence.sha256)

    def test_root_privilege_check(self):
        evidence_root1 = self.verifier.verify_root_privilege("uid=0(root) gid=0(root) groups=0(root)")
        self.assertTrue(evidence_root1.verified)
        self.assertIsNotNone(evidence_root1.sha256)

        evidence_root2 = self.verifier.verify_root_privilege("0\n")
        self.assertTrue(evidence_root2.verified)

        evidence_nonroot1 = self.verifier.verify_root_privilege("uid=1000(kali) gid=1000(kali) groups=1000(kali)")
        self.assertFalse(evidence_nonroot1.verified)

        evidence_nonroot2 = self.verifier.verify_root_privilege("1000")
        self.assertFalse(evidence_nonroot2.verified)

    def test_save_and_hash_manifest(self):
        entry = self.verifier.save_and_hash_evidence("flag", "flag.txt", "EVIDENCE_FLAG_SECRET_123")
        self.assertIn("sha256", entry)
        self.assertIn("file", entry)
        self.assertTrue(self.verifier.manifest_path.is_file())
        with open(self.verifier.manifest_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        self.assertGreaterEqual(len(manifest_data), 1)
        self.assertEqual(manifest_data[-1]["file"], "flag.txt")


class TestRuadanStateAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = RuadanStateAdapter(max_steps=20)
        self.mock_nmap = {
            "192.168.1.10": {
                "ports": [
                    {"portid": 80, "name": "http", "state": "open", "product": "Apache httpd", "version": "2.4.49"},
                    {"portid": 22, "name": "ssh", "state": "open", "product": "OpenSSH", "version": "8.2p1"}
                ]
            },
            "192.168.1.20": {
                "ports": [
                    {"portid": 445, "name": "microsoft-ds", "state": "open", "product": "Windows SMB", "version": ""}
                ]
            }
        }
        self.mock_findings = {
            "192.168.1.10": [
                {"id": "CVE-2021-41773", "tool": "nikto", "description": "Apache Path Traversal RCE"}
            ]
        }
        self.mock_risk = {
            "192.168.1.10": 75.0,
            "192.168.1.20": 30.0
        }

    def test_state_synchronization(self):
        state = self.adapter.sync_from_ruadan(self.mock_nmap, self.mock_findings, self.mock_risk)
        self.assertEqual(len(state.hosts), 2)
        self.assertEqual(state.hosts[0].ip, "192.168.1.10")
        self.assertEqual(state.hosts[0].vuln, 0.75)  # 75.0 / 100.0
        self.assertEqual(len(state.hosts[0].services), 2)
        self.assertEqual(state.hosts[1].ip, "192.168.1.20")
        self.assertEqual(state.hosts[1].vuln, 0.30)  # 30.0 / 100.0

    def test_tensor_generation(self):
        self.adapter.sync_from_ruadan(self.mock_nmap, self.mock_findings, self.mock_risk)
        obs, hf, adj, am, tm = self.adapter.get_tensors()

        # Check observation tensor (8-dimensional)
        self.assertEqual(obs.shape, (8,))
        self.assertAlmostEqual(obs[0], 1.0)  # discovered_fraction (2 / 2)
        self.assertEqual(obs[7], 0.0)  # step normalized (step 0 / max_steps 20)

        # Check host features (N x 7)
        self.assertEqual(hf.shape, (2, 7))
        self.assertEqual(hf[0, 0], 0.75)  # host 0 vulnerability score (column 0)
        self.assertEqual(hf[0, 4], 1.0)   # host 0 discovered flag (column 4)

        # Check adjacency matrix (N x N)
        self.assertEqual(adj.shape, (2, 2))
        self.assertEqual(adj[0, 0], 1.0)  # self-loop
        self.assertEqual(adj[1, 1], 1.0)

        # Check action mask (10 actions)
        self.assertEqual(am.shape, (10,))
        # Scanned hosts should have EXPLOIT_REMOTE active in mask
        self.assertEqual(am[int(RedAction.EXPLOIT_REMOTE)], 1.0)

        # Check target mask (10 actions x N hosts)
        self.assertEqual(tm.shape, (10, 2))
        self.assertTrue(np.any(tm > 0))


class TestMultiLLMClient(unittest.TestCase):
    def test_provider_initialization(self):
        # Test default models for each supported provider
        client_ollama = MultiLLMClient(provider="ollama")
        self.assertEqual(client_ollama.provider, "ollama")
        self.assertIn("qwen", client_ollama.model.lower())

        client_google = MultiLLMClient(provider="google")
        self.assertEqual(client_google.provider, "google")
        self.assertIn("gemini", client_google.model.lower())

        client_openai = MultiLLMClient(provider="openai")
        self.assertEqual(client_openai.provider, "openai")
        self.assertIn("gpt", client_openai.model.lower())

        client_anthropic = MultiLLMClient(provider="anthropic")
        self.assertEqual(client_anthropic.provider, "anthropic")
        self.assertIn("claude", client_anthropic.model.lower())

        client_deepseek = MultiLLMClient(provider="deepseek")
        self.assertEqual(client_deepseek.provider, "deepseek")
        self.assertIn("deepseek", client_deepseek.model.lower())

        client_nvidia = MultiLLMClient(provider="nvidia")
        self.assertEqual(client_nvidia.provider, "nvidia")
        self.assertIn("llama", client_nvidia.model.lower())

    def test_custom_model_override(self):
        client = MultiLLMClient(provider="google", model="gemini-2.0-flash")
        self.assertEqual(client.model, "gemini-2.0-flash")


class TestActionDispatcher(unittest.TestCase):
    class MockRuadan:
        def __init__(self):
            self.executed_commands = []
            self.args = type("Args", (), {"outputFolder": "/tmp/ruadan_test", "domain": "megacorpone.com"})()
            self.nmap_dict = {
                "192.168.1.10": {"ports": [{"portid": "80", "name": "http", "state": "open"}]}
            }
            self.findings = {}
            self.config = configparser.ConfigParser()
            self.config.add_section("Nmap Scan Fast TCP")
            self.config.set("Nmap Scan Fast TCP", "command", "nmap -sT {target}")
            self.config.add_section("http")
            self.config.set("http", "command", "nikto -h {target}")
            self.plan = configparser.ConfigParser()
            self.plan.add_section("Nmap Scan Fast TCP")
            self.plan.add_section("Information Gathering")
            self.phase_commands = []

        def execute_command(self, cmd):
            self.executed_commands.append(cmd)
            return 0

        def enumerate(self, phase_name):
            cmd = f"nmap -F 192.168.1.10 ({phase_name})"
            self.phase_commands = [cmd]
            self.executed_commands.append(cmd)
            return 0

        def exploit_search(self, command_label):
            cmd = f"searchsploit JSON ({command_label})"
            self.executed_commands.append(cmd)
            return 0

        def prepare_command(self, section, keys):
            return f"{section} target={keys.get('target', '')} port={keys.get('port', '')}"

        def get_enumeration_path(self, host, service, port, cmd):
            return f"/tmp/ruadan_test/{host}_{service}_{port}_{cmd}"

        def parse_nmap_xml(self):
            pass

        def findings_post_processing(self):
            pass

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="dispatch_test_")
        self.canary = CanaryVerifier(evidence_dir=self.test_dir)
        self.ruadan = self.MockRuadan()
        self.dispatcher = ActionDispatcher(self.ruadan, self.canary)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_action_dispatch_discover_remote(self):
        result = self.dispatcher.dispatch(int(RedAction.DISCOVER_REMOTE), target_ip="192.168.1.10")
        self.assertTrue(result.success)
        self.assertGreaterEqual(len(result.commands_executed), 1)
        self.assertIn("192.168.1.10", result.commands_executed[0])

    def test_action_dispatch_exfiltrate(self):
        result = self.dispatcher.dispatch(int(RedAction.EXFILTRATE), target_ip="192.168.1.10")
        self.assertTrue(result.success)
        self.assertGreaterEqual(len(result.evidence_files), 1)
        self.assertIn("crown_jewel", result.evidence_files[0])


class TestNmapXmlParsing(unittest.TestCase):
    def test_xml_service_preservation(self):
        import configparser
        import xml.etree.ElementTree as ET
        from ruadan.Ruadan2 import Ruadan
        
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" version="7.99">
        <host>
            <status state="up"/>
            <address addr="192.168.50.210" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH" version="9.2p1 Debian 2+deb12u3"/>
                </port>
                <port protocol="tcp" portid="8080">
                    <state state="open"/>
                    <service name="http-proxy" product="llama.cpp" version="b3000"/>
                </port>
            </ports>
        </host>
        </nmaprun>"""
        
        temp_xml_dir = tempfile.mkdtemp(prefix="nmap_xml_test_")
        try:
            nmap_subdir = Path(temp_xml_dir) / "Nmap"
            nmap_subdir.mkdir(parents=True, exist_ok=True)
            xml_file = nmap_subdir / "test_nmap.xml"
            xml_file.write_text(sample_xml, encoding="utf-8")
            
            ruadan_mock = type("MockRuadan", (), {
                "args": type("Args", (), {"outputFolder": temp_xml_dir})(),
                "nmap_dict": {},
                "config": configparser.ConfigParser(interpolation=None, strict=False)
            })()
            ruadan_mock.config.read("/system/ruadan-new/ruadan/config.ini")
            ruadan_mock.xml_to_dict = Ruadan.xml_to_dict.__get__(ruadan_mock)
            ruadan_mock.parse_nmap_xml = Ruadan.parse_nmap_xml.__get__(ruadan_mock)
            
            ruadan_mock.parse_nmap_xml()
            self.assertIn("192.168.50.210", ruadan_mock.nmap_dict)
            ports = {str(p["portid"]): p for p in ruadan_mock.nmap_dict["192.168.50.210"]["ports"]}
            
            # Port 22 must preserve OpenSSH and version
            self.assertIn("22", ports)
            self.assertEqual(ports["22"]["name"], "ssh")
            self.assertEqual(ports["22"]["product"], "OpenSSH")
            self.assertIn("9.2p1", ports["22"]["version"])
            
            # Port 8080 must preserve product and version
            self.assertIn("8080", ports)
            self.assertEqual(ports["8080"]["product"], "llama.cpp")
            self.assertEqual(ports["8080"]["version"], "b3000")
        finally:
            shutil.rmtree(temp_xml_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
