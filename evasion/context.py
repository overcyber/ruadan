"""
Evasion Context - Contexto compartilhado de evasão
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from enum import Enum
import threading


class BlockType(Enum):
    NONE = "none"
    RATE_LIMIT = "rate_limit"
    IP_BLOCK = "ip_block"
    CAPTCHA = "captcha"
    WAF = "waf"
    FIREWALL = "firewall"
    UNKNOWN = "unknown"


@dataclass
class BlockEvent:
    timestamp: float
    block_type: BlockType
    indicator: str  # IP, subnet, fingerprint
    severity: int  # 1-10
    details: dict = field(default_factory=dict)


@dataclass
class TargetProfile:
    host: str
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)  # port -> service
    os_fingerprint: str = ""
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    defenses_detected: List[str] = field(default_factory=list)
    last_scan: float = 0
    blocked: bool = False
    block_reason: str = ""


@dataclass
class EvasionContext:
    """Contexto compartilhado de evasão entre todos os módulos"""
    target_host: str
    target_ip: str
    target_port: int
    
    # Estado de evasão
    current_ip: str = ""
    current_proxy: Optional[str] = None
    current_user_agent: str = ""
    current_source_port: int = 0
    
    # Histórico de bloqueios
    block_history: List[dict] = field(default_factory=list)
    blocked_ips: Set[str] = field(default_factory=set)
    blocked_subnets: Set[str] = field(default_factory=set)
    
    # Contadores de falha
    consecutive_failures: int = 0
    consecutive_timeouts: int = 0
    consecutive_4xx: int = 0
    consecutive_5xx: int = 0
    
    # Timing
    last_request_time: float = 0
    request_count: int = 0
    last_block_time: float = 0
    
    # Memória de evasão
    tested_endpoints: Set[str] = field(default_factory=set)
    blocked_endpoints: Set[str] = field(default_factory=set)
    successful_payloads: Dict[str, List[str]] = field(default_factory=list)
    failed_payloads: Dict[str, List[str]] = field(default_factory=list)
    
    # Configurações de evasão
    max_retries: int = 3
    max_consecutive_failures: int = 5
    request_timeout: float = 30.0
    min_delay: float = 0.5
    max_delay: float = 30.0
    
    # Estado de bloqueio
    is_blocked: bool = False
    block_reason: str = ""
    block_timestamp: float = 0
    blocked_until: float = 0
    
    def __post_init__(self):
        if not hasattr(self, 'blocked_ips'):
            self.blocked_ips = set()
        if not hasattr(self, 'blocked_subnets'):
            self.blocked_subnets = set()


class EvasionContextManager:
    """Gerenciador singleton do contexto de evasão"""
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls) -> 'EvasionContextManager':
        with cls._lock:
            if cls._instance is None:
                cls._instance = EvasionContextManager()
            return cls._instance
    
    def __init__(self):
        self.contexts: Dict[str, 'EvasionContext'] = {}
        self._lock = threading.Lock()
    
    def get_context(self, target: str) -> 'EvasionContext':
        with self._lock:
            if target not in self.contexts:
                self.contexts[target] = EvasionContext(target_host=target)
            return self.contexts[target]
    
    def reset_context(self, target: str):
        with self._lock:
            if target in self.contexts:
                del self.contexts[target]


# Singleton getter
def get_evasion_context(target: str) -> 'EvasionContext':
    return EvasionContextManager.get_instance().get_context(target)
