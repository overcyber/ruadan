"""
Blocking Detector - Detecta e responde a bloqueios (WAF, Rate Limit, IP Block, CAPTCHA, etc.)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Dict, Any
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


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


class BlockingDetector:
    """Detecta e responde a bloqueios (WAF, Rate Limit, IP Block, CAPTCHA, etc.)"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Padrões de detecção
        self.rate_limit_patterns = [
            r"rate.?limit", r"too many requests", r"rate limit",
            "too many requests", "slow down", "throttle"
        ]
        
        self.ip_block_patterns = [
            r"ip.?block", r"blocked.?ip", r"ip.?banned",
            "access.?denied", "forbidden", "your ip"
        ]
        
        self.captcha_patterns = [
            r"captcha", r"recaptcha", r"hcaptcha", r"cloudflare",
            "challenge", "verify.*human", "prove.*human"
        ]
        
        self.waf_patterns = [
            r"web.?application.?firewall", r"waf", "mod.?security",
            "cloudflare", "incapsula", "akamai", "sucuri",
            "blocked by", "access denied", "request blocked"
        ]
        
        self.firewall_patterns = [
            r"firewall", r"iptables", r"pfSense", r"ufw",
            "connection refused", "connection reset", "connection timed out"
        ]
        
        # Compila regex
        self._compiled_patterns = {
            BlockType.RATE_LIMIT: [re.compile(p, re.IGNORECASE) for p in self.rate_limit_patterns],
            BlockType.IP_BLOCK: [re.compile(p, re.IGNORECASE) for p in self.ip_block_patterns],
            BlockType.CAPTCHA: [re.compile(p, re.IGNORECASE) for p in self.captcha_patterns],
            BlockType.WAF: [re.compile(p, re.IGNORECASE) for p in self.waf_patterns],
            BlockType.FIREWALL: [re.compile(p, re.IGNORECASE) for p in self.firewall_patterns],
        }
        
        # Estado
        self.block_history: List[dict] = []
        self.current_blocks: Dict[str, dict] = {}
        self.block_callbacks: List[callable] = []
        
        # Configurações
        self.sensitivity = 1  # 1-3 (baixo, médio, alto)
        self.auto_mitigate = True
        self.max_retries = 3
        
    def analyze_response(self, response_text: str, status_code: int, headers: Dict) -> List[dict]:
        """Analisa resposta HTTP e detecta bloqueios"""
        detected_blocks = []
        text = response_text.lower() if isinstance(response_text, str) else ""
        
        # Rate Limit
        if status_code == 429 or any(p.search(response_text) for p in self._compiled_patterns[BlockType.RATE_LIMIT]):
            self._register_block(BlockType.RATE_LIMIT, "rate_limit", "Rate limit detectado")
        
        # IP Block
        if status_code in (403, 401) and any(p.search(response_text) for p in self._compiled_patterns[BlockType.IP_BLOCK]):
            self._register_block(BlockType.IP_BLOCK, "ip_block", "IP bloqueado")
        
        # CAPTCHA
        if any(p.search(response_text) for p in self._compiled_patterns[BlockType.CAPTCHA]):
            self._register_block(BlockType.CAPTCHA, "captcha", "CAPTCHA detectado")
        
        # WAF
        if status_code in (403, 406, 501) or any(p.search(response_text) for p in self._compiled_patterns[BlockType.WAF]):
            self._register_block(BlockType.WAF, "waf", "WAF detectado")
        
        # Firewall
        if any(p.search(response_text) for p in self._compiled_patterns[BlockType.FIREWALL]):
            self._register_block(BlockType.FIREWALL, "firewall", "Firewall detectado")
        
        return self.current_blocks
    
    def _register_block(self, block_type: BlockType, indicator: str, details: str):
        event = {
            "timestamp": time.time(),
            "type": block_type.value,
            "details": f"{block_type.value}: {details}"
        }
        self.block_history.append({
            "timestamp": time.time(),
            "type": block_type.value,
            "details": details
        })
        self.current_blocks[block_type.value] = {
            "detected_at": time.time(),
            "details": details
        }
    
    def get_current_blocks(self) -> Dict:
        """Retorna blocos atuais"""
        return self.current_blocks.copy()
    
    def is_blocked(self) -> bool:
        return len(self.current_blocks) > 0
    
    def is_rate_limited(self) -> bool:
        return BlockType.RATE_LIMIT.value in self.current_blocks
    
    def is_ip_blocked(self) -> bool:
        return BlockType.IP_BLOCK.value in self.current_blocks
    
    def is_waf_blocked(self) -> bool:
        return BlockType.WAF.value in self.current_blocks
    
    def register_callback(self, callback: callable):
        """Registra callback para notificação de bloqueio"""
        self.block_callbacks.append(callback)
    
    def reset(self):
        self.current_blocks.clear()
        self.block_history.clear()


class IPRotator:
    """Gerencia rotação de IPs via proxies/VPNs"""
    
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.lock = threading.Lock()
    
    def add_proxy(self, proxy: str):
        """Adiciona proxy à lista"""
        pass
    
    def get_next(self) -> Optional[str]:
        """Retorna próximo proxy disponível"""
        return None
    
    def mark_failed(self, proxy: str):
        """Marca proxy como falho"""
        pass
    
    def mark_success(self, proxy: str):
        pass


class IdentityRotator:
    """Rotação de identidade (User-Agent, headers, source port)"""
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    
    def __init__(self):
        self.current_ua_index = 0
        self.lock = threading.Lock()
    
    def get_next_user_agent(self) -> str:
        with self.lock:
            ua = self.USER_AGENTS[self.current_ua_index]
            self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
            return self.USER_AGENTS[self.current_ua_index]
    
    def get_random_headers(self) -> Dict[str, str]:
        """Gera headers aleatórios realistas"""
        return {
            "User-Agent": self.get_next_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }
    
    def rotate_identity(self):
        """Força rotação completa de identidade"""
        pass
    
    
class TimingEvasion:
    """Evasão baseada em timing - jitter, backoff, rate limiting"""
    
    def __init__(self):
        self.min_delay = 0.5
        self.max_delay = 30.0
        self.base_delay = 1.0
        self.current_delay = 1.0
        self.jitter_factor = 0.3
        self.adaptive = True
        self.last_request_time = 0
        
    def get_delay(self, attempt: int = 0, success: bool = True) -> float:
        """Calcula delay com backoff exponencial e jitter"""
        if success:
            self.current_delay = max(self.base_delay, self.current_delay * 0.5)
        else:
            self.current_delay = min(self.current_delay * 2, self.max_delay)
        
        # Adiciona jitter
        jitter = random.uniform(-self.jitter_factor, self.jitter_factor) * self.current_delay
        return max(self.min_delay, self.current_delay + jitter)
    
    def get_request_delay(self) -> float:
        """Delay antes da próxima requisição"""
        elapsed = time.time() - self.last_request_time
        delay = self.get_delay()
        if elapsed < delay:
            return delay - elapsed
        return 0
    
    def record_request(self, success: bool):
        self.last_request_time = time.time()
        if not success:
            self.current_delay = min(self.current_delay * 1.5, self.max_delay)
        else:
            self.current_delay = max(self.base_delay, self.current_delay * 0.8)
    
    def reset(self):
        self.current_delay = self.base_delay


class IdentityRotator:
    """Rotação de identidade (User-Agent, headers, source port)"""
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    
    def __init__(self):
        self.current_ua_index = 0
        self.lock = threading.Lock()
    
    def get_next_user_agent(self) -> str:
        with self.lock:
            ua = self.USER_AGENTS[self.current_ua_index]
            self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
            return self.USER_AGENTS[self.current_ua_index]
    
    def get_random_headers(self) -> Dict[str, str]:
        """Gera headers aleatórios realistas"""
        return {
            "User-Agent": self.get_next_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }
    
    def rotate_identity(self):
        """Força rotação completa de identidade"""
        pass
    
    
class TimingEvasion:
    """Evasão baseada em timing - jitter, backoff, rate limiting"""
    
    def __init__(self):
        self.min_delay = 0.5
        self.max_delay = 30.0
        self.base_delay = 1.0
        self.current_delay = 1.0
        self.jitter_factor = 0.3
        self.adaptive = True
        self.last_request_time = 0
        self.current_delay = 1.0
        
    def get_delay(self, attempt: int = 0, success: bool = True) -> float:
        """Calcula delay com backoff exponencial e jitter"""
        if success:
            self.current_delay = max(self.base_delay, self.current_delay * 0.5)
        else:
            self.current_delay = min(self.current_delay * 2, self.max_delay)
        
        # Adiciona jitter
        jitter = random.uniform(-self.jitter_factor, self.jitter_factor) * self.current_delay
        return max(self.min_delay, self.current_delay + jitter)
    
    def get_request_delay(self) -> float:
        """Delay antes da próxima requisição"""
        elapsed = time.time() - self.last_request_time
        delay = self.get_delay()
        if elapsed < delay:
            return delay - elapsed
        return 0
    
    def record_request(self, success: bool):
        self.last_request_time = time.time()
        if not success:
            self.current_delay = min(self.current_delay * 1.5, self.max_delay)
        else:
            self.current_delay = max(self.base_delay, self.current_delay * 0.8)
    
    def reset(self):
        self.current_delay = self.base_delay


class IdentityRotator:
    """Rotação de identidade (User-Agent, headers, source port)"""
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    
    def __init__(self):
        self.current_ua_index = 0
        self.lock = threading.Lock()
    
    def get_next_user_agent(self) -> str:
        with self.lock:
            ua = self.USER_AGENTS[self.current_ua_index]
            self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
            return ua
    
    def get_random_headers(self) -> Dict[str, str]:
        """Gera headers aleatórios realistas"""
        return {
            "User-Agent": self.get_next_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }
    
    def rotate_identity(self):
        """Força rotação completa de identidade"""
        pass
