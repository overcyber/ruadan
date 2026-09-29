"""
IP Rotation Pool - Gerencia pool de proxies/VPNs/Tor para rotação de IP
"""
from __future__ import annotations

import os
import random
import requests
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Dict, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ProxyType(Enum):
    HTTP = "http"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    TOR = "tor"
    VPN = "vpn"
    DIRECT = "direct"


@dataclass
class ProxyNode:
    address: str  # host:port
    proxy_type: str = "http"
    username: Optional[str] = None
    password: Optional[str] = None
    country: str = ""
    latency: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    last_used: float = 0
    last_check: float = 0
    is_alive: bool = True
    banned_until: float = 0
    tags: List[str] = field(default_factory=list)
    
    @property
    def url(self) -> str:
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.proxy_type}://{self.username}:{self.password}@{self.address}" if self.username else f"{self.proxy_type}://{self.address}"


@dataclass
class ProxyNode:
    address: str  # host:port
    proxy_type: str = "http"
    username: Optional[str] = None
    password: Optional[str] = None
    country: str = ""
    latency: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    last_used: float = 0
    last_check: float = 0
    is_alive: bool = True
    banned_until: float = 0
    tags: List[str] = field(default_factory=list)
    
    @property
    def url(self) -> str:
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.proxy_type}://{self.username}:{self.password}@{self.address}" if self.username else f"{self.proxy_type}://{self.address}"


class IPRotationPool:
    """Gerencia pool de proxies/VPNs/Tor para rotação de IP"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.proxies: List[ProxyNode] = []
        self.current_index = 0
        self.lock = threading.RLock()
        self.failed_proxies: Set[str] = set()
        self.ban_list: Set[str] = set()
        self.rotation_strategy = "round_robin"  # round_robin, random, weighted
        self.health_check_interval = 300  # 5 min
        self.last_health_check = 0
        self.max_failures_before_ban = 3
        self.ban_duration = 300  # 5 min
        
        # Carrega proxies de fontes configuradas
        self._load_proxies()
        
        # Thread de health check
        self._health_check_thread = None
        self._running = False
    
    def add_proxy(self, address: str, proxy_type: str = "http", 
                  username: Optional[str] = None, password: Optional[str] = None,
                  country: str = "", tags: List[str] = None):
        """Adiciona proxy ao pool"""
        with self.lock:
            proxy = ProxyNode(
                address=address,
                proxy_type=address.split("://")[0] if "://" in address else "http",
                username=username,
                password=password,
                country=country,
                tags=tags or []
            )
            self.proxies.append(proxy)
            logger.info(f"Proxy adicionado: {address}")
    
    def load_from_file(self, filepath: str):
        """Carrega proxies de arquivo (formato: ip:port:type:user:pass)"""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        ip, port = parts[0], parts[1]
                        ptype = parts[2] if len(parts) > 2 else "http"
                        user = parts[3] if len(parts) > 3 else None
                        pwd = parts[4] if len(parts) > 4 else None
                        self.add_proxy(f"{ip}:{port}", ptype, user, pwd)
        except Exception as e:
            logger.error(f"Erro carregando proxies: {e}")
    
    def load_from_env(self):
        """Carrega proxies de variáveis de ambiente"""
        # PROXY_LIST="ip1:port:type:user:pass,ip2:port:type:user:pass"
        proxy_list = os.environ.get('PROXY_LIST', '')
        if proxy_list:
            for entry in proxy_list.split(','):
                parts = entry.split(':')
                if len(parts) >= 2:
                    self.add_proxy(parts[0], parts[1], parts[2] if len(parts) > 2 else "http",
                                 parts[3] if len(parts) > 3 else None,
                                   parts[4] if len(parts) > 4 else None)
    
    def get_next_proxy(self, exclude: Set[str] = None) -> Optional[ProxyNode]:
        """Retorna próximo proxy disponível (round-robin com peso)"""
        with self.lock:
            available = [p for p in self.proxies 
                        if p.is_alive and p.address not in self.ban_list
                        and (not p.banned_until or p.banned_until < time.time())
                        and (not exclude or p.address not in exclude)]
            
            if not self.proxies:
                return None
            
            if self.rotation_strategy == "round_robin":
                proxy = self.proxies[self.current_index % len(self.proxies)]
                self.current_index = (self.current_index + 1) % len(self.proxies)
            elif self.rotation_strategy == "random":
                proxy = random.choice(self.proxies)
            elif self.rotation_strategy == "weighted":
                # Weighted by success rate
                weights = [p.success_count + 1 for p in self.proxies]
                proxy = random.choices(self.proxies, weights=weights)[0]
            else:
                proxy = self.proxies[self.current_index % len(self.proxies)]
                self.current_index = (self.current_index + 1) % len(self.proxies)
            
            return proxy if proxy and proxy.is_alive and proxy.address not in self.ban_list else None
    
    def mark_failure(self, proxy_address: str):
        """Marca proxy como falho"""
        with self.lock:
            for p in self.proxies:
                if p.address == proxy_address:
                    p.failure_count += 1
                    p.last_check = time.time()
                    if p.failure_count >= self.max_failures_before_ban:
                        p.banned_until = time.time() + self.ban_duration
                        p.is_alive = False
                        logger.warning(f"Proxy banido: {proxy_address}")
                    break
    
    def mark_success(self, proxy_address: str):
        """Marca proxy como bem-sucedido"""
        with self.lock:
            for p in self.proxies:
                if p.address == proxy_address:
                    p.success_count += 1
                    p.last_check = time.time()
                    break
    
    def remove_proxy(self, address: str):
        """Remove proxy do pool"""
        with self.lock:
            self.proxies = [p for p in self.proxies if p.address != address]
    
    def get_stats(self) -> Dict:
        with self.lock:
            alive = sum(1 for p in self.proxies if p.is_alive)
            return {
                "total": len(self.proxies),
                "alive": alive,
                "banned": len(self.ban_list),
                "failed": sum(p.failure_count for p in self.proxies),
                "success": sum(p.success_count for p in self.proxies)
            }
    
    def start_health_check(self, interval: int = 300):
        """Inicia thread de health check periódico"""
        self._running = True
        self._health_check_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        self._health_check_thread.start()
    
    def stop_health_check(self):
        self._running = False
        if self._health_check_thread:
            self._health_check_thread.join(timeout=5)
    
    def _health_check_loop(self):
        while self._running:
            time.sleep(self.health_check_interval)
            if not self._running:
                break
            self._health_check()
    
    def _health_check(self):
        """Verifica saúde dos proxies"""
        with self.lock:
            for proxy in self.proxies:
                if proxy.banned_until and proxy.banned_until < time.time():
                    proxy.is_alive = True
                    proxy.banned_until = 0
                    proxy.failure_count = 0
                    continue
                
                if not proxy.is_alive:
                    continue
                
                # Teste rápido de conectividade
                try:
                    start = time.time()
                    response = requests.get("http://httpbin.org/ip", 
                                           proxies={"http": proxy.url, "https": proxy.url},
                                           timeout=5)
                    latency = time.time() - start
                    if response.status_code == 200:
                        proxy.latency = latency
                        proxy.last_check = time.time()
                        proxy.is_alive = True
                    else:
                        proxy.failure_count += 1
                        if proxy.failure_count >= self.max_failures_before_ban:
                            proxy.is_alive = False
                            proxy.banned_until = time.time() + self.ban_duration
                except Exception:
                    proxy.failure_count += 1
                    if proxy.failure_count >= self.max_failures_before_ban:
                        proxy.is_alive = False
                        proxy.banned_until = time.time() + self.ban_duration


class ProxyPool:
    """Pool de proxies com suporte a HTTP/SOCKS/Tor"""
    
    def __init__(self):
        self.http_proxies: List[str] = []
        self.socks_proxies: List[str] = []
        self.current_index = 0
        self.lock = threading.Lock()
    
    def add_http_proxy(self, proxy: str):
        with self.lock:
            self.http_proxies.append(proxy)
    
    def add_socks_proxy(self, proxy: str):
        with self.lock:
            self.socks_proxies.append(proxy)
    
    def get_random_http(self) -> Optional[str]:
        with self.lock:
            if self.http_proxies:
                return random.choice(self.http_proxies)
        return None
    
    def get_random_socks(self) -> Optional[str]:
        with self.lock:
            if self.socks_proxies:
                return random.choice(self.socks_proxies)
        return None
    
    def get_random(self) -> Optional[str]:
        with self.lock:
            all_proxies = self.http_proxies + self.socks_proxies
            if all_proxies:
                return random.choice(all_proxies)
        return None
