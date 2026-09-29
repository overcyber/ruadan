"""
Ruadan Evasion Framework - Camada de evasão para fuzzing avançado
Fornece: IP rotation, detecção de bloqueio, rotação de identidade, timing evasion, evasão stateful
"""
from __future__ import annotations

import os
import random
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Dict, Any
from collections import defaultdict
from enum import Enum
import threading

__all__ = [
    "EvasionManager",
    "IPRotationPool",
    "BlockingDetector",
    "IdentityRotator",
    "TimingEvasion",
    "StatefulEvasion",
    "EvasionContext",
    "ProxyPool",
    "TorManager",
    "VPNManager",
]
