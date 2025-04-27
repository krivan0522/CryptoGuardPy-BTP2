"""
Rules package for CryptoGuardPy.
"""

from .base import BaseRule, Vulnerability
from .crypto_rules import (
    WeakHashingRule,
    InsecureCipherModeRule,
    DeprecatedCryptoRule,
    HardcodedSecretsRule,
    InsecurePRNGRule,
    UnverifiedSSLRule
)

# List of all available rules
AVAILABLE_RULES = [
    WeakHashingRule,
    InsecureCipherModeRule,
    DeprecatedCryptoRule,
    HardcodedSecretsRule,
    InsecurePRNGRule,
    UnverifiedSSLRule
]

__all__ = [
    'BaseRule',
    'Vulnerability',
    'WeakHashingRule',
    'InsecureCipherModeRule',
    'DeprecatedCryptoRule',
    'HardcodedSecretsRule',
    'InsecurePRNGRule',
    'UnverifiedSSLRule',
    'AVAILABLE_RULES'
] 