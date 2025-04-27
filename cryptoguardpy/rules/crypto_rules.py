"""
Specific rules for detecting cryptographic vulnerabilities.
"""

import ast
from typing import Set, Dict, Any, List
from .base import BaseRule
import ssl

class WeakHashingRule(BaseRule):
    """Rule for detecting weak hashing algorithms."""
    
    WEAK_HASHES = {'md5', 'sha1', 'ripemd160'}
    
    @property
    def rule_id(self) -> str:
        return 'CRYPTO001'
    
    @property
    def description(self) -> str:
        return 'Use of weak hashing algorithms'
    
    @property
    def severity(self) -> str:
        return 'high'
    
    def analyze(self, node: ast.AST) -> None:
        """Check for usage of weak hashing algorithms."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib':
                    hash_name = node.func.attr.lower()
                    if hash_name in self.WEAK_HASHES:
                        self.add_vulnerability(
                            f"Use of weak hashing algorithm: {hash_name}",
                            node.lineno,
                            node
                        )

class InsecureCipherModeRule(BaseRule):
    """Rule for detecting insecure cipher modes."""
    
    @property
    def rule_id(self) -> str:
        return 'CRYPTO002'
    
    @property
    def description(self) -> str:
        return 'Use of insecure cipher modes (ECB)'
    
    @property
    def severity(self) -> str:
        return 'high'
    
    def analyze(self, node: ast.AST) -> None:
        """Check for usage of ECB mode."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'new':
                # Check for AES.new() or similar calls
                if isinstance(node.func.value, ast.Name):
                    # Check for ECB mode in arguments
                    for arg in node.args + [kw.value for kw in node.keywords]:
                        if isinstance(arg, ast.Attribute) and 'MODE_ECB' in ast.unparse(arg):
                            self.add_vulnerability(
                                "Use of insecure ECB cipher mode",
                                node.lineno,
                                node
                            )

class DeprecatedCryptoRule(BaseRule):
    """Rule for detecting deprecated cryptographic algorithms."""
    
    DEPRECATED_ALGOS = {
        'DES': 'des',
        'RC4': 'rc4',
        'Blowfish': 'blowfish',
        'IDEA': 'idea'
    }
    
    @property
    def rule_id(self) -> str:
        return 'CRYPTO003'
    
    @property
    def description(self) -> str:
        return 'Use of deprecated cryptographic algorithms'
    
    @property
    def severity(self) -> str:
        return 'high'
    
    def analyze(self, node: ast.AST) -> None:
        """Check for usage of deprecated algorithms."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                for algo_name, algo_id in self.DEPRECATED_ALGOS.items():
                    if algo_id in ast.unparse(node).lower():
                        self.add_vulnerability(
                            f"Use of deprecated algorithm: {algo_name}",
                            node.lineno,
                            node
                        )

class HardcodedSecretsRule(BaseRule):
    """Rule for detecting hardcoded cryptographic secrets."""
    
    @property
    def rule_id(self) -> str:
        return 'CRYPTO004'
    
    @property
    def description(self) -> str:
        return 'Hardcoded cryptographic secrets'
    
    @property
    def severity(self) -> str:
        return 'medium'
    
    def analyze(self, node: ast.AST) -> None:
        """Check for hardcoded secrets."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id.lower()
                    if any(secret in name for secret in {'key', 'secret', 'password', 'token', 'api_key'}):
                        if isinstance(node.value, (ast.Str, ast.Constant)):
                            value = node.value.s if isinstance(node.value, ast.Str) else node.value.value
                            if isinstance(value, str) and len(value) > 0:
                                self.add_vulnerability(
                                    f"Hardcoded secret in variable: {target.id}",
                                    node.lineno,
                                    node
                                )

class InsecurePRNGRule(BaseRule):
    """Rule for detecting insecure pseudo-random number generators."""
    
    INSECURE_RANDOM = {'random', 'randint', 'randrange', 'choice', 'shuffle'}
    
    @property
    def rule_id(self) -> str:
        return 'CRYPTO005'
    
    @property
    def description(self) -> str:
        return 'Use of insecure pseudo-random number generator'
    
    @property
    def severity(self) -> str:
        return 'medium'
    
    def analyze(self, node: ast.AST) -> None:
        """Check for usage of insecure PRNGs."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'random':
                    if node.func.attr in self.INSECURE_RANDOM:
                        self.add_vulnerability(
                            f"Use of insecure PRNG: random.{node.func.attr}",
                            node.lineno,
                            node
                        )

class UnverifiedSSLRule(BaseRule):
    """Rule for detecting unverified SSL connections."""
    
    @property
    def rule_id(self) -> str:
        return 'CRYPTO006'
    
    @property
    def description(self) -> str:
        return 'Use of unverified SSL connections'
    
    @property
    def severity(self) -> str:
        return 'high'
    
    def analyze(self, node: ast.AST) -> None:
        """Check for unverified SSL connections."""
        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name):
                context_var = node.targets[0].id
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute):
                        # Check for ssl.create_default_context()
                        if (isinstance(node.value.func.value, ast.Name) and 
                            node.value.func.value.id == 'ssl' and
                            node.value.func.attr == 'create_default_context'):
                            # Look for modifications to this context
                            parent = node
                            while hasattr(parent, 'parent'):
                                parent = parent.parent
                            for child in ast.walk(parent):
                                if isinstance(child, ast.Assign):
                                    if isinstance(child.targets[0], ast.Attribute):
                                        if (isinstance(child.targets[0].value, ast.Name) and
                                            child.targets[0].value.id == context_var and
                                            child.targets[0].attr in {'verify_mode', 'check_hostname'} and
                                            isinstance(child.value, ast.Constant) and
                                            (child.value.value == ssl.CERT_NONE or 
                                             child.value.value is False)):
                                            self.add_vulnerability(
                                                "SSL certificate verification disabled in SSL context",
                                                child.lineno,
                                                child
                                            )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # Check for requests with verify=False
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'requests':
                    for keyword in node.keywords:
                        if keyword.arg == 'verify' and isinstance(keyword.value, ast.Constant) and not keyword.value.value:
                            self.add_vulnerability(
                                "SSL certificate verification disabled in requests",
                                node.lineno,
                                node
                            )
                # Check for urllib3 with cert_reqs="NONE"
                elif isinstance(node.func.value, ast.Name) and node.func.value.id == 'urllib3':
                    for keyword in node.keywords:
                        if keyword.arg == 'cert_reqs' and isinstance(keyword.value, ast.Str) and keyword.value.s == 'NONE':
                            self.add_vulnerability(
                                "SSL certificate verification disabled in urllib3",
                                node.lineno,
                                node
                            )
        # Check for direct assignments to verify_mode or check_hostname
        elif isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Attribute):
                if node.targets[0].attr in {'verify_mode', 'check_hostname'}:
                    if isinstance(node.value, ast.Constant):
                        if node.value.value == ssl.CERT_NONE or node.value.value is False:
                            self.add_vulnerability(
                                "SSL certificate verification disabled",
                                node.lineno,
                                node
                            ) 