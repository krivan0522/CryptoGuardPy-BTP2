"""
Core analyzer module for CryptoGuardPy.
Handles AST parsing and basic analysis functionality.
"""

import ast
import logging
import os
from typing import List, Dict, Any, Type
from pathlib import Path

from .rules import AVAILABLE_RULES, BaseRule

class CryptoAnalyzer:
    """Main analyzer class for cryptographic vulnerability detection."""
    
    def __init__(self):
        """Initialize the analyzer with logging setup."""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Add console handler if not already present
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # Initialize rules
        self.rules = [rule() for rule in AVAILABLE_RULES]
    
    def parse_file(self, file_path: str) -> ast.AST:
        """
        Parse a Python file into an AST.
        
        Args:
            file_path (str): Path to the Python file to analyze
            
        Returns:
            ast.AST: The parsed Abstract Syntax Tree
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            SyntaxError: If the file contains invalid Python syntax
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                source = file.read()
            return ast.parse(source)
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            raise
        except SyntaxError as e:
            self.logger.error(f"Syntax error in {file_path}: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {str(e)}")
            raise
    
    def analyze_node(self, node: ast.AST) -> None:
        """
        Analyze a single AST node with all rules.
        
        Args:
            node (ast.AST): The AST node to analyze
        """
        for rule in self.rules:
            rule.analyze(node)
        
        # Recursively analyze child nodes
        for child in ast.iter_child_nodes(node):
            self.analyze_node(child)
    
    def analyze_file(self, file_path: str, min_severity: str = "low", 
                    selected_rules: Dict[str, bool] = None,
                    ignore_patterns: List[str] = None) -> Dict[str, Any]:
        """
        Analyze a Python file for cryptographic vulnerabilities.
        
        Args:
            file_path (str): Path to the Python file to analyze
            min_severity (str): Minimum severity level to report (low/medium/high)
            selected_rules (Dict[str, bool]): Dictionary of rule names and their enabled status
            ignore_patterns (List[str]): List of patterns to ignore in file paths
            
        Returns:
            Dict[str, Any]: Analysis results including any found vulnerabilities
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            SyntaxError: If the file contains invalid Python syntax
        """
        self.logger.info(f"Analyzing file: {file_path}")
        
        # Check if file should be ignored
        if ignore_patterns:
            for pattern in ignore_patterns:
                if pattern in file_path:
                    return {
                        'file_path': file_path,
                        'status': 'ignored',
                        'vulnerabilities': [],
                        'metadata': {
                            'total_vulnerabilities': 0,
                            'severity_score': 0.0
                        }
                    }
        
        try:
            tree = self.parse_file(file_path)
        except SyntaxError as e:
            self.logger.error(f"Error analyzing {file_path}: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {str(e)}")
            raise
            
        # Reset rules for new analysis
        self.rules = [rule() for rule in AVAILABLE_RULES]
        
        # Filter rules based on selection
        if selected_rules:
            self.rules = [rule for rule in self.rules 
                        if selected_rules.get(rule.__class__.__name__.lower(), True)]
        
        # Analyze the AST
        self.analyze_node(tree)
        
        # Collect results from all rules
        vulnerabilities = []
        for rule in self.rules:
            vulnerabilities.extend(rule.get_results())
        
        # Filter by severity
        severity_weights = {'high': 1.0, 'medium': 0.5, 'low': 0.2}
        min_weight = severity_weights.get(min_severity.lower(), 0.0)
        vulnerabilities = [v for v in vulnerabilities 
                        if severity_weights.get(v['severity'].lower(), 0.0) >= min_weight]
        
        # Calculate severity score
        severity_score = self._calculate_severity_score(vulnerabilities)
        
        return {
            'file_path': file_path,
            'status': 'completed',
            'vulnerabilities': vulnerabilities,
            'metadata': {
                'total_vulnerabilities': len(vulnerabilities),
                'severity_score': severity_score
            }
        }
    
    def _calculate_severity_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate an overall severity score for the vulnerabilities.
        
        Args:
            vulnerabilities (List[Dict[str, Any]]): List of vulnerability findings
            
        Returns:
            float: Severity score between 0 and 1
        """
        if not vulnerabilities:
            return 0.0
            
        severity_weights = {
            "high": 1.0,
            "medium": 0.5,
            "low": 0.2
        }
        
        total_weight = sum(severity_weights.get(v['severity'].lower(), 0) 
                         for v in vulnerabilities)
        max_possible_weight = len(vulnerabilities) * severity_weights["high"]
        
        return min(total_weight / max_possible_weight, 1.0)

class CryptoGuardAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.current_file = ""
        self.imports = set()
        self.current_function = None
        self.context_stack = []
        self.secure_random_vars = set()  # Track variables containing secure random values
        
    def analyze_file(self, file_path):
        if not os.path.exists(file_path):
            return []
            
        self.current_file = file_path
        self.imports = set()
        self.context_stack = []
        self.secure_random_vars = set()
        with open(file_path, 'r') as file:
            try:
                tree = ast.parse(file.read())
            except SyntaxError:
                return []
                
        self.vulnerabilities = []
        self.visit(tree)
        return self.vulnerabilities
        
    def visit(self, node):
        # Track context
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            self.context_stack.append(node)
            
        # Track imports
        if isinstance(node, ast.Import):
            for name in node.names:
                self.imports.add(name.name)
        elif isinstance(node, ast.ImportFrom):
            self.imports.add(node.module)
            for name in node.names:
                self.imports.add(f"{node.module}.{name.name}")
            
        # Track function definitions
        if isinstance(node, ast.FunctionDef):
            self.current_function = node.name
            
        # Track secure random generation
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute):
                        # Check if it's a call to secrets module functions
                        if (isinstance(node.value.func.value, ast.Name) and 
                            node.value.func.value.id == 'secrets' and 
                            node.value.func.attr in ['token_bytes', 'token_hex', 'token_urlsafe']):
                            self.secure_random_vars.add(node.targets[0].id)
                            
        # Check for weak hashing
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # Weak hashing detection
                if node.func.attr in ['md5', 'sha1', 'ripemd160']:
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib':
                        self.vulnerabilities.append({
                            'type': 'Weak Hashing',
                            'description': f'Use of weak hash function: {node.func.attr}',
                            'severity': 'high',
                            'line_number': getattr(node, 'lineno', 0)
                        })
                
                # Deprecated algorithms detection
                deprecated_algos = {
                    'DES': 'Data Encryption Standard',
                    'RC4': 'RC4 stream cipher',
                    'Blowfish': 'Blowfish',
                    'ARC4': 'RC4 stream cipher'
                }
                
                if node.func.attr == 'new':
                    if isinstance(node.func.value, ast.Name):
                        algo_name = node.func.value.id
                        if algo_name in deprecated_algos:
                            self.vulnerabilities.append({
                                'type': 'Deprecated Algorithms',
                                'description': f'Use of deprecated algorithm: {deprecated_algos[algo_name]}',
                                'severity': 'high',
                                'line_number': getattr(node, 'lineno', 0)
                            })
                
                # Insecure PRNG detection
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id == 'random':
                        if node.func.attr in ['random', 'randint', 'randrange', 'choice']:
                            if self._is_security_context():
                                self.vulnerabilities.append({
                                    'type': 'Insecure PRNGs',
                                    'description': 'Use of insecure random number generator in security-sensitive context',
                                    'severity': 'high',
                                    'line_number': getattr(node, 'lineno', 0)
                                })
                
                # Check for insecure cipher modes
                if node.func.attr == 'new':
                    cipher_modes = []
                    for arg in node.args:
                        if isinstance(arg, ast.Attribute) and arg.attr.startswith('MODE_'):
                            cipher_modes.append(arg.attr)
                    
                    if 'MODE_ECB' in cipher_modes:
                        self.vulnerabilities.append({
                            'type': 'Insecure Cipher Modes',
                            'description': 'Use of ECB mode is highly insecure',
                            'severity': 'high',
                            'line_number': getattr(node, 'lineno', 0)
                        })
                    elif 'MODE_CBC' in cipher_modes:
                        # Check if IV is properly handled
                        has_iv = False
                        has_secure_iv = False
                        
                        # Check for IV in the constructor
                        if len(node.args) > 2:  # Should have key, mode, and IV
                            iv_arg = node.args[2]
                            if isinstance(iv_arg, ast.Name):
                                has_iv = True
                                if iv_arg.id in self.secure_random_vars:
                                    has_secure_iv = True
                                
                        if not has_iv:
                            self.vulnerabilities.append({
                                'type': 'Insecure Cipher Modes',
                                'description': 'CBC mode used without IV parameter',
                                'severity': 'high',
                                'line_number': getattr(node, 'lineno', 0)
                            })
                        elif not has_secure_iv:
                            self.vulnerabilities.append({
                                'type': 'Insecure Cipher Modes',
                                'description': 'CBC mode used with potentially insecure IV - ensure IV is randomly generated',
                                'severity': 'medium',
                                'line_number': getattr(node, 'lineno', 0)
                            })
                
                # Unverified SSL detection
                if node.func.attr == 'create_default_context':
                    self._track_ssl_context(node)
                elif node.func.attr == 'wrap_socket':
                    self.vulnerabilities.append({
                        'type': 'Unverified SSL',
                        'description': 'Direct SSL socket wrapping detected - verify SSL settings',
                        'severity': 'medium',
                        'line_number': getattr(node, 'lineno', 0)
                    })
                
                # Unsafe libraries detection
                if node.func.attr in ['loads', 'load']:
                    if isinstance(node.func.value, ast.Name):
                        unsafe_libs = {
                            'pickle': 'Python pickle module',
                            'yaml': 'YAML loader without safe_load',
                            'marshal': 'Python marshal module'
                        }
                        if node.func.value.id in unsafe_libs:
                            self.vulnerabilities.append({
                                'type': 'Unsafe Libraries',
                                'description': f'Use of unsafe deserialization: {unsafe_libs[node.func.value.id]}',
                                'severity': 'high',
                                'line_number': getattr(node, 'lineno', 0)
                            })
        
        # Check for hardcoded secrets
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if any(key in target.id.lower() for key in ['key', 'password', 'secret', 'token', 'salt']):
                        if isinstance(node.value, (ast.Str, ast.Bytes, ast.Constant)):
                            self.vulnerabilities.append({
                                'type': 'Hardcoded Secrets',
                                'description': f'Hardcoded secret detected: {target.id}',
                                'severity': 'high',
                                'line_number': getattr(node, 'lineno', 0)
                            })
        
        # Check for SSL verification disabling
        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Attribute):
                attr_name = node.targets[0].attr
                if attr_name in ['verify_mode', 'check_hostname']:
                    if isinstance(node.value, (ast.Constant, ast.NameConstant)):
                        if (attr_name == 'verify_mode' and 
                            (getattr(node.value, 'value', None) == 'CERT_NONE' or 
                             getattr(node.value, 'n', None) == 0)):
                            self.vulnerabilities.append({
                                'type': 'Unverified SSL',
                                'description': 'SSL certificate verification disabled',
                                'severity': 'high',
                                'line_number': getattr(node, 'lineno', 0)
                            })
                        elif attr_name == 'check_hostname' and not getattr(node.value, 'value', True):
                            self.vulnerabilities.append({
                                'type': 'Unverified SSL',
                                'description': 'SSL hostname verification disabled',
                                'severity': 'high',
                                'line_number': getattr(node, 'lineno', 0)
                            })
        
        # Visit all child nodes
        for child in ast.iter_child_nodes(node):
            self.visit(child)
            
        # Pop context
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if self.context_stack:
                self.context_stack.pop()
            
    def _is_security_context(self):
        """Check if current context is security-sensitive."""
        security_terms = {'token', 'password', 'secret', 'key', 'hash', 'crypt', 'random', 'salt'}
        for ctx in self.context_stack:
            if any(term in ctx.name.lower() for term in security_terms):
                return True
        return False
    
    def _track_ssl_context(self, node):
        """Track SSL context creation and configuration."""
        parent = self._find_parent_assign(node)
        if parent:
            self.vulnerabilities.append({
                'type': 'Unverified SSL',
                'description': 'SSL context creation detected - verify security settings',
                'severity': 'low',
                'line_number': getattr(node, 'lineno', 0)
            })
            
    def _find_parent_assign(self, node):
        """Helper method to find parent assignment statement."""
        class AssignFinder(ast.NodeVisitor):
            def __init__(self, target):
                self.target = target
                self.found = None
                
            def visit_Assign(self, node):
                for child in ast.walk(node):
                    if child == self.target:
                        self.found = node
                        return
                self.generic_visit(node)
                
        finder = AssignFinder(node)
        finder.visit(ast.parse(open(self.current_file).read()))
        return finder.found 