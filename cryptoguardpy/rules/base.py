"""
Base class for vulnerability detection rules.
"""

import ast
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class Vulnerability:
    """Class representing a detected vulnerability."""
    
    def __init__(self, rule_id: str, severity: str, message: str, line_no: int, node: ast.AST):
        """
        Initialize a vulnerability.
        
        Args:
            rule_id (str): Unique identifier for the rule that found this vulnerability
            severity (str): Severity level ('low', 'medium', 'high')
            message (str): Description of the vulnerability
            line_no (int): Line number where the vulnerability was found
            node (ast.AST): AST node where the vulnerability was found
        """
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.line_no = line_no
        self.node = node
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary format."""
        return {
            'rule_id': self.rule_id,
            'severity': self.severity,
            'message': self.message,
            'line_no': self.line_no,
            'code': ast.unparse(self.node) if self.node else None
        }

class BaseRule(ABC):
    """Base class for all vulnerability detection rules."""
    
    def __init__(self):
        """Initialize the rule."""
        self.vulnerabilities: List[Vulnerability] = []
    
    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for the rule."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what the rule detects."""
        pass
    
    @property
    @abstractmethod
    def severity(self) -> str:
        """Severity level of vulnerabilities found by this rule."""
        pass
    
    @abstractmethod
    def analyze(self, node: ast.AST) -> None:
        """
        Analyze an AST node for vulnerabilities.
        
        Args:
            node (ast.AST): The AST node to analyze
        """
        pass
    
    def add_vulnerability(self, message: str, line_no: int, node: ast.AST) -> None:
        """
        Add a vulnerability to the list of findings.
        
        Args:
            message (str): Description of the vulnerability
            line_no (int): Line number where the vulnerability was found
            node (ast.AST): AST node where the vulnerability was found
        """
        vuln = Vulnerability(
            rule_id=self.rule_id,
            severity=self.severity,
            message=message,
            line_no=line_no,
            node=node
        )
        self.vulnerabilities.append(vuln)
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get the results of the analysis."""
        return [v.to_dict() for v in self.vulnerabilities] 