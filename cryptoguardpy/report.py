"""
Report generation module for CryptoGuardPy.
"""

import json
from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime

class ReportGenerator:
    """Class for generating vulnerability reports."""
    
    SEVERITY_WEIGHTS = {
        'high': 3,
        'medium': 2,
        'low': 1
    }
    
    def __init__(self, output_dir: str = None):
        """
        Initialize the report generator.
        
        Args:
            output_dir (str, optional): Directory to save reports. Defaults to None.
        """
        self.output_dir = Path(output_dir) if output_dir else None
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def calculate_severity_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate an overall severity score for the analysis.
        
        Args:
            vulnerabilities (List[Dict[str, Any]]): List of detected vulnerabilities
            
        Returns:
            float: Overall severity score (0.0 to 1.0)
        """
        if not vulnerabilities:
            return 0.0
        
        total_weight = 0
        for vuln in vulnerabilities:
            total_weight += self.SEVERITY_WEIGHTS.get(vuln['severity'], 1)
        
        max_possible_weight = len(vulnerabilities) * self.SEVERITY_WEIGHTS['high']
        return total_weight / max_possible_weight if max_possible_weight > 0 else 0.0
    
    def generate_report(self, analysis_results: Dict[str, Any], format: str = 'json') -> Dict[str, Any]:
        """
        Generate a report from analysis results.
        
        Args:
            analysis_results (Dict[str, Any]): Results from the analyzer
            format (str): Output format ('json' or 'human')
            
        Returns:
            Dict[str, Any]: Generated report
        """
        # Use the severity score from the analyzer if available
        severity_score = analysis_results.get('metadata', {}).get('severity_score', 
                        self.calculate_severity_score(analysis_results['vulnerabilities']))
        
        # Generate report
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'file_analyzed': analysis_results['file_path'],
                'status': analysis_results.get('status', 'completed'),
                'severity_score': severity_score,
                'vulnerability_count': len(analysis_results['vulnerabilities'])
            },
            'vulnerabilities': analysis_results['vulnerabilities']
        }
        
        # Add summary statistics
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in analysis_results['vulnerabilities']:
            severity_counts[vuln['severity']] += 1
        
        report['summary'] = {
            'severity_counts': severity_counts,
            'recommendations': self._generate_recommendations(severity_counts)
        }
        
        if self.output_dir:
            self._save_report(report, format)
        
        return report
    
    def _generate_recommendations(self, severity_counts: Dict[str, int]) -> List[str]:
        """Generate recommendations based on vulnerability counts."""
        recommendations = []
        
        if severity_counts['high'] > 0:
            recommendations.append(
                f"Critical: {severity_counts['high']} high severity vulnerabilities found. "
                "These should be addressed immediately."
            )
        
        if severity_counts['medium'] > 0:
            recommendations.append(
                f"Warning: {severity_counts['medium']} medium severity vulnerabilities found. "
                "These should be addressed in the next development cycle."
            )
        
        if severity_counts['low'] > 0:
            recommendations.append(
                f"Note: {severity_counts['low']} low severity vulnerabilities found. "
                "Consider addressing these in future updates."
            )
        
        if not any(severity_counts.values()):
            recommendations.append("No vulnerabilities found. Good job!")
        
        return recommendations
    
    def _save_report(self, report: Dict[str, Any], format: str) -> None:
        """Save the report to a file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"cryptoguard_report_{timestamp}"
        
        if format == 'json':
            filepath = self.output_dir / f"{filename}.json"
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
        else:
            filepath = self.output_dir / f"{filename}.txt"
            with open(filepath, 'w') as f:
                f.write(self._format_human_readable(report))
    
    def _format_human_readable(self, report: Dict[str, Any]) -> str:
        """Format report for human-readable output."""
        output = []
        
        # Header
        output.append("=" * 80)
        output.append("CryptoGuardPy Analysis Report")
        output.append("=" * 80)
        output.append(f"File: {report['metadata']['file_analyzed']}")
        output.append(f"Timestamp: {report['metadata']['timestamp']}")
        output.append(f"Severity Score: {report['metadata']['severity_score']:.2f}")
        output.append("")
        
        # Summary
        output.append("Summary")
        output.append("-" * 80)
        for rec in report['summary']['recommendations']:
            output.append(rec)
        output.append("")
        
        # Vulnerabilities
        if report['vulnerabilities']:
            output.append("Vulnerabilities")
            output.append("-" * 80)
            for vuln in report['vulnerabilities']:
                output.append(f"[{vuln['rule_id']} - {vuln['severity'].upper()}]")
                output.append(f"Line {vuln['line_no']}: {vuln['message']}")
                output.append(f"Code: {vuln['code']}")
                output.append("")
        
        return "\n".join(output) 