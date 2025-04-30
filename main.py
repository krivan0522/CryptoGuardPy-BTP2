"""
Main entry point for CryptoGuardPy.
"""

import argparse
import logging
import json
import os
from pathlib import Path
from cryptoguardpy import CryptoGuardAnalyzer
from cryptoguardpy.config import Config
from cryptoguardpy.report import ReportGenerator

import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from functools import partial
import concurrent.futures

def analyze_single_file(file_path, directory_path):
    """
    Analyze a single file and return its results.
    
    Args:
        file_path (Path): Path to the file to analyze
        directory_path (str): Base directory path for relative path calculation
    """
    analyzer = CryptoGuardAnalyzer()
    try:
        vulnerabilities = analyzer.analyze_file(str(file_path))
        if vulnerabilities:
            return {
                'file': str(file_path.relative_to(directory_path)),
                'vulnerabilities': vulnerabilities
            }
    except Exception as e:
        print(f"\nError analyzing {file_path}: {str(e)}")
    return None

def analyze_directory(directory_path, output_file=None):
    """
    Analyze all Python files in a directory for cryptographic vulnerabilities using parallel processing.
    
    Args:
        directory_path (str): Path to the directory to analyze
        output_file (str, optional): Path to save the JSON report
    """
    # Get total number of Python files
    python_files = list(Path(directory_path).rglob("*.py"))
    total_files = len(python_files)
    
    print(f"Found {total_files} Python files to analyze...")
    
    # Determine optimal number of processes (usually number of CPU cores)
    num_processes = multiprocessing.cpu_count()
    
    # Create a partial function with fixed directory_path
    analyze_func = partial(analyze_single_file, directory_path=directory_path)
    
    results = []
    processed_files = 0
    
    # Use ProcessPoolExecutor for parallel processing
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        # Submit all files for processing
        future_to_file = {executor.submit(analyze_func, file_path): file_path 
                         for file_path in python_files}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            processed_files += 1
            
            try:
                result = future.result()
                if result:
                    results.append(result)
                
                # Print progress
                print(f"\rProgress: {processed_files}/{total_files} files analyzed "
                      f"({(processed_files/total_files)*100:.1f}%)", end="")
                
            except Exception as e:
                print(f"\nError analyzing {file_path}: {str(e)}")
    
    print("\nAnalysis complete!")
    
    # Calculate statistics
    vulnerable_files = len(results)
    vulnerability_rate = (vulnerable_files / total_files) * 100 if total_files > 0 else 0
    
    # Create summary
    summary = {
        'statistics': {
            'total_files': total_files,
            'vulnerable_files': vulnerable_files,
            'vulnerability_rate': f"{vulnerability_rate:.1f}%"
        },
        'results': results
    }
    
    # Output results
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\nReport saved to: {output_file}")
    else:
        print("\nSummary:")
        print(f"Total files analyzed: {total_files}")
        print(f"Files with vulnerabilities: {vulnerable_files}")
        print(f"Vulnerability rate: {vulnerability_rate:.1f}%")
        
        if results:
            print("\nVulnerabilities found:")
            for result in results:
                print(f"\nFile: {result['file']}")
                for vuln in result['vulnerabilities']:
                    print(f"- Line {vuln.get('line_number', 'Unknown')}: {vuln['type']} - "
                          f"{vuln['description']} (Severity: {vuln.get('severity', 'medium')})")

def main():
    parser = argparse.ArgumentParser(
        description="CryptoGuardPy - Python Cryptographic Vulnerability Scanner"
    )
    parser.add_argument(
        "path",
        help="Path to file or directory to analyze"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON report file path",
        default=None
    )
    
    args = parser.parse_args()
    
    if os.path.isdir(args.path):
        analyze_directory(args.path, args.output)
    else:
        analyzer = CryptoGuardAnalyzer()
        try:
            vulnerabilities = analyzer.analyze_file(args.path)
            if vulnerabilities:
                result = {
                    'file': os.path.basename(args.path),
                    'vulnerabilities': vulnerabilities
                }
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"Report saved to: {args.output}")
                else:
                    print(f"\nVulnerabilities found in {args.path}:")
                    for vuln in vulnerabilities:
                        print(f"- Line {vuln.get('line_number', 'Unknown')}: {vuln['type']} - {vuln['description']} "
                              f"(Severity: {vuln.get('severity', 'medium')})")
            else:
                print("No vulnerabilities found!")
        except Exception as e:
            print(f"Error analyzing {args.path}: {str(e)}")

if __name__ == "__main__":
    main() 