# CryptoGuardPy

A static analysis tool for detecting cryptographic vulnerabilities in Python code.

## Overview

CryptoGuardPy is an advanced static analysis tool designed to identify cryptographic vulnerabilities in Python source files. By analyzing the Abstract Syntax Tree (AST) and code structure of Python files, CryptoGuardPy can detect common security issues without executing the code, making it a safe and efficient way to audit your codebase for potential cryptographic weaknesses.

## Features

- **Static Code Analysis**: Analyze Python source files without execution
- **AST-based Detection**: Traverse Python's Abstract Syntax Tree to find vulnerable patterns
- **Rule-based Scanning**: Comprehensive set of rules for detecting cryptographic issues
- **JSON Reports**: Detailed vulnerability reports in machine-readable format
- **Streamlit Web Interface**: User-friendly UI for scanning files and viewing results
- **Severity Scoring**: Security issues are ranked by severity (low, medium, high)

## Vulnerabilities Detected

- Weak hashing algorithms (MD5, SHA1, RIPEMD160)
- Insecure cipher modes (ECB mode)
- Deprecated cryptographic algorithms (DES, RC4, Blowfish)
- Hardcoded cryptographic secrets
- Insecure Pseudo-Random Number Generators
- Unverified SSL/TLS connections
- Usage of deprecated/unsafe crypto libraries

## Project Development Phases

### Phase 1: Core Infrastructure Development
- [x] Project setup and use the current file location as the repository
- [x] Design modular architecture for the analyzer
- [x] Create basic Python AST parsing functionality
- [x] Implement configuration loading mechanism
- [x] Develop logging and reporting infrastructure

### Phase 2: Vulnerability Detection Rules
- [x] Implement rule framework for vulnerability detection
- [x] Create detection rules for weak hashing algorithms
- [x] Create detection rules for insecure cipher modes
- [x] Create detection rules for deprecated cryptographic algorithms
- [x] Implement hardcoded secret detection logic
- [x] Develop detection for insecure PRNG usage
- [x] Implement detection of unverified SSL connections
- [x] Create detection rules for unsafe libraries

### Phase 3: Output and Reporting
- [x] Design JSON output format structure
- [x] Implement vulnerability severity scoring algorithm
- [x] Create detailed reporting mechanism with context
- [x] Add file and line number tracking
- [x] Develop report generation functionality

### Phase 4: User Interface Development
- [x] Set up Streamlit app skeleton
- [x] Create repository upload functionality
- [x] Implement report visualization components
- [x] Develop code highlighting for vulnerabilities
- [x] Add report download functionality
- [x] Implement scan configuration options
- [x] Create help and documentation sections

### Phase 5: Testing and Validation
- [x] Create sample vulnerable Python files
- [x] Perform unit testing for each detection rule
- [x] Execute integration testing for the entire system
- [x] Validate detection accuracy against known vulnerabilities
- [x] Document edge cases and limitations

### Phase 6: Documentation and Finalization
- [x] Complete code documentation and comments
- [x] Write comprehensive usage instructions
- [x] Create installation guide
- [x] Prepare IEEE format final project report
- [x] Develop presentation slide deck
- [x] Final code quality review and refactoring


## Technical Details

CryptoGuardPy uses Python's built-in `ast` module to parse source code into an Abstract Syntax Tree. It then applies various visitor patterns to traverse this tree and identify patterns that match known cryptographic vulnerabilities.

The tool's rule-based architecture makes it easily extensible. New vulnerability detection rules can be added by implementing the `BaseRule` interface and registering them with the analyzer.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Python AST module documentation
- OWASP Cryptographic Storage Cheat Sheet
- Various cryptographic libraries' security best practices