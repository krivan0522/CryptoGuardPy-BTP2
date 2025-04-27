import streamlit as st
import os
import json
from cryptoguardpy import CryptoGuardAnalyzer
import tempfile
import shutil
from pathlib import Path

# Page config
st.set_page_config(
    page_title="CryptoGuardPy",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
    }
    .vulnerability-card {
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
        background-color: #f0f2f6;
    }
    .high-severity {
        border-left: 4px solid #ff4b4b;
    }
    .medium-severity {
        border-left: 4px solid #ffa500;
    }
    .low-severity {
        border-left: 4px solid #00cc00;
    }
    .help-section {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

def save_uploaded_files(uploaded_files, temp_dir):
    """Save uploaded files to temporary directory maintaining structure."""
    saved_files = []
    for uploaded_file in uploaded_files:
        # Get the relative path from the uploaded file
        file_path = Path(uploaded_file.name)
        # Create the full path in temp directory
        full_path = Path(temp_dir) / file_path
        # Create parent directories if they don't exist
        full_path.parent.mkdir(parents=True, exist_ok=True)
        # Save the file
        with open(full_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        saved_files.append(str(file_path))
    return saved_files

def analyze_directory(directory_path):
    """Analyze all Python files in a directory."""
    analyzer = CryptoGuardAnalyzer()
    results = []
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                try:
                    vulnerabilities = analyzer.analyze_file(file_path)
                    if vulnerabilities:
                        results.append({
                            'file': os.path.relpath(file_path, directory_path),
                            'vulnerabilities': vulnerabilities
                        })
                except Exception as e:
                    st.error(f"Error analyzing {file}: {str(e)}")
    return results

def show_help_section():
    with st.expander("📚 Help & Documentation"):
        st.markdown("""
        ### How to Use CryptoGuardPy

        1. **File Upload**
           - Upload a Python file using the file uploader
           - Currently supports single .py files
           - Maximum file size: 200MB

        2. **Scan Configuration**
           - Adjust severity thresholds
           - Select specific rule categories to scan
           - Configure custom rules (if enabled)

        3. **Analysis**
           - Click 'Analyze File' to start the scan
           - The tool will analyze the code for cryptographic vulnerabilities
           - Results are displayed with severity-based highlighting

        4. **Results**
           - View the overall severity score
           - Read detailed vulnerability descriptions
           - See affected code snippets
           - Download the complete report in JSON format

        ### Vulnerability Categories

        - Weak hashing algorithms (MD5, SHA1)
        - Insecure cipher modes (ECB)
        - Deprecated algorithms
        - Hardcoded secrets
        - Insecure PRNGs
        - Unverified SSL/TLS
        - Unsafe crypto libraries

        ### Need Help?
        For more information, visit our [GitHub repository](https://github.com/yourusername/cryptoguardpy)
        """)

def show_scan_config():
    st.sidebar.markdown("### 🔧 Scan Configuration")
    
    # Severity threshold
    st.sidebar.markdown("#### Severity Threshold")
    min_severity = st.sidebar.select_slider(
        "Minimum severity to report",
        options=["Low", "Medium", "High"],
        value="Low"
    )
    
    # Rule categories
    st.sidebar.markdown("#### Rule Categories")
    rule_categories = {
        "weak_hash": "Weak Hashing Algorithms",
        "insecure_cipher": "Insecure Cipher Modes",
        "deprecated_algo": "Deprecated Algorithms",
        "hardcoded_secrets": "Hardcoded Secrets",
        "insecure_prng": "Insecure PRNGs",
        "ssl_verify": "SSL/TLS Verification",
        "unsafe_libs": "Unsafe Libraries"
    }
    
    selected_rules = {}
    for key, name in rule_categories.items():
        selected_rules[key] = st.sidebar.checkbox(name, value=True)
    
    # Advanced options
    st.sidebar.markdown("#### Advanced Options")
    custom_rules = st.sidebar.file_uploader("Upload custom rules (JSON)", type=["json"], accept_multiple_files=False)
    ignore_patterns = st.sidebar.text_input("Ignore patterns (comma-separated)", value="venv/,tests/")
    
    return {
        "min_severity": min_severity,
        "selected_rules": selected_rules,
        "custom_rules": custom_rules,
        "ignore_patterns": ignore_patterns
    }

def main():
    st.title("🔒 CryptoGuardPy")
    st.write("A static analysis tool for detecting cryptographic vulnerabilities in Python code")
    
    # Sidebar for upload options
    st.sidebar.title("Analysis Options")
    upload_type = st.sidebar.radio(
        "Choose upload type:",
        ["Single File", "Multiple Files", "Directory"]
    )
    
    # Main content area
    if upload_type == "Single File":
        uploaded_file = st.file_uploader("Upload a Python file", type=['py'])
        if uploaded_file:
            with tempfile.TemporaryDirectory() as temp_dir:
                file_path = os.path.join(temp_dir, uploaded_file.name)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                analyzer = CryptoGuardAnalyzer()
                try:
                    results = analyzer.analyze_file(file_path)
                    if results:
                        st.write("### Analysis Results")
                        for vuln in results:
                            st.warning(
                                f"**{vuln['type']}** (Line {vuln.get('line_number', 'Unknown')})\n\n"
                                f"- Description: {vuln['description']}\n"
                                f"- Severity: {vuln.get('severity', 'medium')}"
                            )
                    else:
                        st.success("No vulnerabilities found!")
                except Exception as e:
                    st.error(f"Error analyzing file: {str(e)}")
    
    elif upload_type == "Multiple Files":
        uploaded_files = st.file_uploader("Upload Python files", type=['py'], accept_multiple_files=True)
        if uploaded_files:
            with tempfile.TemporaryDirectory() as temp_dir:
                saved_files = save_uploaded_files(uploaded_files, temp_dir)
                st.write(f"Analyzing {len(saved_files)} files...")
                
                results = analyze_directory(temp_dir)
                if results:
                    st.write("### Analysis Results")
                    for file_result in results:
                        with st.expander(f"📄 {file_result['file']}"):
                            for vuln in file_result['vulnerabilities']:
                                st.warning(
                                    f"**{vuln['type']}** (Line {vuln.get('line_number', 'Unknown')})\n\n"
                                    f"- Description: {vuln['description']}\n"
                                    f"- Severity: {vuln.get('severity', 'medium')}"
                                )
                else:
                    st.success("No vulnerabilities found in any files!")
    
    else:  # Directory upload
        st.info("To analyze a directory, please provide the directory path in the text input below:")
        dir_path = st.text_input("Directory path:", "")
        
        if dir_path:
            if os.path.isdir(dir_path):
                st.write(f"Analyzing directory: {dir_path}")
                results = analyze_directory(dir_path)
                
                if results:
                    st.write("### Analysis Results")
                    # Add download button for JSON report
                    json_report = json.dumps(results, indent=2)
                    st.download_button(
                        "Download Full Report (JSON)",
                        json_report,
                        "cryptoguard_report.json",
                        "application/json"
                    )
                    
                    # Display results in expandable sections
                    for file_result in results:
                        with st.expander(f"📄 {file_result['file']}"):
                            for vuln in file_result['vulnerabilities']:
                                st.warning(
                                    f"**{vuln['type']}** (Line {vuln.get('line_number', 'Unknown')})\n\n"
                                    f"- Description: {vuln['description']}\n"
                                    f"- Severity: {vuln.get('severity', 'medium')}"
                                )
                                
                    # Display summary statistics
                    total_files = sum(1 for _ in Path(dir_path).rglob("*.py"))
                    vulnerable_files = len(results)
                    st.write("### Summary")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Python Files", total_files)
                    with col2:
                        st.metric("Files with Vulnerabilities", vulnerable_files)
                    with col3:
                        if total_files > 0:
                            percentage = (vulnerable_files / total_files) * 100
                            st.metric("Percentage Vulnerable", f"{percentage:.1f}%")
                else:
                    st.success("No vulnerabilities found in any files!")
            else:
                st.error("Invalid directory path. Please provide a valid directory path.")

    # Show help section at the bottom
    show_help_section()

if __name__ == "__main__":
    main() 