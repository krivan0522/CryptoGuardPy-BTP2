# Installation Guide for CryptoGuardPy

This guide will help you set up CryptoGuardPy on your system.

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git (optional, for cloning the repository)

## Installation Methods

### Method 1: Direct Installation

1. Clone the repository (if using Git):
   ```bash
   git clone https://github.com/yourusername/cryptoguardpy.git
   cd cryptoguardpy
   ```

   Or download and extract the ZIP file from the repository.

2. Create and activate a virtual environment (recommended):
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux/MacOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Method 2: Using pip (if published to PyPI)

```bash
pip install cryptoguardpy
```

## Verifying Installation

1. Run the command-line interface:
   ```bash
   python main.py --help
   ```

2. Or start the web interface:
   ```bash
   python app.py
   ```

   The web interface should be accessible at `http://localhost:8501`

## Configuration

1. Default configuration is provided out of the box
2. Custom configuration can be specified using a JSON file:
   ```bash
   python main.py --config path/to/config.json
   ```

## Common Issues and Solutions

### Issue: Missing Dependencies
If you encounter missing dependency errors, try:
```bash
pip install --upgrade -r requirements.txt
```

### Issue: Version Conflicts
If you encounter version conflicts, try creating a fresh virtual environment:
```bash
deactivate  # if a virtual environment is active
python -m venv venv_new
# Activate the new environment and install dependencies
```

### Issue: Permission Errors
- Windows: Run the command prompt as administrator
- Linux/MacOS: Use `sudo` for system-wide installation or use virtual environments

## System-Specific Notes

### Windows
- Ensure Python is added to your PATH
- Use `python` instead of `python3` in commands
- Use `.\venv\Scripts\activate` for virtual environment

### Linux/MacOS
- Use `python3` instead of `python` in commands
- Use `source venv/bin/activate` for virtual environment
- Ensure proper permissions for installation directories

## Development Installation

For developers who want to contribute:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cryptoguardpy.git
   cd cryptoguardpy
   ```

2. Create a development virtual environment:
   ```bash
   python -m venv venv
   # Activate the virtual environment (see above)
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install pre-commit hooks (optional):
   ```bash
   pre-commit install
   ```

## Next Steps

- Read the [README.md](README.md) for usage instructions
- Check out the example files in the repository
- Try scanning your first Python file for vulnerabilities

## Support

If you encounter any issues during installation:
1. Check the [Common Issues](#common-issues-and-solutions) section above
2. Search existing GitHub issues
3. Create a new issue if your problem persists

## Updating

To update CryptoGuardPy to the latest version:

```bash
git pull  # if installed from git
pip install --upgrade -r requirements.txt
``` 