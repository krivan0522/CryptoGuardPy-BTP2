"""
Configuration module for CryptoGuardPy.
Handles loading and managing application settings.
"""

import os
from typing import Dict, Any
from pathlib import Path
import json
import logging

class Config:
    """Configuration management class."""
    
    def __init__(self, config_path: str = None):
        """
        Initialize configuration.
        
        Args:
            config_path (str, optional): Path to configuration file. Defaults to None.
        """
        self.logger = logging.getLogger(__name__)
        self.config = self._load_default_config()
        
        if config_path:
            self.load_config(config_path)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration settings."""
        return {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'analysis': {
                'max_file_size': 10485760,  # 10MB
                'excluded_dirs': ['__pycache__', '.git', 'venv'],
                'excluded_files': ['*.pyc', '*.pyo', '*.pyd']
            }
        }
    
    def load_config(self, config_path: str) -> None:
        """
        Load configuration from a file.
        
        Args:
            config_path (str): Path to configuration file
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If config file is invalid JSON
        """
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                self.config.update(user_config)
            self.logger.info(f"Loaded configuration from {config_path}")
        except FileNotFoundError:
            self.logger.warning(f"Configuration file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid configuration file format: {str(e)}")
            raise
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key (str): Configuration key
            default (Any, optional): Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value 