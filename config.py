#!/usr/bin/env python3
"""
Configuration management for Veracode Component Matcher

Provides environment-specific configuration and defaults.
"""

import os
import json
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class APIConfig:
    """API configuration"""
    max_retries: int = 3
    backoff_factor: float = 2.0
    request_timeout: int = 30
    rate_limit_interval: float = 0.5
    app_batch_size: int = 10
    cache_dir: str = '.cache'
    cache_ttl_hours: int = 24


@dataclass
class ExportConfig:
    """Export configuration"""
    output_dir: str = '.'
    formats: list = None  # ['json', 'csv']
    include_matching: bool = True
    include_raw_json: bool = True
    timestamp_exports: bool = True
    overwrite_existing: bool = False

    def __post_init__(self):
        if self.formats is None:
            self.formats = ['json', 'csv']


@dataclass
class LogConfig:
    """Logging configuration"""
    level: str = 'INFO'
    format: str = '%(asctime)s - %(levelname)s - %(message)s'
    file_output: Optional[str] = None
    verbose: bool = False


class Config:
    """Application configuration manager"""

    def __init__(self):
        self.api = APIConfig()
        self.export = ExportConfig()
        self.log = LogConfig()
        self.env = os.getenv('VERACODE_ENV', 'production')

    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables"""
        config = cls()

        # API configuration
        if env_retries := os.getenv('VERACODE_MAX_RETRIES'):
            config.api.max_retries = int(env_retries)

        if env_backoff := os.getenv('VERACODE_BACKOFF_FACTOR'):
            config.api.backoff_factor = float(env_backoff)

        if env_timeout := os.getenv('VERACODE_TIMEOUT'):
            config.api.request_timeout = int(env_timeout)

        if env_rate_limit := os.getenv('VERACODE_RATE_LIMIT'):
            config.api.rate_limit_interval = float(env_rate_limit)

        # Export configuration
        if env_output := os.getenv('VERACODE_OUTPUT_DIR'):
            config.export.output_dir = env_output

        if env_formats := os.getenv('VERACODE_EXPORT_FORMATS'):
            config.export.formats = env_formats.split(',')

        if env_match := os.getenv('VERACODE_INCLUDE_MATCHING'):
            config.export.include_matching = env_match.lower() == 'true'

        # Logging configuration
        if env_log_level := os.getenv('VERACODE_LOG_LEVEL'):
            config.log.level = env_log_level

        if env_log_file := os.getenv('VERACODE_LOG_FILE'):
            config.log.file_output = env_log_file

        if env_verbose := os.getenv('VERACODE_VERBOSE'):
            config.log.verbose = env_verbose.lower() == 'true'

        return config

    @classmethod
    def from_file(cls, config_path: str) -> 'Config':
        """Load configuration from JSON file"""
        config = cls()

        try:
            with open(config_path, 'r') as f:
                data = json.load(f)

            # Load API configuration
            if 'api' in data:
                for key, value in data['api'].items():
                    if hasattr(config.api, key):
                        setattr(config.api, key, value)

            # Load export configuration
            if 'export' in data:
                for key, value in data['export'].items():
                    if hasattr(config.export, key):
                        setattr(config.export, key, value)

            # Load logging configuration
            if 'log' in data:
                for key, value in data['log'].items():
                    if hasattr(config.log, key):
                        setattr(config.log, key, value)

        except FileNotFoundError:
            pass  # Use defaults

        return config

    def to_dict(self) -> dict:
        """Convert configuration to dictionary"""
        return {
            'api': {
                'max_retries': self.api.max_retries,
                'backoff_factor': self.api.backoff_factor,
                'request_timeout': self.api.request_timeout,
                'rate_limit_interval': self.api.rate_limit_interval,
                'app_batch_size': self.api.app_batch_size,
                'cache_dir': self.api.cache_dir,
                'cache_ttl_hours': self.api.cache_ttl_hours,
            },
            'export': {
                'output_dir': self.export.output_dir,
                'formats': self.export.formats,
                'include_matching': self.export.include_matching,
                'include_raw_json': self.export.include_raw_json,
                'timestamp_exports': self.export.timestamp_exports,
                'overwrite_existing': self.export.overwrite_existing,
            },
            'log': {
                'level': self.log.level,
                'format': self.log.format,
                'file_output': self.log.file_output,
                'verbose': self.log.verbose,
            },
            'env': self.env,
        }

    def save_to_file(self, config_path: str):
        """Save configuration to JSON file"""
        with open(config_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Default configuration instance
default_config = Config()
