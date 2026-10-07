#!/usr/bin/env python3
"""
Automated Veracode Component Matcher Runner

Provides automated, batch-oriented workflow execution with configuration support.

Run with:
    python run_automated.py
    python run_automated.py --config config.json
    python run_automated.py --mode vuln --output ./results
"""

import sys
import argparse
import logging
from typing import Optional

from config import Config
from workflow import WorkflowExecutor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Configure logging"""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)

        logger.info(f"Logging to file: {log_file}")


def run_with_config(config: Config, args: argparse.Namespace) -> dict:
    """Execute workflow with given configuration"""

    # Override config with command-line args if provided
    if args.mode:
        logger.debug(f"Mode: {args.mode}")
    if args.limit:
        logger.debug(f"App limit: {args.limit}")
    if args.output:
        config.export.output_dir = args.output

    # Create executor
    executor = WorkflowExecutor(config)

    # Run workflow
    logger.info("=" * 80)
    logger.info("STARTING AUTOMATED WORKFLOW")
    logger.info("=" * 80)

    results = executor.execute_collection_workflow(
        mode=args.mode or 'all',
        app_limit=args.limit,
        api_id=args.veracode_api_key_id,
        api_key=args.veracode_api_key_secret
    )

    # Print summary
    executor.print_summary()

    # Save results
    executor.save_results('workflow_results.json')

    return results


def main():
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description='Automated Veracode Component Matcher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with defaults
  python run_automated.py

  # Load configuration from file
  python run_automated.py --config config.json

  # Override configuration
  python run_automated.py --mode vuln --limit 10 --output ./results

  # Verbose logging with file output
  python run_automated.py --verbose --log-file workflow.log

Configuration file example (config.json):
  {
    "api": {
      "max_retries": 3,
      "backoff_factor": 2.0,
      "request_timeout": 30,
      "rate_limit_interval": 0.5
    },
    "export": {
      "output_dir": "./exports",
      "formats": ["json", "csv"],
      "include_matching": true,
      "timestamp_exports": true
    },
    "log": {
      "level": "INFO",
      "verbose": false,
      "file_output": null
    }
  }
        """
    )

    # Configuration
    parser.add_argument('--config', help='Configuration file (JSON)')

    # Collection options
    parser.add_argument('--mode', choices=['vuln', 'sbom', 'all'], help='Collection mode')
    parser.add_argument('--limit', type=int, help='Limit applications')
    parser.add_argument('--output', help='Output directory')

    # Credentials
    parser.add_argument('--veracode_api_key_id', help='Veracode API Key ID')
    parser.add_argument('--veracode_api_key_secret', help='Veracode API Key Secret')

    # Logging
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--log-file', help='Log to file')

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Load configuration
    if args.config:
        logger.info(f"Loading configuration from {args.config}")
        config = Config.from_file(args.config)
    else:
        logger.info("Using default configuration")
        config = Config.from_env()

    # Run workflow
    try:
        results = run_with_config(config, args)

        # Exit with appropriate code
        if results.get('status') == 'success':
            logger.info("Workflow completed successfully")
            sys.exit(0)
        else:
            logger.error(f"Workflow failed: {results.get('error')}")
            sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("Workflow interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
