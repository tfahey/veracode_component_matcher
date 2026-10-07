#!/usr/bin/env python3
"""
Workflow orchestration for Veracode Component Matcher

Handles automated data collection, export, and analysis workflows.
"""

import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from api_fetcher import VeracodeApiFetcher
from vulnerability_matcher import VulnerabilityMatcher
from config import Config

logger = logging.getLogger(__name__)


class WorkflowExecutor:
    """Orchestrates complete data collection and analysis workflows"""

    def __init__(self, config: Config):
        self.config = config
        self.fetcher = None
        self.matcher = None
        self.start_time = None
        self.end_time = None
        self.results = {}

    def execute_collection_workflow(
        self,
        mode: str = 'all',
        app_limit: Optional[int] = None,
        api_id: Optional[str] = None,
        api_key: Optional[str] = None
    ) -> Dict:
        """Execute complete collection workflow"""

        self.start_time = datetime.now()
        logger.info(f"Starting collection workflow: {self.start_time}")

        try:
            # Initialize fetcher with configuration
            self.fetcher = VeracodeApiFetcher(api_id=api_id, api_key=api_key)
            self.fetcher.max_retries = self.config.api.max_retries
            self.fetcher.backoff_factor = self.config.api.backoff_factor
            self.fetcher.request_timeout = self.config.api.request_timeout
            self.fetcher.rate_limit_interval = self.config.api.rate_limit_interval

            # Create output directory
            Path(self.config.export.output_dir).mkdir(parents=True, exist_ok=True)

            all_sca_components = []
            all_sbom_components = []

            # Fetch applications
            logger.info("Fetching applications...")
            apps = self.fetcher.get_all_applications()

            if app_limit:
                apps = apps[:app_limit]
                logger.info(f"Limited to {len(apps)} applications")

            # Process applications
            logger.info(f"Processing {len(apps)} applications...")
            for idx, app in enumerate(apps):
                try:
                    app_id = app.get('id') or app.get('legacy_id')
                    app_name = app.get('name') or app.get('profile', {}).get('name', 'Unknown')
                    app_guid = app.get('guid')

                    if not app_guid:
                        logger.debug(f"Skipping {app_name}: no GUID")
                        continue

                    logger.debug(f"Processing [{idx+1}/{len(apps)}] {app_name}")

                    # Collect SCA data if requested
                    if mode in ('vuln', 'all'):
                        try:
                            build_info = self.fetcher.get_build_info(app_guid)
                            if build_info:
                                sca_data = self.fetcher.extract_sca_vulnerabilities(build_info)
                                all_sca_components.extend(sca_data)
                        except Exception as e:
                            logger.warning(f"Failed to get SCA data for {app_name}: {e}")

                    # Collect SBOM data if requested
                    if mode in ('sbom', 'all'):
                        try:
                            sbom_data_raw = self.fetcher.get_sbom(app_guid)
                            if sbom_data_raw:
                                sbom_data = self.fetcher.extract_sbom_components(sbom_data_raw)
                                all_sbom_components.extend(sbom_data)
                        except Exception as e:
                            logger.warning(f"Failed to get SBOM data for {app_name}: {e}")

                except Exception as e:
                    logger.error(f"Error processing application {idx}: {e}")
                    continue

            # Export data
            logger.info("Exporting data...")
            self._export_data(all_sca_components, all_sbom_components)

            # Run matching if both datasets available
            if mode == 'all' and all_sca_components and all_sbom_components and self.config.export.include_matching:
                logger.info("Running vulnerability matching...")
                self._run_matching(all_sca_components, all_sbom_components)

            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()

            # Compile results
            self.results = {
                'status': 'success',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration_seconds': duration,
                'applications_processed': len(apps),
                'sca_components': len(all_sca_components),
                'sbom_components': len(all_sbom_components),
                'mode': mode,
                'output_dir': self.config.export.output_dir,
                'failure_summary': self.fetcher.get_failure_summary() if self.fetcher else {},
            }

            logger.info(f"Workflow completed in {duration:.2f}s")
            logger.info(f"  SCA components: {len(all_sca_components)}")
            logger.info(f"  SBOM components: {len(all_sbom_components)}")

            return self.results

        except Exception as e:
            logger.error(f"Workflow failed: {e}")
            self.end_time = datetime.now()
            self.results = {
                'status': 'failed',
                'error': str(e),
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
            }
            return self.results

    def _export_data(self, sca_data: List[Dict], sbom_data: List[Dict]):
        """Export collected data in configured formats"""

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S') if self.config.export.timestamp_exports else ''
        suffix = f'_{timestamp}' if timestamp else ''

        # Export SCA data
        if sca_data:
            if 'json' in self.config.export.formats:
                json_path = f"{self.config.export.output_dir}/sca_components{suffix}.json"
                with open(json_path, 'w') as f:
                    json.dump(sca_data, f, indent=2)
                logger.info(f"Exported SCA JSON: {json_path}")

            if 'csv' in self.config.export.formats:
                csv_path = f"{self.config.export.output_dir}/vulnerabilities{suffix}.csv"
                self.fetcher.export_vulnerability_csv(sca_data, csv_path)
                logger.info(f"Exported vulnerability CSV: {csv_path}")

        # Export SBOM data
        if sbom_data:
            if 'json' in self.config.export.formats:
                json_path = f"{self.config.export.output_dir}/sbom_components{suffix}.json"
                with open(json_path, 'w') as f:
                    json.dump(sbom_data, f, indent=2)
                logger.info(f"Exported SBOM JSON: {json_path}")

            if 'csv' in self.config.export.formats:
                csv_path = f"{self.config.export.output_dir}/sbom_components{suffix}.csv"
                self.fetcher.export_sbom_csv(sbom_data, csv_path)
                logger.info(f"Exported SBOM CSV: {csv_path}")

    def _run_matching(self, sca_data: List[Dict], sbom_data: List[Dict]):
        """Run vulnerability matching workflow"""

        try:
            self.matcher = VulnerabilityMatcher()
            self.matcher.load_sbom_data(sbom_data)
            self.matcher.load_sca_data(sca_data)
            self.matcher.match_all()

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S') if self.config.export.timestamp_exports else ''
            suffix = f'_{timestamp}' if timestamp else ''

            matched_path = f"{self.config.export.output_dir}/matched_components{suffix}.csv"
            unmatched_path = f"{self.config.export.output_dir}/unmatched_components{suffix}.csv"

            self.matcher.export_matched_csv(matched_path)
            self.matcher.export_unmatched_csv(unmatched_path)

            logger.info(f"Matching results exported to {self.config.export.output_dir}")

        except Exception as e:
            logger.error(f"Matching workflow failed: {e}")

    def save_results(self, results_file: str = 'workflow_results.json'):
        """Save workflow results to file"""

        results_path = f"{self.config.export.output_dir}/{results_file}"
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        logger.info(f"Workflow results saved to {results_path}")

    def print_summary(self):
        """Print workflow summary"""

        print("\n" + "=" * 80)
        print("WORKFLOW EXECUTION SUMMARY")
        print("=" * 80)

        if self.results.get('status') == 'success':
            print(f"Status: ✅ SUCCESS")
            print(f"Duration: {self.results.get('duration_seconds', 0):.2f}s")
            print(f"Applications processed: {self.results.get('applications_processed', 0)}")
            print(f"SCA components collected: {self.results.get('sca_components', 0)}")
            print(f"SBOM components collected: {self.results.get('sbom_components', 0)}")
            print(f"Output directory: {self.results.get('output_dir')}")

            if failure := self.results.get('failure_summary'):
                if failure.get('failed_apps', 0) > 0:
                    print(f"Failed apps: {failure['failed_apps']}")
                    print(f"Total retries: {failure['total_retries']}")
        else:
            print(f"Status: ❌ FAILED")
            print(f"Error: {self.results.get('error', 'Unknown error')}")

        print("=" * 80 + "\n")
