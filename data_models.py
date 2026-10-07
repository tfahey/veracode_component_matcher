#!/usr/bin/env python3
"""
Phase 2: Data Structure Design
Data model classes for SBOM and SCA component matching

Defines dataclasses for:
- SCAVulnerabilityRecord: Vulnerability data from detailedreport.do
- SBOMComponent: Component data from SBOM v1 API (CycloneDX)

Both classes support JSON serialization and type hints for the matching workflow.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


@dataclass
class SCAVulnerabilityRecord:
    """
    Represents a vulnerability finding from Veracode detailedreport.do API.

    Maps to "SCA Vuln Data" sheet columns A-AL in the Excel file.
    Note: One vulnerability per row (denormalized format, multiple rows per component).

    Matching Keys:
    - sha1 (Column AA): Primary key, 100% confidence
    - library_id (Column AE): Secondary key, 80-85% confidence
    """

    # ========== MATCHING KEYS (Critical for SBOM linking) ==========
    sha1: Optional[str] = None
    library_id: Optional[str] = None

    # ========== VULNERABILITY INFORMATION ==========
    cve_id: Optional[str] = None
    severity: Optional[int] = None  # 1-5
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_summary: Optional[str] = None
    description: Optional[str] = None
    vulnerability_affects_policy_compliance: bool = False

    # ========== COMPONENT INFORMATION ==========
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    component_id: Optional[str] = None
    file_name: Optional[str] = None

    # ========== BUILD INFORMATION ==========
    build_id: Optional[str] = None
    build_version: Optional[str] = None
    build_published_date: Optional[str] = None

    # ========== APPLICATION INFORMATION ==========
    app_id: Optional[str] = None
    app_guid: Optional[str] = None
    app_name: Optional[str] = None
    business_criticality: Optional[str] = None

    # ========== SCAN INFORMATION ==========
    scantype: Optional[str] = None  # "SCA", "Static", "Dynamic", etc.
    static_version: Optional[str] = None
    dynamic_version: Optional[str] = None
    static_submitted_date: Optional[str] = None
    dynamic_submitted_date: Optional[str] = None

    # ========== MITIGATION INFORMATION ==========
    first_found_date: Optional[str] = None
    mitigated_date: Optional[str] = None
    mitigation: Optional[str] = None
    mitigation_type: Optional[str] = None
    mitigation_action: Optional[str] = None
    mitigation_date: Optional[str] = None

    # ========== BLOCKER FLAGS ==========
    blocklisted: bool = False
    new: bool = False
    component_affects_policy_compliance: bool = False

    # ========== METADATA ==========
    added_date: Optional[str] = None
    max_cvss_score: Optional[float] = None

    def __post_init__(self):
        """Validate and normalize fields after initialization"""
        if isinstance(self.severity, str):
            try:
                self.severity = int(self.severity)
            except (ValueError, TypeError):
                self.severity = None

        if isinstance(self.cvss_score, str):
            try:
                self.cvss_score = float(self.cvss_score)
            except (ValueError, TypeError):
                self.cvss_score = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values"""
        return {k: v for k, v in asdict(self).items() if v is not None}

    def is_valid(self) -> bool:
        """Check if record has required matching keys"""
        return bool(self.sha1 or self.library_id)

    def get_component_key(self) -> tuple:
        """Get unique component key for grouping"""
        return (self.sha1, self.library_id, self.component_name, self.component_version)


@dataclass
class SBOMComponent:
    """
    Represents a software component from Veracode SBOM v1 API (CycloneDX format).

    Maps to "SBOM Components" sheet columns A-M in the Excel file.

    Matching Keys:
    - sha1 (Column F): Primary key, extracted from hashes[].content where alg=SHA-1
    - bom_ref (Column E): Secondary key, unique SBOM reference

    Additional Information:
    - purl: Package URL for PURL-based matching
    - name + version: For composite key matching
    """

    # ========== APPLICATION IDENTIFICATION ==========
    application_id: str
    app_name: str

    # ========== COMPONENT IDENTIFICATION ==========
    component_name: str
    component_version: Optional[str] = None
    component_type: str = "library"  # "library", "application", "framework", etc.

    # ========== MATCHING KEYS (Critical for vulnerability linking) ==========
    bom_ref: Optional[str] = None  # Column E: Unique SBOM reference
    sha1: Optional[str] = None  # Column F: Primary matching key

    # ========== ADDITIONAL HASHES ==========
    sha256: Optional[str] = None
    md5: Optional[str] = None
    bytecode_hash: Optional[str] = None

    # ========== PACKAGE INFORMATION ==========
    purl: Optional[str] = None  # Package URL (pkg:type/namespace/name@version)
    vendor: Optional[str] = None

    # ========== FILE INFORMATION ==========
    file_path: Optional[str] = None

    # ========== VULNERABILITY INFORMATION ==========
    cve_ids: Optional[str] = None  # Comma-separated list
    cwe_ids: Optional[str] = None  # Comma-separated list

    # ========== DEPENDENCY INFORMATION ==========
    all_dependencies: Optional[str] = None  # Serialized or comma-separated

    # ========== MATCHING METADATA ==========
    match_type: Optional[str] = None  # How component was matched (sha1, purl, etc.)

    def __post_init__(self):
        """Validate and normalize fields after initialization"""
        if not self.component_name:
            raise ValueError("component_name is required")
        if not self.application_id:
            raise ValueError("application_id is required")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    def is_valid(self) -> bool:
        """Check if component has required fields"""
        return bool(self.component_name and self.application_id)

    def get_component_key(self) -> tuple:
        """Get unique component key for matching"""
        return (self.sha1, self.bom_ref, self.component_name, self.component_version)

    def get_purl_parts(self) -> Optional[Dict[str, str]]:
        """Parse PURL into components if available"""
        if not self.purl:
            return None

        # Simple PURL parsing: pkg:type/namespace/name@version
        import re
        match = re.match(r'pkg:(\w+)(?:/([^/]+))?/([^@]+)(?:@([^?#]+))?', self.purl)

        if match:
            return {
                'type': match.group(1),
                'namespace': match.group(2),
                'name': match.group(3),
                'version': match.group(4)
            }
        return None


@dataclass
class VulnerabilityGroup:
    """
    Represents a group of vulnerabilities for a single component.

    Used during aggregation to group multiple CVEs by component.
    One component may have multiple vulnerabilities.
    """

    component: SCAVulnerabilityRecord
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def add_vulnerability(self, vuln: Dict[str, Any]) -> None:
        """Add a vulnerability to this group"""
        self.vulnerabilities.append(vuln)

    def get_cve_count(self) -> int:
        """Get count of vulnerabilities for this component"""
        return len(self.vulnerabilities)

    def get_cve_ids(self) -> str:
        """Get comma-separated list of CVE IDs"""
        cves = [v.get('cve_id', 'N/A') for v in self.vulnerabilities]
        return ', '.join(cves)

    def get_max_severity(self) -> Optional[int]:
        """Get maximum severity among vulnerabilities"""
        if not self.vulnerabilities:
            return None

        severities = [
            v.get('severity', 0)
            for v in self.vulnerabilities
            if isinstance(v.get('severity'), int)
        ]
        return max(severities) if severities else None


class DataAggregator:
    """
    Helper class for aggregating and processing component data.
    """

    @staticmethod
    def group_vulnerabilities_by_component(
        findings: List[Dict[str, Any]]
    ) -> Dict[tuple, VulnerabilityGroup]:
        """
        Group vulnerability findings by component key.

        Args:
            findings: List of vulnerability finding dictionaries from detailedreport.do

        Returns:
            Dict mapping component key to VulnerabilityGroup

        Example:
            findings = [
                {'sha1': 'abc123', 'library_id': 'lib-001', 'cve_id': 'CVE-2021-1234', ...},
                {'sha1': 'abc123', 'library_id': 'lib-001', 'cve_id': 'CVE-2021-5678', ...},
            ]

            groups = DataAggregator.group_vulnerabilities_by_component(findings)
            # Result: {('abc123', 'lib-001', 'component', 'version'): VulnerabilityGroup(...)}
        """
        grouped = {}

        for finding in findings:
            # Create base component record
            component = SCAVulnerabilityRecord(
                sha1=finding.get('sha1'),
                library_id=finding.get('library_id'),
                cve_id=finding.get('cve_id'),
                severity=finding.get('severity'),
                cwe_id=finding.get('cwe_id'),
                cvss_score=finding.get('cvss_score'),
                component_name=finding.get('component_name'),
                component_version=finding.get('component_version'),
                component_id=finding.get('component_id'),
                file_name=finding.get('file_name'),
                build_id=finding.get('build_id'),
                build_version=finding.get('build_version'),
                app_id=finding.get('app_id'),
                app_guid=finding.get('app_guid'),
                app_name=finding.get('app_name'),
                scantype=finding.get('scantype'),
            )

            # Use component key for grouping
            key = component.get_component_key()

            if key not in grouped:
                grouped[key] = VulnerabilityGroup(component=component)

            # Add vulnerability details
            vuln_info = {
                'cve_id': finding.get('cve_id'),
                'severity': finding.get('severity'),
                'cwe_id': finding.get('cwe_id'),
                'cvss_score': finding.get('cvss_score'),
                'description': finding.get('description'),
                'first_found_date': finding.get('first_found_date'),
            }
            grouped[key].add_vulnerability(vuln_info)

        return grouped

    @staticmethod
    def flatten_vulnerability_groups(
        groups: Dict[tuple, VulnerabilityGroup]
    ) -> List[SCAVulnerabilityRecord]:
        """
        Convert vulnerability groups back to individual records.

        Returns denormalized format with one row per vulnerability.
        """
        records = []

        for group in groups.values():
            for vuln in group.vulnerabilities:
                record = SCAVulnerabilityRecord(
                    sha1=group.component.sha1,
                    library_id=group.component.library_id,
                    cve_id=vuln.get('cve_id'),
                    severity=vuln.get('severity'),
                    cwe_id=vuln.get('cwe_id'),
                    cvss_score=vuln.get('cvss_score'),
                    description=vuln.get('description'),
                    component_name=group.component.component_name,
                    component_version=group.component.component_version,
                    component_id=group.component.component_id,
                    file_name=group.component.file_name,
                    build_id=group.component.build_id,
                    build_version=group.component.build_version,
                    app_id=group.component.app_id,
                    app_guid=group.component.app_guid,
                    app_name=group.component.app_name,
                    scantype=group.component.scantype,
                    first_found_date=vuln.get('first_found_date'),
                )
                records.append(record)

        return records

    @staticmethod
    def deduplicate_sbom_components(
        components: List[SBOMComponent]
    ) -> List[SBOMComponent]:
        """
        Remove duplicate SBOM components, keeping first occurrence.

        Duplicates identified by component_key: (sha1, bom_ref, name, version)
        """
        seen = {}
        unique = []

        for component in components:
            key = component.get_component_key()

            if key not in seen:
                seen[key] = True
                unique.append(component)

        return unique

    @staticmethod
    def validate_records(
        records: List[SCAVulnerabilityRecord],
        min_match_keys: bool = True
    ) -> tuple[List[SCAVulnerabilityRecord], List[str]]:
        """
        Validate vulnerability records.

        Args:
            records: List of vulnerability records
            min_match_keys: If True, require at least one matching key

        Returns:
            Tuple of (valid_records, error_messages)
        """
        valid = []
        errors = []

        for idx, record in enumerate(records):
            if min_match_keys and not record.is_valid():
                errors.append(f"Record {idx}: Missing both sha1 and library_id")
                continue

            if not record.component_name:
                errors.append(f"Record {idx}: Missing component_name")
                continue

            if not record.app_id:
                errors.append(f"Record {idx}: Missing app_id")
                continue

            valid.append(record)

        return valid, errors


def create_sample_vulnerability_record() -> SCAVulnerabilityRecord:
    """Create a sample vulnerability record for testing"""
    return SCAVulnerabilityRecord(
        sha1="abc123def456",
        library_id="lib-001",
        cve_id="CVE-2021-44228",
        severity=5,
        cwe_id="CWE-94",
        cvss_score=9.8,
        component_name="log4j-core",
        component_version="2.14.1",
        build_id="build-001",
        app_id="app-001",
        app_name="TestApp",
        scantype="SCA",
        first_found_date="2024-01-10",
        description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    )


def create_sample_sbom_component() -> SBOMComponent:
    """Create a sample SBOM component for testing"""
    return SBOMComponent(
        application_id="550e8400-e29b-41d4-a716-446655440000",
        app_name="TestApp",
        component_name="lodash",
        component_version="4.17.21",
        bom_ref="pkg:npm/lodash@4.17.21",
        sha1="88d36f5051fb029ad5ef1119a73953f7add33fd9",
        purl="pkg:npm/lodash@4.17.21",
        cve_ids="CVE-2021-23337",
    )


if __name__ == '__main__':
    # Test data models
    print("Testing SCAVulnerabilityRecord...")
    vuln = create_sample_vulnerability_record()
    print(f"✓ Created: {vuln.component_name}@{vuln.component_version}")
    print(f"  CVE: {vuln.cve_id} (Severity: {vuln.severity})")
    print(f"  Matching keys - SHA1: {bool(vuln.sha1)}, Library ID: {bool(vuln.library_id)}")

    print("\nTesting SBOMComponent...")
    component = create_sample_sbom_component()
    print(f"✓ Created: {component.component_name}@{component.component_version}")
    print(f"  BOM-Ref: {component.bom_ref}")
    print(f"  Matching keys - SHA1: {bool(component.sha1)}, BOM-Ref: {bool(component.bom_ref)}")

    print("\nTesting DataAggregator...")
    findings = [
        {
            'sha1': 'abc123',
            'library_id': 'lib-001',
            'cve_id': 'CVE-2021-1234',
            'severity': 5,
            'component_name': 'log4j',
            'component_version': '2.14.1',
            'app_id': 'app-001',
            'app_name': 'TestApp',
        },
        {
            'sha1': 'abc123',
            'library_id': 'lib-001',
            'cve_id': 'CVE-2021-5678',
            'severity': 4,
            'component_name': 'log4j',
            'component_version': '2.14.1',
            'app_id': 'app-001',
            'app_name': 'TestApp',
        },
    ]

    groups = DataAggregator.group_vulnerabilities_by_component(findings)
    print(f"✓ Grouped {len(findings)} findings into {len(groups)} component(s)")

    for key, group in groups.items():
        print(f"  Component: {group.component.component_name}@{group.component.component_version}")
        print(f"  Vulnerabilities: {group.get_cve_count()}")
        print(f"  CVEs: {group.get_cve_ids()}")
        print(f"  Max Severity: {group.get_max_severity()}")

    print("\n✅ All tests passed!")
