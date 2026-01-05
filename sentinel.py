import os
import re
import json
import argparse
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Pattern, Any, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    """Represents a single security vulnerability found in a file."""
    file_path: str
    line_number: int
    severity: Severity
    rule_id: str
    description: str
    snippet: str

    def to_dict(self):
        return {
            "file": self.file_path,
            "line": self.line_number,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "message": self.description,
            "code_snippet": self.snippet.strip()
        }


class BaseRule(ABC):
    """Abstract base class for a security rule."""
    def __init__(self, rule_id: str, severity: Severity, description: str):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description

    @abstractmethod
    def check(self, file_content: str, file_path: str) -> List[Finding]:
        pass

class BaseScanner(ABC):
    """Abstract base class for file type scanners."""
    def __init__(self):
        self.rules: List[BaseRule] = []

    def register_rule(self, rule: BaseRule):
        self.rules.append(rule)

    @abstractmethod
    def supports_file(self, filename: str) -> bool:
        pass

    def scan_file(self, file_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for rule in self.rules:
                findings.extend(rule.check(content, file_path))
        except Exception as e:
            logging.error(f"Error scanning {file_path}: {e}")
        return findings

#Logic

class RegexRule(BaseRule):
    """A generic rule based on Regular Expressions."""
    def __init__(self, rule_id: str, severity: Severity, description: str, pattern: str, ignore_case: bool = False):
        super().__init__(rule_id, severity, description)
        flags = re.IGNORECASE if ignore_case else 0
        self.regex = re.compile(pattern, flags)

    def check(self, file_content: str, file_path: str) -> List[Finding]:
        findings = []
        lines = file_content.splitlines()
        for i, line in enumerate(lines):
            if self.regex.search(line):
                findings.append(Finding(
                    file_path=file_path,
                    line_number=i + 1,
                    severity=self.severity,
                    rule_id=self.rule_id,
                    description=self.description,
                    snippet=line
                ))
        return findings

class TerraformOpenSecurityGroupRule(BaseRule):
    """Detects Security Groups open to the world (0.0.0.0/0)."""
    def __init__(self):
        super().__init__("TF-001", Severity.HIGH, "Security Group opens port to 0.0.0.0/0")

    def check(self, file_content: str, file_path: str) -> List[Finding]:
        findings = []
        # Look for cidr_blocks = ["0.0.0.0/0"] inside an ingress block
        #this regex handles standard formatting
        lines = file_content.splitlines()
        ingress_open = False
        
        for i, line in enumerate(lines):
            if 'ingress' in line:
                ingress_open = True
            if 'egress' in line or '}' in line:
                ingress_open = False
            
            if ingress_open and '0.0.0.0/0' in line:
                findings.append(Finding(
                    file_path=file_path,
                    line_number=i + 1,
                    severity=self.severity,
                    rule_id=self.rule_id,
                    description="Found ingress rule allowing traffic from 0.0.0.0/0",
                    snippet=line
                ))
        return findings

class DockerUserRule(BaseRule):
    """Detects if a Dockerfile runs as Root (missing USER instruction)."""
    def __init__(self):
        super().__init__("DKR-001", Severity.MEDIUM, "Container running as root (No USER instruction found)")

    def check(self, file_content: str, file_path: str) -> List[Finding]:
        # This is a file-level check, not a line-level check.
        if not re.search(r'^\s*USER\s+', file_content, re.MULTILINE):
            return [Finding(
                file_path=file_path,
                line_number=1,
                severity=self.severity,
                rule_id=self.rule_id,
                description=self.description,
                snippet="<Entire File>"
            )]
        return []

#Scanners

class TerraformScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        #Terraform specific rules
        self.register_rule(TerraformOpenSecurityGroupRule())
        self.register_rule(RegexRule("TF-002", Severity.CRITICAL, "Hardcoded AWS Access Key", r'AWS_ACCESS_KEY_ID\s*=\s*".+"'))
        self.register_rule(RegexRule("TF-003", Severity.CRITICAL, "Hardcoded Private Key", r'-----BEGIN PRIVATE KEY-----'))

    def supports_file(self, filename: str) -> bool:
        return filename.endswith('.tf')

class DockerScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        #Docker specific rules
        self.register_rule(DockerUserRule())
        self.register_rule(RegexRule("DKR-002", Severity.CRITICAL, "Exposed SSH Port 22", r'^\s*EXPOSE\s+.*22'))
        self.register_rule(RegexRule("DKR-003", Severity.HIGH, "Use of 'ADD' instead of 'COPY'", r'^\s*ADD\s+'))
        self.register_rule(RegexRule("DKR-004", Severity.CRITICAL, "Hardcoded Secrets in ENV", r'^\s*ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN).*='))

    def supports_file(self, filename: str) -> bool:
        return filename.endswith('Dockerfile') or filename == 'Dockerfile'

#Core Engine

class SentinelEngine:
    def __init__(self):
        self.scanners: List[BaseScanner] = [TerraformScanner(), DockerScanner()]
        self.findings: List[Finding] = []

    def _get_scanner(self, file_path: str) -> BaseScanner:
        for scanner in self.scanners:
            if scanner.supports_file(os.path.basename(file_path)):
                return scanner
        return None

    def scan_directory(self, root_path: str):
        files_to_scan = []
        for dirpath, _, filenames in os.walk(root_path):
            for f in filenames:
                full_path = os.path.join(dirpath, f)
                scanner = self._get_scanner(full_path)
                if scanner:
                    files_to_scan.append((scanner, full_path))

        print(f"[*] Detected {len(files_to_scan)} files to scan. Starting analysis...")

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_file = {
                executor.submit(scanner.scan_file, fpath): fpath 
                for scanner, fpath in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                fpath = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        self.findings.extend(result)
                except Exception as exc:
                    logging.error(f"Generated an exception for {fpath}: {exc}")

    def generate_report(self, output_format: str):
        if output_format == 'json':
            data = [f.to_dict() for f in self.findings]
            print(json.dumps(data, indent=4))
        else:
            self._print_console_report()

    def _print_console_report(self):
        if not self.findings:
            print("\n✅ No vulnerabilities found. Good job!")
            return

        print(f"\n{'='*60}")
        print(f"SENTINEL SCAN REPORT - {len(self.findings)} ISSUES FOUND")
        print(f"{'='*60}\n")
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 1, 
            Severity.HIGH: 2, 
            Severity.MEDIUM: 3, 
            Severity.LOW: 4
        }
        
        sorted_findings = sorted(self.findings, key=lambda x: severity_order[x.severity])

        for f in sorted_findings:
            color = ""
            if f.severity == Severity.CRITICAL: color = "\033[91m" # Red
            elif f.severity == Severity.HIGH: color = "\033[33m" # Orange
            else: color = "\033[37m" # White
            reset = "\033[0m"

            print(f"[{color}{f.severity.value}{reset}] {f.rule_id}: {f.description}")
            print(f"  File: {f.file_path}:{f.line_number}")
            print(f"  Code: {f.snippet.strip()}")
            print("-" * 40)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel: IaC Security Scanner")
    parser.add_argument("path", help="Path to the directory to scan")
    parser.add_argument("--format", choices=['console', 'json'], default='console', help="Output format")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist.")
        exit(1)

    sentinel = SentinelEngine()
    sentinel.scan_directory(args.path)
    sentinel.generate_report(args.format)
