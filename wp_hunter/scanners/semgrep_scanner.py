# Semgrep security scanner for WordPress plugins

import os
import json
import subprocess
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from wp_hunter.config import Colors


print_lock = threading.Lock()

DEFAULT_SEMGREP_RULES = """
rules:
  - id: php-sql-injection
    patterns:
      - pattern-either:
          - pattern: $WPDB->query($X . $Y)
          - pattern: $WPDB->prepare($X . $Y, ...)
          - pattern: mysqli_query($CONN, $X . $Y)
          - pattern: mysql_query($X . $Y)
    message: Potential SQL injection - string concatenation in query
    languages: [php]
    severity: ERROR

  - id: php-command-injection
    patterns:
      - pattern-either:
          - pattern: exec($X . $Y)
          - pattern: shell_exec($X . $Y)
          - pattern: system($X . $Y)
          - pattern: passthru($X . $Y)
          - pattern: popen($X . $Y, ...)
          - pattern: proc_open($X . $Y, ...)
    message: Potential command injection
    languages: [php]
    severity: ERROR

  - id: php-code-injection
    patterns:
      - pattern-either:
          - pattern: eval($X)
          - pattern: create_function($X, $Y)
          - pattern: assert($X)
          - pattern: preg_replace("/.*/e", $X, ...)
    message: Potential code injection via eval/assert
    languages: [php]
    severity: ERROR

  - id: php-file-inclusion
    patterns:
      - pattern-either:
          - pattern: include($X)
          - pattern: include_once($X)
          - pattern: require($X)
          - pattern: require_once($X)
    message: Dynamic file inclusion
    languages: [php]
    severity: WARNING

  - id: php-ssrf
    patterns:
      - pattern-either:
          - pattern: file_get_contents($URL)
          - pattern: curl_exec($CH)
          - pattern: wp_remote_get($URL)
          - pattern: wp_remote_post($URL, ...)
    message: Potential SSRF - external request
    languages: [php]
    severity: WARNING

  - id: wp-ajax-missing-nonce
    patterns:
      - pattern: |
          add_action('wp_ajax_$ACTION', $CALLBACK);
          ...
          function $CALLBACK(...) {
            ...
          }
      - pattern-not: |
          function $CALLBACK(...) {
            ...
            wp_verify_nonce(...)
            ...
          }
      - pattern-not: |
          function $CALLBACK(...) {
            ...
            check_ajax_referer(...)
            ...
          }
    message: AJAX handler may be missing nonce verification
    languages: [php]
    severity: WARNING

  - id: wp-unescaped-output
    patterns:
      - pattern-either:
          - pattern: echo $_GET[$X]
          - pattern: echo $_POST[$X]
          - pattern: echo $_REQUEST[$X]
          - pattern: print $_GET[$X]
          - pattern: print $_POST[$X]
    message: Unescaped user input in output (XSS)
    languages: [php]
    severity: ERROR

  - id: php-deserialization
    patterns:
      - pattern: unserialize($X)
    message: Unsafe deserialization
    languages: [php]
    severity: ERROR

  - id: wp-direct-db-query
    patterns:
      - pattern-either:
          - pattern: $WPDB->query("$X")
          - pattern: $WPDB->get_results("$X")
          - pattern: $WPDB->get_row("$X")
    message: Direct database query - consider using prepared statements
    languages: [php]
    severity: INFO
"""


@dataclass
class SemgrepResult:
    slug: str
    findings: List[Dict[str, Any]]
    errors: List[str]
    success: bool


class SemgrepScanner:
    
    def __init__(
        self,
        rules_path: Optional[str] = None,
        output_dir: str = "./semgrep_results",
        workers: int = 3
    ):
        self.rules_path = rules_path
        self.output_dir = Path(output_dir)
        self.workers = workers
        self.stop_event = threading.Event()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if not rules_path:
            self._create_default_rules()
    
    def _create_default_rules(self):
        rules_file = self.output_dir / "wp_security_rules.yaml"
        if not rules_file.exists():
            rules_file.write_text(DEFAULT_SEMGREP_RULES)
        self.rules_path = str(rules_file)
    
    def _check_semgrep_available(self) -> bool:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def scan_plugin(self, plugin_path: str, slug: str) -> SemgrepResult:
        if self.stop_event.is_set():
            return SemgrepResult(slug=slug, findings=[], errors=["Stopped"], success=False)
        
        output_file = self.output_dir / f"{slug}_results.json"
        
        try:
            cmd = [
                "semgrep",
                "--config", self.rules_path,
                "--json",
                "--output", str(output_file),
                "--no-git-ignore",
                plugin_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per plugin
            )

            findings = []
            errors = []
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    findings = data.get('results', [])
                    errors = [e.get('message', '') for e in data.get('errors', [])]
            
            return SemgrepResult(
                slug=slug,
                findings=findings,
                errors=errors,
                success=True
            )
            
        except subprocess.TimeoutExpired:
            return SemgrepResult(
                slug=slug,
                findings=[],
                errors=["Scan timeout"],
                success=False
            )
        except Exception as e:
            return SemgrepResult(
                slug=slug,
                findings=[],
                errors=[str(e)],
                success=False
            )
    
    def scan_plugins(self, plugin_dirs: List[str], verbose: bool = True) -> Dict[str, SemgrepResult]:
        if not self._check_semgrep_available():
            if verbose:
                print(f"{Colors.RED}[!] Semgrep is not installed.{Colors.RESET}")
                print(f"    Install with: pip install semgrep")
                print(f"    Or: brew install semgrep")
            return {}
        
        if verbose:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}🔍 Running Semgrep Security Scan{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"  📁 Plugins: {len(plugin_dirs)}")
            print(f"  📋 Rules: {self.rules_path}")
            print(f"  📄 Output: {self.output_dir}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        results: Dict[str, SemgrepResult] = {}
        total_findings = 0
        
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_plugin = {}
            
            for plugin_path in plugin_dirs:
                path = Path(plugin_path)
                if path.exists() and path.is_dir():
                    slug = path.name
                    future = executor.submit(self.scan_plugin, str(path), slug)
                    future_to_plugin[future] = slug
            
            completed = 0
            for future in as_completed(future_to_plugin):
                if self.stop_event.is_set():
                    break
                
                slug = future_to_plugin[future]
                completed += 1
                
                try:
                    result = future.result()
                    results[slug] = result
                    
                    finding_count = len(result.findings)
                    total_findings += finding_count
                    
                    if verbose:
                        if finding_count > 0:
                            color = Colors.RED if finding_count >= 5 else Colors.YELLOW
                            print(f"  [{completed}/{len(plugin_dirs)}] {color}⚠{Colors.RESET} {slug}: {finding_count} findings")
                        else:
                            print(f"  [{completed}/{len(plugin_dirs)}] {Colors.GREEN}✓{Colors.RESET} {slug}: clean")
                            
                except Exception as e:
                    if verbose:
                        print(f"  [{completed}/{len(plugin_dirs)}] {Colors.RED}✗{Colors.RESET} {slug}: {e}")
        
        if verbose and results:
            self._print_summary(results, total_findings)
        self._save_combined_report(results)
        
        return results
    
    def _print_summary(self, results: Dict[str, SemgrepResult], total_findings: int):
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 Scan Summary{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"  🔌 Plugins scanned: {len(results)}")
        print(f"  ⚠️  Total findings: {total_findings}")
        severities = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        for result in results.values():
            for finding in result.findings:
                sev = finding.get('extra', {}).get('severity', 'INFO')
                severities[sev] = severities.get(sev, 0) + 1
        
        if total_findings > 0:
            print(f"\n  By Severity:")
            if severities.get('ERROR', 0) > 0:
                print(f"    {Colors.RED}ERROR{Colors.RESET}: {severities['ERROR']}")
            if severities.get('WARNING', 0) > 0:
                print(f"    {Colors.YELLOW}WARNING{Colors.RESET}: {severities['WARNING']}")
            if severities.get('INFO', 0) > 0:
                print(f"    {Colors.GRAY}INFO{Colors.RESET}: {severities['INFO']}")
        sorted_results = sorted(
            results.items(),
            key=lambda x: len(x[1].findings),
            reverse=True
        )[:5]
        
        if sorted_results and len(sorted_results[0][1].findings) > 0:
            print(f"\n  Top Vulnerable Plugins:")
            for slug, result in sorted_results:
                if len(result.findings) > 0:
                    print(f"    • {slug}: {len(result.findings)} findings")
        
        print(f"\n  📁 Results saved to: {self.output_dir}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    def _save_combined_report(self, results: Dict[str, SemgrepResult]):
        report = {
            "total_plugins": len(results),
            "total_findings": sum(len(r.findings) for r in results.values()),
            "plugins": {}
        }
        
        for slug, result in results.items():
            report["plugins"][slug] = {
                "findings": result.findings,
                "errors": result.errors,
                "success": result.success
            }
        
        report_path = self.output_dir / "combined_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def stop(self):
        self.stop_event.set()
