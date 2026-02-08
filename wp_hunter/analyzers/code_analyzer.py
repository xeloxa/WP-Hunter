"""
WP-Hunter Code Analyzer

Static code analysis for PHP plugins and themes.
"""

import re
from pathlib import Path
from typing import List

from wp_hunter.config import DANGEROUS_FUNCTIONS, AJAX_PATTERNS, THEME_PATTERNS
from wp_hunter.models import CodeAnalysisResult


class CodeAnalyzer:
    """Advanced code analysis for plugins and themes."""
    
    @staticmethod
    def analyze_php_file(file_path: Path) -> CodeAnalysisResult:
        """Analyze a single PHP file for security issues."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return CodeAnalysisResult()
        
        # Find dangerous functions
        dangerous_found = []
        for func in DANGEROUS_FUNCTIONS:
            pattern = rf'\b{func}\s*\('
            if re.search(pattern, content, re.IGNORECASE):
                dangerous_found.append(func)
        
        # Find AJAX endpoints
        ajax_found = []
        for pattern in AJAX_PATTERNS:
            if pattern in content:
                ajax_found.append(pattern)
        
        # Find theme functions
        theme_found = []
        for pattern in THEME_PATTERNS:
            if pattern in content:
                theme_found.append(pattern)
        
        # Find file operations
        file_ops = []
        file_patterns = ['fopen', 'file_get_contents', 'file_put_contents', 'readfile', 'unlink']
        for pattern in file_patterns:
            if re.search(rf'\b{pattern}\s*\(', content, re.IGNORECASE):
                file_ops.append(pattern)
        
        # Find SQL queries
        sql_found = []
        sql_patterns = ['$wpdb->', 'prepare(', 'get_results', 'get_var', 'query(']
        for pattern in sql_patterns:
            if pattern in content:
                sql_found.append(pattern)
        
        # Find nonce usage
        nonce_found = []
        nonce_patterns = ['wp_nonce_field', 'wp_verify_nonce', 'wp_create_nonce', 'check_admin_referer']
        for pattern in nonce_patterns:
            if pattern in content:
                nonce_found.append(pattern)
        
        # Find sanitization issues (missing sanitization)
        sanitization_issues = []
        if '$_GET' in content and 'sanitize_' not in content:
            sanitization_issues.append('$_GET without sanitization')
        if '$_POST' in content and 'sanitize_' not in content:
            sanitization_issues.append('$_POST without sanitization')
        if '$_REQUEST' in content:
            sanitization_issues.append('$_REQUEST usage (deprecated)')
        
        return CodeAnalysisResult(
            dangerous_functions=dangerous_found,
            ajax_endpoints=ajax_found,
            theme_functions=theme_found,
            file_operations=file_ops,
            sql_queries=sql_found,
            nonce_usage=nonce_found,
            sanitization_issues=sanitization_issues
        )
    
    @staticmethod
    def analyze_plugin_code(plugin_path: Path) -> CodeAnalysisResult:
        """Analyze entire plugin directory."""
        combined_result = CodeAnalysisResult()
        
        # Analyze all PHP files
        for php_file in plugin_path.rglob("*.php"):
            if php_file.is_file():
                result = CodeAnalyzer.analyze_php_file(php_file)
                
                # Combine results
                combined_result.dangerous_functions.extend(result.dangerous_functions)
                combined_result.ajax_endpoints.extend(result.ajax_endpoints)
                combined_result.theme_functions.extend(result.theme_functions)
                combined_result.file_operations.extend(result.file_operations)
                combined_result.sql_queries.extend(result.sql_queries)
                combined_result.nonce_usage.extend(result.nonce_usage)
                combined_result.sanitization_issues.extend(result.sanitization_issues)
        
        # Remove duplicates
        combined_result.dangerous_functions = list(set(combined_result.dangerous_functions))
        combined_result.ajax_endpoints = list(set(combined_result.ajax_endpoints))
        combined_result.theme_functions = list(set(combined_result.theme_functions))
        combined_result.file_operations = list(set(combined_result.file_operations))
        combined_result.sql_queries = list(set(combined_result.sql_queries))
        combined_result.nonce_usage = list(set(combined_result.nonce_usage))
        combined_result.sanitization_issues = list(set(combined_result.sanitization_issues))
        
        return combined_result
