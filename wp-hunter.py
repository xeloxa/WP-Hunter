import requests
import argparse
import sys
import os
from datetime import datetime
import time
import json
import csv
import zipfile
import shutil
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import List, Dict, Any, Tuple, Optional, Set
from dataclasses import dataclass
import tempfile

# --- CONSTANTS ---
CURRENT_WP_VERSION = 6.7
MAX_WORKERS = 5

RISKY_TAGS: Set[str] = {
    # E-commerce & Payment
    'ecommerce', 'woocommerce', 'payment', 'gateway', 'stripe', 'paypal', 'checkout', 'cart', 'shop',
    
    # Forms & Input
    'form', 'contact', 'input', 'survey', 'quiz', 'poll', 'booking', 'reservation',
    
    # File Operations
    'upload', 'file', 'image', 'gallery', 'media', 'download', 'import', 'export', 'backup',
    
    # User Management
    'login', 'register', 'membership', 'user', 'profile', 'admin', 'role', 'authentication',
    
    # Communication
    'chat', 'ticket', 'support', 'comment', 'review', 'rating', 'forum', 'message',
    
    # API & Database
    'api', 'rest', 'endpoint', 'ajax', 'query', 'database', 'sql', 'db', 'webhook',
    
    # Events & Booking
    'calendar', 'event', 'booking', 'appointment', 'schedule',
    
    # Security & Auth
    'oauth', 'token', 'sso', 'ldap', '2fa', 'captcha',
    
    # Custom Post Types
    'custom-post-type', 'cpt', 'meta', 'field', 'acf'
}

USER_FACING_TAGS: Set[str] = {
    'chat', 'contact', 'form', 'gallery', 'slider', 'calendar', 'booking',
    'appointment', 'event', 'social', 'share', 'comment', 'review', 'forum',
    'membership', 'profile', 'login', 'register', 'ecommerce', 'shop', 'cart',
    'product', 'checkout', 'newsletter', 'popup', 'banner', 'map', 'faq',
    'survey', 'poll', 'quiz', 'ticket', 'support', 'download', 'frontend',
    'video', 'audio', 'player', 'gamification', 'badge', 'points'
}

SECURITY_KEYWORDS: Set[str] = {
    'xss', 'sql', 'injection', 'security', 'vulnerability', 'exploit', 'csrf', 'rce', 'ssrf',
    'lfi', 'rfi', 'idor', 'xxe', 'deserialization', 'bypass', 'privilege escalation',
    'fix', 'patched', 'sanitize', 'escape', 'harden', 'cve-', 'authentication bypass',
    'authorization', 'nonce', 'validation', 'security update', 'security fix'
}

FEATURE_KEYWORDS: Set[str] = {
    'added', 'new', 'feature', 'support for', 'introduced', 'now allows', 'implementation',
    'custom endpoint', 'custom ajax', 'custom api', 'file upload', 'import tool', 'export',
    'rest api', 'guest access', 'public access', 'allows users', 'direct access',
    'shortcode', 'widget', 'custom post type'
}

# New: Dangerous PHP functions to look for in code
DANGEROUS_FUNCTIONS: Set[str] = {
    'eval', 'exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open',
    'pcntl_exec', 'assert', 'create_function', 'unserialize', 'file_get_contents',
    'file_put_contents', 'fopen', 'readfile', 'include', 'require',
    'include_once', 'require_once', 'call_user_func', 'call_user_func_array'
}

# AJAX patterns to detect
AJAX_PATTERNS: Set[str] = {
    'wp_ajax_', 'admin-ajax.php', 'wp_ajax_nopriv_', 'ajaxurl', 'ajax_action',
    'wp_localize_script', 'wp_enqueue_script', 'jQuery.post', '$.post', '$.ajax',
    'XMLHttpRequest', 'fetch(', 'wp.ajax'
}

# Theme-specific patterns
THEME_PATTERNS: Set[str] = {
    'wp_head', 'wp_footer', 'get_header', 'get_footer', 'get_sidebar',
    'wp_enqueue_style', 'wp_enqueue_script', 'add_theme_support',
    'register_nav_menus', 'wp_nav_menu', 'dynamic_sidebar'
}

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    ORANGE = '\033[38;5;208m'
    GRAY = '\033[90m'

# ================= NEW CLASSES =================

@dataclass
class CodeAnalysisResult:
    """Code analysis result for plugins/themes"""
    dangerous_functions: List[str]
    ajax_endpoints: List[str]
    theme_functions: List[str]
    file_operations: List[str]
    sql_queries: List[str]
    nonce_usage: List[str]
    sanitization_issues: List[str]
    
class ThemeScanner:
    """WordPress Theme Scanner"""
    
    @staticmethod
    def fetch_themes(page: int = 1, max_retries: int = 3) -> List[Dict[str, Any]]:
        """Fetch themes from WordPress.org API"""
        url = 'https://api.wordpress.org/themes/info/1.2/'
        params = {
            'action': 'query_themes',
            'request[browse]': 'popular',
            'request[page]': page,
            'request[per_page]': 100,
            'request[fields][description]': True,
            'request[fields][downloaded]': True,
            'request[fields][last_updated]': True,
            'request[fields][download_link]': True,
            'request[fields][version]': True,
            'request[fields][author]': True,
            'request[fields][tags]': True,
            'request[fields][screenshot_url]': True
        }
        
        for attempt in range(max_retries):
            try:
                response = session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    return data.get('themes', []) if data else []
                elif response.status_code == 429:
                    wait_time = 5 * (attempt + 1)
                    print(f"{Colors.YELLOW}[!] Rate limited, waiting {wait_time}s...{Colors.RESET}")
                    time.sleep(wait_time)
                    continue
            except Exception as e:
                print(f"{Colors.RED}[!] Theme API Error: {e}{Colors.RESET}")
                time.sleep(2)
                continue
        return []

class CodeAnalyzer:
    """Advanced code analysis for plugins and themes"""
    
    @staticmethod
    def analyze_php_file(file_path: Path) -> CodeAnalysisResult:
        """Analyze a single PHP file for security issues"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return CodeAnalysisResult([], [], [], [], [], [], [])
        
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
        """Analyze entire plugin directory"""
        combined_result = CodeAnalysisResult([], [], [], [], [], [], [])
        
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

class PluginDownloader:
    """Plugin downloader and extractor"""
    
    @staticmethod
    def download_and_extract(download_url: str, slug: str, base_dir: str = ".") -> Optional[Path]:
        """Download and extract plugin"""
        plugins_dir = Path(base_dir) / "Downloaded_Plugins"
        plugins_dir.mkdir(exist_ok=True)
        
        plugin_dir = plugins_dir / slug
        zip_path = plugin_dir / f"{slug}.zip"
        extract_path = plugin_dir / "source"
        
        try:
            plugin_dir.mkdir(exist_ok=True)
            
            # Download
            print(f"{Colors.CYAN}[⬇] Downloading {slug}...{Colors.RESET}")
            response = session.get(download_url, stream=True, timeout=60)
            response.raise_for_status()
            
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract
            print(f"{Colors.CYAN}[📦] Extracting {slug}...{Colors.RESET}")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            
            # Clean up zip
            zip_path.unlink()
            
            # Normalize directory structure
            children = list(extract_path.iterdir())
            if len(children) == 1 and children[0].is_dir():
                # Move contents up one level
                temp_dir = extract_path.parent / "temp"
                children[0].rename(temp_dir)
                shutil.rmtree(extract_path)
                temp_dir.rename(extract_path)
            
            return extract_path
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to download {slug}: {e}{Colors.RESET}")
            if plugin_dir.exists():
                shutil.rmtree(plugin_dir, ignore_errors=True)
            return None

# Thread-safe lock for console output
print_lock = threading.Lock()
# Global session for connection pooling
session = requests.Session()


# --- HELPER FUNCTIONS ---

def calculate_days_ago(date_str: Optional[str]) -> int:
    """Calculates number of days since the given date string."""
    if not date_str: 
        return 9999
    try:
        date_obj = datetime.strptime(date_str.split(' ')[0], '%Y-%m-%d')
        delta = datetime.now() - date_obj
        return delta.days
    except ValueError:
        return 9999

def analyze_changelog(sections: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """Analyzes changelog for security and feature keywords."""
    if not sections or 'changelog' not in sections:
        return [], []
    
    changelog_text = sections['changelog'].lower()
    recent_log = changelog_text[:2000] 
    recent_words = set(recent_log.split())
    
    found_security = list(SECURITY_KEYWORDS.intersection(recent_words))
    found_features = list(FEATURE_KEYWORDS.intersection(recent_words))
    
    return found_security, found_features

def calculate_vps_score(
    plugin: Dict[str, Any], 
    days_ago: int, 
    matched_tags: List[str], 
    support_rate: int, 
    tested_ver: str, 
    sec_flags: List[str], 
    feat_flags: List[str],
    code_analysis: Optional[CodeAnalysisResult] = None
) -> int:
    """
    Enhanced VPS calculation with code analysis integration.
    High Score = High Probability of Unknown Vulnerabilities (0-day) or Unpatched Code.
    """
    score = 0
    
    # 1. CODE ROT (Maintenance Latency) - Max 40 pts
    if days_ago > 730: score += 40      # Abandoned (> 2 years) - Critical Risk
    elif days_ago > 365: score += 25    # Neglected (> 1 year)
    elif days_ago > 180: score += 15    # Stale (> 6 months)
    
    # 2. ATTACK SURFACE (Intrinsic Risk) - Max 30 pts
    if matched_tags: 
        surface_score = min(30, len(matched_tags) * 3)
        score += surface_score

    # 3. DEVELOPER NEGLECT (Support Health) - Max 15 pts
    if support_rate < 20: score += 15
    elif support_rate < 50: score += 10
    
    # 4. TECHNICAL DEBT (Compatibility) - Max 15 pts
    try:
        if float(tested_ver) < CURRENT_WP_VERSION - 0.5: 
            score += 15
    except (ValueError, TypeError): 
        score += 10  # Unknown compatibility is risky
        
    # 5. REPUTATION (Quality Signal) - Max 10 pts
    rating = plugin.get('rating', 0) / 20  # Convert 100 scale to 5
    if rating < 3.5: score += 10
    
    # 6. NEW: CODE ANALYSIS BONUS - Max 25 pts
    if code_analysis:
        # Dangerous functions found
        if code_analysis.dangerous_functions:
            score += min(15, len(code_analysis.dangerous_functions) * 3)
        
        # Missing security measures
        if code_analysis.sanitization_issues:
            score += min(10, len(code_analysis.sanitization_issues) * 2)
        
        # AJAX without proper nonce checking
        if code_analysis.ajax_endpoints and not code_analysis.nonce_usage:
            score += 8
        
        # File operations without proper validation
        if code_analysis.file_operations:
            score += min(5, len(code_analysis.file_operations))
            
    # BONUS: User Facing Risk
    # Plugins that interact with users are inherently more risky (XSS, inputs, etc)
    # We check the tags passed in matched_tags, but we also check against USER_FACING_TAGS if available in scope
    # Since we don't pass USER_FACING_TAGS into this function, we rely on the caller or check tags here if needed.
    # However, to keep it simple, if the user specifically requested user-facing plugins, we can assume they are high value.
    # But let's check tags again here for scoring accuracy even if flag is not set.
    
    # Check for user facing tags in matched_tags (which only contains RISKY_TAGS currently)
    # or re-evaluate tags. Ideally, we should pass is_user_facing flag.
    # For now, let's just add a small boost if it hits known risky user-input tags.
    
    user_input_tags = {'form', 'contact', 'input', 'chat', 'comment', 'review', 'upload', 'profile'}
    if any(tag in matched_tags for tag in user_input_tags):
        score += 5
    
    # BONUS: Active Maintenance Reward
    if days_ago < 14: score = max(0, score - 5)
    
    # BONUS: Good security practices
    if code_analysis and code_analysis.nonce_usage:
        score = max(0, score - 3)  # Reward for using nonces

    return min(score, 100)

def get_score_display(score: int) -> str:
    """Generates a colored ASCII bar for the score."""
    bar_len = 10
    filled = int((score / 100) * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    
    if score >= 80: 
        return f"{Colors.RED}[{bar}] {score} (CRITICAL){Colors.RESET}"
    elif score >= 50: 
        return f"{Colors.ORANGE}[{bar}] {score} (HIGH){Colors.RESET}"
    else: 
        return f"{Colors.GREEN}[{bar}] {score} (LOW){Colors.RESET}"

def generate_html_report(results: List[Dict[str, Any]]) -> str:
    """Generates a complete HTML report string from results."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WP-Hunter Scan Results</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 20px; background-color: #f4f4f9; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.2); background: white; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; font-size: 14px; }}
        th {{ background-color: #007bff; color: white; }}
        tr:hover {{ background-color: #f1f1f1; }}
        .score-high {{ color: #d9534f; font-weight: bold; }}
        .score-med {{ color: #f0ad4e; font-weight: bold; }}
        .score-low {{ color: #5cb85c; font-weight: bold; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .tag {{ display: inline-block; padding: 2px 6px; font-size: 11px; font-weight: bold; color: white; background-color: #777; border-radius: 4px; margin-right: 4px; }}
        .tag-risk {{ background-color: #d9534f; }}
        .tag-safe {{ background-color: #5cb85c; }}
    </style>
</head>
<body>
    <h1>WP-Hunter Reconnaissance Report</h1>
    <p>Generated: {timestamp}</p>
    <table>
        <thead>
            <tr>
                <th>Name (Slug)</th>
                <th>Version</th>
                <th>Score</th>
                <th>Installs</th>
                <th>Updated</th>
                <th>Trusted Author</th>
                <th>Links</th>
            </tr>
        </thead>
        <tbody>
"""
    
    for res in results:
        score = res.get('score', 0)
        score_class = 'score-high' if score >= 50 else ('score-med' if score >= 30 else 'score-low')
        trusted = '<span class="tag tag-safe">YES</span>' if res.get('author_trusted') else '<span class="tag">NO</span>'
        
        html += f"""
            <tr>
                <td><b>{res.get('name')}</b><br><small>{res.get('slug')}</small></td>
                <td>{res.get('version')}</td>
                <td class="{score_class}">{score}</td>
                <td>{res.get('installations')}+</td>
                <td>{res.get('days_since_update')} days ago</td>
                <td>{trusted}</td>
                <td>
                    <a href="{res.get('wpscan_link')}" target="_blank">WPScan</a> | 
                    <a href="{res.get('cve_search_link')}" target="_blank">CVE</a> | 
                    <a href="{res.get('patchstack_link')}" target="_blank">Patchstack</a> |
                    <a href="{res.get('download_link')}" target="_blank">Download</a>
                </td>
            </tr>"""

    html += """
        </tbody>
    </table>
</body>
</html>"""
    return html

# --- CORE LOGIC ---

def fetch_plugins(page: int, browse_type: str, max_retries: int = 3) -> List[Dict[str, Any]]:
    """Fetches plugins from WP API with robust retry logic."""
    url = 'https://api.wordpress.org/plugins/info/1.2/'
    params = {
        'action': 'query_plugins',
        'request[browse]': browse_type,
        'request[page]': page, 'request[per_page]': 100,
        'request[fields][active_installs]': True, 'request[fields][short_description]': True,
        'request[fields][last_updated]': True, 'request[fields][download_link]': True,
        'request[fields][ratings]': True, 'request[fields][num_ratings]': True,
        'request[fields][support_threads]': True, 'request[fields][support_threads_resolved]': True,
        'request[fields][tested]': True, 'request[fields][author]': True,
        'request[fields][version]': True, 'request[fields][tags]': True,
        'request[fields][sections]': True, 'request[fields][donate_link]': True
    }
    
    for attempt in range(max_retries):
        try:
            response = session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('plugins', []) if data else []
            
            elif response.status_code == 429:
                wait_time = 5 * (attempt + 1)
                with print_lock:
                    print(f"{Colors.YELLOW}[!] Rate limited, waiting {wait_time}s...{Colors.RESET}")
                time.sleep(wait_time)
                continue
                
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            with print_lock:
                print(f"{Colors.RED}[!] Network error ({e}), retrying...{Colors.RESET}")
            time.sleep(2)
            continue
        except Exception as e:
            with print_lock:
                print(f"{Colors.RED}[!] Unexpected API Error: {e}{Colors.RESET}")
            break
            
    return []

def display_plugin_console(idx: int, plugin: Dict[str, Any], analysis: Dict[str, Any]) -> None:
    """Handles the formatted console output for a single plugin."""
    p = plugin
    a = analysis
    
    print(f"{Colors.BOLD}{Colors.CYAN}┌── [{idx}] {p.get('name')} {Colors.RESET}(v{p.get('version')})")
    
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.BOLD}SCORE:{Colors.RESET} {a['score_display']}  |  {Colors.BOLD}Compatibility:{Colors.RESET} {a['compat_display']}")
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.BOLD}Data:{Colors.RESET} {a['installs']}+ Installations | {a['days_ago']} days ago")

    dev_type = f"{Colors.YELLOW}Individual/Indie{Colors.RESET}" if p.get('donate_link') else f"{Colors.BLUE}Corporate{Colors.RESET}"
    if a['is_trusted']: dev_type += f" {Colors.GREEN}(Trusted Author){Colors.RESET}"
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.BOLD}Type:{Colors.RESET} {dev_type}")
    
    if a.get('is_user_facing'):
        print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.MAGENTA}{Colors.BOLD}🎯 USER FACING:{Colors.RESET} Detected")

    if a['sec_flags']:
        print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}{Colors.BOLD}⚠ SECURITY PATCH: {', '.join(a['sec_flags']).upper()}{Colors.RESET}")
    elif a['feat_flags']:
        print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.YELLOW}{Colors.BOLD}★ NEW FEATURE: {', '.join(a['feat_flags']).upper()}{Colors.RESET}")

    if a['matched_tags']:
        print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.BOLD}Risk Areas:{Colors.RESET} {Colors.ORANGE}{', '.join(list(set(a['matched_tags']))[:5]).upper()}{Colors.RESET}")

    # NEW: Code Analysis Results
    if 'code_analysis' in a and a['code_analysis']:
        ca = a['code_analysis']
        print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.GRAY}--- Code Analysis ---{Colors.RESET}")
        
        if ca.dangerous_functions:
            print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}🚨 Dangerous Functions: {', '.join(ca.dangerous_functions[:3])}{Colors.RESET}")
        
        if ca.ajax_endpoints:
            nonce_status = "✓ Protected" if ca.nonce_usage else "⚠ Unprotected"
            print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.YELLOW}🔗 AJAX Endpoints: {len(ca.ajax_endpoints)} ({nonce_status}){Colors.RESET}")
        
        if ca.sanitization_issues:
            print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}🔓 Sanitization Issues: {len(ca.sanitization_issues)}{Colors.RESET}")
        
        if ca.file_operations:
            print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.ORANGE}📁 File Operations: {len(ca.file_operations)}{Colors.RESET}")

    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.MAGENTA}[Trac Diff]:{Colors.RESET} https://plugins.trac.wordpress.org/log/{p.get('slug')}/")
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.BLUE}[Download]:{Colors.RESET}  {p.get('download_link')}")
    
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.GRAY}--- Vulnerability Intel ---{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}[Smart Dork]:{Colors.RESET} {a['links']['google_dork']}")
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}[WPScan]:{Colors.RESET}     {a['links']['wpscan']}")
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}[Patchstack]:{Colors.RESET} {a['links']['patchstack']}")
    print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}[Wordfence]:{Colors.RESET}  {a['links']['wordfence']}")
    
    print(f"{Colors.CYAN}└──{Colors.RESET}\n")

def process_page_task(
    page: int, 
    args: argparse.Namespace, 
    found_count_ref: List[int], 
    collected_results: List[Dict[str, Any]], 
    stop_event: threading.Event
) -> None:
    """Worker function to process a single page of results."""
    if stop_event.is_set(): return

    plugins = fetch_plugins(page, args.sort)
    if not plugins: return

    for p in plugins:
        if stop_event.is_set(): break
        
        # --- FILTERING LOGIC ---
        with print_lock:
             if args.limit > 0 and found_count_ref[0] >= args.limit:
                stop_event.set()
                break

        installs = p.get('active_installs', 0)
        
        if installs < args.min: continue
        if args.max > 0 and installs > args.max: continue

        days_ago = calculate_days_ago(p.get('last_updated'))
        
        if args.min_days > 0 and days_ago < args.min_days: continue
        if args.max_days > 0 and days_ago > args.max_days: continue

        if args.abandoned and days_ago < 730: continue

        plugin_tags = list(p.get('tags', {}).keys())
        name = p.get('name', '').lower()
        desc = p.get('short_description', '').lower()
        matched_tags = [tag for tag in RISKY_TAGS if tag in plugin_tags or tag in name or tag in desc]
        
        if args.smart and not matched_tags: continue

        # --- USER FACING FILTER ---
        is_user_facing = False
        if args.user_facing:
            # Check for user-facing tags
            user_facing_match = [tag for tag in USER_FACING_TAGS if tag in plugin_tags or tag in name or tag in desc]
            if not user_facing_match:
                continue
            is_user_facing = True
        else:
             # Even if flag is not set, check for is_user_facing for reporting
             user_facing_match = [tag for tag in USER_FACING_TAGS if tag in plugin_tags or tag in name or tag in desc]
             is_user_facing = bool(user_facing_match)

        # --- ANALYSIS LOGIC ---
        total_sup = p.get('support_threads', 0)
        res_sup = p.get('support_threads_resolved', 0)
        res_rate = int((res_sup / total_sup) * 100) if total_sup > 0 else 0
        
        sec_flags, feat_flags = analyze_changelog(p.get('sections', {}))
        tested_ver = p.get('tested', '?')
        slug = p.get('slug', '')  # Moved here to fix NameError bug
        
        # NEW: Code Analysis Integration
        code_analysis = None
        if hasattr(args, 'deep_analysis') and args.deep_analysis:
            # Download and analyze plugin code
            download_url = p.get('download_link')
            if download_url:
                plugin_path = PluginDownloader.download_and_extract(download_url, slug)
                if plugin_path:
                    code_analysis = CodeAnalyzer.analyze_plugin_code(plugin_path)
                    print(f"{Colors.GREEN}[✓] Code analysis completed for {slug}{Colors.RESET}")
        
        vps_score = calculate_vps_score(p, days_ago, matched_tags, res_rate, p.get('tested', '0'), sec_flags, feat_flags, code_analysis)
        
        author_raw = p.get('author', 'Unknown')
        is_trusted = 'automattic' in author_raw.lower() or 'wordpress.org' in author_raw.lower()
        
        # Link Generation
        links = {
            'cve': f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={slug}",
            'wpscan': f"https://wpscan.com/plugin/{slug}",
            'patchstack': f"https://patchstack.com/database?search={slug}",
            'wordfence': f"https://www.wordfence.com/threat-intel/vulnerabilities/search?search={slug}",
            'google_dork': f"https://www.google.com/search?q={slug}+site:wpscan.com+OR+site:patchstack.com+OR+site:cve.mitre.org+%22vulnerability%22".replace(' ', '+').replace('"', '%22')
        }

        compat_display = f"{Colors.RED}Outdated (WP {tested_ver}){Colors.RESET}" if str(tested_ver) < str(CURRENT_WP_VERSION - 0.5) else f"{Colors.GREEN}Up-to-date{Colors.RESET}"
        score_display = get_score_display(vps_score)

        # Analysis Object for Display
        analysis_data = {
            'score': vps_score,
            'score_display': score_display,
            'compat_display': compat_display,
            'installs': installs,
            'days_ago': days_ago,
            'is_trusted': is_trusted,
            'sec_flags': sec_flags,
            'feat_flags': feat_flags,
            'matched_tags': matched_tags,
            'links': links,
            'is_user_facing': is_user_facing, # NEW: Pass this status
            'code_analysis': code_analysis  # NEW: Add code analysis results
        }

        # --- OUTPUT & COLLECTION ---
        with print_lock:
            if args.limit > 0 and found_count_ref[0] >= args.limit:
                stop_event.set()
                break

            found_count_ref[0] += 1
            display_plugin_console(found_count_ref[0], p, analysis_data)

            if args.output or args.download > 0:
                collected_results.append({
                    'name': p.get('name'),
                    'slug': slug,
                    'version': p.get('version'),
                    'score': vps_score,
                    'installations': installs,
                    'days_since_update': days_ago,
                    'tested_wp_version': tested_ver,
                    'author_trusted': is_trusted,
                    'is_risky_category': bool(matched_tags),
                    'is_user_facing': is_user_facing,
                    'risk_tags': ', '.join(matched_tags),
                    'security_flags': ', '.join(sec_flags),
                    'download_link': p.get('download_link'),
                    'cve_search_link': links['cve'],
                    'wpscan_link': links['wpscan'],
                    'patchstack_link': links['patchstack'],
                    'wordfence_link': links['wordfence'],
                    'google_dork_link': links['google_dork']
                })

def save_results(results: List[Dict[str, Any]], filename: str, format_type: str) -> None:
    """Saves the collected results to a file."""
    if not results:
        with print_lock:
            print(f"{Colors.YELLOW}[!] No results to save.{Colors.RESET}")
        return

    try:
        with open(filename, 'w', encoding='utf-8', newline='') as f:
            if format_type == 'json':
                json.dump(results, f, indent=4)
            
            elif format_type == 'csv':
                writer = csv.writer(f)
                headers = list(results[0].keys())
                writer.writerow(headers)
                for res in results:
                    writer.writerow([res.get(h, '') for h in headers])
            
            elif format_type == 'html':
                f.write(generate_html_report(results))
        
        with print_lock:
            print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")

    except Exception as e:
        print(f"{Colors.RED}[!] Error saving results: {e}{Colors.RESET}")

def download_top_plugins(results: List[Dict[str, Any]], download_limit: int, base_dir: str = ".") -> None:
    """Downloads and extracts top N plugins sorted by VPS score to ./Plugins/ directory."""
    if not results:
        print(f"{Colors.YELLOW}[!] No results to download.{Colors.RESET}")
        return

    # Sort by score (highest first)
    sorted_results = sorted(results, key=lambda x: x.get('score', 0), reverse=True)
    plugins_to_download = sorted_results[:download_limit]

    # Create Plugins directory
    plugins_dir = os.path.join(base_dir, "Plugins")
    os.makedirs(plugins_dir, exist_ok=True)

    print(f"\n{Colors.BOLD}{Colors.CYAN}=== Downloading Top {len(plugins_to_download)} High-Score Plugins ==={Colors.RESET}")
    print(f"Download directory: {os.path.abspath(plugins_dir)}\n")

    downloaded_count = 0
    for idx, plugin in enumerate(plugins_to_download, 1):
        slug = plugin.get('slug', 'unknown')
        version = plugin.get('version', 'latest')
        score = plugin.get('score', 0)
        download_url = plugin.get('download_link')

        if not download_url:
            print(f"{Colors.YELLOW}[{idx}] Skipping {slug} - No download link available{Colors.RESET}")
            continue

        zip_filename = f"{slug}.{version}.zip"
        zip_filepath = os.path.join(plugins_dir, zip_filename)
        extract_dir = os.path.join(plugins_dir, slug)

        try:
            print(f"{Colors.CYAN}[{idx}] Downloading: {slug} (v{version}) - VPS Score: {score}{Colors.RESET}")
            response = session.get(download_url, stream=True, timeout=60)
            response.raise_for_status()

            with open(zip_filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            file_size = os.path.getsize(zip_filepath) / 1024  # KB
            print(f"{Colors.GREEN}    ✓ Downloaded: {zip_filename} ({file_size:.1f} KB){Colors.RESET}")
            
            # Auto-extract ZIP
            print(f"{Colors.CYAN}    📦 Extracting to {slug}/...{Colors.RESET}")
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Remove ZIP file after extraction
            os.remove(zip_filepath)
            
            # Count extracted files
            file_count = sum(1 for _ in Path(extract_dir).rglob('*') if _.is_file())
            print(f"{Colors.GREEN}    ✓ Extracted: {file_count} files{Colors.RESET}")
            
            downloaded_count += 1

        except zipfile.BadZipFile:
            print(f"{Colors.RED}    ✗ Invalid ZIP file{Colors.RESET}")
            if os.path.exists(zip_filepath):
                os.remove(zip_filepath)
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}    ✗ Download failed: {e}{Colors.RESET}")
        except IOError as e:
            print(f"{Colors.RED}    ✗ File error: {e}{Colors.RESET}")

    print(f"\n{Colors.GREEN}[✓] Download complete: {downloaded_count}/{len(plugins_to_download)} plugins extracted to {plugins_dir}{Colors.RESET}")

def scan_themes(pages: int = 5, limit: int = 0) -> None:
    """NEW: WordPress Theme Scanner"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}=== WordPress Theme Scanner ==={Colors.RESET}")
    print(f"Scanning {pages} pages of themes...\n")
    
    found_count = 0
    
    for page in range(1, pages + 1):
        if limit > 0 and found_count >= limit:
            break
            
        print(f"{Colors.CYAN}[Page {page}] Fetching themes...{Colors.RESET}")
        themes = ThemeScanner.fetch_themes(page)
        
        if not themes:
            print(f"{Colors.YELLOW}[!] No themes found on page {page}{Colors.RESET}")
            break
        
        for theme in themes:
            if limit > 0 and found_count >= limit:
                break
                
            found_count += 1
            
            # Basic theme analysis
            name = theme.get('name', 'Unknown')
            version = theme.get('version', '?')
            downloads = theme.get('downloaded', 0)
            last_updated = theme.get('last_updated', '')
            author = theme.get('author', 'Unknown')
            
            days_ago = calculate_days_ago(last_updated)
            
            # Check for risky patterns in theme
            theme_tags = list(theme.get('tags', {}).keys())
            desc = theme.get('description', '').lower()
            matched_tags = [tag for tag in RISKY_TAGS if tag in theme_tags or tag in desc]
            
            # Simple risk assessment for themes
            risk_score = 0
            if days_ago > 730: risk_score += 30
            elif days_ago > 365: risk_score += 20
            if matched_tags: risk_score += 15
            if downloads < 1000: risk_score += 10
            
            risk_level = "HIGH" if risk_score >= 40 else ("MEDIUM" if risk_score >= 20 else "LOW")
            risk_color = Colors.RED if risk_score >= 40 else (Colors.ORANGE if risk_score >= 20 else Colors.GREEN)
            
            print(f"{Colors.BOLD}{Colors.MAGENTA}┌── [{found_count}] {name} {Colors.RESET}(v{version})")
            print(f"{Colors.MAGENTA}│{Colors.RESET}   {Colors.BOLD}Risk:{Colors.RESET} {risk_color}{risk_level} ({risk_score}){Colors.RESET}")
            print(f"{Colors.MAGENTA}│{Colors.RESET}   {Colors.BOLD}Downloads:{Colors.RESET} {downloads:,} | {Colors.BOLD}Updated:{Colors.RESET} {days_ago} days ago")
            print(f"{Colors.MAGENTA}│{Colors.RESET}   {Colors.BOLD}Author:{Colors.RESET} {author}")
            
            if matched_tags:
                print(f"{Colors.MAGENTA}│{Colors.RESET}   {Colors.BOLD}Risk Areas:{Colors.RESET} {Colors.ORANGE}{', '.join(matched_tags[:3]).upper()}{Colors.RESET}")
            
            download_link = theme.get('download_link', '')
            if download_link:
                print(f"{Colors.MAGENTA}│{Colors.RESET}   {Colors.BLUE}[Download]:{Colors.RESET} {download_link}")
            
            print(f"{Colors.MAGENTA}└──{Colors.RESET}\n")
        
        time.sleep(0.5)  # Rate limiting
    
    print(f"{Colors.GREEN}[✓] Theme scan complete: {found_count} themes analyzed{Colors.RESET}")

def print_banner() -> None:
    banner = f"""{Colors.BOLD}{Colors.CYAN}
██╗    ██╗██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║    ██║██╔══██╗      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║███╗██║██╔═══╝ ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚███╔███╔╝██║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

                       WordPress Plugin Reconnaissance Tool                 

{Colors.RESET}{Colors.YELLOW}Author: Ali Sünbül (xeloxa)
Email:  alisunbul@proton.me
Repo:   https://github.com/xeloxa/wp-hunter{Colors.RESET}
"""
    print(banner)

def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='WP Hunter - WordPress Plugin & Theme Security Scanner')
    
    # Basic scanning options
    parser.add_argument('--pages', type=int, default=5, help='Maximum number of pages to scan (Default: 5)')
    parser.add_argument('--limit', type=int, default=0, help='Maximum number of targets to list (0 = Unlimited)')
    parser.add_argument('--min', type=int, default=1000, help='Minimum active installations')
    parser.add_argument('--max', type=int, default=0, help='Maximum active installations (0 = Unlimited)')
    parser.add_argument('--sort', type=str, default='updated', choices=['new', 'updated', 'popular'])
    parser.add_argument('--smart', action='store_true', help='Show only risky categories')
    parser.add_argument('--abandoned', action='store_true', help='Show only plugins not updated for > 2 years')
    
    # Output options
    parser.add_argument('--output', type=str, help='Output file name (e.g., results.json)')
    parser.add_argument('--format', type=str, default='json', choices=['json', 'csv', 'html'], help='Output format')
    parser.add_argument('--download', type=int, default=0, metavar='N', help='Download top N plugins (sorted by VPS score) to ./Plugins/')
    
    # Time filtering
    parser.add_argument('--min-days', type=int, default=0, help='Minimum days since last update')
    parser.add_argument('--max-days', type=int, default=0, help='Maximum days since last update')
    
    # NEW: Enhanced features
    parser.add_argument('--deep-analysis', action='store_true', help='Download and analyze plugin code (slower but more accurate)')
    parser.add_argument('--themes', action='store_true', help='Scan WordPress themes instead of plugins')
    parser.add_argument('--ajax-scan', action='store_true', help='Focus on plugins with AJAX functionality')
    parser.add_argument('--dangerous-functions', action='store_true', help='Look for plugins using dangerous PHP functions')
    parser.add_argument('--user-facing', action='store_true', help='Focus on plugins that interact directly with end-users (high risk)')
    parser.add_argument('--auto-download-risky', type=int, default=0, metavar='N', help='Auto-download top N riskiest plugins for analysis')
    
    return parser.parse_args()

def main() -> None:
    print_banner()
    args = get_args()
    
    # NEW: Theme scanning mode
    if args.themes:
        scan_themes(args.pages, args.limit)
        return

    # Override defaults for Abandoned Mode to be effective
    if args.abandoned:
        if args.sort == 'updated':
            args.sort = 'popular'
            print(f"{Colors.YELLOW}[!] Mode switched to POPULAR to find abandoned plugins effectively.{Colors.RESET}")
        
        # Abandoned plugins are rarely quickly accessible in popular lists
        if args.pages == 5: # If user didn't change default
            args.pages = 100
            print(f"{Colors.YELLOW}[!] Increased page scan limit to 100 to dig deeper for abandoned plugins.{Colors.RESET}")
    
    # Increase scan depth for date filtering
    if args.min_days > 0 and args.pages == 5:
        args.pages = 50
        print(f"{Colors.YELLOW}[!] Increased page scan limit to 50 to find plugins older than {args.min_days} days.{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}{Colors.WHITE}=== WP Hunter ==={Colors.RESET}")
    range_str = f"{args.min}-{args.max}" if args.max > 0 else f"{args.min}+"
    print(f"Mode: {args.sort.upper()} | Range: {range_str} installs")
    
    limit_msg = f"{args.limit} items" if args.limit > 0 else "Unlimited"
    print(f"Target Limit: {Colors.YELLOW}{limit_msg}{Colors.RESET}")

    # NEW: Enhanced mode indicators
    if args.smart: print(f"{Colors.RED}[!] Smart Filter: ON{Colors.RESET}")
    if args.abandoned: print(f"{Colors.RED}[!] Abandoned Filter: ON (>730 days){Colors.RESET}")
    if args.deep_analysis: print(f"{Colors.CYAN}[!] Deep Code Analysis: ON (slower but more accurate){Colors.RESET}")
    if args.ajax_scan: print(f"{Colors.YELLOW}[!] AJAX Focus: ON{Colors.RESET}")
    if args.user_facing: print(f"{Colors.MAGENTA}[!] User-Facing Plugin Filter: ON{Colors.RESET}")
    if args.dangerous_functions: print(f"{Colors.RED}[!] Dangerous Functions Detection: ON{Colors.RESET}")
    
    if args.min_days > 0 or args.max_days > 0:
        d_min = args.min_days
        d_max = args.max_days if args.max_days > 0 else "∞"
        print(f"{Colors.RED}[!] Update Age Filter: {d_min} to {d_max} days{Colors.RESET}")

    print("=" * 70)

    found_count_ref = [0] 
    collected_results: List[Dict[str, Any]] = []
    stop_event = threading.Event()
    
    pages_to_scan = list(range(1, args.pages + 1))
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                process_page_task, 
                page, args, found_count_ref, collected_results, stop_event
            ): page for page in pages_to_scan
        }
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass
            
            if stop_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break

    if args.output and collected_results:
        save_results(collected_results, args.output, args.format)

    # Download top plugins if requested
    if args.download > 0 and collected_results:
        download_top_plugins(collected_results, args.download)
    
    # NEW: Auto-download riskiest plugins
    if args.auto_download_risky > 0 and collected_results:
        print(f"\n{Colors.BOLD}{Colors.RED}=== Auto-Downloading Riskiest Plugins ==={Colors.RESET}")
        risky_plugins = sorted(collected_results, key=lambda x: x.get('score', 0), reverse=True)
        download_top_plugins(risky_plugins[:args.auto_download_risky], args.auto_download_risky)

    print(f"\n{Colors.GREEN}[✓] Scan completed. Total {found_count_ref[0]} targets analyzed.{Colors.RESET}")
    
    # NEW: Summary statistics
    if collected_results:
        high_risk = sum(1 for r in collected_results if r.get('score', 0) >= 50)
        abandoned = sum(1 for r in collected_results if r.get('days_since_update', 0) > 730)
        risky_categories = sum(1 for r in collected_results if r.get('is_risky_category', False))
        user_facing_count = sum(1 for r in collected_results if r.get('is_user_facing', False))
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}=== Scan Summary ==={Colors.RESET}")
        print(f"High Risk Plugins: {Colors.RED}{high_risk}{Colors.RESET}")
        print(f"Abandoned Plugins: {Colors.YELLOW}{abandoned}{Colors.RESET}")
        print(f"User Facing Plugins: {Colors.MAGENTA}{user_facing_count}{Colors.RESET}")
        print(f"Risky Categories: {Colors.ORANGE}{risky_categories}{Colors.RESET}")
        print(f"Total Analyzed: {Colors.GREEN}{len(collected_results)}{Colors.RESET}")

def cleanup_session() -> None:
    session.close()

if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup_session()
