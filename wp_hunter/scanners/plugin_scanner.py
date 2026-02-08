"""
WP-Hunter Plugin Scanner

Plugin fetching and analysis from WordPress.org API.
"""

import time
import threading
import requests
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime

from wp_hunter.config import (
    Colors, RISKY_TAGS, USER_FACING_TAGS, SECURITY_KEYWORDS, FEATURE_KEYWORDS
)
from wp_hunter.models import ScanConfig, PluginResult, CodeAnalysisResult
from wp_hunter.analyzers.code_analyzer import CodeAnalyzer
from wp_hunter.analyzers.vps_scorer import calculate_vps_score


# Thread-safe lock for console output
print_lock = threading.Lock()

# Global session for connection pooling
_session: Optional[requests.Session] = None


def get_session(pool_size: int = 100) -> requests.Session:
    """Get or create the global requests session with optimized pooling."""
    global _session
    if _session is None:
        _session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=3
        )
        _session.mount('https://', adapter)
        _session.mount('http://', adapter)
    return _session


def close_session():
    """Close the global session."""
    global _session
    if _session:
        _session.close()
        _session = None


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


def analyze_changelog(sections: Dict[str, str]) -> tuple:
    """Analyzes changelog for security and feature keywords."""
    if not sections or 'changelog' not in sections:
        return [], []
    
    changelog_text = sections['changelog'].lower()
    recent_log = changelog_text[:2000] 
    recent_words = set(recent_log.split())
    
    found_security = list(SECURITY_KEYWORDS.intersection(recent_words))
    found_features = list(FEATURE_KEYWORDS.intersection(recent_words))
    
    return found_security, found_features


def fetch_plugins(page: int, browse_type: str, max_retries: int = 3) -> List[Dict[str, Any]]:
    """Fetches plugins from WP API with robust retry logic."""
    session = get_session()
    url = 'https://api.wordpress.org/plugins/info/1.2/'
    params = {
        'action': 'query_plugins',
        'request[browse]': browse_type,
        'request[page]': page, 
        'request[per_page]': 100,
        'request[fields][active_installs]': True, 
        'request[fields][short_description]': True,
        'request[fields][last_updated]': True, 
        'request[fields][download_link]': True,
        'request[fields][ratings]': True, 
        'request[fields][num_ratings]': True,
        'request[fields][support_threads]': True, 
        'request[fields][support_threads_resolved]': True,
        'request[fields][tested]': True, 
        'request[fields][author]': True,
        'request[fields][version]': True, 
        'request[fields][tags]': True,
        'request[fields][sections]': True, 
        'request[fields][donate_link]': True
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


class PluginScanner:
    """High-level plugin scanner with configurable callbacks."""
    
    def __init__(
        self, 
        config: ScanConfig,
        on_result: Optional[Callable[[PluginResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None
    ):
        self.config = config
        self.on_result = on_result
        self.on_progress = on_progress
        self.results: List[PluginResult] = []
        self.found_count = 0
        self.stop_event = threading.Event()
        self._downloader = None
    
    def set_downloader(self, downloader):
        """Set the downloader for deep analysis."""
        self._downloader = downloader
    
    def stop(self):
        """Stop the scan."""
        self.stop_event.set()
    
    def process_plugin(self, plugin: Dict[str, Any]) -> Optional[PluginResult]:
        """Process a single plugin and return a PluginResult if it passes filters."""
        config = self.config
        
        installs = plugin.get('active_installs', 0)
        
        # Filter by installations
        if installs < config.min_installs:
            return None
        if config.max_installs > 0 and installs > config.max_installs:
            return None
        
        days_ago = calculate_days_ago(plugin.get('last_updated'))
        
        # Filter by update age
        if config.min_days > 0 and days_ago < config.min_days:
            return None
        if config.max_days > 0 and days_ago > config.max_days:
            return None
        
        # Abandoned filter
        if config.abandoned and days_ago < 730:
            return None
        
        # Tag analysis
        plugin_tags = list(plugin.get('tags', {}).keys())
        name = plugin.get('name', '').lower()
        desc = plugin.get('short_description', '').lower()
        matched_tags = [tag for tag in RISKY_TAGS if tag in plugin_tags or tag in name or tag in desc]
        
        if config.smart and not matched_tags:
            return None
        
        # User facing filter
        is_user_facing = False
        if config.user_facing:
            user_facing_match = [tag for tag in USER_FACING_TAGS if tag in plugin_tags or tag in name or tag in desc]
            if not user_facing_match:
                return None
            is_user_facing = True
        else:
            user_facing_match = [tag for tag in USER_FACING_TAGS if tag in plugin_tags or tag in name or tag in desc]
            is_user_facing = bool(user_facing_match)
        
        # Analysis
        total_sup = plugin.get('support_threads', 0)
        res_sup = plugin.get('support_threads_resolved', 0)
        res_rate = int((res_sup / total_sup) * 100) if total_sup > 0 else 0
        
        sec_flags, feat_flags = analyze_changelog(plugin.get('sections', {}))
        tested_ver = plugin.get('tested', '?')
        slug = plugin.get('slug', '')
        
        # Code analysis if enabled
        code_analysis = None
        if config.deep_analysis and self._downloader:
            download_url = plugin.get('download_link')
            if download_url:
                plugin_path = self._downloader.download_and_extract(download_url, slug)
                if plugin_path:
                    code_analysis = CodeAnalyzer.analyze_plugin_code(plugin_path)
        
        # Calculate VPS score
        vps_score = calculate_vps_score(
            plugin, days_ago, matched_tags, res_rate, 
            tested_ver, sec_flags, feat_flags, code_analysis
        )
        
        author_raw = plugin.get('author', 'Unknown')
        is_trusted = 'automattic' in author_raw.lower() or 'wordpress.org' in author_raw.lower()
        
        # Create result object
        result = PluginResult(
            name=plugin.get('name', 'Unknown'),
            slug=slug,
            version=plugin.get('version', '?'),
            score=vps_score,
            installations=installs,
            days_since_update=days_ago,
            tested_wp_version=tested_ver,
            author_trusted=is_trusted,
            is_risky_category=bool(matched_tags),
            is_user_facing=is_user_facing,
            risk_tags=matched_tags,
            security_flags=sec_flags,
            feature_flags=feat_flags,
            code_analysis=code_analysis,
            download_link=plugin.get('download_link', ''),
            cve_search_link=f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={slug}",
            wpscan_link=f"https://wpscan.com/plugin/{slug}",
            patchstack_link=f"https://patchstack.com/database?search={slug}",
            wordfence_link=f"https://www.wordfence.com/threat-intel/vulnerabilities/search?search={slug}",
            google_dork_link=f"https://www.google.com/search?q={slug}+site:wpscan.com+OR+site:patchstack.com+OR+site:cve.mitre.org+%22vulnerability%22".replace(' ', '+').replace('"', '%22'),
            trac_link=f"https://plugins.trac.wordpress.org/log/{slug}/"
        )
        
        if result and result.score < config.min_score:
            return None

        return result
    
    def scan_page(self, page: int) -> List[PluginResult]:
        """Scan a single page of plugins."""
        if self.stop_event.is_set():
            return []
        
        plugins = fetch_plugins(page, self.config.sort)
        results = []
        
        for plugin in plugins:
            if self.stop_event.is_set():
                break
            
            if self.config.limit > 0 and self.found_count >= self.config.limit:
                self.stop_event.set()
                break
            
            result = self.process_plugin(plugin)
            if result:
                self.found_count += 1
                results.append(result)
                self.results.append(result)
                
                if self.on_result:
                    self.on_result(result)
        
        return results
    
    def scan(self) -> List[PluginResult]:
        """Run the full scan based on configuration."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        pages_to_scan = list(range(1, self.config.pages + 1))
        
        max_threads = 50 if self.config.aggressive else 5
        if self.config.aggressive:
            print(f"Using {max_threads} threads for aggressive scan...")
            
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(self.scan_page, page): page 
                for page in pages_to_scan
            }
            
            for i, future in enumerate(as_completed(futures)):
                try:
                    future.result()
                except Exception:
                    pass
                
                if self.on_progress:
                    self.on_progress(i + 1, len(pages_to_scan))
                
                if self.stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
        
        return self.results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics."""
        return {
            "total_found": len(self.results),
            "high_risk": sum(1 for r in self.results if r.score >= 50),
            "abandoned": sum(1 for r in self.results if r.days_since_update > 730),
            "user_facing": sum(1 for r in self.results if r.is_user_facing),
            "risky_categories": sum(1 for r in self.results if r.is_risky_category),
        }
