import requests
import argparse
import sys
from datetime import datetime
import time
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import List, Dict, Any, Tuple, Optional, Set

# --- CONSTANTS ---
CURRENT_WP_VERSION = 6.7
MAX_WORKERS = 5

RISKY_TAGS: Set[str] = {
    'ecommerce', 'woocommerce', 'payment', 'gateway', 'stripe', 
    'form', 'contact', 'input', 'survey', 
    'upload', 'file', 'image', 'gallery', 'media', 'download',
    'login', 'register', 'membership', 'user', 'profile', 'admin', 'role',
    'booking', 'calendar', 'event', 
    'chat', 'ticket', 'support', 'comment',
    'api', 'query', 'database', 'sql', 'db'
}

SECURITY_KEYWORDS: Set[str] = {
    'xss', 'sql', 'injection', 'security', 'vulnerability', 'exploit', 
    'csrf', 'rce', 'fix', 'patched', 'sanitize', 'escape', 'harden'
}

FEATURE_KEYWORDS: Set[str] = {
    'added', 'new', 'feature', 'support for', 'introduced', 
    'now allows', 'implementation'
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
    feat_flags: List[str]
) -> int:
    """Calculates the Vulnerability Probability Score (VPS) based on heuristics."""
    score = 0
    
    if matched_tags: score += 25
    
    if support_rate < 50: score += 20
    elif support_rate < 80: score += 10
    
    try:
        if float(tested_ver) < CURRENT_WP_VERSION - 0.5: 
            score += 15
    except (ValueError, TypeError): 
        pass
        
    rating = plugin.get('rating', 0) / 20
    if rating < 3.5: score += 10
    
    if days_ago < 30: score += 10
    
    if len(sec_flags) > 0: score += 20     
    elif len(feat_flags) > 0: score += 15
    
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

    if a['sec_flags']:
        print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.RED}{Colors.BOLD}⚠ SECURITY PATCH: {', '.join(a['sec_flags']).upper()}{Colors.RESET}")
    elif a['feat_flags']:
        print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.YELLOW}{Colors.BOLD}★ NEW FEATURE: {', '.join(a['feat_flags']).upper()}{Colors.RESET}")

    if a['matched_tags']:
            print(f"{Colors.CYAN}│{Colors.RESET}   {Colors.BOLD}Risk Areas:{Colors.RESET} {Colors.ORANGE}{', '.join(list(set(a['matched_tags']))[:5]).upper()}{Colors.RESET}")

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
        if args.abandoned and days_ago < 730: continue

        plugin_tags = list(p.get('tags', {}).keys())
        name = p.get('name', '').lower()
        desc = p.get('short_description', '').lower()
        matched_tags = [tag for tag in RISKY_TAGS if tag in plugin_tags or tag in name or tag in desc]
        
        if args.smart and not matched_tags: continue

        # --- ANALYSIS LOGIC ---
        total_sup = p.get('support_threads', 0)
        res_sup = p.get('support_threads_resolved', 0)
        res_rate = int((res_sup / total_sup) * 100) if total_sup > 0 else 0
        
        sec_flags, feat_flags = analyze_changelog(p.get('sections', {}))
        tested_ver = p.get('tested', '?')
        vps_score = calculate_vps_score(p, days_ago, matched_tags, res_rate, p.get('tested', '0'), sec_flags, feat_flags)
        
        author_raw = p.get('author', 'Unknown')
        is_trusted = 'automattic' in author_raw.lower() or 'wordpress.org' in author_raw.lower()
        
        slug = p.get('slug')
        
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
            'links': links
        }

        # --- OUTPUT & COLLECTION ---
        with print_lock:
            if args.limit > 0 and found_count_ref[0] >= args.limit:
                stop_event.set()
                break

            found_count_ref[0] += 1
            display_plugin_console(found_count_ref[0], p, analysis_data)

            if args.output:
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
        with print_lock:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.RESET}")

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
    parser = argparse.ArgumentParser(description='WP Hunter')
    parser.add_argument('--pages', type=int, default=5, help='Maximum number of pages to scan (Default: 5)')
    parser.add_argument('--limit', type=int, default=0, help='Maximum number of targets to list (0 = Unlimited)')
    parser.add_argument('--min', type=int, default=1000, help='Minimum active installations')
    parser.add_argument('--max', type=int, default=0, help='Maximum active installations (0 = Unlimited)')
    parser.add_argument('--sort', type=str, default='updated', choices=['new', 'updated', 'popular'])
    parser.add_argument('--smart', action='store_true', help='Show only risky categories')
    parser.add_argument('--abandoned', action='store_true', help='Show only plugins not updated for > 2 years')
    parser.add_argument('--output', type=str, help='Output file name (e.g., results.json)')
    parser.add_argument('--format', type=str, default='json', choices=['json', 'csv', 'html'], help='Output format')
    return parser.parse_args()

def main() -> None:
    print_banner()
    args = get_args()

    # Override defaults for Abandoned Mode to be effective
    if args.abandoned:
        if args.sort == 'updated':
            args.sort = 'popular'
            print(f"{Colors.YELLOW}[!] Mode switched to POPULAR to find abandoned plugins effectively.{Colors.RESET}")
        
        # Abandoned plugins are rarely quickly accessible in popular lists
        if args.pages == 5: # If user didn't change default
            args.pages = 100
            print(f"{Colors.YELLOW}[!] Increased page scan limit to 100 to dig deeper for abandoned plugins.{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}{Colors.WHITE}=== WP Hunter ==={Colors.RESET}")
    range_str = f"{args.min}-{args.max}" if args.max > 0 else f"{args.min}+"
    print(f"Mode: {args.sort.upper()} | Range: {range_str} installs")
    
    limit_msg = f"{args.limit} items" if args.limit > 0 else "Unlimited"
    print(f"Target Limit: {Colors.YELLOW}{limit_msg}{Colors.RESET}")

    if args.smart: print(f"{Colors.RED}[!] Smart Filter: ON{Colors.RESET}")
    if args.abandoned: print(f"{Colors.RED}[!] Abandoned Filter: ON (>730 days){Colors.RESET}")

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

    print(f"\n{Colors.GREEN}[✓] Task Completed. Total {found_count_ref[0]} targets listed.{Colors.RESET}")

def cleanup_session() -> None:
    session.close()

if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup_session()