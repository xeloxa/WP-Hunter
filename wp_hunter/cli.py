"""
WP-Hunter CLI

Command-line interface and main entry point.
"""

import argparse
import webbrowser
import threading
from typing import List, Dict, Any

from wp_hunter.config import Colors
from wp_hunter.models import ScanConfig, PluginResult
from wp_hunter.scanners.plugin_scanner import PluginScanner, close_session
from wp_hunter.scanners.theme_scanner import ThemeScanner
from wp_hunter.downloaders.plugin_downloader import PluginDownloader
from wp_hunter.reports.html_report import save_results
from wp_hunter.ui.console import (
    print_banner, 
    display_plugin_console, 
    display_theme_console,
    print_summary
)


def get_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='WP Hunter - WordPress Plugin & Theme Security Scanner'
    )
    
    # Basic scanning options
    parser.add_argument('--pages', type=int, default=5, 
                        help='Maximum number of pages to scan (Default: 5)')
    parser.add_argument('--limit', type=int, default=0, 
                        help='Maximum number of targets to list (0 = Unlimited)')
    parser.add_argument('--min', type=int, default=1000, 
                        help='Minimum active installations')
    parser.add_argument('--max', type=int, default=0, 
                        help='Maximum active installations (0 = Unlimited)')
    parser.add_argument('--sort', type=str, default='updated', 
                        choices=['new', 'updated', 'popular'])
    parser.add_argument('--smart', action='store_true', 
                        help='Show only risky categories')
    parser.add_argument('--abandoned', action='store_true', 
                        help='Show only plugins not updated for > 2 years')
    
    # Output options
    parser.add_argument('--output', type=str, 
                        help='Output file name (e.g., results.json)')
    parser.add_argument('--format', type=str, default='json', 
                        choices=['json', 'csv', 'html'], help='Output format')
    parser.add_argument('--download', type=int, default=0, metavar='N', 
                        help='Download top N plugins (sorted by VPS score) to ./Plugins/')
    
    # Time filtering
    parser.add_argument('--min-days', type=int, default=0, 
                        help='Minimum days since last update')
    parser.add_argument('--max-days', type=int, default=0, 
                        help='Maximum days since last update')
    
    # Enhanced features
    parser.add_argument('--deep-analysis', action='store_true', 
                        help='Download and analyze plugin code (slower but more accurate)')
    parser.add_argument('--themes', action='store_true', 
                        help='Scan WordPress themes instead of plugins')
    parser.add_argument('--ajax-scan', action='store_true', 
                        help='Focus on plugins with AJAX functionality')
    parser.add_argument('--dangerous-functions', action='store_true', 
                        help='Look for plugins using dangerous PHP functions')
    parser.add_argument('--user-facing', action='store_true', 
                        help='Focus on plugins that interact directly with end-users (high risk)')
    parser.add_argument('--auto-download-risky', type=int, default=0, metavar='N', 
                        help='Auto-download top N riskiest plugins for analysis')
    parser.add_argument('--aggressive', action='store_true',
                        help='AGGRESSIVE MODE: Scan everything, no limits, high concurrency.')
    
    # GUI mode
    parser.add_argument('--gui', action='store_true',
                        help='Launch web dashboard on localhost:8080')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port for web dashboard (default: 8080)')
    
    # Database sync options
    parser.add_argument('--sync-db', action='store_true',
                        help='Sync plugin metadata from WordPress.org API to local SQLite database')
    parser.add_argument('--sync-pages', type=int, default=100,
                        help='Number of pages to sync (100 plugins per page, default: 100)')
    parser.add_argument('--sync-workers', type=int, default=10,
                        help='Number of parallel workers for sync (default: 10)')
    parser.add_argument('--sync-type', type=str, default='updated',
                        choices=['updated', 'new', 'popular'],
                        help='Browse type for sync (default: updated)')
    parser.add_argument('--sync-all', action='store_true',
                        help='Sync entire WordPress plugin catalog (~60k plugins, uses all browse types)')
    parser.add_argument('--incremental', action='store_true',
                        help='Only sync plugins updated since last sync')
    
    # Database query options
    parser.add_argument('--query-db', action='store_true',
                        help='Query plugins from local database instead of API')
    parser.add_argument('--db-stats', action='store_true',
                        help='Show database statistics')
    parser.add_argument('--search', type=str, default=None,
                        help='Search term for database query')
    parser.add_argument('--tags', type=str, default=None,
                        help='Comma-separated tags to filter (e.g., "form,payment")')
    parser.add_argument('--min-rating', type=int, default=0,
                        help='Minimum plugin rating (0-100)')
    parser.add_argument('--requires-php', type=str, default=None,
                        help='Filter by PHP version requirement (e.g., "7.4")')
    parser.add_argument('--tested-wp', type=str, default=None,
                        help='Filter by tested WordPress version (e.g., "6.0")')
    parser.add_argument('--author', type=str, default=None,
                        help='Filter by author name')
    parser.add_argument('--sort-by', type=str, default='active_installs',
                        choices=['active_installs', 'rating', 'last_updated', 'downloaded'],
                        help='Sort results by field (default: active_installs)')
    parser.add_argument('--sort-order', type=str, default='desc',
                        choices=['asc', 'desc'],
                        help='Sort order (default: desc)')
    
    # Export options
    parser.add_argument('--export', type=str, default=None, metavar='FILE',
                        help='Export query results to file (CSV or JSON based on extension)')
    
    # SVN download options
    parser.add_argument('--svn-download', type=int, default=0, metavar='N',
                        help='Download top N plugins from database via SVN')
    parser.add_argument('--svn-workers', type=int, default=5,
                        help='Number of parallel SVN download workers (default: 5)')
    parser.add_argument('--svn-output', type=str, default='./Plugins_SVN',
                        help='Output directory for SVN downloads (default: ./Plugins_SVN)')
    
    # Semgrep integration
    parser.add_argument('--semgrep-scan', action='store_true',
                        help='Run Semgrep scan on downloaded plugins')
    parser.add_argument('--semgrep-rules', type=str, default=None,
                        help='Path to custom Semgrep rules (default: built-in PHP security rules)')
    parser.add_argument('--semgrep-output', type=str, default='./semgrep_results',
                        help='Output directory for Semgrep results (default: ./semgrep_results)')
    
    return parser.parse_args()


def args_to_config(args: argparse.Namespace) -> ScanConfig:
    """Convert argparse namespace to ScanConfig."""
    return ScanConfig(
        pages=args.pages,
        limit=args.limit,
        min_installs=args.min,
        max_installs=args.max,
        sort=args.sort,
        smart=args.smart,
        abandoned=args.abandoned,
        user_facing=args.user_facing,
        themes=args.themes,
        min_days=args.min_days,
        max_days=args.max_days,
        deep_analysis=args.deep_analysis,
        ajax_scan=args.ajax_scan,
        dangerous_functions=args.dangerous_functions,
        output=args.output,
        format=args.format,
        download=args.download,
        auto_download_risky=args.auto_download_risky,
        aggressive=args.aggressive,
    )


def run_theme_scan(args: argparse.Namespace) -> None:
    """Run theme scanning mode."""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}=== WordPress Theme Scanner ==={Colors.RESET}")
    print(f"Scanning {args.pages} pages of themes...\n")
    
    found_count = [0]
    
    def on_result(result: Dict[str, Any]):
        found_count[0] += 1
        display_theme_console(found_count[0], result)
    
    scanner = ThemeScanner(
        pages=args.pages,
        limit=args.limit,
        on_result=on_result
    )
    
    scanner.scan()
    
    print(f"{Colors.GREEN}[✓] Theme scan complete: {found_count[0]} themes analyzed{Colors.RESET}")


def run_plugin_scan(args: argparse.Namespace) -> None:
    """Run plugin scanning mode."""
    config = args_to_config(args)
    
    # Override defaults for Abandoned Mode to be effective
    if args.abandoned:
        if config.sort == 'updated':
            config.sort = 'popular'
            print(f"{Colors.YELLOW}[!] Mode switched to POPULAR to find abandoned plugins effectively.{Colors.RESET}")
        
        if args.pages == 5:  # If user didn't change default
            config.pages = 100
            print(f"{Colors.YELLOW}[!] Increased page scan limit to 100 to dig deeper for abandoned plugins.{Colors.RESET}")
    
    # Increase scan depth for date filtering
    # Increased page scan limit to 50 to find plugins older than {args.min_days} days.{Colors.RESET}")

    # Aggressive Mode Overrides
    if config.aggressive:
        print(f"{Colors.BOLD}{Colors.RED}[!!!] AGGRESSIVE MODE ENABLED [!!!]{Colors.RESET}")
        
        # Override limits if they are at defaults
        if args.pages == 5:
            config.pages = 200
            print(f"{Colors.RED}[!] Pages increased to 200{Colors.RESET}")
        
        # In Aggressive Mode, we focus on High Value Targets (High Score OR High Popularity)
        config.min_score = 40  # Only show HIGH risk items
        print(f"{Colors.RED}[!] Filtering for High Risk (Score > 40){Colors.RESET}")
            
        config.limit = 0
        print(f"{Colors.RED}[!] Result limit removed{Colors.RESET}")
        
        # We keep min_installs default (1000) or user value to avoid junk
        if args.min == 1000:
             print(f"{Colors.RED}[!] Min installs kept at 1000 to filter low-quality plugins{Colors.RESET}")
        
        if config.smart:
            config.smart = False
            print(f"{Colors.RED}[!] Smart filter DISABLED (scanning all categories){Colors.RESET}")
            
    print(f"\n{Colors.BOLD}{Colors.WHITE}=== WP Hunter ==={Colors.RESET}")
    range_str = f"{config.min_installs}-{config.max_installs}" if config.max_installs > 0 else f"{config.min_installs}+"
    print(f"Mode: {config.sort.upper()} | Range: {range_str} installs")
    
    limit_msg = f"{config.limit} items" if config.limit > 0 else "Unlimited"
    print(f"Target Limit: {Colors.YELLOW}{limit_msg}{Colors.RESET}")

    # Mode indicators
    if config.smart: 
        print(f"{Colors.RED}[!] Smart Filter: ON{Colors.RESET}")
    if config.abandoned: 
        print(f"{Colors.RED}[!] Abandoned Filter: ON (>730 days){Colors.RESET}")
    if config.deep_analysis: 
        print(f"{Colors.CYAN}[!] Deep Code Analysis: ON (slower but more accurate){Colors.RESET}")
    if config.ajax_scan: 
        print(f"{Colors.YELLOW}[!] AJAX Focus: ON{Colors.RESET}")
    if config.user_facing: 
        print(f"{Colors.MAGENTA}[!] User-Facing Plugin Filter: ON{Colors.RESET}")
    if config.dangerous_functions: 
        print(f"{Colors.RED}[!] Dangerous Functions Detection: ON{Colors.RESET}")
    
    if config.min_days > 0 or config.max_days > 0:
        d_min = config.min_days
        d_max = config.max_days if config.max_days > 0 else "∞"
        print(f"{Colors.RED}[!] Update Age Filter: {d_min} to {d_max} days{Colors.RESET}")

    print("=" * 70)

    # Set up scanner with callbacks
    found_count = [0]
    collected_results: List[PluginResult] = []
    
    def on_result(result: PluginResult):
        found_count[0] += 1
        display_plugin_console(found_count[0], result)
        collected_results.append(result)
    
    # Create scanner
    scanner = PluginScanner(config, on_result=on_result)
    
    # Set up downloader for deep analysis
    if config.deep_analysis:
        downloader = PluginDownloader()
        scanner.set_downloader(downloader)
    
    # Run scan
    scanner.scan()
    
    # Save results
    if config.output and collected_results:
        results_dicts = [r.to_dict() for r in collected_results]
        save_results(results_dicts, config.output, config.format)

    # Download top plugins if requested
    if config.download > 0 and collected_results:
        downloader = PluginDownloader()
        results_dicts = [r.to_dict() for r in collected_results]
        downloader.download_top_plugins(results_dicts, config.download)
    
    # Auto-download riskiest plugins
    if config.auto_download_risky > 0 and collected_results:
        print(f"\n{Colors.BOLD}{Colors.RED}=== Auto-Downloading Riskiest Plugins ==={Colors.RESET}")
        sorted_results = sorted(collected_results, key=lambda x: x.score, reverse=True)
        downloader = PluginDownloader()
        results_dicts = [r.to_dict() for r in sorted_results[:config.auto_download_risky]]
        downloader.download_top_plugins(results_dicts, config.auto_download_risky)

    print(f"\n{Colors.GREEN}[✓] Scan completed. Total {found_count[0]} targets analyzed.{Colors.RESET}")
    
    # Print summary
    if collected_results:
        summary = scanner.get_summary()
        print_summary(summary)


def run_db_sync(args: argparse.Namespace) -> None:
    """Sync plugin metadata from WordPress.org API to local database."""
    from wp_hunter.syncers.plugin_syncer import PluginSyncer, SyncConfig
    from wp_hunter.database.plugin_metadata import PluginMetadataRepository
    
    # Check for incremental sync
    if args.incremental:
        repo = PluginMetadataRepository()
        last_sync = repo.get_last_sync_time()
        if last_sync:
            print(f"{Colors.CYAN}[*] Incremental sync mode - last sync: {last_sync}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] No previous sync found. Running full sync.{Colors.RESET}")
    
    # Sync-all mode: sync all browse types for full coverage
    if args.sync_all:
        print(f"\n{Colors.BOLD}{Colors.CYAN}=== FULL CATALOG SYNC MODE ==={Colors.RESET}")
        print(f"  This will sync approximately 60,000+ plugins from WordPress.org")
        print(f"  Estimated time: 30-60 minutes depending on connection\n")
        
        browse_types = ['updated', 'popular', 'new']
        total_synced = 0
        
        for browse_type in browse_types:
            print(f"\n{Colors.BOLD}[*] Syncing '{browse_type}' browse type...{Colors.RESET}")
            
            sync_config = SyncConfig(
                pages=args.sync_pages or 600,  # 600 pages = ~60k plugins
                browse_type=browse_type,
                workers=args.sync_workers
            )
            
            syncer = PluginSyncer(config=sync_config)
            progress = syncer.sync(verbose=True)
            total_synced += progress.plugins_synced
            
            if progress.error:
                print(f"{Colors.RED}[!] Error syncing {browse_type}: {progress.error}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}[✓] Full catalog sync complete! Total synced: {total_synced:,} plugins{Colors.RESET}")
        return
    
    # Regular sync
    sync_config = SyncConfig(
        pages=args.sync_pages,
        browse_type=args.sync_type,
        workers=args.sync_workers
    )
    
    syncer = PluginSyncer(config=sync_config)
    progress = syncer.sync(verbose=True)
    
    if progress.error:
        print(f"{Colors.RED}[!] Sync failed: {progress.error}{Colors.RESET}")


def run_db_stats(args: argparse.Namespace) -> None:
    """Show database statistics."""
    from wp_hunter.database.plugin_metadata import PluginMetadataRepository
    
    repo = PluginMetadataRepository()
    stats = repo.get_stats()
    
    print(f"\n{Colors.CYAN}{'='*50}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 Database Statistics{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
    print(f"  📦 Total records: {stats['total_records']:,}")
    print(f"  🔌 Unique plugins: {stats['unique_plugins']:,}")
    print(f"  ⭐ Popular (10k+): {stats['popular_10k']:,}")
    print(f"  🌟 Very Popular (100k+): {stats['popular_100k']:,}")
    print(f"  🕐 Last sync: {stats['last_sync'] or 'Never'}")
    print(f"{Colors.CYAN}{'='*50}{Colors.RESET}\n")


def run_db_query(args: argparse.Namespace) -> None:
    """Query plugins from local database with advanced filters."""
    from wp_hunter.database.plugin_metadata import PluginMetadataRepository
    from wp_hunter.downloaders.svn_downloader import SVNDownloader
    import json
    import csv
    from pathlib import Path
    
    repo = PluginMetadataRepository()
    
    # Parse tags if provided
    tags = args.tags.split(',') if args.tags else None
    
    plugins = repo.query_plugins(
        min_installs=args.min,
        max_installs=args.max if args.max > 0 else 0,
        min_rating=getattr(args, 'min_rating', 0),
        tags=tags,
        search=args.search,
        author=getattr(args, 'author', None),
        requires_php=getattr(args, 'requires_php', None),
        tested_wp=getattr(args, 'tested_wp', None),
        sort_by=getattr(args, 'sort_by', 'active_installs'),
        sort_order=getattr(args, 'sort_order', 'desc'),
        limit=args.limit if args.limit > 0 else 100
    )
    
    if not plugins:
        print(f"{Colors.YELLOW}[!] No plugins found matching your criteria.{Colors.RESET}")
        print(f"{Colors.GRAY}    Try running --sync-db first to populate the database.{Colors.RESET}")
        return
    
    # Export to file if requested
    export_path = getattr(args, 'export', None)
    if export_path:
        export_file = Path(export_path)
        export_data = [{
            'slug': p.get('slug'),
            'name': p.get('name'),
            'version': p.get('version'),
            'active_installs': p.get('active_installs'),
            'rating': p.get('rating'),
            'last_updated': p.get('last_updated'),
            'author': p.get('author'),
            'requires_php': p.get('requires_php'),
            'tested': p.get('tested'),
            'download_link': p.get('download_link')
        } for p in plugins]
        
        if export_file.suffix.lower() == '.json':
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2)
        else:  # Default to CSV
            if not export_file.suffix:
                export_file = export_file.with_suffix('.csv')
            with open(export_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=export_data[0].keys() if export_data else [])
                writer.writeheader()
                writer.writerows(export_data)
        
        print(f"{Colors.GREEN}[✓] Exported {len(plugins)} plugins to {export_file}{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}📦 Found {len(plugins)} plugins in database{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*80}{Colors.RESET}\n")
    
    # Display results in table format
    print(f"{'#':<4} {'Slug':<35} {'Installs':<12} {'Rating':<8} {'Updated':<12}")
    print("-" * 80)
    
    for i, plugin in enumerate(plugins, 1):
        slug = plugin.get('slug', '')[:34]
        installs = plugin.get('active_installs', 0)
        rating = plugin.get('rating', 0)
        updated = plugin.get('last_updated', '')[:10]
        
        # Color based on installs
        if installs >= 100000:
            color = Colors.GREEN
        elif installs >= 10000:
            color = Colors.YELLOW
        else:
            color = Colors.WHITE
        
        print(f"{i:<4} {color}{slug:<35}{Colors.RESET} {installs:<12,} {rating:<8} {updated:<12}")
    
    print(f"\n{Colors.GRAY}Use --svn-download N to download top N plugins{Colors.RESET}")
    
    # SVN download if requested
    downloaded_dirs = []
    if args.svn_download > 0:
        print(f"\n{Colors.BOLD}Starting SVN download...{Colors.RESET}")
        slugs = [p['slug'] for p in plugins[:args.svn_download]]
        
        downloader = SVNDownloader(
            output_dir=args.svn_output,
            workers=args.svn_workers
        )
        results = downloader.download_many(slugs, verbose=True)
        
        # Collect downloaded directories for Semgrep scan
        for result in results:
            if result.success:
                plugin_dir = Path(args.svn_output) / result.slug
                if plugin_dir.exists():
                    downloaded_dirs.append(str(plugin_dir))
    
    # Semgrep scan if requested
    if getattr(args, 'semgrep_scan', False) and downloaded_dirs:
        print(f"\n{Colors.BOLD}Starting Semgrep security scan...{Colors.RESET}")
        
        try:
            from wp_hunter.scanners.semgrep_scanner import SemgrepScanner
            
            scanner = SemgrepScanner(
                rules_path=getattr(args, 'semgrep_rules', None),
                output_dir=getattr(args, 'semgrep_output', './semgrep_results'),
                workers=3
            )
            scanner.scan_plugins(downloaded_dirs, verbose=True)
            
        except ImportError:
            print(f"{Colors.YELLOW}[!] Semgrep scanner module not loaded.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Semgrep scan error: {e}{Colors.RESET}")


def run_gui(port: int = 8080) -> None:
    """Start the web dashboard."""
    try:
        from wp_hunter.server.app import create_app
        import uvicorn
    except ImportError:
        print(f"{Colors.RED}[!] GUI mode requires additional dependencies.{Colors.RESET}")
        print(f"{Colors.YELLOW}Please install: pip install fastapi uvicorn websockets{Colors.RESET}")
        return
    
    print(f"{Colors.BOLD}{Colors.CYAN}=== WP-Hunter Dashboard ==={Colors.RESET}")
    print(f"Starting web server on http://localhost:{port}")
    print(f"{Colors.GRAY}Press Ctrl+C to stop{Colors.RESET}\n")
    
    # Open browser after a short delay
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open(f"http://localhost:{port}")
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run server
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")


def main() -> None:
    """Main entry point."""
    print_banner()
    args = get_args()
    
    try:
        # GUI mode
        if args.gui:
            run_gui(args.port)
            return
        
        # Database sync mode
        if args.sync_db:
            run_db_sync(args)
            return
        
        # Database stats
        if args.db_stats:
            run_db_stats(args)
            return
        
        # Database query mode
        if args.query_db:
            run_db_query(args)
            return
        
        # Theme scanning mode
        if args.themes:
            run_theme_scan(args)
            return
        
        # Plugin scanning mode (default)
        run_plugin_scan(args)
        
    finally:
        close_session()


if __name__ == "__main__":
    main()
