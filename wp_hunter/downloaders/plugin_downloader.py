"""
WP-Hunter Plugin Downloader

Download and extract plugins for analysis.
"""

import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import os
import zipfile
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any

from wp_hunter.config import Colors
from wp_hunter.scanners.plugin_scanner import get_session


class PluginDownloader:
    """Plugin downloader and extractor."""
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir)
        self.plugins_dir = self.base_dir / "Plugins"
        self.plugins_dir.mkdir(exist_ok=True)
    
    
    def _validate_url(self, url: str) -> None:
        """
        Validate URL to prevent SSRF attacks.

        Blocks:
        - Non-HTTP(S) schemes
        - Loopback addresses (127.0.0.0/8, ::1)
        - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        - Link-local addresses (169.254.0.0/16, fe80::/10)
        - Cloud metadata endpoints (169.254.169.254)
        - IPv6 localhost
        """
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Invalid URL scheme: {parsed.scheme}")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid URL: Missing hostname")

        # Block common cloud metadata hostnames
        blocked_hostnames = {
            'metadata.google.internal',
            'metadata.goog',
            '169.254.169.254',
            'instance-data',
            'metadata',
        }
        if hostname.lower() in blocked_hostnames:
            raise ValueError(f"SSRF Protection: Access to cloud metadata endpoint is blocked")

        try:
            # Resolve IP to check against internal ranges
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)

            # Comprehensive SSRF protection checks
            if ip_obj.is_loopback:
                raise ValueError(f"SSRF Protection: Access to loopback address {ip_str} is blocked")

            if ip_obj.is_private:
                raise ValueError(f"SSRF Protection: Access to private IP {ip_str} is blocked")

            if ip_obj.is_link_local:
                raise ValueError(f"SSRF Protection: Access to link-local address {ip_str} is blocked")

            if ip_obj.is_reserved:
                raise ValueError(f"SSRF Protection: Access to reserved IP {ip_str} is blocked")

            if ip_obj.is_multicast:
                raise ValueError(f"SSRF Protection: Access to multicast address {ip_str} is blocked")

            # Cloud metadata IP check (AWS, GCP, Azure)
            if str(ip_obj) == "169.254.169.254":
                raise ValueError("SSRF Protection: Access to cloud metadata endpoint is blocked")

            # IPv6 localhost check
            if str(ip_obj) == "::1":
                raise ValueError("SSRF Protection: Access to IPv6 localhost is blocked")

        except socket.gaierror:
            raise ValueError(f"Could not resolve hostname: {hostname}")

    def download_and_extract(
        self, 
        download_url: str, 
        slug: str,
        verbose: bool = True
    ) -> Optional[Path]:
        """Download and extract a plugin, returning the path to extracted files."""
        session = get_session()
        
        plugin_dir = self.plugins_dir / slug
        zip_path = plugin_dir / f"{slug}.zip"
        extract_path = plugin_dir / "source"
        
        try:
            plugin_dir.mkdir(exist_ok=True)
            
            # Download
            if verbose:
                print(f"{Colors.CYAN}[⬇] Downloading {slug}...{Colors.RESET}")

            # Follow redirects manually with validation
            current_url = download_url
            response = None

            for _ in range(5):  # Max 5 redirects
                self._validate_url(current_url)

                response = session.get(current_url, stream=True, timeout=60, allow_redirects=False)

                if response.is_redirect:
                    location = response.headers['Location']
                    # Handle relative redirects
                    if not urlparse(location).netloc:
                        current_url = urljoin(current_url, location)
                    else:
                        current_url = location
                    continue
                else:
                    break
            else:
                raise ValueError("Too many redirects")

            response.raise_for_status()

            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract
            if verbose:
                print(f"{Colors.CYAN}[📦] Extracting {slug}...{Colors.RESET}")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Zip Slip mitigation
                for member in zip_ref.infolist():
                    member_path = os.path.join(str(extract_path), member.filename)
                    if not os.path.abspath(member_path).startswith(os.path.abspath(str(extract_path))):
                        raise Exception(f'Zip Slip attempt detected: {member.filename}')
                    zip_ref.extract(member, extract_path)
            
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
            
            if verbose:
                file_count = sum(1 for _ in extract_path.rglob('*') if _.is_file())
                print(f"{Colors.GREEN}[✓] Extracted {slug}: {file_count} files{Colors.RESET}")
            
            return extract_path
            
        except zipfile.BadZipFile:
            if verbose:
                print(f"{Colors.RED}[!] Invalid ZIP file for {slug}{Colors.RESET}")
            if zip_path.exists():
                zip_path.unlink()
            return None
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[!] Failed to download {slug}: {e}{Colors.RESET}")
            if plugin_dir.exists():
                shutil.rmtree(plugin_dir, ignore_errors=True)
            return None
    
    def download_top_plugins(
        self, 
        results: List[Dict[str, Any]], 
        download_limit: int,
        verbose: bool = True
    ) -> int:
        """Downloads and extracts top N plugins sorted by VPS score."""
        if not results:
            if verbose:
                print(f"{Colors.YELLOW}[!] No results to download.{Colors.RESET}")
            return 0
        
        # Sort by score (highest first)
        sorted_results = sorted(results, key=lambda x: x.get('score', 0), reverse=True)
        plugins_to_download = sorted_results[:download_limit]
        
        if verbose:
            print(f"\n{Colors.BOLD}{Colors.CYAN}=== Downloading Top {len(plugins_to_download)} High-Score Plugins ==={Colors.RESET}")
            print(f"Download directory: {self.plugins_dir.absolute()}\n")
        
        downloaded_count = 0
        for idx, plugin in enumerate(plugins_to_download, 1):
            slug = plugin.get('slug', 'unknown')
            version = plugin.get('version', 'latest')
            score = plugin.get('score', 0)
            download_url = plugin.get('download_link')
            
            if not download_url:
                if verbose:
                    print(f"{Colors.YELLOW}[{idx}] Skipping {slug} - No download link available{Colors.RESET}")
                continue
            
            if verbose:
                print(f"{Colors.CYAN}[{idx}] Downloading: {slug} (v{version}) - VPS Score: {score}{Colors.RESET}")
            
            result = self.download_and_extract(download_url, slug, verbose=False)
            if result:
                downloaded_count += 1
                if verbose:
                    file_count = sum(1 for _ in result.rglob('*') if _.is_file())
                    print(f"{Colors.GREEN}    ✓ Downloaded and extracted: {file_count} files{Colors.RESET}")
        
        if verbose:
            print(f"\n{Colors.GREEN}[✓] Download complete: {downloaded_count}/{len(plugins_to_download)} plugins{Colors.RESET}")
        
        return downloaded_count
    
    def get_downloaded_plugins(self) -> List[str]:
        """Get list of downloaded plugin slugs."""
        if not self.plugins_dir.exists():
            return []
        return [d.name for d in self.plugins_dir.iterdir() if d.is_dir()]
    
    def get_plugin_path(self, slug: str) -> Optional[Path]:
        """Get the source path for a downloaded plugin."""
        source_path = self.plugins_dir / slug / "source"
        if source_path.exists():
            return source_path
        return None
