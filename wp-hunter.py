#!/usr/bin/env python3
"""
WP-Hunter: WordPress Plugin & Theme Security Scanner

A reconnaissance tool for identifying vulnerable WordPress plugins and themes.

Usage:
    python3 wp-hunter.py [options]         # CLI mode (default)
    python3 wp-hunter.py --gui             # Launch web dashboard

For full options, run: python3 wp-hunter.py --help
"""

from wp_hunter.cli import main

if __name__ == "__main__":
    main()
