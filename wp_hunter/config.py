"""
WP-Hunter Configuration and Constants

All global constants, tag sets, and color definitions.
"""

from typing import Set

# --- VERSION & LIMITS ---
CURRENT_WP_VERSION = 6.7
MAX_WORKERS = 5
DEFAULT_SERVER_PORT = 8080

# --- SECURITY LIMITS ---
# Maximum connection pool size to prevent DoS via resource exhaustion
MAX_POOL_SIZE = 50
# Maximum threads for aggressive scanning mode
MAX_SCAN_THREADS_AGGRESSIVE = 50
MAX_SCAN_THREADS_NORMAL = 5
# Request timeout in seconds
DEFAULT_REQUEST_TIMEOUT = 30
# Maximum pages for sync operations
MAX_SYNC_PAGES = 1000

# --- RISKY TAG SETS ---
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

# --- CODE ANALYSIS PATTERNS ---
DANGEROUS_FUNCTIONS: Set[str] = {
    'eval', 'exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open',
    'pcntl_exec', 'assert', 'create_function', 'unserialize', 'file_get_contents',
    'file_put_contents', 'fopen', 'readfile', 'include', 'require',
    'include_once', 'require_once', 'call_user_func', 'call_user_func_array'
}

AJAX_PATTERNS: Set[str] = {
    'wp_ajax_', 'admin-ajax.php', 'wp_ajax_nopriv_', 'ajaxurl', 'ajax_action',
    'wp_localize_script', 'wp_enqueue_script', 'jQuery.post', '$.post', '$.ajax',
    'XMLHttpRequest', 'fetch(', 'wp.ajax'
}

THEME_PATTERNS: Set[str] = {
    'wp_head', 'wp_footer', 'get_header', 'get_footer', 'get_sidebar',
    'wp_enqueue_style', 'wp_enqueue_script', 'add_theme_support',
    'register_nav_menus', 'wp_nav_menu', 'dynamic_sidebar'
}


class Colors:
    """ANSI color codes for terminal output."""
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
