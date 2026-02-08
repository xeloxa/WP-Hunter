"""
WP-Hunter VPS Scorer

Vulnerability Probability Score calculation.
"""

from typing import Dict, Any, List, Optional

from wp_hunter.config import Colors, CURRENT_WP_VERSION
from wp_hunter.models import CodeAnalysisResult


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
    
    Scoring breakdown:
    - CODE ROT (Maintenance Latency): Max 40 pts
    - ATTACK SURFACE (Intrinsic Risk): Max 30 pts
    - DEVELOPER NEGLECT (Support Health): Max 15 pts
    - TECHNICAL DEBT (Compatibility): Max 15 pts
    - REPUTATION (Quality Signal): Max 10 pts
    - CODE ANALYSIS BONUS: Max 25 pts
    """
    score = 0
    
    # 1. CODE ROT (Maintenance Latency) - Max 40 pts
    if days_ago > 730: 
        score += 40      # Abandoned (> 2 years) - Critical Risk
    elif days_ago > 365: 
        score += 25    # Neglected (> 1 year)
    elif days_ago > 180: 
        score += 15    # Stale (> 6 months)
    
    # 2. ATTACK SURFACE (Intrinsic Risk) - Max 30 pts
    if matched_tags: 
        surface_score = min(30, len(matched_tags) * 3)
        score += surface_score

    # 3. DEVELOPER NEGLECT (Support Health) - Max 15 pts
    if support_rate < 20: 
        score += 15
    elif support_rate < 50: 
        score += 10
    
    # 4. TECHNICAL DEBT (Compatibility) - Max 15 pts
    try:
        if float(tested_ver) < CURRENT_WP_VERSION - 0.5: 
            score += 15
    except (ValueError, TypeError): 
        score += 10  # Unknown compatibility is risky
        
    # 5. REPUTATION (Quality Signal) - Max 10 pts
    rating = plugin.get('rating', 0) / 20  # Convert 100 scale to 5
    if rating < 3.5: 
        score += 10
    
    # 6. CODE ANALYSIS BONUS - Max 25 pts
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
    user_input_tags = {'form', 'contact', 'input', 'chat', 'comment', 'review', 'upload', 'profile'}
    if any(tag in matched_tags for tag in user_input_tags):
        score += 5
    
    # BONUS: Active Maintenance Reward
    if days_ago < 14: 
        score = max(0, score - 5)
    
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


def get_score_class(score: int) -> str:
    """Get CSS class for score display in HTML."""
    if score >= 50:
        return "score-high"
    elif score >= 30:
        return "score-med"
    else:
        return "score-low"


def get_score_level(score: int) -> str:
    """Get text level for score."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"
