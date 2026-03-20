import re
import math


# ── Strength tier definitions ──────────────────────────────────────────────────

STRENGTH_TIERS = [
    {"label": "CRITICAL",  "color": "#ff3355"},
    {"label": "WEAK",      "color": "#ff3355"},
    {"label": "MODERATE",  "color": "#ffaa00"},
    {"label": "STRONG",    "color": "#00d4ff"},
    {"label": "FORTIFIED", "color": "#00ff88"},
]

# Time constants (in seconds)
MINUTE = 60
HOUR   = 3_600
DAY    = 86_400
YEAR   = 31_536_000

# Assumed attack speed: 100 billion hashes per second (fast GPU rig)
HASHES_PER_SECOND = 1e11


# ── Check functions ────────────────────────────────────────────────────────────

def has_uppercase(password: str) -> bool:
    """Returns True if password contains at least one uppercase letter."""
    return bool(re.search(r'[A-Z]', password))


def has_lowercase(password: str) -> bool:
    """Returns True if password contains at least one lowercase letter."""
    return bool(re.search(r'[a-z]', password))


def has_digit(password: str) -> bool:
    """Returns True if password contains at least one numeric digit."""
    return bool(re.search(r'[0-9]', password))


def has_symbol(password: str) -> bool:
    """Returns True if password contains at least one special character."""
    return bool(re.search(r'[^a-zA-Z0-9]', password))


def is_long_enough(password: str, min_length: int = 12) -> bool:
    """Returns True if password meets the minimum length requirement."""
    return len(password) >= min_length


def has_no_repeats(password: str) -> bool:
    """Returns True if password has no 3+ consecutive repeating characters."""
    return not bool(re.search(r'(.).*\1.*\1', password))


# ── Entropy calculation ────────────────────────────────────────────────────────

def calculate_charset_size(password: str) -> int:
    """Calculate the number of possible characters in the password."""
    charset_size = 0
    if has_lowercase(password):  charset_size += 26
    if has_uppercase(password):  charset_size += 26
    if has_digit(password):      charset_size += 10
    if has_symbol(password):     charset_size += 32
    return charset_size


def calculate_entropy(password: str) -> int:
    """Calculate Shannon entropy for the password in bits."""
    charset_size = calculate_charset_size(password)
    if charset_size == 0:
        return 0
    return round(len(password) * math.log2(charset_size))


# ── Crack time estimation ──────────────────────────────────────────────────────

def estimate_crack_time(entropy_bits: int) -> str:
    """Estimate time to crack password at 100B hashes/sec."""
    if entropy_bits == 0:
        return "INSTANT"
    
    total_combinations = 2 ** entropy_bits
    avg_seconds_to_crack = total_combinations / (2 * HASHES_PER_SECOND)

    if avg_seconds_to_crack < 1:
        return "INSTANT"
    if avg_seconds_to_crack < MINUTE:
        return str(round(avg_seconds_to_crack)) + " seconds"
    if avg_seconds_to_crack < HOUR:
        return str(round(avg_seconds_to_crack / MINUTE)) + " minutes"
    if avg_seconds_to_crack < DAY:
        return str(round(avg_seconds_to_crack / HOUR)) + " hours"
    if avg_seconds_to_crack < YEAR:
        return str(round(avg_seconds_to_crack / DAY)) + " days"
    if avg_seconds_to_crack < YEAR * 1e3:
        return str(round(avg_seconds_to_crack / YEAR)) + " years"
    if avg_seconds_to_crack < YEAR * 1e6:
        return str(round(avg_seconds_to_crack / (YEAR * 1e3))) + " thousand yrs"
    if avg_seconds_to_crack < YEAR * 1e9:
        return str(round(avg_seconds_to_crack / (YEAR * 1e6))) + " million yrs"
    return "EFFECTIVELY UNCRACKABLE"


# ── Charset description ────────────────────────────────────────────────────────

def describe_charset(password: str) -> str:
    """Describe the character set used in the password."""
    parts = []
    if has_lowercase(password):
        parts.append("a-z")
    if has_uppercase(password):
        parts.append("A-Z")
    if has_digit(password):
        parts.append("0-9")
    if has_symbol(password):
        parts.append("sym")
    return "+".join(parts) if parts else "--"


# ── Score calculation ──────────────────────────────────────────────────────────

def calculate_score(password: str) -> int:
    """Calculate strength score based on various criteria (0-7)."""
    score = 0
    if len(password) >= 6:
        score += 1
    if len(password) >= 10:
        score += 1
    if len(password) >= 14:
        score += 1
    if has_uppercase(password) and has_lowercase(password):
        score += 1
    if has_digit(password):
        score += 1
    if has_symbol(password):
        score += 1
    if has_no_repeats(password) and len(password) > 8:
        score += 1
    return score


def score_to_tier_index(score: int) -> int:
    """Convert score (0-7) to tier index (0-4)."""
    return min(int(score * 5 / 7), 4)


# ── Tips / recommendations ─────────────────────────────────────────────────────

def generate_tips(password: str) -> list:
    """Generate security recommendations based on password analysis."""
    tips = []
    
    if not is_long_enough(password):
        tips.append("Extend to 12+ characters for better coverage")
    if not has_uppercase(password):
        tips.append("Add uppercase letters to widen the charset")
    if not has_lowercase(password):
        tips.append("Mix in lowercase characters")
    if not has_digit(password):
        tips.append("Include at least one numeric digit")
    if not has_symbol(password):
        tips.append("Special chars (!@#$) multiply crack complexity")
    if not has_no_repeats(password):
        tips.append("Avoid 3+ repeating characters in a row")

    entropy = calculate_entropy(password)
    if len(password) >= 16 and entropy >= 60:
        tips.append("Excellent entropy — consider storing in a password manager")

    if not tips:
        tips.append("All criteria met. Password is cryptographically robust.")

    return tips


# ── Main function — called by app.py ──────────────────────────────────────────

def analyze_password(password: str) -> dict:
    """
    Runs all checks and returns a complete result dictionary.
    This is the only function imported by app.py.
    """
    if not password:
        return {"empty": True}

    entropy = calculate_entropy(password)
    score = calculate_score(password)
    tier_index = score_to_tier_index(score)
    tier = STRENGTH_TIERS[tier_index]

    return {
        "entropy": entropy,
        "charset": describe_charset(password),
        "length": len(password),
        "crack_time": estimate_crack_time(entropy),
        "score": score,
        "tier_index": tier_index,
        "tier_label": tier["label"],
        "tier_color": tier["color"],
        "checks": {
            "length": is_long_enough(password),
            "uppercase": has_uppercase(password),
            "lowercase": has_lowercase(password),
            "digit": has_digit(password),
            "symbol": has_symbol(password),
            "no_repeat": has_no_repeats(password),
        },
        "tips": generate_tips(password),
    }
