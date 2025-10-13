"""
Configuration file for n'éccrit optional addons.

This file contains configuration flags for optional features like
cover traffic generation, HTTP mimicry, and steganography.

⚠️ SECURITY NOTE:
- Cover traffic generation can help obfuscate communication patterns
- Zero-width steganography is DISABLED by default for responsible use
- All cover traffic is still encrypted through the standard crypto layer
"""

# Cover Traffic Configuration
# ---------------------------
# Enable periodic cover traffic to obfuscate communication patterns
ENABLE_COVER_TRAFFIC = True

# Minimum interval between cover traffic packets (seconds)
COVER_MIN_INTERVAL_S = 20

# Maximum interval between cover traffic packets (seconds)
COVER_MAX_INTERVAL_S = 45

# HTTP Mimicry
# ------------
# Format cover traffic as HTTP-like requests for better camouflage
ENABLE_HTTP_MIMICRY = True

# Zero-Width Steganography
# ------------------------
# ⚠️ DISABLED BY DEFAULT - Use responsibly for legitimate research only
# This feature embeds data in zero-width unicode characters
ENABLE_ZW_STEGANO = False
