"""
tripolar_mask.py - Tripolare/N-Polare Maskierungsfunktionen für Privacy-Engine
"""
import numpy as np
def tripolar_mask(fragment, kappa, theta, seed, t=None):
    """Maskiert ein Fragment mit beliebig vielen Polen (n-Pol)."""
    fragment = np.array(fragment)
    if t is None:
        t = np.arange(len(fragment))
    mask = np.zeros_like(fragment, dtype=float)
    for i in range(len(kappa)):
        mask += kappa[i] * np.sin(seed * t + theta[i])
    return fragment + mask

def tripolar_unmask(masked_fragment, kappa, theta, seed, t=None):
    masked_fragment = np.array(masked_fragment)
    if t is None:
        t = np.arange(len(masked_fragment))
    mask = np.zeros_like(masked_fragment, dtype=float)
    for i in range(len(kappa)):
        mask += kappa[i] * np.sin(seed * t + theta[i])
    return masked_fragment - mask
