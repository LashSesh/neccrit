
import random
import time
import math

def dtt_tripolar_entropy(cpu_load, ram_idle, mouse_activity):
    # Dynamische tripolare Bewertung (1 = ok, 0 = unklar, -1 = verdächtig)
    score = 0
    if cpu_load < 20 and ram_idle > 70:
        score -= 1
    if mouse_activity < 5:
        score -= 1
    if 20 <= cpu_load <= 60 and mouse_activity > 10:
        score += 1
    return max(-1, min(1, score))

def trm_resonance_score(timing_deltas):
    # Tripolarer Resonanzwert basierend auf Zeitintervallen (Mensch vs. Bot)
    if len(timing_deltas) < 3:
        return 0
    avg = sum(timing_deltas) / len(timing_deltas)
    var = sum((x - avg)**2 for x in timing_deltas) / len(timing_deltas)
    return -1 if var < 0.01 else (1 if var > 0.3 else 0)

def erm_mic_noise_floor(mic_signal):
    # Mikroskopischer Entropie-Check im Audiospektrum
    spectrum = [abs(math.sin(x)) for x in mic_signal]
    entropy = sum(spectrum) / len(spectrum)
    return 1 if entropy > 0.4 else (-1 if entropy < 0.1 else 0)

def angelcore_decision(cpu, ram, mouse, timing, mic):
    dtt = dtt_tripolar_entropy(cpu, ram, mouse)
    trm = trm_resonance_score(timing)
    erm = erm_mic_noise_floor(mic)
    total = dtt + trm + erm
    if total <= -2:
        return "ALERT"
    elif total >= 2:
        return "SAFE"
    else:
        return "UNCERTAIN"
