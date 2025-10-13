"""
Oscillator Core Modul
--------------------
Wandelt Eingangsdaten in ein Spektralprofil um (Fourier-Analyse).
Autor: SPCM-Prototyp | 2025
TODO:
- Wavelet-Analyse ergänzen
- Tests für verschiedene Signaltypen (Text, Zahlen, Audio)
Beispielaufruf:
    oc = OscillatorCore([1, 2, 3, 4])
    profile = oc.spectral_profile([0, 1, 0, -1])
    print(profile)
"""
import numpy as np
class OscillatorCore:
    """
    Wandelt Eingangsdaten in spektrale Profile um.
    Nutzt Fourier-Transformation für Kontextresonanz.
    """
    def __init__(self, base_frequencies):
        """
        base_frequencies: Liste von Frequenzwerten (float oder int), die als Basisspektrum genutzt werden.
        """
        self.base_frequencies = base_frequencies
    def spectral_profile(self, input_signal):
        """
        Berechnet das Frequenzspektrum des Eingangssignals.
        input_signal: Liste oder numpy-Array mit numerischen Werten.
        Rückgabe: Betragsspektrum (nur positive Frequenzen).
        """
        signal = np.array(input_signal)
        spectrum = np.fft.fft(signal)
        half = len(spectrum) // 2
        spectral_power = np.abs(spectrum[:half])
        return spectral_power
if __name__ == "__main__":
    print("OscillatorCore Test:")
    oc = OscillatorCore([1, 2, 3, 4])
    test_signal = [0, 1, 0, -1]
    result = oc.spectral_profile(test_signal)
    print("Spektralprofil:", result)
