
import threading
import time
import random
from angelcore_spectralwatch import angelcore_decision

def simulate_inputs():
    cpu = random.randint(5, 80)
    ram = random.randint(30, 90)
    mouse = random.randint(0, 20)
    timing = [random.random() for _ in range(5)]
    mic = [random.uniform(-1.0, 1.0) for _ in range(32)]
    return cpu, ram, mouse, timing, mic

def angel_loop():
    print("👼 AngelCore Monitor läuft... Drücke STRG+C zum Beenden.")
    try:
        while True:
            cpu, ram, mouse, timing, mic = simulate_inputs()
            result = angelcore_decision(cpu, ram, mouse, timing, mic)
            print(f"[AngelCore] CPU={cpu}%, RAM={ram}%, MOUSE={mouse} ... STATUS: {result}")
            if result == "ALERT":
                print("⚠️  SYSTEMWARNUNG: VISUELLE TARNUNG EMPFOHLEN")
            time.sleep(5)
    except KeyboardInterrupt:
        print("👼 AngelCore beendet.")

if __name__ == "__main__":
    angel_loop()
