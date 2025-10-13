
import threading
import time
from angelcore_spectralwatch import angelcore_decision
import random

from PyQt6.QtWidgets import QApplication, QWidget, QTextEdit, QVBoxLayout, QLabel
from PyQt6.QtCore import QTimer

class AngelChat(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("n’éccrit Chat – AngelCore aktiv")
        self.resize(400, 300)
        self.layout = QVBoxLayout()
        self.label = QLabel("AngelCore Status: Initialisiere...")
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Nachricht eingeben...")
        self.layout.addWidget(self.label)
        self.layout.addWidget(self.text_edit)
        self.setLayout(self.layout)
        self.status = "SAFE"
        self.start_angel_thread()

    def update_ui_state(self, status):
        if status == "ALERT":
            self.text_edit.setReadOnly(True)
            self.text_edit.setStyleSheet("background-color: black; color: black;")
            self.label.setText("⚠️ ANGELCORE: Visuelle Tarnung aktiviert!")
        elif status == "UNCERTAIN":
            self.text_edit.setReadOnly(True)
            self.text_edit.setStyleSheet("background-color: gray; color: white;")
            self.label.setText("⚠️ AngelCore: Eingeschränkter Modus.")
        else:
            self.text_edit.setReadOnly(False)
            self.text_edit.setStyleSheet("")
            self.label.setText("🛡️ AngelCore: Sicher")

    def simulate_inputs(self):
        cpu = random.randint(5, 80)
        ram = random.randint(30, 90)
        mouse = random.randint(0, 20)
        timing = [random.random() for _ in range(5)]
        mic = [random.uniform(-1.0, 1.0) for _ in range(32)]
        return cpu, ram, mouse, timing, mic

    def angel_loop(self):
        while True:
            cpu, ram, mouse, timing, mic = self.simulate_inputs()
            status = angelcore_decision(cpu, ram, mouse, timing, mic)
            self.status = status
            QTimer.singleShot(0, lambda: self.update_ui_state(status))
            time.sleep(5)

    def start_angel_thread(self):
        t = threading.Thread(target=self.angel_loop, daemon=True)
        t.start()

if __name__ == "__main__":
    app = QApplication([])
    win = AngelChat()
    win.show()
    app.exec()
