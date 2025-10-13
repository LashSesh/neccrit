#!/usr/bin/env python3
"""
n'éccrit - Production Privacy Chat Application
A secure P2P chat system with tripolar masking, AES encryption, and surveillance detection.
"""

import sys
import threading
import time
import io
import json
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel, QGroupBox, QGridLayout,
    QMessageBox, QFileDialog, QTabWidget, QScrollArea, QStatusBar, QCheckBox
)
from PyQt6.QtCore import QTimer, pyqtSignal, QObject, Qt
from PyQt6.QtGui import QPixmap, QImage, QPalette, QColor

from spectralship_engine_duallayer import SpectralNode
from angelcore_spectralwatch import angelcore_decision
from qr_utils import generate_qr_img, decode_qr_from_imagefile
import random


class ChatSignals(QObject):
    """Qt signals for thread-safe GUI updates"""
    message_received = pyqtSignal(str, str)  # sender, message
    message_sent = pyqtSignal(str)  # message
    error_occurred = pyqtSignal(str)  # error message
    angel_status_changed = pyqtSignal(str)  # status (SAFE, UNCERTAIN, ALERT)
    connection_status_changed = pyqtSignal(str)  # status message


class NeccritMainWindow(QMainWindow):
    """Main application window for n'éccrit chat"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("n'éccrit - Secure Privacy Chat")
        self.setMinimumSize(900, 700)
        
        # Initialize variables
        self.node = None
        self.is_running = False
        self.signals = ChatSignals()
        self.angel_enabled = False
        self.angel_thread = None
        
        # Connect signals
        self.signals.message_received.connect(self.on_message_received)
        self.signals.message_sent.connect(self.on_message_sent)
        self.signals.error_occurred.connect(self.on_error)
        self.signals.angel_status_changed.connect(self.on_angel_status_changed)
        self.signals.connection_status_changed.connect(self.on_connection_status_changed)
        
        # Setup UI
        self.init_ui()
        
        # Apply dark crypto theme
        self.apply_crypto_theme()
        
        # Note: AngelCore is now optional and NOT started automatically
    
    def init_ui(self):
        """Initialize the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Chat tab
        chat_tab = QWidget()
        chat_layout = QVBoxLayout(chat_tab)
        
        # Status bar at top
        self.status_label = QLabel("🔴 Not Connected")
        self.status_label.setStyleSheet("QLabel { font-weight: bold; padding: 8px; font-size: 14px; background-color: #1a1a1a; color: #ff4444; border-radius: 4px; }")
        chat_layout.addWidget(self.status_label)
        
        # AngelCore status (initially hidden)
        self.angel_label = QLabel("🛡️ AngelCore: Disabled")
        self.angel_label.setStyleSheet("QLabel { padding: 8px; background-color: #2a2a2a; color: #888888; border-radius: 4px; font-size: 12px; }")
        self.angel_label.setVisible(False)  # Hidden by default
        chat_layout.addWidget(self.angel_label)
        
        # Message history
        history_group = QGroupBox("Message History")
        history_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00ff88; border: 2px solid #00ff88; border-radius: 6px; margin-top: 10px; padding-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        history_layout = QVBoxLayout()
        self.message_display = QTextEdit()
        self.message_display.setReadOnly(True)
        self.message_display.setStyleSheet("QTextEdit { font-family: 'Courier New', monospace; background-color: #0a0a0a; color: #00ff88; border: 1px solid #00ff88; border-radius: 4px; padding: 8px; font-size: 13px; }")
        history_layout.addWidget(self.message_display)
        history_group.setLayout(history_layout)
        chat_layout.addWidget(history_group)
        
        # Message input
        input_group = QGroupBox("Send Message")
        input_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00ff88; border: 2px solid #00ff88; border-radius: 6px; margin-top: 10px; padding-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your encrypted message here...")
        self.message_input.setStyleSheet("QLineEdit { background-color: #0a0a0a; color: #00ff88; border: 1px solid #00ff88; border-radius: 4px; padding: 8px; font-family: 'Courier New', monospace; font-size: 13px; }")
        self.message_input.setEnabled(False)
        self.message_input.returnPressed.connect(self.send_message)
        self.send_button = QPushButton("🔐 Send")
        self.send_button.setStyleSheet("QPushButton { background-color: #00ff88; color: #000000; border: none; border-radius: 4px; padding: 8px 16px; font-weight: bold; font-size: 13px; } QPushButton:hover { background-color: #00dd77; } QPushButton:pressed { background-color: #00bb66; } QPushButton:disabled { background-color: #333333; color: #666666; }")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)
        input_group.setLayout(input_layout)
        chat_layout.addWidget(input_group)
        
        tabs.addTab(chat_tab, "💬 Chat")
        
        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        # Scroll area for settings
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # Local settings group
        local_group = QGroupBox("Local Settings")
        local_layout = QGridLayout()
        
        local_layout.addWidget(QLabel("Your Name:"), 0, 0)
        self.name_input = QLineEdit("User")
        local_layout.addWidget(self.name_input, 0, 1)
        
        local_layout.addWidget(QLabel("Your Port:"), 1, 0)
        self.port_input = QLineEdit("55555")
        local_layout.addWidget(self.port_input, 1, 1)
        
        local_layout.addWidget(QLabel("Resonance Code:"), 2, 0)
        self.resonance_input = QLineEdit("1337")
        local_layout.addWidget(self.resonance_input, 2, 1)
        
        local_layout.addWidget(QLabel("Kappa (e.g., 2.5,3.1,4.7):"), 3, 0)
        self.kappa_input = QLineEdit("2.5,3.1,4.7")
        local_layout.addWidget(self.kappa_input, 3, 1)
        
        local_layout.addWidget(QLabel("Theta (e.g., 0.1,1.3,2.1):"), 4, 0)
        self.theta_input = QLineEdit("0.1,1.3,2.1")
        local_layout.addWidget(self.theta_input, 4, 1)
        
        local_layout.addWidget(QLabel("Crypto Password:"), 5, 0)
        self.crypto_pw_input = QLineEdit("secret_password")
        self.crypto_pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        local_layout.addWidget(self.crypto_pw_input, 5, 1)
        
        # AngelCore toggle
        local_layout.addWidget(QLabel("Enable AngelCore:"), 6, 0)
        self.angel_checkbox = QCheckBox("Surveillance Detection")
        self.angel_checkbox.setStyleSheet("QCheckBox { color: #cccccc; } QCheckBox::indicator { width: 18px; height: 18px; }")
        self.angel_checkbox.setToolTip("Enable real-time surveillance detection monitoring.\nWarning: May block chat when suspicious activity is detected.")
        self.angel_checkbox.stateChanged.connect(self.on_angel_checkbox_changed)
        local_layout.addWidget(self.angel_checkbox, 6, 1)
        
        local_group.setLayout(local_layout)
        scroll_layout.addWidget(local_group)
        
        # Peer settings group
        peer_group = QGroupBox("Peer Settings")
        peer_layout = QGridLayout()
        
        peer_layout.addWidget(QLabel("Peer IP:"), 0, 0)
        self.peer_ip_input = QLineEdit("127.0.0.1")
        peer_layout.addWidget(self.peer_ip_input, 0, 1)
        
        peer_layout.addWidget(QLabel("Peer Port:"), 1, 0)
        self.peer_port_input = QLineEdit("55556")
        peer_layout.addWidget(self.peer_port_input, 1, 1)
        
        peer_layout.addWidget(QLabel("Peer Name:"), 2, 0)
        self.peer_name_input = QLineEdit("Peer")
        peer_layout.addWidget(self.peer_name_input, 2, 1)
        
        peer_group.setLayout(peer_layout)
        scroll_layout.addWidget(peer_group)
        
        # QR Code buttons
        qr_group = QGroupBox("QR Code")
        qr_layout = QHBoxLayout()
        self.show_qr_button = QPushButton("📱 Show My QR Code")
        self.show_qr_button.setStyleSheet("QPushButton { background-color: #2196F3; color: white; border: none; border-radius: 4px; padding: 8px 16px; font-weight: bold; } QPushButton:hover { background-color: #1976D2; }")
        self.show_qr_button.clicked.connect(self.show_qr_code)
        self.scan_qr_button = QPushButton("📷 Load from QR Image")
        self.scan_qr_button.setStyleSheet("QPushButton { background-color: #2196F3; color: white; border: none; border-radius: 4px; padding: 8px 16px; font-weight: bold; } QPushButton:hover { background-color: #1976D2; }")
        self.scan_qr_button.clicked.connect(self.load_qr_code)
        qr_layout.addWidget(self.show_qr_button)
        qr_layout.addWidget(self.scan_qr_button)
        qr_group.setLayout(qr_layout)
        scroll_layout.addWidget(qr_group)
        
        # Connection control
        control_group = QGroupBox("Connection")
        control_layout = QHBoxLayout()
        self.start_button = QPushButton("▶️ Start Chat")
        self.start_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; border: none; border-radius: 4px; padding: 10px 20px; font-weight: bold; font-size: 14px; } QPushButton:hover { background-color: #45a049; } QPushButton:disabled { background-color: #333333; color: #666666; }")
        self.start_button.clicked.connect(self.start_chat)
        self.stop_button = QPushButton("⏹️ Stop Chat")
        self.stop_button.setStyleSheet("QPushButton { background-color: #f44336; color: white; border: none; border-radius: 4px; padding: 10px 20px; font-weight: bold; font-size: 14px; } QPushButton:hover { background-color: #da190b; } QPushButton:disabled { background-color: #333333; color: #666666; }")
        self.stop_button.clicked.connect(self.stop_chat)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_group.setLayout(control_layout)
        scroll_layout.addWidget(control_group)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        settings_layout.addWidget(scroll)
        
        tabs.addTab(settings_tab, "⚙️ Settings")
        
        # About tab
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <h2>n'éccrit - Secure Privacy Chat</h2>
        <h3>Features:</h3>
        <ul>
            <li><b>Dual-Layer Security:</b> Tripolar masking + AES-256-GCM encryption</li>
            <li><b>P2P Architecture:</b> No central server, direct peer-to-peer communication</li>
            <li><b>AngelCore:</b> Surveillance detection monitoring CPU, RAM, and user activity</li>
            <li><b>Resonance Codes:</b> Shared secrets for message validation</li>
            <li><b>QR Code Support:</b> Easy parameter sharing via QR codes</li>
        </ul>
        <h3>How it works:</h3>
        <p>Each message undergoes mathematical n-pole (tripolar) masking AND AES-256-GCM authenticated encryption.
        Nobody can decipher messages with only one half of the security layers.</p>
        <h3>Security Notes:</h3>
        <ul>
            <li>Both peers must use the same resonance code, kappa, theta, and crypto password</li>
            <li>AES keys are never transmitted in plaintext</li>
            <li>Each message is dynamically masked and encrypted</li>
            <li>Replay attacks, MITM, and brute-force are practically impossible</li>
        </ul>
        <h3>Getting Started:</h3>
        <ol>
            <li>Configure your local settings (name, port, encryption parameters)</li>
            <li>Share your QR code with your peer OR load their QR code</li>
            <li>Click "Start Chat" to begin listening</li>
            <li>Enter peer IP and port to connect</li>
            <li>Start chatting securely!</li>
        </ol>
        """)
        about_layout.addWidget(about_text)
        tabs.addTab(about_tab, "ℹ️ About")
        
        main_layout.addWidget(tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def apply_crypto_theme(self):
        """Apply dark crypto-themed styling to the application"""
        # Set dark theme palette
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(200, 200, 200))
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(15, 15, 15))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(0, 0, 0))
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(200, 200, 200))
        dark_palette.setColor(QPalette.ColorRole.Text, QColor(200, 200, 200))
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(200, 200, 200))
        dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(0, 255, 136))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 255, 136))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
        self.setPalette(dark_palette)
        
        # Apply stylesheet for additional styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
            }
            QTabWidget::pane {
                border: 2px solid #00ff88;
                border-radius: 6px;
                background-color: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: #cccccc;
                padding: 10px 20px;
                margin: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #00ff88;
                color: #000000;
            }
            QTabBar::tab:hover:!selected {
                background-color: #3a3a3a;
                color: #00ff88;
            }
            QGroupBox {
                color: #cccccc;
                border: 1px solid #444444;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel {
                color: #cccccc;
            }
            QLineEdit {
                background-color: #2a2a2a;
                color: #cccccc;
                border: 1px solid #444444;
                border-radius: 4px;
                padding: 5px;
            }
            QLineEdit:focus {
                border: 1px solid #00ff88;
            }
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff88;
                border: 1px solid #00ff88;
            }
            QScrollArea {
                border: none;
            }
            QStatusBar {
                background-color: #2a2a2a;
                color: #cccccc;
            }
        """)
    
    def get_params(self):
        """Get current parameters as dictionary"""
        try:
            return {
                "name": self.name_input.text().strip(),
                "port": int(self.port_input.text().strip()),
                "resonance_code": self.resonance_input.text().strip(),
                "kappa": [float(x.strip()) for x in self.kappa_input.text().split(",")],
                "theta": [float(x.strip()) for x in self.theta_input.text().split(",")],
                "crypto_pw": self.crypto_pw_input.text().strip(),
                "peer_ip": self.peer_ip_input.text().strip(),
                "peer_port": int(self.peer_port_input.text().strip())
            }
        except Exception as e:
            raise ValueError(f"Invalid parameters: {e}")
    
    def set_params(self, params):
        """Set parameters from dictionary"""
        self.name_input.setText(params.get("name", "User"))
        self.port_input.setText(str(params.get("port", 55555)))
        self.resonance_input.setText(str(params.get("resonance_code", "1337")))
        self.kappa_input.setText(",".join(str(x) for x in params.get("kappa", [2.5, 3.1, 4.7])))
        self.theta_input.setText(",".join(str(x) for x in params.get("theta", [0.1, 1.3, 2.1])))
        self.crypto_pw_input.setText(params.get("crypto_pw", "secret"))
        self.peer_ip_input.setText(params.get("peer_ip", "127.0.0.1"))
        self.peer_port_input.setText(str(params.get("peer_port", 55556)))
    
    def start_chat(self):
        """Start the chat node"""
        try:
            params = self.get_params()
            
            # Create node
            self.node = SpectralNode(
                name=params["name"],
                port=params["port"],
                resonance_code=params["resonance_code"],
                kappa=params["kappa"],
                theta=params["theta"],
                crypto_pw=params["crypto_pw"]
            )
            
            # Store peer info
            self.peer_ip = params["peer_ip"]
            self.peer_port = params["peer_port"]
            self.peer_name = self.peer_name_input.text().strip()
            
            # Start listening
            self.node.start_listening(on_receive=self.on_receive_callback)
            self.is_running = True
            
            # Update UI
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.message_input.setEnabled(True)
            self.send_button.setEnabled(True)
            self.status_label.setText("🟢 Connected & Encrypted")
            self.status_label.setStyleSheet("QLabel { font-weight: bold; padding: 8px; font-size: 14px; background-color: #1a3a1a; color: #00ff88; border-radius: 4px; }")
            
            # Disable settings while running
            self.name_input.setEnabled(False)
            self.port_input.setEnabled(False)
            self.resonance_input.setEnabled(False)
            self.kappa_input.setEnabled(False)
            self.theta_input.setEnabled(False)
            self.crypto_pw_input.setEnabled(False)
            
            self.signals.connection_status_changed.emit("Chat started successfully")
            self.add_system_message(f"Chat started. Listening on port {params['port']}")
            
        except Exception as e:
            self.signals.error_occurred.emit(f"Failed to start chat: {e}")
    
    def stop_chat(self):
        """Stop the chat node"""
        if self.node:
            self.node.stop()
            self.node = None
        
        self.is_running = False
        
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.message_input.setEnabled(False)
        self.send_button.setEnabled(False)
        self.status_label.setText("🔴 Disconnected")
        self.status_label.setStyleSheet("QLabel { font-weight: bold; padding: 8px; font-size: 14px; background-color: #1a1a1a; color: #ff4444; border-radius: 4px; }")
        
        # Re-enable settings
        self.name_input.setEnabled(True)
        self.port_input.setEnabled(True)
        self.resonance_input.setEnabled(True)
        self.kappa_input.setEnabled(True)
        self.theta_input.setEnabled(True)
        self.crypto_pw_input.setEnabled(True)
        
        self.signals.connection_status_changed.emit("Chat stopped")
        self.add_system_message("Chat stopped")
    
    def send_message(self):
        """Send a message to the peer"""
        if not self.is_running or not self.node:
            return
        
        message = self.message_input.text().strip()
        if not message:
            return
        
        # Clear input
        self.message_input.clear()
        
        # Send in background thread
        def send_thread():
            try:
                self.node.send_fragment(message, self.peer_ip, self.peer_port, self.peer_name)
                self.signals.message_sent.emit(message)
            except Exception as e:
                self.signals.error_occurred.emit(f"Failed to send message: {e}")
        
        threading.Thread(target=send_thread, daemon=True).start()
    
    def on_receive_callback(self, sender, message):
        """Callback when message is received (runs in network thread)"""
        self.signals.message_received.emit(sender, message)
    
    def on_message_received(self, sender, message):
        """Handle received message (runs in GUI thread)"""
        timestamp = time.strftime("%H:%M:%S")
        self.message_display.append(f"<span style='color: #00aaff; font-weight: bold;'>[{timestamp}] {sender}:</span> <span style='color: #00ff88;'>{message}</span>")
    
    def on_message_sent(self, message):
        """Handle sent message (runs in GUI thread)"""
        timestamp = time.strftime("%H:%M:%S")
        self.message_display.append(f"<span style='color: #ffaa00; font-weight: bold;'>[{timestamp}] You:</span> <span style='color: #00ff88;'>{message}</span>")
    
    def on_error(self, error_msg):
        """Handle error (runs in GUI thread)"""
        QMessageBox.warning(self, "Error", error_msg)
        self.statusBar().showMessage(f"Error: {error_msg}", 5000)
    
    def on_connection_status_changed(self, status):
        """Handle connection status change"""
        self.statusBar().showMessage(status, 3000)
    
    def add_system_message(self, message):
        """Add system message to display"""
        timestamp = time.strftime("%H:%M:%S")
        self.message_display.append(f"<i style='color: #888888;'>[{timestamp}] System: {message}</i>")
    
    def show_qr_code(self):
        """Show QR code for current parameters"""
        try:
            params = self.get_params()
            
            # Generate QR code
            qr_img = generate_qr_img(params)
            
            # Convert PIL image to QPixmap
            buf = io.BytesIO()
            qr_img.save(buf, format='PNG')
            buf.seek(0)
            qimage = QImage()
            qimage.loadFromData(buf.read())
            pixmap = QPixmap.fromImage(qimage)
            
            # Create dialog
            dialog = QMessageBox(self)
            dialog.setWindowTitle("My QR Code")
            dialog.setText("Share this QR code with your peer")
            dialog.setIconPixmap(pixmap.scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio))
            dialog.exec()
            
        except Exception as e:
            self.signals.error_occurred.emit(f"Failed to generate QR code: {e}")
    
    def load_qr_code(self):
        """Load parameters from QR code image"""
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self,
                "Select QR Code Image",
                "",
                "Images (*.png *.jpg *.jpeg *.bmp)"
            )
            
            if not filename:
                return
            
            # Decode QR code
            params = decode_qr_from_imagefile(filename)
            
            if params:
                self.set_params(params)
                QMessageBox.information(self, "Success", "Parameters loaded from QR code!")
            else:
                QMessageBox.warning(self, "Error", "Could not decode QR code from image")
                
        except Exception as e:
            self.signals.error_occurred.emit(f"Failed to load QR code: {e}")
    
    def start_angel_monitoring(self):
        """Start AngelCore surveillance detection monitoring"""
        if self.angel_enabled:
            return  # Already running
            
        def angel_loop():
            while self.angel_enabled:
                # Simulate inputs (in production, these would be real metrics)
                cpu = random.randint(5, 80)
                ram = random.randint(30, 90)
                mouse = random.randint(0, 20)
                timing = [random.random() for _ in range(5)]
                mic = [random.uniform(-1.0, 1.0) for _ in range(32)]
                
                status = angelcore_decision(cpu, ram, mouse, timing, mic)
                self.signals.angel_status_changed.emit(status)
                
                time.sleep(5)  # Check every 5 seconds
        
        self.angel_enabled = True
        self.angel_label.setVisible(True)
        self.angel_thread = threading.Thread(target=angel_loop, daemon=True)
        self.angel_thread.start()
        self.add_system_message("AngelCore surveillance detection enabled")
    
    def stop_angel_monitoring(self):
        """Stop AngelCore surveillance detection monitoring"""
        self.angel_enabled = False
        self.angel_label.setText("🛡️ AngelCore: Disabled")
        self.angel_label.setStyleSheet("QLabel { padding: 8px; background-color: #2a2a2a; color: #888888; border-radius: 4px; font-size: 12px; }")
        self.angel_label.setVisible(False)
        # Reset message display styling if it was affected
        self.message_display.setStyleSheet("QTextEdit { font-family: 'Courier New', monospace; background-color: #0a0a0a; color: #00ff88; border: 1px solid #00ff88; border-radius: 4px; padding: 8px; font-size: 13px; }")
        if self.is_running:
            self.message_input.setEnabled(True)
        self.add_system_message("AngelCore surveillance detection disabled")
    
    def on_angel_checkbox_changed(self, state):
        """Handle AngelCore checkbox state change"""
        if state == Qt.CheckState.Checked.value:
            self.start_angel_monitoring()
        else:
            self.stop_angel_monitoring()
    
    def on_angel_status_changed(self, status):
        """Handle AngelCore status change"""
        if not self.angel_enabled:
            return
            
        if status == "ALERT":
            self.angel_label.setText("⚠️ ANGELCORE: Visual camouflage activated!")
            self.angel_label.setStyleSheet("QLabel { padding: 8px; background-color: #3a1a1a; color: #ff4444; font-weight: bold; border-radius: 4px; font-size: 12px; }")
            self.message_display.setStyleSheet("QTextEdit { background-color: black; color: black; }")
            self.message_input.setEnabled(False)
        elif status == "UNCERTAIN":
            self.angel_label.setText("⚠️ AngelCore: Restricted mode")
            self.angel_label.setStyleSheet("QLabel { padding: 8px; background-color: #3a3a1a; color: #ffaa00; border-radius: 4px; font-size: 12px; }")
            self.message_display.setStyleSheet("QTextEdit { background-color: #1a1a1a; color: #888888; font-family: 'Courier New', monospace; }")
            self.message_input.setEnabled(False)
        else:  # SAFE
            self.angel_label.setText("🛡️ AngelCore: Secure")
            self.angel_label.setStyleSheet("QLabel { padding: 8px; background-color: #1a3a1a; color: #00ff88; border-radius: 4px; font-size: 12px; }")
            self.message_display.setStyleSheet("QTextEdit { font-family: 'Courier New', monospace; background-color: #0a0a0a; color: #00ff88; border: 1px solid #00ff88; border-radius: 4px; padding: 8px; font-size: 13px; }")
            if self.is_running:
                self.message_input.setEnabled(True)
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.is_running:
            reply = QMessageBox.question(
                self,
                "Confirm Exit",
                "Chat is still running. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_chat()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("n'éccrit")
    app.setOrganizationName("SPECTRALSHIP")
    
    window = NeccritMainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
