#!/usr/bin/env python3
"""
Example integration of ScorpioSync cover traffic addon with n'éccrit.

This script demonstrates how to enable cover traffic generation in a n'éccrit
chat session. It's a simplified example showing the integration pattern.

Usage:
    python example_cover_traffic_integration.py
"""
import threading
import time

from spectralship_engine_duallayer import SpectralNode
from config import (
    ENABLE_COVER_TRAFFIC,
    COVER_MIN_INTERVAL_S,
    COVER_MAX_INTERVAL_S,
    ENABLE_HTTP_MIMICRY,
)


def main():
    """Example integration of cover traffic with a chat session."""
    
    # Configuration
    print("=== n'éccrit + ScorpioSync Cover Traffic Example ===\n")
    
    # Create node
    node = SpectralNode(
        name="Alice",
        port=55555,
        resonance_code="1337",
        kappa=[2.5, 3.1, 4.7],
        theta=[0.1, 1.3, 2.1],
        crypto_pw="example_password_change_this"
    )
    
    # Peer configuration
    peer_ip = "127.0.0.1"
    peer_port = 55556
    peer_name = "Bob"
    
    print(f"Node configured: {node.name} on port {node.port}")
    print(f"Peer: {peer_name} at {peer_ip}:{peer_port}\n")
    
    # Start listening
    def on_message(sender, text):
        print(f"📨 Received: [{sender}] {text}")
    
    node.start_listening(on_receive=on_message)
    print("✓ Listening started\n")
    
    # Configure and start cover traffic if enabled
    cover_thread = None
    stop_flag = None
    
    if ENABLE_COVER_TRAFFIC:
        print(f"🎭 Cover traffic ENABLED")
        print(f"   - Interval: {COVER_MIN_INTERVAL_S}-{COVER_MAX_INTERVAL_S}s")
        print(f"   - HTTP Mimicry: {ENABLE_HTTP_MIMICRY}")
        
        from addons.scorpiosync_adapter import set_active_node, start_cover_traffic
        
        # Set the active session
        set_active_node(node, peer_ip, peer_port, peer_name)
        
        # Start cover traffic thread
        stop_flag = threading.Event()
        cover_thread = start_cover_traffic(
            min_s=COVER_MIN_INTERVAL_S,
            max_s=COVER_MAX_INTERVAL_S,
            use_http_mimicry=ENABLE_HTTP_MIMICRY,
            stop_flag=stop_flag
        )
        print("✓ Cover traffic thread started\n")
    else:
        print("ℹ️  Cover traffic DISABLED in config.py\n")
    
    # Example: Send a message
    print("💬 Sending test message...")
    try:
        node.send_fragment("Hello from Alice!", peer_ip, peer_port, peer_name)
        print("✓ Message sent\n")
    except Exception as e:
        print(f"⚠️  Could not send (peer may not be running): {e}\n")
    
    # Run for a short demo period
    print("Running for 30 seconds as demonstration...")
    print("(In a real application, this would run indefinitely)\n")
    
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    
    # Cleanup
    print("\n=== Shutting down ===")
    
    if cover_thread and stop_flag:
        print("Stopping cover traffic...")
        stop_flag.set()
        cover_thread.join(timeout=5)
    
    node.running = False
    print("✓ Cleanup complete")
    print("\n=== Example complete ===")


if __name__ == "__main__":
    main()
