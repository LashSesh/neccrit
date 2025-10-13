#!/usr/bin/env python3
"""
Simple launcher script for n'éccrit chat application
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from neccrit_pyqt6 import main
    main()
except ImportError as e:
    print(f"Error: Missing dependencies. Please install requirements first:")
    print(f"  pip install -r requirements.txt")
    print(f"\nDetails: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error starting application: {e}")
    sys.exit(1)
