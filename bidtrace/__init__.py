"""
BidTrace Global Standard: Forwarding Package
"""
import sys
import os

# Ensure bidtrace_py is importable
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from bidtrace_py import *
