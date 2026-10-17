"""Compatibility entry point for the integrated application."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import main

if __name__ == '__main__':
    main()
