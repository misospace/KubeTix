"""Pytest config: make the kubetix_api package importable."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
