import sys
from pathlib import Path

# Ensure kubetix-api is on the path for test imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "kubetix-api"))
