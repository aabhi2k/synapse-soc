"""
Server runner for Security Alert Summarizer Web Dashboard.
"""

import sys
from pathlib import Path
import uvicorn

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if __name__ == "__main__":
    print("\n=======================================================")
    print("  Starting SHIELD-AI Security Alert Summarizer Console ")
    print("  Dashboard URL: http://localhost:8000                 ")
    print("=======================================================\n")
    uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=False)
