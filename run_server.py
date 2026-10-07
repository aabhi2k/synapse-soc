"""
Web Server Launcher for SYNAPSE-SOC Web Console.
Checks port availability, initialises dataset, and launches FastAPI via Uvicorn.
"""

import sys
import socket
import argparse
from pathlib import Path

# Fix Windows cp1252 encoding
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def start_server(host: str = "127.0.0.1", port: int = 8000):
    print("=" * 65)
    print("  SYNAPSE-SOC : FASTAPI WEB TRIAGE CONSOLE LAUNCHER")
    print("=" * 65)

    # Pre-flight check: Port availability
    if is_port_in_use(port, host=host):
        print(f"\n[!] ERROR: Port {port} is already in use by another application.")
        print(f"    Please stop the process running on port {port} or specify another port:")
        print(f"    Example: python run_server.py --port {port + 1}")
        sys.exit(1)

    print(f"\n[+] Local Port {port} verified available.")
    print(f"[+] Loading triage data and mounting REST APIs...")
    print(f"[+] Web Console accessible at: http://localhost:{port}")
    print(f"[+] API Health check endpoint:  http://localhost:{port}/api/health\n")

    # Automatically launch default browser to localhost
    import threading
    import webbrowser
    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{port}")).start()

    try:
        import uvicorn
        uvicorn.run("web.app:app", host=host, port=port, reload=False, log_level="info")
    except ImportError:
        print("[!] ERROR: 'uvicorn' is not installed. Please run: pip install uvicorn")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] SYNAPSE-SOC Web Console stopped cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Launch SYNAPSE-SOC Web Console")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    args = parser.parse_args()

    start_server(host=args.host, port=args.port)

