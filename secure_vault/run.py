#!/usr/bin/env python3
"""
SecureVault — Launcher
Starts both the vault server (port 5001) and the GUI app (port 5000).
"""

import subprocess
import sys
import time
import os
import signal
from pathlib import Path

BASE = Path(__file__).parent

procs = []

def start():
    print("\n" + "═"*60)
    print("  🔐  S E C U R E V A U L T  v2.0.0")
    print("  Encrypted File Transfer & Storage System")
    print("═"*60)

    # Start vault server
    print("\n[1/2] Starting Vault Server on :5001...")
    vault = subprocess.Popen(
        [sys.executable, str(BASE / "server" / "server.py")],
        env={**os.environ, "PYTHONPATH": str(BASE)}
    )
    procs.append(vault)
    time.sleep(1.5)

    # Start GUI app
    print("[2/2] Starting GUI App on :5000...")
    gui = subprocess.Popen(
        [sys.executable, str(BASE / "app.py")],
        env={**os.environ, "PYTHONPATH": str(BASE)}
    )
    procs.append(gui)
    time.sleep(1.5)

    print("\n" + "═"*60)
    print("  ✓  Vault Server:  http://localhost:5001")
    print("  ✓  GUI Interface: http://localhost:5000")
    print("═"*60)
    print("\n  Open http://localhost:5000 in your browser")
    print("  Press Ctrl+C to stop all services\n")

    def shutdown(sig, frame):
        print("\n[shutdown] Stopping services...")
        for p in procs:
            p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Wait
    for p in procs:
        p.wait()

if __name__ == '__main__':
    start()
