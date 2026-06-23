"""
VulnSight — single entry point
================================
Starts two services in parallel:
  1. FastAPI backend   (http://localhost:8000)
  2. Vite dev server   (http://localhost:5173)

Usage
-----
    python main.py              # API + frontend
    python main.py --api-only   # API only (no frontend)
"""

import argparse
import subprocess
import sys
import threading
import time
from pathlib import Path

import uvicorn

_ROOT = Path(__file__).parent

# ── ANSI colours ────────────────────────────────────────────────────────────
R  = "\033[0m"          # reset
B  = "\033[1m"          # bold
CY = "\033[1;36m"       # bold cyan
GR = "\033[1;32m"       # bold green
YL = "\033[1;33m"       # bold yellow
RD = "\033[1;31m"       # bold red
DIM= "\033[2m"          # dim


def banner():
    print(f"""
{CY}{B}
  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
  ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║██║  ███╗███████║   ██║
  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║██║   ██║██╔══██║   ██║
   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║██║╚██████╔╝██║  ██║   ██║
    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
{R}
{DIM}  AI-powered Network Intrusion Detection System{R}
""")


def log(tag: str, color: str, msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{R} {color}{B}[{tag}]{R}  {msg}")


# ── 1. API server ────────────────────────────────────────────────────────────

def run_api():
    from src.core.settings import settings
    from src.api.server import app
    from fastapi import HTTPException
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    dist = _ROOT / "frontend" / "dist"
    if dist.exists():
        assets = dist / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _spa(full_path: str):
            # Unknown /api/ paths must 404, not fall through to index.html.
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404, detail="Not Found")
            candidate = dist / full_path
            if candidate.is_file():
                return FileResponse(str(candidate))
            return FileResponse(str(dist / "index.html"))

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level="warning",        # suppress per-request noise
    )


# ── 2. Vite dev server ──────────────────────────────────────────────────────

def run_frontend():
    frontend_dir = _ROOT / "frontend"
    if not frontend_dir.exists():
        log("FRONTEND", YL, "frontend/ directory not found — skipping")
        return

    npm = "npm.cmd" if sys.platform == "win32" else "npm"
    log("FRONTEND", YL, "Starting Vite dev server …")

    proc = subprocess.Popen(
        [npm, "run", "dev"],
        cwd=str(frontend_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        # surface the "ready" line and errors; suppress noisy HMR chatter
        if any(k in line for k in ("Local:", "ready", "localhost", "ERROR", "error")):
            log("FRONTEND", YL, line.strip())

    proc.wait()


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VulnSight NIDS launcher")
    parser.add_argument("--api-only",    action="store_true", help="Start API server only")
    parser.add_argument("--no-frontend", action="store_true", help="Skip the Vite dev server")
    args = parser.parse_args()

    banner()

    from src.core.settings import settings

    threads: list[threading.Thread] = []

    # always start the API
    log("API", CY, f"Starting on http://localhost:{settings.api_port}")
    api_thread = threading.Thread(target=run_api, daemon=True, name="api")
    api_thread.start()
    threads.append(api_thread)
    time.sleep(1)   # brief pause so the API port is open before anything connects

    if not args.api_only and not args.no_frontend:
        fe_thread = threading.Thread(target=run_frontend, daemon=True, name="frontend")
        fe_thread.start()
        threads.append(fe_thread)

    # ── ready banner ─────────────────────────────────────────────────────────
    time.sleep(2)
    print(f"""
{GR}{B}  ✓ VulnSight is running{R}

  {CY}API{R}       →  http://localhost:{settings.api_port}/api/v1
  {CY}Docs{R}      →  http://localhost:{settings.api_port}/docs
  {YL}Frontend{R}  →  http://localhost:5173

  {DIM}Press Ctrl+C to stop{R}
""")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YL}  Shutting down VulnSight …{R}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
