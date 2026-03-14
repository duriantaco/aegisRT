
from __future__ import annotations

import socket
import webbrowser
from threading import Timer


def _port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _find_port(host: str, start: int, max_tries: int = 10) -> int:
    for offset in range(max_tries):
        candidate = start + offset
        if _port_available(host, candidate):
            return candidate
    raise SystemExit(f"No available port found in range {start}-{start + max_tries - 1}")


def start_server(
    host: str = "127.0.0.1",
    port: int = 8484,
    open_browser: bool = True,
) -> None:
    try:
        import uvicorn
    except ImportError:
        raise SystemExit(
            "uvicorn is required to run the AegisRT dashboard.\n"
            "Install it with: pip install 'aegisrt[web]'"
        )

    if not _port_available(host, port):
        new_port = _find_port(host, port + 1)
        print(f"Port {port} is in use, using {new_port} instead")
        port = new_port

    if open_browser:
        Timer(1.5, webbrowser.open, args=[f"http://{host}:{port}"]).start()

    uvicorn.run(
        "aegisrt.web.app:app",
        host=host,
        port=port,
        log_level="info",
    )
