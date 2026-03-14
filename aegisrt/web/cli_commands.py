
from __future__ import annotations

import click

@click.command()
@click.option("--port", default=8484, show_default=True, help="Port to listen on.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--no-browser", is_flag=True, help="Do not open a browser on startup.")
def serve(port: int, host: str, no_browser: bool) -> None:
    from aegisrt.web.server import start_server

    click.echo(f"Starting AegisRT dashboard at http://{host}:{port}")
    start_server(host=host, port=port, open_browser=not no_browser)
