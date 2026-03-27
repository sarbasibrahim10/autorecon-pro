#!/usr/bin/env python3
"""AutoRecon Pro - World-class bug bounty automation tool."""
from __future__ import annotations
import asyncio
import sys
import platform

import click
import colorama
from rich.console import Console

colorama.init()

if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

console = Console()

BANNER = """
[bold cyan]
   ___         __        ____                      ____
  / _ | __ __ / /_ ___  / __ \___  _______  ___   / __ \_______
 / __ |/ // // __// _ \/ /_/ / -_)/ __/ _ \/ _ \ / /_/ / __/ _ \\
/_/ |_|\_,_/ \__/ \___/\____/\__/ \__/\___/_//_/ \____/_/  \___/
[/][bold green]
  Bug Bounty Automation | Zero Cost | Full Pipeline | v1.0
[/]"""


@click.group()
def cli():
    """AutoRecon Pro - Automated bug bounty recon and vulnerability scanning."""
    console.print(BANNER)


@cli.command()
@click.option("--target", "-t", required=True, help="Target domain (e.g. example.com)")
@click.option("--output", "-o", default="./reports", show_default=True, help="Output directory")
@click.option("--concurrency", "-c", default=50, show_default=True, help="Max concurrent requests")
@click.option("--timeout", default=10, show_default=True, help="Request timeout in seconds")
@click.option("--resume", is_flag=True, default=False, help="Resume a previous scan")
@click.option("--scan-id", default=None, help="Scan ID to resume (required with --resume)")
@click.option("--no-nuclei", is_flag=True, default=False, help="Skip Nuclei scanning")
@click.option("--rps", default=10.0, show_default=True, help="Requests per second per domain")
def scan(target, output, concurrency, timeout, resume, scan_id, no_nuclei, rps):
    """Run a full automated bug bounty scan against a target domain."""
    from config import Config
    from core.pipeline import Pipeline

    # Strip protocol if provided
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    cfg = Config(
        target=target,
        output_dir=output,
        concurrency=concurrency,
        timeout=timeout,
        resume=resume,
        nuclei_enabled=not no_nuclei,
        rps=rps,
    )

    if resume and scan_id:
        cfg.scan_id = scan_id

    # Save session file for resuming
    session_file = cfg.scan_dir / ".autorecon_session"
    session_file.write_text(cfg.scan_id)

    console.print(f"[bold]Target:[/] {target}")
    console.print(f"[bold]Output:[/] {cfg.scan_dir}")
    console.print(f"[bold]Nuclei:[/] {'disabled' if no_nuclei else 'enabled'}\n")

    pipeline = Pipeline(cfg)
    asyncio.run(pipeline.run())


@cli.command()
@click.option("--scan-id", "-s", required=True, help="Scan ID to regenerate report for")
@click.option("--output", "-o", default="./reports", show_default=True)
def report(scan_id, output):
    """Regenerate HTML report from an existing scan database."""
    from config import Config
    from core.database import Database
    from reporting.report_builder import ReportBuilder
    from reporting.html_renderer import HtmlRenderer

    cfg = Config(target="", scan_id=scan_id, output_dir=output)
    cfg.scan_id = scan_id
    cfg.scan_dir = cfg.output_dir / scan_id
    cfg.db_path = cfg.scan_dir / "scan.db"
    cfg.report_path = cfg.scan_dir / "dashboard.html"

    async def _regen():
        db = Database(cfg.db_path)
        await db.connect()
        builder = ReportBuilder(db, scan_id)
        data = await builder.build()
        await db.close()
        renderer = HtmlRenderer()
        renderer.render(data, cfg.report_path)
        console.print(f"[green]Report saved:[/] {cfg.report_path}")

    asyncio.run(_regen())


if __name__ == "__main__":
    cli()
