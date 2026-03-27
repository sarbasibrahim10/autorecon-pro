from __future__ import annotations
import asyncio
import sys
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich import box

from config import Config
from core.database import Database
from core.session import make_session
from core.rate_limiter import RateLimiter
from core.models import Finding

console = Console()

SEVERITY_COLORS = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "blue",
    "Info": "dim",
}

# -----------------------------------------------------------------------
# Concurrency limits — scanning is much more sensitive than recon
# -----------------------------------------------------------------------
SCAN_CONCURRENCY = 5      # max parallel vuln scanner tasks
PROBE_CONCURRENCY = 50    # HTTP probing (fast, low payload)
DNS_CONCURRENCY = 200     # DNS resolution (very fast)
CRAWL_CONCURRENCY = 10    # Crawling per host


class Pipeline:
    def __init__(self, config: Config):
        self.config = config
        self.db = Database(config.db_path)
        self.session = None
        self.rate_limiter = RateLimiter(config.rps)
        self._findings_table = Table(
            "Severity", "Type", "URL", "Parameter",
            box=box.SIMPLE, show_header=True, header_style="bold cyan"
        )

    async def run(self):
        await self.db.connect()
        self.session = make_session(self.config.timeout)

        try:
            await self.db.create_scan(
                self.config.scan_id,
                self.config.target,
                {"concurrency": self.config.concurrency, "timeout": self.config.timeout}
            )

            completed = await self.db.get_completed_phases(self.config.scan_id)

            console.print(Panel.fit(
                f"[bold cyan]AutoRecon Pro[/] | Target: [green]{self.config.target}[/] | "
                f"Scan ID: [yellow]{self.config.scan_id}[/]",
                border_style="cyan"
            ))

            if "recon" not in completed:
                await self._phase_recon()
                await self.db.mark_phase_complete(self.config.scan_id, "recon")
            else:
                console.print("[dim]Phase 1 (Recon): Skipped (resumed)[/]")

            if "probe" not in completed:
                await self._phase_probe()
                await self.db.mark_phase_complete(self.config.scan_id, "probe")
            else:
                console.print("[dim]Phase 2 (Probe): Skipped (resumed)[/]")

            if "discovery" not in completed:
                await self._phase_discovery()
                await self.db.mark_phase_complete(self.config.scan_id, "discovery")
            else:
                console.print("[dim]Phase 3 (Discovery): Skipped (resumed)[/]")

            if "scan" not in completed:
                await self._phase_scan()
                await self.db.mark_phase_complete(self.config.scan_id, "scan")
            else:
                console.print("[dim]Phase 4 (Scan): Skipped (resumed)[/]")

            if "nuclei" not in completed and self.config.nuclei_enabled:
                await self._phase_nuclei()
                await self.db.mark_phase_complete(self.config.scan_id, "nuclei")
            else:
                console.print("[dim]Phase 4b (Nuclei): Skipped[/]")

            await self._phase_report()
            await self.db.complete_scan(self.config.scan_id)

            console.print(Panel.fit(
                f"[bold green]Scan Complete![/]\n"
                f"Report: [cyan]{self.config.report_path}[/]",
                border_style="green"
            ))

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted — progress saved. Use --resume to continue.[/]")
        finally:
            await self.session.aclose()
            await self.db.close()

    async def _phase_recon(self):
        console.print("\n[bold cyan]Phase 1: Subdomain Enumeration[/]")
        from recon.subdomain_enum import SubdomainEnumerator
        from recon.dns_resolver import DNSResolver
        from recon.whois_lookup import whois_lookup

        enumerator = SubdomainEnumerator(self.config.target, self.session, self.rate_limiter)
        resolver = DNSResolver()

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(), console=console
        ) as progress:
            task = progress.add_task("Enumerating subdomains...", total=None)
            subdomains = await enumerator.enumerate()
            progress.update(task, total=len(subdomains), completed=len(subdomains),
                            description=f"Found {len(subdomains)} subdomains")

            resolve_task = progress.add_task("Resolving DNS...", total=len(subdomains))
            sem = asyncio.Semaphore(DNS_CONCURRENCY)

            async def resolve_one(sub):
                async with sem:
                    resolved = await resolver.resolve(sub)
                    await self.db.upsert_subdomain(self.config.scan_id, resolved)
                    progress.advance(resolve_task)

            await asyncio.gather(*[resolve_one(s) for s in subdomains], return_exceptions=True)

        whois_data = await whois_lookup(self.config.target)
        if whois_data:
            console.print(f"  [dim]WHOIS Registrar: {whois_data.get('registrar', 'N/A')}[/]")

        stats = await self.db.get_scan_stats(self.config.scan_id)
        console.print(f"  [green]✓[/] {stats['total_subdomains']} subdomains discovered")

    async def _phase_probe(self):
        console.print("\n[bold cyan]Phase 2: HTTP Probing[/]")
        from recon.http_prober import HttpProber

        subdomains = await self.db.get_subdomains(self.config.scan_id)
        prober = HttpProber(self.session, self.rate_limiter, self.config.timeout)

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(), console=console
        ) as progress:
            task = progress.add_task("Probing hosts...", total=len(subdomains))
            sem = asyncio.Semaphore(PROBE_CONCURRENCY)

            async def probe_one(sub):
                async with sem:
                    probed = await prober.probe(sub)
                    await self.db.upsert_subdomain(self.config.scan_id, probed)
                    progress.advance(task)

            await asyncio.gather(*[probe_one(s) for s in subdomains], return_exceptions=True)

        stats = await self.db.get_scan_stats(self.config.scan_id)
        console.print(f"  [green]✓[/] {stats['live_subdomains']} live hosts found")

    async def _phase_discovery(self):
        console.print("\n[bold cyan]Phase 3: Discovery[/]")
        from discovery.crawler import Crawler
        from discovery.js_analyzer import JsAnalyzer
        from discovery.wayback_fetcher import WaybackFetcher
        from discovery.api_detector import ApiDetector

        live_hosts = await self.db.get_subdomains(self.config.scan_id, live_only=True)

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(), console=console
        ) as progress:
            crawl_task = progress.add_task("Crawling live hosts...", total=len(live_hosts))
            crawler = Crawler(self.session, self.rate_limiter, self.config)
            js_analyzer = JsAnalyzer(self.session)
            api_detector = ApiDetector(self.session)
            sem = asyncio.Semaphore(CRAWL_CONCURRENCY)

            async def crawl_host(sub):
                async with sem:
                    endpoints = await crawler.crawl(sub.final_url or f"https://{sub.domain}")
                    for ep in endpoints:
                        await self.db.upsert_endpoint(self.config.scan_id, ep)
                    js_eps = [e for e in endpoints if e.url.endswith(".js")]
                    for js_ep in js_eps[:20]:
                        extra = await js_analyzer.analyze(js_ep.url)
                        for ep in extra:
                            await self.db.upsert_endpoint(self.config.scan_id, ep)
                    api_eps = await api_detector.detect(sub.final_url or f"https://{sub.domain}")
                    for ep in api_eps:
                        await self.db.upsert_endpoint(self.config.scan_id, ep)
                    progress.advance(crawl_task)

            await asyncio.gather(*[crawl_host(h) for h in live_hosts], return_exceptions=True)

            wayback_task = progress.add_task("Fetching Wayback Machine...", total=1)
            wayback = WaybackFetcher(self.session)
            wb_endpoints = await wayback.fetch(self.config.target)
            for ep in wb_endpoints:
                await self.db.upsert_endpoint(self.config.scan_id, ep)
            progress.advance(wayback_task)

        stats = await self.db.get_scan_stats(self.config.scan_id)
        console.print(f"  [green]✓[/] {stats['total_endpoints']} unique endpoints mapped")

    async def _phase_scan(self):
        console.print("\n[bold cyan]Phase 4: Vulnerability Scanning[/]")
        console.print(f"  [dim]Scan concurrency: {SCAN_CONCURRENCY} (rate-limit safe)[/]")

        from scanners.xss_scanner import XSSScanner
        from scanners.sqli_scanner import SQLiScanner
        from scanners.ssrf_scanner import SSRFScanner
        from scanners.open_redirect_scanner import OpenRedirectScanner
        from scanners.cors_scanner import CORSScanner
        from scanners.header_scanner import HeaderScanner
        from scanners.secret_scanner import SecretScanner
        from scanners.subdomain_takeover import SubdomainTakeoverScanner
        from scanners.cloud_bucket_scanner import CloudBucketScanner
        from scanners.idor_scanner import IDORScanner
        from scanners.xxe_scanner import XXEScanner
        from scanners.oauth_scanner import OAuthScanner

        endpoints = await self.db.get_endpoints(self.config.scan_id)
        subdomains = await self.db.get_subdomains(self.config.scan_id, live_only=True)

        active_scanners = [
            XSSScanner(self.session),
            SQLiScanner(self.session),
            SSRFScanner(self.session),
            OpenRedirectScanner(self.session),
            IDORScanner(self.session),
            XXEScanner(self.session),
        ]
        passive_scanners = [
            CORSScanner(self.session),
            HeaderScanner(self.session),
            SecretScanner(self.session),
            OAuthScanner(self.session),
        ]
        host_scanners = [
            SubdomainTakeoverScanner(self.session),
            CloudBucketScanner(self.session),
        ]

        finding_count = 0

        # ---------------------------------------------------------------
        # FIXED: Use SCAN_CONCURRENCY (5) instead of config.concurrency (50)
        # Active scanners send many payloads per endpoint — keep it slow
        # ---------------------------------------------------------------
        active_sem = asyncio.Semaphore(SCAN_CONCURRENCY)

        # Passive scanners (just read headers/responses) can go faster
        passive_sem = asyncio.Semaphore(min(self.config.concurrency, 20))

        async def run_scanner(scanner, target, sem):
            async with sem:
                try:
                    findings = await scanner.scan(target)
                    for f in findings:
                        await self.db.insert_finding(self.config.scan_id, f)
                        self._print_finding(f)
                        nonlocal finding_count
                        finding_count += 1
                except Exception:
                    pass

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(), console=console
        ) as progress:
            # Active scanners — low concurrency
            active_total = sum(
                1 for scanner in active_scanners
                for ep in endpoints
                if scanner.is_applicable(ep)
            )
            ep_task = progress.add_task("Active scanning...", total=active_total or 1)
            active_tasks = []
            for scanner in active_scanners:
                for ep in endpoints:
                    if scanner.is_applicable(ep):
                        t = asyncio.create_task(run_scanner(scanner, ep, active_sem))
                        t.add_done_callback(lambda _: progress.advance(ep_task))
                        active_tasks.append(t)
            await asyncio.gather(*active_tasks, return_exceptions=True)

            # Passive scanners — higher concurrency ok
            passive_total = sum(
                1 for scanner in passive_scanners
                for ep in endpoints
                if scanner.is_applicable(ep)
            )
            passive_task = progress.add_task("Passive scanning...", total=passive_total or 1)
            passive_tasks = []
            for scanner in passive_scanners:
                for ep in endpoints:
                    if scanner.is_applicable(ep):
                        t = asyncio.create_task(run_scanner(scanner, ep, passive_sem))
                        t.add_done_callback(lambda _: progress.advance(passive_task))
                        passive_tasks.append(t)
            await asyncio.gather(*passive_tasks, return_exceptions=True)

            # Host-level scanners
            host_task = progress.add_task(
                "Host-level scans...", total=len(subdomains) * len(host_scanners)
            )
            host_tasks = []
            for scanner in host_scanners:
                for sub in subdomains:
                    t = asyncio.create_task(run_scanner(scanner, sub, passive_sem))
                    t.add_done_callback(lambda _: progress.advance(host_task))
                    host_tasks.append(t)
            await asyncio.gather(*host_tasks, return_exceptions=True)

        console.print(f"  [green]✓[/] {finding_count} findings from Python scanners")

    async def _phase_nuclei(self):
        console.print("\n[bold cyan]Phase 4b: Nuclei Scanning[/]")
        from scanners.nuclei_scanner import NucleiScanner

        live_hosts = await self.db.get_subdomains(self.config.scan_id, live_only=True)
        scanner = NucleiScanner(self.config.tools_dir)

        findings = await scanner.scan(live_hosts)
        for f in findings:
            await self.db.insert_finding(self.config.scan_id, f)
            self._print_finding(f)

        console.print(f"  [green]✓[/] {len(findings)} findings from Nuclei")

    async def _phase_report(self):
        console.print("\n[bold cyan]Phase 5: Generating Report[/]")
        from reporting.report_builder import ReportBuilder
        from reporting.html_renderer import HtmlRenderer

        builder = ReportBuilder(self.db, self.config.scan_id)
        data = await builder.build()

        renderer = HtmlRenderer()
        renderer.render(data, self.config.report_path)
        console.print(f"  [green]✓[/] Dashboard saved: [cyan]{self.config.report_path}[/]")

    def _print_finding(self, f: Finding):
        color = SEVERITY_COLORS.get(f.severity, "white")
        url_short = f.url[:60] + "..." if len(f.url) > 60 else f.url
        console.print(
            f"  [{color}][{f.severity}][/] {f.finding_type} | {url_short}"
            + (f" | param={f.parameter}" if f.parameter else "")
        )
