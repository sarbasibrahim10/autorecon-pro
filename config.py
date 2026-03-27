from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import uuid


@dataclass
class Config:
    target: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    output_dir: Path = Path("./reports")
    concurrency: int = 50
    timeout: int = 10
    rps: float = 10.0
    max_crawl_depth: int = 3
    max_urls_per_host: int = 500
    resume: bool = False
    enabled_scanners: list[str] = field(default_factory=lambda: ["all"])
    nuclei_enabled: bool = True

    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        self.scan_dir = self.output_dir / self.scan_id
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.scan_dir / "scan.db"
        self.report_path = self.scan_dir / "dashboard.html"
        self.tools_dir = Path(__file__).parent / "tools"
        self.tools_dir.mkdir(exist_ok=True)
