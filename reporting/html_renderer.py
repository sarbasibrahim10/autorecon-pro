from __future__ import annotations
import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


class HtmlRenderer:
    def __init__(self):
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def render(self, data: dict, output_path: Path):
        template = self.env.get_template("dashboard.html.j2")
        # Embed data as JSON for JS
        data["findings_json"] = json.dumps(data["findings"])
        data["subdomains_json"] = json.dumps(data["subdomains"])
        data["type_dist_json"] = json.dumps(data["type_distribution"])
        data["top_subs_json"] = json.dumps(data["top_subdomains_by_findings"])
        html = template.render(**data)
        Path(output_path).write_text(html, encoding="utf-8")
