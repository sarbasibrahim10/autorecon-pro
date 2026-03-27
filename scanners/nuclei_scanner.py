from __future__ import annotations
import asyncio
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Optional
import httpx
from core.models import Finding, Subdomain

GITHUB_RELEASES = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"


class NucleiScanner:
    def __init__(self, tools_dir: Path):
        self.tools_dir = tools_dir
        self._nuclei_bin: Optional[str] = None

    async def scan(self, hosts: list[Subdomain]) -> list[Finding]:
        if not hosts:
            return []

        bin_path = await self._ensure_nuclei()
        if not bin_path:
            print("  [!] Nuclei not available — skipping")
            return []

        # Write live hosts to temp file
        live_urls = []
        for h in hosts:
            if h.final_url:
                live_urls.append(h.final_url)
            elif h.is_live:
                live_urls.append(f"https://{h.domain}")

        if not live_urls:
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(live_urls))
            hosts_file = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            output_file = f.name

        findings = []
        try:
            cmd = [
                bin_path,
                "-l", hosts_file,
                "-je", output_file,
                "-severity", "critical,high,medium,low,info",
                "-timeout", "10",
                "-bulk-size", "25",
                "-c", "25",
                "-silent",
                "-no-color",
                "-stats",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=1800)  # 30 min max
            except asyncio.TimeoutError:
                proc.kill()

            # Parse JSONL output
            out_path = Path(output_file)
            if out_path.exists():
                for line in out_path.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        f = self._parse_nuclei_finding(data)
                        if f:
                            findings.append(f)
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            print(f"  [!] Nuclei error: {e}")
        finally:
            Path(hosts_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)

        return findings

    def _parse_nuclei_finding(self, data: dict) -> Optional[Finding]:
        try:
            info = data.get("info", {})
            severity_map = {
                "critical": "Critical", "high": "High",
                "medium": "Medium", "low": "Low", "info": "Info",
            }
            severity = severity_map.get(info.get("severity", "info").lower(), "Info")
            url = data.get("matched-at") or data.get("host", "")
            template_id = data.get("template-id", "")
            name = info.get("name", template_id)
            description = info.get("description", "")
            remediation = info.get("remediation", "")
            tags = info.get("tags", [])

            # Extract evidence from matcher output
            evidence_parts = []
            if data.get("matcher-name"):
                evidence_parts.append(f"Matcher: {data['matcher-name']}")
            if data.get("extracted-results"):
                evidence_parts.append(f"Extracted: {', '.join(data['extracted-results'][:3])}")
            if data.get("curl-command"):
                evidence_parts.append(f"cURL: {data['curl-command'][:200]}")

            return Finding(
                finding_type=f"[Nuclei] {name}",
                severity=severity,
                url=url,
                evidence="\n".join(evidence_parts)[:2000],
                poc_curl=data.get("curl-command", "")[:500],
                description=description or f"Nuclei template '{template_id}' matched on {url}",
                remediation=remediation,
                source="nuclei",
                template_id=template_id,
            )
        except Exception:
            return None

    async def _ensure_nuclei(self) -> Optional[str]:
        # Check PATH first
        bin_name = "nuclei.exe" if platform.system() == "Windows" else "nuclei"
        system_bin = shutil.which("nuclei")
        if system_bin:
            self._nuclei_bin = system_bin
            await self._update_templates(system_bin)
            return system_bin

        # Check tools dir
        local_bin = self.tools_dir / bin_name
        if local_bin.exists():
            self._nuclei_bin = str(local_bin)
            await self._update_templates(str(local_bin))
            return str(local_bin)

        # Auto-download
        print("  Nuclei not found — downloading automatically...")
        downloaded = await self._download_nuclei(local_bin)
        if downloaded:
            await self._update_templates(str(local_bin))
            return str(local_bin)

        return None

    async def _download_nuclei(self, dest: Path) -> bool:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
                r = await client.get(GITHUB_RELEASES)
                release = r.json()
                assets = release.get("assets", [])

                system = platform.system().lower()
                machine = platform.machine().lower()

                # Map to nuclei asset naming
                if system == "windows":
                    os_name, arch = "windows", "amd64"
                elif system == "darwin":
                    os_name = "macOS"
                    arch = "arm64" if "arm" in machine else "amd64"
                else:
                    os_name = "linux"
                    arch = "arm64" if "arm" in machine else "amd64"

                # Find matching asset (ZIP)
                asset_url = None
                for asset in assets:
                    name = asset["name"].lower()
                    if os_name.lower() in name and arch in name and name.endswith(".zip"):
                        asset_url = asset["browser_download_url"]
                        break

                if not asset_url:
                    return False

                print(f"  Downloading Nuclei from {asset_url}...")
                r2 = await client.get(asset_url)
                zf = zipfile.ZipFile(BytesIO(r2.content))

                # Extract nuclei binary
                bin_name = "nuclei.exe" if system == "windows" else "nuclei"
                for member in zf.namelist():
                    if member.endswith(bin_name):
                        data = zf.read(member)
                        dest.write_bytes(data)
                        if system != "windows":
                            import os
                            os.chmod(dest, 0o755)
                        print(f"  Nuclei installed at: {dest}")
                        return True

        except Exception as e:
            print(f"  Failed to download Nuclei: {e}")
        return False

    async def _update_templates(self, bin_path: str):
        try:
            proc = await asyncio.create_subprocess_exec(
                bin_path, "-update-templates", "-silent",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=120)
        except Exception:
            pass
