import re
import discord
from datetime import datetime
# from .vulners_client import VulnersClient # Removed VulnersClient
from .nvd_client import NVDClient # Added NVDClient

class CVEMonitor:
    # def __init__(self, vulners_client: VulnersClient):
    def __init__(self, nvd_client: NVDClient): # Updated type hint
        # self.vulners_client = vulners_client
        self.nvd_client = nvd_client # Store NVD client
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    def find_cves(self, content: str) -> list:
        return self.cve_pattern.findall(content)

    def create_cve_embed(self, cve_data: dict) -> discord.Embed:
        # Use NVD data fields
        embed = discord.Embed(
            title=cve_data['title'], # NVD provides a less descriptive title
            url=cve_data['link'],
            description=cve_data['description'][:2048] if cve_data['description'] else "No description available",
            color=self._get_severity_color(cve_data.get('cvss')) # Use .get for safety
        )
        
        cvss_score_display = str(cve_data.get('cvss') or "N/A")
        if cve_data.get('cvss_version'):
            cvss_score_display += f" (v{cve_data['cvss_version']})"

        embed.add_field(name="CVE ID", value=cve_data['id'], inline=True)
        # embed.add_field(name="CVSS Score", value=str(cve_data['cvss'] or "N/A"), inline=True)
        embed.add_field(name="CVSS Score", value=cvss_score_display, inline=True)
        embed.add_field(name="Published", value=self._format_date(cve_data['published']), inline=True)
        embed.add_field(name="Last Modified", value=self._format_date(cve_data.get('modified')), inline=True) # Add modified date
        
        # embed.set_footer(text="Data provided by Vulners.com") # Update footer
        source = cve_data.get('source', 'N/A')
        embed.set_footer(text=f"Data provided by {source}")
        return embed

    def _get_severity_color(self, cvss: float | None) -> int:
        if cvss is None:
            return 0x808080  # Gray for unknown
        elif cvss >= 9.0:
            return 0xFF0000  # Red for critical
        elif cvss >= 7.0:
            return 0xFF8C00  # Orange for high
        elif cvss >= 4.0:
            return 0xFFFF00  # Yellow for medium
        else:
            return 0x00FF00  # Green for low

    def _format_date(self, date_str: str | None) -> str:
        if not date_str:
            return "N/A"
        try:
            # NVDClient now provides YYYY-MM-DDTHH:MM:SS format
            date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
            return date.strftime('%B %d, %Y')
        except ValueError:
            # Fallback for unexpected format or if original string was kept
            try:
                date = datetime.strptime(date_str.split('T')[0], '%Y-%m-%d')
                return date.strftime('%B %d, %Y')
            except Exception:
                return date_str # Return original string if all parsing fails 