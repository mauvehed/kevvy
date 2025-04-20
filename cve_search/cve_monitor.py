import re
import discord
from datetime import datetime
# from .vulners_client import VulnersClient # Removed VulnersClient
from .nvd_client import NVDClient # Added NVDClient

# Max length for embed fields
MAX_FIELD_LENGTH = 1024
MAX_REFERENCE_LINKS = 5

class CVEMonitor:
    # def __init__(self, vulners_client: VulnersClient):
    def __init__(self, nvd_client: NVDClient): # Updated type hint
        # self.vulners_client = vulners_client
        self.nvd_client = nvd_client # Store NVD client
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    def find_cves(self, content: str) -> list:
        return self.cve_pattern.findall(content)

    def create_cve_embed(self, cve_data: dict) -> discord.Embed:
        description = cve_data.get('description', "No description available.")
        # Ensure description fits within embed limits (2048 for description itself)
        if len(description) > 2048:
            description = description[:2045] + "..."
        
        embed = discord.Embed(
            title=cve_data.get('title', cve_data['id']), # Fallback title to CVE ID
            url=cve_data.get('link'),
            description=description,
            color=self._get_severity_color(cve_data.get('cvss'))
        )

        # Basic Info
        embed.add_field(name="CVE ID", value=cve_data['id'], inline=True)
        embed.add_field(name="Published", value=self._format_date(cve_data.get('published')), inline=True)
        embed.add_field(name="Last Modified", value=self._format_date(cve_data.get('modified')), inline=True)

        # CVSS Info
        cvss_score_display = str(cve_data.get('cvss') or "N/A")
        if cve_data.get('cvss_version'):
            cvss_score_display += f" (v{cve_data['cvss_version']})"
        embed.add_field(name="CVSS Score", value=cvss_score_display, inline=True)
        
        cvss_vector = cve_data.get('cvss_vector')
        if cvss_vector:
            # Ensure vector fits in field value (max 1024)
            if len(cvss_vector) > MAX_FIELD_LENGTH:
                 cvss_vector = cvss_vector[:MAX_FIELD_LENGTH - 3] + "..."
            embed.add_field(name="CVSS Vector", value=f"`{cvss_vector}`", inline=False) 

        # CWE Info
        cwe_ids = cve_data.get('cwe_ids')
        if cwe_ids:
            cwe_display = ", ".join(cwe_ids)
            # Ensure CWEs fit in field value
            if len(cwe_display) > MAX_FIELD_LENGTH:
                cwe_display = cwe_display[:MAX_FIELD_LENGTH - 3] + "..."
            embed.add_field(name="Weaknesses (CWE)", value=cwe_display, inline=False)

        # References
        references = cve_data.get('references', [])
        if references:
            ref_links = []
            count = 0
            for ref in references:
                if ref.get('url') and count < MAX_REFERENCE_LINKS:
                    # Simple link format, could add tags later if needed
                    link = f"- [{ref.get('source', 'Link')}]({ref['url']})"
                    ref_links.append(link)
                    count += 1
            
            if ref_links:
                ref_display = "\n".join(ref_links)
                if len(references) > MAX_REFERENCE_LINKS:
                    ref_display += f"\n*({len(references) - MAX_REFERENCE_LINKS} more references not shown)*"
                
                # Ensure references fit
                if len(ref_display) > MAX_FIELD_LENGTH:
                    ref_display = ref_display[:MAX_FIELD_LENGTH - 3] + "..."
                embed.add_field(name="References", value=ref_display, inline=False)

        source = cve_data.get('source', 'N/A')
        embed.set_footer(text=f"Data provided by {source}")
        return embed

    def _get_severity_color(self, cvss: float | None) -> int:
        if cvss is None:
            return 0x808080  # Gray for unknown
        elif cvss >= 9.0:
            return 0xFF0000  # Critical
        elif cvss >= 7.0:
            return 0xFF8C00  # High
        elif cvss >= 4.0:
            return 0xFFFF00  # Medium
        else:
            return 0x00FF00  # Low

    def _format_date(self, date_str: str | None) -> str:
        if not date_str:
            return "N/A"
        # Try parsing the expected format first
        try:
            date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
            return date.strftime('%B %d, %Y')
        except ValueError:
            # Fallback for just date part if full parsing failed (e.g., if NVDClient returned original string)
            try:
                date_part = date_str.split('T')[0]
                date = datetime.strptime(date_part, '%Y-%m-%d')
                return date.strftime('%B %d, %Y')
            except Exception:
                # If all else fails, return the original string
                return date_str 