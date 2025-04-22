import re
import discord
import logging
from datetime import datetime
# from .vulners_client import VulnersClient # Removed VulnersClient
from .nvd_client import NVDClient # Added NVDClient
from .cisa_kev_client import CisaKevClient
from typing import Optional, List, Dict, Any

# Max length for embed fields
MAX_FIELD_LENGTH = 1024
MAX_REFERENCE_LINKS = 5

logger = logging.getLogger(__name__)

class CVEMonitor:
    # def __init__(self, vulners_client: VulnersClient):
    def __init__(self, nvd_client: NVDClient, kev_client: Optional[CisaKevClient] = None):
        # self.vulners_client = vulners_client
        self.nvd_client = nvd_client # Store NVD client
        self.kev_client = kev_client
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    def find_cves(self, content: str) -> list:
        return self.cve_pattern.findall(content)

    async def create_cve_embed(self, cve_data: dict) -> List[discord.Embed]:
        """Creates Discord embeds for a CVE, including KEV information if available."""
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

        embeds = [embed]

        # Check for KEV entry if client is available
        if self.kev_client:
            try:
                kev_entry = await self.kev_client.get_kev_entry(cve_data['id'])
                if kev_entry:
                    kev_embed = discord.Embed(
                        title=f"🚨 CISA KEV Alert: {cve_data['id']}",
                        description=kev_entry.get('shortDescription', 'No description available.'),
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_data['id']}",
                        color=discord.Color.dark_red()
                    )
                    
                    kev_embed.add_field(name="Vulnerability Name", value=kev_entry.get('vulnerabilityName', 'N/A'), inline=False)
                    kev_embed.add_field(name="Vendor/Project", value=kev_entry.get('vendorProject', 'N/A'), inline=True)
                    kev_embed.add_field(name="Product", value=kev_entry.get('product', 'N/A'), inline=True)
                    kev_embed.add_field(name="Date Added", value=kev_entry.get('dateAdded', 'N/A'), inline=True)
                    kev_embed.add_field(name="Required Action", value=kev_entry.get('requiredAction', 'N/A'), inline=False)
                    kev_embed.add_field(name="Due Date", value=kev_entry.get('dueDate', 'N/A'), inline=True)
                    kev_embed.add_field(name="Known Ransomware Use", value=kev_entry.get('knownRansomwareCampaignUse', 'N/A'), inline=True)

                    if notes := kev_entry.get('notes', ''):
                        notes_display = notes[:1020] + '...' if len(notes) > 1024 else notes
                        kev_embed.add_field(name="Notes", value=notes_display, inline=False)

                    kev_embed.set_footer(text="Source: CISA Known Exploited Vulnerabilities Catalog")
                    embeds.append(kev_embed)
            except Exception as e:
                logger.error(f"Error checking KEV status for {cve_data['id']}: {e}", exc_info=True)

        return embeds

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