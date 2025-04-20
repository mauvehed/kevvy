import vulners
from typing import Optional, Dict
import logging

class VulnersClient:
    def __init__(self, api_key: str):
        self.api = vulners.Vulners(api_key=api_key)

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        try:
            # Search for the specific CVE
            results = self.api.search(f"id:{cve_id}")
            
            if not results:
                return None
                
            # Get the first result which should be our CVE
            cve_data = results[0]
            
            return {
                'id': cve_data.get('id'),
                'title': cve_data.get('title'),
                'description': cve_data.get('description'),
                'published': cve_data.get('published'),
                'modified': cve_data.get('modified'),
                'cvss': cve_data.get('cvss', {}).get('score'),
                'link': f"https://vulners.com/{cve_data.get('type')}/{cve_data.get('id')}"
            }
        except Exception as e:
            logging.error(f"Error fetching CVE details for {cve_id}: {e}", exc_info=True)
            return None 