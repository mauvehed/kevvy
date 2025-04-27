import pytest
from unittest.mock import AsyncMock
import discord # Add discord import for Color

from kevvy.cve_monitor import CVEMonitor

# We don't need actual clients for testing find_cves
# @pytest.fixture
# def monitor():
#     # Create a CVEMonitor instance for testing
#     # Pass None for clients as they aren't used by find_cves
#     return CVEMonitor(nvd_client=None, kev_client=None)

# --- Fixtures ---

@pytest.fixture
def mock_nvd_client():
    return AsyncMock()

@pytest.fixture
def mock_kev_client():
    return AsyncMock()

@pytest.fixture
def monitor(mock_nvd_client, mock_kev_client):
    # This fixture is now used for all tests needing a monitor instance
    return CVEMonitor(nvd_client=mock_nvd_client, kev_client=mock_kev_client)

# Sample CVE data for testing embeds
SAMPLE_CVE_DATA = {
    'id': 'CVE-2024-12345',
    'title': 'Test Vulnerability',
    'link': 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
    'description': 'This is a detailed test description.',
    'cvss': 7.5,
    'cvss_version': '3.1 (HIGH)',
    'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    'cwe_ids': ['CWE-79'],
    'published': '2024-01-01T10:00:00',
    'modified': '2024-01-02T11:00:00',
    'references': [{'url': 'https://example.com/ref1', 'source': 'Example', 'tags': ['Patch']}],
    'source': 'NVD'
}

SAMPLE_KEV_DATA = {
    'cveID': 'CVE-2024-12345',
    'shortDescription': 'KEV Description.',
    'vulnerabilityName': 'Test KEV Vuln',
    'vendorProject': 'TestVendor',
    'product': 'TestProduct',
    'dateAdded': '2024-01-10',
    'requiredAction': 'Apply patch.',
    'dueDate': '2024-01-31',
    'knownRansomwareCampaignUse': 'No',
    'notes': 'Some notes here.'
}

# --- Test Cases for find_cves --- 

@pytest.mark.parametrize(
    "message_content, expected_cves",
    [
        # Basic cases
        ("Check out CVE-2023-12345", ["CVE-2023-12345"]),
        ("Potential issue: cve-2024-9876", ["cve-2024-9876"]),
        ("Multiple CVEs: CVE-2022-0001 and CVE-2022-0002", ["CVE-2022-0001", "CVE-2022-0002"]),
        # Case insensitivity
        ("cVe-2021-54321 reported", ["cVe-2021-54321"]),
        # No CVEs
        ("This is a normal message without any identifiers.", []),
        ("Almost a CVE-2023- but not quite", []),
        # CVEs with surrounding punctuation
        ("Patched (CVE-2024-1111).", ["CVE-2024-1111"]),
        ("Is CVE-2024-2222 the issue?", ["CVE-2024-2222"]),
        ("Found CVE-2024-3333!", ["CVE-2024-3333"]),
        # Mixed case and duplicates (should return unique based on input casing)
        ("Look at CVE-2023-1000 and cve-2023-1000", ["CVE-2023-1000", "cve-2023-1000"]),
        # Edge cases
        ("CVE-2023-1234", ["CVE-2023-1234"]), # 4-digit year, 4-digit sequence
        ("CVE-1999-99999", ["CVE-1999-99999"]), # Older year, longer sequence
        ("Text with CVE-2023-00001 inside", ["CVE-2023-00001"]),
        # Ensure it doesn't match invalid formats
        ("Not a CVE-202-12345", []),
        ("Not a CVE-20230-1234", []),
        ("Not a CVE-2023-123", []),
    ]
)
def test_find_cves(monitor: CVEMonitor, message_content: str, expected_cves: list[str]):
    """Test the find_cves method with various message formats."""
    actual_cves = monitor.find_cves(message_content)
    # We compare lists directly - order matters and duplicates matter based on input casing
    assert actual_cves == expected_cves

# --- NEW Test Cases for create_cve_embed (verbose) ---

@pytest.mark.asyncio
async def test_create_cve_embed_non_verbose(monitor: CVEMonitor, mock_kev_client):
    """Test the non-verbose embed format."""
    mock_kev_client.get_kev_entry.return_value = None # Assume not in KEV for simplicity
    
    embeds = await monitor.create_cve_embed(SAMPLE_CVE_DATA, verbose=False)
    
    assert len(embeds) == 1
    embed = embeds[0]
    
    # Check essential fields are present
    assert embed.title == SAMPLE_CVE_DATA['title']
    assert embed.url == SAMPLE_CVE_DATA['link']
    assert embed.color.value == 0xFF8C00 # Compare .value
    assert len(embed.fields) == 2 # Only CVE ID and CVSS Score
    assert embed.fields[0].name == "CVE ID" and embed.fields[0].value == SAMPLE_CVE_DATA['id']
    assert embed.fields[1].name == "CVSS Score" and embed.fields[1].value == f"{SAMPLE_CVE_DATA['cvss']} (v{SAMPLE_CVE_DATA['cvss_version']})"
    assert embed.description == f"[View on NVD]({SAMPLE_CVE_DATA['link']})"
    assert embed.footer.text == f"Data via {SAMPLE_CVE_DATA['source']}"

@pytest.mark.asyncio
async def test_create_cve_embed_verbose(monitor: CVEMonitor, mock_kev_client):
    """Test the verbose embed format."""
    mock_kev_client.get_kev_entry.return_value = None
    
    embeds = await monitor.create_cve_embed(SAMPLE_CVE_DATA, verbose=True)
    
    assert len(embeds) == 1
    embed = embeds[0]
    
    # Check essential fields
    assert embed.title == SAMPLE_CVE_DATA['title']
    assert embed.url == SAMPLE_CVE_DATA['link']
    assert embed.description == SAMPLE_CVE_DATA['description']
    assert embed.color.value == 0xFF8C00 # Compare .value
    
    # Check all expected verbose fields are present
    assert len(embed.fields) >= 6 # ID, Score, Published, Modified, Vector, CWE, References (if present)
    field_names = [f.name for f in embed.fields]
    assert "CVE ID" in field_names
    assert "CVSS Score" in field_names
    assert "Published" in field_names
    assert "Last Modified" in field_names
    assert "CVSS Vector" in field_names
    assert "Weaknesses (CWE)" in field_names
    assert "References" in field_names
    assert embed.footer.text == f"Data via {SAMPLE_CVE_DATA['source']}"

@pytest.mark.asyncio
async def test_create_cve_embed_with_kev_non_verbose(monitor: CVEMonitor, mock_kev_client):
    """Test non-verbose embed when KEV entry exists."""
    mock_kev_client.get_kev_entry.return_value = SAMPLE_KEV_DATA
    
    embeds = await monitor.create_cve_embed(SAMPLE_CVE_DATA, verbose=False)
    
    assert len(embeds) == 2
    
    # Check CVE embed (should be non-verbose)
    cve_embed = embeds[0]
    assert len(cve_embed.fields) == 2
    assert cve_embed.description == f"[View on NVD]({SAMPLE_CVE_DATA['link']})"

    # Check KEV embed (should be terse)
    kev_embed = embeds[1]
    assert kev_embed.title == f"🚨 CISA KEV Alert: {SAMPLE_KEV_DATA['cveID']}"
    assert kev_embed.description == f"This vulnerability is listed in the CISA KEV catalog.\n[View on NVD](https://nvd.nist.gov/vuln/detail/{SAMPLE_KEV_DATA['cveID']})"
    assert len(kev_embed.fields) == 0 # Terse KEV has no fields
    assert kev_embed.footer.text == "Source: CISA KEV Catalog"

@pytest.mark.asyncio
async def test_create_cve_embed_with_kev_verbose(monitor: CVEMonitor, mock_kev_client):
    """Test verbose embed when KEV entry exists."""
    mock_kev_client.get_kev_entry.return_value = SAMPLE_KEV_DATA
    
    embeds = await monitor.create_cve_embed(SAMPLE_CVE_DATA, verbose=True)
    
    assert len(embeds) == 2
    
    # Check CVE embed (should be verbose)
    cve_embed = embeds[0]
    assert len(cve_embed.fields) >= 6
    assert cve_embed.description == SAMPLE_CVE_DATA['description']

    # Check KEV embed (should be detailed)
    kev_embed = embeds[1]
    assert kev_embed.title == f"🚨 CISA KEV Alert: {SAMPLE_KEV_DATA['cveID']}"
    assert kev_embed.description == SAMPLE_KEV_DATA['shortDescription']
    assert len(kev_embed.fields) >= 6 # Detailed KEV has multiple fields
    assert kev_embed.footer.text == "Source: CISA KEV Catalog" 