import pytest
from kevvy.cve_monitor import CVEMonitor

# We don't need actual clients for testing find_cves
@pytest.fixture
def monitor():
    # Create a CVEMonitor instance for testing
    # Pass None for clients as they aren't used by find_cves
    return CVEMonitor(nvd_client=None, kev_client=None)

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