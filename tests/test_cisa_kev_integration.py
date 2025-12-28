"""
Integration tests for CISA KEV API connectivity and response parsing.

These tests make real HTTP requests to the CISA KEV API.
Run with: CISA_KEV_LIVE_TESTS=1 poetry run pytest tests/test_cisa_kev_integration.py -v
Skip with: poetry run pytest -m "not integration"
"""

import os
import pytest
import pytest_asyncio
import aiohttp
from kevvy.cisa_kev_client import CisaKevClient
from unittest.mock import MagicMock

# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def skip_unless_live_tests_enabled():
    """Skip all tests in this module unless CISA_KEV_LIVE_TESTS=1 is set."""
    if os.getenv("CISA_KEV_LIVE_TESTS") != "1":
        pytest.skip(
            "CISA_KEV_LIVE_TESTS not set to '1'; skipping live CISA KEV API tests"
        )


@pytest_asyncio.fixture
async def real_http_session():
    """Create a real aiohttp session for integration tests."""
    async with aiohttp.ClientSession() as session:
        yield session


@pytest.fixture
def mock_db():
    """Mock database that returns empty seen KEVs."""
    db = MagicMock()
    db.load_seen_kevs.return_value = set()
    db.add_seen_kevs = MagicMock()
    return db


@pytest.mark.asyncio
async def test_cisa_kev_api_connectivity(real_http_session):
    """Test that we can connect to the CISA KEV API and get a valid response."""
    async with real_http_session.get(
        CisaKevClient.KEV_CATALOG_URL,
        headers=CisaKevClient.HEADERS,
        timeout=aiohttp.ClientTimeout(total=30),
    ) as response:
        assert response.status == 200, f"Expected 200, got {response.status}"
        assert (
            response.content_type == "application/json"
        ), f"Expected application/json, got {response.content_type}"


@pytest.mark.asyncio
async def test_cisa_kev_api_response_structure(real_http_session):
    """Test that the API response has the expected top-level structure."""
    async with real_http_session.get(
        CisaKevClient.KEV_CATALOG_URL,
        headers=CisaKevClient.HEADERS,
        timeout=aiohttp.ClientTimeout(total=30),
    ) as response:
        data = await response.json()

        # Check required top-level fields per schema
        assert "catalogVersion" in data, "Missing catalogVersion"
        assert "dateReleased" in data, "Missing dateReleased"
        assert "count" in data, "Missing count"
        assert "vulnerabilities" in data, "Missing vulnerabilities"

        # Validate types
        assert isinstance(data["catalogVersion"], str)
        assert isinstance(data["dateReleased"], str)
        assert isinstance(data["count"], int)
        assert isinstance(data["vulnerabilities"], list)

        # Sanity check - should have many vulnerabilities
        assert data["count"] > 1000, f"Expected >1000 KEVs, got {data['count']}"
        assert (
            len(data["vulnerabilities"]) == data["count"]
        ), f"Count mismatch: {data['count']} vs {len(data['vulnerabilities'])}"


@pytest.mark.asyncio
async def test_cisa_kev_vulnerability_schema(real_http_session):
    """Test that vulnerability entries have all required fields."""
    async with real_http_session.get(
        CisaKevClient.KEV_CATALOG_URL,
        headers=CisaKevClient.HEADERS,
        timeout=aiohttp.ClientTimeout(total=30),
    ) as response:
        data = await response.json()

        # Required fields per CISA schema
        required_fields = [
            "cveID",
            "vendorProject",
            "product",
            "vulnerabilityName",
            "dateAdded",
            "shortDescription",
            "requiredAction",
            "dueDate",
        ]

        # Check first 5 entries for required fields
        for i, vuln in enumerate(data["vulnerabilities"][:5]):
            for field in required_fields:
                assert (
                    field in vuln
                ), f"Vulnerability {i} missing required field: {field}"

            # Validate cveID format
            cve_id = vuln["cveID"]
            assert cve_id.startswith("CVE-"), f"Invalid CVE ID format: {cve_id}"

            # Validate date formats (YYYY-MM-DD)
            assert (
                len(vuln["dateAdded"]) == 10
            ), f"Invalid dateAdded format: {vuln['dateAdded']}"
            assert (
                len(vuln["dueDate"]) == 10
            ), f"Invalid dueDate format: {vuln['dueDate']}"


@pytest.mark.asyncio
async def test_cisa_kev_client_get_full_catalog(real_http_session, mock_db):
    """Test that CisaKevClient can fetch and parse the full catalog."""
    client = CisaKevClient(session=real_http_session, db=mock_db)

    catalog = await client.get_full_kev_catalog()

    assert catalog is not None, "Failed to fetch catalog"
    assert isinstance(catalog, list), f"Expected list, got {type(catalog)}"
    assert len(catalog) > 1000, f"Expected >1000 entries, got {len(catalog)}"

    # Verify first entry structure
    first_entry = catalog[0]
    assert "cveID" in first_entry
    assert "vendorProject" in first_entry
    assert "shortDescription" in first_entry


@pytest.mark.asyncio
async def test_cisa_kev_client_get_kev_entry(real_http_session, mock_db):
    """Test looking up a specific known KEV entry."""
    client = CisaKevClient(session=real_http_session, db=mock_db)

    # Log4j - a well-known KEV that should always exist
    entry = await client.get_kev_entry("CVE-2021-44228")

    assert entry is not None, "CVE-2021-44228 (Log4j) should be in KEV catalog"
    assert entry["cveID"] == "CVE-2021-44228"
    assert "Apache" in entry["vendorProject"] or "Log4j" in entry["vulnerabilityName"]


@pytest.mark.asyncio
async def test_cisa_kev_client_get_nonexistent_entry(real_http_session, mock_db):
    """Test looking up a CVE that doesn't exist in KEV."""
    client = CisaKevClient(session=real_http_session, db=mock_db)

    # Made-up CVE ID that shouldn't exist
    entry = await client.get_kev_entry("CVE-9999-99999")

    assert entry is None, "Non-existent CVE should return None"


@pytest.mark.asyncio
async def test_cisa_kev_client_caching(real_http_session, mock_db):
    """Test that the client caches responses properly."""
    client = CisaKevClient(session=real_http_session, db=mock_db)

    # First fetch - should hit the API
    catalog1 = await client.get_full_kev_catalog()
    cache_time1 = client._cache_time

    # Second fetch - should use cache
    catalog2 = await client.get_full_kev_catalog()
    cache_time2 = client._cache_time

    assert catalog1 is catalog2, "Second fetch should return cached object"
    assert cache_time1 == cache_time2, "Cache time should not change"


@pytest.mark.asyncio
async def test_fields_used_by_embed_generation(real_http_session, mock_db):
    """Test that all fields used by _create_kev_embed are present in API response."""
    client = CisaKevClient(session=real_http_session, db=mock_db)
    catalog = await client.get_full_kev_catalog()

    # Fields used by TasksCog._create_kev_embed()
    embed_fields = [
        "cveID",
        "shortDescription",
        "vulnerabilityName",
        "vendorProject",
        "product",
        "dateAdded",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
        # "notes" is optional, checked separately
    ]

    # Check first 10 entries
    for i, vuln in enumerate(catalog[:10]):
        for field in embed_fields:
            assert (
                field in vuln
            ), f"Entry {i} ({vuln.get('cveID', 'unknown')}) missing field: {field}"

    # Notes is optional but should be handled gracefully
    # At least some entries should have notes
    entries_with_notes = sum(1 for v in catalog[:100] if v.get("notes"))
    assert entries_with_notes > 0, "Expected some entries to have notes field"
