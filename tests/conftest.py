import pytest
import aiohttp
from unittest.mock import AsyncMock

from kevvy.nvd_client import NVDClient

# Sample NVD API response structure for a single CVE
SAMPLE_NVD_RESPONSE_DATA = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-04-29T12:00:00.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-12345",
                "sourceIdentifier": "test@example.com",
                "published": "2024-04-20T10:00:00.000",
                "lastModified": "2024-04-28T15:30:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "This is a test vulnerability description.",
                    },
                    {
                        "lang": "es",
                        "value": "Esta es una descripción de vulnerabilidad de prueba.",
                    },
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "test@example.com",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9,
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "test@example.com",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-79"}],
                    }
                ],
                "configurations": [],
                "references": [
                    {
                        "url": "http://example.com/ref1",
                        "source": "test@example.com",
                        "tags": ["Vendor Advisory"],
                    },
                    {"url": "http://example.com/ref2", "source": "other@example.com"},
                ],
            }
        }
    ],
}


@pytest.fixture(
    scope="session"
)  # Add fixture decorator, scope=session is typical for constant data
def SAMPLE_NVD_RESPONSE():
    """Provides the sample NVD API response data."""
    return SAMPLE_NVD_RESPONSE_DATA


@pytest.fixture
def mock_session():
    """Fixture for a mocked aiohttp.ClientSession."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    session.get = AsyncMock()  # Mock the .get method
    return session


@pytest.fixture
def nvd_client(mock_session):
    """Fixture for an NVDClient instance with a mocked session."""
    client = NVDClient(
        session=mock_session, api_key="test-api-key"
    )  # Use API key for faster retry tests
    # Patch the internal sleep to speed up retry tests
    client._sleep = AsyncMock()
    return client
