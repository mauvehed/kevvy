import pytest
import discord
import asyncio
from unittest.mock import AsyncMock, MagicMock, PropertyMock
from datetime import datetime, timezone
from collections import defaultdict
import aiohttp
import sys
from types import ModuleType

# Mock the vulncheck_sdk module to avoid dependency issues in tests
mock_vulncheck_sdk = ModuleType("vulncheck_sdk")
sys.modules["vulncheck_sdk"] = mock_vulncheck_sdk

from kevvy.nvd_client import NVDClient, NVDRateLimitError
from kevvy.bot import SecurityBot
from kevvy.db_utils import KEVConfigDB
from kevvy.cve_monitor import CVEMonitor
from kevvy.cisa_kev_client import CisaKevClient

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


@pytest.fixture
def mock_message(mocker):
    """Fixture for a mocked discord.Message object."""
    message = AsyncMock(spec=discord.Message)
    message.author = AsyncMock(spec=discord.User)
    message.author.bot = False  # Assume user message by default
    message.guild = AsyncMock(spec=discord.Guild)
    message.guild.id = 12345
    message.channel = AsyncMock(spec=discord.TextChannel)
    message.channel.id = 67890
    message.channel.send = AsyncMock()
    message.content = ""  # Default empty content
    message.id = 99999
    return message


@pytest.fixture
def mock_db(mocker):
    """Fixture for a mocked KEVConfigDB object."""
    db = MagicMock(spec=KEVConfigDB)
    # Default behavior: Monitoring enabled, threshold 'all', non-verbose
    db.get_cve_guild_config.return_value = {
        "enabled": True,
        "severity_threshold": "all",
        "verbose_mode": False,
    }
    db.get_cve_channel_config.return_value = {
        "enabled": True,
        "verbose_mode": None,
    }  # Channel enabled, no verbosity override
    db.get_effective_verbosity.return_value = False  # Defaults to global False
    return db


@pytest.fixture
def mock_cve_monitor(mocker):
    """Fixture for a mocked CVEMonitor object."""
    monitor = MagicMock(spec=CVEMonitor)
    monitor.CVE_REGEX = CVEMonitor.CVE_REGEX  # Use the real regex
    monitor.find_cves.side_effect = lambda content: CVEMonitor.CVE_REGEX.findall(
        content
    )  # Use real find_cves
    monitor.get_cve_data = AsyncMock(return_value=None)  # Default: No data found
    monitor.check_severity_threshold.return_value = (
        True,
        "High",
    )  # Default: Passes threshold
    monitor.create_cve_embed = MagicMock(
        return_value=discord.Embed(title="Mock CVE Embed")
    )
    monitor.check_kev.return_value = None  # Default: Not in KEV
    monitor.create_kev_status_embed = MagicMock(
        return_value=discord.Embed(title="Mock KEV Embed")
    )
    return monitor


@pytest.fixture
def mock_cisa_kev_client(mocker):
    """Fixture for a mocked CisaKevClient object."""
    client = AsyncMock(spec=CisaKevClient)
    client.get_new_kev_entries = AsyncMock(return_value=[])  # Default: No new entries
    return client


@pytest.fixture
def mock_stats_manager(mocker):
    """Fixture for a mocked StatsManager object."""
    stats_manager = MagicMock()
    stats_manager.increment_messages_processed = AsyncMock()
    stats_manager.increment_cve_lookups = AsyncMock()
    stats_manager.increment_nvd_fallback_success = AsyncMock()
    stats_manager.record_api_error = AsyncMock()
    stats_manager.record_nvd_rate_limit_hit = AsyncMock()
    stats_manager.increment_kev_alerts_sent = AsyncMock()
    return stats_manager


@pytest.fixture
def mock_bot(mocker, mock_db, mock_cve_monitor, mock_stats_manager):
    """Fixture for a mocked SecurityBot instance with mocked dependencies."""
    bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    bot.db = mock_db
    bot.cve_monitor = mock_cve_monitor
    bot.http_session = AsyncMock(spec=aiohttp.ClientSession)
    bot.stats_lock = asyncio.Lock()
    bot.start_time = datetime.now(timezone.utc)
    bot.stats_manager = mock_stats_manager  # Add the stats manager

    # Support legacy attributes for backward compatibility with tests
    bot.stats_cve_lookups = 0
    bot.stats_kev_alerts_sent = 0
    bot.stats_messages_processed = 0
    bot.stats_vulncheck_success = 0
    bot.stats_nvd_fallback_success = 0
    bot.stats_api_errors_vulncheck = 0
    bot.stats_api_errors_nvd = 0
    bot.stats_api_errors_cisa = 0
    bot.stats_api_errors_kev = 0
    bot.stats_rate_limits_nvd = 0
    bot.stats_rate_limits_hit_nvd = 0
    bot.stats_app_command_errors = defaultdict(int)

    mock_user = AsyncMock(spec=discord.ClientUser)
    mock_user.id = 987654321
    mock_user.name = "TestBot"
    mocker.patch.object(
        SecurityBot, "user", new_callable=PropertyMock, return_value=mock_user
    )

    # Add the direct on_message method for tests (similar to CoreEventsCog implementation)
    async def mock_on_message(message):
        if message.author.bot:
            return
        if not message.guild:
            return

        # Increment message processed using StatsManager
        await bot.stats_manager.increment_messages_processed()
        # Also increment legacy counter for backward compatibility with tests
        bot.stats_messages_processed += 1

        # Find potential CVEs in the message
        potential_cves = bot.cve_monitor.find_cves(message.content)
        if not potential_cves:
            return

        guild_id = message.guild.id
        channel_id = message.channel.id

        guild_config = bot.db.get_cve_guild_config(guild_id)
        if not guild_config or not guild_config.get("enabled"):
            return

        channel_config = bot.db.get_cve_channel_config(guild_id, channel_id)
        if not channel_config or not channel_config.get("enabled"):
            return

        # Process each unique CVE
        unique_cves = sorted(list(set(potential_cves)))
        now = datetime.now(timezone.utc)

        processed_count = 0
        max_embeds = getattr(bot, "MAX_EMBEDS_PER_MESSAGE", 5)

        for cve_id in unique_cves:
            if processed_count >= max_embeds:
                break  # Stop processing if hit the max embed limit

            # Skip if recently processed
            cache_key = (channel_id, cve_id)
            if cache_key in bot.recently_processed_cves:
                continue

            # Get CVE data and increment counter
            await bot.stats_manager.increment_cve_lookups()
            # Legacy counter for backward compatibility with tests
            bot.stats_cve_lookups += 1

            try:
                cve_data = await bot.cve_monitor.get_cve_data(cve_id)
                if not cve_data:
                    continue

                # Record successful lookup
                await bot.stats_manager.increment_nvd_fallback_success()
                # Legacy counter for backward compatibility with tests
                bot.stats_nvd_fallback_success += 1

                # Check severity threshold
                min_severity = guild_config.get("severity_threshold", "all")
                passes_threshold, _ = bot.cve_monitor.check_severity_threshold(
                    cve_data, threshold=min_severity
                )
                if not passes_threshold:
                    continue

                # Get verbosity setting
                is_verbose = bot.db.get_effective_verbosity(guild_id, channel_id)

                # Create and send embed
                cve_embed = bot.cve_monitor.create_cve_embed(
                    cve_data, verbose=is_verbose
                )
                try:
                    await message.channel.send(embed=cve_embed)

                    # Only add to cache and increment processed count if successfully sent
                    bot.recently_processed_cves[cache_key] = now
                    processed_count += 1

                    # Only check KEV status after successfully sending the first embed
                    kev_data = None
                    try:
                        kev_data = await bot.cve_monitor.check_kev(cve_id)
                    except Exception:
                        # Record KEV API error using StatsManager
                        await bot.stats_manager.record_api_error("kev")
                        # Legacy counter for backward compatibility with tests
                        bot.stats_api_errors_kev += 1

                    # Send KEV status if available
                    if kev_data:
                        kev_embed = bot.cve_monitor.create_kev_status_embed(
                            cve_id, kev_data, verbose=is_verbose
                        )
                        await message.channel.send(embed=kev_embed)

                except (discord.Forbidden, discord.HTTPException):
                    # Exit the loop early on Discord errors
                    break

            except NVDRateLimitError:
                # Record rate limit hit
                await bot.stats_manager.record_nvd_rate_limit_hit()
                # Legacy stats
                bot.stats_rate_limits_hit_nvd += 1
                bot.stats_api_errors_nvd += 1
                # Exit the loop early on rate limit
                break

            except Exception:
                # Record API error for other exceptions
                await bot.stats_manager.record_api_error("nvd")
                # Legacy stats
                bot.stats_api_errors_nvd += 1
                continue

    bot.on_message = mock_on_message
    bot.loaded_cogs = []
    bot.failed_cogs = []
    bot.timestamp_last_kev_check_success = None
    bot.timestamp_last_kev_alert_sent = None
    bot.recently_processed_cves = {}
    bot.RECENT_CVE_CACHE_SECONDS = 20  # Add the same cache duration

    return bot
