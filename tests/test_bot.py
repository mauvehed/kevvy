import pytest
import discord
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call, PropertyMock
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import logging
import aiohttp
import importlib.metadata
from discord.ext import commands

# Import the bot class and other necessary components
from kevvy.bot import SecurityBot
from kevvy.db_utils import KEVConfigDB
from kevvy.cve_monitor import CVEMonitor, NVDRateLimitError
from kevvy.cisa_kev_client import CisaKevClient

# --- Fixtures ---


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
def mock_bot(mocker, mock_db, mock_cve_monitor):
    """Fixture for a mocked SecurityBot instance with mocked dependencies."""
    # We don't need real API keys for mocked tests
    bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    # Patch dependencies onto the instance BEFORE setup_hook is implicitly called by tests
    bot.db = mock_db
    bot.cve_monitor = mock_cve_monitor
    bot.http_session = AsyncMock()  # Mock the session
    bot.stats_lock = asyncio.Lock()  # Use a real lock
    bot.start_time = datetime.now(timezone.utc)  # Set a start time

    # Prevent background tasks from starting during tests
    mocker.patch.object(bot.check_cisa_kev_feed, "start", return_value=None)
    mocker.patch.object(bot.send_stats_to_webapp, "start", return_value=None)

    # Mock the .user property using PropertyMock
    mock_user = AsyncMock(spec=discord.ClientUser)
    mock_user.id = 987654321
    mock_user.name = "TestBot"
    # Patch the property on the class to affect the instance
    mocker.patch.object(
        SecurityBot, "user", new_callable=PropertyMock, return_value=mock_user
    )

    # Initialize stats (these are instance attributes)
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
    bot.loaded_cogs = []
    bot.failed_cogs = []
    bot.timestamp_last_kev_check_success = None
    bot.timestamp_last_kev_alert_sent = None
    bot.recently_processed_cves = {}  # Initialize cache

    return bot


@pytest.fixture
def mock_bot_with_tasks(mocker, mock_db, mock_cve_monitor, mock_cisa_kev_client):
    """Fixture for a mocked SecurityBot including task-related mocks."""
    # We don't need real API keys for mocked tests
    bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    # Patch dependencies
    bot.db = mock_db
    bot.cve_monitor = mock_cve_monitor
    bot.http_session = AsyncMock()
    bot.stats_lock = asyncio.Lock()
    bot.start_time = datetime.now(timezone.utc)
    bot.cisa_kev_client = mock_cisa_kev_client  # Add mocked KEV client

    # Mock user property
    mock_user = AsyncMock(spec=discord.ClientUser)
    mock_user.id = 987654321
    mock_user.name = "TestBot"
    mocker.patch.object(
        SecurityBot, "user", new_callable=PropertyMock, return_value=mock_user
    )

    # Mock latency property
    mocker.patch.object(
        SecurityBot, "latency", new_callable=PropertyMock, return_value=0.12345
    )

    # Mock discord object getters
    bot.get_guild = MagicMock()
    bot.get_channel = MagicMock()

    # Initialize stats
    bot.stats_cve_lookups = 0
    bot.stats_kev_alerts_sent = 0
    bot.stats_messages_processed = 0
    bot.stats_nvd_fallback_success = 0
    bot.stats_api_errors_cisa = 0
    bot.stats_api_errors_nvd = 0
    bot.stats_api_errors_kev = 0
    bot.stats_rate_limits_hit_nvd = 0
    bot.stats_app_command_errors = defaultdict(int)
    bot.timestamp_last_kev_check_success = None
    bot.timestamp_last_kev_alert_sent = None
    bot.recently_processed_cves = {}

    # Mock the internal embed creation helper too, as the task calls it directly
    bot._create_kev_embed = MagicMock(
        return_value=discord.Embed(title="Mock KEV Task Embed")
    )
    # Add the new helper method to the mock instance explicitly
    bot._post_stats = AsyncMock()  # Add it as an AsyncMock

    return bot


# --- Test Cases ---


@pytest.mark.asyncio
async def test_on_message_ignore_bots(mock_bot, mock_message):
    """Test that messages from bots are ignored."""
    mock_message.author.bot = True

    await mock_bot.on_message(mock_message)

    mock_message.channel.send.assert_not_called()
    mock_bot.cve_monitor.find_cves.assert_not_called()
    assert (
        mock_bot.stats_messages_processed == 0
    )  # Should not increment if ignored early


@pytest.mark.asyncio
async def test_on_message_ignore_dm(mock_bot, mock_message):
    """Test that direct messages are ignored."""
    mock_message.guild = None  # No guild means DM
    mock_message.content = "CVE-2023-1234"

    await mock_bot.on_message(mock_message)

    mock_message.channel.send.assert_not_called()
    mock_bot.cve_monitor.find_cves.assert_not_called()
    assert (
        mock_bot.stats_messages_processed == 0
    )  # Should not increment if ignored early


@pytest.mark.asyncio
async def test_on_message_no_cves(mock_bot, mock_message):
    """Test that messages without CVE patterns are ignored."""
    mock_message.content = "This is a regular message."

    await mock_bot.on_message(mock_message)

    mock_message.channel.send.assert_not_called()
    assert mock_bot.stats_messages_processed == 1
    assert mock_bot.stats_cve_lookups == 0  # No lookup should occur


@pytest.mark.asyncio
async def test_on_message_guild_disabled(mock_bot, mock_message, mock_db):
    """Test scenario where global monitoring is disabled for the guild."""
    mock_message.content = "CVE-2023-1234"
    mock_db.get_cve_guild_config.return_value = {
        "enabled": False
    }  # Override default mock

    await mock_bot.on_message(mock_message)

    mock_message.channel.send.assert_not_called()
    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_not_called()  # Should exit before checking channel
    assert mock_bot.stats_messages_processed == 1
    assert mock_bot.stats_cve_lookups == 0


@pytest.mark.asyncio
async def test_on_message_channel_disabled(mock_bot, mock_message, mock_db):
    """Test scenario where the specific channel monitoring is disabled."""
    mock_message.content = "CVE-2023-1234"
    # Global is enabled (default mock), but channel is disabled
    mock_db.get_cve_channel_config.return_value = {"enabled": False}

    await mock_bot.on_message(mock_message)

    mock_message.channel.send.assert_not_called()
    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    assert mock_bot.stats_messages_processed == 1
    assert mock_bot.stats_cve_lookups == 0


@pytest.mark.asyncio
async def test_on_message_success_simple_cve_non_verbose_no_kev(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test a successful simple case: 1 CVE, enabled, passes threshold, non-verbose, not in KEV."""
    cve_id = "CVE-2023-1234"
    cve_id_upper = cve_id.upper()
    mock_message.content = f"Found {cve_id}"

    # --- Mock Setup ---
    # DB: Defaults are okay (enabled, non-verbose)
    # Monitor:
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}  # Sample data
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_severity_threshold.return_value = (
        True,
        "High",
    )  # Passes threshold
    mock_cve_monitor.check_kev.return_value = None  # Not in KEV

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    # DB Calls
    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_db.get_effective_verbosity.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )

    # Monitor Calls
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once_with(
        mock_cve_data, "all"
    )
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()  # Not in KEV

    # Discord Calls
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )

    # Cache Update
    assert (mock_message.channel.id, cve_id_upper) in mock_bot.recently_processed_cves

    # Stats Update
    assert mock_bot.stats_messages_processed == 1
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1  # Assumed NVD success
    assert mock_bot.stats_api_errors_kev == 0


@pytest.mark.asyncio
async def test_on_message_success_verbose_global(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test success path with global verbosity enabled."""
    cve_id = "CVE-2023-5555"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 7.0}

    # --- Mock Setup ---
    mock_db.get_cve_guild_config.return_value["verbose_mode"] = (
        True  # Global verbose TRUE
    )
    mock_db.get_effective_verbosity.return_value = True  # Effective is TRUE
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = None  # No KEV

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_db.get_effective_verbosity.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=True
    )  # Check verbose=True
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()


@pytest.mark.asyncio
async def test_on_message_success_channel_override_verbose(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test success path with channel override enabling verbosity when global is off."""
    cve_id = "CVE-2023-5555"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 7.0}

    # --- Mock Setup ---
    # Global is FALSE (default fixture)
    # Channel override is TRUE
    mock_db.get_cve_channel_config.return_value = {
        "enabled": True,
        "verbose_mode": True,
    }
    mock_db.get_effective_verbosity.return_value = (
        True  # Effective is TRUE due to channel
    )
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = None  # No KEV

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_db.get_effective_verbosity.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=True
    )  # Check verbose=True
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()


@pytest.mark.asyncio
async def test_on_message_success_with_kev_non_verbose(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test success path with KEV found, non-verbose."""
    cve_id = "CVE-2023-1234"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}
    mock_kev_data = {"cveID": cve_id_upper}  # Sample KEV data

    # --- Mock Setup ---
    # DB: Defaults are okay (enabled, non-verbose)
    mock_db.get_effective_verbosity.return_value = False
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = mock_kev_data  # KEV FOUND

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_cve_monitor.create_kev_status_embed.assert_called_once_with(
        cve_id_upper, mock_kev_data, verbose=False
    )  # KEV embed non-verbose

    # Check that channel.send was called twice (once for CVE, once for KEV)
    assert mock_message.channel.send.await_count == 2
    send_calls = mock_message.channel.send.await_args_list
    assert send_calls[0] == call(embed=mock_cve_monitor.create_cve_embed.return_value)
    assert send_calls[1] == call(
        embed=mock_cve_monitor.create_kev_status_embed.return_value
    )

    # Stats
    assert mock_bot.stats_api_errors_kev == 0


@pytest.mark.asyncio
async def test_on_message_success_with_kev_verbose(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test success path with KEV found, verbose."""
    cve_id = "CVE-2023-1234"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}
    mock_kev_data = {"cveID": cve_id_upper}

    # --- Mock Setup ---
    mock_db.get_cve_guild_config.return_value["verbose_mode"] = True
    mock_db.get_effective_verbosity.return_value = True
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = mock_kev_data  # KEV FOUND

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=True
    )  # Verbose
    mock_cve_monitor.create_kev_status_embed.assert_called_once_with(
        cve_id_upper, mock_kev_data, verbose=True
    )  # KEV embed verbose

    assert mock_message.channel.send.await_count == 2
    # (Optional: check call args like previous test if needed)


@pytest.mark.asyncio
async def test_on_message_cache_hit(mock_bot, mock_message, mock_db, mock_cve_monitor):
    """Test that a recently processed CVE is skipped."""
    cve_id = "CVE-2023-7777"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    channel_id = mock_message.channel.id
    cache_key = (channel_id, cve_id_upper)

    # --- Mock Setup ---
    # Pre-populate cache with a recent timestamp
    mock_bot.recently_processed_cves[cache_key] = datetime.now(
        timezone.utc
    ) - timedelta(seconds=5)
    mock_cve_monitor.get_cve_data.return_value = {
        "id": cve_id_upper
    }  # Need some data for first pass if cache fails

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    # Crucially, the API call and send should NOT happen
    mock_cve_monitor.get_cve_data.assert_not_awaited()
    mock_message.channel.send.assert_not_called()

    # Check basic calls that happen before cache check
    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )

    # Check stats (lookup shouldn't increment)
    assert mock_bot.stats_cve_lookups == 0
    assert mock_bot.stats_messages_processed == 1


@pytest.mark.asyncio
async def test_on_message_severity_threshold_fail(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test scenario where CVE severity is below the configured threshold."""
    cve_id = "CVE-2023-1111"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 3.0}  # Low severity

    # --- Mock Setup ---
    # Set guild threshold to medium
    mock_db.get_cve_guild_config.return_value["severity_threshold"] = "medium"
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    # Make check_severity_threshold return False based on threshold
    mock_cve_monitor.check_severity_threshold.return_value = (False, "Low")

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once_with(
        mock_cve_data, "medium"
    )

    # Should not proceed to get verbosity or send messages
    mock_db.get_effective_verbosity.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()

    # Check stats
    assert mock_bot.stats_cve_lookups == 1  # Lookup happened
    assert mock_bot.stats_nvd_fallback_success == 1  # Data was found
    assert mock_bot.stats_messages_processed == 1


@pytest.mark.asyncio
async def test_on_message_multiple_cves_below_limit(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test processing multiple CVEs in one message when below the limit."""
    cve1 = "CVE-2023-0001"
    cve2 = "CVE-2023-0002"
    mock_message.content = f"Check {cve1} and {cve2}"
    mock_cve_data1 = {"id": cve1, "cvss": 5.0}
    mock_cve_data2 = {"id": cve2, "cvss": 6.0}

    # --- Mock Setup ---
    mock_cve_monitor.get_cve_data.side_effect = [mock_cve_data1, mock_cve_data2]
    mock_cve_monitor.check_kev.return_value = None  # None for both
    mock_db.get_effective_verbosity.return_value = False  # Non-verbose

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    assert mock_cve_monitor.get_cve_data.await_count == 2
    mock_cve_monitor.get_cve_data.assert_has_awaits([call(cve1), call(cve2)])
    assert mock_cve_monitor.check_severity_threshold.call_count == 2
    assert mock_cve_monitor.create_cve_embed.call_count == 2
    mock_cve_monitor.create_cve_embed.assert_has_calls(
        [call(mock_cve_data1, verbose=False), call(mock_cve_data2, verbose=False)]
    )
    assert mock_cve_monitor.check_kev.await_count == 2
    mock_cve_monitor.check_kev.assert_has_awaits([call(cve1), call(cve2)])
    mock_cve_monitor.create_kev_status_embed.assert_not_called()

    assert mock_message.channel.send.await_count == 2

    assert (mock_message.channel.id, cve1) in mock_bot.recently_processed_cves
    assert (mock_message.channel.id, cve2) in mock_bot.recently_processed_cves

    assert mock_bot.stats_cve_lookups == 2
    assert mock_bot.stats_nvd_fallback_success == 2


@pytest.mark.asyncio
async def test_on_message_multiple_cves_above_limit(
    mocker, mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test processing multiple CVEs and hitting the MAX_EMBEDS_PER_MESSAGE limit."""
    cve1 = "CVE-2023-0001"
    cve2 = "CVE-2023-0002"
    cve3 = "CVE-2023-0003"
    mock_message.content = f"Check {cve1}, {cve2}, and also {cve3}"
    mock_cve_data1 = {"id": cve1, "cvss": 5.0}
    mock_cve_data2 = {"id": cve2, "cvss": 6.0}
    # No need for cve_data3 as it shouldn't be processed

    # --- Mock Setup ---
    # Patch the constant specifically for this test
    mocker.patch("kevvy.bot.MAX_EMBEDS_PER_MESSAGE", 2)

    mock_cve_monitor.get_cve_data.side_effect = [mock_cve_data1, mock_cve_data2]
    mock_cve_monitor.check_kev.return_value = None
    mock_db.get_effective_verbosity.return_value = False

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    # Only first 2 should be fully processed
    assert mock_cve_monitor.get_cve_data.await_count == 2
    mock_cve_monitor.get_cve_data.assert_has_awaits(
        [call(cve1), call(cve2)]
    )  # No call for cve3
    assert mock_cve_monitor.check_severity_threshold.call_count == 2
    assert mock_cve_monitor.create_cve_embed.call_count == 2
    assert mock_cve_monitor.check_kev.await_count == 2

    # Should send 2 embeds + 1 notice message
    assert mock_message.channel.send.await_count == 3
    send_calls = mock_message.channel.send.await_args_list
    # Check the content of the last call (the notice)
    assert "more CVEs, but only showing the first 2" in send_calls[2].args[0]
    assert send_calls[2].kwargs.get("delete_after") == 30

    # Cache should only contain the processed CVEs
    assert (mock_message.channel.id, cve1) in mock_bot.recently_processed_cves
    assert (mock_message.channel.id, cve2) in mock_bot.recently_processed_cves
    assert (mock_message.channel.id, cve3) not in mock_bot.recently_processed_cves

    # Stats should only reflect the processed CVEs
    assert mock_bot.stats_cve_lookups == 2
    assert mock_bot.stats_nvd_fallback_success == 2


@pytest.mark.asyncio
async def test_on_message_error_nvd_rate_limit(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test error handling for NVDRateLimitError during data fetch."""
    cve_id = "CVE-2023-8888"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id

    # --- Mock Setup ---
    mock_cve_monitor.get_cve_data.side_effect = NVDRateLimitError("Rate limit hit")

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()

    # Cache should not be updated
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    # Check stats
    assert mock_bot.stats_cve_lookups == 1  # Lookup was attempted
    assert mock_bot.stats_nvd_fallback_success == 0
    assert mock_bot.stats_rate_limits_hit_nvd == 1
    assert mock_bot.stats_api_errors_nvd == 1


@pytest.mark.asyncio
async def test_on_message_error_kev_check(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test error handling when check_kev raises an exception."""
    cve_id = "CVE-2023-9999"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}

    # --- Mock Setup ---
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.side_effect = Exception("KEV Service Unavailable")
    mock_db.get_effective_verbosity.return_value = False

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()

    # Should still send the CVE embed
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )

    # Cache should be updated because CVE part succeeded
    assert (mock_message.channel.id, cve_id_upper) in mock_bot.recently_processed_cves

    # Check stats
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1
    assert mock_bot.stats_api_errors_kev == 1


@pytest.mark.asyncio
async def test_on_message_error_discord_forbidden(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test error handling when discord.Forbidden is raised on send."""
    cve_id = "CVE-2023-1212"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}

    # --- Mock Setup ---
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_db.get_effective_verbosity.return_value = False
    # Raise Forbidden when send is called
    mock_message.channel.send.side_effect = discord.Forbidden(
        MagicMock(), "Missing Permissions"
    )

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )

    # Should stop processing after Forbidden
    mock_cve_monitor.check_kev.assert_not_awaited()

    # Cache should NOT be updated because the send failed
    # Note: Current implementation updates cache *before* send, this might need adjustment if we want this behavior
    # assert (mock_message.channel.id, cve_id_upper) not in mock_bot.recently_processed_cves
    # Correction: Cache is updated BEFORE send in current code. Let's assert that.
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    # Check stats
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1


@pytest.mark.asyncio
async def test_on_message_error_discord_http(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test error handling when discord.HTTPException is raised on send."""
    cve_id = "CVE-2023-2323"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 7.0}

    # --- Mock Setup ---
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_db.get_effective_verbosity.return_value = False
    mock_message.channel.send.side_effect = discord.HTTPException(
        MagicMock(), "Server Error"
    )

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )

    # Should NOT continue processing check_kev for this CVE after HTTPException during send
    mock_cve_monitor.check_kev.assert_not_awaited()

    # Cache should NOT be updated as the exception happened before the update line
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    # Check stats (no specific stat for HTTP errors currently)
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1


@pytest.mark.asyncio
async def test_on_message_error_generic_exception(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test error handling for unexpected exceptions during processing."""
    cve_id = "CVE-2023-4545"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id

    # --- Mock Setup ---
    # Simulate an error during DB call for verbosity
    mock_db.get_effective_verbosity.side_effect = Exception("Unexpected DB issue")
    mock_cve_monitor.get_cve_data.return_value = {"id": cve_id_upper, "cvss": 8.0}

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()

    # Processing should stop before creating/sending embeds
    mock_cve_monitor.create_cve_embed.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()

    # Cache should not be updated
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    # Check stats (should increment generic NVD error as per current code)
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1  # Found data before error
    assert (
        mock_bot.stats_api_errors_nvd == 1
    )  # Generic exception falls back to this stat


@pytest.mark.asyncio
async def test_on_message_cve_data_not_found(
    mock_bot, mock_message, mock_db, mock_cve_monitor
):
    """Test scenario where CVE is detected but no data is found via API."""
    cve_id = "CVE-2023-0000"
    cve_id_upper = cve_id.upper()
    mock_message.content = f"Look at {cve_id}"

    # --- Mock Setup ---
    # DB: Defaults are okay (enabled, non-verbose)
    # Monitor: get_cve_data returns None
    mock_cve_monitor.get_cve_data.return_value = None

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    # Basic config checks should happen
    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )

    # API call was made
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)

    # No further processing or sending should occur
    mock_cve_monitor.check_severity_threshold.assert_not_called()
    mock_db.get_effective_verbosity.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()

    # Cache should not be updated as processing failed early
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    # Stats Update
    assert mock_bot.stats_messages_processed == 1
    assert mock_bot.stats_cve_lookups == 1  # Lookup attempted
    assert mock_bot.stats_nvd_fallback_success == 0  # No data found
    assert (
        mock_bot.stats_api_errors_nvd == 0
    )  # Not necessarily an API error, just no data
    assert mock_bot.stats_api_errors_kev == 0


# --- Tests for check_cisa_kev_feed Task ---


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_no_new_entries(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db
):
    """Test the KEV check task when no new entries are returned."""
    # --- Mock Setup ---
    mock_cisa_kev_client.get_new_kev_entries.return_value = []

    # --- Run Task (call directly for testing) ---
    start_time = (
        mock_bot_with_tasks.timestamp_last_kev_check_success
    )  # Capture initial state
    await mock_bot_with_tasks.check_cisa_kev_feed()

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_not_called()  # Should not fetch configs if no entries
    mock_bot_with_tasks._create_kev_embed.assert_not_called()
    assert mock_bot_with_tasks.stats_kev_alerts_sent == 0
    assert mock_bot_with_tasks.stats_api_errors_cisa == 0
    # Timestamp should update on successful check even with no entries
    assert mock_bot_with_tasks.timestamp_last_kev_check_success is not None
    assert mock_bot_with_tasks.timestamp_last_kev_check_success != start_time


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_new_entries_success(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db
):
    """Test the KEV check task with new entries and successful sending."""
    # --- Mock Setup ---
    new_entry1 = {"cveID": "CVE-2023-1111", "shortDescription": "Test 1"}
    new_entry2 = {"cveID": "CVE-2023-2222", "shortDescription": "Test 2"}
    mock_cisa_kev_client.get_new_kev_entries.return_value = [new_entry1, new_entry2]

    guild_id1 = 1001
    channel_id1 = 2001
    guild_id2 = 1002
    channel_id2 = 2002
    mock_db.get_enabled_kev_configs.return_value = [
        {"guild_id": guild_id1, "channel_id": channel_id1},
        {"guild_id": guild_id2, "channel_id": channel_id2},
    ]

    mock_guild1 = AsyncMock(spec=discord.Guild)
    mock_channel1 = AsyncMock(spec=discord.TextChannel)
    mock_guild2 = AsyncMock(spec=discord.Guild)
    mock_channel2 = AsyncMock(spec=discord.TextChannel)
    mock_bot_with_tasks.get_guild.side_effect = lambda gid: (
        mock_guild1 if gid == guild_id1 else mock_guild2
    )
    mock_bot_with_tasks.get_channel.side_effect = lambda cid: (
        mock_channel1 if cid == channel_id1 else mock_channel2
    )

    # --- Run Task ---
    await mock_bot_with_tasks.check_cisa_kev_feed()

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_called_once()

    # Check embed creation calls (2 entries x 2 configs = 4 calls)
    assert mock_bot_with_tasks._create_kev_embed.call_count == 4
    mock_bot_with_tasks._create_kev_embed.assert_has_calls(
        [
            call(new_entry1),
            call(new_entry2),  # For first config
            call(new_entry1),
            call(new_entry2),  # For second config
        ],
        any_order=True,
    )

    # Check send calls (2 entries x 2 configs = 4 calls)
    assert mock_channel1.send.await_count == 2
    assert mock_channel2.send.await_count == 2
    mock_channel1.send.assert_has_awaits(
        [
            call(embed=mock_bot_with_tasks._create_kev_embed.return_value),
            call(embed=mock_bot_with_tasks._create_kev_embed.return_value),
        ]
    )

    # Check stats
    assert mock_bot_with_tasks.stats_kev_alerts_sent == 4  # 2 entries * 2 channels
    assert mock_bot_with_tasks.stats_api_errors_cisa == 0
    assert mock_bot_with_tasks.timestamp_last_kev_check_success is not None
    assert mock_bot_with_tasks.timestamp_last_kev_alert_sent is not None


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_client_error(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db
):
    """Test the KEV check task when the CISA client fetch fails."""
    # --- Mock Setup ---
    mock_cisa_kev_client.get_new_kev_entries.side_effect = Exception("CISA API Down")
    start_time = mock_bot_with_tasks.timestamp_last_kev_check_success

    # --- Run Task ---
    await mock_bot_with_tasks.check_cisa_kev_feed()

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_not_called()  # Should fail before getting configs
    mock_bot_with_tasks._create_kev_embed.assert_not_called()

    # Check stats
    assert mock_bot_with_tasks.stats_kev_alerts_sent == 0
    assert mock_bot_with_tasks.stats_api_errors_cisa == 1
    # Timestamp should NOT update on fetch failure
    assert mock_bot_with_tasks.timestamp_last_kev_check_success == start_time


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_discord_forbidden(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db
):
    """Test KEV check when sending to a channel fails with Forbidden."""
    # --- Mock Setup ---
    new_entry1 = {"cveID": "CVE-2023-1111"}
    mock_cisa_kev_client.get_new_kev_entries.return_value = [new_entry1]

    guild_id1 = 1001
    channel_id1 = 2001
    mock_db.get_enabled_kev_configs.return_value = [
        {"guild_id": guild_id1, "channel_id": channel_id1}
    ]

    mock_guild1 = AsyncMock(spec=discord.Guild)
    mock_channel1 = AsyncMock(spec=discord.TextChannel)
    mock_bot_with_tasks.get_guild.return_value = mock_guild1
    mock_bot_with_tasks.get_channel.return_value = mock_channel1

    # Make the send call fail
    mock_channel1.send.side_effect = discord.Forbidden(MagicMock(), "No Send Perms")

    # --- Run Task ---
    await mock_bot_with_tasks.check_cisa_kev_feed()

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_called_once()
    mock_bot_with_tasks._create_kev_embed.assert_called_once_with(new_entry1)
    mock_channel1.send.assert_awaited_once()  # Send was attempted

    # Check stats (alert should not be counted)
    assert mock_bot_with_tasks.stats_kev_alerts_sent == 0
    assert mock_bot_with_tasks.stats_api_errors_cisa == 0  # CISA fetch succeeded
    assert mock_bot_with_tasks.timestamp_last_kev_check_success is not None
    assert mock_bot_with_tasks.timestamp_last_kev_alert_sent is None  # Not updated


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_missing_guild_channel(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db, caplog
):
    """Test KEV check when configured guild or channel is missing."""
    # --- Mock Setup ---
    new_entry1 = {"cveID": "CVE-2023-1111"}
    mock_cisa_kev_client.get_new_kev_entries.return_value = [new_entry1]

    valid_guild_id = 1001
    valid_channel_id = 2001
    missing_guild_id = 1002
    missing_channel_config = {
        "guild_id": valid_guild_id,
        "channel_id": 9999,
    }  # Valid guild, missing channel

    mock_db.get_enabled_kev_configs.return_value = [
        {"guild_id": missing_guild_id, "channel_id": 3001},  # Guild 1002 missing
        missing_channel_config,  # Guild 1001 exists, channel 9999 missing
        {"guild_id": valid_guild_id, "channel_id": valid_channel_id},  # Valid config
    ]

    mock_valid_guild = AsyncMock(
        spec=discord.Guild, id=valid_guild_id, name="Valid Guild"
    )
    mock_valid_channel = AsyncMock(
        spec=discord.TextChannel, id=valid_channel_id, name="valid-channel"
    )

    def mock_get_guild(gid):
        if gid == valid_guild_id:
            return mock_valid_guild
        elif gid == missing_guild_id:
            return None  # Simulate missing guild
        return MagicMock()  # Default mock for any other unexpected ID

    def mock_get_channel(cid):
        if cid == valid_channel_id:
            return mock_valid_channel
        elif cid == 9999:
            return None  # Simulate missing channel
        return MagicMock()

    mock_bot_with_tasks.get_guild.side_effect = mock_get_guild
    mock_bot_with_tasks.get_channel.side_effect = mock_get_channel

    # --- Run Task ---
    with caplog.at_level(logging.WARNING):
        await mock_bot_with_tasks.check_cisa_kev_feed()

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_called_once()

    # Check warnings were logged for missing guild/channel
    assert (
        f"Could not find guild {missing_guild_id} from KEV config, skipping."
        in caplog.text
    )
    assert (
        f"Could not find CISA KEV target channel with ID: {missing_channel_config['channel_id']}"
        in caplog.text
    )

    # Check embed creation only happened for the valid config
    mock_bot_with_tasks._create_kev_embed.assert_called_once_with(new_entry1)

    # Check send only happened in the valid channel
    mock_valid_channel.send.assert_awaited_once()

    # Check stats (only 1 alert sent)
    assert mock_bot_with_tasks.stats_kev_alerts_sent == 1
    assert mock_bot_with_tasks.timestamp_last_kev_check_success is not None
    assert mock_bot_with_tasks.timestamp_last_kev_alert_sent is not None


# --- Tests for send_stats_to_webapp Task ---


@pytest.mark.asyncio
async def test_send_stats_to_webapp_success(mocker, mock_bot_with_tasks, caplog):
    """Test successful sending of stats to the web app."""
    # --- Mock Setup ---
    # Set some sample stats
    mock_bot_with_tasks.stats_messages_processed = 50
    mock_bot_with_tasks.stats_cve_lookups = 10
    mock_bot_with_tasks.stats_kev_alerts_sent = 2
    mock_bot_with_tasks.latency = 0.123  # Sample latency

    # Mock the module-level constant directly
    test_url = "http://test-webapp.com/base"
    mocker.patch("kevvy.bot.WEBAPP_ENDPOINT_URL", test_url)
    # Patch the API Key constant directly
    mocker.patch("kevvy.bot.WEBAPP_API_KEY", "test-api-key")

    # --- Mock the _post_stats helper method ---
    mock_post_stats = mocker.patch.object(
        mock_bot_with_tasks, "_post_stats", new_callable=AsyncMock
    )
    # Configure it to return success status and text
    mock_post_stats.return_value = (200, "Success")

    # --- Run Task ---
    with caplog.at_level(logging.INFO):  # Capture INFO logs
        await mock_bot_with_tasks.send_stats_to_webapp()

    # --- Assertions ---
    # Verify correct logging indicates call attempt
    expected_url = f"{test_url}/api/bot-status"
    assert f"Sending stats payload to {expected_url}" in caplog.text
    assert (
        "Successfully sent stats to web app (Status: 200)" in caplog.text
    )  # Check for success log

    # Verify _post_stats was called correctly
    # Construct the payload exactly as it's built in the actual function
    # Use ANY for timestamp as it's hard to predict exactly
    expected_payload_actual_structure = {
        "bot_id": mock_bot_with_tasks.user.id,
        "bot_name": str(mock_bot_with_tasks.user),
        "guild_count": 0,  # Fixture bot isn't in guilds yet
        "latency_ms": round(mock_bot_with_tasks.latency * 1000, 2),
        "start_time": mock_bot_with_tasks.start_time.isoformat(),
        "timestamp": mocker.ANY,  # Use ANY for timestamp
        "last_stats_sent_time": None,  # Initially None before first successful send
        "stats": {
            "cve_lookups": 10,
            "kev_alerts_sent": 2,
            "messages_processed": 50,
            "vulncheck_success": 0,  # Default in fixture
            "nvd_fallback_success": 0,  # Default in fixture
            "api_errors_vulncheck": 0,
            "api_errors_nvd": 0,
            "api_errors_cisa": 0,
            "api_errors_kev": 0,
            "rate_limits_nvd": 0,
            "rate_limits_hit_nvd": 0,
            "app_command_errors": {},  # Default in fixture
            "loaded_cogs": [],  # Default in fixture
            "failed_cogs": [],  # Default in fixture
            "last_kev_check_success": None,
            "last_kev_alert_sent": None,
        },
    }
    expected_headers_actual_structure = {
        "Content-Type": "application/json",
        "Authorization": "Bearer test-api-key",
        # User-Agent is added inside _post_stats, not passed to it
    }

    # Assert call to _post_stats with correct positional arguments
    mock_post_stats.assert_awaited_once_with(
        expected_url,
        expected_payload_actual_structure,  # Check against the detailed structure
        expected_headers_actual_structure,
    )

    # Verify stats time was updated (it should no longer be None)
    assert mock_bot_with_tasks.last_stats_sent_time is not None


@pytest.mark.asyncio
async def test_send_stats_to_webapp_no_url(mocker, mock_bot_with_tasks, caplog):
    """Test that stats are not sent if KEVVY_WEB_URL is not configured."""
    # --- Mock Setup ---
    # Patch the module-level constant to the default unconfigured value
    mocker.patch("kevvy.bot.WEBAPP_ENDPOINT_URL", "YOUR_WEBAPP_ENDPOINT_URL_HERE")
    # Patch the API Key constant directly
    mocker.patch("kevvy.bot.WEBAPP_API_KEY", "test-api-key")

    patched_post = mocker.patch(
        "aiohttp.ClientSession.post"
    )  # Patch post just to assert not called

    # --- Run Task ---
    with caplog.at_level(logging.DEBUG):
        await mock_bot_with_tasks.send_stats_to_webapp()

    # --- Assertions ---
    # mocked_post.assert_not_called() # Assert on the patch object
    patched_post.assert_not_called()
    assert "Web app endpoint base URL not configured" in caplog.text
    assert mock_bot_with_tasks.last_stats_sent_time is None


@pytest.mark.asyncio
async def test_send_stats_to_webapp_http_error(mocker, mock_bot_with_tasks, caplog):
    """Test error handling when the web app POST returns an error status."""
    # --- Mock Setup ---
    test_url = "http://test-webapp.com"
    mocker.patch("kevvy.bot.WEBAPP_ENDPOINT_URL", test_url)
    # Patch the API Key constant directly
    mocker.patch("kevvy.bot.WEBAPP_API_KEY", "test-api-key")

    # --- Mock the _post_stats helper method ---
    mock_post_stats = mocker.patch.object(
        mock_bot_with_tasks, "_post_stats", new_callable=AsyncMock
    )
    # Configure it to return an error status and text
    mock_post_stats.return_value = (500, "Server Error Details")

    # --- Run Task ---
    start_time = mock_bot_with_tasks.last_stats_sent_time
    with caplog.at_level(logging.INFO):  # Capture INFO and ERROR logs
        await mock_bot_with_tasks.send_stats_to_webapp()

    # --- Assertions ---
    # Verify logging indicates attempt and failure
    expected_url = f"{test_url}/api/bot-status"  # Use the patched base URL
    assert f"Sending stats payload to {expected_url}" in caplog.text
    # Check for the more detailed error log message (using the status and text from the mocked helper)
    assert (
        "Failed to send stats to web app. Status: 500. Response: Server Error Details"
        in caplog.text
    )

    # Verify _post_stats was called
    mock_post_stats.assert_awaited_once()  # Args checked in success test

    # Verify last sent time was NOT updated
    assert mock_bot_with_tasks.last_stats_sent_time == start_time


@pytest.mark.asyncio
async def test_send_stats_to_webapp_connection_error(
    mocker, mock_bot_with_tasks, caplog
):
    """Test error handling for connection errors during stats send."""
    # --- Mock Setup ---
    web_url = "http://invalid-host.local"
    mocker.patch("kevvy.bot.WEBAPP_ENDPOINT_URL", web_url)
    # Patch the API Key constant directly (consistency)
    mocker.patch("kevvy.bot.WEBAPP_API_KEY", "test-api-key")

    # Make the post call raise the exception directly when awaited
    connection_error = aiohttp.ClientConnectorError(
        MagicMock(), OSError("DNS lookup failed")
    )

    # --- Mock the _post_stats helper method to raise an error ---
    mock_post_stats = mocker.patch.object(
        mock_bot_with_tasks, "_post_stats", new_callable=AsyncMock
    )
    mock_post_stats.side_effect = connection_error

    # --- Run Task ---
    start_time = mock_bot_with_tasks.last_stats_sent_time
    with caplog.at_level(logging.INFO):  # Capture INFO and ERROR
        await mock_bot_with_tasks.send_stats_to_webapp()

    # --- Assertions ---
    # Verify logging indicates attempt and failure
    expected_url = f"{web_url}/api/bot-status"
    assert (
        f"Sending stats payload to {expected_url}" in caplog.text
    )  # Check if the attempt log happened
    # Check the specific error log message structure
    assert (
        f"Connection error sending stats to web app {expected_url}: ClientConnectorError"
        in caplog.text
    )  # Check specific error type
    # Check that the string representation of the exception is in the log
    assert str(connection_error) in caplog.text

    # Verify _post_stats was called
    mock_post_stats.assert_awaited_once()  # Check it was called

    # Verify last sent time was NOT updated
    assert mock_bot_with_tasks.last_stats_sent_time == start_time


# --- Tests for Bot Initialization ---


@patch("kevvy.bot.VulnCheckClient")  # Mock client used in init
def test_bot_init_version_success(MockVulnCheckClient, mocker):
    """Test bot correctly reads version from metadata."""
    test_version = "9.9.9-test"
    # Patch importlib.metadata.version to return our test version
    mock_get_version = mocker.patch(
        "importlib.metadata.version", return_value=test_version
    )

    # Instantiate the bot (pass dummy args)
    bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    # Assert version was called correctly and attribute is set
    mock_get_version.assert_called_once_with("kevvy")
    assert bot.version == test_version


@patch("kevvy.bot.VulnCheckClient")  # Mock client used in init
def test_bot_init_version_not_found(MockVulnCheckClient, mocker, caplog):
    """Test bot handles PackageNotFoundError and sets default version."""
    # Patch importlib.metadata.version to raise error
    mock_get_version = mocker.patch(
        "importlib.metadata.version",
        side_effect=importlib.metadata.PackageNotFoundError("Package not found"),
    )

    # Instantiate the bot
    with caplog.at_level(logging.ERROR):
        bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    # Assert version was called correctly and fallback attribute is set
    mock_get_version.assert_called_once_with("kevvy")
    assert bot.version == "0.0.0-unknown"
    # Assert error was logged
    assert (
        "Could not determine package version for 'kevvy'. Using default." in caplog.text
    )


# --- Tests for Bot Lifecycle (Setup/Close) ---


# Mock dependencies that might be needed even for basic init/setup_hook
@patch("kevvy.bot.VulnCheckClient")
@patch("kevvy.bot.NVDClient")
@patch("kevvy.bot.KEVConfigDB")
@patch("kevvy.bot.CisaKevClient")
@patch("kevvy.bot.CVEMonitor")
@patch("kevvy.bot.aiohttp.ClientSession")  # Also mock the session creation
@pytest.mark.asyncio
async def test_setup_hook_success(
    MockSession,
    MockMonitor,
    MockKevClient,
    MockDB,
    MockNvdClient,
    MockVulnCheck,
    mocker,
):
    """Test successful execution of the setup_hook."""
    # Instantiate the bot
    bot = SecurityBot(nvd_api_key="fake_key", vulncheck_api_token="fake_token")

    # Mock methods called by setup_hook
    mock_load = mocker.patch.object(bot, "load_extension", new_callable=AsyncMock)
    mock_sync = mocker.patch.object(bot.tree, "sync", new_callable=AsyncMock)
    mock_kev_task_start = mocker.patch.object(bot.check_cisa_kev_feed, "start")
    mock_stats_task_start = mocker.patch.object(bot.send_stats_to_webapp, "start")
    # Mock signal setup to avoid issues on different platforms
    mocker.patch.object(bot, "_setup_signal_handlers")

    # --- Run setup_hook ---
    await bot.setup_hook()

    # --- Assertions ---
    # Check dependencies initialized (mocks should have been assigned)
    MockSession.assert_called_once()  # Check session was created
    assert bot.http_session is not None
    MockNvdClient.assert_called_once()
    assert bot.nvd_client is not None
    MockDB.assert_called_once()
    assert bot.db is not None
    MockKevClient.assert_called_once()
    assert bot.cisa_kev_client is not None
    MockMonitor.assert_called_once()
    assert bot.cve_monitor is not None

    # Check extensions loaded
    expected_extensions = ["kevvy.cogs.kev_commands", "kevvy.cogs.cve_lookup"]
    assert mock_load.await_count == len(expected_extensions)
    mock_load.assert_has_awaits([call(ext) for ext in expected_extensions])
    assert bot.loaded_cogs == expected_extensions
    assert not bot.failed_cogs

    # Check signal handlers setup
    bot._setup_signal_handlers.assert_called_once()

    # Check commands synced
    mock_sync.assert_awaited_once()

    # Check tasks started
    mock_kev_task_start.assert_called_once()
    mock_stats_task_start.assert_called_once()


@patch("kevvy.bot.VulnCheckClient")
@patch("kevvy.bot.NVDClient")
@patch("kevvy.bot.KEVConfigDB")
@patch("kevvy.bot.CisaKevClient")
@patch("kevvy.bot.CVEMonitor")
@patch("kevvy.bot.aiohttp.ClientSession")
@pytest.mark.asyncio
async def test_setup_hook_extension_load_error(
    MockSession,
    MockMonitor,
    MockKevClient,
    MockDB,
    MockNvdClient,
    MockVulnCheck,
    mocker,
    caplog,
):
    """Test setup_hook handling commands.ExtensionError during load_extension."""
    bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    failing_extension = "kevvy.cogs.cve_lookup"
    load_error = commands.ExtensionFailed(
        failing_extension, Exception("Cog init failed")
    )

    # Mock load_extension to raise error for one specific extension
    async def mock_load_side_effect(extension):
        if extension == failing_extension:
            raise load_error
        # No else needed, just don't raise for successful ones
        # The actual setup_hook will append to bot.loaded_cogs

    mock_load = mocker.patch.object(
        bot, "load_extension", side_effect=mock_load_side_effect
    )
    mock_sync = mocker.patch.object(bot.tree, "sync", new_callable=AsyncMock)
    mock_kev_task_start = mocker.patch.object(bot.check_cisa_kev_feed, "start")
    mock_stats_task_start = mocker.patch.object(bot.send_stats_to_webapp, "start")
    mocker.patch.object(bot, "_setup_signal_handlers")

    # --- Run setup_hook ---
    with caplog.at_level(logging.ERROR):
        await bot.setup_hook()

    # --- Assertions ---
    # Check initialization happened
    assert bot.http_session is not None
    assert bot.db is not None

    # Check load was attempted for all
    expected_extensions = ["kevvy.cogs.kev_commands", "kevvy.cogs.cve_lookup"]
    assert mock_load.call_count == len(expected_extensions)

    # Check loaded/failed lists are correct
    assert bot.loaded_cogs == [
        ext for ext in expected_extensions if ext != failing_extension
    ]
    assert len(bot.failed_cogs) == 1
    assert (
        failing_extension in bot.failed_cogs[0]
    )  # Check the name is part of the string
    assert "Load Error" in bot.failed_cogs[0]  # Check reason
    assert f"Failed to load extension {failing_extension}" in caplog.text

    # Check sync and task start still happened
    mock_sync.assert_awaited_once()
    mock_kev_task_start.assert_called_once()
    mock_stats_task_start.assert_called_once()


@patch("kevvy.bot.VulnCheckClient")
@patch("kevvy.bot.NVDClient")
@patch("kevvy.bot.KEVConfigDB")
@patch("kevvy.bot.CisaKevClient")
@patch("kevvy.bot.CVEMonitor")
@patch("kevvy.bot.aiohttp.ClientSession")
@pytest.mark.asyncio
async def test_setup_hook_command_sync_error(
    MockSession,
    MockMonitor,
    MockKevClient,
    MockDB,
    MockNvdClient,
    MockVulnCheck,
    mocker,
    caplog,
):
    """Test setup_hook handling an error during tree.sync()."""
    bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    sync_error = discord.HTTPException(MagicMock(), "Sync Failed")

    # Mock methods called by setup_hook
    mock_load = mocker.patch.object(bot, "load_extension", new_callable=AsyncMock)
    # Mock sync to raise an error
    mock_sync = mocker.patch.object(bot.tree, "sync", side_effect=sync_error)
    mock_kev_task_start = mocker.patch.object(bot.check_cisa_kev_feed, "start")
    mock_stats_task_start = mocker.patch.object(bot.send_stats_to_webapp, "start")
    mocker.patch.object(bot, "_setup_signal_handlers")

    # --- Run setup_hook ---
    with caplog.at_level(logging.ERROR):
        await bot.setup_hook()

    # --- Assertions ---
    # Check initialization and loading still happened
    assert bot.http_session is not None
    assert bot.db is not None
    assert mock_load.await_count > 0  # Check load was attempted
    assert not bot.failed_cogs  # Loading succeeded

    # Check sync was attempted and failed
    mock_sync.assert_awaited_once()
    assert "Failed to sync application commands" in caplog.text

    # Check tasks still started
    mock_kev_task_start.assert_called_once()
    mock_stats_task_start.assert_called_once()
