import pytest
import discord
from unittest.mock import AsyncMock, MagicMock, PropertyMock
from datetime import datetime, timedelta, timezone
import logging
import aiohttp
import os
import asyncio

# Import the bot class and other necessary components
from kevvy.bot import SecurityBot
from kevvy.db_utils import KEVConfigDB
from kevvy.cve_monitor import CVEMonitor
from kevvy.cisa_kev_client import CisaKevClient
from kevvy.cogs.diagnostics import DiagnosticsCog
from kevvy.stats_manager import StatsManager

# --- Fixtures (Duplicated for simplicity, consider conftest.py later) ---


@pytest.fixture
def mock_db(mocker):
    """Fixture for a mocked KEVConfigDB object."""
    db = MagicMock(spec=KEVConfigDB)
    # Add specific mock behaviors needed by task tests if different from defaults
    db.get_enabled_kev_configs.return_value = []  # Default for task tests
    return db


@pytest.fixture
def mock_cve_monitor(mocker):
    """Fixture for a mocked CVEMonitor object."""
    monitor = MagicMock(spec=CVEMonitor)
    # Add specific mock behaviors if needed
    return monitor


@pytest.fixture
def mock_cisa_kev_client(mocker):
    """Fixture for a mocked CisaKevClient object."""
    client = AsyncMock(spec=CisaKevClient)
    client.get_new_kev_entries = AsyncMock(return_value=[])  # Default: No new entries
    return client


@pytest.fixture
def mock_bot_with_tasks(mocker, mock_db, mock_cve_monitor, mock_cisa_kev_client):
    """Fixture for a mocked SecurityBot including task-related mocks."""
    bot = SecurityBot(nvd_api_key=None, vulncheck_api_token=None)

    # Patch dependencies
    bot.db = mock_db
    bot.cve_monitor = mock_cve_monitor
    bot.http_session = AsyncMock()
    bot.start_time = datetime.now(timezone.utc)
    bot.cisa_kev_client = mock_cisa_kev_client

    # Create a properly mocked StatsManager with async methods
    mock_stats_manager = MagicMock()
    mock_stats_manager.get_stats_dict = AsyncMock(return_value={})
    mock_stats_manager.increment_kev_alerts_sent = AsyncMock()
    mock_stats_manager.record_api_error = AsyncMock()
    bot.stats_manager = mock_stats_manager

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

    # Initialize specific attributes
    bot.timestamp_last_kev_check_success = None
    bot.timestamp_last_kev_alert_sent = None
    bot.last_stats_sent_time = None

    bot._create_kev_embed = MagicMock(
        return_value=discord.Embed(title="Mock KEV Task Embed")
    )
    bot._post_stats = AsyncMock()

    return bot


# --- Tests for check_cisa_kev_feed Task ---


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_no_new_entries(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db
):
    """Test the KEV check task with no new entries."""
    # --- Mock Setup ---
    mock_cisa_kev_client.get_new_kev_entries.return_value = []
    mock_db.get_enabled_kev_configs.return_value = []

    # Set some initial timestamps to ensure they're updated correctly
    initial_timestamp = datetime.now(timezone.utc) - timedelta(days=1)
    mock_bot_with_tasks.timestamp_last_kev_check_success = initial_timestamp

    # --- Run Task ---
    await mock_bot_with_tasks.check_cisa_kev_feed.coro(mock_bot_with_tasks)

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_not_called()
    mock_bot_with_tasks._create_kev_embed.assert_not_called()

    assert mock_bot_with_tasks.timestamp_last_kev_check_success is not None
    assert mock_bot_with_tasks.timestamp_last_kev_check_success > initial_timestamp

    mock_bot_with_tasks.stats_manager.record_api_error.assert_not_called()
    mock_bot_with_tasks.stats_manager.increment_kev_alerts_sent.assert_not_called()


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

    initial_check_timestamp = datetime.now(timezone.utc) - timedelta(days=1)
    initial_alert_timestamp = datetime.now(timezone.utc) - timedelta(days=1)
    mock_bot_with_tasks.timestamp_last_kev_check_success = initial_check_timestamp
    mock_bot_with_tasks.timestamp_last_kev_alert_sent = initial_alert_timestamp

    # --- Run Task ---
    await mock_bot_with_tasks.check_cisa_kev_feed.coro(mock_bot_with_tasks)

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_called_once()
    assert mock_bot_with_tasks._create_kev_embed.call_count == 2

    # Verify channel sends - one for each config (2) for each entry (2)
    assert mock_channel1.send.await_count == 2  # Once per entry
    assert mock_channel2.send.await_count == 2  # Once per entry

    assert mock_bot_with_tasks.timestamp_last_kev_check_success is not None
    assert (
        mock_bot_with_tasks.timestamp_last_kev_check_success > initial_check_timestamp
    )
    assert mock_bot_with_tasks.timestamp_last_kev_alert_sent is not None
    assert mock_bot_with_tasks.timestamp_last_kev_alert_sent > initial_alert_timestamp


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_client_error(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db
):
    """Test the KEV check task when the CISA client fetch fails."""
    # --- Mock Setup ---
    mock_cisa_kev_client.get_new_kev_entries.side_effect = Exception("CISA API Down")
    initial_timestamp = datetime.now(timezone.utc) - timedelta(days=1)
    mock_bot_with_tasks.timestamp_last_kev_check_success = initial_timestamp

    # --- Run Task ---
    await mock_bot_with_tasks.check_cisa_kev_feed.coro(mock_bot_with_tasks)

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_not_called()
    mock_bot_with_tasks._create_kev_embed.assert_not_called()

    assert (
        mock_bot_with_tasks.timestamp_last_kev_check_success == initial_timestamp
    )  # Not updated on failure


@pytest.mark.asyncio
async def test_check_cisa_kev_feed_discord_forbidden(
    mock_bot_with_tasks, mock_cisa_kev_client, mock_db
):
    """Test KEV check when a guild has permissions issues."""
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

    # Define initial_timestamp before running the task
    initial_timestamp = datetime.now(timezone.utc) - timedelta(days=1)
    mock_bot_with_tasks.timestamp_last_kev_check_success = initial_timestamp

    # --- Run Task ---
    await mock_bot_with_tasks.check_cisa_kev_feed.coro(mock_bot_with_tasks)

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_called_once()
    mock_bot_with_tasks._create_kev_embed.assert_called_once_with(new_entry1)
    mock_channel1.send.assert_awaited_once()  # Send was attempted

    assert mock_bot_with_tasks.timestamp_last_kev_check_success is not None
    assert (
        mock_bot_with_tasks.timestamp_last_kev_check_success > initial_timestamp
    )  # Check succeeded


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
    }
    mock_db.get_enabled_kev_configs.return_value = [
        {"guild_id": missing_guild_id, "channel_id": 3001},
        missing_channel_config,
        {"guild_id": valid_guild_id, "channel_id": valid_channel_id},
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
            return None
        return MagicMock()

    def mock_get_channel(cid):
        if cid == valid_channel_id:
            return mock_valid_channel
        elif cid == 9999:
            return None
        return MagicMock()

    mock_bot_with_tasks.get_guild.side_effect = mock_get_guild
    mock_bot_with_tasks.get_channel.side_effect = mock_get_channel

    # --- Run Task ---
    with caplog.at_level(logging.WARNING):
        await mock_bot_with_tasks.check_cisa_kev_feed.coro(mock_bot_with_tasks)

    # --- Assertions ---
    mock_cisa_kev_client.get_new_kev_entries.assert_awaited_once()
    mock_db.get_enabled_kev_configs.assert_called_once()
    assert mock_bot_with_tasks._create_kev_embed.call_count == 1

    # Verify the appropriate error logs
    assert "Could not find guild 1002 from KEV config" in caplog.text
    assert "Error fetching CISA KEV target channel 9999" in caplog.text

    # Check embed creation only happened for the valid config
    mock_bot_with_tasks._create_kev_embed.assert_called_once_with(new_entry1)

    # Check send only happened in the valid channel
    mock_valid_channel.send.assert_awaited_once()


# --- Tests for send_stats_to_webapp Task ---


@pytest.mark.asyncio
async def test_diagnostics_cog_update_web_status_success(mocker, caplog):
    """Test successful sending of stats by DiagnosticsCog.update_web_status."""
    # --- Mock Environment ---
    test_url_base = "http://test-webapp.com"
    test_api_endpoint = f"{test_url_base}/api/bot-status"

    # Mock os.getenv calls made by DiagnosticsCog.__init__
    # This mock needs to be active when DiagnosticsCog is instantiated.
    mocker.patch(
        "os.getenv",
        side_effect=lambda key, default=None: {
            "KEVVY_WEB_URL": test_url_base,
            "KEVVY_WEB_API_KEY": "test-api-key",
        }.get(key, default),
    )

    # --- Mock Bot and Cog ---
    mock_bot = MagicMock(spec=SecurityBot)
    mock_bot.http_session = AsyncMock(spec=aiohttp.ClientSession)
    mock_bot.stats_manager = AsyncMock(spec=StatsManager)
    mock_bot.latency = 0.05
    mock_bot.guilds = [MagicMock(), MagicMock()]
    mock_bot.cogs = {"CoreEventsCog": MagicMock(), "DiagnosticsCog": MagicMock()}
    mock_bot.timestamp_last_kev_check_success = None
    mock_bot.timestamp_last_kev_alert_sent = None
    mock_bot.db = MagicMock()
    mock_bot.user = MagicMock()
    mock_bot.user.id = 12345
    mock_bot.user.name = "TestBot"
    # Add any other attributes DiagnosticsCog might access on self.bot
    # For example, BOT_VERSION might be on self.bot.version if not using the module-level one in the cog
    mock_bot.version = "test-version"  # Assuming DiagnosticsCog might use self.bot.version if BOT_VERSION from __init__ fails

    mock_stats_dict = {
        "cve_lookups": 10,
        "kev_alerts_sent": 2,
        "messages_processed": 100,
        "vulncheck_success": 5,
        "nvd_fallback_success": 1,
        "api_errors_nvd": 0,
        "api_errors_kev": 0,
        "api_errors_vulncheck": 0,
        "api_errors_cisa": 0,
        "rate_limits_hit_nvd": 0,
        # Ensure all keys accessed by current_bot_stats.get() in DiagnosticsCog are here
    }
    mock_bot.stats_manager.get_stats_dict = AsyncMock(return_value=mock_stats_dict)

    # Instantiate DiagnosticsCog
    # It will try to start its loop; for testing one execution of .coro, this is usually fine.
    # The mock_os_getenv must be active here.
    diagnostics_cog = DiagnosticsCog(bot=mock_bot)
    # Ensure the cog's session is the one we can mock `post` on
    # DiagnosticsCog init assigns self.session = bot.http_session, so this should be covered by mock_bot

    # Mock the actual post call on the session object used by the cog
    mock_api_response = AsyncMock(spec=aiohttp.ClientResponse)
    mock_api_response.status = 200
    mock_api_response.reason = "OK"
    mock_api_response.text = AsyncMock(return_value="OK")

    # This is the object returned by session.post(), which needs to be an async context manager
    mock_request_context_manager = AsyncMock()
    mock_request_context_manager.__aenter__ = AsyncMock(return_value=mock_api_response)
    # __aexit__ needs to be an awaitable, even if it does nothing or returns None/False
    mock_request_context_manager.__aexit__ = AsyncMock(return_value=False)

    # mock_bot.http_session.post is the function that returns the context manager
    # It should be a MagicMock because aiohttp.ClientSession.post is a regular method
    mock_bot.http_session.post = MagicMock(return_value=mock_request_context_manager)

    # --- Run Task ---
    # The DiagnosticsCog task starts itself if URL and Key are present.
    # We need to ensure it's not actually looping during the test of a single call.
    # A common way is to cancel it after the test or mock the tasks.loop decorator itself.
    # For now, we call .coro() which should bypass the loop's scheduling for one execution.

    # If the task is already running due to init, store it and cancel later
    task_to_cancel = None
    if diagnostics_cog.update_web_status.is_running():
        task_to_cancel = diagnostics_cog.update_web_status
        task_to_cancel.cancel()  # Cancel to prevent interference
        # Wait for cancellation to complete if necessary, or hope .coro call is sufficient
        try:
            await asyncio.sleep(0)  # Allow cancellation to process
        except asyncio.CancelledError:
            pass

    with caplog.at_level(logging.INFO):
        # Call the update_web_status's underlying coroutine
        await diagnostics_cog.update_web_status.coro(diagnostics_cog)

    # --- Assertions ---
    mock_bot.stats_manager.get_stats_dict.assert_called_once()
    mock_bot.http_session.post.assert_called_once()  # Changed from assert_awaited_once

    args, kwargs = mock_bot.http_session.post.call_args
    assert args[0] == test_api_endpoint
    assert kwargs["json"]["cve_lookups"] == 10
    assert kwargs["json"]["kev_alerts"] == 2
    assert kwargs["headers"]["Authorization"] == "Bearer test-api-key"

    assert (
        f"Successfully sent bot status to web API ({test_api_endpoint})" in caplog.text
    )
    # This log might not happen if cogs_list_sent becomes true too quickly or if test setup changes order
    # For more robust test, explicitly set diagnostics_cog.cogs_list_sent = False before calling .coro
    # diagnostics_cog.cogs_list_sent = False # <-- Add this before the 'with caplog' block
    # assert "First status update - sending" in caplog.text

    # Clean up: if we didn't cancel it above, or if we want to ensure it's stopped
    if task_to_cancel and task_to_cancel.is_running():
        task_to_cancel.cancel()
    elif not task_to_cancel and diagnostics_cog.update_web_status.is_running():
        diagnostics_cog.update_web_status.cancel()


@pytest.mark.asyncio
async def test_diagnostics_cog_update_web_status_no_config(mocker, caplog):
    """Test DiagnosticsCog when KEVVY_WEB_URL or KEVVY_WEB_API_KEY is not configured."""
    # --- Mock Environment ---
    # Simulate os.getenv returning None for the web URL
    mock_os_getenv = mocker.patch(
        "os.getenv",
        side_effect=lambda key, default=None: {
            "KEVVY_WEB_API_KEY": "test-api-key"  # Provide key, but no URL
        }.get(key, default)
        if key == "KEVVY_WEB_API_KEY"
        else None,
    )

    # --- Mock Bot ---
    mock_bot = MagicMock(spec=SecurityBot)
    mock_bot.http_session = AsyncMock(
        spec=aiohttp.ClientSession
    )  # Session still needs to be there
    # Add other attributes DiagnosticsCog might access on self.bot during __init__ or early in update_web_status
    mock_bot.stats_manager = AsyncMock(spec=StatsManager)
    mock_bot.latency = 0.05
    mock_bot.guilds = []
    mock_bot.cogs = {}
    mock_bot.timestamp_last_kev_check_success = None
    mock_bot.timestamp_last_kev_alert_sent = None
    mock_bot.db = MagicMock()
    mock_bot.user = MagicMock()  # Basic user mock
    mock_bot.version = "test-version"

    # --- Instantiate Cog ---
    with caplog.at_level(logging.WARNING):
        diagnostics_cog = DiagnosticsCog(bot=mock_bot)

    # --- Assertions for __init__ ---
    mock_os_getenv.assert_any_call("KEVVY_WEB_URL")
    assert (
        "KEVVY_WEB_URL or KEVVY_WEB_API_KEY not set. Web status updates disabled."
        in caplog.text
    )
    assert (
        not diagnostics_cog.update_web_status.is_running()
    )  # Task should not have been started

    # --- Test .coro() behavior ---
    # Clear previous logs if any, or use a new caplog context
    caplog.clear()
    with caplog.at_level(logging.DEBUG):  # Use DEBUG to catch the "Skipping update" log
        await diagnostics_cog.update_web_status.coro(diagnostics_cog)

    # Assert that no HTTP POST was attempted
    mock_bot.http_session.post.assert_not_called()
    # Assert that the method logged its intention to skip
    assert (
        "Diagnostics task running without endpoint, secret, or session. Skipping update."
        in caplog.text
    )


@pytest.mark.asyncio
async def test_diagnostics_cog_update_web_status_http_error(mocker, caplog):
    """Test DiagnosticsCog.update_web_status when the web API POST returns an error status."""
    # --- Mock Environment ---
    test_url_base = "http://test-webapp.com"
    test_api_key = "test-api-key"
    mocker.patch(
        "os.getenv",
        side_effect=lambda key, default=None: {
            "KEVVY_WEB_URL": test_url_base,
            "KEVVY_WEB_API_KEY": test_api_key,
        }.get(key, default),
    )

    # --- Mock Bot & Cog ---
    mock_bot = MagicMock(spec=SecurityBot)
    mock_bot.http_session = AsyncMock(spec=aiohttp.ClientSession)
    mock_bot.stats_manager = AsyncMock(spec=StatsManager)
    mock_bot.stats_manager.get_stats_dict = AsyncMock(return_value={"cve_lookups": 5})
    mock_bot.latency = 0.05
    mock_bot.guilds = [MagicMock(), MagicMock()]
    mock_bot.cogs = {
        "DiagnosticsCog": MagicMock()
    }  # So it doesn't try to log itself as new
    mock_bot.timestamp_last_kev_check_success = None
    mock_bot.timestamp_last_kev_alert_sent = None
    mock_bot.db = MagicMock()
    mock_bot.db.count_enabled_guilds = MagicMock(return_value=1)
    mock_bot.db.count_globally_enabled_cve_guilds = MagicMock(return_value=1)
    mock_bot.db.count_active_cve_channels = MagicMock(return_value=1)
    mock_bot.user = MagicMock()
    mock_bot.version = "test-version"

    diagnostics_cog = DiagnosticsCog(bot=mock_bot)
    # Ensure the task doesn't run on its own during the test of .coro()
    if diagnostics_cog.update_web_status.is_running():
        diagnostics_cog.update_web_status.cancel()
        try:  # Allow cancellation to process
            await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
    diagnostics_cog.cogs_list_sent = (
        True  # Prevent cog list logging for this test focus
    )

    # Mock the aiohttp.ClientSession.post response for HTTP error
    # This is the final response object
    mock_api_response = AsyncMock(spec=aiohttp.ClientResponse)
    mock_api_response.status = 500
    mock_api_response.reason = "Internal Server Error"
    mock_api_response.text = AsyncMock(return_value="Server Error Details")

    # This is the async context manager returned by session.post()
    mock_request_context_manager = AsyncMock()
    mock_request_context_manager.__aenter__ = AsyncMock(return_value=mock_api_response)
    # __aexit__ still needs to be a valid awaitable mock, though it might not be reached if __aenter__ fails
    mock_request_context_manager.__aexit__ = AsyncMock(return_value=False)

    # mock_bot.http_session.post is the function that returns the context manager
    # It should be a MagicMock because aiohttp.ClientSession.post is a regular method
    mock_bot.http_session.post = MagicMock(return_value=mock_request_context_manager)

    # --- Run Task ---
    with caplog.at_level(logging.WARNING):
        await diagnostics_cog.update_web_status.coro(diagnostics_cog)

    # --- Assertions ---
    mock_bot.http_session.post.assert_called_once()  # Changed from assert_awaited_once
    args, kwargs = mock_bot.http_session.post.call_args
    assert args[0] == f"{test_url_base}/api/bot-status"
    assert kwargs["json"]["cve_lookups"] == 5
    assert kwargs["headers"]["Authorization"] == f"Bearer {test_api_key}"

    assert (
        "Failed to send bot status to web API. Status: 500, Reason: Internal Server Error"
        in caplog.text
    )
    assert "Web API Response Body (Truncated): Server Error Details" in caplog.text


@pytest.mark.asyncio
async def test_diagnostics_cog_update_web_status_connection_error(mocker, caplog):
    """Test DiagnosticsCog.update_web_status for connection errors during stats send."""
    # --- Mock Environment ---
    test_url_base = "http://unreachable-host.local"
    test_api_key = "test-api-key"
    mocker.patch(
        "os.getenv",
        side_effect=lambda key, default=None: {
            "KEVVY_WEB_URL": test_url_base,
            "KEVVY_WEB_API_KEY": test_api_key,
        }.get(key, default),
    )

    # --- Mock Bot & Cog ---
    mock_bot = MagicMock(spec=SecurityBot)
    mock_bot.http_session = AsyncMock(spec=aiohttp.ClientSession)
    mock_bot.stats_manager = AsyncMock(spec=StatsManager)
    mock_bot.stats_manager.get_stats_dict = AsyncMock(return_value={"cve_lookups": 3})
    # Fill in other necessary bot attributes similar to the HTTP error test
    mock_bot.latency = 0.05
    mock_bot.guilds = [MagicMock()]
    mock_bot.cogs = {"DiagnosticsCog": MagicMock()}
    mock_bot.timestamp_last_kev_check_success = None
    mock_bot.timestamp_last_kev_alert_sent = None
    mock_bot.db = MagicMock()
    mock_bot.db.count_enabled_guilds = MagicMock(return_value=1)
    mock_bot.db.count_globally_enabled_cve_guilds = MagicMock(return_value=1)
    mock_bot.db.count_active_cve_channels = MagicMock(return_value=1)
    mock_bot.user = MagicMock()
    mock_bot.version = "test-version"

    diagnostics_cog = DiagnosticsCog(bot=mock_bot)
    if diagnostics_cog.update_web_status.is_running():
        diagnostics_cog.update_web_status.cancel()
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
    diagnostics_cog.cogs_list_sent = True

    # Mock the aiohttp.ClientSession.post to raise a ClientError from __aenter__
    # This simulates an error during the establishment of the request context
    mock_request_context_manager_raising_error = AsyncMock()
    mock_request_context_manager_raising_error.__aenter__ = AsyncMock(
        side_effect=aiohttp.ClientError("Connection failed miserably in __aenter__")
    )
    # __aexit__ still needs to be a valid awaitable mock, though it might not be reached if __aenter__ fails
    mock_request_context_manager_raising_error.__aexit__ = AsyncMock(return_value=False)

    # mock_bot.http_session.post should be a MagicMock
    mock_bot.http_session.post = MagicMock(
        return_value=mock_request_context_manager_raising_error
    )

    # --- Run Task ---
    with caplog.at_level(logging.ERROR):
        await diagnostics_cog.update_web_status.coro(diagnostics_cog)

    # --- Assertions ---
    mock_bot.http_session.post.assert_called_once()  # Changed from assert_awaited_once
    args, kwargs = mock_bot.http_session.post.call_args
    assert args[0] == f"{test_url_base}/api/bot-status"  # Check URL construction

    # Check for the correct error message for aiohttp.ClientError
    assert (
        f"HTTP Error sending status to web API ({test_url_base}/api/bot-status): Connection failed miserably in __aenter__"
        in caplog.text
    )
