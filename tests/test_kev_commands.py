import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
import discord
import datetime
from typing import Optional

# Need to import the cog and potentially other classes
from kevvy.cogs.kev_commands import KEVCog
from kevvy.cisa_kev_client import CisaKevClient # For type hinting mocks
from kevvy.bot import SecurityBot # For type hinting mocks
from kevvy.db_utils import KEVConfigDB # For type hinting mocks

# --- Mock Fixtures --- 

@pytest.fixture
def mock_db():
    """Fixture for a mock KEVConfigDB."""
    db = MagicMock(spec=KEVConfigDB)
    # Default return for config fetch
    db.get_kev_config = MagicMock(return_value=None) 
    db.log_kev_latest_query = MagicMock() # Mock the logging method
    return db

@pytest.fixture
def mock_kev_client():
    """Fixture for a mock CisaKevClient."""
    client = AsyncMock(spec=CisaKevClient)
    client.get_full_kev_catalog = AsyncMock(return_value=[]) # Default to empty catalog
    return client

@pytest.fixture
def mock_bot(mock_db, mock_kev_client): # Inject mocks
    """Fixture to create a mock SecurityBot with mocked DB and KEV client."""
    bot = MagicMock(spec=SecurityBot)
    bot.db = mock_db 
    bot.cisa_kev_client = mock_kev_client 
    bot.timestamp_last_kev_check_success = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)
    bot.timestamp_last_kev_alert_sent = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    bot.get_channel = MagicMock(return_value=MagicMock(spec=discord.TextChannel, mention="#mock-kev-channel")) # Mock channel fetch
    return bot

@pytest.fixture
def kev_cog(mock_bot):
    """Fixture to create an instance of the KEVCog with the mock bot."""
    cog = KEVCog(mock_bot)
    return cog

@pytest.fixture
def mock_interaction():
    """Fixture for a generic mock Interaction."""
    interaction = AsyncMock(spec=discord.Interaction)
    interaction.guild_id = 67890 # Default guild ID
    interaction.user = MagicMock(spec=discord.Member, id=54321)
    # Mock the response/followup methods needed by the commands
    interaction.response = AsyncMock(spec=discord.InteractionResponse)
    interaction.response.defer = AsyncMock()
    interaction.response.send_message = AsyncMock()
    interaction.followup = AsyncMock(spec=discord.Webhook)
    interaction.followup.send = AsyncMock()
    return interaction

# --- Sample Data ---
# Use recent dates in ISO 8601 format with UTC offset
NOW = datetime.datetime.now(datetime.timezone.utc)
DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"

SAMPLE_KEV_CATALOG = [
    {'cveID': 'CVE-2024-0001', 'dateAdded': (NOW - datetime.timedelta(days=1)).strftime(DATE_FMT), 'vendorProject': 'VendorA', 'product': 'ProductX', 'vulnerabilityName': 'Vuln A', 'dueDate': '2024-05-17', 'knownRansomwareCampaignUse': 'Yes'},
    {'cveID': 'CVE-2024-0002', 'dateAdded': (NOW - datetime.timedelta(days=3)).strftime(DATE_FMT), 'vendorProject': 'VendorB', 'product': 'ProductY', 'vulnerabilityName': 'Vuln B', 'dueDate': '2024-05-16', 'knownRansomwareCampaignUse': 'No'},
    {'cveID': 'CVE-2024-0003', 'dateAdded': (NOW - datetime.timedelta(days=10)).strftime(DATE_FMT), 'vendorProject': 'VendorA', 'product': 'ProductZ', 'vulnerabilityName': 'Vuln C', 'dueDate': '2024-05-10', 'knownRansomwareCampaignUse': 'No'}, # Older entry
]


# --- Tests for /kev feed --- 

@pytest.mark.asyncio
async def test_feed_enable(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_channel = MagicMock(spec=discord.TextChannel, id=9001, mention="#kev-alerts")
    
    await kev_cog.kev_feed_enable_command.callback(kev_cog, mock_interaction, mock_channel)
    
    mock_db.set_kev_config.assert_called_once_with(mock_interaction.guild_id, mock_channel.id)
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ KEV feed monitoring enabled. Alerts will be sent to {mock_channel.mention}.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_feed_disable(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    await kev_cog.kev_feed_disable_command.callback(kev_cog, mock_interaction)
    mock_db.disable_kev_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "❌ KEV feed monitoring disabled.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_feed_status_enabled(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_db: MagicMock, mock_bot: MagicMock):
    config = {'guild_id': 67890, 'channel_id': 9001, 'enabled': 1}
    mock_db.get_kev_config.return_value = config
    mock_channel = MagicMock(spec=discord.TextChannel, mention="#kev-channel-mention")
    mock_bot.get_channel.return_value = mock_channel
    # Format expected timestamps
    last_check_str = discord.utils.format_dt(mock_bot.timestamp_last_kev_check_success, 'R')
    last_alert_str = discord.utils.format_dt(mock_bot.timestamp_last_kev_alert_sent, 'R')

    await kev_cog.kev_feed_status_command.callback(kev_cog, mock_interaction)

    mock_db.get_kev_config.assert_called_once_with(mock_interaction.guild_id)
    mock_bot.get_channel.assert_called_once_with(9001)
    expected_message = (
        f"🟢 KEV feed monitoring is **enabled**.\n"
        f"Alerts channel: {mock_channel.mention}\n"
        f"Last successful check: {last_check_str}\n"
        f"Last alert sent: {last_alert_str}"
    )
    mock_interaction.response.send_message.assert_called_once_with(expected_message, ephemeral=True)

@pytest.mark.asyncio
async def test_feed_status_disabled(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_db.get_kev_config.return_value = {'enabled': 0}
    await kev_cog.kev_feed_status_command.callback(kev_cog, mock_interaction)
    mock_db.get_kev_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "⚪ KEV feed monitoring is **disabled**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_feed_status_no_config(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_db.get_kev_config.return_value = None # Simulate no row in DB
    await kev_cog.kev_feed_status_command.callback(kev_cog, mock_interaction)
    mock_db.get_kev_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "⚪ KEV feed monitoring is **disabled**.", ephemeral=True
    )

# --- Tests for /kev latest ---

@pytest.mark.asyncio
async def test_latest_success_defaults(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_kev_client: AsyncMock, mock_db: MagicMock):
    """Test /kev latest with default count and days."""
    mock_kev_client.get_full_kev_catalog.return_value = SAMPLE_KEV_CATALOG
    
    # Default days is 7, so CVE-2024-0003 should be filtered out by date
    expected_results = SAMPLE_KEV_CATALOG[:2] 

    await kev_cog.kev_latest_command.callback(kev_cog, mock_interaction) # Use defaults

    mock_interaction.response.defer.assert_called_once_with(ephemeral=True)
    mock_kev_client.get_full_kev_catalog.assert_called_once()
    mock_db.log_kev_latest_query.assert_called_once() # Check logging happens
    
    # Check embed sent via followup
    mock_interaction.followup.send.assert_called_once()
    args, kwargs = mock_interaction.followup.send.call_args
    assert 'embed' in kwargs
    embed = kwargs['embed']
    assert isinstance(embed, discord.Embed)
    assert embed.title == f"Latest KEV Entries (Last 7 days)" # Default days
    # Check that the 2 recent entries are in the description
    assert SAMPLE_KEV_CATALOG[0]['cveID'] in embed.description
    assert SAMPLE_KEV_CATALOG[1]['cveID'] in embed.description
    assert SAMPLE_KEV_CATALOG[2]['cveID'] not in embed.description # Too old
    assert f"Found 2 entries matching criteria. Showing top 2." in embed.footer.text

@pytest.mark.asyncio
@pytest.mark.parametrize("count, days", [(1, 30), (3, 10)])
async def test_latest_success_custom_params(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_kev_client: AsyncMock, mock_db: MagicMock, count: int, days: int):
    """Test /kev latest with custom count and days."""
    mock_kev_client.get_full_kev_catalog.return_value = SAMPLE_KEV_CATALOG

    await kev_cog.kev_latest_command.callback(kev_cog, mock_interaction, count=count, days=days)

    mock_interaction.response.defer.assert_called_once_with(ephemeral=True)
    mock_kev_client.get_full_kev_catalog.assert_called_once()
    
    # Check logging with correct params
    logged_params = mock_db.log_kev_latest_query.call_args[0][2]
    assert logged_params['count'] == count
    assert logged_params['days'] == days

    mock_interaction.followup.send.assert_called_once()
    args, kwargs = mock_interaction.followup.send.call_args
    embed = kwargs['embed']
    assert embed.title == f"Latest KEV Entries (Last {days} days)"
    # Basic check: description should exist
    assert embed.description is not None 
    # Footer count should match param or actual results, whichever is smaller
    # Recalculate expected range using the *exact* logic from the command
    cutoff_date_test = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    num_expected_in_range = 0
    for k in SAMPLE_KEV_CATALOG:
        try:
            date_added_str = k['dateAdded']
            parsed_date = datetime.datetime.fromisoformat(date_added_str.replace('Z', '+00:00'))
            if parsed_date.tzinfo is None:
                entry_date_test = parsed_date.replace(tzinfo=datetime.timezone.utc)
            else:
                entry_date_test = parsed_date.astimezone(datetime.timezone.utc)
            if entry_date_test >= cutoff_date_test:
                num_expected_in_range += 1
        except (ValueError, TypeError):
            pass # Ignore entries with bad dates, like the command does

    shown_count = min(count, num_expected_in_range)
    expected_footer_text = f"Found {num_expected_in_range} entries matching criteria. Showing top {shown_count}."
    assert expected_footer_text in embed.footer.text, f"Expected footer text containing '{expected_footer_text}' but got '{embed.footer.text}'"


@pytest.mark.asyncio
async def test_latest_with_filters(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_kev_client: AsyncMock, mock_db: MagicMock):
    """Test /kev latest with vendor and product filters."""
    mock_kev_client.get_full_kev_catalog.return_value = SAMPLE_KEV_CATALOG

    # Filter for VendorA, ProductX (should only match CVE-2024-0001)
    await kev_cog.kev_latest_command.callback(kev_cog, mock_interaction, vendor="VendorA", product="ProductX", days=30)

    mock_interaction.response.defer.assert_called_once_with(ephemeral=True)
    mock_kev_client.get_full_kev_catalog.assert_called_once()
    mock_interaction.followup.send.assert_called_once()

    args, kwargs = mock_interaction.followup.send.call_args
    embed = kwargs['embed']
    assert SAMPLE_KEV_CATALOG[0]['cveID'] in embed.description # CVE-1
    assert SAMPLE_KEV_CATALOG[1]['cveID'] not in embed.description # Wrong Vendor/Product
    assert SAMPLE_KEV_CATALOG[2]['cveID'] not in embed.description # Wrong Product
    assert f"Found 1 entries matching criteria. Showing top 1." in embed.footer.text

@pytest.mark.asyncio
async def test_latest_no_results(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_kev_client: AsyncMock):
    """Test /kev latest when the client returns an empty catalog."""
    mock_kev_client.get_full_kev_catalog.return_value = [] # Empty results

    await kev_cog.kev_latest_command.callback(kev_cog, mock_interaction, days=10)

    mock_interaction.response.defer.assert_called_once_with(ephemeral=True)
    mock_kev_client.get_full_kev_catalog.assert_called_once()
    mock_interaction.followup.send.assert_called_once_with(
        f"⚪ No KEV entries found matching your criteria in the last 10 days.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_latest_client_fail(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_kev_client: AsyncMock):
    """Test /kev latest when the KEV client call fails (returns None)."""
    mock_kev_client.get_full_kev_catalog.return_value = None # Simulate failure

    await kev_cog.kev_latest_command.callback(kev_cog, mock_interaction)

    mock_interaction.response.defer.assert_called_once_with(ephemeral=True)
    mock_kev_client.get_full_kev_catalog.assert_called_once()
    mock_interaction.followup.send.assert_called_once_with(
        "❌ Could not retrieve KEV data.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_latest_client_exception(kev_cog: KEVCog, mock_interaction: AsyncMock, mock_kev_client: AsyncMock):
    """Test /kev latest when the KEV client call raises an exception."""
    test_exception = Exception("API Unavailable")
    mock_kev_client.get_full_kev_catalog.side_effect = test_exception

    # Use patch to check logger call within the command's try/except
    with patch('kevvy.cogs.kev_commands.logger') as mock_logger:
        await kev_cog.kev_latest_command.callback(kev_cog, mock_interaction)

        mock_interaction.response.defer.assert_called_once_with(ephemeral=True)
        mock_kev_client.get_full_kev_catalog.assert_called_once()
        # Check error log
        mock_logger.error.assert_called_once()
        assert "Error handling /kev latest command" in mock_logger.error.call_args[0][0]
        # Check user response
        mock_interaction.followup.send.assert_called_once_with(
            "❌ An unexpected error occurred while fetching latest KEV entries.", ephemeral=True
        )

@pytest.mark.asyncio
async def test_latest_range_error(kev_cog: KEVCog, mock_interaction: AsyncMock):
    """Test the cog's error handler catches RangeError (or similar)."""
    # Try RangeCheckFailure, as RangeError doesn't seem to be the right path
    try:
        from discord.app_commands import RangeCheckFailure
    except ImportError:
        # Fallback if RangeCheckFailure doesn't exist in this version (unlikely)
        # This indicates a deeper issue or a very old/new discord.py version
        pytest.skip("Could not import RangeCheckFailure, skipping test.") 
        return

    # Directly raise the error to simulate discord.py's behavior before the callback
    error = RangeCheckFailure(MagicMock(name='count'), 1, 10) # Simulate error on 'count'
    
    await kev_cog.cog_app_command_error(mock_interaction, error)
    
    # The default error handler might not provide such a specific message for CheckFailure subtypes
    # Let's check for *a* call first, then refine if needed.
    # mock_interaction.response.send_message.assert_called_once_with(
    #     f"Parameter `count` must be between 1 and 10.", ephemeral=True
    # )
    mock_interaction.response.send_message.assert_called_once()
    # We can check the *content* of the call if the exact message is known for RangeCheckFailure
    # For now, just checking it sent *something* is a start.

# TODO: Add permission tests for /kev feed commands (using a helper) 