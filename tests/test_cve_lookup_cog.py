import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
import discord

# Need to import the cog and potentially other classes
from kevvy.cogs.cve_lookup import CVELookupCog
from kevvy.vulncheck_client import VulnCheckClient # For type hinting mocks
from kevvy.nvd_client import NVDClient # For type hinting mocks
from kevvy.bot import SecurityBot # For type hinting mocks
from kevvy.db_utils import KEVConfigDB # Added for DB testing


@pytest.fixture
def mock_db():
    """Fixture for a mock KEVConfigDB."""
    db = MagicMock(spec=KEVConfigDB)
    # Default return for config fetch
    db.get_cve_channel_config = MagicMock(return_value=None)
    return db

@pytest.fixture
def mock_bot(mock_db): # Inject mock_db into mock_bot
    """Fixture to create a mock SecurityBot with mocked clients and DB."""
    bot = MagicMock(spec=SecurityBot)
    bot.vulncheck_client = MagicMock(spec=VulnCheckClient)
    bot.nvd_client = MagicMock(spec=NVDClient)
    bot.cisa_kev_client = MagicMock() # Mock KEV client too
    bot.db = mock_db # Assign the mock DB
    bot.stats_lock = AsyncMock()
    bot.stats_cve_lookups = 0
    bot.stats_vulncheck_success = 0
    bot.stats_nvd_fallback_success = 0
    bot.stats_api_errors_vulncheck = 0
    bot.stats_api_errors_nvd = 0
    bot.get_channel = MagicMock(return_value=MagicMock(spec=discord.TextChannel, mention="#mock-channel")) # Mock channel fetch
    return bot

@pytest.fixture
def cve_lookup_cog(mock_bot):
    """Fixture to create an instance of the CVELookupCog with the mock bot."""
    cog = CVELookupCog(mock_bot)
    return cog

@pytest.fixture
def mock_interaction():
    """Fixture for a generic mock Interaction."""
    interaction = AsyncMock(spec=discord.Interaction)
    interaction.guild_id = 12345 # Default guild ID
    interaction.user = MagicMock(spec=discord.Member, id=98765)
    interaction.response = AsyncMock()
    interaction.followup = AsyncMock()
    return interaction

# --- Helper for Permissions Check --- 

async def check_permissions(cog_command, interaction: AsyncMock):
    """Helper to simulate a permissions check failure."""
    # Simulate the check failing by raising the specific error
    interaction.response.send_message.side_effect = discord.app_commands.MissingPermissions(["manage_guild"])
    with pytest.raises(discord.app_commands.MissingPermissions):
         # Call the command's callback directly
         # Note: This assumes the check decorator is correctly applied
         # and the error handler in the cog catches MissingPermissions.
         # We might need to adjust args depending on the command.
         # For simple commands like disable/reset/view:
         if cog_command.name in ["disable", "reset", "view"]:
              await cog_command.callback(cog_command.__self__, interaction)
         elif cog_command.name == "set": # Set needs level
              await cog_command.callback(cog_command.__self__, interaction, level='high') 
         elif cog_command.name == "enable": # Enable needs channel
              mock_channel = MagicMock(spec=discord.TextChannel)
              await cog_command.callback(cog_command.__self__, interaction, channel=mock_channel)
         else:
             pytest.fail(f"Unsupported command for check_permissions helper: {cog_command.name}")
    
    interaction.response.send_message.assert_called_with(
        "🚫 You need the 'Manage Server' permission to use this command.", 
        ephemeral=True
    )

# --- Existing Tests for /cve lookup --- 

@pytest.mark.asyncio
async def test_cve_lookup_success_nvd(cve_lookup_cog: CVELookupCog, mock_bot: MagicMock):
    """Test /cve lookup command succeeding using the NVD client."""
    # --- Arrange ---
    mock_interaction = AsyncMock()
    test_cve_id = "CVE-2024-12345"
    mock_cve_data = {"id": test_cve_id, "description": "Mock NVD Data"}
    mock_embed = MagicMock(spec=discord.Embed) # Mock the embed that WOULD be created

    # Patch the cog's create_cve_embed method *for this test only*
    with patch.object(cve_lookup_cog, 'create_cve_embed', return_value=mock_embed) as patched_create_embed:
        # Configure mock bot's clients - NVD returns data this time
        mock_bot.vulncheck_client.get_cve_details = AsyncMock(return_value=None)
        mock_bot.nvd_client.get_cve_details = AsyncMock(return_value=mock_cve_data)

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(cve_lookup_cog, mock_interaction, test_cve_id)

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check NVD was called
        mock_bot.nvd_client.get_cve_details.assert_called_once_with(test_cve_id.upper()) # Code calls .upper()
        # Check VulnCheck was NOT called
        mock_bot.vulncheck_client.get_cve_details.assert_not_called()
        # Check the PATCHED embed creation was called
        patched_create_embed.assert_called_once_with(mock_cve_data)
        # Check interaction followup response
        mock_interaction.followup.send.assert_called_once_with(embed=mock_embed)
        # Check stats
        mock_bot.stats_lock.__aenter__.assert_called()
        mock_bot.stats_lock.__aexit__.assert_called()
        assert mock_bot.stats_cve_lookups == 1
        assert mock_bot.stats_nvd_fallback_success == 1
        assert mock_bot.stats_api_errors_nvd == 0

@pytest.mark.asyncio
async def test_cve_lookup_nvd_fail(cve_lookup_cog: CVELookupCog, mock_bot: MagicMock):
    """Test /cve lookup command when NVD client returns None."""
    # Patch the cog's create_cve_embed (it shouldn't be called anyway)
    with patch.object(cve_lookup_cog, 'create_cve_embed') as patched_create_embed:
        # --- Arrange ---
        mock_interaction = AsyncMock()
        test_cve_id = "CVE-2024-54321"

        # Configure mock bot's clients - NVD returns None
        mock_bot.vulncheck_client.get_cve_details = AsyncMock(return_value=None)
        mock_bot.nvd_client.get_cve_details = AsyncMock(return_value=None)

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(cve_lookup_cog, mock_interaction, test_cve_id)

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check NVD was called
        mock_bot.nvd_client.get_cve_details.assert_called_once_with(test_cve_id.upper())
        # Check the PATCHED embed creation was NOT called
        patched_create_embed.assert_not_called()
        # Check interaction followup response for failure message
        expected_message = f"🤷 Could not find details for `{test_cve_id}` in NVD, or an error occurred during fetch."
        mock_interaction.followup.send.assert_called_once_with(expected_message)
        # Check stats
        mock_bot.stats_lock.__aenter__.assert_called()
        mock_bot.stats_lock.__aexit__.assert_called()
        assert mock_bot.stats_cve_lookups == 1 # Lookup was attempted
        assert mock_bot.stats_nvd_fallback_success == 0 # Success was not reached
        assert mock_bot.stats_api_errors_nvd == 0 # No exception occurred

@pytest.mark.asyncio
async def test_cve_lookup_invalid_format(cve_lookup_cog: CVELookupCog, mock_bot: MagicMock):
    """Test /cve lookup command with an invalid CVE ID format."""
    # Patch the cog's create_cve_embed (it shouldn't be called anyway)
    with patch.object(cve_lookup_cog, 'create_cve_embed') as patched_create_embed:
        # --- Arrange ---
        mock_interaction = AsyncMock()
        invalid_cve_id = "NOT-A-CVE-ID"

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(cve_lookup_cog, mock_interaction, invalid_cve_id)

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check NVD client was NOT called
        mock_bot.nvd_client.get_cve_details.assert_not_called()
        # Check VulnCheck client was NOT called
        mock_bot.vulncheck_client.get_cve_details.assert_not_called()
        # Check the PATCHED embed creation was NOT called
        patched_create_embed.assert_not_called()
        # Check interaction followup response for invalid format message
        expected_message = "❌ Invalid CVE ID format. Please use `CVE-YYYY-NNNNN...` (e.g., CVE-2023-12345)."
        mock_interaction.followup.send.assert_called_once_with(expected_message, ephemeral=True)
        # Check stats (lock should NOT have been acquired as it returns early)
        mock_bot.stats_lock.__aenter__.assert_not_called()
        assert mock_bot.stats_cve_lookups == 0
        assert mock_bot.stats_nvd_fallback_success == 0
        assert mock_bot.stats_api_errors_nvd == 0

@pytest.mark.asyncio
async def test_cve_lookup_nvd_client_unavailable(cve_lookup_cog: CVELookupCog, mock_bot: MagicMock):
    """Test /cve lookup command when the NVD client is not available on the bot."""
    # Patch the cog's create_cve_embed (it shouldn't be called anyway)
    with patch.object(cve_lookup_cog, 'create_cve_embed') as patched_create_embed:
        # --- Arrange ---
        mock_interaction = AsyncMock()
        test_cve_id = "CVE-2024-11223"

        # Simulate NVD client being None on the bot
        # Note: We need to modify the mock_bot *after* the cog is initialized,
        # because the cog copies the reference in its __init__.
        # A better approach might be to pass clients directly to cog init in tests.
        # For now, let's reflect the current cog structure:
        cve_lookup_cog.nvd_client = None # Directly set the cog's client attribute to None

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(cve_lookup_cog, mock_interaction, test_cve_id)

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check the PATCHED embed creation was NOT called
        patched_create_embed.assert_not_called()
        # Check interaction followup response for client unavailable message
        expected_message = "❌ The NVD client is not configured or failed to initialize. Cannot perform lookup."
        mock_interaction.followup.send.assert_called_once_with(expected_message, ephemeral=True)
        # Check stats (lock should NOT have been acquired as it returns early)
        mock_bot.stats_lock.__aenter__.assert_not_called()
        assert mock_bot.stats_cve_lookups == 0
        assert mock_bot.stats_nvd_fallback_success == 0
        assert mock_bot.stats_api_errors_nvd == 0

@pytest.mark.asyncio
async def test_cve_lookup_nvd_exception(cve_lookup_cog: CVELookupCog, mock_bot: MagicMock):
    """Test /cve lookup command when NVD client raises an exception."""
    # Patch the cog's create_cve_embed (it shouldn't be called anyway)
    with patch.object(cve_lookup_cog, 'create_cve_embed') as patched_create_embed:
        # --- Arrange ---
        mock_interaction = AsyncMock()
        test_cve_id = "CVE-2024-66666"
        test_exception = Exception("Something went wrong during API call")

        # Configure mock bot's NVD client to raise an exception
        mock_bot.nvd_client.get_cve_details = AsyncMock(side_effect=test_exception)

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(cve_lookup_cog, mock_interaction, test_cve_id)

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check NVD was called
        mock_bot.nvd_client.get_cve_details.assert_called_once_with(test_cve_id.upper())
        # Check the PATCHED embed creation was NOT called
        patched_create_embed.assert_not_called()
        # Check interaction followup response for the generic exception message
        expected_message = f"❌ An unexpected error occurred while looking up `{test_cve_id}`. Please try again later."
        mock_interaction.followup.send.assert_called_once_with(expected_message, ephemeral=True)
        # Check stats
        mock_bot.stats_lock.__aenter__.assert_called()
        mock_bot.stats_lock.__aexit__.assert_called()
        assert mock_bot.stats_cve_lookups == 1 # Lookup was attempted
        assert mock_bot.stats_nvd_fallback_success == 0 # Success was not reached
        assert mock_bot.stats_api_errors_nvd == 1 # Exception was caught

# --- NEW Tests for /cve channel --- 

@pytest.mark.asyncio
async def test_channel_enable(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_channel = MagicMock(spec=discord.TextChannel, id=1001, mention="#test-channel")
    mock_db.get_cve_channel_config.return_value = None # Simulate no prior config
    
    await cve_lookup_cog.channel_enable_command.callback(cve_lookup_cog, mock_interaction, mock_channel)
    
    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_db.set_cve_channel_config.assert_called_once_with(
        mock_interaction.guild_id, mock_channel.id, enabled=True, verbose_mode=False, severity_threshold='all'
    )
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ CVE monitoring enabled. Alerts will be sent to {mock_channel.mention}.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_enable_preserves_settings(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_channel = MagicMock(spec=discord.TextChannel, id=1002, mention="#new-channel")
    # Simulate existing config with verbose true and threshold high
    existing_config = {'channel_id': 1001, 'enabled': 0, 'verbose_mode': 1, 'severity_threshold': 'high'}
    mock_db.get_cve_channel_config.return_value = existing_config
    
    await cve_lookup_cog.channel_enable_command.callback(cve_lookup_cog, mock_interaction, mock_channel)
    
    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    # Should preserve verbose and threshold from existing config
    mock_db.set_cve_channel_config.assert_called_once_with(
        mock_interaction.guild_id, mock_channel.id, enabled=True, verbose_mode=True, severity_threshold='high'
    )
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ CVE monitoring enabled. Alerts will be sent to {mock_channel.mention}.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_disable(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    await cve_lookup_cog.channel_disable_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.disable_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "❌ CVE monitoring disabled for this server.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_set(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test that /cve channel set calls the enable logic."""
    mock_channel = MagicMock(spec=discord.TextChannel, id=1003, mention="#set-channel")
    mock_db.get_cve_channel_config.return_value = None # Simulate no prior config

    # Call the set command
    await cve_lookup_cog.channel_set_command.callback(cve_lookup_cog, mock_interaction, mock_channel)

    # Assert that the underlying DB method (called by enable) was called correctly
    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_db.set_cve_channel_config.assert_called_once_with(
        mock_interaction.guild_id, mock_channel.id, enabled=True, verbose_mode=False, severity_threshold='all'
    )
    # Assert the final response message (which comes from the enable logic)
    mock_interaction.response.send_message.assert_called_once_with(
         f"✅ CVE monitoring enabled. Alerts will be sent to {mock_channel.mention}.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_all_enabled(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock, mock_bot: MagicMock):
    config = {'guild_id': 12345, 'channel_id': 1001, 'enabled': 1}
    mock_db.get_cve_channel_config.return_value = config
    mock_channel = MagicMock(spec=discord.TextChannel, mention="#mock-channel")
    mock_bot.get_channel.return_value = mock_channel

    await cve_lookup_cog.channel_all_command.callback(cve_lookup_cog, mock_interaction)

    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_bot.get_channel.assert_called_once_with(1001)
    mock_interaction.response.send_message.assert_called_once_with(
        f"ℹ️ CVE monitoring is **enabled** in: {mock_channel.mention}", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_all_disabled(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_db.get_cve_channel_config.return_value = {'enabled': 0}
    await cve_lookup_cog.channel_all_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "ℹ️ CVE monitoring is currently **disabled** for this server.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_all_no_config(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_db.get_cve_channel_config.return_value = None
    await cve_lookup_cog.channel_all_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "ℹ️ CVE monitoring is currently **disabled** for this server.", ephemeral=True
    )

# --- NEW Tests for /cve verbose ---

@pytest.mark.asyncio
async def test_verbose_enable(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    # Simulate existing, enabled config
    existing_config = {'channel_id': 1001, 'enabled': 1, 'verbose_mode': 0, 'severity_threshold': 'all'}
    mock_db.get_cve_channel_config.return_value = existing_config

    await cve_lookup_cog.verbose_enable_command.callback(cve_lookup_cog, mock_interaction)

    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_db.set_cve_channel_config.assert_called_once_with(
        mock_interaction.guild_id, 1001, enabled=True, verbose_mode=True, severity_threshold='all'
    )
    mock_interaction.response.send_message.assert_called_once_with(
        "✅ Verbose CVE alerts **enabled**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_verbose_enable_when_disabled(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    # Simulate existing but disabled config
    existing_config = {'channel_id': 1001, 'enabled': 0, 'verbose_mode': 0, 'severity_threshold': 'all'}
    mock_db.get_cve_channel_config.return_value = existing_config

    await cve_lookup_cog.verbose_enable_command.callback(cve_lookup_cog, mock_interaction)

    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    # Should not have called set_cve_channel_config
    mock_db.set_cve_channel_config.assert_not_called()
    mock_interaction.response.send_message.assert_called_once_with(
        "ℹ️ Please enable CVE monitoring first using `/cve channel enable` before setting verbosity.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_verbose_disable(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    # Simulate existing, enabled, verbose config
    existing_config = {'channel_id': 1001, 'enabled': 1, 'verbose_mode': 1, 'severity_threshold': 'high'}
    mock_db.get_cve_channel_config.return_value = existing_config

    await cve_lookup_cog.verbose_disable_command.callback(cve_lookup_cog, mock_interaction)

    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_db.set_cve_channel_config.assert_called_once_with(
        mock_interaction.guild_id, 1001, enabled=True, verbose_mode=False, severity_threshold='high'
    )
    mock_interaction.response.send_message.assert_called_once_with(
        "✅ Verbose CVE alerts **disabled**. Standard format will be used.", ephemeral=True
    )

# --- NEW Tests for /cve threshold --- 

@pytest.mark.asyncio
@pytest.mark.parametrize("level", ["critical", "high", "medium", "low", "all"])
async def test_threshold_set(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock, level: str):
    await cve_lookup_cog.threshold_set_command.callback(cve_lookup_cog, mock_interaction, level=level)
    mock_db.set_cve_severity_threshold.assert_called_once_with(mock_interaction.guild_id, level)
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ CVE alert severity threshold set to **{level}**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_threshold_view(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_db.get_cve_channel_config.return_value = {'severity_threshold': 'high'}
    await cve_lookup_cog.threshold_view_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "ℹ️ Current CVE alert severity threshold is **high**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_threshold_view_no_config(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    mock_db.get_cve_channel_config.return_value = None
    await cve_lookup_cog.threshold_view_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.get_cve_channel_config.assert_called_once_with(mock_interaction.guild_id)
    mock_interaction.response.send_message.assert_called_once_with(
        "ℹ️ Current CVE alert severity threshold is **all**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_threshold_reset(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    await cve_lookup_cog.threshold_reset_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.set_cve_severity_threshold.assert_called_once_with(mock_interaction.guild_id, 'all')
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ CVE alert severity threshold reset to **all**.", ephemeral=True
    )

# --- NEW Tests for /cve latest --- 

@pytest.mark.asyncio
async def test_cve_latest_success(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    """Test basic /cve latest success case."""
    mock_cve1 = {'id': 'CVE-2024-0001', 'description': 'Desc 1', 'cvss': 9.8, 'published': '2024-04-27T10:00:00', 'link': 'link1'}
    mock_cve2 = {'id': 'CVE-2024-0002', 'description': 'Desc 2', 'cvss': 5.0, 'published': '2024-04-26T10:00:00', 'link': 'link2'}
    mock_bot.nvd_client.get_recent_cves.return_value = [mock_cve1, mock_cve2]
    # Mock KEV client just in case filter is added later or default is True
    mock_bot.cisa_kev_client.get_full_kev_catalog = AsyncMock(return_value=[]) 

    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction, count=5, days=7)

    mock_bot.nvd_client.get_recent_cves.assert_called_once_with(days=7)
    mock_interaction.response.defer.assert_called_once()
    # Check that followup.send was called (embed check is complex, just check call)
    mock_interaction.followup.send.assert_called_once()
    # Verify embed content roughly
    args, kwargs = mock_interaction.followup.send.call_args
    assert 'embed' in kwargs
    embed = kwargs['embed']
    assert isinstance(embed, discord.Embed)
    assert embed.title == "Recent CVEs (Last 7 days)"
    assert str(mock_cve1['id']) in embed.description
    assert str(mock_cve2['id']) in embed.description
    assert "Showing top 2" in embed.footer.text

@pytest.mark.asyncio
async def test_cve_latest_with_filters(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    """Test /cve latest with severity and KEV filters."""
    mock_cve1 = {'id': 'CVE-2024-0001', 'description': 'Desc 1', 'cvss': 9.8, 'published': '2024-04-27T10:00:00', 'link': 'link1'}
    mock_cve2 = {'id': 'CVE-2024-0002', 'description': 'Desc 2', 'cvss': 5.0, 'published': '2024-04-26T10:00:00', 'link': 'link2'}
    mock_cve3 = {'id': 'CVE-2024-0003', 'description': 'Desc 3', 'cvss': 8.0, 'published': '2024-04-25T10:00:00', 'link': 'link3'}
    mock_bot.nvd_client.get_recent_cves.return_value = [mock_cve1, mock_cve2, mock_cve3]
    # Simulate CVE-1 and CVE-3 being in KEV
    mock_bot.cisa_kev_client.get_full_kev_catalog = AsyncMock(return_value=[
        {'cveID': 'CVE-2024-0001'}, {'cveID': 'CVE-2024-0003'}
    ]) 

    # Filter: severity >= high (7.0), in_kev=True
    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction, severity='high', in_kev=True)

    mock_bot.nvd_client.get_recent_cves.assert_called_once()
    mock_bot.cisa_kev_client.get_full_kev_catalog.assert_called_once()
    mock_interaction.followup.send.assert_called_once()
    
    args, kwargs = mock_interaction.followup.send.call_args
    embed = kwargs['embed']
    # Only CVE-1 (9.8, KEV) and CVE-3 (8.0, KEV) should match
    assert str(mock_cve1['id']) in embed.description
    assert str(mock_cve3['id']) in embed.description
    assert str(mock_cve2['id']) not in embed.description # CVSS too low
    assert "severity>=high" in embed.title
    assert "in_kev=True" in embed.title
    assert "Showing top 2" in embed.footer.text

@pytest.mark.asyncio
async def test_cve_latest_no_results(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    """Test /cve latest when NVD client returns an empty list."""
    mock_bot.nvd_client.get_recent_cves.return_value = []

    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction, days=3)

    mock_bot.nvd_client.get_recent_cves.assert_called_once_with(days=3)
    mock_interaction.followup.send.assert_called_once_with(
        f"⚪ No CVEs found published in the last 3 days.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_cve_latest_nvd_fail(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    """Test /cve latest when NVD client returns None."""
    mock_bot.nvd_client.get_recent_cves.return_value = None

    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction)

    mock_bot.nvd_client.get_recent_cves.assert_called_once()
    mock_interaction.followup.send.assert_called_once_with(
        "❌ Failed to fetch recent CVE data from NVD.", ephemeral=True
    )

# --- Existing Tests for create_cve_embed --- 

def test_create_cve_embed_basic(cve_lookup_cog: CVELookupCog):
    """Test basic embed creation with essential fields."""
    cve_data = {
        "id": "CVE-2024-99999",
        "link": "http://example.com/cve",
        "description": "This is a test description.",
        "source": "Test Source"
    }
    embed = cve_lookup_cog.create_cve_embed(cve_data)

    assert isinstance(embed, discord.Embed)
    assert embed.title == "CVE-2024-99999"
    assert embed.url == "http://example.com/cve"
    assert embed.description == "This is a test description."
    assert embed.footer.text == "Source: Test Source"
    assert len(embed.fields) == 0 # No optional fields added

def test_create_cve_embed_with_cvss(cve_lookup_cog: CVELookupCog):
    """Test embed creation includes CVSS score and vector."""
    cve_data = {
        "id": "CVE-2024-99998",
        "description": "Desc",
        "cvss": "9.8",
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
    embed = cve_lookup_cog.create_cve_embed(cve_data)

    assert len(embed.fields) == 2
    assert embed.fields[0].name == "CVSS Vector"
    assert embed.fields[0].value == "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`"
    assert embed.fields[1].name == "CVSS Score"
    assert embed.fields[1].value == "**Score:** 9.8 (3.1)"

def test_create_cve_embed_with_details(cve_lookup_cog: CVELookupCog):
    """Test embed creation includes CWE, dates, and references."""
    cve_data = {
        "id": "CVE-2024-99997",
        "description": "Desc",
        "cwe_ids": ["CWE-79", "CWE-89"],
        "published": "2024-01-01T00:00:00.000Z",
        "modified": "2024-02-01T12:00:00.000Z",
        "references": [
            {"source": "Source1", "url": "http://ref1.com", "tags": ["tagA"]},
            {"source": "Source2", "url": "http://ref2.com", "tags": ["tagB", "tagC"]}
        ]
    }
    embed = cve_lookup_cog.create_cve_embed(cve_data)

    assert len(embed.fields) == 4 # CWE, Published, Modified, References
    assert embed.fields[0].name == "Weakness (CWE)"
    assert embed.fields[0].value == "CWE-79, CWE-89"
    assert embed.fields[1].name == "Published"
    assert embed.fields[1].value == "2024-01-01T00:00:00.000Z"
    assert embed.fields[2].name == "Last Modified"
    assert embed.fields[2].value == "2024-02-01T12:00:00.000Z"
    assert embed.fields[3].name == "References"
    assert "[Source1](http://ref1.com) (tagA)" in embed.fields[3].value
    assert "[Source2](http://ref2.com) (tagB, tagC)" in embed.fields[3].value

def test_create_cve_embed_reference_limit(cve_lookup_cog: CVELookupCog):
    """Test embed creation limits the number of references shown."""
    cve_data = {
        "id": "CVE-2024-99996",
        "description": "Desc",
        "references": [
            {"source": f"Ref{i}", "url": f"http://ref{i}.com"} for i in range(10)
        ]
    }
    embed = cve_lookup_cog.create_cve_embed(cve_data)
    ref_field = next((f for f in embed.fields if f.name == "References"), None)
    assert ref_field is not None
    # Check for the first 5 refs and the '...and X more' text
    for i in range(5):
        assert f"[Ref{i}](http://ref{i}.com)" in ref_field.value
    assert f"...and {10 - 5} more." in ref_field.value

# Note: Removed old TODOs, covered basic /cve lookup cases.
# Need to potentially add more detailed tests for different CVSS versions in create_cve_embed. 