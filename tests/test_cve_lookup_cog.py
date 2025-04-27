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
    return CVELookupCog(mock_bot)

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
    """Test /cve channel enable command."""
    mock_channel = MagicMock(spec=discord.TextChannel, id=67890, mention="<#67890>")
    mock_interaction.guild_id = 12345
    
    # Simulate no existing guild config initially
    mock_db.get_cve_guild_config.return_value = None 

    await cve_lookup_cog.channel_enable_command.callback(cve_lookup_cog, mock_interaction, mock_channel)

    # Check guild config creation/update was called
    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.set_cve_guild_config.assert_called_once_with(12345, enabled=True, verbose_mode=False, severity_threshold='all')
    mock_db.update_cve_guild_enabled.assert_not_called() # Shouldn't be called if created new

    # Check channel config add/update was called
    mock_db.add_or_update_cve_channel.assert_called_once_with(
        guild_id=12345, 
        channel_id=67890, 
        enabled=True,
        verbose_mode=None,
        severity_threshold=None,
        alert_format=None
    )
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ CVE monitoring configured for channel {mock_channel.mention}.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_enable_when_guild_disabled(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve channel enable when guild config exists but is disabled."""
    mock_channel = MagicMock(spec=discord.TextChannel, id=67890, mention="<#67890>")
    mock_interaction.guild_id = 12345

    # Simulate existing but disabled guild config
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'enabled': False, 'verbose_mode': False, 'severity_threshold': 'all'}
    
    await cve_lookup_cog.channel_enable_command.callback(cve_lookup_cog, mock_interaction, mock_channel)

    # Check guild config check and update
    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.set_cve_guild_config.assert_not_called() # Should not create new
    mock_db.update_cve_guild_enabled.assert_called_once_with(12345, True) # Should enable globally

    # Check channel config add/update
    mock_db.add_or_update_cve_channel.assert_called_once_with(
        guild_id=12345, channel_id=67890, enabled=True, 
        verbose_mode=None, severity_threshold=None, alert_format=None
    )
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ CVE monitoring configured for channel {mock_channel.mention}.", ephemeral=True
    )


@pytest.mark.asyncio
async def test_channel_disable(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve channel disable command."""
    # NOTE: The current disable command implementation calls a method `disable_cve_channel_config`
    # which doesn't seem to exist in the refactored db_utils. It should likely call
    # `update_cve_guild_enabled(guild_id, False)` instead. 
    # We will test the *intended* behavior based on the refactored DB structure.
    mock_interaction.guild_id = 12345
    
    await cve_lookup_cog.channel_disable_command.callback(cve_lookup_cog, mock_interaction)
    
    # Assert that the correct method *should* be called
    # Assuming the command is fixed to call update_cve_guild_enabled:
    mock_db.update_cve_guild_enabled.assert_called_once_with(12345, False)
    mock_interaction.response.send_message.assert_called_once_with(
        "❌ CVE monitoring disabled for this server.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_set(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve channel set command (should behave like enable)."""
    # This test is similar to test_channel_enable
    mock_channel = MagicMock(spec=discord.TextChannel, id=67890, mention="<#67890>")
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = None # Simulate no existing config

    await cve_lookup_cog.channel_set_command.callback(cve_lookup_cog, mock_interaction, mock_channel)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.set_cve_guild_config.assert_called_once_with(12345, enabled=True, verbose_mode=False, severity_threshold='all')
    mock_db.add_or_update_cve_channel.assert_called_once_with(
        guild_id=12345, channel_id=67890, enabled=True,
        verbose_mode=None, severity_threshold=None, alert_format=None
    )
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ CVE monitoring configured for channel {mock_channel.mention}.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_all_enabled(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock, mock_bot: MagicMock):
    """Test /cve channel all when enabled (using new DB structure)."""
    # NOTE: This command also needs updating. It should list channels from `cve_channel_configs`
    # not just check the global config. We test the *expected* behavior assuming multi-channel.
    mock_interaction.guild_id = 12345
    mock_channel_1 = MagicMock(spec=discord.TextChannel, id=111, mention="<#111>", name="alerts-1")
    mock_channel_2 = MagicMock(spec=discord.TextChannel, id=222, mention="<#222>", name="alerts-2")
    
    # Simulate global config being enabled
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'enabled': True}
    # Simulate multiple channels configured
    mock_db.get_all_cve_channel_configs_for_guild.return_value = [
        {'guild_id': 12345, 'channel_id': 111, 'enabled': True}, 
        {'guild_id': 12345, 'channel_id': 222, 'enabled': True}
    ]
    # Mock bot channel fetching
    mock_bot.get_channel = MagicMock(side_effect=lambda id: mock_channel_1 if id == 111 else mock_channel_2 if id == 222 else None)

    await cve_lookup_cog.channel_all_command.callback(cve_lookup_cog, mock_interaction)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.get_all_cve_channel_configs_for_guild.assert_called_once_with(12345)
    expected_message = f"ℹ️ CVE monitoring is **enabled** globally.\nConfigured channels:\n- {mock_channel_1.mention}\n- {mock_channel_2.mention}"
    mock_interaction.response.send_message.assert_called_once_with(expected_message, ephemeral=True)

@pytest.mark.asyncio
async def test_channel_all_disabled(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve channel all when globally disabled."""
    mock_interaction.guild_id = 12345
    # Simulate global config being disabled
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'enabled': False}

    await cve_lookup_cog.channel_all_command.callback(cve_lookup_cog, mock_interaction)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    # Should not fetch individual channels if globally disabled
    mock_db.get_all_cve_channel_configs_for_guild.assert_not_called()
    mock_interaction.response.send_message.assert_called_once_with(
        "ℹ️ CVE monitoring is currently **disabled** globally for this server.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_channel_all_no_config(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve channel all when no global config exists."""
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = None # No config found

    await cve_lookup_cog.channel_all_command.callback(cve_lookup_cog, mock_interaction)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.get_all_cve_channel_configs_for_guild.assert_not_called()
    mock_interaction.response.send_message.assert_called_once_with(
        "ℹ️ CVE monitoring is currently **disabled** globally for this server.", ephemeral=True
    )

# --- Tests for /verbose commands ---

@pytest.mark.asyncio
async def test_verbose_enable_global(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /verbose enable_global command."""
    await cve_lookup_cog.verbose_enable_global_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.update_cve_guild_verbose_mode.assert_called_once_with(mock_interaction.guild_id, True)
    mock_interaction.response.send_message.assert_called_once_with(
        "✅ Global verbose CVE alerts **enabled**. Specific channel settings may override this.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_verbose_disable_global(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /verbose disable_global command."""
    await cve_lookup_cog.verbose_disable_global_command.callback(cve_lookup_cog, mock_interaction)
    mock_db.update_cve_guild_verbose_mode.assert_called_once_with(mock_interaction.guild_id, False)
    mock_interaction.response.send_message.assert_called_once_with(
        "✅ Global verbose CVE alerts **disabled**. Standard format will be used (unless channels override).", ephemeral=True
    )

@pytest.mark.asyncio
@pytest.mark.parametrize("verbosity_param", [True, False])
async def test_verbose_channel_set(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock, verbosity_param: bool):
    """Test /verbose set command for a specific channel."""
    mock_channel = MagicMock(spec=discord.TextChannel, id=67890, mention="<#67890>")
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345} # Simulate guild config exists

    await cve_lookup_cog.verbose_channel_set_command.callback(cve_lookup_cog, mock_interaction, mock_channel, verbosity_param)

    mock_db.set_channel_verbosity.assert_called_once_with(12345, mock_channel.id, verbosity_param)
    status_text = "verbose" if verbosity_param else "standard (non-verbose)"
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ Verbosity for {mock_channel.mention} set to **{status_text}**. This overrides the global setting.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_verbose_channel_unset(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /verbose unset command for a specific channel."""
    mock_channel = MagicMock(spec=discord.TextChannel, id=67890, mention="<#67890>")
    mock_interaction.guild_id = 12345

    await cve_lookup_cog.verbose_channel_unset_command.callback(cve_lookup_cog, mock_interaction, mock_channel)

    # Check that it calls set_channel_verbosity with None
    mock_db.set_channel_verbosity.assert_called_once_with(12345, mock_channel.id, None)
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ Verbosity override for {mock_channel.mention} **removed**. It will now use the global server setting.", ephemeral=True
    )

@pytest.mark.asyncio
@pytest.mark.parametrize("verbosity_param", [True, False])
async def test_verbose_channel_setall(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock, verbosity_param: bool):
    """Test /verbose setall command."""
    mock_interaction.guild_id = 12345

    await cve_lookup_cog.verbose_channel_setall_command.callback(cve_lookup_cog, mock_interaction, verbosity_param)

    mock_db.set_all_channel_verbosity.assert_called_once_with(12345, verbosity_param)
    status_text = "verbose" if verbosity_param else "standard (non-verbose)"
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ Verbosity override for **all configured channels** set to **{status_text}**. This may differ from the global setting.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_verbose_status_global_only(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /verbose status with only global setting (no channel overrides)."""
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'verbose_mode': True} # Global verbose is True
    mock_db.get_all_cve_channel_configs_for_guild.return_value = [] # No channel configs

    await cve_lookup_cog.verbose_channel_status_command.callback(cve_lookup_cog, mock_interaction, channel=None)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.get_all_cve_channel_configs_for_guild.assert_called_once_with(12345)
    
    call_args, call_kwargs = mock_interaction.response.send_message.call_args
    sent_embed = call_kwargs.get('embed')
    assert isinstance(sent_embed, discord.Embed)
    assert "Global Setting: **Verbose**" in sent_embed.description
    assert len(sent_embed.fields) == 1
    assert sent_embed.fields[0].name == "Channel Overrides"
    assert "No channels have specific verbosity overrides" in sent_embed.fields[0].value
    assert call_kwargs.get('ephemeral') is True

@pytest.mark.asyncio
async def test_verbose_status_with_overrides(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock, mock_bot: MagicMock):
    """Test /verbose status with global setting and channel overrides."""
    mock_interaction.guild_id = 12345
    mock_channel_1 = MagicMock(spec=discord.TextChannel, id=111, name="alerts-verbose")
    mock_channel_2 = MagicMock(spec=discord.TextChannel, id=222, name="alerts-standard")
    mock_channel_3 = MagicMock(spec=discord.TextChannel, id=333, name="alerts-global")
    
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'verbose_mode': False} # Global verbose is False
    mock_db.get_all_cve_channel_configs_for_guild.return_value = [
        {'channel_id': 111, 'verbose_mode': True}, # Override: True
        {'channel_id': 222, 'verbose_mode': False},# Override: False
        {'channel_id': 333, 'verbose_mode': None}  # No override (inherits global)
    ]
    # Mock bot channel fetching
    def get_channel_side_effect(id_):
        if id_ == 111: return mock_channel_1
        if id_ == 222: return mock_channel_2
        if id_ == 333: return mock_channel_3
        return None
    mock_bot.get_channel = MagicMock(side_effect=get_channel_side_effect)

    await cve_lookup_cog.verbose_channel_status_command.callback(cve_lookup_cog, mock_interaction, channel=None)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.get_all_cve_channel_configs_for_guild.assert_called_once_with(12345)
    
    call_args, call_kwargs = mock_interaction.response.send_message.call_args
    sent_embed = call_kwargs.get('embed')
    assert isinstance(sent_embed, discord.Embed)
    assert "Global Setting: **Standard (Non-Verbose)**" in sent_embed.description
    assert len(sent_embed.fields) == 1
    assert sent_embed.fields[0].name == "Channel Overrides"
    assert "#alerts-verbose: **Verbose** (Override)" in sent_embed.fields[0].value
    assert "#alerts-standard: **Standard** (Override)" in sent_embed.fields[0].value
    assert "#alerts-global" not in sent_embed.fields[0].value # Should not list channels without override
    assert call_kwargs.get('ephemeral') is True

@pytest.mark.asyncio
async def test_verbose_status_specific_channel_override(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /verbose status for a specific channel with an override."""
    mock_channel = MagicMock(spec=discord.TextChannel, id=111, name="channel-with-override")
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'verbose_mode': False} # Global False
    mock_db.get_cve_channel_config.return_value = {'channel_id': 111, 'verbose_mode': True} # Override True

    await cve_lookup_cog.verbose_channel_status_command.callback(cve_lookup_cog, mock_interaction, channel=mock_channel)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.get_cve_channel_config.assert_called_once_with(12345, mock_channel.id)
    
    call_args, call_kwargs = mock_interaction.response.send_message.call_args
    sent_embed = call_kwargs.get('embed')
    assert isinstance(sent_embed, discord.Embed)
    assert "Global Setting: **Standard (Non-Verbose)**" in sent_embed.description
    assert len(sent_embed.fields) == 1
    assert sent_embed.fields[0].name == f"#{mock_channel.name}"
    assert sent_embed.fields[0].value == "Verbose (Override)"
    assert call_kwargs.get('ephemeral') is True

@pytest.mark.asyncio
async def test_verbose_status_specific_channel_inherit(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /verbose status for a specific channel inheriting global setting."""
    mock_channel = MagicMock(spec=discord.TextChannel, id=222, name="channel-inheriting")
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'verbose_mode': True} # Global True
    mock_db.get_cve_channel_config.return_value = {'channel_id': 222, 'verbose_mode': None} # Override None

    await cve_lookup_cog.verbose_channel_status_command.callback(cve_lookup_cog, mock_interaction, channel=mock_channel)

    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_db.get_cve_channel_config.assert_called_once_with(12345, mock_channel.id)
    
    call_args, call_kwargs = mock_interaction.response.send_message.call_args
    sent_embed = call_kwargs.get('embed')
    assert isinstance(sent_embed, discord.Embed)
    assert "Global Setting: **Verbose**" in sent_embed.description
    assert len(sent_embed.fields) == 1
    assert sent_embed.fields[0].name == f"#{mock_channel.name}"
    assert sent_embed.fields[0].value == "Inheriting Global (Verbose)"
    assert call_kwargs.get('ephemeral') is True


# --- Tests for /cve threshold --- 
# These tests need updating based on the DB method changes

@pytest.mark.asyncio
@pytest.mark.parametrize("level", ["critical", "high", "medium", "low", "all"])
async def test_threshold_set(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock, level: str):
    """Test /cve threshold set command (using updated DB method)."""
    await cve_lookup_cog.threshold_set_command.callback(cve_lookup_cog, mock_interaction, level)
    # Check the correct DB method is called
    mock_db.update_cve_guild_severity_threshold.assert_called_once_with(mock_interaction.guild_id, level)
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ Global CVE alert severity threshold set to **{level}**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_threshold_view(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve threshold view command (using updated DB method)."""
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = {'guild_id': 12345, 'severity_threshold': 'high'} 
    
    await cve_lookup_cog.threshold_view_command.callback(cve_lookup_cog, mock_interaction)
    
    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    mock_interaction.response.send_message.assert_called_once_with(
        f"ℹ️ Current global CVE alert severity threshold is **high**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_threshold_view_no_config(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve threshold view when no guild config exists."""
    mock_interaction.guild_id = 12345
    mock_db.get_cve_guild_config.return_value = None # No config
    
    await cve_lookup_cog.threshold_view_command.callback(cve_lookup_cog, mock_interaction)
    
    mock_db.get_cve_guild_config.assert_called_once_with(12345)
    # Should default to 'all'
    mock_interaction.response.send_message.assert_called_once_with(
        f"ℹ️ Current global CVE alert severity threshold is **all**.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_threshold_reset(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_db: MagicMock):
    """Test /cve threshold reset command (using updated DB method)."""
    await cve_lookup_cog.threshold_reset_command.callback(cve_lookup_cog, mock_interaction)
    # Check the correct DB method is called with 'all'
    mock_db.update_cve_guild_severity_threshold.assert_called_once_with(mock_interaction.guild_id, 'all')
    mock_interaction.response.send_message.assert_called_once_with(
        "✅ Global CVE alert severity threshold reset to **all**.", ephemeral=True
    )


# --- Tests for /cve latest --- (Keep existing tests, ensure they don't break)
@pytest.mark.asyncio
async def test_cve_latest_success(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    # ... (Implementation as before) ...
    mock_bot.nvd_client.get_recent_cves = AsyncMock(return_value=[{"id": "CVE-1", "published": "2024-01-01T00:00:00.000"}])
    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction)
    assert mock_interaction.followup.send.call_args[1].get('embed').title == "Recent CVEs (Last 7 days)"

@pytest.mark.asyncio
async def test_cve_latest_with_filters(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    # ... (Implementation as before) ...
    mock_bot.nvd_client.get_recent_cves = AsyncMock(return_value=[
        {"id": "CVE-1", "published": "2024-01-01T00:00:00.000", "cvss": 9.5}, 
        {"id": "CVE-2", "published": "2024-01-02T00:00:00.000", "cvss": 5.0}
    ])
    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction, severity="high")
    sent_embed = mock_interaction.followup.send.call_args[1].get('embed')
    assert "severity>=high" in sent_embed.title
    assert "CVE-1" in sent_embed.description
    assert "CVE-2" not in sent_embed.description

@pytest.mark.asyncio
async def test_cve_latest_no_results(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    # ... (Implementation as before) ...
    mock_bot.nvd_client.get_recent_cves = AsyncMock(return_value=[])
    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction)
    mock_interaction.followup.send.assert_called_with(
        "⚪ No CVEs found published in the last 7 days.", ephemeral=True
    )

@pytest.mark.asyncio
async def test_cve_latest_nvd_fail(cve_lookup_cog: CVELookupCog, mock_interaction: AsyncMock, mock_bot: MagicMock):
    # ... (Implementation as before) ...
    mock_bot.nvd_client.get_recent_cves = AsyncMock(return_value=None)
    await cve_lookup_cog.cve_latest_command.callback(cve_lookup_cog, mock_interaction)
    mock_interaction.followup.send.assert_called_with(
        "❌ Failed to fetch recent CVE data from NVD.", ephemeral=True
    )

# --- Tests for create_cve_embed --- (Keep existing tests)
# ... (tests for embed creation remain the same) ...

# Fixture to provide a sample CVE dictionary
@pytest.fixture
def sample_cve_data():
    return {
        "id": "CVE-2024-1234",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "description": "This is a test CVE description.",
        "cvss": 7.5,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_ids": ["CWE-79"],
        "published": "2024-01-15T10:00:00.000",
        "modified": "2024-01-20T12:30:00.000",
        "references": [
            {"source": "NIST", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
            {"source": "ExploitDB", "url": "https://exploit-db.com/exploits/12345", "tags": ["Exploit"]}
        ],
        "source": "NVD"
    }

def test_create_cve_embed_basic(cve_lookup_cog: CVELookupCog, sample_cve_data):
    """Test basic embed creation (non-verbose)."""
    embed = cve_lookup_cog.create_cve_embed(sample_cve_data, verbose=False)
    assert isinstance(embed, discord.Embed)
    assert embed.title == "CVE-2024-1234"
    assert embed.url == sample_cve_data['link']
    assert "[View on NVD]" in embed.description
    assert len(embed.fields) == 2 # Only ID and Score in non-verbose base
    assert embed.fields[0].name == "CVE ID"
    assert embed.fields[1].name == "CVSS Score"

def test_create_cve_embed_verbose(cve_lookup_cog: CVELookupCog, sample_cve_data):
    """Test verbose embed creation."""
    embed = cve_lookup_cog.create_cve_embed(sample_cve_data, verbose=True)
    assert isinstance(embed, discord.Embed)
    assert embed.description == sample_cve_data['description']
    assert len(embed.fields) > 4 # Should have more fields in verbose mode
    assert any(field.name == "Published" for field in embed.fields)
    assert any(field.name == "CVSS Vector" for field in embed.fields)
    assert any(field.name == "Weakness (CWE)" for field in embed.fields)
    assert any(field.name == "References" for field in embed.fields)


def test_create_cve_embed_reference_limit(cve_lookup_cog: CVELookupCog, sample_cve_data):
    """Test that references are limited in verbose mode."""
    # Add more references than the limit
    sample_cve_data['references'].extend([{"source": f"Link{i}", "url": f"http://example.com/{i}"} for i in range(10)])
    
    embed = cve_lookup_cog.create_cve_embed(sample_cve_data, verbose=True)
    
    ref_field = next((f for f in embed.fields if f.name == "References"), None)
    assert ref_field is not None
    # Assuming MAX_REFERENCE_LINKS is 5
    assert ref_field.value.count("http://") == 5 
    assert "more references not shown" in ref_field.value


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