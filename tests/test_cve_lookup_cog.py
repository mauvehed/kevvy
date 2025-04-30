import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
import discord

# Need to import the cog and potentially other classes
from kevvy.cogs.cve_lookup import CVELookupCog
from kevvy.vulncheck_client import VulnCheckClient  # For type hinting mocks
from kevvy.nvd_client import NVDClient  # For type hinting mocks
from kevvy.bot import SecurityBot  # For type hinting mocks
from kevvy.db_utils import KEVConfigDB  # Added for DB testing


@pytest.fixture
def mock_db():
    """Fixture for a mock KEVConfigDB."""
    db = MagicMock(spec=KEVConfigDB)
    # Default return for config fetch
    db.get_cve_channel_config = MagicMock(return_value=None)
    return db


@pytest.fixture
def mock_bot(mock_db):  # Inject mock_db into mock_bot
    """Fixture to create a mock SecurityBot with mocked clients and DB."""
    bot = MagicMock(spec=SecurityBot)
    bot.vulncheck_client = MagicMock(spec=VulnCheckClient)
    bot.nvd_client = MagicMock(spec=NVDClient)
    bot.cisa_kev_client = MagicMock()  # Mock KEV client too
    bot.db = mock_db  # Assign the mock DB
    bot.stats_lock = AsyncMock()
    bot.stats_cve_lookups = 0
    bot.stats_vulncheck_success = 0
    bot.stats_nvd_fallback_success = 0
    bot.stats_api_errors_vulncheck = 0
    bot.stats_api_errors_nvd = 0
    bot.get_channel = MagicMock(
        return_value=MagicMock(spec=discord.TextChannel, mention="#mock-channel")
    )  # Mock channel fetch
    return bot


@pytest.fixture
def cve_lookup_cog(mock_bot):
    """Fixture to create an instance of the CVELookupCog with the mock bot."""
    return CVELookupCog(mock_bot)


@pytest.fixture
def mock_interaction():
    """Fixture for a generic mock Interaction."""
    interaction = AsyncMock(spec=discord.Interaction)
    interaction.guild_id = 12345  # Default guild ID
    interaction.user = MagicMock(spec=discord.Member, id=98765)
    interaction.response = AsyncMock()
    interaction.followup = AsyncMock()
    return interaction


# --- Helper for Permissions Check ---


async def check_permissions(cog_command, interaction: AsyncMock):
    """Helper to simulate a permissions check failure."""
    # Simulate the check failing by raising the specific error
    interaction.response.send_message.side_effect = (
        discord.app_commands.MissingPermissions(["manage_guild"])
    )
    with pytest.raises(discord.app_commands.MissingPermissions):
        # Call the command's callback directly
        # Note: This assumes the check decorator is correctly applied
        # and the error handler in the cog catches MissingPermissions.
        # We might need to adjust args depending on the command.
        # For simple commands like disable/reset/view:
        if cog_command.name in ["disable", "reset", "view"]:
            await cog_command.callback(cog_command.__self__, interaction)
        elif cog_command.name == "set":  # Set needs level
            await cog_command.callback(cog_command.__self__, interaction, level="high")
        elif cog_command.name == "enable":  # Enable needs channel
            mock_channel = MagicMock(spec=discord.TextChannel)
            await cog_command.callback(
                cog_command.__self__, interaction, channel=mock_channel
            )
        else:
            pytest.fail(
                f"Unsupported command for check_permissions helper: {cog_command.name}"
            )

    interaction.response.send_message.assert_called_with(
        "🚫 You need the 'Manage Server' permission to use this command.",
        ephemeral=True,
    )


# --- Existing Tests for /cve lookup ---


@pytest.mark.asyncio
async def test_cve_lookup_success_nvd(
    cve_lookup_cog: CVELookupCog, mock_bot: MagicMock
):
    """Test /cve lookup command succeeding using the NVD client."""
    # --- Arrange ---
    mock_interaction = AsyncMock()
    test_cve_id = "CVE-2024-12345"
    mock_cve_data = {"id": test_cve_id, "description": "Mock NVD Data"}
    mock_embed = MagicMock(spec=discord.Embed)  # Mock the embed that WOULD be created

    # Patch the cog's create_cve_embed method *for this test only*
    with patch.object(
        cve_lookup_cog, "create_cve_embed", return_value=mock_embed
    ) as patched_create_embed:
        # Configure mock bot's clients - NVD returns data this time
        mock_bot.vulncheck_client.get_cve_details = AsyncMock(return_value=None)
        mock_bot.nvd_client.get_cve_details = AsyncMock(return_value=mock_cve_data)

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(
            cve_lookup_cog, mock_interaction, test_cve_id
        )

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check NVD was called
        mock_bot.nvd_client.get_cve_details.assert_called_once_with(
            test_cve_id.upper()
        )  # Code calls .upper()
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
    with patch.object(cve_lookup_cog, "create_cve_embed") as patched_create_embed:
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
        await cve_lookup_cog.lookup_subcommand.callback(
            cve_lookup_cog, mock_interaction, test_cve_id
        )

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
        assert mock_bot.stats_cve_lookups == 1  # Lookup was attempted
        assert mock_bot.stats_nvd_fallback_success == 0  # Success was not reached
        assert mock_bot.stats_api_errors_nvd == 0  # No exception occurred


@pytest.mark.asyncio
async def test_cve_lookup_invalid_format(
    cve_lookup_cog: CVELookupCog, mock_bot: MagicMock
):
    """Test /cve lookup command with an invalid CVE ID format."""
    # Patch the cog's create_cve_embed (it shouldn't be called anyway)
    with patch.object(cve_lookup_cog, "create_cve_embed") as patched_create_embed:
        # --- Arrange ---
        mock_interaction = AsyncMock()
        invalid_cve_id = "NOT-A-CVE-ID"

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(
            cve_lookup_cog, mock_interaction, invalid_cve_id
        )

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
        mock_interaction.followup.send.assert_called_once_with(
            expected_message, ephemeral=True
        )
        # Check stats (lock should NOT have been acquired as it returns early)
        mock_bot.stats_lock.__aenter__.assert_not_called()
        assert mock_bot.stats_cve_lookups == 0
        assert mock_bot.stats_nvd_fallback_success == 0
        assert mock_bot.stats_api_errors_nvd == 0


@pytest.mark.asyncio
async def test_cve_lookup_nvd_client_unavailable(
    cve_lookup_cog: CVELookupCog, mock_bot: MagicMock
):
    """Test /cve lookup command when the NVD client is not available on the bot."""
    # Patch the cog's create_cve_embed (it shouldn't be called anyway)
    with patch.object(cve_lookup_cog, "create_cve_embed") as patched_create_embed:
        # --- Arrange ---
        mock_interaction = AsyncMock()
        test_cve_id = "CVE-2024-11223"

        # Simulate NVD client being None on the bot
        # Note: We need to modify the mock_bot *after* the cog is initialized,
        # because the cog copies the reference in its __init__.
        # A better approach might be to pass clients directly to cog init in tests.
        # For now, let's reflect the current cog structure:
        cve_lookup_cog.nvd_client = (
            None  # Directly set the cog's client attribute to None
        )

        # Reset stats for this test
        mock_bot.stats_cve_lookups = 0
        mock_bot.stats_nvd_fallback_success = 0
        mock_bot.stats_api_errors_nvd = 0

        # --- Act ---
        await cve_lookup_cog.lookup_subcommand.callback(
            cve_lookup_cog, mock_interaction, test_cve_id
        )

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check the PATCHED embed creation was NOT called
        patched_create_embed.assert_not_called()
        # Check interaction followup response for client unavailable message
        expected_message = "❌ The NVD client is not configured or failed to initialize. Cannot perform lookup."
        mock_interaction.followup.send.assert_called_once_with(
            expected_message, ephemeral=True
        )
        # Check stats (lock should NOT have been acquired as it returns early)
        mock_bot.stats_lock.__aenter__.assert_not_called()
        assert mock_bot.stats_cve_lookups == 0
        assert mock_bot.stats_nvd_fallback_success == 0
        assert mock_bot.stats_api_errors_nvd == 0


@pytest.mark.asyncio
async def test_cve_lookup_nvd_exception(
    cve_lookup_cog: CVELookupCog, mock_bot: MagicMock
):
    """Test /cve lookup command when NVD client raises an exception."""
    # Patch the cog's create_cve_embed (it shouldn't be called anyway)
    with patch.object(cve_lookup_cog, "create_cve_embed") as patched_create_embed:
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
        await cve_lookup_cog.lookup_subcommand.callback(
            cve_lookup_cog, mock_interaction, test_cve_id
        )

        # --- Assert ---
        # Check interaction was deferred
        mock_interaction.response.defer.assert_called_once()
        # Check NVD was called
        mock_bot.nvd_client.get_cve_details.assert_called_once_with(test_cve_id.upper())
        # Check the PATCHED embed creation was NOT called
        patched_create_embed.assert_not_called()
        # Check interaction followup response for the generic exception message
        expected_message = f"❌ An unexpected error occurred while looking up `{test_cve_id}`. Please try again later."
        mock_interaction.followup.send.assert_called_once_with(
            expected_message, ephemeral=True
        )
        # Check stats
        mock_bot.stats_lock.__aenter__.assert_called()
        mock_bot.stats_lock.__aexit__.assert_called()
        assert mock_bot.stats_cve_lookups == 1  # Lookup was attempted
        assert mock_bot.stats_nvd_fallback_success == 0  # Success was not reached
        assert mock_bot.stats_api_errors_nvd == 1  # Exception was caught


# --- NEW Tests for /cve channel ---


@pytest.mark.asyncio
async def test_channel_enable(cve_lookup_cog, mock_interaction, mock_db):
    mock_guild_id = 12345
    mock_channel = AsyncMock(discord.TextChannel)
    mock_channel.id = 67890
    mock_channel.mention = "<#67890>"
    mock_interaction.guild_id = mock_guild_id
    mock_interaction.user = AsyncMock()

    # Assume no initial guild config, _ensure_guild_config will create one
    mock_db.get_cve_guild_config.return_value = None

    await cve_lookup_cog.channels_add_command.callback(
        cve_lookup_cog, mock_interaction, mock_channel
    )

    # Check _ensure_guild_config created the default
    mock_db.set_cve_guild_config.assert_called_once_with(
        mock_guild_id, enabled=True, verbose_mode=False, severity_threshold="all"
    )
    # Verify get_cve_guild_config was called by _ensure_guild_config AND the command itself
    assert mock_db.get_cve_guild_config.call_count == 2
    mock_db.get_cve_guild_config.assert_has_calls(
        [call(mock_guild_id), call(mock_guild_id)]
    )

    # Check the channel was added/updated
    mock_db.add_or_update_cve_channel.assert_called_once_with(
        guild_id=mock_guild_id,
        channel_id=mock_channel.id,
        enabled=True,
        verbose_mode=None,
        severity_threshold=None,
        alert_format=None,
    )
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ Automatic CVE monitoring enabled for channel {mock_channel.mention}.",
        ephemeral=True,
    )
    # Also check update_cve_guild_enabled wasn't called because the new config defaults to enabled=True
    mock_db.update_cve_guild_enabled.assert_not_called()


@pytest.mark.asyncio
async def test_channel_enable_when_guild_globally_disabled(
    cve_lookup_cog, mock_interaction, mock_db
):
    mock_guild_id = 12345
    mock_channel = AsyncMock(discord.TextChannel)
    mock_channel.id = 67890
    mock_channel.mention = "<#67890>"
    mock_interaction.guild_id = mock_guild_id
    mock_interaction.user = AsyncMock()

    # Simulate existing guild config with monitoring disabled
    mock_db.get_cve_guild_config.return_value = {
        "guild_id": mock_guild_id,
        "cve_monitoring_enabled": False,
    }

    await cve_lookup_cog.channels_add_command.callback(
        cve_lookup_cog, mock_interaction, mock_channel
    )

    # Check _ensure_guild_config did NOT create a default
    mock_db.set_cve_guild_config.assert_not_called()
    # Verify get_cve_guild_config was called by _ensure_guild_config AND the command itself
    assert mock_db.get_cve_guild_config.call_count == 2
    mock_db.get_cve_guild_config.assert_has_calls(
        [call(mock_guild_id), call(mock_guild_id)]
    )
    # Verify global monitoring was enabled
    mock_db.update_cve_guild_enabled.assert_called_once_with(mock_guild_id, True)

    # Check the channel was added/updated
    mock_db.add_or_update_cve_channel.assert_called_once_with(
        guild_id=mock_guild_id,
        channel_id=mock_channel.id,
        enabled=True,
        verbose_mode=None,
        severity_threshold=None,
        alert_format=None,
    )
    mock_interaction.response.send_message.assert_called_once_with(
        f"✅ Automatic CVE monitoring enabled for channel {mock_channel.mention}.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_channel_disable(mock_bot, mock_db, mock_interaction):
    """Test disabling a channel for CVE monitoring."""
    guild_id = 12345
    channel = MagicMock(spec=discord.TextChannel)
    channel.id = 67890
    channel.mention = "<#67890>"
    mock_interaction.guild_id = guild_id
    mock_interaction.user = MagicMock(id=1, name="TestUser")

    cve_lookup_cog = CVELookupCog(mock_bot)

    # --- Use the correct command name ---
    await cve_lookup_cog.channels_remove_command.callback(
        cve_lookup_cog, mock_interaction, channel
    )

    # Check the remove function was called
    mock_db.remove_cve_channel.assert_called_once_with(guild_id, channel.id)

    # Check the response (should indicate removal)
    expected_message = f"✅ Automatic CVE monitoring configuration **removed** for channel {channel.mention}."
    mock_interaction.response.send_message.assert_called_once_with(
        expected_message, ephemeral=True
    )


@pytest.mark.asyncio
async def test_channel_list_enabled(
    cve_lookup_cog, mock_interaction, mock_db, mock_bot
):
    mock_guild_id = 12345
    mock_interaction.guild_id = mock_guild_id

    # Mock DB response for channel configs (one enabled, one disabled)
    mock_db.get_all_cve_channel_configs_for_guild.return_value = [
        {"channel_id": 67890, "enabled": True},
        {"channel_id": 67891, "enabled": False},  # This one should NOT be listed
    ]

    # Mock bot.get_channel to return mock channel objects
    mock_channel_1 = MagicMock(discord.TextChannel)
    mock_channel_1.mention = "<#67890>"
    mock_channel_2 = MagicMock(
        discord.TextChannel
    )  # Not used, but get_channel might be called
    mock_channel_2.mention = "<#67891>"

    # Setup side effect for get_channel
    def get_channel_side_effect(channel_id):
        if channel_id == 67890:
            return mock_channel_1
        elif channel_id == 67891:
            return mock_channel_2
        return None

    mock_bot.get_channel.side_effect = get_channel_side_effect

    await cve_lookup_cog.channels_list_command.callback(
        cve_lookup_cog, mock_interaction
    )

    # Verify DB was called
    mock_db.get_all_cve_channel_configs_for_guild.assert_called_once_with(mock_guild_id)

    # Verify get_channel was called ONLY for the enabled channel
    mock_bot.get_channel.assert_called_once_with(67890)

    # Verify the response message lists only the enabled channel
    expected_message = f"ℹ️ Channels configured for automatic CVE monitoring:\n- {mock_channel_1.mention}"
    mock_interaction.response.send_message.assert_called_once_with(
        expected_message, ephemeral=True
    )


@pytest.mark.asyncio
async def test_channel_list_disabled(mock_bot, mock_db, mock_interaction):
    """Test listing channels when the only configured channel is disabled."""
    guild_id = 12345
    mock_interaction.guild_id = guild_id

    # Mock DB: Only one channel configured, and it's disabled
    mock_db.get_all_cve_channel_configs_for_guild.return_value = [
        {"channel_id": 67890, "enabled": False}
    ]
    # Mock bot's channel fetching (though it might not be called if channel isn't enabled)
    channel1 = MagicMock(spec=discord.TextChannel, id=67890, name="alerts")
    channel1.mention = "<#67890>"
    mock_bot.get_channel.return_value = channel1

    cve_lookup_cog = CVELookupCog(mock_bot)

    # --- Use the correct command name ---
    await cve_lookup_cog.channels_list_command.callback(
        cve_lookup_cog, mock_interaction
    )

    # Check the DB was queried
    mock_db.get_all_cve_channel_configs_for_guild.assert_called_once_with(guild_id)
    # --- Assert get_cve_guild_config is NOT called ---
    mock_db.get_cve_guild_config.assert_not_called()

    # Check the response for no enabled channels
    expected_message = "ℹ️ No channels are currently configured for automatic CVE monitoring. Use `/cve channels add`."
    mock_interaction.response.send_message.assert_called_once_with(
        expected_message, ephemeral=True
    )


@pytest.mark.asyncio
async def test_channel_list_no_config(mock_bot, mock_db, mock_interaction):
    """Test listing channels when no channels are configured at all."""
    guild_id = 12345
    mock_interaction.guild_id = guild_id

    # Mock DB: No channel configs returned for the guild
    mock_db.get_all_cve_channel_configs_for_guild.return_value = []

    cve_lookup_cog = CVELookupCog(mock_bot)

    # --- Use the correct command name ---
    await cve_lookup_cog.channels_list_command.callback(
        cve_lookup_cog, mock_interaction
    )

    # Check the DB was queried
    mock_db.get_all_cve_channel_configs_for_guild.assert_called_once_with(guild_id)
    # --- Assert get_cve_guild_config is NOT called ---
    mock_db.get_cve_guild_config.assert_not_called()

    # Check the response for no configured channels
    expected_message = "ℹ️ No channels are currently configured for automatic CVE monitoring. Use `/cve channels add`."
    mock_interaction.response.send_message.assert_called_once_with(
        expected_message, ephemeral=True
    )


@pytest.mark.asyncio
async def test_threshold_view(mock_bot, mock_db, mock_interaction):
    """Test viewing the current CVE severity threshold."""
    guild_id = 12345
    mock_interaction.guild_id = guild_id

    # --- Mock using the correct DB key 'cve_severity_threshold' ---
    mock_db.get_cve_guild_config.return_value = {
        "guild_id": guild_id,
        "cve_severity_threshold": "high",
    }

    cve_lookup_cog = CVELookupCog(mock_bot)

    # --- Command name is already correct ---
    await cve_lookup_cog.threshold_view_command.callback(
        cve_lookup_cog, mock_interaction
    )

    # Check DB was called
    mock_db.get_cve_guild_config.assert_called_once_with(guild_id)

    # Check response uses the value from the mock
    expected_message = "ℹ️ Current global CVE alert severity threshold is **high**."
    mock_interaction.response.send_message.assert_called_once_with(
        expected_message, ephemeral=True
    )
