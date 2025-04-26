import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import discord

# Need to import the cog and potentially other classes
from kevvy.cogs.cve_lookup import CVELookupCog
from kevvy.vulncheck_client import VulnCheckClient # For type hinting mocks
from kevvy.nvd_client import NVDClient # For type hinting mocks
from kevvy.bot import SecurityBot # For type hinting mocks


@pytest.fixture
def mock_bot():
    """Fixture to create a mock SecurityBot with mocked clients."""
    bot = MagicMock(spec=SecurityBot)
    bot.vulncheck_client = MagicMock(spec=VulnCheckClient)
    bot.nvd_client = MagicMock(spec=NVDClient)
    # Mock the monitor directly on the bot instance if the cog accesses it via self.bot.cve_monitor
    # If the cog gets monitor via __init__, we inject it there instead.
    # Assuming cog gets clients via bot:
    bot.cve_monitor = MagicMock() 
    bot.cve_monitor.create_cve_embed = AsyncMock(return_value=[MagicMock()]) # Mock embed creation
    bot.stats_lock = AsyncMock() # Mock the lock if stats are incremented
    bot.stats_cve_lookups = 0
    bot.stats_vulncheck_success = 0
    bot.stats_nvd_fallback_success = 0
    bot.stats_api_errors_vulncheck = 0
    bot.stats_api_errors_nvd = 0
    return bot

@pytest.fixture
def cve_lookup_cog(mock_bot):
    """Fixture to create an instance of the CVELookupCog with the mock bot.
    This cog will have the REAL create_cve_embed method.
    """
    # Pass the mock bot instance to the cog's constructor
    cog = CVELookupCog(mock_bot)
    # REMOVED: cog.create_cve_embed = MagicMock(return_value=MagicMock(spec=discord.Embed))
    return cog

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

# TODO: Add tests for lookup failure (NVD returns None), invalid ID, NVD client unavailable, exceptions

# TODO: Write test cases for the /cve lookup command 

# --- Tests for create_cve_embed --- 

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

# TODO: Add tests for missing optional fields within embed creation 