import pytest

# Fixtures like mock_bot, mock_message, mock_db are expected to be in conftest.py


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
