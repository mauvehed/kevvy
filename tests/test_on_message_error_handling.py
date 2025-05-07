import pytest
import discord
from unittest.mock import MagicMock  # Import necessary mocks

from kevvy.nvd_client import NVDRateLimitError  # Specific error import

# Fixtures are expected from conftest.py


@pytest.mark.asyncio
async def test_on_message_error_nvd_rate_limit(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test error handling for NVDRateLimitError during data fetch."""
    cve_id = "CVE-2023-8888"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id

    mock_cve_monitor.get_cve_data.side_effect = NVDRateLimitError("Rate limit hit")

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.record_nvd_rate_limit_hit.assert_awaited_once()

    # For backward compatibility
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 0
    assert mock_bot.stats_rate_limits_hit_nvd == 1
    assert mock_bot.stats_api_errors_nvd == 1


@pytest.mark.asyncio
async def test_on_message_error_kev_check(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test error handling when check_kev raises an exception."""
    cve_id = "CVE-2023-9999"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}

    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.side_effect = Exception("KEV Service Unavailable")
    mock_db.get_effective_verbosity.return_value = False

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    assert (mock_message.channel.id, cve_id_upper) in mock_bot.recently_processed_cves

    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()
    mock_stats_manager.record_api_error.assert_awaited_once_with("kev")

    # For backward compatibility
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1
    assert mock_bot.stats_api_errors_kev == 1


@pytest.mark.asyncio
async def test_on_message_error_discord_forbidden(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test error handling when discord.Forbidden is raised on send."""
    cve_id = "CVE-2023-1212"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}

    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_db.get_effective_verbosity.return_value = False
    mock_message.channel.send.side_effect = discord.Forbidden(
        MagicMock(), "Missing Permissions"
    )

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    mock_cve_monitor.check_kev.assert_not_awaited()
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()

    # For backward compatibility
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1


@pytest.mark.asyncio
async def test_on_message_error_discord_http(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test error handling when discord.HTTPException is raised on send."""
    cve_id = "CVE-2023-2323"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 7.0}

    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_db.get_effective_verbosity.return_value = False
    mock_message.channel.send.side_effect = discord.HTTPException(
        MagicMock(), "Server Error"
    )

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    mock_cve_monitor.check_kev.assert_not_awaited()
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()

    # For backward compatibility
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1


@pytest.mark.asyncio
async def test_on_message_error_generic_exception(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test error handling for unexpected exceptions during processing."""
    cve_id = "CVE-2023-4545"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id

    mock_db.get_effective_verbosity.side_effect = Exception("Unexpected DB issue")
    mock_cve_monitor.get_cve_data.return_value = {"id": cve_id_upper, "cvss": 8.0}

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once()
    mock_db.get_effective_verbosity.assert_called_once()
    mock_cve_monitor.create_cve_embed.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()
    mock_stats_manager.record_api_error.assert_awaited_once_with("nvd")

    # For backward compatibility
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1
    assert mock_bot.stats_api_errors_nvd == 1


@pytest.mark.asyncio
async def test_on_message_cve_data_not_found(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test scenario where CVE is detected but no data is found via API."""
    cve_id = "CVE-2023-0000"
    cve_id_upper = cve_id.upper()
    mock_message.content = f"Look at {cve_id}"

    mock_cve_monitor.get_cve_data.return_value = None

    await mock_bot.on_message(mock_message)

    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_not_called()
    mock_db.get_effective_verbosity.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()
    assert (
        mock_message.channel.id,
        cve_id_upper,
    ) not in mock_bot.recently_processed_cves

    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_not_awaited()

    # For backward compatibility
    assert mock_bot.stats_messages_processed == 1
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 0
    assert mock_bot.stats_api_errors_nvd == 0
    assert mock_bot.stats_api_errors_kev == 0
