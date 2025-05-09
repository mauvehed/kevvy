import pytest
from unittest.mock import call  # Import necessary mocks

# Fixtures are expected from conftest.py


@pytest.mark.asyncio
async def test_on_message_success_simple_cve_non_verbose_no_kev(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test a successful simple case: 1 CVE, enabled, passes threshold, non-verbose, not in KEV."""
    cve_id = "CVE-2023-1234"
    cve_id_upper = cve_id.upper()
    mock_message.content = f"Found {cve_id}"

    # --- Mock Setup ---
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_severity_threshold.return_value = (True, "High")
    mock_cve_monitor.check_kev.return_value = None

    # --- Run Test ---
    await mock_bot.on_message(mock_message)

    # --- Assertions ---
    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_db.get_effective_verbosity.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once_with(
        mock_cve_data,
        threshold=mock_db.get_cve_guild_config.return_value.get(
            "severity_threshold", "all"
        ),
    )
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    assert (mock_message.channel.id, cve_id_upper) in mock_bot.recently_processed_cves

    # Check that stats_manager methods were called
    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()
    mock_stats_manager.record_api_error.assert_not_called()

    # For backward compatibility, also verify bot stats directly
    assert mock_bot.stats_messages_processed == 1
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1
    assert mock_bot.stats_api_errors_kev == 0


@pytest.mark.asyncio
async def test_on_message_success_verbose_global(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test success path with global verbosity enabled."""
    cve_id = "CVE-2023-5555"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 7.0}

    mock_db.get_cve_guild_config.return_value["verbose_mode"] = True
    mock_db.get_effective_verbosity.return_value = True
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = None

    await mock_bot.on_message(mock_message)

    mock_db.get_effective_verbosity.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=True
    )
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()

    # Check stats were incremented
    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()


@pytest.mark.asyncio
async def test_on_message_success_channel_override_verbose(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test success path with channel override enabling verbosity when global is off."""
    cve_id = "CVE-2023-5555"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 7.0}

    mock_db.get_cve_channel_config.return_value = {
        "enabled": True,
        "verbose_mode": True,
    }
    mock_db.get_effective_verbosity.return_value = True
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = None

    await mock_bot.on_message(mock_message)

    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_db.get_effective_verbosity.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=True
    )
    mock_message.channel.send.assert_awaited_once_with(
        embed=mock_cve_monitor.create_cve_embed.return_value
    )
    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_kev_status_embed.assert_not_called()

    # Check stats were incremented
    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()


@pytest.mark.asyncio
async def test_on_message_success_with_kev_non_verbose(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test success path with KEV found, non-verbose."""
    cve_id = "CVE-2023-1234"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}
    mock_kev_data = {"cveID": cve_id_upper}

    mock_db.get_effective_verbosity.return_value = False
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = mock_kev_data

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=False
    )
    mock_cve_monitor.create_kev_status_embed.assert_called_once_with(
        cve_id_upper, mock_kev_data, verbose=False
    )
    assert mock_message.channel.send.await_count == 2
    send_calls = mock_message.channel.send.await_args_list
    assert send_calls[0] == call(embed=mock_cve_monitor.create_cve_embed.return_value)
    assert send_calls[1] == call(
        embed=mock_cve_monitor.create_kev_status_embed.return_value
    )

    # Check stats were incremented
    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()
    mock_stats_manager.record_api_error.assert_not_called()

    # For backward compatibility
    assert mock_bot.stats_api_errors_kev == 0


@pytest.mark.asyncio
async def test_on_message_success_with_kev_verbose(
    mock_bot, mock_message, mock_db, mock_cve_monitor, mock_stats_manager
):
    """Test success path with KEV found, verbose."""
    cve_id = "CVE-2023-1234"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    mock_cve_data = {"id": cve_id_upper, "cvss": 8.0}
    mock_kev_data = {"cveID": cve_id_upper}

    mock_db.get_cve_guild_config.return_value["verbose_mode"] = True
    mock_db.get_effective_verbosity.return_value = True
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_kev.return_value = mock_kev_data

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.check_kev.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.create_cve_embed.assert_called_once_with(
        mock_cve_data, verbose=True
    )
    mock_cve_monitor.create_kev_status_embed.assert_called_once_with(
        cve_id_upper, mock_kev_data, verbose=True
    )
    assert mock_message.channel.send.await_count == 2

    # Check stats were incremented
    mock_stats_manager.increment_messages_processed.assert_awaited_once()
    mock_stats_manager.increment_cve_lookups.assert_awaited_once()
    mock_stats_manager.increment_nvd_fallback_success.assert_awaited_once()
