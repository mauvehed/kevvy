import pytest
from unittest.mock import call  # Import necessary mocks
from datetime import datetime, timedelta, timezone  # For cache test

# Fixtures are expected from conftest.py


@pytest.mark.asyncio
async def test_on_message_cache_hit(mock_bot, mock_message, mock_db, mock_cve_monitor):
    """Test that a recently processed CVE is skipped."""
    cve_id = "CVE-2023-7777"
    cve_id_upper = cve_id.upper()
    mock_message.content = cve_id
    channel_id = mock_message.channel.id
    cache_key = (channel_id, cve_id_upper)

    mock_bot.recently_processed_cves[cache_key] = datetime.now(
        timezone.utc
    ) - timedelta(seconds=5)
    mock_cve_monitor.get_cve_data.return_value = {"id": cve_id_upper}

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.get_cve_data.assert_not_awaited()
    mock_message.channel.send.assert_not_called()
    mock_db.get_cve_guild_config.assert_called_once_with(mock_message.guild.id)
    mock_db.get_cve_channel_config.assert_called_once_with(
        mock_message.guild.id, mock_message.channel.id
    )
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
    mock_cve_data = {"id": cve_id_upper, "cvss": 3.0}

    mock_db.get_cve_guild_config.return_value["severity_threshold"] = "medium"
    mock_cve_monitor.get_cve_data.return_value = mock_cve_data
    mock_cve_monitor.check_severity_threshold.return_value = (False, "Low")

    await mock_bot.on_message(mock_message)

    mock_cve_monitor.get_cve_data.assert_awaited_once_with(cve_id_upper)
    mock_cve_monitor.check_severity_threshold.assert_called_once_with(
        mock_cve_data, "medium"
    )
    mock_db.get_effective_verbosity.assert_not_called()
    mock_message.channel.send.assert_not_called()
    mock_cve_monitor.check_kev.assert_not_awaited()
    assert mock_bot.stats_cve_lookups == 1
    assert mock_bot.stats_nvd_fallback_success == 1
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

    mock_cve_monitor.get_cve_data.side_effect = [mock_cve_data1, mock_cve_data2]
    mock_cve_monitor.check_kev.return_value = None
    mock_db.get_effective_verbosity.return_value = False

    await mock_bot.on_message(mock_message)

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
    mocker,
    mock_bot,
    mock_message,
    mock_db,
    mock_cve_monitor,  # mocker is needed here
):
    """Test processing multiple CVEs and hitting the MAX_EMBEDS_PER_MESSAGE limit."""
    cve1 = "CVE-2023-0001"
    cve2 = "CVE-2023-0002"
    cve3 = "CVE-2023-0003"
    mock_message.content = f"Check {cve1}, {cve2}, and also {cve3}"
    mock_cve_data1 = {"id": cve1, "cvss": 5.0}
    mock_cve_data2 = {"id": cve2, "cvss": 6.0}

    mocker.patch("kevvy.bot.MAX_EMBEDS_PER_MESSAGE", 2)
    mock_cve_monitor.get_cve_data.side_effect = [mock_cve_data1, mock_cve_data2]
    mock_cve_monitor.check_kev.return_value = None
    mock_db.get_effective_verbosity.return_value = False

    await mock_bot.on_message(mock_message)

    assert mock_cve_monitor.get_cve_data.await_count == 2
    mock_cve_monitor.get_cve_data.assert_has_awaits([call(cve1), call(cve2)])
    assert mock_cve_monitor.check_severity_threshold.call_count == 2
    assert mock_cve_monitor.create_cve_embed.call_count == 2
    assert mock_cve_monitor.check_kev.await_count == 2
    assert mock_message.channel.send.await_count == 3
    send_calls = mock_message.channel.send.await_args_list
    assert "more CVEs, but only showing the first 2" in send_calls[2].args[0]
    assert send_calls[2].kwargs.get("delete_after") == 30
    assert (mock_message.channel.id, cve1) in mock_bot.recently_processed_cves
    assert (mock_message.channel.id, cve2) in mock_bot.recently_processed_cves
    assert (mock_message.channel.id, cve3) not in mock_bot.recently_processed_cves
    assert mock_bot.stats_cve_lookups == 2
    assert mock_bot.stats_nvd_fallback_success == 2
