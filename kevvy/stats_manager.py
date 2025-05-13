import asyncio
from collections import defaultdict
from typing import Dict, Any


class StatsManager:
    """Manages and provides thread-safe access to bot statistics."""

    def __init__(self):
        self.lock = asyncio.Lock()
        # Initialize all stats counters here
        self.cve_lookups = 0
        self.kev_alerts_sent = 0
        self.messages_processed = 0
        self.vulncheck_success = 0  # Consider if this is still used/needed
        self.nvd_fallback_success = 0
        self.api_errors_vulncheck = 0  # Consider if this is still used/needed
        self.api_errors_nvd = 0
        self.api_errors_cisa = 0
        self.api_errors_kev = 0
        self.rate_limits_nvd = (
            0  # Consider if this is tracked elsewhere (e.g., NVDClient)
        )
        self.rate_limits_hit_nvd = 0
        self.app_command_errors: Dict[str, int] = defaultdict(int)
        # Note: loaded_cogs, failed_cogs, timestamps are managed by the bot instance itself,
        # they don't necessarily belong in this stats *counter* manager.

    async def increment_cve_lookups(self, count: int = 1):
        async with self.lock:
            self.cve_lookups += count

    async def increment_kev_alerts_sent(self, count: int = 1):
        async with self.lock:
            self.kev_alerts_sent += count

    async def increment_messages_processed(self, count: int = 1):
        async with self.lock:
            self.messages_processed += count

    async def increment_nvd_fallback_success(self, count: int = 1):
        async with self.lock:
            self.nvd_fallback_success += count

    async def increment_vulncheck_success(self, count: int = 1):
        async with self.lock:
            self.vulncheck_success += count

    async def record_api_error(self, service: str, count: int = 1):
        """Records an API error for a specific service (e.g., 'nvd', 'cisa', 'kev')."""
        async with self.lock:
            if service == "nvd":
                self.api_errors_nvd += count
            elif service == "cisa":  # Used by KEV check task for client errors
                self.api_errors_cisa += count
            elif service == "kev":  # Used by on_message for kev check errors
                self.api_errors_kev += count
            # Add other services like vulncheck if needed
            elif service == "vulncheck":
                self.api_errors_vulncheck += count

    async def record_nvd_rate_limit_hit(self, count: int = 1):
        async with self.lock:
            self.rate_limits_hit_nvd += count
            self.api_errors_nvd += count  # Also count as a general NVD error

    async def record_app_command_error(self, error_type_name: str):
        async with self.lock:
            self.app_command_errors[error_type_name] += 1

    async def get_stats_dict(self) -> Dict[str, Any]:
        """Returns a dictionary containing the current stats values."""
        async with self.lock:
            # Return a copy of the current stats
            stats_data = {
                "cve_lookups": self.cve_lookups,
                "kev_alerts_sent": self.kev_alerts_sent,
                "messages_processed": self.messages_processed,
                "vulncheck_success": self.vulncheck_success,
                "nvd_fallback_success": self.nvd_fallback_success,
                "api_errors_vulncheck": self.api_errors_vulncheck,
                "api_errors_nvd": self.api_errors_nvd,
                "api_errors_cisa": self.api_errors_cisa,
                "api_errors_kev": self.api_errors_kev,
                "rate_limits_nvd": self.rate_limits_nvd,
                "rate_limits_hit_nvd": self.rate_limits_hit_nvd,
                "app_command_errors": dict(
                    self.app_command_errors
                ),  # Convert defaultdict
            }
        return stats_data
