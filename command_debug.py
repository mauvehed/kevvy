"""
Command Debug Utility for Kevvy Bot.

This script checks registered commands and permissions.

Usage:
    poetry run python command_debug.py

Environment Variables:
    TEST_GUILD_ID: Discord server ID to check commands in
    BOT_OWNER_ID: Your Discord user ID to test owner permissions
"""

import os
import asyncio
import discord
from discord import app_commands
from discord.ext import commands


class CommandDebugBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        # Print bot info
        print(f"Logged in as {self.user} (ID: {self.user.id})")

        # Get test guild
        test_guild_id_str = os.getenv("TEST_GUILD_ID", "")
        if test_guild_id_str:
            try:
                test_guild_id = int(test_guild_id_str)
                guild = self.get_guild(test_guild_id)
                if guild:
                    print(
                        f"✅ Connected to test guild: {guild.name} (ID: {test_guild_id})"
                    )

                    # Get registered commands
                    print("\n📋 Fetching Guild Commands...")
                    guild_commands = await self.tree.fetch_commands(
                        guild=discord.Object(id=test_guild_id)
                    )
                    if guild_commands:
                        print(f"Found {len(guild_commands)} guild command(s):")
                        for cmd in guild_commands:
                            print(f"  • {cmd.name} - {cmd.description}")
                            if isinstance(cmd, app_commands.Group):
                                print("    Subcommands:")
                                for subcmd in await cmd.fetch_commands():
                                    print(
                                        f"      ◦ {subcmd.name} - {subcmd.description}"
                                    )
                    else:
                        print("❌ No guild commands found!")
                else:
                    print(f"❌ Could not find guild with ID {test_guild_id}")
            except ValueError:
                print(f"❌ Invalid TEST_GUILD_ID: {test_guild_id_str}")
        else:
            print("❌ TEST_GUILD_ID environment variable not set")

        # Check BOT_OWNER_ID
        bot_owner_id_str = os.getenv("BOT_OWNER_ID", "")
        if bot_owner_id_str:
            try:
                bot_owner_id = int(bot_owner_id_str)
                print(f"\n👑 BOT_OWNER_ID is set to: {bot_owner_id}")
                print("Owner-only commands should be visible to this user ID")
            except ValueError:
                print(f"❌ Invalid BOT_OWNER_ID: {bot_owner_id_str}")
        else:
            print("\n❌ BOT_OWNER_ID environment variable not set")
            print("Owner-only commands will not be visible to any user")

        # Check global commands too
        print("\n🌐 Fetching Global Commands...")
        global_commands = await self.tree.fetch_commands()
        if global_commands:
            print(f"Found {len(global_commands)} global command(s):")
            for cmd in global_commands:
                print(f"  • {cmd.name} - {cmd.description}")
                if isinstance(cmd, app_commands.Group):
                    print("    Subcommands:")
                    for subcmd in await cmd.fetch_commands():
                        print(f"      ◦ {subcmd.name} - {subcmd.description}")
        else:
            print("No global commands found")

        print("\n⚠️ Important Notes:")
        print(
            "1. Commands with app_commands.check() decorators might not be visible to users who don't pass the check"
        )
        print(
            "2. Guild command updates are instant, but global command updates can take up to an hour"
        )
        print(
            "3. Make sure you're using the correct bot token when running the actual bot"
        )

        # Exit after diagnostics
        await self.close()


async def main():
    # Load token from environment variable
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        print("❌ Error: DISCORD_BOT_TOKEN environment variable not set")
        return

    # Create and run bot
    bot = CommandDebugBot()
    try:
        await bot.start(token)
    except discord.errors.LoginFailure:
        print("❌ Error: Invalid bot token")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if not bot.is_closed():
            await bot.close()


if __name__ == "__main__":
    asyncio.run(main())
