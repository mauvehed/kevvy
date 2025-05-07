import discord
from discord import app_commands
from discord.ext import commands
from typing import Optional, Union, List
import datetime  # Added for uptime calculation
import textwrap
import io
import traceback
import importlib.metadata  # Import here to avoid issues
import sys
import logging

# Assuming SecurityBot is in kevvy/bot.py, one level up from kevvy/cogs/
from ..bot import SecurityBot


# Helper function to format parameter details
def _format_parameter(param: app_commands.Parameter) -> str:
    param_type_name_parts = []
    actual_type = param.type
    if hasattr(actual_type, "__origin__") and actual_type.__origin__ is Union:
        union_args = getattr(actual_type, "__args__", [])
        actual_types = [arg for arg in union_args if arg is not type(None)]
        if not actual_types:
            param_type_name_parts.append(str(actual_type))
        else:
            for arg_type in actual_types:
                if hasattr(arg_type, "__name__"):
                    param_type_name_parts.append(arg_type.__name__)
                elif hasattr(arg_type, "name"):
                    param_type_name_parts.append(arg_type.name)
                else:
                    param_type_name_parts.append(str(arg_type))
        param_type_name = " or ".join(param_type_name_parts)
    elif hasattr(param.type, "name"):
        param_type_name = param.type.name
    elif hasattr(param.type, "__name__"):
        param_type_name = param.type.__name__
    else:
        param_type_name = str(param.type)
    required_text = "" if param.required else " (Optional)"
    default_text = (
        f" (Default: `{param.default}`)"
        if param.default is not None and param.default != discord.utils.MISSING
        else ""
    )
    description = param.description or "No description."
    description = description.replace("\n", "\\n")
    return f"`{param.name}`: *{param_type_name}*{required_text}{default_text}\\n   - {description}"


# Helper function to build embed for a command
def _build_command_embed(
    interaction: discord.Interaction,
    command: Union[app_commands.Command, app_commands.Group],
    full_command_name_str: str,
) -> discord.Embed:
    embed = discord.Embed(
        title=f"Help for `/{full_command_name_str}`",
        description=command.description or "No description available.",
        color=discord.Color.green(),
    )
    if isinstance(command, app_commands.Group):
        if command.commands:
            sub_cmds_formatted = []
            for sub_cmd in sorted(command.commands, key=lambda c: c.name):
                sub_full_name = f"{full_command_name_str} {sub_cmd.name}"
                sub_cmds_formatted.append(
                    f"`/{sub_full_name}`: {sub_cmd.description or 'No description.'}"
                )
            if sub_cmds_formatted:
                embed.add_field(
                    name="Subcommands",
                    value="\\n".join(sub_cmds_formatted),
                    inline=False,
                )
            else:
                embed.add_field(
                    name="Subcommands",
                    value="No subcommands found for this group.",
                    inline=False,
                )
        else:
            embed.add_field(
                name="Subcommands", value="This group has no subcommands.", inline=False
            )
    elif isinstance(command, app_commands.Command):
        params_list: List[app_commands.Parameter] = []
        if hasattr(command, "parameters") and isinstance(command.parameters, dict):
            params_list = list(command.parameters.values())
        params_formatted = [_format_parameter(p_obj) for p_obj in params_list]
        if params_formatted:
            embed.add_field(
                name="Parameters", value="\\n".join(params_formatted), inline=False
            )
        else:
            embed.add_field(
                name="Parameters",
                value="This command takes no parameters.",
                inline=False,
            )
    usage_parts = [f"/{full_command_name_str}"]
    if isinstance(command, app_commands.Command) and command.parameters:
        sorted_params: List[app_commands.Parameter] = []
        if hasattr(command, "parameters") and isinstance(command.parameters, dict):
            sorted_params = sorted(
                list(command.parameters.values()),
                key=lambda p: (not p.required, p.name),
            )
        for p_obj in sorted_params:
            usage_parts.append(
                f"<{p_obj.name}>" if p_obj.required else f"[{p_obj.name}]"
            )
    embed.add_field(name="Usage Example", value=" ".join(usage_parts), inline=False)
    footer_text = "Use `/kevvy help` for a list of all main command groups."
    if isinstance(command, app_commands.Group) and command.commands:
        footer_text = f"Use `/kevvy help {full_command_name_str} <subcommand_name>` for details on a specific subcommand. {footer_text}"
    embed.set_footer(text=footer_text)
    return embed


# Helper function to find a command by name parts (recursive)
def _find_command_by_name(
    bot_or_group: Union[commands.Bot, app_commands.Group], name_parts: List[str]
) -> Optional[Union[app_commands.Command, app_commands.Group]]:
    if not name_parts:
        return None
    current_level_commands: List[Union[app_commands.Command, app_commands.Group]]
    if isinstance(bot_or_group, commands.Bot):
        all_app_commands = bot_or_group.tree.get_commands()
        current_level_commands = [
            cmd
            for cmd in all_app_commands
            if isinstance(cmd, (app_commands.Command, app_commands.Group))
        ]
    elif isinstance(bot_or_group, app_commands.Group):
        current_level_commands = bot_or_group.commands
    else:
        return None
    target_name = name_parts[0]
    remaining_parts = name_parts[1:]
    found_command_on_level = None
    for cmd_obj in current_level_commands:
        if cmd_obj.name == target_name:
            found_command_on_level = cmd_obj
            break
    if not found_command_on_level:
        return None
    if not remaining_parts:
        return found_command_on_level
    if isinstance(found_command_on_level, app_commands.Group):
        return _find_command_by_name(found_command_on_level, remaining_parts)
    else:
        return None


# --- Bot Owner Check ---
BOT_OWNER_ID = 260818647344218112


async def is_bot_owner(interaction: discord.Interaction) -> bool:
    """Check if the interaction user is the bot owner."""
    is_owner = interaction.user.id == BOT_OWNER_ID
    if not is_owner:
        await interaction.response.send_message(
            "Sorry, this command is restricted to the bot owner.", ephemeral=True
        )
    return is_owner


# --- End Bot Owner Check ---


class UtilityCog(commands.Cog, name="Utility"):
    """Cog for utility commands like help and admin functions."""

    def __init__(self, bot: SecurityBot):
        self.bot = bot

    # Define the app_commands.Group as a class attribute of the Cog
    kevvy_group = app_commands.Group(
        name="kevvy", description="Kevvy utility commands (e.g., help, admin)."
    )

    # --- Admin Subgroup (must be defined within the class scope) ---
    admin_group = app_commands.Group(
        name="admin",
        description="Restricted administrative commands for Kevvy.",
        parent=kevvy_group,
    )

    @admin_group.command(
        name="status", description="Shows the operational status of the bot."
    )
    @app_commands.check(is_bot_owner)  # Enable the check for production
    async def admin_status(self, interaction: discord.Interaction):
        """Displays basic operational status of the bot. Restricted to bot owner."""
        # Get actual version instead of placeholder
        version = getattr(self.bot, "version", "Unknown")

        embed = discord.Embed(
            title="Kevvy Bot Status",
            color=discord.Color.orange(),
            timestamp=datetime.datetime.now(datetime.timezone.utc),
        )

        # Overall status
        embed.add_field(
            name="Overall Status", value=":green_circle: Running", inline=False
        )

        # Bot information
        embed.add_field(name="Version", value=version, inline=True)
        embed.add_field(
            name="Latency", value=f"{round(self.bot.latency * 1000)}ms", inline=True
        )
        embed.add_field(name="Uptime", value=self.get_uptime(), inline=True)

        # Guild count
        guild_count = len(self.bot.guilds)
        embed.add_field(name="Server Count", value=str(guild_count), inline=True)

        # Show loaded extensions/cogs
        loaded_cogs = getattr(self.bot, "loaded_cogs", [])
        failed_cogs = getattr(self.bot, "failed_cogs", [])

        embed.add_field(
            name="Loaded Cogs",
            value=f"{len(loaded_cogs)}/{len(loaded_cogs) + len(failed_cogs)}",
            inline=True,
        )

        # API Status
        nvd_client_status = (
            ":green_circle: Connected"
            if self.bot.nvd_client
            else ":red_circle: Not Initialized"
        )
        kev_client_status = (
            ":green_circle: Connected"
            if self.bot.cisa_kev_client
            else ":red_circle: Not Initialized"
        )
        embed.add_field(
            name="API Connectivity",
            value=f"NVD: {nvd_client_status}\nCISA: {kev_client_status}",
            inline=False,
        )

        # Database Status
        db_status = (
            ":green_circle: Connected"
            if self.bot.db
            else ":red_circle: Not Initialized"
        )
        embed.add_field(
            name="Database Status",
            value=db_status,
            inline=False,
        )

        embed.set_footer(text=f"Requested by {interaction.user.display_name}")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @admin_group.command(
        name="stats",
        description="Shows detailed statistics about the bot's operations.",
    )
    @app_commands.check(is_bot_owner)
    async def admin_stats(self, interaction: discord.Interaction):
        """Shows detailed stats about the bot usage. Owner-only."""
        await interaction.response.defer(ephemeral=True)

        try:
            # Get stats from the bot's StatsManager
            stats_dict = await self.bot.stats_manager.get_stats_dict()

            embed = discord.Embed(
                title="Kevvy Bot Statistics",
                description="Operational statistics since last restart",
                color=discord.Color.blue(),
                timestamp=datetime.datetime.now(datetime.timezone.utc),
            )

            # CVE-related stats
            cve_stats = [
                f"Messages Processed: {stats_dict.get('messages_processed', 0):,}",
                f"CVE Lookups: {stats_dict.get('cve_lookups', 0):,}",
                f"NVD Rate Limits: {stats_dict.get('nvd_rate_limit_hits', 0):,}",
                f"NVD Fallbacks: {stats_dict.get('nvd_fallback_success', 0):,}",
            ]
            embed.add_field(
                name="CVE Statistics", value="\n".join(cve_stats), inline=False
            )

            # KEV-related stats
            kev_stats = [f"KEV Alerts Sent: {stats_dict.get('kev_alerts_sent', 0):,}"]
            embed.add_field(
                name="KEV Statistics", value="\n".join(kev_stats), inline=False
            )

            # API error stats
            api_errors = [
                f"NVD API Errors: {stats_dict.get('api_errors_nvd', 0):,}",
                f"CISA API Errors: {stats_dict.get('api_errors_cisa', 0):,}",
                f"KEV API Errors: {stats_dict.get('api_errors_kev', 0):,}",
                f"VulnCheck API Errors: {stats_dict.get('api_errors_vulncheck', 0):,}",
            ]
            embed.add_field(
                name="API Errors", value="\n".join(api_errors), inline=False
            )

            # Add command usage statistics
            command_stats = [
                f"/cve lookup: {stats_dict.get('command_cve_lookup', 0):,}",
                f"/kev commands: {stats_dict.get('command_kev', 0):,}",
            ]
            embed.add_field(
                name="Command Usage", value="\n".join(command_stats), inline=False
            )

            embed.set_footer(text=f"Requested by {interaction.user.display_name}")
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            await interaction.followup.send(
                f"Error fetching stats: {str(e)}", ephemeral=True
            )

    @admin_group.command(name="reload", description="Reloads bot extensions/cogs.")
    @app_commands.check(is_bot_owner)
    @app_commands.describe(
        extension="The extension to reload. If omitted, reloads all extensions."
    )
    async def admin_reload(
        self, interaction: discord.Interaction, extension: Optional[str] = None
    ):
        """Reloads bot extensions. Owner-only."""
        await interaction.response.defer(ephemeral=True)

        if extension:
            # Reload a specific extension
            try:
                await self.bot.reload_extension(extension)
                await interaction.followup.send(
                    f"✅ Successfully reloaded extension: `{extension}`", ephemeral=True
                )
            except commands.ExtensionError as e:
                await interaction.followup.send(
                    f"❌ Error reloading extension `{extension}`: {str(e)}",
                    ephemeral=True,
                )
        else:
            # Reload all extensions
            results = []
            for ext in self.bot.loaded_cogs:
                try:
                    await self.bot.reload_extension(ext)
                    results.append(f"✅ `{ext}`")
                except commands.ExtensionError as e:
                    results.append(f"❌ `{ext}`: {str(e)}")

            embed = discord.Embed(
                title="Extension Reload Results",
                description="\n".join(results),
                color=discord.Color.green(),
                timestamp=datetime.datetime.now(datetime.timezone.utc),
            )
            embed.set_footer(text=f"Requested by {interaction.user.display_name}")
            await interaction.followup.send(embed=embed, ephemeral=True)

    @admin_group.command(
        name="version", description="Shows version information for the bot."
    )
    @app_commands.check(is_bot_owner)
    async def admin_version(self, interaction: discord.Interaction):
        """Shows detailed version information. Owner-only."""
        import platform
        import discord

        version = getattr(self.bot, "version", "Unknown")

        embed = discord.Embed(
            title="Kevvy Version Information",
            description=f"**Current Version:** {version}",
            color=discord.Color.blue(),
            timestamp=datetime.datetime.now(datetime.timezone.utc),
        )

        # Environment information
        env_info = [
            f"Python: {platform.python_version()}",
            f"discord.py: {discord.__version__}",
            f"OS: {platform.system()} {platform.release()}",
            f"Host: {platform.node()}",
        ]
        embed.add_field(name="Environment", value="\n".join(env_info), inline=False)

        # Dependencies - use importlib.metadata
        try:
            # Get versions of important packages
            dependencies = []
            for pkg_name in ["aiohttp", "sqlalchemy", "pytest", "pytest-asyncio"]:
                try:
                    pkg_version = importlib.metadata.version(pkg_name)
                    dependencies.append(f"{pkg_name} {pkg_version}")
                except importlib.metadata.PackageNotFoundError:
                    pass

            embed.add_field(
                name="Key Dependencies",
                value="\n".join(dependencies) or "None found",
                inline=False,
            )
        except Exception as e:
            embed.add_field(
                name="Key Dependencies",
                value=f"Error retrieving dependency information: {str(e)}",
                inline=False,
            )

        embed.set_footer(text=f"Requested by {interaction.user.display_name}")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @admin_group.command(
        name="servers", description="Shows a list of servers the bot is in."
    )
    @app_commands.check(is_bot_owner)
    async def admin_servers(self, interaction: discord.Interaction):
        """Lists all servers the bot is in. Owner-only."""
        await interaction.response.defer(ephemeral=True)

        if not self.bot.guilds:
            await interaction.followup.send(
                "Bot is not in any servers.", ephemeral=True
            )
            return

        # Create an embed to display server information
        embed = discord.Embed(
            title="Kevvy Server List",
            description=f"Bot is in {len(self.bot.guilds)} servers",
            color=discord.Color.blue(),
            timestamp=datetime.datetime.now(datetime.timezone.utc),
        )

        # Sort guilds by member count (largest first)
        # Use a default value of 0 for member_count to ensure it's always an int
        sorted_guilds = sorted(
            self.bot.guilds,
            key=lambda g: getattr(g, "member_count", 0) or 0,
            reverse=True,
        )

        # Format guild information
        guild_list: List[str] = []
        for i, guild in enumerate(sorted_guilds, 1):
            # Try to get the guild owner
            owner = f"<@{guild.owner_id}>" if guild.owner_id else "Unknown"

            # Format guild entry with safe timestamp handling
            joined_timestamp = 0
            if guild.me and guild.me.joined_at:
                joined_timestamp = int(guild.me.joined_at.timestamp())

            created_timestamp = (
                int(guild.created_at.timestamp()) if guild.created_at else 0
            )

            guild_entry = (
                f"**{i}. {guild.name}** (ID: {guild.id})\n"
                f"  • Members: {getattr(guild, 'member_count', 0) or 0:,}\n"
                f"  • Owner: {owner}\n"
                f"  • Created: <t:{created_timestamp}:R>\n"
                f"  • Joined: <t:{joined_timestamp}:R>\n"
            )
            guild_list.append(guild_entry)

        # Split into multiple embeds if needed (Discord has a 6000 character limit)
        current_chunk: List[str] = []
        current_length = 0
        embeds: List[discord.Embed] = []

        for entry in guild_list:
            if (
                current_length + len(entry) > 4000
            ):  # Leave buffer for embed title/footer
                # Add the current chunk to embeds and start a new one
                embed = discord.Embed(
                    title=f"Kevvy Server List ({len(embeds)+1})",
                    description="\n".join(current_chunk),
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now(datetime.timezone.utc),
                )
                embeds.append(embed)
                current_chunk = [entry]
                current_length = len(entry)
            else:
                current_chunk.append(entry)
                current_length += len(entry)

        # Add the last chunk if not empty
        if current_chunk:
            embed = discord.Embed(
                title=f"Kevvy Server List ({len(embeds)+1})",
                description="\n".join(current_chunk),
                color=discord.Color.blue(),
                timestamp=datetime.datetime.now(datetime.timezone.utc),
            )
            embeds.append(embed)

        # Send all embeds
        for i, embed in enumerate(embeds):
            embed.set_footer(
                text=f"Page {i+1}/{len(embeds)} • Requested by {interaction.user.display_name}"
            )
            if i == 0:
                await interaction.followup.send(embed=embed, ephemeral=True)
            else:
                await interaction.followup.send(embed=embed, ephemeral=True)

    @admin_group.command(
        name="debug", description="Evaluates Python code for debugging."
    )
    @app_commands.check(is_bot_owner)
    @app_commands.describe(code="The Python code to evaluate.")
    async def admin_debug(self, interaction: discord.Interaction, code: str):
        """Evaluates Python code for debugging purposes. Restricted to bot owner."""
        await interaction.response.defer(ephemeral=True)

        # Create clean environment for code execution
        local_vars = {
            "bot": self.bot,
            "interaction": interaction,
            "discord": discord,
            "commands": commands,
            "guild": interaction.guild,
            "channel": interaction.channel,
            "author": interaction.user,
        }

        # Add globals but avoid potential security issues
        global_vars = globals().copy()

        # Format code for execution
        code = code.strip("` ")
        if code.startswith("py\n"):
            code = code[3:]

        # Create the function to execute code
        func_str = f'async def _debug_func():\n{textwrap.indent(code, "    ")}'

        try:
            # Execute the code
            exec(func_str, global_vars, local_vars)
            result = await local_vars["_debug_func"]()

            # Format the result
            output = (
                str(result) if result is not None else "Code executed successfully."
            )

            # Send the output
            if len(output) > 1990:
                # If the output is too long, send it as a file
                file = discord.File(
                    io.BytesIO(output.encode("utf-8")), filename="debug_output.txt"
                )
                await interaction.followup.send(
                    "Output too large, sending as file:", file=file, ephemeral=True
                )
            else:
                await interaction.followup.send(f"```py\n{output}\n```", ephemeral=True)
        except Exception:
            await interaction.followup.send(
                f"Error executing code: ```py\n{traceback.format_exc()}\n```",
                ephemeral=True,
            )

    @commands.Cog.listener()
    async def on_app_command_error(
        self,
        interaction: discord.Interaction,
        error: discord.app_commands.AppCommandError,
    ):
        """Global error handler for all application commands in this cog."""
        # Check if the error is a permissions check failure
        if isinstance(error, discord.app_commands.CheckFailure):
            # Don't respond if interaction is already responded to
            if interaction.response.is_done():
                return

            # Log the denied access for monitoring
            command_name = getattr(interaction.command, "qualified_name", "unknown")
            logging.warning(
                f"Access denied for command '{command_name}' by user {interaction.user.id} ({interaction.user.name})"
            )

            # Check if this is an admin command access attempt
            if command_name and "admin" in command_name:
                await interaction.response.send_message(
                    "These commands are restricted to the bot owner only.",
                    ephemeral=True,
                )
            else:
                await interaction.response.send_message(
                    "You don't have permission to use this command.", ephemeral=True
                )
        # Handle command invocation errors (errors during command execution)
        elif isinstance(error, discord.app_commands.CommandInvokeError):
            # Extract the original error
            original = error.original

            # Log detailed error information
            logging.error(
                f"Command error in {interaction.command.qualified_name if interaction.command else 'unknown command'}: "
                f"{str(error)}\n{traceback.format_exc()}"
            )

            # Don't respond if interaction is already responded to
            if interaction.response.is_done():
                return

            # Provide a friendly error message to the user
            await interaction.response.send_message(
                f"An error occurred during command execution: {str(original)}",
                ephemeral=True,
            )
        else:
            # Log the error
            logging.error(f"Unhandled command error: {error}\n{traceback.format_exc()}")

            # Don't respond if interaction is already responded to
            if interaction.response.is_done():
                return

            await interaction.response.send_message(
                f"An error occurred: {str(error)}", ephemeral=True
            )

    # --- End Admin Subgroup ---

    @kevvy_group.command(
        name="help", description="Shows help information for Kevvy commands."
    )
    @app_commands.describe(
        command_input="The command or command group to get help for (e.g., 'cve' or 'cve lookup')."
    )
    async def help_cmd(
        self, interaction: discord.Interaction, command_input: Optional[str] = None
    ):
        """
        Provides help information for Kevvy's commands.
        Can show a general overview or details for a specific command/group.
        """
        # Check if user is asking for admin help but isn't the bot owner
        is_bot_owner = interaction.user.id == BOT_OWNER_ID
        if command_input and ("admin" in command_input.lower()) and not is_bot_owner:
            await interaction.response.send_message(
                "Sorry, you don't have permission to view admin command help.",
                ephemeral=True,
            )
            return

        if command_input:
            name_parts = [
                part
                for part in command_input.lower().strip().lstrip("/").split(" ")
                if part
            ]
            if not name_parts:
                await interaction.response.send_message(
                    "Please specify a command or command group after `/kevvy help`, or omit it for general help.",
                    ephemeral=True,
                )
                return

            target_command = _find_command_by_name(self.bot, name_parts)
            if target_command:
                # Check if this is an admin command and user is not the bot owner
                if ("admin" in name_parts) and not is_bot_owner:
                    await interaction.response.send_message(
                        "Sorry, you don't have permission to view admin command help.",
                        ephemeral=True,
                    )
                    return

                full_command_name_str = " ".join(name_parts)
                embed = _build_command_embed(
                    interaction, target_command, full_command_name_str
                )
                await interaction.response.send_message(embed=embed, ephemeral=True)
            else:
                await interaction.response.send_message(
                    f"Sorry, I couldn't find a command or group matching `/{' '.join(name_parts)}`. Try `/kevvy help` for a list of main command groups.",
                    ephemeral=True,
                )
        else:
            embed = discord.Embed(
                title="Kevvy Bot Help",
                description="I provide tools for CVE and CISA KEV catalog interactions. Here are my main command groups:",
                color=discord.Color.blue(),
            )
            embed.set_footer(
                text="Use `/kevvy help <command_group_name>` or `/kevvy help <group_name> <subcommand_name>` for more details."
            )
            all_top_level_app_commands = self.bot.tree.get_commands()
            relevant_commands = [
                cmd
                for cmd in all_top_level_app_commands
                if isinstance(cmd, (app_commands.Command, app_commands.Group))
            ]
            sorted_commands = sorted(relevant_commands, key=lambda cmd: cmd.name)
            for cmd in sorted_commands:
                # Skip admin commands in kevvy_group for non-owners
                if cmd.name == self.kevvy_group.name and not is_bot_owner:
                    # Filter out admin subcommands when showing kevvy group
                    kevvy_subcommands = []
                    for subcmd in cmd.commands:
                        if subcmd.name != "admin":
                            kevvy_subcommands.append(subcmd.name)
                else:
                    field_value = (
                        getattr(cmd, "description", None) or "No description available."
                    )
                    if (
                        isinstance(cmd, app_commands.Group)
                        and cmd.name == self.kevvy_group.name
                    ):
                        sub_cmds_names = []
                        for sub in cmd.commands:
                            # Only include admin command for bot owner
                            if sub.name != "admin" or is_bot_owner:
                                sub_cmds_names.append(sub.name)

                        if sub_cmds_names:
                            field_value += f"\\nSubcommands: `{'`, `'.join(sorted(sub_cmds_names))}`"
                        else:
                            field_value += "\\nSubcommands: `help`"
                    embed.add_field(
                        name=f"`/{cmd.name}`", value=field_value, inline=False
                    )

            # Add a special section for admin commands if the user is the bot owner
            if is_bot_owner:
                admin_embed = discord.Embed(
                    title="🔐 Administrator Commands",
                    description="The following commands are restricted to the bot owner:",
                    color=discord.Color.dark_red(),
                )

                admin_help_text = (
                    "• `/kevvy admin status` - Shows the operational status of the bot\n"
                    "• `/kevvy admin stats` - Shows detailed statistics and usage metrics\n"
                    "• `/kevvy admin servers` - Lists all servers the bot is in\n"
                    "• `/kevvy admin reload` - Reloads bot extensions/cogs\n"
                    "• `/kevvy admin version` - Shows detailed version information\n"
                    "• `/kevvy admin debug` - Evaluates Python code for debugging"
                )

                admin_embed.add_field(
                    name="Available Commands", value=admin_help_text, inline=False
                )

                admin_embed.set_footer(
                    text="⚠️ These commands are restricted to the bot owner only"
                )

                await interaction.response.send_message(
                    embeds=[embed, admin_embed], ephemeral=True
                )
            else:
                await interaction.response.send_message(embed=embed, ephemeral=True)

    # --- Uptime Functionality ---
    def get_uptime(self) -> str:
        """Calculates the bot's uptime based on its start_time attribute."""
        if not hasattr(self.bot, "start_time") or not isinstance(
            self.bot.start_time, datetime.datetime
        ):
            return "Uptime unavailable (bot start_time not found or invalid)."

        now = datetime.datetime.now(datetime.timezone.utc)
        delta = now - self.bot.start_time

        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        days, hours = divmod(hours, 24)

        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    @kevvy_group.command(
        name="uptime", description="Shows how long the bot has been running."
    )
    async def uptime_cmd(self, interaction: discord.Interaction):
        """Displays the bot's current uptime."""
        uptime_str = self.get_uptime()
        await interaction.response.send_message(
            f"Bot uptime: {uptime_str}", ephemeral=True
        )

    # --- End Uptime Functionality ---

    @app_commands.command(
        name="pingutility", description="A simple ping from UtilityCog."
    )
    async def ping_utility_command(self, interaction: discord.Interaction):
        await interaction.response.send_message("Pong from UtilityCog!", ephemeral=True)


# Standard setup function (remains the same)
async def setup(bot: SecurityBot):
    """Standard setup function to add the cog to the bot."""
    await bot.add_cog(UtilityCog(bot))
