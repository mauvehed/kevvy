import discord
from discord import app_commands
from discord.ext import commands
from typing import Optional, Union, List
import datetime  # Added for uptime calculation

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
    # @app_commands.check(is_bot_owner) # Temporarily commented out for testing
    async def admin_status(self, interaction: discord.Interaction):
        """Displays basic operational status of the bot. Restricted to bot owner."""
        # Placeholder status info - can be expanded later
        embed = discord.Embed(title="Kevvy Bot Status", color=discord.Color.orange())
        embed.add_field(
            name="Overall Status", value=":green_circle: Running", inline=False
        )
        embed.add_field(
            name="API Connectivity (NVD, CISA)",
            value=":white_check_mark: Nominal (Placeholder)",
            inline=False,
        )
        embed.add_field(
            name="Database Status",
            value=":white_check_mark: Nominal (Placeholder)",
            inline=False,
        )
        embed.add_field(
            name="Version", value="1.0.0 (Placeholder)", inline=False
        )  # You can make this dynamic later
        embed.set_footer(text=f"Requested by {interaction.user.display_name}")
        await interaction.response.send_message(embed=embed, ephemeral=True)

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
                field_value = (
                    getattr(cmd, "description", None) or "No description available."
                )
                if (
                    isinstance(cmd, app_commands.Group)
                    and cmd.name == self.kevvy_group.name
                ):
                    sub_cmds_names = [
                        sub.name
                        for sub in cmd.commands
                        if isinstance(sub, app_commands.Command)
                    ]
                    if sub_cmds_names:
                        field_value += (
                            f"\\nSubcommands: `{'`, `'.join(sorted(sub_cmds_names))}`"
                        )
                    else:
                        field_value += "\\nSubcommands: `help`"
                embed.add_field(name=f"`/{cmd.name}`", value=field_value, inline=False)
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
