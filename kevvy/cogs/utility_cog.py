import discord
from discord import app_commands
from discord.ext import commands
from typing import Optional, Union, List


# Helper function to format parameter details
def _format_parameter(param: app_commands.Parameter) -> str:
    param_type_name_parts = []
    # Handle Union types like Optional[discord.TextChannel] or discord.TextChannel | None
    actual_type = param.type
    if hasattr(actual_type, "__origin__") and actual_type.__origin__ is Union:
        # Filter out NoneType for Optional, then get names of actual types
        # actual_types = [arg for arg in actual_type.__args__ if arg is not type(None)]
        # A more robust way for Python 3.9+ (Optional[X] is Union[X, NoneType])
        union_args = getattr(actual_type, "__args__", [])
        actual_types = [arg for arg in union_args if arg is not type(None)]

        if not actual_types:  # Should not happen with proper typing e.g. Optional[str]
            param_type_name_parts.append(str(actual_type))  # Fallback
        else:
            for arg_type in actual_types:
                if hasattr(arg_type, "__name__"):  # e.g. str, int, discord.TextChannel
                    param_type_name_parts.append(arg_type.__name__)
                elif hasattr(arg_type, "name"):  # e.g. discord.ChannelType
                    param_type_name_parts.append(arg_type.name)
                else:  # Fallback for complex types
                    param_type_name_parts.append(str(arg_type))
        param_type_name = " or ".join(param_type_name_parts)
    elif hasattr(param.type, "name"):  # e.g. discord.ChannelType enum members
        param_type_name = param.type.name
    elif hasattr(param.type, "__name__"):  # e.g. str, int, discord.TextChannel
        param_type_name = param.type.__name__
    else:  # Fallback
        param_type_name = str(param.type)

    required_text = "" if param.required else " (Optional)"
    default_text = (
        f" (Default: `{param.default}`)"
        if param.default is not None and param.default != discord.utils.MISSING
        else ""
    )
    description = param.description or "No description."
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

    elif isinstance(command, app_commands.Command):  # Explicitly app_commands.Command
        # command.parameters is indeed a dict[str, app_commands.Parameter]
        # The linter might be confused about the exact Command type.
        # Let's iterate directly if .items() is causing issues for the linter.
        params_list = []  # type: List[app_commands.Parameter]
        if hasattr(command, "parameters") and isinstance(command.parameters, dict):
            params_list = list(command.parameters.values())

        # Sort parameters by name for consistent order, or by required status first
        # For now, let's assume the order in command.parameters is fine or sort by name if needed.
        # params_list.sort(key=lambda p: p.name) # Optional: sort by name

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
        # command.parameters is a dict.
        # Iterate through its values (which are app_commands.Parameter objects)
        # Sorting by name for consistent usage string or by required then name
        sorted_params: List[app_commands.Parameter] = []
        if hasattr(command, "parameters") and isinstance(command.parameters, dict):
            sorted_params = sorted(
                list(command.parameters.values()),
                key=lambda p: (not p.required, p.name),
            )

        for p_obj in sorted_params:  # p_obj is app_commands.Parameter
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
    if isinstance(
        bot_or_group, commands.Bot
    ):  # Starting search from the bot's root tree
        # bot.tree.get_commands() returns List[Union[Command[Any, ..., Any], Group, ContextMenu]]
        # We are interested in Commands and Groups for this style of help.
        # ContextMenu commands could be listed in general help but are searched differently.
        all_app_commands = bot_or_group.tree.get_commands()
        current_level_commands = [
            cmd
            for cmd in all_app_commands
            if isinstance(cmd, (app_commands.Command, app_commands.Group))
        ]
    elif isinstance(
        bot_or_group, app_commands.Group
    ):  # Searching within a group's subcommands
        current_level_commands = bot_or_group.commands
    else:
        return None  # Invalid type for searching

    target_name = name_parts[0]
    remaining_parts = name_parts[1:]

    found_command_on_level = None
    for cmd_obj in current_level_commands:
        if cmd_obj.name == target_name:
            found_command_on_level = cmd_obj
            break

    if not found_command_on_level:
        return None  # Command part not found at this level

    if (
        not remaining_parts
    ):  # This was the last part of the name, so we found our target
        return found_command_on_level

    # If there are remaining parts, the found command must be a group to continue searching
    if isinstance(found_command_on_level, app_commands.Group):
        return _find_command_by_name(
            found_command_on_level, remaining_parts
        )  # Recurse into the group
    else:  # Found a command, but there are more name parts specified - invalid path
        return None


class UtilityCog(commands.Cog, name="Utility"):
    """Cog for utility commands like help."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # Define the app_commands.Group as a class attribute of the Cog
    kevvy_group = app_commands.Group(
        name="kevvy", description="Kevvy utility commands (e.g., help)."
    )

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
            # Clean and split the input: " /cve  lookup  " -> ["cve", "lookup"]
            name_parts = [
                part
                for part in command_input.lower().strip().lstrip("/").split(" ")
                if part
            ]

            if not name_parts:  # User might have typed just "/" or " / "
                await interaction.response.send_message(
                    "Please specify a command or command group after `/kevvy help`, or omit it for general help.",
                    ephemeral=True,
                )
                return

            target_command = _find_command_by_name(self.bot, name_parts)

            if target_command:
                full_command_name_str = " ".join(
                    name_parts
                )  # Use the cleaned parts for display
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
            # General help
            embed = discord.Embed(
                title="Kevvy Bot Help",
                description="I provide tools for CVE and CISA KEV catalog interactions. Here are my main command groups:",
                color=discord.Color.blue(),
            )
            embed.set_footer(
                text="Use `/kevvy help <command_group_name>` or `/kevvy help <group_name> <subcommand_name>` for more details."
            )

            # Get all top-level commands and groups registered to the bot's tree
            all_top_level_app_commands = self.bot.tree.get_commands()
            # Filter for slash commands and groups for this overview
            relevant_commands = [
                cmd
                for cmd in all_top_level_app_commands
                if isinstance(cmd, (app_commands.Command, app_commands.Group))
            ]
            sorted_commands = sorted(relevant_commands, key=lambda cmd: cmd.name)

            for cmd in sorted_commands:
                # cmd here is Union[app_commands.Command, app_commands.Group]
                field_value = (
                    getattr(cmd, "description", None) or "No description available."
                )
                # If the command is a group and it's our own /kevvy group, list its known subcommands
                if (
                    isinstance(cmd, app_commands.Group)
                    and cmd.name == self.kevvy_group.name
                ):
                    # Accessing cmd.commands here is safe due to isinstance check
                    sub_cmds_names = [
                        sub.name
                        for sub in cmd.commands
                        if isinstance(sub, app_commands.Command)
                    ]
                    if sub_cmds_names:
                        field_value += (
                            f"\\nSubcommands: `{'`, `'.join(sorted(sub_cmds_names))}`"
                        )
                    else:  # Fallback if subcommands aren't populated yet or only help is there
                        field_value += "\\nSubcommands: `help`"

                embed.add_field(name=f"`/{cmd.name}`", value=field_value, inline=False)
            await interaction.response.send_message(embed=embed, ephemeral=True)


async def setup(bot: commands.Bot):
    """Standard setup function to add the cog to the bot."""
    await bot.add_cog(UtilityCog(bot))
