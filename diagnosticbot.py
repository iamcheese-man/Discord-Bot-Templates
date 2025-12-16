import discord
from discord import app_commands
from discord.ui import Modal, TextInput, View, Button
import asyncio
import subprocess
import paramiko
import aiohttp
import psutil
import platform
import socket
import os
import shlex
import logging
from datetime import datetime
from typing import Callable, Optional

# -----------------------------
# CONFIGURATION
# -----------------------------
TOKEN = os.getenv("DISCORD_TOKEN", "YOUR_BOT_TOKEN")
OWNER_ID = int(os.getenv("DISCORD_OWNER_ID", "123456789012345678"))

# Audit log configuration
AUDIT_LOG_ENABLED = True
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "./logs/audit.log")  # customizable path

# Command safety
# Prefer a whitelist in real deployments. This is just an improved blacklist check.
BLOCKED_SHELL_COMMANDS = {"rm", "sudo", "mkfs", "dd", ":(){"}  # set of tokens/patterns to block
MAX_OUTPUT_LENGTH = 1900
COMMAND_TIMEOUT = 10  # seconds

# -----------------------------
# LOGGING (safe, thread-safe)
# -----------------------------
logger = logging.getLogger("diagnosticbot")
logger.setLevel(logging.INFO)
if AUDIT_LOG_ENABLED:
    log_dir = os.path.dirname(AUDIT_LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    handler = logging.FileHandler(AUDIT_LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)


# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def owner_only(interaction: discord.Interaction) -> bool:
    return interaction.user.id == OWNER_ID


def log_command(user_id: int, guild_id: int, command: str, target: str) -> None:
    if not AUDIT_LOG_ENABLED:
        return
    # Avoid logging secrets (do not log passwords or full command arguments that may contain secrets)
    logger.info("User: %s | Guild: %s | Command: %s | Target: %s", user_id, guild_id, command, target)


def truncate_output(output: str) -> str:
    if len(output) > MAX_OUTPUT_LENGTH:
        return output[:MAX_OUTPUT_LENGTH] + "\n[TRUNCATED]"
    return output


def is_shell_command_blocked(cmd: str) -> bool:
    # Tokenize command and check first token against blocked command list.
    # Also do a simple check for known dangerous patterns.
    try:
        tokens = shlex.split(cmd)
    except Exception:
        # If the input can't be parsed, treat as suspicious
        return True
    if not tokens:
        return True
    cmd_name = os.path.basename(tokens[0])
    if cmd_name in BLOCKED_SHELL_COMMANDS:
        return True
    # block fork-bomb style or dangerous redirections/executions
    if ":(){" in cmd or "&&" in cmd and any(tok in {"rm", "sudo"} for tok in tokens):
        return True
    return False


async def run_blocking_in_executor(func: Callable, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


# -----------------------------
# BOT SETUP
# -----------------------------
class DiagnosticBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        # Consider syncing to a dev guild with self.tree.copy_global_to_guild() for faster feedback
        await self.tree.sync()


bot = DiagnosticBot()


# -----------------------------
# /ping - Full server info
# -----------------------------
@bot.tree.command(name="ping", description="Show full server diagnostics")
async def ping(interaction: discord.Interaction):
    if not owner_only(interaction):
        return await interaction.response.send_message("Access denied.", ephemeral=True)

    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    hostname = socket.gethostname()
    os_info = platform.platform()
    # Use utcfromtimestamp to avoid mixing local and UTC timestamps
    uptime_seconds = (datetime.utcnow() - datetime.utcfromtimestamp(psutil.boot_time())).total_seconds()
    uptime = f"{int(uptime_seconds // 3600)}h {(int(uptime_seconds) % 3600) // 60}m"

    latency_ms = round(bot.latency * 1000) if bot.latency is not None else "N/A"

    msg = (
        f"🖥 **SERVER INFO**\n"
        f"Host: `{hostname}`\n"
        f"OS: `{os_info}`\n\n"
        f"⚙ **SYSTEM**\n"
        f"CPU Usage: `{cpu}%`\n"
        f"RAM Usage: `{ram.percent}%` / {round(ram.total / 1024 ** 3, 1)} GB\n"
        f"Disk Usage: `{disk.percent}%` / {round(disk.total / 1024 ** 3, 1)} GB\n"
        f"Uptime: `{uptime}`\n\n"
        f"🤖 **BOT**\n"
        f"Latency: `{latency_ms}ms`\n"
        f"Python: `{platform.python_version()}`\n"
    )
    await interaction.response.send_message(msg, ephemeral=True)
    log_command(interaction.user.id, interaction.guild.id if interaction.guild else 0, "ping", "server_info")


# -----------------------------
# COMMAND CONFIRMATION VIEW
# -----------------------------
class ConfirmView(View):
    def __init__(self, user_id: int, on_confirm: Callable[[discord.Interaction], asyncio.coroutine]):
        super().__init__(timeout=15)
        self.user_id = user_id
        self.on_confirm = on_confirm

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("This is not for you.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Execute ✅", style=discord.ButtonStyle.success)
    async def confirm(self, interaction: discord.Interaction, button: Button):
        # Call the provided coroutine, which should accept the interaction
        await self.on_confirm(interaction)
        self.stop()

    @discord.ui.button(label="Cancel ❌", style=discord.ButtonStyle.danger)
    async def cancel(self, interaction: discord.Interaction, button: Button):
        await interaction.response.send_message("Command cancelled.", ephemeral=True)
        self.stop()


# -----------------------------
# /shell modal
# -----------------------------
class ShellModal(Modal, title="Shell Command"):
    command = TextInput(label="Shell Command", style=discord.TextStyle.long)

    async def on_submit(self, interaction: discord.Interaction):
        cmd = self.command.value.strip()
        if is_shell_command_blocked(cmd):
            return await interaction.response.send_message("Blocked or malformed command detected.", ephemeral=True)

        async def execute(interaction: discord.Interaction):
            try:
                # run as an async subprocess (non-blocking)
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=COMMAND_TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    await interaction.followup.send("Command timed out.", ephemeral=True)
                    return
                output = truncate_output((stdout + stderr).decode(errors="ignore") or "[no output]")
                await interaction.followup.send(f"```\n{output}\n```", ephemeral=True)
            except Exception as e:
                await interaction.followup.send(f"Execution error:\n```\n{e}\n```", ephemeral=True)

        await interaction.response.send_message(
            "Are you sure you want to execute this shell command?",
            ephemeral=True,
            view=ConfirmView(interaction.user.id, execute),
        )
        log_command(interaction.user.id, interaction.guild.id if interaction.guild else 0, "shell", cmd)


@bot.tree.command(name="shell", description="Run a local shell command")
async def shell(interaction: discord.Interaction):
    if not owner_only(interaction):
        return await interaction.response.send_message("Access denied.", ephemeral=True)
    await interaction.response.send_modal(ShellModal())


# -----------------------------
# /ssh modal
# -----------------------------
class SSHModal(Modal, title="SSH Command"):
    host = TextInput(label="Host (host[:port])")
    username = TextInput(label="Username")
    password = TextInput(label="Password", style=discord.TextStyle.short)  # note: modals can't fully hide text
    command = TextInput(label="Command", style=discord.TextStyle.long)

    async def on_submit(self, interaction: discord.Interaction):
        host_val = self.host.value.strip()
        username = self.username.value.strip()
        password = self.password.value  # never log this

        async def run_ssh_blocking(host: str, username: str, password: str, command: str) -> str:
            # This runs in a thread executor because paramiko is blocking
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                # parse host:port
                if ":" in host:
                    h, p = host.rsplit(":", 1)
                    port = int(p)
                else:
                    h = host
                    port = 22
                ssh.connect(h, port=port, username=username, password=password, timeout=5)
                stdin, stdout, stderr = ssh.exec_command(command, timeout=COMMAND_TIMEOUT)
                out = stdout.read().decode(errors="ignore") if stdout is not None else ""
                err = stderr.read().decode(errors="ignore") if stderr is not None else ""
                return out + err or "[no output]"
            finally:
                try:
                    ssh.close()
                except Exception:
                    pass

        async def execute(interaction: discord.Interaction):
            try:
                output = await run_blocking_in_executor(run_ssh_blocking, host_val, username, password, self.command.value)
                body = truncate_output(output)
                await interaction.followup.send(f"```\n{body}\n```", ephemeral=True)
            except Exception as e:
                await interaction.followup.send(f"SSH Error:\n```\n{e}\n```", ephemeral=True)

        await interaction.response.send_message(
            f"Execute SSH command on `{host_val}`?",
            ephemeral=True,
            view=ConfirmView(interaction.user.id, execute),
        )
        log_command(interaction.user.id, interaction.guild.id if interaction.guild else 0, "ssh", host_val)


@bot.tree.command(name="ssh", description="Run SSH command")
async def ssh(interaction: discord.Interaction):
    if not owner_only(interaction):
        return await interaction.response.send_message("Access denied.", ephemeral=True)
    await interaction.response.send_modal(SSHModal())


# -----------------------------
# /http_get modal
# -----------------------------
class HTTPGetModal(Modal, title="HTTP GET"):
    url = TextInput(label="URL")

    async def on_submit(self, interaction: discord.Interaction):
        url_val = self.url.value.strip()

        async def execute(interaction: discord.Interaction):
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url_val) as r:
                        text = await r.text()
                        body = truncate_output(text)
                        await interaction.followup.send(f"Status: {r.status}\n```\n{body}\n```", ephemeral=True)
            except Exception as e:
                await interaction.followup.send(f"HTTP GET Error:\n```\n{e}\n```", ephemeral=True)

        await interaction.response.send_message(
            f"Execute HTTP GET on `{url_val}`?",
            ephemeral=True,
            view=ConfirmView(interaction.user.id, execute),
        )
        log_command(interaction.user.id, interaction.guild.id if interaction.guild else 0, "http_get", url_val)


@bot.tree.command(name="http_get", description="HTTP GET request")
async def http_get(interaction: discord.Interaction):
    if not owner_only(interaction):
        return await interaction.response.send_message("Access denied.", ephemeral=True)
    await interaction.response.send_modal(HTTPGetModal())


# -----------------------------
# /http_post modal
# -----------------------------
class HTTPPostModal(Modal, title="HTTP POST"):
    url = TextInput(label="URL")
    data = TextInput(label="POST Data", style=discord.TextStyle.long)

    async def on_submit(self, interaction: discord.Interaction):
        url_val = self.url.value.strip()
        data_val = self.data.value

        async def execute(interaction: discord.Interaction):
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(url_val, data=data_val) as r:
                        text = await r.text()
                        body = truncate_output(text)
                        await interaction.followup.send(f"Status: {r.status}\n```\n{body}\n```", ephemeral=True)
            except Exception as e:
                await interaction.followup.send(f"HTTP POST Error:\n```\n{e}\n```", ephemeral=True)

        await interaction.response.send_message(
            f"Execute HTTP POST on `{url_val}`?",
            ephemeral=True,
            view=ConfirmView(interaction.user.id, execute),
        )
        log_command(interaction.user.id, interaction.guild.id if interaction.guild else 0, "http_post", url_val)


@bot.tree.command(name="http_post", description="HTTP POST request")
async def http_post(interaction: discord.Interaction):
    if not owner_only(interaction):
        return await interaction.response.send_message("Access denied.", ephemeral=True)
    await interaction.response.send_modal(HTTPPostModal())


# -----------------------------
# RUN BOT
# -----------------------------
if __name__ == "__main__":
    bot.run(TOKEN)
