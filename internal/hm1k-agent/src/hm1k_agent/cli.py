"""
Command-line interface for HM1K Agent.

Provides commands for:
- init: Interactive setup wizard
- status: Show agent status and current job
- test-connection: Verify server connectivity
- register: Manually trigger registration
- logs: Tail the agent log
- benchmark: Run hashcat benchmark
- run: Start the agent daemon (usually via systemd)
"""

import click
from rich.console import Console
from rich.table import Table

from hm1k_agent import __version__

console = Console()


def format_speed(speed: float) -> str:
    """Format hash speed with appropriate unit (H/s, KH/s, MH/s, GH/s, TH/s)."""
    units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"]
    unit_index = 0

    while speed >= 1000 and unit_index < len(units) - 1:
        speed /= 1000
        unit_index += 1

    return f"{speed:,.2f} {units[unit_index]}"


@click.group()
@click.version_option(version=__version__, prog_name="hm1k-agent")
def main():
    """HM1K Agent - Hashcat cracking agent for Hash Master 1000."""
    pass


@main.command()
@click.option("--server", "-s", help="HM1K server URL")
@click.option("--token", "-t", help="Pre-shared authentication token")
@click.option("--hashcat", "-h", help="Path to hashcat binary")
@click.option("--non-interactive", is_flag=True, help="Skip interactive prompts")
def init(server: str | None, token: str | None, hashcat: str | None, non_interactive: bool):
    """
    Initialize the agent with interactive setup wizard.

    This command:
    1. Prompts for server URL and optional pre-shared token
    2. Detects hashcat binary location
    3. Discovers GPU hardware via nvidia-smi or hashcat -I
    4. Creates config file at /etc/hm1k-agent/config.yaml
    5. Sets up working directories with appropriate permissions
    6. Generates systemd unit file
    7. Optionally starts in discovery mode for server-side registration
    """
    from hm1k_agent.init_wizard import run_init_wizard

    run_init_wizard(
        server_url=server,
        token=token,
        hashcat_path=hashcat,
        interactive=not non_interactive,
    )


@main.command()
def status():
    """Show agent status, connection state, and current job."""
    from hm1k_agent.config import Config
    from hm1k_agent.api_client import APIClient

    try:
        config = Config.load()
    except FileNotFoundError:
        console.print("[red]Agent not initialized. Run 'hm1k-agent init' first.[/red]")
        raise SystemExit(1)

    table = Table(title="HM1K Agent Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Agent ID", config.agent.id)
    table.add_row("Agent Name", config.agent.name)
    table.add_row("Server URL", config.server.url)
    table.add_row("Hashcat Binary", config.hashcat.binary)

    # TODO: Check actual connection status and current job
    table.add_row("Connection", "[yellow]Not implemented[/yellow]")
    table.add_row("Current Job", "[yellow]Not implemented[/yellow]")

    console.print(table)


@main.command("test-connection")
def test_connection():
    """Verify connectivity to the HM1K server."""
    from hm1k_agent.config import Config
    from hm1k_agent.api_client import APIClient

    try:
        config = Config.load()
    except FileNotFoundError:
        console.print("[red]Agent not initialized. Run 'hm1k-agent init' first.[/red]")
        raise SystemExit(1)

    console.print(f"Testing connection to {config.server.url}...")

    client = APIClient(config)
    try:
        result = client.test_connection()
        if result.success:
            console.print("[green]Connection successful![/green]")
            console.print(f"  Server version: {result.server_version}")
            console.print(f"  Agent recognized: {result.agent_recognized}")
        else:
            console.print(f"[red]Connection failed: {result.error}[/red]")
            raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Connection error: {e}[/red]")
        raise SystemExit(1)


@main.command()
def register():
    """Manually trigger registration with the HM1K server."""
    from hm1k_agent.config import Config
    from hm1k_agent.auth import AuthManager

    try:
        config = Config.load()
    except FileNotFoundError:
        console.print("[red]Agent not initialized. Run 'hm1k-agent init' first.[/red]")
        raise SystemExit(1)

    if config.server.token:
        console.print("[yellow]Agent already has a token. Use --force to re-register.[/yellow]")
        return

    auth = AuthManager(config)
    console.print("Starting registration in discovery mode...")
    console.print("A registration code will be displayed.")
    console.print("Enter this code in the HM1K web interface to approve the agent.")

    # TODO: Implement discovery mode registration
    console.print("[yellow]Not implemented yet[/yellow]")


@main.command()
@click.option("--follow", "-f", is_flag=True, help="Follow log output (like tail -f)")
@click.option("--lines", "-n", default=50, help="Number of lines to show")
def logs(follow: bool, lines: int):
    """View agent logs."""
    import subprocess
    from hm1k_agent.config import Config

    try:
        config = Config.load()
        log_file = config.logging.file
    except FileNotFoundError:
        log_file = "/var/log/hm1k-agent/agent.log"

    if follow:
        cmd = ["tail", "-f", "-n", str(lines), log_file]
    else:
        cmd = ["tail", "-n", str(lines), log_file]

    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        console.print(f"[red]Log file not found: {log_file}[/red]")
        console.print("Try: sudo journalctl -u hm1k-agent -f")


@main.command()
@click.option("--hash-mode", "-m", default=1000, help="Hash mode to benchmark (default: 1000 NTLM)")
@click.option("--report", is_flag=True, help="Report results to HM1K server")
def benchmark(hash_mode: int, report: bool):
    """Run hashcat benchmark and optionally report to server."""
    from hm1k_agent.config import Config
    from hm1k_agent.hashcat_runner import HashcatRunner

    try:
        config = Config.load()
    except FileNotFoundError:
        console.print("[red]Agent not initialized. Run 'hm1k-agent init' first.[/red]")
        raise SystemExit(1)

    console.print(f"Running hashcat benchmark for mode {hash_mode}...")

    runner = HashcatRunner(config)
    result = runner.benchmark(hash_mode)

    if result.success:
        table = Table(title=f"Benchmark Results (Mode {hash_mode})")
        table.add_column("Device", style="cyan")
        table.add_column("Speed", style="green")

        for device in result.devices:
            table.add_row(device.name, format_speed(device.speed))

        if len(result.devices) > 1:
            table.add_row("[bold]Total[/bold]", f"[bold]{format_speed(result.total_speed)}[/bold]")

        console.print(table)

        if report:
            console.print("Reporting to server...")
            # TODO: Implement server reporting
            console.print("[yellow]Server reporting not implemented yet[/yellow]")
    else:
        console.print(f"[red]Benchmark failed: {result.error}[/red]")
        raise SystemExit(1)


def setup_logging(config) -> None:
    """Configure logging based on config settings."""
    import logging
    import os
    from logging.handlers import RotatingFileHandler

    log_level = getattr(logging, config.logging.level.upper(), logging.INFO)
    log_format = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Create root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Console handler (for foreground mode and systemd)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(log_format, date_format))
    root_logger.addHandler(console_handler)

    # File handler (rotating)
    log_file = config.logging.file
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            # Fall back to current directory if we can't create log dir
            log_file = "agent.log"

    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=config.logging.max_size_mb * 1024 * 1024,
            backupCount=config.logging.backup_count,
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(log_format, date_format))
        root_logger.addHandler(file_handler)
    except PermissionError:
        logging.warning(f"Cannot write to log file: {log_file}")

    # Suppress noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Suppress SSL verification warnings (agent uses verify_ssl=False for self-signed certs)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@main.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize)")
def run(foreground: bool):
    """
    Start the agent daemon.

    Usually invoked by systemd, but can be run manually for debugging.
    """
    from hm1k_agent.config import Config
    from hm1k_agent.agent import Agent

    try:
        config = Config.load()
    except FileNotFoundError:
        console.print("[red]Agent not initialized. Run 'hm1k-agent init' first.[/red]")
        raise SystemExit(1)

    # Configure logging before starting agent
    setup_logging(config)

    if foreground:
        console.print("Starting agent in foreground mode...")

    agent = Agent(config)
    try:
        agent.start()
    except KeyboardInterrupt:
        console.print("\nShutting down...")
        agent.stop()


if __name__ == "__main__":
    main()
