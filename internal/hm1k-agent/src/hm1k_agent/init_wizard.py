"""
Interactive setup wizard for HM1K agent initialization.

Guides users through:
- Hashcat detection and verification
- Server connection setup
- Discovery mode registration or token entry
- Initial configuration file creation
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional
import logging

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from hm1k_agent import __version__
from hm1k_agent.config import Config, ServerConfig, AgentConfig, HashcatConfig
from hm1k_agent.api_client import APIClient
from hm1k_agent.auth import TokenManager
from hm1k_agent.hashcat_runner import HashcatRunner

logger = logging.getLogger(__name__)
console = Console()


class InitWizard:
    """Interactive setup wizard for HM1K agent."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the wizard.

        Args:
            config_path: Path to save config file (default: /etc/hm1k-agent/config.yaml)
        """
        self.config_path = Path(config_path or "/etc/hm1k-agent/config.yaml")
        self.config: Optional[Config] = None

    def run(self) -> bool:
        """
        Run the interactive setup wizard.

        Returns:
            True if setup completed successfully
        """
        self._print_header()

        # Check for existing config
        if self.config_path.exists():
            if not Confirm.ask(
                f"[yellow]Config already exists at {self.config_path}. Overwrite?[/yellow]",
                default=False,
            ):
                console.print("[dim]Setup cancelled.[/dim]")
                return False

        try:
            # Step 1: Detect hashcat
            hashcat_path = self._detect_hashcat()
            if not hashcat_path:
                return False

            # Step 2: Get server URL
            server_url = self._get_server_url()
            if not server_url:
                return False

            # Step 3: Test connection and register
            token = self._register_with_server(server_url)
            if not token:
                return False

            # Step 4: Get agent name
            agent_name = self._get_agent_name()

            # Step 5: Create config
            self._create_config(
                hashcat_path=hashcat_path,
                server_url=server_url,
                token=token,
                agent_name=agent_name,
            )

            # Step 6: Create directories
            self._create_directories()

            # Success!
            self._print_success()
            return True

        except KeyboardInterrupt:
            console.print("\n[yellow]Setup cancelled.[/yellow]")
            return False
        except Exception as e:
            console.print(f"\n[red]Setup failed: {e}[/red]")
            logger.exception("Setup wizard error")
            return False

    def _print_header(self) -> None:
        """Print welcome header."""
        console.print()
        console.print(
            Panel.fit(
                f"[bold blue]HM1K Agent Setup Wizard[/bold blue]\n"
                f"[dim]Version {__version__}[/dim]",
                border_style="blue",
            )
        )
        console.print()

    def _detect_hashcat(self) -> Optional[str]:
        """Detect and verify hashcat installation."""
        console.print("[bold]Step 1:[/bold] Detecting hashcat installation\n")

        # Common hashcat locations
        search_paths = [
            "/usr/bin/hashcat",
            "/usr/local/bin/hashcat",
            "/opt/hashcat/hashcat",
            os.path.expanduser("~/hashcat/hashcat"),
            shutil.which("hashcat"),
        ]

        hashcat_path = None

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Searching for hashcat...", total=None)

            for path in search_paths:
                if path and Path(path).exists():
                    hashcat_path = path
                    break

        if hashcat_path:
            console.print(f"  [green]✓[/green] Found hashcat at: {hashcat_path}")

            # Verify it works
            try:
                result = subprocess.run(
                    [hashcat_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                version = result.stdout.strip()
                console.print(f"  [green]✓[/green] Version: {version}")
            except Exception as e:
                console.print(f"  [yellow]![/yellow] Could not get version: {e}")
        else:
            console.print("  [red]✗[/red] Hashcat not found in standard locations")
            hashcat_path = Prompt.ask(
                "  Enter path to hashcat binary",
                default="",
            )

            if not hashcat_path or not Path(hashcat_path).exists():
                console.print("  [red]Invalid path. Please install hashcat first.[/red]")
                return None

        # Check for GPU support
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Checking GPU support...", total=None)

            try:
                result = subprocess.run(
                    [hashcat_path, "-I"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if "OpenCL" in result.stdout or "CUDA" in result.stdout:
                    # Count devices
                    lines = result.stdout.split("\n")
                    device_lines = [l for l in lines if "Device #" in l]
                    console.print(f"  [green]✓[/green] Found {len(device_lines)} compute device(s)")
                else:
                    console.print("  [yellow]![/yellow] No GPU detected - CPU-only mode")
            except Exception as e:
                console.print(f"  [yellow]![/yellow] Could not check devices: {e}")

        console.print()
        return hashcat_path

    def _get_server_url(self) -> Optional[str]:
        """Get HM1K server URL from user."""
        console.print("[bold]Step 2:[/bold] Configure HM1K server connection\n")

        while True:
            server_url = Prompt.ask(
                "  Enter HM1K server URL",
                default="https://hm1k.example.com",
            )

            # Normalize URL
            server_url = server_url.rstrip("/")
            if not server_url.startswith("http"):
                server_url = f"https://{server_url}"

            console.print()

            # Test connection
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("Testing connection...", total=None)

                try:
                    # Create temporary config to test
                    import socket
                    temp_config = Config(
                        server=ServerConfig(url=server_url),
                        agent=AgentConfig(id="temp", name=socket.gethostname()),
                        hashcat=HashcatConfig(),
                    )
                    api = APIClient(temp_config)

                    if api.test_connection():
                        console.print(f"  [green]✓[/green] Connected to {server_url}")
                        return server_url
                    else:
                        console.print(f"  [red]✗[/red] Could not connect to server")
                except Exception as e:
                    console.print(f"  [red]✗[/red] Connection failed: {e}")

            if not Confirm.ask("  Try again?", default=True):
                return None

            console.print()

    def _register_with_server(self, server_url: str) -> Optional[str]:
        """Register agent with server."""
        console.print("\n[bold]Step 3:[/bold] Register with HM1K server\n")

        console.print("  Choose registration method:")
        console.print("    [1] Discovery mode (recommended)")
        console.print("    [2] Enter existing token")
        console.print()

        choice = Prompt.ask("  Selection", choices=["1", "2"], default="1")

        if choice == "1":
            return self._discovery_mode_registration(server_url)
        else:
            return self._manual_token_entry()

    def _discovery_mode_registration(self, server_url: str) -> Optional[str]:
        """Register using discovery mode."""
        console.print()
        console.print("  [bold]Discovery Mode Registration[/bold]")
        console.print()

        # Create temporary config (with SSL verification disabled for self-signed certs)
        import socket
        temp_config = Config(
            server=ServerConfig(url=server_url, verify_ssl=False),
            agent=AgentConfig(id="temp", name=socket.gethostname()),
            hashcat=HashcatConfig(),
        )

        token_manager = TokenManager(temp_config)

        # Start discovery mode
        try:
            registration_code = token_manager.start_discovery_mode()

            console.print(
                Panel.fit(
                    f"[bold yellow]Registration Code: {registration_code}[/bold yellow]\n\n"
                    f"Go to your HM1K server and approve this agent:\n"
                    f"  {server_url}/admin/agents",
                    title="Waiting for Approval",
                    border_style="yellow",
                )
            )
            console.print()

            # Poll for approval
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
            ) as progress:
                task = progress.add_task("Waiting for admin approval...", total=None)

                token = token_manager.poll_for_approval(timeout=300)

                if token:
                    console.print()
                    console.print("  [green]✓[/green] Registration approved!")
                    return token
                else:
                    console.print()
                    console.print("  [red]✗[/red] Registration timed out or was rejected")
                    return None

        except Exception as e:
            console.print(f"  [red]✗[/red] Registration failed: {e}")
            return None

    def _manual_token_entry(self) -> Optional[str]:
        """Get token manually from user."""
        console.print()
        token = Prompt.ask("  Enter JWT token", password=True)

        if token:
            console.print("  [green]✓[/green] Token saved")
            return token

        return None

    def _get_agent_name(self) -> str:
        """Get friendly name for this agent."""
        console.print("\n[bold]Step 4:[/bold] Agent identification\n")

        # Suggest hostname as default
        import socket
        default_name = socket.gethostname()

        agent_name = Prompt.ask(
            "  Enter a name for this agent",
            default=default_name,
        )

        console.print()
        return agent_name

    def _create_config(
        self,
        hashcat_path: str,
        server_url: str,
        token: str,
        agent_name: str,
    ) -> None:
        """Create and save configuration file."""
        console.print("[bold]Step 5:[/bold] Creating configuration\n")

        # Generate agent ID
        import uuid
        agent_id = str(uuid.uuid4())

        self.config = Config(
            server=ServerConfig(
                url=server_url,
                token=token,
            ),
            agent=AgentConfig(
                id=agent_id,
                name=agent_name,
            ),
            hashcat=HashcatConfig(
                path=Path(hashcat_path),
            ),
        )

        # Save config
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.save(self.config_path)

        console.print(f"  [green]✓[/green] Config saved to {self.config_path}")

    def _create_directories(self) -> None:
        """Create required directories."""
        directories = [
            Path("/var/lib/hm1k-agent/cache"),
            Path("/var/lib/hm1k-agent/data"),
            Path("/var/lib/hm1k-agent/hashcat"),
            Path("/var/log/hm1k-agent"),
        ]

        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                console.print(f"  [green]✓[/green] Created {directory}")
            except PermissionError:
                console.print(f"  [yellow]![/yellow] Could not create {directory} (run as root)")
            except Exception as e:
                console.print(f"  [yellow]![/yellow] Error creating {directory}: {e}")

    def _print_success(self) -> None:
        """Print success message with next steps."""
        console.print()
        console.print(
            Panel.fit(
                "[bold green]Setup Complete![/bold green]\n\n"
                "Next steps:\n"
                "  1. Start the agent:\n"
                "     [cyan]hm1k-agent run[/cyan]\n\n"
                "  2. Or install as a service:\n"
                "     [cyan]sudo cp hm1k-agent.service /etc/systemd/system/[/cyan]\n"
                "     [cyan]sudo systemctl enable --now hm1k-agent[/cyan]\n\n"
                "  3. Check status:\n"
                "     [cyan]hm1k-agent status[/cyan]",
                title="Success",
                border_style="green",
            )
        )
        console.print()


def run_wizard(config_path: Optional[str] = None) -> bool:
    """
    Run the setup wizard.

    Args:
        config_path: Path to save config file

    Returns:
        True if setup completed successfully
    """
    wizard = InitWizard(config_path)
    return wizard.run()


def run_init_wizard(
    server_url: Optional[str] = None,
    token: Optional[str] = None,
    hashcat_path: Optional[str] = None,
    interactive: bool = True,
) -> bool:
    """
    Run the setup wizard with optional pre-configured values.

    This is the entry point called by the CLI. Parameters can be pre-set
    via command-line options to skip interactive prompts.

    Args:
        server_url: Pre-configured server URL (skips prompt if set)
        token: Pre-shared authentication token (skips discovery mode if set)
        hashcat_path: Path to hashcat binary (skips detection if set)
        interactive: If False, fail if required values are missing

    Returns:
        True if setup completed successfully
    """
    # For now, use the basic interactive wizard
    # TODO: Support non-interactive mode with pre-configured values
    if not interactive and not all([server_url, token, hashcat_path]):
        console.print("[red]Non-interactive mode requires --server, --token, and --hashcat[/red]")
        return False

    wizard = InitWizard()
    return wizard.run()
