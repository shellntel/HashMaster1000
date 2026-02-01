"""
HM1K Agent - Hashcat cracking agent for Hash Master 1000

A lightweight Python agent that runs on cracking servers to execute
hashcat jobs and report status back to the HM1K server.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("hm1k-agent")
except PackageNotFoundError:
    # Package not installed, fallback for development
    __version__ = "0.0.0-dev"

__author__ = "Brian Judd"

from hm1k_agent.agent import Agent
from hm1k_agent.config import Config

__all__ = ["Agent", "Config", "__version__"]
