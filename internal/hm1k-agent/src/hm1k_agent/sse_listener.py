"""
Server-Sent Events (SSE) listener for server → agent commands.

Maintains a persistent connection to receive real-time commands:
- job:assigned - New job for this agent
- job:pause - Pause current job
- job:resume - Resume paused job
- job:stop - Stop and cancel current job
- resource:sync - New resource available
- config:update - Agent config changed
- ping - Keep-alive
"""

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional
import logging

import sseclient
import requests

from hm1k_agent.config import Config

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of SSE events from server."""

    JOB_ASSIGNED = "job:assigned"
    JOB_PAUSE = "job:pause"
    JOB_RESUME = "job:resume"
    JOB_STOP = "job:stop"
    RESOURCE_SYNC = "resource:sync"
    SOFTWARE_INSTALL = "software:install"
    CONFIG_UPDATE = "config:update"
    BENCHMARK = "benchmark"
    PING = "ping"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, event_type: str) -> "EventType":
        """Convert string to EventType."""
        for et in cls:
            if et.value == event_type:
                return et
        return cls.UNKNOWN


@dataclass
class SSEEvent:
    """Parsed SSE event from server."""

    event_type: EventType
    data: dict
    event_id: Optional[str] = None
    retry: Optional[int] = None


# Type alias for event handlers
EventHandler = Callable[[SSEEvent], None]


class SSEListener:
    """
    Listens for Server-Sent Events from HM1K server.

    Maintains a persistent HTTP connection and dispatches events
    to registered handlers. Auto-reconnects on connection loss.
    """

    def __init__(self, config: Config):
        """
        Initialize SSE listener.

        Args:
            config: Agent configuration
        """
        self.config = config
        self.base_url = config.server.url.rstrip("/")
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._reconnect_delay = 5  # Initial reconnect delay in seconds
        self._max_reconnect_delay = 300  # Max reconnect delay

    def on(self, event_type: EventType, handler: EventHandler) -> None:
        """
        Register a handler for an event type.

        Args:
            event_type: Type of event to handle
            handler: Callback function
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def off(self, event_type: EventType, handler: EventHandler) -> None:
        """
        Unregister a handler for an event type.

        Args:
            event_type: Type of event
            handler: Callback to remove
        """
        if event_type in self._handlers:
            self._handlers[event_type].remove(handler)

    def start(self) -> None:
        """Start listening for events in a background thread."""
        if self._running:
            logger.warning("SSE listener already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        logger.info("SSE listener started")

    def stop(self) -> None:
        """Stop listening for events."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("SSE listener stopped")

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "User-Agent": f"hm1k-agent/{self.config.agent.id}",
        }

        if self.config.server.token:
            headers["Authorization"] = f"Bearer {self.config.server.token}"

        return headers

    def _listen_loop(self) -> None:
        """Main event listening loop with auto-reconnect."""
        url = f"{self.base_url}/api/agent/events"
        reconnect_delay = self._reconnect_delay

        while self._running:
            try:
                logger.info(f"Connecting to SSE stream: {url}")

                response = requests.get(
                    url,
                    headers=self._get_headers(),
                    stream=True,
                    verify=self.config.server.verify_ssl,
                    timeout=(10, None),  # 10s connect, no read timeout
                )

                if response.status_code == 401:
                    logger.error("SSE connection unauthorized - check token")
                    time.sleep(reconnect_delay)
                    continue

                response.raise_for_status()

                # Connection successful, reset reconnect delay
                reconnect_delay = self._reconnect_delay
                logger.info("SSE connection established")

                # Process events
                client = sseclient.SSEClient(response)
                for event in client.events():
                    if not self._running:
                        break

                    self._handle_event(event)

            except requests.exceptions.ConnectionError as e:
                logger.warning(f"SSE connection lost: {e}")
            except requests.exceptions.Timeout as e:
                logger.warning(f"SSE connection timeout: {e}")
            except Exception as e:
                logger.error(f"SSE error: {e}")

            if self._running:
                logger.info(f"Reconnecting in {reconnect_delay}s...")
                time.sleep(reconnect_delay)

                # Exponential backoff with max limit
                reconnect_delay = min(reconnect_delay * 2, self._max_reconnect_delay)

    def _handle_event(self, raw_event: sseclient.Event) -> None:
        """
        Handle a raw SSE event.

        Args:
            raw_event: Raw event from sseclient
        """
        try:
            event_type = EventType.from_string(raw_event.event or "unknown")

            # Parse JSON data
            import json
            try:
                data = json.loads(raw_event.data) if raw_event.data else {}
            except json.JSONDecodeError:
                data = {"raw": raw_event.data}

            event = SSEEvent(
                event_type=event_type,
                data=data,
                event_id=raw_event.id,
                retry=int(raw_event.retry) if raw_event.retry else None,
            )

            logger.debug(f"Received SSE event: {event_type.value}")

            # Dispatch to handlers
            handlers = self._handlers.get(event_type, [])
            for handler in handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")

            # Also dispatch to wildcard handlers
            for handler in self._handlers.get(EventType.UNKNOWN, []):
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Wildcard handler error: {e}")

        except Exception as e:
            logger.error(f"Failed to handle SSE event: {e}")

    @property
    def is_connected(self) -> bool:
        """Check if currently connected to SSE stream."""
        return self._running and self._thread and self._thread.is_alive()
