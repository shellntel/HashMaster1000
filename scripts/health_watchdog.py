#!/usr/bin/env python3
"""
HM1K Health Watchdog

Monitors the HM1K server health and restarts gunicorn if workers become
unresponsive or unhealthy. Run as a separate systemd service.

Usage:
    python health_watchdog.py [--interval SECONDS] [--max-failures COUNT]

Configuration via environment variables:
    HM1K_HEALTH_URL: URL to check (default: https://127.0.0.1:8443/api/health/liveness)
    HM1K_CHECK_INTERVAL: Seconds between checks (default: 30)
    HM1K_MAX_FAILURES: Failures before restart (default: 3)
    HM1K_SERVICE_NAME: Systemd service name (default: hm1k)
"""

import argparse
import logging
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
import ssl
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def check_health(url: str, timeout: int = 10) -> dict:
    """
    Check the health endpoint and return the response.

    Args:
        url: Health check URL
        timeout: Request timeout in seconds

    Returns:
        dict with status and details, or error info
    """
    try:
        # Create SSL context that doesn't verify certs (for self-signed)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            data = json.loads(response.read().decode('utf-8'))
            return {
                'success': True,
                'status_code': response.status,
                'data': data,
            }
    except urllib.error.URLError as e:
        return {
            'success': False,
            'error': f"Connection error: {e.reason}",
        }
    except urllib.error.HTTPError as e:
        return {
            'success': False,
            'error': f"HTTP error: {e.code} {e.reason}",
            'status_code': e.code,
        }
    except TimeoutError:
        return {
            'success': False,
            'error': "Request timed out",
        }
    except json.JSONDecodeError as e:
        return {
            'success': False,
            'error': f"Invalid JSON response: {e}",
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"Unexpected error: {e}",
        }


def restart_service(service_name: str) -> bool:
    """
    Restart the systemd service.

    Args:
        service_name: Name of the systemd service

    Returns:
        True if restart succeeded, False otherwise
    """
    logger.warning(f"Restarting service: {service_name}")
    try:
        result = subprocess.run(
            ['sudo', 'systemctl', 'restart', service_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            logger.info(f"Service {service_name} restarted successfully")
            return True
        else:
            logger.error(f"Failed to restart service: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("Service restart timed out")
        return False
    except Exception as e:
        logger.error(f"Failed to restart service: {e}")
        return False


def run_watchdog(
    health_url: str,
    check_interval: int,
    max_failures: int,
    service_name: str,
    restart_cooldown: int = 120,
):
    """
    Main watchdog loop.

    Args:
        health_url: URL to check for health
        check_interval: Seconds between health checks
        max_failures: Consecutive failures before restart
        service_name: Systemd service to restart
        restart_cooldown: Seconds to wait after restart before checking again
    """
    consecutive_failures = 0
    last_restart_time = 0

    logger.info(f"HM1K Health Watchdog starting")
    logger.info(f"  Health URL: {health_url}")
    logger.info(f"  Check interval: {check_interval}s")
    logger.info(f"  Max failures: {max_failures}")
    logger.info(f"  Service: {service_name}")

    while True:
        try:
            result = check_health(health_url)

            if result['success']:
                if consecutive_failures > 0:
                    logger.info(f"Health check recovered after {consecutive_failures} failures")
                consecutive_failures = 0

                # Log any slow requests detected
                data = result.get('data', {})
                active_requests = data.get('active_requests', 0)
                if active_requests > 10:
                    logger.warning(f"High active request count: {active_requests}")
            else:
                consecutive_failures += 1
                logger.warning(
                    f"Health check failed ({consecutive_failures}/{max_failures}): "
                    f"{result.get('error', 'Unknown error')}"
                )

                if consecutive_failures >= max_failures:
                    # Check cooldown to prevent restart loops
                    time_since_restart = time.time() - last_restart_time
                    if time_since_restart < restart_cooldown:
                        logger.warning(
                            f"Skipping restart - cooldown active "
                            f"({int(restart_cooldown - time_since_restart)}s remaining)"
                        )
                    else:
                        logger.error(
                            f"Max failures reached ({max_failures}), restarting service"
                        )
                        if restart_service(service_name):
                            last_restart_time = time.time()
                            consecutive_failures = 0
                            # Wait extra time after restart for service to come up
                            logger.info(f"Waiting {restart_cooldown}s for service to stabilize...")
                            time.sleep(restart_cooldown)
                            continue

            time.sleep(check_interval)

        except KeyboardInterrupt:
            logger.info("Watchdog stopped by user")
            break
        except Exception as e:
            logger.error(f"Watchdog error: {e}")
            time.sleep(check_interval)


def main():
    parser = argparse.ArgumentParser(
        description='HM1K Health Watchdog - monitors and restarts unhealthy workers'
    )
    parser.add_argument(
        '--url',
        default=os.environ.get('HM1K_HEALTH_URL', 'https://127.0.0.1:8443/api/health/liveness'),
        help='Health check URL',
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=int(os.environ.get('HM1K_CHECK_INTERVAL', '30')),
        help='Seconds between health checks',
    )
    parser.add_argument(
        '--max-failures',
        type=int,
        default=int(os.environ.get('HM1K_MAX_FAILURES', '3')),
        help='Consecutive failures before restart',
    )
    parser.add_argument(
        '--service',
        default=os.environ.get('HM1K_SERVICE_NAME', 'hm1k'),
        help='Systemd service name to restart',
    )
    parser.add_argument(
        '--cooldown',
        type=int,
        default=int(os.environ.get('HM1K_RESTART_COOLDOWN', '120')),
        help='Seconds to wait after restart before checking again',
    )

    args = parser.parse_args()

    run_watchdog(
        health_url=args.url,
        check_interval=args.interval,
        max_failures=args.max_failures,
        service_name=args.service,
        restart_cooldown=args.cooldown,
    )


if __name__ == '__main__':
    main()
