"""
Ollama Integration Toolkit for HM1K

This module provides AI-powered analysis capabilities using a local Ollama server.
Currently a hidden/experimental feature for internal testing.

Features:
- Executive Summary Generation
- Semantic Password Clustering
- Natural Language Pattern Description
- Attack Strategy Recommendations
"""

import os
import json
import time
import requests
from typing import Optional, Dict, List, Any, Callable, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from app.ollama_prompts import (
    SYSTEM_PROMPT,
    EXECUTIVE_SUMMARY_PROMPT,
    PATTERN_DESCRIPTION_PROMPT,
    SEMANTIC_CLUSTERING_PROMPT,
    ATTACK_STRATEGY_PROMPT,
    BATCH_ANALYSIS_PROMPTS,
    # AI Report Section Prompts
    WEAK_HABITS_PROMPT,
    COMPANY_INTEL_PROMPT,
    USER_BEHAVIOR_PROMPT,
    RISK_ASSESSMENT_PROMPT,
    RECOMMENDATIONS_PROMPT,
    FULL_REPORT_PROMPT,
    AI_REPORT_SECTIONS,
    # Pipeline Prompts (Phase 2 & 3) - section-specific
    get_validation_prompt,
    get_formatting_prompt,
    PHASE_CONFIG,
    get_phase_config,
)


@dataclass
class OllamaConfig:
    """Configuration for Ollama API connection."""
    host: str = "http://localhost:11434"
    timeout: int = 120
    enabled: bool = False


@dataclass
class OllamaServer:
    """Configuration for a single LLM server (Ollama or OpenAI-compatible)."""
    id: str
    name: str
    host: str
    description: str = ""
    hardware: str = ""
    api_type: str = "auto"  # "ollama", "openai", or "auto" (auto-detect)


@dataclass
class ValidationResult:
    """Result from Phase 2 validation of AI-generated content."""
    issues: List[Dict[str, str]]  # [{type, description, original_text, evidence_reference, severity}]
    corrected_content: str
    confidence: float  # 0.0 - 1.0
    needs_human_review: bool
    validation_stats: Dict[str, Any]  # {facts_checked, issues_found, corrections_made, overall_assessment}
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class PipelineResult:
    """Result from the full 3-phase AI analysis pipeline."""
    section_id: str
    phase1_raw: Optional[str] = None
    phase2_validated: Optional[ValidationResult] = None
    phase3_final: Optional[str] = None
    retry_count: int = 0
    needs_human_review: bool = False
    error: Optional[str] = None
    timing: Dict[str, float] = None  # {phase1: seconds, phase2: seconds, phase3: seconds}

    def __post_init__(self):
        if self.timing is None:
            self.timing = {}


@dataclass
class PipelineProgress:
    """Tracks progress of the AI analysis pipeline."""
    job_id: str
    total_steps: int
    current_step: int
    current_phase: str  # "phase1", "phase2", "phase3"
    current_section: str
    current_action: str  # Human-readable description
    phase_timing: Dict[str, float]  # Timing for completed phases
    started_at: float
    estimated_remaining: Optional[float] = None

    def __post_init__(self):
        if self.phase_timing is None:
            self.phase_timing = {}


# Multi-server configuration
# Servers are loaded from environment variables with fallback to defaults

# Server status cache (90-minute TTL)
_server_status_cache: Dict[str, Any] = {}
_server_status_cache_time: float = 0
SERVER_STATUS_CACHE_TTL = 90 * 60  # 90 minutes in seconds

# API type detection cache (per-host, persists until invalidated)
_api_type_cache: Dict[str, str] = {}


def detect_api_type(host: str, timeout: float = 3.0) -> str:
    """
    Detect whether a server uses Ollama or OpenAI-compatible API.

    Probes both API endpoints to determine the correct type.
    Results are cached to avoid repeated detection.

    Args:
        host: Server URL (e.g., "http://localhost:11434")
        timeout: Connection timeout in seconds

    Returns:
        "ollama" or "openai" based on detection, or "unknown" if unreachable
    """
    # Check cache first
    if host in _api_type_cache:
        return _api_type_cache[host]

    api_type = "unknown"

    # Try Ollama API first (more common in this app)
    try:
        response = requests.get(f"{host}/api/tags", timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            # Ollama returns {"models": [...]}
            if "models" in data:
                api_type = "ollama"
                _api_type_cache[host] = api_type
                return api_type
    except requests.RequestException:
        pass

    # Try OpenAI-compatible API (LM Studio, vLLM, etc.)
    try:
        response = requests.get(f"{host}/v1/models", timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            # OpenAI format returns {"data": [...]} or {"object": "list", "data": [...]}
            if "data" in data or "object" in data:
                api_type = "openai"
                _api_type_cache[host] = api_type
                return api_type
    except requests.RequestException:
        pass

    return api_type


def get_api_type_for_server(server: 'OllamaServer') -> str:
    """
    Get the API type for a server, using auto-detection if needed.

    Args:
        server: OllamaServer instance

    Returns:
        "ollama" or "openai" (never "auto" or "unknown")
    """
    if server.api_type in ("ollama", "openai"):
        return server.api_type

    # Auto-detect
    detected = detect_api_type(server.host)
    if detected in ("ollama", "openai"):
        return detected

    # Default to ollama if detection fails
    return "ollama"


def invalidate_api_type_cache(host: Optional[str] = None) -> None:
    """
    Invalidate API type cache.

    Args:
        host: Specific host to invalidate, or None to clear all
    """
    global _api_type_cache
    if host:
        _api_type_cache.pop(host, None)
    else:
        _api_type_cache = {}


# =============================================================================
# OpenAI-Compatible API Adapters
# =============================================================================

def list_models_openai(host: str, timeout: float = 10.0) -> List[Dict[str, Any]]:
    """
    List models from an OpenAI-compatible API server.

    Args:
        host: Server URL (e.g., "http://localhost:1234")
        timeout: Request timeout

    Returns:
        List of model info dicts with 'name' and 'size' keys
    """
    try:
        response = requests.get(f"{host}/v1/models", timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            models = data.get("data", [])
            # Normalize to our format
            return [
                {
                    "name": m.get("id", m.get("name", "unknown")),
                    "size": m.get("size", 0)  # OpenAI format may not include size
                }
                for m in models
            ]
    except requests.RequestException:
        pass
    return []


def generate_openai(
    host: str,
    model: str,
    prompt: str,
    system: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: Optional[int] = None,
    timeout: int = 120,
    include_usage: bool = False
) -> Optional[Any]:
    """
    Generate text using OpenAI-compatible API.

    Args:
        host: Server URL
        model: Model name/ID
        prompt: User prompt
        system: Optional system prompt
        temperature: Sampling temperature
        max_tokens: Maximum tokens to generate
        timeout: Request timeout
        include_usage: If True, return dict with response and token usage

    Returns:
        Generated text (str) or dict with usage info, or None on error
    """
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "temperature": float(temperature),
        "stream": False
    }

    if max_tokens:
        payload["max_tokens"] = max_tokens

    try:
        response = requests.post(
            f"{host}/v1/chat/completions",
            json=payload,
            timeout=timeout
        )

        if response.status_code == 200:
            data = response.json()
            content = ""
            if data.get("choices"):
                content = data["choices"][0].get("message", {}).get("content", "")

            if include_usage:
                usage = data.get("usage", {})
                return {
                    "response": content,
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0)
                }
            return content
        else:
            print(f"OpenAI API error: {response.status_code} - {response.text}")
            return None

    except requests.RequestException as e:
        print(f"OpenAI request failed: {e}")
        return None


def chat_openai(
    host: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float = 0.7,
    timeout: int = 120
) -> Optional[str]:
    """
    Send chat messages using OpenAI-compatible API.

    Args:
        host: Server URL
        model: Model name/ID
        messages: List of {"role": "...", "content": "..."}
        temperature: Sampling temperature
        timeout: Request timeout

    Returns:
        Generated response or None on error
    """
    payload = {
        "model": model,
        "messages": messages,
        "temperature": float(temperature),
        "stream": False
    }

    try:
        response = requests.post(
            f"{host}/v1/chat/completions",
            json=payload,
            timeout=timeout
        )

        if response.status_code == 200:
            data = response.json()
            if data.get("choices"):
                return data["choices"][0].get("message", {}).get("content", "")
            return ""
        else:
            print(f"OpenAI API error: {response.status_code} - {response.text}")
            return None

    except requests.RequestException as e:
        print(f"OpenAI request failed: {e}")
        return None


def get_ollama_servers() -> List[OllamaServer]:
    """Get list of configured Ollama servers."""
    servers = []

    # Primary server from OLLAMA_HOST
    primary_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    servers.append(OllamaServer(
        id="primary",
        name=os.getenv("OLLAMA_PRIMARY_NAME", "Primary Server"),
        host=primary_host,
        description=os.getenv("OLLAMA_PRIMARY_DESC", "Default Ollama server"),
        hardware=os.getenv("OLLAMA_PRIMARY_HARDWARE", "")
    ))

    # Secondary server (optional)
    secondary_host = os.getenv("OLLAMA_SECONDARY_HOST", "")
    if secondary_host:
        servers.append(OllamaServer(
            id="secondary",
            name=os.getenv("OLLAMA_SECONDARY_NAME", "Secondary Server"),
            host=secondary_host,
            description=os.getenv("OLLAMA_SECONDARY_DESC", "Secondary Ollama server"),
            hardware=os.getenv("OLLAMA_SECONDARY_HARDWARE", "")
        ))

    # Tertiary server (optional)
    tertiary_host = os.getenv("OLLAMA_TERTIARY_HOST", "")
    if tertiary_host:
        servers.append(OllamaServer(
            id="tertiary",
            name=os.getenv("OLLAMA_TERTIARY_NAME", "Tertiary Server"),
            host=tertiary_host,
            description=os.getenv("OLLAMA_TERTIARY_DESC", "Tertiary Ollama server"),
            hardware=os.getenv("OLLAMA_TERTIARY_HARDWARE", "")
        ))

    return servers


def get_server_by_id(server_id: str) -> Optional[OllamaServer]:
    """Get a specific server by its ID."""
    servers = get_ollama_servers()
    for server in servers:
        if server.id == server_id:
            return server
    return None


def get_ollama_config(server_id: Optional[str] = None) -> OllamaConfig:
    """Load Ollama configuration from environment variables.

    Args:
        server_id: Optional server ID to get config for specific server
    """
    timeout = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    enabled = os.getenv("OLLAMA_ENABLED", "false").lower() == "true"

    if server_id:
        server = get_server_by_id(server_id)
        if server:
            return OllamaConfig(
                host=server.host,
                timeout=timeout,
                enabled=enabled
            )

    return OllamaConfig(
        host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        timeout=timeout,
        enabled=enabled
    )


def get_client_for_server(server_id: str) -> Optional['OllamaClient']:
    """
    Create an OllamaClient configured for a specific server.

    Uses auto-detection for API type unless the server has an explicit type set.

    Args:
        server_id: The server ID

    Returns:
        Configured OllamaClient or None if server not found
    """
    server = get_server_by_id(server_id)
    if not server:
        return None

    config = get_ollama_config(server_id)
    return OllamaClient(config, api_type=server.api_type)


class OllamaClient:
    """Client for interacting with LLM servers (Ollama or OpenAI-compatible)."""

    def __init__(self, config: Optional[OllamaConfig] = None, api_type: str = "auto"):
        self.config = config or get_ollama_config()
        self._available_models: Optional[List[str]] = None
        self._api_type = api_type  # "ollama", "openai", or "auto"
        self._detected_api_type: Optional[str] = None

    @property
    def api_type(self) -> str:
        """Get the API type, detecting if needed."""
        if self._api_type in ("ollama", "openai"):
            return self._api_type
        if self._detected_api_type is None:
            self._detected_api_type = detect_api_type(self.config.host)
        return self._detected_api_type if self._detected_api_type in ("ollama", "openai") else "ollama"

    def is_available(self) -> bool:
        """Check if server is reachable (supports both API types)."""
        if not self.config.enabled:
            return False

        # Try detection - this tells us if the server is reachable
        detected = detect_api_type(self.config.host, timeout=5)
        return detected in ("ollama", "openai")

    def list_models(self, include_details: bool = False) -> List:
        """Get list of available models from server.

        Args:
            include_details: If True, return full model info dicts. If False, return just names.
        """
        if self.api_type == "openai":
            models = list_models_openai(self.config.host)
            if include_details:
                return models
            else:
                names = [m["name"] for m in models]
                if self._available_models is None:
                    self._available_models = names
                return names

        # Ollama API
        try:
            response = requests.get(
                f"{self.config.host}/api/tags",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", [])
                if include_details:
                    # Return full model info with name and size
                    return [{"name": m.get("name"), "size": m.get("size", 0)} for m in models]
                else:
                    # Return just names (for backwards compatibility)
                    if self._available_models is None:
                        self._available_models = [m["name"] for m in models]
                    return self._available_models
        except requests.RequestException:
            pass
        return []

    def get_running_models(self) -> Dict[str, Any]:
        """Get currently running/loaded models from server.

        Note: OpenAI-compatible APIs don't support this - returns empty result.

        Returns dict with:
        - models: List of running model info (name, size, vram, context_length, expires_at)
        - count: Number of running models
        - total_vram: Total VRAM usage in bytes
        - busy: True if any model is loaded (likely processing or ready)
        """
        result = {
            "models": [],
            "count": 0,
            "total_vram": 0,
            "busy": False
        }

        if not self.config.enabled:
            return result

        # OpenAI API doesn't have a /ps endpoint
        if self.api_type == "openai":
            return result

        try:
            response = requests.get(
                f"{self.config.host}/api/ps",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", [])
                result["models"] = [
                    {
                        "name": m.get("model", ""),
                        "size": m.get("size", 0),
                        "size_vram": m.get("size_vram", 0),
                        "context_length": m.get("context_length", 0),
                        "expires_at": m.get("expires_at", ""),
                        "parameter_size": m.get("details", {}).get("parameter_size", ""),
                        "quantization": m.get("details", {}).get("quantization_level", "")
                    }
                    for m in models
                ]
                result["count"] = len(models)
                result["total_vram"] = sum(m.get("size_vram", 0) for m in models)
                result["busy"] = len(models) > 0
        except requests.RequestException:
            pass

        return result

    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific model.

        Note: OpenAI-compatible APIs have limited model info support.

        Returns dict with model details including:
        - modelfile, parameters, template, license, etc. (Ollama)
        - id, object, owned_by (OpenAI)
        """
        if not self.config.enabled:
            return None

        # OpenAI API - try to get model info from /v1/models/{model}
        if self.api_type == "openai":
            try:
                response = requests.get(
                    f"{self.config.host}/v1/models/{model_name}",
                    timeout=10
                )
                if response.status_code == 200:
                    return response.json()
            except requests.RequestException:
                pass
            return None

        # Ollama API
        try:
            response = requests.post(
                f"{self.config.host}/api/show",
                json={"model": model_name},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            pass

        return None

    def get_version(self) -> Optional[str]:
        """Get server version."""
        if not self.config.enabled:
            return None

        # OpenAI API doesn't have a standard version endpoint
        if self.api_type == "openai":
            return "OpenAI-compatible"

        try:
            response = requests.get(
                f"{self.config.host}/api/version",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("version", "unknown")
        except requests.RequestException:
            pass

        return None

    def ensure_model_loaded(
        self,
        model: str,
        num_ctx: int = 16384,
        timeout: Optional[int] = None,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> bool:
        """
        Ensure a model is loaded and ready for inference.

        If the model is not currently loaded, triggers a load by sending a minimal
        request and waits for it to complete.

        Note: OpenAI-compatible APIs don't support explicit model loading.
        For these, we assume the model is always ready.

        Args:
            model: Model name to load
            num_ctx: Context window size
            timeout: Maximum time to wait for model to load (seconds).
                     Defaults to 180s (3 min) which is enough for even 671B models.
            progress_callback: Optional callback for progress updates

        Returns:
            True if model is loaded and ready, False otherwise
        """
        if not self.config.enabled:
            return False

        # OpenAI-compatible APIs don't have explicit model loading
        # Model is loaded on first request or kept in memory by the server
        if self.api_type == "openai":
            if progress_callback:
                progress_callback(f"Model {model} ready (OpenAI-compatible server)")
            return True

        # Use reasonable timeout for model loading (not the long generation timeout)
        # 70B models load in ~20s, 405B in ~1-2 min, 671B in ~3-5 min
        if timeout is None:
            # Very large models need more time, especially when unloading another large model first
            if "671b" in model.lower() or "405b" in model.lower():
                timeout = 420  # 7 minutes for 400B+ models
            else:
                timeout = 180  # 3 minutes for smaller models

        # Check if model is already loaded
        running = self.get_running_models()
        for m in running.get("models", []):
            loaded_name = m.get("name", "")
            # Check for exact match or base model match (e.g., "deepseek-r1:671b" matches "deepseek-r1:671b")
            if loaded_name == model or loaded_name.startswith(model.split(":")[0] + ":"):
                if progress_callback:
                    progress_callback(f"Model {model} already loaded")
                return True

        if progress_callback:
            progress_callback(f"Loading model {model}...")

        # First, unload any currently loaded models to free memory
        # This prevents crashes when switching between large models
        running = self.get_running_models()
        for m in running.get("models", []):
            loaded_name = m.get("name", "")
            if loaded_name and loaded_name != model:
                print(f"[ensure_model_loaded] Unloading {loaded_name} before loading {model}")
                if progress_callback:
                    progress_callback(f"Unloading {loaded_name}...")
                try:
                    # Send keep_alive: 0 to immediately unload the model
                    unload_payload = {
                        "model": loaded_name,
                        "keep_alive": 0
                    }
                    unload_resp = requests.post(
                        f"{self.config.host}/api/generate",
                        json=unload_payload,
                        timeout=60
                    )
                    if unload_resp.status_code == 200:
                        print(f"[ensure_model_loaded] Successfully unloaded {loaded_name}")
                        # Give the server time to fully release resources
                        time.sleep(3)
                    else:
                        print(f"[ensure_model_loaded] Warning: Could not unload {loaded_name}")
                except Exception as e:
                    print(f"[ensure_model_loaded] Warning: Error unloading {loaded_name}: {e}")
                    # Continue anyway - the load might still work

        # Trigger model load with a minimal request
        # Use small context for warmup to reduce memory - actual requests will set their own context
        # The 671B model with 16K context needs ~78GB KV cache alone, which can cause OOM
        warmup_ctx = 2048  # Minimal context for warmup only

        payload = {
            "model": model,
            "prompt": "hi",  # Minimal prompt
            "stream": False,
            "options": {
                "num_ctx": warmup_ctx,
                "num_predict": 1  # Generate just 1 token
            },
            "keep_alive": "10m"  # Keep model loaded for 10 minutes
        }

        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                print(f"[ensure_model_loaded] Sending warmup request for {model} (timeout={timeout}s, attempt {attempt + 1}/{max_retries + 1})")
                response = requests.post(
                    f"{self.config.host}/api/generate",
                    json=payload,
                    timeout=timeout
                )

                if response.status_code == 200:
                    print(f"[ensure_model_loaded] Success: {model} loaded")
                    if progress_callback:
                        progress_callback(f"Model {model} loaded and ready")
                    return True
                else:
                    try:
                        error_msg = response.json().get("error", "Unknown error")
                    except:
                        error_msg = f"HTTP {response.status_code}"
                    print(f"[ensure_model_loaded] Failed (attempt {attempt + 1}): {error_msg}")

                    # If it's a "model runner stopped" error, retry after a delay
                    if "model runner" in error_msg.lower() and attempt < max_retries:
                        print(f"[ensure_model_loaded] Retrying in 5 seconds...")
                        time.sleep(5)
                        continue

                    if progress_callback:
                        progress_callback(f"Failed to load model: {error_msg}")
                    return False

            except requests.Timeout:
                print(f"[ensure_model_loaded] Timeout after {timeout}s waiting for {model}")
                if progress_callback:
                    progress_callback(f"Timeout loading model {model}")
                return False
            except requests.RequestException as e:
                print(f"[ensure_model_loaded] Request error (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries:
                    print(f"[ensure_model_loaded] Retrying in 5 seconds...")
                    time.sleep(5)
                    continue
                if progress_callback:
                    progress_callback(f"Error loading model: {str(e)}")
                return False

        return False

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        include_usage: bool = False,
        num_ctx: int = 16384
    ) -> Optional[str] | Dict[str, Any]:
        """
        Generate a response from the LLM server.

        Args:
            prompt: The user prompt
            system: Optional system prompt
            model: Model to use (defaults to config model)
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate
            include_usage: If True, return dict with response and token usage
            num_ctx: Context window size (default 16384 to avoid truncation)

        Returns:
            Generated text or None if failed.
            If include_usage=True, returns dict with 'response', 'prompt_tokens', 'completion_tokens', 'total_tokens'
        """
        if not self.config.enabled:
            return None

        if not model:
            return None

        # Use OpenAI adapter for OpenAI-compatible servers
        if self.api_type == "openai":
            return generate_openai(
                host=self.config.host,
                model=model,
                prompt=prompt,
                system=system,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=self.config.timeout,
                include_usage=include_usage
            )

        # Ollama API below
        # Adjust context size for very large models to avoid OOM
        # The 671B model with 16K context needs ~78GB KV cache which can exceed available memory
        actual_ctx = num_ctx
        if "671b" in model.lower():
            # Limit 671B models to 8K context to fit in memory
            # 8K context = ~39GB KV cache instead of 78GB
            actual_ctx = min(num_ctx, 8192)
            if actual_ctx < num_ctx:
                print(f"[generate] Reducing context from {num_ctx} to {actual_ctx} for {model} to avoid OOM")

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": float(temperature),
                "num_ctx": actual_ctx
            }
        }

        if system:
            payload["system"] = system

        if max_tokens:
            payload["options"]["num_predict"] = max_tokens

        try:
            response = requests.post(
                f"{self.config.host}/api/generate",
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                if include_usage:
                    return {
                        "response": data.get("response", ""),
                        "prompt_tokens": data.get("prompt_eval_count", 0),
                        "completion_tokens": data.get("eval_count", 0),
                        "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
                    }
                return data.get("response", "")
            else:
                print(f"Ollama API error: {response.status_code} - {response.text}")
                return None

        except requests.RequestException as e:
            print(f"Ollama request failed: {e}")
            return None

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        num_ctx: int = 16384
    ) -> Optional[str]:
        """
        Send a chat conversation to the LLM server.

        Args:
            messages: List of {"role": "user"|"assistant"|"system", "content": "..."}
            model: Model to use (defaults to config model)
            temperature: Sampling temperature
            num_ctx: Context window size (default 16384)

        Returns:
            Generated response or None if failed
        """
        if not self.config.enabled:
            return None

        if not model:
            return None

        # Use OpenAI adapter for OpenAI-compatible servers
        if self.api_type == "openai":
            return chat_openai(
                host=self.config.host,
                model=model,
                messages=messages,
                temperature=temperature,
                timeout=self.config.timeout
            )

        # Ollama API
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": float(temperature),
                "num_ctx": num_ctx
            }
        }

        try:
            response = requests.post(
                f"{self.config.host}/api/chat",
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("message", {}).get("content", "")
            else:
                print(f"Ollama API error: {response.status_code} - {response.text}")
                return None

        except requests.RequestException as e:
            print(f"Ollama request failed: {e}")
            return None


# =============================================================================
# Analysis Functions
# =============================================================================

class PasswordAnalysisAI:
    """AI-powered password analysis using Ollama."""

    def __init__(self, client: Optional[OllamaClient] = None, model: Optional[str] = None):
        self.client = client or OllamaClient()
        self.model = model

    def generate_executive_summary(
        self,
        stats: Dict[str, Any],
        patterns: Dict[str, Any],
        critical_findings: List[str],
        model: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate an executive summary of the password audit.

        Args:
            stats: Dictionary with total_accounts, cracked_accounts, etc.
            patterns: Dictionary of pattern names to counts
            critical_findings: List of critical finding descriptions

        Returns:
            Executive summary text or None if failed
        """
        # Format patterns for the prompt
        pattern_lines = []
        for name, data in patterns.items():
            if isinstance(data, dict) and "count" in data:
                count = data["count"]
                if count > 0:
                    pattern_lines.append(f"- {name}: {count} passwords")
            elif isinstance(data, int) and data > 0:
                pattern_lines.append(f"- {name}: {data} passwords")

        patterns_text = "\n".join(pattern_lines) if pattern_lines else "No significant patterns detected"

        # Format critical findings
        findings_text = "\n".join(f"- {f}" for f in critical_findings) if critical_findings else "No critical findings"

        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            total_accounts=stats.get("total_accounts", 0),
            cracked_accounts=stats.get("cracked_accounts", 0),
            cracked_percent=stats.get("cracked_percent", 0),
            unique_passwords=stats.get("unique_passwords", 0),
            avg_length=stats.get("avg_length", 0),
            min_length=stats.get("min_length", 0),
            max_length=stats.get("max_length", 0),
            blank_passwords=stats.get("blank_passwords", 0),
            patterns=patterns_text,
            critical_findings=findings_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.7
        )

    def describe_patterns(self, pattern_data: Dict[str, Any], model: Optional[str] = None) -> Optional[str]:
        """
        Generate natural language descriptions of password patterns.

        Args:
            pattern_data: Dictionary of patterns with counts and examples

        Returns:
            Pattern analysis text or None if failed
        """
        # Format pattern data for the prompt
        formatted = json.dumps(pattern_data, indent=2, default=str)

        prompt = PATTERN_DESCRIPTION_PROMPT.format(pattern_data=formatted)

        return self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.5
        )

    def cluster_passwords_semantically(
        self,
        passwords: List[str],
        sample_size: int = 500,
        model: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Categorize passwords by semantic meaning.

        Args:
            passwords: List of passwords to analyze
            sample_size: Max passwords to send (for token limits)

        Returns:
            Dictionary with categories and insights or None if failed
        """
        # Sample if too many passwords
        if len(passwords) > sample_size:
            import random
            passwords = random.sample(passwords, sample_size)

        # Format passwords (one per line)
        passwords_text = "\n".join(passwords)

        prompt = SEMANTIC_CLUSTERING_PROMPT.format(passwords=passwords_text)

        response = self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.3  # Lower temperature for more consistent JSON
        )

        if response:
            # Try to parse JSON from response
            try:
                # Find JSON in response (it might have text before/after)
                start = response.find("{")
                end = response.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(response[start:end])
            except json.JSONDecodeError:
                # Return raw response if JSON parsing fails
                return {"raw_response": response}

        return None

    def recommend_attack_strategy(
        self,
        patterns: Dict[str, Any],
        stats: Dict[str, Any],
        base_words: List[str],
        structures: List[str],
        model: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate attack strategy recommendations for remaining hashes.

        Args:
            patterns: Observed patterns in cracked passwords
            stats: Cracking statistics
            base_words: Most common base words found
            structures: Most common password structures
            model: Model to use for generation

        Returns:
            Attack strategy text or None if failed
        """
        patterns_text = json.dumps(patterns, indent=2, default=str)
        base_words_text = "\n".join(f"- {w}" for w in base_words[:20])
        structures_text = "\n".join(f"- {s}" for s in structures[:20])

        prompt = ATTACK_STRATEGY_PROMPT.format(
            patterns=patterns_text,
            total_hashes=stats.get("total_hashes", 0),
            cracked=stats.get("cracked", 0),
            cracked_percent=stats.get("cracked_percent", 0),
            remaining=stats.get("remaining", 0),
            base_words=base_words_text,
            structures=structures_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.5
        )

    def analyze_password_batch(
        self,
        passwords: List[str],
        analysis_type: str = "general",
        model: Optional[str] = None
    ) -> Optional[str]:
        """
        Generic password batch analysis.

        Args:
            passwords: List of passwords
            analysis_type: Type of analysis ("general", "weakness", "theme")

        Returns:
            Analysis text or None if failed
        """
        prompt_template = BATCH_ANALYSIS_PROMPTS.get(analysis_type, BATCH_ANALYSIS_PROMPTS["general"])
        passwords_text = "\n".join(passwords[:200])  # Limit for token size

        return self.client.generate(
            prompt=prompt_template.format(passwords=passwords_text),
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.6
        )


# =============================================================================
# AI Report Section Analysis
# =============================================================================

class AIReportAnalyzer:
    """Generates AI analysis for report sections."""

    def __init__(self, client: Optional[OllamaClient] = None):
        self.client = client or OllamaClient()

    def get_section_config(self, section_id: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a report section."""
        return AI_REPORT_SECTIONS.get(section_id)

    def get_all_sections(self) -> Dict[str, Any]:
        """Get all section configurations sorted by order."""
        sections = dict(sorted(
            AI_REPORT_SECTIONS.items(),
            key=lambda x: x[1].get("order", 99)
        ))
        return sections

    def analyze_weak_habits(
        self,
        cracked_passwords: str,
        account_passwords: str,
        password_reuse: str,
        length_distribution: str,
        org_context: str,
        total_accounts: int,
        cracked_count: int,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Analyze weak password habits using raw password data.

        This method sends raw password data to the LLM for independent pattern
        discovery, rather than relying on pre-processed categories.

        Args:
            cracked_passwords: All cracked passwords as formatted string
            account_passwords: Account:password pairs for context
            password_reuse: Password reuse details
            length_distribution: Password length distribution stats
            org_context: Organizational context (domains, account types)
            total_accounts: Total number of accounts analyzed
            cracked_count: Number of passwords cracked
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting (defaults to section recommendation)
        """
        config = self.get_section_config("weak-habits")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = WEAK_HABITS_PROMPT.format(
            cracked_passwords=cracked_passwords,
            account_passwords=account_passwords,
            password_reuse=password_reuse,
            length_distribution=length_distribution,
            org_context=org_context,
            total_accounts=total_accounts,
            cracked_count=cracked_count
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def analyze_company_intel(
        self,
        cracked_passwords: str,
        account_names: str,
        org_context: str,
        total_accounts: int,
        cracked_count: int,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Analyze passwords and account names to infer company information.

        This method sends raw data to the LLM for independent discovery of
        company-identifying information like company name, industry, location.

        Args:
            cracked_passwords: All cracked passwords as formatted string
            account_names: All account names grouped by domain
            org_context: Organizational context (domains, account types)
            total_accounts: Total number of accounts analyzed
            cracked_count: Number of passwords cracked
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting (defaults to section recommendation)
        """
        config = self.get_section_config("company-intel")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = COMPANY_INTEL_PROMPT.format(
            cracked_passwords=cracked_passwords,
            account_names=account_names,
            org_context=org_context,
            total_accounts=total_accounts,
            cracked_count=cracked_count
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def analyze_user_behavior(
        self,
        cracked_passwords: str,
        account_passwords: str,
        password_reuse: str,
        length_distribution: str,
        org_context: str,
        total_accounts: int,
        cracked_count: int,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Analyze user psychology and behavior patterns from raw password data.

        This method sends raw password data to the LLM for independent behavioral
        analysis, rather than relying on pre-processed categories.

        Args:
            cracked_passwords: All cracked passwords as formatted string
            account_passwords: Account:password pairs for context
            password_reuse: Password reuse details
            length_distribution: Password length distribution stats
            org_context: Organizational context (domains, account types)
            total_accounts: Total number of accounts analyzed
            cracked_count: Number of passwords cracked
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting (defaults to section recommendation)
        """
        config = self.get_section_config("user-behavior")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = USER_BEHAVIOR_PROMPT.format(
            cracked_passwords=cracked_passwords,
            account_passwords=account_passwords,
            password_reuse=password_reuse,
            length_distribution=length_distribution,
            org_context=org_context,
            total_accounts=total_accounts,
            cracked_count=cracked_count
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def analyze_risk(
        self,
        stats: Dict[str, Any],
        policy_failures: Dict[str, int],
        critical_findings: List[str],
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generate risk assessment.

        Args:
            stats: Password audit statistics
            policy_failures: Counts of policy failures by type
            critical_findings: List of critical findings
            model: Model to use
            temperature: Temperature setting
        """
        config = self.get_section_config("risk-assessment")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        stats_text = "\n".join(f"- {k}: {v}" for k, v in stats.items())
        failures_text = "\n".join(f"- {policy}: {count} accounts" for policy, count in policy_failures.items())
        findings_text = "\n".join(f"- {f}" for f in critical_findings) if critical_findings else "None identified"

        prompt = RISK_ASSESSMENT_PROMPT.format(
            stats=stats_text,
            policy_failures=failures_text,
            critical_findings=findings_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def generate_recommendations(
        self,
        key_findings: List[str],
        current_policy: Dict[str, Any],
        worst_practices: List[str],
        audit_stats: str = "",
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generate security recommendations.

        Args:
            key_findings: Summary of key findings
            current_policy: Current password policy settings
            worst_practices: Worst password practices observed
            audit_stats: Audit statistics summary
            model: Model to use
            temperature: Temperature setting
        """
        config = self.get_section_config("recommendations")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        findings_text = "\n".join(f"- {f}" for f in key_findings)
        policy_text = "\n".join(f"- {k}: {v}" for k, v in current_policy.items())
        practices_text = "\n".join(f"- {p}" for p in worst_practices)

        prompt = RECOMMENDATIONS_PROMPT.format(
            audit_stats=audit_stats,
            key_findings=findings_text,
            current_policy=policy_text,
            worst_practices=practices_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def generate_full_report(
        self,
        audit_stats: str,
        org_context: str,
        weak_habits_analysis: str,
        company_intel_analysis: str,
        user_behavior_analysis: str,
        risk_assessment_analysis: str,
        recommendations_analysis: str,
        raw_data_summary: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generate a comprehensive security assessment report.

        This method synthesizes all prior AI analyses into a cohesive,
        board-ready report. It should be called after all other sections
        have been generated.

        Args:
            audit_stats: Complete cracking statistics
            org_context: Organizational context
            weak_habits_analysis: Output from weak-habits section
            company_intel_analysis: Output from company-intel section
            user_behavior_analysis: Output from user-behavior section
            risk_assessment_analysis: Output from risk-assessment section
            recommendations_analysis: Output from recommendations section
            raw_data_summary: Summary of raw JSON data
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting
        """
        config = self.get_section_config("full-report")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = FULL_REPORT_PROMPT.format(
            audit_stats=audit_stats,
            org_context=org_context,
            weak_habits_analysis=weak_habits_analysis or "[Not yet generated]",
            company_intel_analysis=company_intel_analysis or "[Not yet generated]",
            user_behavior_analysis=user_behavior_analysis or "[Not yet generated]",
            risk_assessment_analysis=risk_assessment_analysis or "[Not yet generated]",
            recommendations_analysis=recommendations_analysis or "[Not yet generated]",
            raw_data_summary=raw_data_summary
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def generate_section(
        self,
        section_id: str,
        data: Dict[str, Any],
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generic method to generate any section by ID.

        Args:
            section_id: The section identifier (e.g., "weak-habits")
            data: Dictionary containing all required data for the prompt
            model: Override model selection
            temperature: Override temperature
        """
        config = self.get_section_config(section_id)
        if not config:
            return None

        # Map section IDs to their analysis methods
        section_methods = {
            "weak-habits": lambda: self.analyze_weak_habits(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_passwords=data.get("account_passwords", ""),
                password_reuse=data.get("password_reuse", ""),
                length_distribution=data.get("length_distribution", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0),
                model=model,
                temperature=temperature
            ),
            "company-intel": lambda: self.analyze_company_intel(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_names=data.get("account_names", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0),
                model=model,
                temperature=temperature
            ),
            "user-behavior": lambda: self.analyze_user_behavior(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_passwords=data.get("account_passwords", ""),
                password_reuse=data.get("password_reuse", ""),
                length_distribution=data.get("length_distribution", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0),
                model=model,
                temperature=temperature
            ),
            "risk-assessment": lambda: self.analyze_risk(
                stats=data.get("stats", {}),
                policy_failures=data.get("policy_failures", {}),
                critical_findings=data.get("critical_findings", []),
                model=model,
                temperature=temperature
            ),
            "recommendations": lambda: self.generate_recommendations(
                key_findings=data.get("key_findings", []),
                current_policy=data.get("current_policy", {}),
                worst_practices=data.get("worst_practices", []),
                audit_stats=data.get("audit_stats", ""),
                model=model,
                temperature=temperature
            ),
            "full-report": lambda: self.generate_full_report(
                audit_stats=data.get("audit_stats", ""),
                org_context=data.get("org_context", ""),
                weak_habits_analysis=data.get("weak_habits_analysis", ""),
                company_intel_analysis=data.get("company_intel_analysis", ""),
                user_behavior_analysis=data.get("user_behavior_analysis", ""),
                risk_assessment_analysis=data.get("risk_assessment_analysis", ""),
                recommendations_analysis=data.get("recommendations_analysis", ""),
                raw_data_summary=data.get("raw_data_summary", ""),
                model=model,
                temperature=temperature
            )
        }

        method = section_methods.get(section_id)
        if method:
            return method()
        return None

    def generate_section_with_usage(
        self,
        section_id: str,
        data: Dict[str, Any],
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a section and return response with token usage info.

        Returns dict with:
        - response: The generated analysis text
        - prompt_tokens: Number of tokens in the prompt
        - completion_tokens: Number of tokens in the response
        - total_tokens: Total tokens used
        """
        from app.ollama_prompts import (
            SYSTEM_PROMPT, WEAK_HABITS_PROMPT, COMPANY_INTEL_PROMPT,
            USER_BEHAVIOR_PROMPT, RECOMMENDATIONS_PROMPT
        )

        config = self.get_section_config(section_id)
        if not config:
            return None

        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        # Build the prompt based on section
        prompt = None
        if section_id == "weak-habits":
            prompt = WEAK_HABITS_PROMPT.format(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_passwords=data.get("account_passwords", ""),
                password_reuse=data.get("password_reuse", ""),
                length_distribution=data.get("length_distribution", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0)
            )
        elif section_id == "company-intel":
            prompt = COMPANY_INTEL_PROMPT.format(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_names=data.get("account_names", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0)
            )
        elif section_id == "user-behavior":
            prompt = USER_BEHAVIOR_PROMPT.format(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_passwords=data.get("account_passwords", ""),
                password_reuse=data.get("password_reuse", ""),
                length_distribution=data.get("length_distribution", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0)
            )
        elif section_id == "recommendations":
            prompt = RECOMMENDATIONS_PROMPT.format(
                audit_stats=data.get("audit_stats", ""),
                key_findings=data.get("key_findings", []),
                current_policy=data.get("current_policy", {}),
                worst_practices=data.get("worst_practices", [])
            )
        else:
            # Fallback to regular generation without usage info
            result = self.generate_section(section_id, data, model, temperature)
            if result:
                return {"response": result, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            return None

        if prompt:
            return self.client.generate(
                prompt=prompt,
                model=model,
                system=SYSTEM_PROMPT,
                temperature=temperature,
                include_usage=True
            )
        return None


def get_ai_report_sections() -> Dict[str, Any]:
    """Get all AI report section configurations."""
    return AI_REPORT_SECTIONS


# =============================================================================
# AI Report Data Loader
# =============================================================================

class AIReportDataLoader:
    """
    Loads and transforms analysis data for AI report sections.

    Handles loading data from:
    - JSON files in /data directory
    - Flask session
    - Derived computations from other data
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self._cache: Dict[str, Any] = {}

    def _load_json_file(self, filename: str) -> Any:
        """Load a JSON file from the data directory."""
        if filename in self._cache:
            return self._cache[filename]

        filepath = os.path.join(self.data_dir, f"{filename}.json")
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                self._cache[filename] = data
                return data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading {filepath}: {e}")
            return None

    def _derive_password_samples(self, limit: int = 200) -> List[str]:
        """Extract password samples from top_passwords and account_data."""
        samples = []

        # Get from top passwords
        top_pw = self._load_json_file("pw_top_passwords")
        if top_pw and isinstance(top_pw, dict):
            samples.extend([pw for pw in top_pw.keys() if pw and pw != "{blank}"])

        # If we need more, get from account_data
        if len(samples) < limit:
            account_data = self._load_json_file("account_data")
            if account_data and isinstance(account_data, dict):
                for account in account_data.values():
                    pw = account.get("cracked_pw")
                    if pw and pw not in samples:
                        samples.append(pw)
                    if len(samples) >= limit:
                        break

        return samples[:limit]

    def _derive_company_terms(self) -> List[str]:
        """Extract company-specific terms from bad practices."""
        bad_practices = self._load_json_file("pw_bad_practices")
        if not bad_practices:
            return []

        company_terms_data = bad_practices.get("Company Terms", {})
        if isinstance(company_terms_data, dict):
            examples = company_terms_data.get("examples", {})
            return list(examples.keys()) if isinstance(examples, dict) else []
        return []

    # -------------------------------------------------------------------------
    # New derive functions for raw password analysis (Weak Habits section)
    # -------------------------------------------------------------------------

    # Sampling thresholds - if dataset exceeds these, switch to sampling mode
    SAMPLING_THRESHOLD_PASSWORDS = 2000  # Max unique passwords before sampling
    SAMPLING_THRESHOLD_ACCOUNTS = 2000   # Max account pairs before sampling

    def _derive_all_cracked_passwords(self) -> str:
        """
        Get all cracked passwords as a formatted string for LLM analysis.
        Returns unique passwords with their frequency counts.

        If dataset exceeds SAMPLING_THRESHOLD_PASSWORDS, uses intelligent sampling:
        - All passwords with frequency > 1 (reused passwords)
        - Top N most common passwords
        - Random sample of unique passwords
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No password data available"

        # Count password frequencies
        password_counts: Dict[str, int] = {}
        for account in account_data.values():
            pw = account.get("cracked_pw")
            if pw:
                password_counts[pw] = password_counts.get(pw, 0) + 1

        if not password_counts:
            return "No cracked passwords found"

        total_unique = len(password_counts)
        total_cracked = sum(password_counts.values())

        # Sort by frequency (most common first), then alphabetically
        sorted_passwords = sorted(
            password_counts.items(),
            key=lambda x: (-x[1], x[0])
        )

        # Check if sampling is needed
        sampling_used = False
        sampling_note = ""

        if total_unique > self.SAMPLING_THRESHOLD_PASSWORDS:
            sampling_used = True
            import random

            # Strategy: Keep all reused passwords + sample of unique passwords
            reused = [(pw, count) for pw, count in sorted_passwords if count > 1]
            unique = [(pw, count) for pw, count in sorted_passwords if count == 1]

            # Calculate how many unique passwords we can include
            remaining_slots = self.SAMPLING_THRESHOLD_PASSWORDS - len(reused)

            if remaining_slots > 0 and unique:
                # Random sample from unique passwords
                sampled_unique = random.sample(unique, min(remaining_slots, len(unique)))
                sorted_passwords = reused + sampled_unique
            else:
                sorted_passwords = reused[:self.SAMPLING_THRESHOLD_PASSWORDS]

            sampling_note = f"""⚠️ SAMPLING ACTIVE: Dataset contains {total_unique:,} unique passwords ({total_cracked:,} total cracked).
Analysis includes: {len(reused)} reused passwords + {len(sorted_passwords) - len(reused)} sampled unique passwords = {len(sorted_passwords)} total.
Statistics remain accurate; pattern analysis based on representative sample.

"""

        # Format as list with counts for passwords used more than once
        lines = []
        if sampling_note:
            lines.append(sampling_note)

        for pw, count in sorted_passwords:
            if count > 1:
                lines.append(f"{pw} (x{count})")
            else:
                lines.append(pw)

        return "\n".join(lines)

    def _derive_account_password_pairs(self) -> str:
        """
        Get account:password pairs to show username-password relationships.

        If dataset exceeds SAMPLING_THRESHOLD_ACCOUNTS, uses intelligent sampling:
        - Accounts with reused passwords (important for security analysis)
        - Random sample of remaining accounts
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No account data available"

        # First, identify password reuse
        password_to_accounts: Dict[str, List[str]] = {}
        all_pairs = []

        for username, data in account_data.items():
            pw = data.get("cracked_pw")
            if pw:
                simple_name = username.split("\\")[-1] if "\\" in username else username
                all_pairs.append((simple_name, pw))
                if pw not in password_to_accounts:
                    password_to_accounts[pw] = []
                password_to_accounts[pw].append(simple_name)

        if not all_pairs:
            return "No cracked account-password pairs found"

        total_pairs = len(all_pairs)
        sampling_note = ""

        if total_pairs > self.SAMPLING_THRESHOLD_ACCOUNTS:
            import random

            # Identify accounts with reused passwords (security priority)
            reused_passwords = {pw for pw, accounts in password_to_accounts.items() if len(accounts) > 1}
            reused_pairs = [(name, pw) for name, pw in all_pairs if pw in reused_passwords]
            unique_pairs = [(name, pw) for name, pw in all_pairs if pw not in reused_passwords]

            # Calculate remaining slots for unique pairs
            remaining_slots = self.SAMPLING_THRESHOLD_ACCOUNTS - len(reused_pairs)

            if remaining_slots > 0 and unique_pairs:
                sampled_unique = random.sample(unique_pairs, min(remaining_slots, len(unique_pairs)))
                all_pairs = reused_pairs + sampled_unique
            else:
                all_pairs = reused_pairs[:self.SAMPLING_THRESHOLD_ACCOUNTS]

            sampling_note = f"""⚠️ SAMPLING ACTIVE: Dataset contains {total_pairs:,} account-password pairs.
Analysis includes: {len(reused_pairs)} accounts with reused passwords + {len(all_pairs) - len(reused_pairs)} sampled unique accounts = {len(all_pairs)} total.
Username-password relationship analysis based on representative sample.

"""

        lines = []
        if sampling_note:
            lines.append(sampling_note)

        for name, pw in all_pairs:
            lines.append(f"{name}: {pw}")

        return "\n".join(lines)

    def _derive_all_account_names(self) -> str:
        """
        Get all account names for company intelligence analysis.
        Includes full usernames with domains to help identify company.

        If dataset exceeds SAMPLING_THRESHOLD_ACCOUNTS, uses intelligent sampling:
        - Preserves domain distribution proportionally
        - Prioritizes accounts with cracked passwords
        - Adds clear warning note to output
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No account data available"

        # Group accounts by domain for easier analysis
        domains: Dict[str, List[str]] = {}
        no_domain: List[str] = []

        # Also track which accounts have cracked passwords (higher priority for sampling)
        cracked_accounts = set()

        for username, data in account_data.items():
            if data.get("cracked_pw"):
                cracked_accounts.add(username)

            if "\\" in username:
                domain, name = username.split("\\", 1)
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append(name)
            else:
                no_domain.append(username)

        total_accounts = len(account_data)
        lines = []
        sampling_note = ""

        # Check if sampling is needed
        if total_accounts > self.SAMPLING_THRESHOLD_ACCOUNTS:
            import random
            random.seed(42)  # Reproducible sampling

            sampling_note = f"""⚠️ SAMPLING ACTIVE: Dataset contains {total_accounts:,} accounts, showing representative sample of {self.SAMPLING_THRESHOLD_ACCOUNTS:,}.
Sample preserves domain distribution and prioritizes accounts with compromised passwords.
Patterns and naming conventions shown are representative of the full dataset.

"""
            # Calculate proportional samples per domain
            sampled_domains: Dict[str, List[str]] = {}
            sampled_no_domain: List[str] = []

            # Calculate domain proportions
            domain_sizes = {d: len(accts) for d, accts in domains.items()}
            no_domain_size = len(no_domain)

            # Allocate slots proportionally
            remaining_slots = self.SAMPLING_THRESHOLD_ACCOUNTS

            for domain, accounts in sorted(domains.items(), key=lambda x: -len(x[1])):
                # Proportional allocation
                proportion = len(accounts) / total_accounts
                slots_for_domain = max(1, int(proportion * self.SAMPLING_THRESHOLD_ACCOUNTS))
                slots_for_domain = min(slots_for_domain, remaining_slots, len(accounts))

                if slots_for_domain > 0:
                    # Prioritize accounts with cracked passwords
                    domain_cracked = [a for a in accounts if f"{domain}\\{a}" in cracked_accounts]
                    domain_uncracked = [a for a in accounts if f"{domain}\\{a}" not in cracked_accounts]

                    sampled = []
                    # Take cracked accounts first
                    if domain_cracked:
                        sampled.extend(domain_cracked[:slots_for_domain])

                    # Fill remaining with random uncracked
                    if len(sampled) < slots_for_domain and domain_uncracked:
                        remaining = slots_for_domain - len(sampled)
                        random.shuffle(domain_uncracked)
                        sampled.extend(domain_uncracked[:remaining])

                    sampled_domains[domain] = sorted(sampled)
                    remaining_slots -= len(sampled)

                if remaining_slots <= 0:
                    break

            # Handle no-domain accounts with remaining slots
            if remaining_slots > 0 and no_domain:
                slots_for_no_domain = min(remaining_slots, len(no_domain))
                # Prioritize cracked accounts
                nd_cracked = [a for a in no_domain if a in cracked_accounts]
                nd_uncracked = [a for a in no_domain if a not in cracked_accounts]

                sampled = []
                if nd_cracked:
                    sampled.extend(nd_cracked[:slots_for_no_domain])
                if len(sampled) < slots_for_no_domain and nd_uncracked:
                    remaining = slots_for_no_domain - len(sampled)
                    random.shuffle(nd_uncracked)
                    sampled.extend(nd_uncracked[:remaining])

                sampled_no_domain = sorted(sampled)

            domains = sampled_domains
            no_domain = sampled_no_domain

        if sampling_note:
            lines.append(sampling_note)

        # Output by domain
        for domain in sorted(domains.keys()):
            lines.append(f"=== Domain: {domain} ===")
            # Sort accounts alphabetically within domain
            for account in sorted(domains[domain]):
                lines.append(account)
            lines.append("")

        # Output accounts without domain
        if no_domain:
            lines.append("=== No Domain ===")
            for account in sorted(no_domain):
                lines.append(account)

        return "\n".join(lines)

    def _derive_password_reuse_details(self) -> str:
        """
        Get details about passwords shared across multiple accounts.
        """
        reuse_data = self._load_json_file("pw_reuse_table")
        account_data = self._load_json_file("account_data")

        if not reuse_data or not account_data:
            return "No password reuse data available"

        # Build hash-to-password mapping
        hash_to_pw: Dict[str, str] = {}
        for username, data in account_data.items():
            ntlm = data.get("ntlm_hash")
            pw = data.get("cracked_pw")
            if ntlm and pw:
                hash_to_pw[ntlm] = pw

        cracked_reuse = []
        uncracked_reuse = []

        for item in reuse_data:
            if isinstance(item, list) and len(item) >= 3:
                hash_val, count, accounts = item[0], item[1], item[2]
                if count > 1:
                    pw = hash_to_pw.get(hash_val)
                    account_list = ", ".join(accounts[:5])
                    if len(accounts) > 5:
                        account_list += f" (+{len(accounts)-5} more)"

                    if pw:
                        # Password was cracked - show the password
                        cracked_reuse.append((count, f"'{pw}' shared by {count} accounts: {account_list}"))
                    else:
                        # Password not cracked - check for known hashes and show hash info
                        if hash_val == "31d6cfe0d16ae931b73c59d7e0c089c0":
                            cracked_reuse.append((count, f"'{{blank}}' shared by {count} accounts: {account_list}"))
                        else:
                            # Show truncated hash for uncracked shared passwords
                            hash_preview = hash_val[:8] + "..." if len(hash_val) > 8 else hash_val
                            uncracked_reuse.append((count, f"[UNCRACKED HASH: {hash_preview}] shared by {count} accounts: {account_list}"))

        if not cracked_reuse and not uncracked_reuse:
            return "No significant password reuse detected"

        # Sort by count (most reused first) and combine
        cracked_reuse.sort(key=lambda x: x[0], reverse=True)
        uncracked_reuse.sort(key=lambda x: x[0], reverse=True)

        lines = []
        if cracked_reuse:
            lines.append("=== Cracked Password Reuse ===")
            lines.extend([item[1] for item in cracked_reuse[:20]])

        if uncracked_reuse:
            if lines:
                lines.append("")
            lines.append("=== Uncracked Hash Reuse (same unknown password) ===")
            lines.extend([item[1] for item in uncracked_reuse[:10]])

        return "\n".join(lines)

    def _derive_organizational_context(self) -> str:
        """
        Extract organizational context from account data (domains, account types, etc.)
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No organizational context available"

        domains = set()
        account_types = {
            "user": 0,
            "computer": 0,
            "service": 0,
            "admin": 0
        }

        for username in account_data.keys():
            # Extract domain
            if "\\" in username:
                domain = username.split("\\")[0]
                domains.add(domain)

            # Classify account type
            lower_name = username.lower()
            if lower_name.endswith("$"):
                account_types["computer"] += 1
            elif any(x in lower_name for x in ["svc", "service", "sql", "app"]):
                account_types["service"] += 1
            elif any(x in lower_name for x in ["admin", "adm", "root"]):
                account_types["admin"] += 1
            else:
                account_types["user"] += 1

        lines = []
        if domains:
            lines.append(f"Domains detected: {', '.join(sorted(domains))}")

        type_summary = ", ".join(f"{t}: {c}" for t, c in account_types.items() if c > 0)
        if type_summary:
            lines.append(f"Account types: {type_summary}")

        return "\n".join(lines) if lines else "No organizational context detected"

    def _derive_audit_stats_summary(self) -> str:
        """
        Generate a comprehensive audit statistics summary for recommendations.
        Includes cracking stats, password length info, and policy violations.
        """
        lines = []

        # Get cracking stats
        stats = self._parse_stats_table()
        if stats:
            lines.append("Cracking Results:")
            lines.append(f"- Total accounts analyzed: {stats.get('Total Accounts Analyzed', 'N/A')}")
            lines.append(f"- Cracked accounts: {stats.get('Cracked Accounts', 'N/A')} ({stats.get('Percent of Accounts Cracked', 'N/A')})")
            lines.append(f"- Uncracked accounts: {stats.get('Uncracked Accounts', 'N/A')}")
            lines.append(f"- Unique NTLM hashes: {stats.get('Unique NTLM Hashes Analyzed', 'N/A')}")
            lines.append(f"- Average password length: {stats.get('Average Password Length', 'N/A')} characters")
            lines.append(f"- Shortest password: {stats.get('Shortest Cracked Password', 'N/A')} chars")
            lines.append(f"- Longest password: {stats.get('Longest Cracked Password', 'N/A')} chars")
            lines.append("")

        # LM hash info
        lm_hashes = self._load_json_file("pw_lm_hashes")
        if lm_hashes and len(lm_hashes) > 0:
            lines.append(f"Legacy Security Issues:")
            lines.append(f"- Accounts with legacy LM hashes: {len(lm_hashes)}")
            lines.append("")

        # Blank password details with enabled/disabled breakdown
        blank = self._load_json_file("pw_fails_blank")
        if blank and len(blank) > 0:
            enabled_count = sum(1 for acc in blank if isinstance(acc, dict) and acc.get("status") == "Enabled")
            disabled_count = sum(1 for acc in blank if isinstance(acc, dict) and acc.get("status") == "Disabled")
            lines.append(f"Blank Password Accounts: {len(blank)} total")
            lines.append(f"- Enabled (active risk): {enabled_count}")
            lines.append(f"- Disabled (mitigated): {disabled_count}")
            lines.append("")

        # Password reuse summary
        reuse = self._load_json_file("pw_reuse_table")
        if reuse and isinstance(reuse, list):
            high_reuse = [r for r in reuse if isinstance(r, list) and len(r) > 1 and r[1] > 5]
            moderate_reuse = [r for r in reuse if isinstance(r, list) and len(r) > 1 and 2 < r[1] <= 5]
            if high_reuse or moderate_reuse:
                lines.append(f"Password Reuse:")
                if high_reuse:
                    lines.append(f"- Passwords shared by >5 accounts: {len(high_reuse)}")
                if moderate_reuse:
                    lines.append(f"- Passwords shared by 3-5 accounts: {len(moderate_reuse)}")
                lines.append("")

        # Password length distribution summary
        length_dist = self._load_json_file("pw_length_distribution")
        if length_dist and isinstance(length_dist, dict):
            total_cracked = sum(int(v) for v in length_dist.values())
            short_passwords = sum(int(length_dist.get(str(i), 0)) for i in range(0, 8))
            if total_cracked > 0 and short_passwords > 0:
                pct_short = (short_passwords / total_cracked) * 100
                lines.append(f"Password Length Analysis:")
                lines.append(f"- Passwords under 8 characters: {short_passwords} ({pct_short:.1f}%)")
                lines.append("")

        return "\n".join(lines) if lines else "No audit statistics available"

    def _derive_password_length_distribution(self) -> str:
        """
        Get password length distribution as formatted string.
        Shows count of passwords at each length.
        """
        length_dist = self._load_json_file("pw_length_distribution")
        if not length_dist or not isinstance(length_dist, dict):
            return "No password length data available"

        lines = ["Password Length Distribution:"]
        total = sum(int(v) for v in length_dist.values())

        # Sort by length (numeric)
        for length in sorted(length_dist.keys(), key=lambda x: int(x)):
            count = int(length_dist[length])
            if count > 0:
                pct = (count / total * 100) if total > 0 else 0
                lines.append(f"  {length} chars: {count} ({pct:.1f}%)")

        return "\n".join(lines)

    def _derive_total_account_count(self) -> int:
        """Get total number of accounts."""
        account_data = self._load_json_file("account_data")
        return len(account_data) if account_data else 0

    def _derive_cracked_account_count(self) -> int:
        """Get number of accounts with cracked passwords."""
        account_data = self._load_json_file("account_data")
        if not account_data:
            return 0
        return sum(1 for acc in account_data.values() if acc.get("cracked_pw"))

    def _derive_policy_failures(self) -> Dict[str, int]:
        """Compile policy failure counts from multiple JSON files."""
        failures = {}

        # Min length failures
        min_length = self._load_json_file("pw_fails_min_length")
        if min_length:
            failures["Minimum Length"] = len(min_length) if isinstance(min_length, dict) else 0

        # Complexity failures
        complexity = self._load_json_file("pw_fails_complexity")
        if complexity:
            failures["Complexity Requirements"] = len(complexity) if isinstance(complexity, dict) else 0

        # Blank passwords
        blank = self._load_json_file("pw_fails_blank")
        if blank:
            failures["Blank Passwords"] = len(blank) if isinstance(blank, list) else 0

        # Max age failures
        max_age = self._load_json_file("pw_fails_max_age")
        if max_age:
            failures["Password Age"] = len(max_age) if isinstance(max_age, dict) else 0

        # LM hashes
        lm_hashes = self._load_json_file("pw_lm_hashes")
        if lm_hashes:
            failures["Legacy LM Hashes"] = len(lm_hashes) if isinstance(lm_hashes, list) else 0

        return failures

    def _derive_critical_findings(self) -> List[str]:
        """Generate critical findings from analysis data."""
        findings = []

        # Get stats
        stats = self._load_json_file("cracking_stats_table")
        stats_dict = {}
        if stats and isinstance(stats, list):
            for item in stats:
                if isinstance(item, dict):
                    key = item.get("key", "").strip().rstrip(":")
                    stats_dict[key] = item.get("value")

        # Check crack rate
        crack_pct = stats_dict.get("Percent of Accounts Cracked", "0%")
        if isinstance(crack_pct, str):
            crack_pct = crack_pct.replace("%", "")
        try:
            crack_rate = float(crack_pct)
            if crack_rate > 50:
                findings.append(f"CRITICAL: {crack_rate:.0f}% of passwords were cracked")
            elif crack_rate > 30:
                findings.append(f"HIGH: {crack_rate:.0f}% of passwords were cracked")
        except (ValueError, TypeError):
            pass

        # Check blank passwords - include enabled/disabled breakdown
        blank = self._load_json_file("pw_fails_blank")
        if blank and len(blank) > 0:
            # Count enabled vs disabled accounts
            enabled_count = sum(1 for acc in blank if isinstance(acc, dict) and acc.get("status") == "Enabled")
            disabled_count = sum(1 for acc in blank if isinstance(acc, dict) and acc.get("status") == "Disabled")

            if enabled_count > 0:
                findings.append(f"CRITICAL: {enabled_count} ENABLED accounts have blank passwords (immediate risk)")
            if disabled_count > 0:
                # Lower priority if all are disabled
                if enabled_count == 0:
                    findings.append(f"INFO: {disabled_count} disabled accounts have blank passwords (lower risk - already disabled)")
                else:
                    findings.append(f"LOW: {disabled_count} additional disabled accounts have blank passwords")

        # Check LM hashes
        lm_hashes = self._load_json_file("pw_lm_hashes")
        if lm_hashes and len(lm_hashes) > 0:
            findings.append(f"HIGH: {len(lm_hashes)} accounts have legacy LM hashes stored")

        # Check password reuse
        reuse = self._load_json_file("pw_reuse_table")
        if reuse and isinstance(reuse, list):
            high_reuse = [r for r in reuse if isinstance(r, list) and len(r) > 1 and r[1] > 5]
            if high_reuse:
                findings.append(f"HIGH: {len(high_reuse)} passwords are shared by more than 5 accounts")

        # Check bad practices
        bad = self._load_json_file("pw_bad_practices")
        if bad and isinstance(bad, dict):
            total_bad = sum(
                cat.get("count", 0) if isinstance(cat, dict) else 0
                for cat in bad.values()
            )
            if total_bad > 100:
                findings.append(f"MEDIUM: {total_bad} passwords follow known weak patterns")

        return findings

    def _derive_key_findings(self) -> List[str]:
        """Generate key findings for recommendations section."""
        findings = self._derive_critical_findings()

        # Add pattern-based findings
        bad = self._load_json_file("pw_bad_practices")
        if bad and isinstance(bad, dict):
            for category, data in bad.items():
                if isinstance(data, dict) and data.get("count", 0) > 20:
                    findings.append(f"{category}: {data['count']} passwords")

        return findings[:15]  # Limit to top 15 findings

    def _derive_worst_practices(self) -> List[str]:
        """Extract worst password practices with examples."""
        practices = []
        bad = self._load_json_file("pw_bad_practices")

        if bad and isinstance(bad, dict):
            # Sort by count descending
            sorted_cats = sorted(
                bad.items(),
                key=lambda x: x[1].get("count", 0) if isinstance(x[1], dict) else 0,
                reverse=True
            )

            for category, data in sorted_cats[:10]:
                if isinstance(data, dict):
                    count = data.get("count", 0)
                    examples = data.get("examples", {})
                    if isinstance(examples, dict):
                        top_examples = list(examples.keys())[:3]
                        practices.append(f"{category} ({count}): {', '.join(top_examples)}")

        return practices

    def _parse_stats_table(self) -> Dict[str, Any]:
        """Convert cracking_stats_table array to dictionary."""
        stats = self._load_json_file("cracking_stats_table")
        result = {}

        if stats and isinstance(stats, list):
            for item in stats:
                if isinstance(item, dict):
                    key = item.get("key", "").strip().rstrip(": ")
                    result[key] = item.get("value")

        return result

    def _derive_raw_data_summary(self) -> str:
        """
        Generate a summary of all available raw JSON data for the full report appendix.
        """
        lines = []

        # Stats summary
        stats = self._parse_stats_table()
        if stats:
            lines.append("=== Cracking Statistics ===")
            for key, value in stats.items():
                lines.append(f"  {key}: {value}")
            lines.append("")

        # Password length distribution
        account_data = self._load_json_file("account_data")
        if account_data:
            lengths = {}
            for acc in account_data.values():
                pw = acc.get("cracked_pw", "")
                if pw:
                    length = len(pw)
                    lengths[length] = lengths.get(length, 0) + 1

            if lengths:
                lines.append("=== Password Length Distribution ===")
                for length in sorted(lengths.keys()):
                    lines.append(f"  {length} chars: {lengths[length]} passwords")
                lines.append("")

        # Character class analysis
        if account_data:
            char_classes = {
                "lowercase_only": 0,
                "uppercase_only": 0,
                "digits_only": 0,
                "mixed_case": 0,
                "alphanumeric": 0,
                "with_symbols": 0
            }
            for acc in account_data.values():
                pw = acc.get("cracked_pw", "")
                if pw:
                    has_lower = any(c.islower() for c in pw)
                    has_upper = any(c.isupper() for c in pw)
                    has_digit = any(c.isdigit() for c in pw)
                    has_symbol = any(not c.isalnum() for c in pw)

                    if has_symbol:
                        char_classes["with_symbols"] += 1
                    elif has_lower and has_upper and has_digit:
                        char_classes["alphanumeric"] += 1
                    elif has_lower and has_upper:
                        char_classes["mixed_case"] += 1
                    elif has_lower:
                        char_classes["lowercase_only"] += 1
                    elif has_upper:
                        char_classes["uppercase_only"] += 1
                    elif has_digit:
                        char_classes["digits_only"] += 1

            lines.append("=== Character Class Distribution ===")
            for cls, count in char_classes.items():
                if count > 0:
                    lines.append(f"  {cls.replace('_', ' ').title()}: {count}")
            lines.append("")

        # Bad practices summary
        bad = self._load_json_file("pw_bad_practices")
        if bad and isinstance(bad, dict):
            lines.append("=== Pattern Frequency ===")
            sorted_cats = sorted(
                bad.items(),
                key=lambda x: x[1].get("count", 0) if isinstance(x[1], dict) else 0,
                reverse=True
            )
            for cat, data in sorted_cats:
                if isinstance(data, dict):
                    count = data.get("count", 0)
                    if count > 0:
                        lines.append(f"  {cat}: {count}")
            lines.append("")

        # Top reused passwords
        reuse = self._load_json_file("pw_reuse_table")
        if reuse and isinstance(reuse, list):
            high_reuse = [r for r in reuse if isinstance(r, list) and len(r) > 1 and r[1] > 2]
            if high_reuse:
                lines.append(f"=== Password Reuse (>{2} accounts) ===")
                lines.append(f"  {len(high_reuse)} passwords shared across multiple accounts")
                lines.append("")

        # Policy failures summary
        failures = self._derive_policy_failures()
        if failures:
            lines.append("=== Policy Violations ===")
            for policy, count in failures.items():
                lines.append(f"  {policy}: {count}")
            lines.append("")

        return "\n".join(lines) if lines else "No raw data available"

    def load_section_data(
        self,
        section_id: str,
        session_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Load all required data for a specific AI report section.

        Args:
            section_id: The section identifier (e.g., "weak-habits")
            session_data: Optional Flask session data for session-based sources

        Returns:
            Dictionary with all data needed for the section's prompt
        """
        section_config = AI_REPORT_SECTIONS.get(section_id)
        if not section_config:
            return {}

        data_sources = section_config.get("data_sources", {})
        result = {}

        for var_name, source in data_sources.items():
            if source.startswith("file:"):
                filename = source.replace("file:", "")
                data = self._load_json_file(filename)

                # Transform certain file formats for prompt compatibility
                if filename == "pw_substrings" and isinstance(data, list):
                    # Already in correct format
                    result[var_name] = data
                elif filename == "pw_dict_words" and isinstance(data, dict):
                    # Convert to list format for prompts
                    result[var_name] = [
                        {"word": word, "count": count}
                        for word, count in data.items()
                    ]
                elif filename == "cracking_stats_table":
                    # Parse to dictionary format
                    result[var_name] = self._parse_stats_table()
                else:
                    result[var_name] = data

            elif source.startswith("derived:"):
                func_name = source.replace("derived:", "")
                # Original derive functions
                if func_name == "password_samples":
                    result[var_name] = self._derive_password_samples()
                elif func_name == "company_terms":
                    result[var_name] = self._derive_company_terms()
                elif func_name == "policy_failures":
                    result[var_name] = self._derive_policy_failures()
                elif func_name == "critical_findings":
                    result[var_name] = self._derive_critical_findings()
                elif func_name == "key_findings":
                    result[var_name] = self._derive_key_findings()
                elif func_name == "worst_practices":
                    result[var_name] = self._derive_worst_practices()
                # Raw data derive functions for AI analysis
                elif func_name == "all_cracked_passwords":
                    result[var_name] = self._derive_all_cracked_passwords()
                elif func_name == "account_password_pairs":
                    result[var_name] = self._derive_account_password_pairs()
                elif func_name == "all_account_names":
                    result[var_name] = self._derive_all_account_names()
                elif func_name == "password_reuse_details":
                    result[var_name] = self._derive_password_reuse_details()
                elif func_name == "organizational_context":
                    result[var_name] = self._derive_organizational_context()
                elif func_name == "total_account_count":
                    result[var_name] = self._derive_total_account_count()
                elif func_name == "cracked_account_count":
                    result[var_name] = self._derive_cracked_account_count()
                elif func_name == "raw_data_summary":
                    result[var_name] = self._derive_raw_data_summary()
                elif func_name == "audit_stats_summary":
                    result[var_name] = self._derive_audit_stats_summary()
                elif func_name == "password_length_distribution":
                    result[var_name] = self._derive_password_length_distribution()

            elif source.startswith("session:"):
                key = source.replace("session:", "")
                if session_data and key in session_data:
                    result[var_name] = session_data[key]
                else:
                    # Provide sensible defaults for policy
                    if key == "analysis_options":
                        result[var_name] = {
                            "min_length": 12,
                            "complexity": "3 of 4 character types",
                            "max_age": 90
                        }

        return result

    def has_analysis_data(self) -> bool:
        """Check if analysis data files exist."""
        required_files = ["pw_top_passwords", "cracking_stats_table", "account_data"]
        for filename in required_files:
            filepath = os.path.join(self.data_dir, f"{filename}.json")
            if not os.path.exists(filepath):
                return False
        return True

    def get_data_summary(self) -> Dict[str, Any]:
        """Get a summary of available analysis data for the UI."""
        summary = {
            "has_data": self.has_analysis_data(),
            "files_found": [],
            "files_missing": [],
            "stats": {}
        }

        all_files = [
            "account_data", "cracking_stats_table", "pw_top_passwords",
            "pw_substrings", "pw_dict_words", "pw_bad_practices",
            "pw_length_distribution", "pw_fails_min_length",
            "pw_fails_complexity", "pw_fails_blank", "pw_fails_max_age",
            "pw_lm_hashes", "pw_reuse_table"
        ]

        for filename in all_files:
            filepath = os.path.join(self.data_dir, f"{filename}.json")
            if os.path.exists(filepath):
                summary["files_found"].append(filename)
            else:
                summary["files_missing"].append(filename)

        # Get basic stats if available
        if summary["has_data"]:
            stats = self._parse_stats_table()
            summary["stats"] = {
                "total_accounts": stats.get("Total Accounts Analyzed", 0),
                "cracked_accounts": stats.get("Cracked Accounts", 0),
                "crack_percent": stats.get("Percent of Accounts Cracked", "0%")
            }

        return summary


def get_ai_data_loader(data_dir: str = "data") -> AIReportDataLoader:
    """Factory function to create an AIReportDataLoader instance."""
    return AIReportDataLoader(data_dir)


# =============================================================================
# Utility Functions
# =============================================================================

def test_ollama_connection(host: Optional[str] = None, server_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Test connection to LLM server (Ollama or OpenAI-compatible) and return status info.

    Args:
        host: Server URL (uses env var if not provided)
        server_id: Server ID to test (alternative to host)

    Returns:
        Dictionary with connection status, API type, and available models
    """
    config = get_ollama_config(server_id)
    if host:
        config.host = host
        config.enabled = True

    result = {
        "host": config.host,
        "enabled": config.enabled,
        "reachable": False,
        "api_type": "unknown",
        "available_models": [],
        "error": None
    }

    # Detect API type (this also tests reachability)
    detected_type = detect_api_type(config.host, timeout=3.0)

    if detected_type in ("ollama", "openai"):
        result["reachable"] = True
        result["api_type"] = detected_type

        # Get model list using the appropriate API
        if detected_type == "openai":
            models = list_models_openai(config.host)
            result["available_models"] = [m["name"] for m in models]
        else:
            # Ollama API
            try:
                response = requests.get(f"{config.host}/api/tags", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    result["available_models"] = [m["name"] for m in data.get("models", [])]
            except requests.RequestException as e:
                result["error"] = str(e)
    else:
        result["error"] = "Server unreachable or unknown API type"

    return result


def test_all_servers(use_cache: bool = True, force_refresh: bool = False) -> Dict[str, Any]:
    """
    Test connection to all configured Ollama servers concurrently.

    Uses ThreadPoolExecutor to test all servers in parallel, reducing
    total wait time from (5s × num_servers) to ~2s total.

    Results are cached for 90 minutes to avoid repeated slow checks on page loads.

    Args:
        use_cache: If True, return cached results if available and not expired
        force_refresh: If True, ignore cache and always test servers

    Returns:
        Dictionary with status for each server
    """
    global _server_status_cache, _server_status_cache_time

    # Check cache first (unless force_refresh)
    if use_cache and not force_refresh and _server_status_cache:
        cache_age = time.time() - _server_status_cache_time
        if cache_age < SERVER_STATUS_CACHE_TTL:
            # Return cached results with cache metadata
            cached_result = _server_status_cache.copy()
            cached_result["from_cache"] = True
            cached_result["cache_age_seconds"] = int(cache_age)
            return cached_result

    servers = get_ollama_servers()
    results = {
        "servers": [],
        "any_available": False,
        "from_cache": False,
        "cache_age_seconds": 0
    }

    def test_server(server: OllamaServer) -> Dict[str, Any]:
        """Test a single server and return its info."""
        status = test_ollama_connection(host=server.host)
        return {
            "id": server.id,
            "name": server.name,
            "host": server.host,
            "description": server.description,
            "hardware": server.hardware,
            "reachable": status["reachable"],
            "api_type": status.get("api_type", "unknown"),
            "available_models": status["available_models"],
            "error": status.get("error")
        }

    # Test all servers concurrently
    with ThreadPoolExecutor(max_workers=len(servers)) as executor:
        future_to_server = {executor.submit(test_server, server): server for server in servers}

        for future in as_completed(future_to_server):
            server_info = future.result()
            results["servers"].append(server_info)
            if server_info["reachable"]:
                results["any_available"] = True

    # Sort servers by their original order (id-based)
    server_order = {s.id: i for i, s in enumerate(servers)}
    results["servers"].sort(key=lambda x: server_order.get(x["id"], 999))

    # Update cache
    _server_status_cache = {
        "servers": results["servers"],
        "any_available": results["any_available"]
    }
    _server_status_cache_time = time.time()

    return results


def invalidate_server_cache() -> None:
    """Invalidate the server status cache, forcing a refresh on next check."""
    global _server_status_cache, _server_status_cache_time
    _server_status_cache = {}
    _server_status_cache_time = 0


def get_cached_server_status() -> Optional[Dict[str, Any]]:
    """
    Get cached server status without triggering a refresh.

    Returns:
        Cached server status if available and not expired, None otherwise
    """
    if not _server_status_cache:
        return None

    cache_age = time.time() - _server_status_cache_time
    if cache_age >= SERVER_STATUS_CACHE_TTL:
        return None

    result = _server_status_cache.copy()
    result["from_cache"] = True
    result["cache_age_seconds"] = int(cache_age)
    return result


def quick_generate(prompt: str, host: Optional[str] = None) -> Optional[str]:
    """
    Quick one-off generation without full client setup.

    Args:
        prompt: The prompt to send
        host: Ollama server URL

    Returns:
        Generated text or None
    """
    config = get_ollama_config()
    if host:
        config.host = host
        config.enabled = True

    client = OllamaClient(config)
    return client.generate(prompt)


# Popular models from Ollama library - curated list for UI selection
# recommended_for: list of analysis types this model excels at
POPULAR_OLLAMA_MODELS = [
    {
        "name": "llama3.2",
        "description": "Meta's latest Llama model (3B, 1B)",
        "sizes": ["3b", "1b"],
        "recommended_for": ["quick-analysis"],
        "notes": "Fast, good for interactive testing"
    },
    {
        "name": "llama3.1",
        "description": "Meta's Llama 3.1 (8B, 70B, 405B)",
        "sizes": ["8b", "70b", "405b"],
        "recommended_for": ["executive-summary", "pattern-analysis", "report-writing"],
        "notes": "Best balance of quality and speed. 70B recommended for reports."
    },
    {
        "name": "deepseek-r1",
        "description": "DeepSeek reasoning model",
        "sizes": ["7b", "14b", "32b", "70b", "671b"],
        "recommended_for": ["attack-strategy", "semantic-clustering", "technical-analysis"],
        "notes": "Excellent reasoning. Best for complex analysis tasks."
    },
    {
        "name": "qwen2.5",
        "description": "Alibaba's Qwen 2.5",
        "sizes": ["0.5b", "1.5b", "3b", "7b", "14b", "32b", "72b"],
        "recommended_for": ["pattern-analysis", "quick-analysis"],
        "notes": "Good general purpose model"
    },
    {
        "name": "qwen2.5-coder",
        "description": "Qwen 2.5 optimized for code",
        "sizes": ["0.5b", "1.5b", "3b", "7b", "14b", "32b"],
        "recommended_for": ["attack-strategy"],
        "notes": "Good for generating hashcat commands and rules"
    },
    {
        "name": "mistral",
        "description": "Mistral AI 7B model",
        "sizes": ["7b"],
        "recommended_for": ["quick-analysis"],
        "notes": "Fast and efficient for simple tasks"
    },
    {
        "name": "mixtral",
        "description": "Mistral's MoE model",
        "sizes": ["8x7b", "8x22b"],
        "recommended_for": ["executive-summary", "pattern-analysis"],
        "notes": "Good quality with reasonable speed"
    },
    {
        "name": "gemma2",
        "description": "Google's Gemma 2",
        "sizes": ["2b", "9b", "27b"],
        "recommended_for": ["quick-analysis", "pattern-analysis"],
        "notes": "Efficient, good for structured output"
    },
    {
        "name": "phi4",
        "description": "Microsoft Phi-4",
        "sizes": ["14b"],
        "recommended_for": ["pattern-analysis", "semantic-clustering"],
        "notes": "Strong reasoning for its size"
    },
    {
        "name": "codellama",
        "description": "Meta's code-focused Llama",
        "sizes": ["7b", "13b", "34b", "70b"],
        "recommended_for": ["attack-strategy"],
        "notes": "Best for generating attack commands and scripts"
    },
    {
        "name": "llava",
        "description": "Vision-language model",
        "sizes": ["7b", "13b", "34b"],
        "recommended_for": [],
        "notes": "Not recommended for text-only password analysis"
    },
    {
        "name": "nomic-embed-text",
        "description": "Text embedding model",
        "sizes": [],
        "recommended_for": [],
        "notes": "Embedding model - not for text generation"
    },
    {
        "name": "mxbai-embed-large",
        "description": "Mixedbread embedding model",
        "sizes": [],
        "recommended_for": [],
        "notes": "Embedding model - not for text generation"
    },
]


# =============================================================================
# Analysis Presets
# =============================================================================
# Pre-configured settings for different analysis types

ANALYSIS_PRESETS = {
    "executive-summary": {
        "name": "Executive Summary",
        "description": "Generate polished summaries for C-level executives",
        "recommended_models": ["llama3.1:70b", "llama3.1:405b", "gpt-oss:120b", "mixtral:8x22b"],
        "temperature": 0.7,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "EXECUTIVE_SUMMARY_PROMPT",
        "tips": "Use larger models for better prose quality. Lower temperature for consistency."
    },
    "pattern-analysis": {
        "name": "Pattern Analysis",
        "description": "Analyze password patterns and explain security implications",
        "recommended_models": ["llama3.1:70b", "deepseek-r1:70b", "phi4:14b"],
        "temperature": 0.5,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "PATTERN_DESCRIPTION_PROMPT",
        "tips": "Lower temperature helps maintain consistent analysis structure."
    },
    "semantic-clustering": {
        "name": "Semantic Clustering",
        "description": "Categorize passwords by meaning and theme",
        "recommended_models": ["deepseek-r1:70b", "llama3.1:70b", "phi4:14b"],
        "temperature": 0.3,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "SEMANTIC_CLUSTERING_PROMPT",
        "tips": "Low temperature ensures consistent JSON output. DeepSeek excels at categorization."
    },
    "attack-strategy": {
        "name": "Attack Strategy",
        "description": "Generate hashcat commands and attack recommendations",
        "recommended_models": ["deepseek-r1:70b", "codellama:70b", "qwen2.5-coder:32b"],
        "temperature": 0.5,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "ATTACK_STRATEGY_PROMPT",
        "tips": "Reasoning models produce better strategic recommendations."
    },
    "quick-analysis": {
        "name": "Quick Analysis",
        "description": "Fast, interactive password analysis for testing",
        "recommended_models": ["llama3.1:8b", "llama3.2:3b", "mistral:7b", "gemma2:9b"],
        "temperature": 0.6,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": None,
        "tips": "Use smaller models for faster iteration during testing."
    },
    "report-writing": {
        "name": "Report Writing",
        "description": "Generate professional report sections",
        "recommended_models": ["llama3.1:70b", "llama3.1:405b", "gpt-oss:120b"],
        "temperature": 0.6,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": None,
        "tips": "Larger models produce more polished, professional prose."
    },
    "technical-analysis": {
        "name": "Technical Analysis",
        "description": "Deep technical analysis of password weaknesses",
        "recommended_models": ["deepseek-r1:70b", "deepseek-r1:671b", "llama3.1:405b"],
        "temperature": 0.4,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": None,
        "tips": "DeepSeek's reasoning ability excels at technical deep-dives."
    }
}


def get_analysis_presets() -> Dict[str, Any]:
    """Get all analysis preset configurations."""
    return ANALYSIS_PRESETS


def get_preset_for_task(task_type: str) -> Optional[Dict[str, Any]]:
    """Get the preset configuration for a specific task type."""
    return ANALYSIS_PRESETS.get(task_type)


def get_available_library_models() -> List[Dict[str, Any]]:
    """
    Get list of popular models available to pull from Ollama library.

    Returns:
        List of model dictionaries with name, description, and sizes
    """
    return POPULAR_OLLAMA_MODELS


def pull_model(model_name: str, host: Optional[str] = None, server_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Pull (download) a model from Ollama library.

    Note: This only works with Ollama servers. OpenAI-compatible servers (like LM Studio)
    don't support remote model pulling - models must be managed through their own UI.

    Args:
        model_name: Name of the model to pull (e.g., "llama3.1:70b")
        host: Ollama server URL (uses env var if not provided)
        server_id: Server ID to use (overrides host if provided)

    Returns:
        Dictionary with pull status and any error message
    """
    config = get_ollama_config(server_id)
    if host and not server_id:
        config.host = host
        config.enabled = True

    if not config.enabled:
        return {"success": False, "error": "LLM integration is not enabled"}

    result = {
        "success": False,
        "model": model_name,
        "status": "",
        "error": None
    }

    # Check API type - pulling only works with Ollama
    api_type = detect_api_type(config.host)
    if api_type == "openai":
        result["error"] = "Model pulling is not supported for OpenAI-compatible servers (like LM Studio). Please use the server's own interface to download models."
        return result
    elif api_type == "unknown":
        result["error"] = "Server is not reachable"
        return result

    try:
        # Ollama pull API - uses streaming by default
        response = requests.post(
            f"{config.host}/api/pull",
            json={"name": model_name, "stream": False},
            timeout=600  # 10 minutes for large models
        )

        if response.status_code == 200:
            data = response.json()
            result["success"] = True
            result["status"] = data.get("status", "success")
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text}"

    except requests.Timeout:
        result["error"] = "Request timed out - model may still be downloading in background"
    except requests.RequestException as e:
        result["error"] = str(e)

    return result


def delete_model(model_name: str, host: Optional[str] = None, server_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Delete a model from the Ollama server.

    Note: This only works with Ollama servers. OpenAI-compatible servers (like LM Studio)
    don't support remote model deletion - models must be managed through their own UI.

    Args:
        model_name: Name of the model to delete
        host: Ollama server URL (uses env var if not provided)
        server_id: Server ID to use (overrides host if provided)

    Returns:
        Dictionary with deletion status
    """
    config = get_ollama_config(server_id)
    if host and not server_id:
        config.host = host
        config.enabled = True

    if not config.enabled:
        return {"success": False, "error": "LLM integration is not enabled"}

    result = {
        "success": False,
        "model": model_name,
        "error": None
    }

    # Check API type - deletion only works with Ollama
    api_type = detect_api_type(config.host)
    if api_type == "openai":
        result["error"] = "Model deletion is not supported for OpenAI-compatible servers (like LM Studio). Please use the server's own interface to manage models."
        return result
    elif api_type == "unknown":
        result["error"] = "Server is not reachable"
        return result

    try:
        response = requests.delete(
            f"{config.host}/api/delete",
            json={"name": model_name},
            timeout=30
        )

        if response.status_code == 200:
            result["success"] = True
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text}"

    except requests.RequestException as e:
        result["error"] = str(e)

    return result


def get_model_info(model_name: str, host: Optional[str] = None) -> Dict[str, Any]:
    """
    Get detailed information about a model.

    Args:
        model_name: Name of the model
        host: Ollama server URL

    Returns:
        Dictionary with model details or error
    """
    config = get_ollama_config()
    if host:
        config.host = host
        config.enabled = True

    if not config.enabled:
        return {"error": "Ollama integration is not enabled"}

    try:
        response = requests.post(
            f"{config.host}/api/show",
            json={"name": model_name},
            timeout=10
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}"}

    except requests.RequestException as e:
        return {"error": str(e)}


# =============================================================================
# Tier-0 Deterministic Prechecks (Fast validation gate)
# =============================================================================

@dataclass
class Tier0Result:
    """Result of Tier-0 deterministic prechecks."""
    flags_fired: List[Tuple[str, str]] = field(default_factory=list)  # (rule_id, matched_text)
    requires_llm_validation: bool = False
    suggested_model: str = "llama3.1:70b"  # Default to faster model
    extracted_claims: List[dict] = field(default_factory=list)  # For claim extraction
    skip_reason: str = ""


class Tier0Validator:
    """
    Fast deterministic prechecks before expensive LLM validation.

    Rules:
    - If no flags fire → skip Phase 2 entirely OR use fast model
    - If flags fire → route to appropriate model based on complexity
    """

    # Patterns that indicate problems requiring validation
    PROBLEM_PATTERNS = {
        # Masked passwords (should never appear in audit)
        "MASKED_PASSWORD": re.compile(r'[*•]{3,}|password[:\s]+\*+', re.IGNORECASE),

        # Risk Prioritization Framework (should be removed from user-behavior)
        "UNWANTED_SECTION": re.compile(r'Risk\s+Prioritization\s+Framework', re.IGNORECASE),

        # Specific numeric claims that need verification
        "SPECIFIC_PERCENTAGE": re.compile(r'\b(\d{1,2}(?:\.\d+)?%)\b'),
        "SPECIFIC_COUNT": re.compile(r'\b(\d+)\s+(accounts?|users?|passwords?)\b', re.IGNORECASE),

        # Cloud/third-party references in AD-only context
        "CLOUD_TERM": re.compile(r'\b(Azure\s+AD|Entra\s+ID|Okta|Auth0|cloud[-\s]based)\b', re.IGNORECASE),

        # Outdated guidance
        "FORCED_ROTATION": re.compile(r'(rotate|change|reset)\s+(all\s+)?passwords?\s+(every|quarterly|monthly|annually)', re.IGNORECASE),

        # Invented policy language
        "POLICY_LANGUAGE": re.compile(r'(policy\s+requires?|must\s+comply|compliance\s+mandate)', re.IGNORECASE),
    }

    # Section-specific rules
    SECTION_RULES = {
        "weak-habits": ["MASKED_PASSWORD", "SPECIFIC_PERCENTAGE", "SPECIFIC_COUNT"],
        "company-intel": ["MASKED_PASSWORD", "SPECIFIC_PERCENTAGE"],
        "user-behavior": ["MASKED_PASSWORD", "UNWANTED_SECTION", "SPECIFIC_PERCENTAGE", "SPECIFIC_COUNT"],
        "recommendations": ["CLOUD_TERM", "FORCED_ROTATION", "POLICY_LANGUAGE"],
    }

    # Thresholds for routing decisions
    CLAIM_THRESHOLD = 5  # If more than N claims, use heavy model

    def run_prechecks(self, content: str, section_id: str) -> Tier0Result:
        """
        Run fast deterministic checks on Phase 1 content.

        Returns:
            Tier0Result with routing decision and any extracted claims
        """
        result = Tier0Result()

        rules_to_check = self.SECTION_RULES.get(section_id, list(self.PROBLEM_PATTERNS.keys()))

        for rule_id in rules_to_check:
            pattern = self.PROBLEM_PATTERNS.get(rule_id)
            if pattern:
                matches = pattern.findall(content)
                if matches:
                    for match in matches[:3]:  # Limit to first 3 matches per rule
                        match_text = match if isinstance(match, str) else match[0] if match else ""
                        result.flags_fired.append((rule_id, match_text))

        # Determine routing based on flags
        if not result.flags_fired:
            # Clean content - skip LLM validation entirely
            result.requires_llm_validation = False
            result.skip_reason = "No Tier-0 flags fired - content appears clean"
            result.suggested_model = None
        elif self._is_simple_fix(result.flags_fired, section_id):
            # Simple issues - use fast model
            result.requires_llm_validation = True
            result.suggested_model = "llama3.1:70b"
        else:
            # Complex issues - use reasoning model
            result.requires_llm_validation = True
            result.suggested_model = "deepseek-r1:671b"

        # For user-behavior, extract claims for focused validation
        if section_id == "user-behavior" and result.requires_llm_validation:
            result.extracted_claims = self._extract_claims(content)
            # If many claims, definitely need heavy model
            if len(result.extracted_claims) > self.CLAIM_THRESHOLD:
                result.suggested_model = "deepseek-r1:671b"

        return result

    def _is_simple_fix(self, flags: List[Tuple[str, str]], section_id: str) -> bool:
        """Determine if flagged issues are simple (fast model) or complex (reasoning model)."""
        simple_rules = {"MASKED_PASSWORD", "UNWANTED_SECTION"}
        complex_rules = {"CLOUD_TERM", "FORCED_ROTATION", "POLICY_LANGUAGE"}

        flag_types = {f[0] for f in flags}

        # If any complex flags, need reasoning model
        if flag_types & complex_rules:
            return False

        # If only simple flags, fast model is fine
        if flag_types <= simple_rules:
            return True

        # Mixed - check count of numeric claims
        numeric_flags = sum(1 for f in flags if f[0] in {"SPECIFIC_PERCENTAGE", "SPECIFIC_COUNT"})
        return numeric_flags <= 3  # Few numeric claims = simple

    def _extract_claims(self, content: str) -> List[dict]:
        """
        Extract verifiable claims from user-behavior content.

        This creates a focused list for validation instead of validating full prose.
        """
        claims = []

        # Extract numeric claims
        pct_pattern = re.compile(r'([^.]*?\b\d{1,3}(?:\.\d+)?%[^.]*\.)', re.IGNORECASE)
        for match in pct_pattern.findall(content):
            claims.append({"type": "percentage", "text": match.strip()})

        count_pattern = re.compile(r'([^.]*?\b\d+\s+(?:accounts?|users?|passwords?)[^.]*\.)', re.IGNORECASE)
        for match in count_pattern.findall(content):
            if match.strip() not in [c["text"] for c in claims]:  # Avoid duplicates
                claims.append({"type": "count", "text": match.strip()})

        # Extract behavioral assertions
        behavior_pattern = re.compile(r'([^.]*?(?:users?\s+(?:tend|often|typically|commonly)|most\s+users?|many\s+users?)[^.]*\.)', re.IGNORECASE)
        for match in behavior_pattern.findall(content):
            claims.append({"type": "behavioral", "text": match.strip()})

        return claims[:15]  # Limit to top 15 claims


# =============================================================================
# Evidence Pack Builder (for Phase 2 Validation)
# =============================================================================

class EvidencePackBuilder:
    """
    Assembles authoritative evidence packs for AI validation.

    The evidence pack contains the "source of truth" data that the validator
    uses to fact-check AI-generated content.
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self._cache: Dict[str, Any] = {}

    def _load_json_file(self, filename: str) -> Any:
        """Load a JSON file from the data directory."""
        if filename in self._cache:
            return self._cache[filename]

        filepath = os.path.join(self.data_dir, f"{filename}.json")
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                self._cache[filename] = data
                return data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading {filepath}: {e}")
            return None

    def build_evidence_pack(self, section_id: str) -> str:
        """
        Build a structured evidence pack for validation.

        Args:
            section_id: The section being validated (determines which evidence to include)

        Returns:
            Formatted string containing all authoritative data for validation
        """
        phase_config = get_phase_config(section_id)
        evidence_sources = phase_config.get("evidence_sources", [])

        pack_sections = []

        # Always include core statistics
        stats = self._get_core_statistics()
        if stats:
            pack_sections.append(f"### Core Audit Statistics\n{stats}")

        # Section-specific evidence (skip empty files)
        for source in evidence_sources:
            data = self._load_json_file(source)
            if data:
                formatted = self._format_evidence(source, data)
                if formatted:  # Skip if _format_evidence returned empty string
                    pack_sections.append(f"### {source.replace('_', ' ').title()}\n{formatted}")

        # Account status information (critical for mitigated-issue checking)
        status_info = self._get_account_status_summary()
        if status_info:
            pack_sections.append(f"### Account Status Summary\n{status_info}")

        # For weak-habits section, include password whitelist for hallucination checking
        if section_id == "weak-habits":
            whitelist = self._get_password_whitelist()
            if whitelist:
                pack_sections.append(f"### PASSWORD WHITELIST (for validation)\n{whitelist}")

        return "\n\n".join(pack_sections) if pack_sections else "No evidence data available"

    def _get_core_statistics(self) -> str:
        """Get authoritative cracking statistics."""
        stats = self._load_json_file("cracking_stats_table")
        if not stats:
            return ""

        lines = []
        for item in stats:
            if isinstance(item, dict):
                key = item.get("key", "").strip().rstrip(": ")
                value = item.get("value")
                if key and value is not None:
                    lines.append(f"- {key}: {value}")

        return "\n".join(lines) if lines else ""

    def _get_account_status_summary(self) -> str:
        """Get summary of enabled/disabled accounts from various sources."""
        lines = []

        # From pw_fails_blank.json - blank password accounts with status
        blank = self._load_json_file("pw_fails_blank")
        if blank and isinstance(blank, list):
            enabled = sum(1 for acc in blank if isinstance(acc, dict) and acc.get("status") == "Enabled")
            disabled = sum(1 for acc in blank if isinstance(acc, dict) and acc.get("status") == "Disabled")
            total = len(blank)
            lines.append(f"Blank password accounts: {total} total ({enabled} enabled, {disabled} disabled)")

        # LM hash accounts
        lm_hashes = self._load_json_file("pw_lm_hashes")
        if lm_hashes and isinstance(lm_hashes, list):
            lines.append(f"Accounts with legacy LM hashes: {len(lm_hashes)}")

        # Password reuse summary
        reuse = self._load_json_file("pw_reuse_table")
        if reuse and isinstance(reuse, list):
            high_reuse = sum(1 for item in reuse if isinstance(item, list) and len(item) >= 2 and item[1] > 5)
            med_reuse = sum(1 for item in reuse if isinstance(item, list) and len(item) >= 2 and 3 <= item[1] <= 5)
            lines.append(f"Password reuse: {high_reuse} passwords shared by >5 accounts, {med_reuse} shared by 3-5 accounts")

        return "\n".join(lines) if lines else ""

    def _get_password_whitelist(self) -> str:
        """
        Build a definitive list of all valid passwords from the evidence.
        This helps validators identify hallucinated passwords.
        """
        passwords = set()

        # From pw_top_passwords.json (dict: password -> count)
        top_passwords = self._load_json_file("pw_top_passwords")
        if top_passwords and isinstance(top_passwords, dict):
            passwords.update(top_passwords.keys())

        # From pw_bad_practices.json (list of dicts with 'password' key)
        bad_practices = self._load_json_file("pw_bad_practices")
        if bad_practices and isinstance(bad_practices, list):
            for item in bad_practices:
                if isinstance(item, dict) and item.get("password"):
                    passwords.add(item["password"])

        # From pw_reuse_table.json (list of [password, count] pairs)
        reuse_table = self._load_json_file("pw_reuse_table")
        if reuse_table and isinstance(reuse_table, list):
            for item in reuse_table:
                if isinstance(item, list) and len(item) >= 1 and item[0]:
                    passwords.add(item[0])

        # Remove blank/empty entries
        passwords.discard("")
        passwords.discard("{blank}")

        if not passwords:
            return ""

        # Sort for consistency and format as a simple list
        sorted_passwords = sorted(passwords, key=str.lower)
        return "Valid passwords (ONLY use these as examples):\n" + ", ".join(f"`{p}`" for p in sorted_passwords)

    def _format_evidence(self, source: str, data: Any) -> str:
        """Format evidence data for the prompt using compact, token-efficient formatting."""
        # Skip empty data entirely
        if not data:
            return ""

        if isinstance(data, list):
            if len(data) == 0:
                return ""
            # Use compact JSON (no indentation) for lists
            if len(data) > 20:
                # Truncate large lists with summary - show top 20 only
                return f"[{len(data)} items, showing top 20]: " + json.dumps(data[:20], separators=(',', ':'))
            return json.dumps(data, separators=(',', ':'))
        elif isinstance(data, dict):
            if len(data) == 0:
                return ""
            # Use compact JSON for dicts
            if len(data) > 20:
                # Truncate large dicts - show top 20 entries
                truncated = dict(list(data.items())[:20])
                return f"[{len(data)} items, showing top 20]: " + json.dumps(truncated, separators=(',', ':'))
            return json.dumps(data, separators=(',', ':'))
        return str(data)


# =============================================================================
# AI Pipeline Runner
# =============================================================================

class AIPipelineRunner:
    """
    Runs the 3-phase AI analysis pipeline.

    Phase 1: Initial Analysis (section-specific model)
    Phase 2: Validation (with Tier-0 gating for efficiency)
    Phase 3: Formatting (llama3.1:70b for polishing)
    """

    def __init__(self, client: 'OllamaClient' = None, data_dir: str = "data", debug_dir: str = None):
        self.client = client
        self.data_dir = data_dir
        self.evidence_builder = EvidencePackBuilder(data_dir)
        self.data_loader = AIReportDataLoader(data_dir)
        self.tier0_validator = Tier0Validator()
        self.debug_mode = os.getenv("AI_PIPELINE_DEBUG", "false").lower() == "true"
        # Use provided debug_dir (session-specific) or fall back to global data/ai_analysis
        self.debug_dir = debug_dir if debug_dir else os.path.join(data_dir, "ai_analysis")

    def run_pipeline(
        self,
        section_id: str,
        phase1_generator: callable,
        progress_callback: callable = None,
        max_retries: int = 2
    ) -> PipelineResult:
        """
        Run the full 3-phase pipeline for a section.

        Args:
            section_id: Section to process
            phase1_generator: Function that generates Phase 1 content
            progress_callback: Optional callback for progress updates (phase, section, action)
            max_retries: Max Phase 1 retries if validation fails

        Returns:
            PipelineResult with all phase outputs
        """
        import time

        config = get_phase_config(section_id)

        result = PipelineResult(
            section_id=section_id,
            timing={}
        )

        feedback = None

        for attempt in range(max_retries + 1):
            # Phase 1: Initial Analysis
            if progress_callback:
                action = f"Generating {section_id}" + (f" (retry {attempt})" if attempt > 0 else "")
                progress_callback("phase1", section_id, action)

            start = time.time()

            try:
                # Call the provided generator function
                phase1_result = phase1_generator(feedback=feedback)
                result.phase1_raw = phase1_result
                result.timing["phase1"] = time.time() - start
            except Exception as e:
                result.error = f"Phase 1 failed: {str(e)}"
                return result

            if not phase1_result:
                result.error = "Phase 1 failed to generate content"
                return result

            # Save Phase 1 output (debug mode)
            if self.debug_mode:
                self._save_debug_output(section_id, "phase1_raw", phase1_result, attempt)

            # Phase 2: Validation (with Tier-0 gating)
            phase2_config = config.get("phase2", {})
            if phase2_config.get("enabled", True):
                # Run Tier-0 prechecks first (fast, deterministic)
                tier0_start = time.time()
                tier0_result = self.tier0_validator.run_prechecks(phase1_result, section_id)
                tier0_time = time.time() - tier0_start

                if self.debug_mode:
                    self._save_debug_output(section_id, "tier0_precheck", {
                        "flags_fired": tier0_result.flags_fired,
                        "requires_llm": tier0_result.requires_llm_validation,
                        "suggested_model": tier0_result.suggested_model,
                        "skip_reason": tier0_result.skip_reason,
                        "extracted_claims_count": len(tier0_result.extracted_claims),
                        "precheck_time_ms": int(tier0_time * 1000)
                    }, attempt)

                if not tier0_result.requires_llm_validation:
                    # Clean content - skip LLM validation entirely
                    if progress_callback:
                        progress_callback("phase2", section_id, f"Skipping validation (clean)")

                    result.phase2_validated = ValidationResult(
                        issues=[],
                        corrected_content=phase1_result,
                        confidence=0.95,
                        needs_human_review=False,
                        validation_stats={
                            "tier0_skipped": True,
                            "skip_reason": tier0_result.skip_reason,
                            "precheck_time_ms": int(tier0_time * 1000)
                        }
                    )
                    result.timing["phase2"] = tier0_time
                else:
                    # Tier-0 flagged issues - run LLM validation
                    if progress_callback:
                        model_label = "fast" if tier0_result.suggested_model == "llama3.1:70b" else "deep"
                        progress_callback("phase2", section_id, f"Validating {section_id} ({model_label})")

                    start = time.time()

                    # Use Tier-0's model suggestion, or fall back to config
                    validation_model = tier0_result.suggested_model or phase2_config.get("model", "deepseek-r1:671b")

                    # For user-behavior with extracted claims, use focused validation
                    if section_id == "user-behavior" and tier0_result.extracted_claims:
                        validation = self._run_claim_validation(
                            section_id=section_id,
                            phase1_content=phase1_result,
                            claims=tier0_result.extracted_claims,
                            model=validation_model,
                            temperature=phase2_config.get("temperature", 0.2)
                        )
                    else:
                        validation = self._run_validation_phase(
                            section_id=section_id,
                            phase1_content=phase1_result,
                            model=validation_model,
                            temperature=phase2_config.get("temperature", 0.2)
                        )

                    # Add Tier-0 context to validation stats
                    validation.validation_stats["tier0_flags"] = tier0_result.flags_fired
                    validation.validation_stats["tier0_model_suggestion"] = tier0_result.suggested_model
                    validation.validation_stats["actual_model_used"] = validation_model

                    result.phase2_validated = validation
                    result.timing["phase2"] = time.time() - start + tier0_time

                    if self.debug_mode:
                        self._save_debug_output(section_id, "phase2_validated", validation, attempt)

                    # Check if retry needed
                    critical_issues = [i for i in validation.issues if i.get("severity") == "critical"]
                    if critical_issues and attempt < max_retries:
                        # Build feedback for retry
                        feedback = self._build_retry_feedback(validation.issues)
                        result.retry_count = attempt + 1
                        continue

                    # Check if human review needed
                    if validation.needs_human_review or validation.confidence < 0.7:
                        result.needs_human_review = True
            else:
                # Skip validation, use Phase 1 output directly
                result.phase2_validated = ValidationResult(
                    issues=[],
                    corrected_content=phase1_result,
                    confidence=1.0,
                    needs_human_review=False,
                    validation_stats={"skipped": True}
                )

            # Phase 3: Formatting (if enabled)
            phase3_config = config.get("phase3", {})
            if phase3_config.get("enabled", True):
                if progress_callback:
                    progress_callback("phase3", section_id, f"Formatting {section_id}")

                start = time.time()
                content_to_format = result.phase2_validated.corrected_content
                result.phase3_final = self._run_formatting_phase(
                    validated_content=content_to_format,
                    section_id=section_id,
                    model=phase3_config.get("model", "llama3.1:70b"),
                    temperature=phase3_config.get("temperature", 0.15)
                )
                result.timing["phase3"] = time.time() - start

                if self.debug_mode:
                    self._save_debug_output(section_id, "phase3_final", result.phase3_final, attempt)
            else:
                # Skip formatting, use validated content
                result.phase3_final = result.phase2_validated.corrected_content

            break  # Success, exit retry loop

        return result

    def _run_validation_phase(
        self,
        section_id: str,
        phase1_content: str,
        model: str = "deepseek-r1:671b",
        temperature: float = 0.2
    ) -> ValidationResult:
        """
        Phase 2: Validate content against evidence.

        Returns ValidationResult with issues, corrected content, and confidence.
        """
        # Build evidence pack
        evidence_pack = self.evidence_builder.build_evidence_pack(section_id)

        # Get section-specific validation prompt
        validation_prompt_template = get_validation_prompt(section_id)
        prompt = validation_prompt_template.format(
            evidence_pack=evidence_pack,
            content_to_validate=phase1_content
        )

        # Call model with token tracking
        result_data = self.client.generate(
            prompt=prompt,
            model=model,
            system="You are a precise fact-checking assistant. Return only valid JSON.",
            temperature=temperature,
            include_usage=True
        )

        # Extract response and token counts
        if isinstance(result_data, dict):
            response = result_data.get("response", "")
            prompt_tokens = result_data.get("prompt_tokens", 0)
            completion_tokens = result_data.get("completion_tokens", 0)
            total_tokens = result_data.get("total_tokens", 0)
        else:
            response = result_data
            prompt_tokens = completion_tokens = total_tokens = 0

        if not response:
            return ValidationResult(
                issues=[{"type": "error", "description": "Validation API call failed", "severity": "critical"}],
                corrected_content=phase1_content,
                confidence=0.3,
                needs_human_review=True,
                validation_stats={"error": "API call failed"},
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens
            )

        # Parse JSON response
        try:
            # Strip thinking tags from deepseek-r1 models
            json_str = response
            if "<think>" in json_str and "</think>" in json_str:
                # Remove thinking section - find the last </think> and take content after
                think_end = json_str.rfind("</think>")
                if think_end != -1:
                    json_str = json_str[think_end + 8:].strip()

            # Find JSON in response (handle markdown code blocks)
            if "```json" in json_str:
                start = json_str.find("```json") + 7
                end = json_str.find("```", start)
                if end > start:
                    json_str = json_str[start:end].strip()
            elif "```" in json_str:
                start = json_str.find("```") + 3
                end = json_str.find("```", start)
                if end > start:
                    json_str = json_str[start:end].strip()
            else:
                # Find raw JSON object - look for outermost braces
                start = json_str.find("{")
                end = json_str.rfind("}") + 1
                if start != -1 and end > start:
                    json_str = json_str[start:end]

            # Clean up common JSON issues from LLM output
            # Remove trailing commas before closing braces/brackets
            import re
            json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)

            result = json.loads(json_str)

            # Handle case where model returns a list instead of dict
            if isinstance(result, list):
                # Model returned array - treat as list of issues, use original content
                return ValidationResult(
                    issues=result if all(isinstance(i, dict) for i in result) else [],
                    corrected_content=phase1_content,
                    confidence=0.6,
                    needs_human_review=True,
                    validation_stats={"note": "Model returned list format instead of expected object"},
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens
                )

            # Handle find/replace format (new optimized output)
            issues = result.get("issues", [])
            corrected_content = result.get("corrected_content")

            # If no corrected_content provided, apply find/replace patches
            if corrected_content is None and issues:
                corrected_content = phase1_content
                for issue in issues:
                    find_text = issue.get("find") or issue.get("source_quote") or issue.get("original")
                    replace_text = issue.get("replace") or issue.get("correction", "")
                    if find_text and find_text in corrected_content:
                        if replace_text == "remove" or replace_text == "":
                            corrected_content = corrected_content.replace(find_text, "")
                        else:
                            corrected_content = corrected_content.replace(find_text, replace_text)
            elif corrected_content is None:
                corrected_content = phase1_content

            return ValidationResult(
                issues=issues,
                corrected_content=corrected_content,
                confidence=result.get("confidence", 0.5),
                needs_human_review=result.get("needs_human_review", False),
                validation_stats=result.get("validation_summary", {}),
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens
            )
        except json.JSONDecodeError as e:
            # Fallback: return original content with low confidence
            return ValidationResult(
                issues=[{"type": "parse_error", "description": f"Failed to parse validation response: {str(e)}", "severity": "medium"}],
                corrected_content=phase1_content,
                confidence=0.4,
                needs_human_review=True,
                validation_stats={"error": "JSON parse failed", "raw_response_length": len(response)},
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens
            )

    def _run_claim_validation(
        self,
        section_id: str,
        phase1_content: str,
        claims: List[dict],
        model: str = "llama3.1:70b",
        temperature: float = 0.2
    ) -> ValidationResult:
        """
        Focused validation for extracted claims (used for user-behavior).

        Instead of validating full prose, validates a list of specific claims.
        This dramatically reduces prompt size and model reasoning load.
        """
        # Build compact evidence pack
        evidence_pack = self.evidence_builder.build_evidence_pack(section_id)

        # Format claims as a simple numbered list
        claims_text = "\n".join([
            f"{i+1}. [{c['type'].upper()}] {c['text']}"
            for i, c in enumerate(claims)
        ])

        # Compact validation prompt for claims
        prompt = f"""Validate these specific claims from a security audit against the evidence.

## EVIDENCE
{evidence_pack}

## CLAIMS TO VALIDATE
{claims_text}

## RULES
- For each claim, check if the numbers/percentages match evidence (allow ~20% variance)
- Mark behavioral claims as OK if they're reasonable interpretations
- Do NOT validate prose style, only factual accuracy

## OUTPUT (JSON only)
{{"issues":[{{"claim_num":1,"find":"text to fix","replace":"corrected text"}}],"confidence":0.9}}

If all claims are accurate: {{"issues":[],"confidence":0.95}}"""

        result_data = self.client.generate(
            prompt=prompt,
            model=model,
            system="You are a fact-checker. Return only JSON.",
            temperature=temperature,
            include_usage=True
        )

        # Extract response and token counts
        if isinstance(result_data, dict):
            response = result_data.get("response", "")
            prompt_tokens = result_data.get("prompt_tokens", 0)
            completion_tokens = result_data.get("completion_tokens", 0)
            total_tokens = result_data.get("total_tokens", 0)
        else:
            response = result_data
            prompt_tokens = completion_tokens = total_tokens = 0

        if not response:
            return ValidationResult(
                issues=[],
                corrected_content=phase1_content,
                confidence=0.7,
                needs_human_review=False,
                validation_stats={"claim_validation": True, "error": "API call failed"},
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens
            )

        # Parse response
        try:
            json_str = response
            # Strip thinking tags
            if "<think>" in json_str and "</think>" in json_str:
                think_end = json_str.rfind("</think>")
                if think_end != -1:
                    json_str = json_str[think_end + 8:].strip()

            # Extract JSON (handle both object and array formats)
            if "```json" in json_str:
                start = json_str.find("```json") + 7
                end = json_str.find("```", start)
                if end > start:
                    json_str = json_str[start:end].strip()
            else:
                # Find first { or [ (whichever comes first)
                obj_start = json_str.find("{")
                arr_start = json_str.find("[")
                if arr_start != -1 and (obj_start == -1 or arr_start < obj_start):
                    # Array format
                    start = arr_start
                    end = json_str.rfind("]") + 1
                else:
                    # Object format
                    start = obj_start
                    end = json_str.rfind("}") + 1
                if start != -1 and end > start:
                    json_str = json_str[start:end]

            result = json.loads(json_str)
            # Handle both {"issues": [...]} and direct [...] array formats
            if isinstance(result, list):
                issues = result
                confidence = 0.85  # Default when LLM returns array directly
            else:
                issues = result.get("issues", [])
                confidence = result.get("confidence", 0.85)

            # Apply fixes to original content
            corrected_content = phase1_content
            for issue in issues:
                find_text = issue.get("find")
                replace_text = issue.get("replace", "")
                if find_text and find_text in corrected_content:
                    corrected_content = corrected_content.replace(find_text, replace_text)

            return ValidationResult(
                issues=issues,
                corrected_content=corrected_content,
                confidence=confidence,
                needs_human_review=False,
                validation_stats={
                    "claim_validation": True,
                    "claims_checked": len(claims),
                    "issues_found": len(issues)
                },
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens
            )

        except json.JSONDecodeError:
            return ValidationResult(
                issues=[],
                corrected_content=phase1_content,
                confidence=0.7,
                needs_human_review=False,
                validation_stats={"claim_validation": True, "parse_error": True},
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens
            )

    def _run_formatting_phase(
        self,
        validated_content: str,
        section_id: str = "",
        model: str = "llama3.1:70b",
        temperature: float = 0.15
    ) -> Dict[str, Any]:
        """
        Phase 3: Format content for executive presentation.

        Returns dict with formatted content and token usage:
        {
            "content": str,
            "prompt_tokens": int,
            "completion_tokens": int,
            "total_tokens": int
        }
        """
        # Get section-specific formatting prompt
        formatting_prompt_template = get_formatting_prompt(section_id)
        prompt = formatting_prompt_template.format(
            validated_content=validated_content
        )

        result_data = self.client.generate(
            prompt=prompt,
            model=model,
            system="You are a professional editor. Return only the formatted content.",
            temperature=temperature,
            include_usage=True
        )

        # Extract response and token counts
        if isinstance(result_data, dict):
            response = result_data.get("response", "")
            prompt_tokens = result_data.get("prompt_tokens", 0)
            completion_tokens = result_data.get("completion_tokens", 0)
            total_tokens = result_data.get("total_tokens", 0)
        else:
            response = result_data
            prompt_tokens = completion_tokens = total_tokens = 0

        return {
            "content": response if response else validated_content,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        }

    def _build_retry_feedback(self, issues: List[Dict]) -> str:
        """Build feedback string from validation issues for retry."""
        lines = ["The previous output had the following issues that must be corrected:"]
        for i, issue in enumerate(issues[:5], 1):  # Limit to top 5 issues
            issue_type = issue.get("type", "issue")
            description = issue.get("description", "")
            lines.append(f"{i}. [{issue_type.upper()}]: {description}")
            if issue.get("evidence_reference"):
                lines.append(f"   Evidence shows: {issue['evidence_reference']}")

        lines.append("\nPlease regenerate the analysis correcting these issues. Do not include any invented facts.")
        return "\n".join(lines)

    def _save_debug_output(self, section_id: str, phase: str, content: Any, attempt: int = 0):
        """Save debug output to data/ai_analysis/ folder."""
        os.makedirs(self.debug_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        attempt_suffix = f"_attempt{attempt}" if attempt > 0 else ""
        filename = f"{section_id}_{phase}{attempt_suffix}_{timestamp}"

        if isinstance(content, ValidationResult):
            filepath = os.path.join(self.debug_dir, f"{filename}.json")
            with open(filepath, "w") as f:
                json.dump({
                    "issues": content.issues,
                    "corrected_content": content.corrected_content,
                    "confidence": content.confidence,
                    "needs_human_review": content.needs_human_review,
                    "validation_stats": content.validation_stats
                }, f, indent=2)
        else:
            filepath = os.path.join(self.debug_dir, f"{filename}.md")
            with open(filepath, "w") as f:
                f.write(content if isinstance(content, str) else str(content))


# Global pipeline progress storage (for polling)
_pipeline_progress: Dict[str, PipelineProgress] = {}


def get_pipeline_progress(job_id: str) -> Optional[PipelineProgress]:
    """Get the progress for a pipeline job."""
    return _pipeline_progress.get(job_id)


def set_pipeline_progress(progress: PipelineProgress):
    """Update the progress for a pipeline job."""
    _pipeline_progress[progress.job_id] = progress


def clear_pipeline_progress(job_id: str):
    """Clear the progress for a completed pipeline job."""
    if job_id in _pipeline_progress:
        del _pipeline_progress[job_id]
