"""
Prompt Manager for AAIA

Manages custom prompts with fallback to defaults. Allows users to view,
edit, and save custom prompts while preserving the ability to revert
to hardcoded defaults at any time.

Custom prompts are stored in data/prompts_custom.json.

Usage:
    manager = PromptManager()

    # Get a prompt (returns custom if set, otherwise default)
    prompt, is_custom = manager.get_prompt("spi", "sports")

    # Save a custom prompt
    manager.save_prompt("spi", "sports", "Custom prompt text...")

    # Revert to default
    manager.revert_prompt("spi", "sports")

    # List all prompts with their custom status
    all_prompts = manager.list_all_prompts()
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PromptManager:
    """
    Manages custom prompts with fallback to defaults.

    Categories:
        - main: Main section prompts (WEAK_HABITS_PROMPT, COMPANY_INTEL_PROMPT, etc.)
        - spi: Semantic Password Intelligence category prompts (11 categories)
        - ci: Company Intelligence category prompts (3 categories)
        - da: Description Analysis category prompts (3 categories)
        - validation: Validation prompts for each section
        - formatting: Formatting prompts for each section
        - preambles: System prompts and preambles
    """

    CUSTOM_PROMPTS_FILE = "data/prompts_custom.json"

    def __init__(self) -> None:
        """Initialize the PromptManager and load custom prompts."""
        self.custom_prompts = self._load_custom_prompts()
        self._default_prompts_cache: dict[str, dict[str, Any]] = {}

    def _get_custom_prompts_path(self) -> Path:
        """Get the path to the custom prompts file."""
        # Handle both running from project root and from app directory
        base_path = Path(self.CUSTOM_PROMPTS_FILE)
        if base_path.exists():
            return base_path

        # Try relative to app directory
        app_path = Path(__file__).parent.parent / self.CUSTOM_PROMPTS_FILE
        return app_path

    def _load_custom_prompts(self) -> dict[str, Any]:
        """Load custom prompts from JSON file."""
        path = self._get_custom_prompts_path()

        if not path.exists():
            return self._get_empty_custom_prompts()

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("prompts", {})
        except (json.JSONDecodeError, OSError):
            return self._get_empty_custom_prompts()

    def _get_empty_custom_prompts(self) -> dict[str, dict[str, str | None]]:
        """Return the empty custom prompts structure."""
        return {
            "main": {},
            "spi": {},
            "ci": {},
            "da": {},
            "validation": {},
            "formatting": {},
            "preambles": {}
        }

    def _save_custom_prompts(self) -> None:
        """Save custom prompts to JSON file."""
        path = self._get_custom_prompts_path()

        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "prompts": self.custom_prompts
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _get_default_prompts_registry(self) -> dict[str, dict[str, Any]]:
        """
        Build and cache the registry of all default prompts.

        Returns a dict mapping category -> name -> prompt_info dict
        where prompt_info contains: template, name, description, variables
        """
        if self._default_prompts_cache:
            return self._default_prompts_cache

        registry: dict[str, dict[str, Any]] = {
            "main": {},
            "spi": {},
            "ci": {},
            "da": {},
            "validation": {},
            "formatting": {},
            "preambles": {}
        }

        # Import prompt modules
        from app import ollama_prompts, spi_prompts, company_intel_prompts, description_llm_prompts

        # Main prompts - only SYSTEM_PROMPT is still used
        # The old main prompts (WEAK_HABITS_PROMPT, etc.) have been removed
        # Active AAIA pipelines use their own prompt modules (spi_prompts, company_intel_prompts, description_llm_prompts)

        # SPI prompts (preamble + categories)
        registry["preambles"]["SPI_PREAMBLE"] = {
            "template": spi_prompts.SPI_PREAMBLE,
            "name": "SPI Preamble",
            "description": "System context for Semantic Password Intelligence prompts",
            "variables": []
        }

        for key, category_data in spi_prompts.SPI_CATEGORIES.items():
            # Build a display template showing the structure
            template_parts = [
                f"**Name:** {category_data.get('name', key)}",
                f"\n**Description:** {category_data.get('description', '')}",
                f"\n**Include:** {category_data.get('include', '')}",
                f"\n**Exclude:** {category_data.get('exclude', '')}",
                f"\n**Examples (match):** {category_data.get('examples_match', '')}",
                f"\n**Examples (no match):** {category_data.get('examples_nomatch', '')}",
            ]
            if category_data.get('output_extra'):
                template_parts.append(f"\n**Output Extra:** {category_data.get('output_extra', '')}")

            registry["spi"][key] = {
                "template": "\n".join(template_parts),
                "name": category_data.get("name", key),
                "description": category_data.get("description", ""),
                "variables": ["{passwords}"],
                "raw_data": category_data  # Store original structure for editing
            }

        # CI prompts (preamble + categories)
        registry["preambles"]["CI_PREAMBLE"] = {
            "template": company_intel_prompts.CI_PREAMBLE,
            "name": "CI Preamble",
            "description": "System context for Company Intelligence prompts",
            "variables": []
        }

        for key, category_data in company_intel_prompts.CI_CATEGORIES.items():
            template_parts = [
                f"**Name:** {category_data.get('name', key)}",
                f"\n**Description:** {category_data.get('description', '')}",
                f"\n**Look For:** {category_data.get('look_for', '')}",
                f"\n**Examples:** {category_data.get('examples', '')}",
                f"\n**Output Format:** {category_data.get('output_format', '')}",
            ]

            registry["ci"][key] = {
                "template": "\n".join(template_parts),
                "name": category_data.get("name", key),
                "description": category_data.get("description", ""),
                "variables": ["{passwords}", "{accounts}"],
                "raw_data": category_data
            }

        # DA prompts (preamble + categories)
        registry["preambles"]["DA_PREAMBLE"] = {
            "template": description_llm_prompts.DA_PREAMBLE,
            "name": "DA Preamble",
            "description": "System context for Account Description Inspector prompts",
            "variables": []
        }

        for key, category_data in description_llm_prompts.DA_CATEGORIES.items():
            template_parts = [
                f"**Name:** {category_data.get('name', key)}",
                f"\n**Description:** {category_data.get('description', '')}",
                f"\n**Look For:** {category_data.get('look_for', '')}",
                f"\n**Include Rules:** {category_data.get('include_rules', '')}",
                f"\n**Exclude Rules:** {category_data.get('exclude_rules', '')}",
                f"\n**Examples:** {category_data.get('examples', '')}",
                f"\n**Output Format:** {category_data.get('output_format', '')}",
            ]

            registry["da"][key] = {
                "template": "\n".join(template_parts),
                "name": category_data.get("name", key),
                "description": category_data.get("description", ""),
                "variables": ["{accounts_data}"],
                "raw_data": category_data
            }

        # Validation and formatting prompts are no longer used
        # Active AAIA pipelines use Python-based validation and formatting

        # System prompt preamble
        registry["preambles"]["SYSTEM_PROMPT"] = {
            "template": ollama_prompts.SYSTEM_PROMPT,
            "name": "System Prompt",
            "description": "Sets AI persona and context for all requests",
            "variables": []
        }

        self._default_prompts_cache = registry
        return registry

    def _extract_variables(self, template: str) -> list[str]:
        """Extract {variable} placeholders from a template string."""
        # Match {word} but not {{word}} (escaped braces)
        pattern = r'(?<!\{)\{([a-zA-Z_][a-zA-Z0-9_]*)\}(?!\})'
        matches = re.findall(pattern, template)
        # Return unique variables in order of first appearance
        seen: set[str] = set()
        result: list[str] = []
        for match in matches:
            if match not in seen:
                seen.add(match)
                result.append(f"{{{match}}}")
        return result

    def get_prompt(self, category: str, name: str) -> tuple[str, bool]:
        """
        Get a prompt, returning custom if set, otherwise default.

        Args:
            category: Prompt category (main, spi, ci, da, validation, formatting, preambles)
            name: Prompt name within the category

        Returns:
            Tuple of (prompt_text, is_custom)

        Raises:
            ValueError: If category or name is not found
        """
        registry = self._get_default_prompts_registry()

        if category not in registry:
            raise ValueError(f"Unknown category: {category}. Valid: {list(registry.keys())}")

        if name not in registry[category]:
            raise ValueError(f"Unknown prompt: {name} in category {category}. "
                           f"Valid: {list(registry[category].keys())}")

        # Check for custom prompt
        custom = self.custom_prompts.get(category, {}).get(name)
        if custom is not None:
            return custom, True

        # Return default
        return registry[category][name]["template"], False

    def get_default_prompt(self, category: str, name: str) -> str:
        """
        Always returns the hardcoded default prompt.

        Args:
            category: Prompt category
            name: Prompt name within the category

        Returns:
            The default prompt text

        Raises:
            ValueError: If category or name is not found
        """
        registry = self._get_default_prompts_registry()

        if category not in registry:
            raise ValueError(f"Unknown category: {category}")

        if name not in registry[category]:
            raise ValueError(f"Unknown prompt: {name} in category {category}")

        return registry[category][name]["template"]

    def get_prompt_info(self, category: str, name: str) -> dict[str, Any]:
        """
        Get full information about a prompt.

        Returns:
            Dict with: template, name, description, variables, is_custom, custom_content
        """
        registry = self._get_default_prompts_registry()

        if category not in registry:
            raise ValueError(f"Unknown category: {category}")

        if name not in registry[category]:
            raise ValueError(f"Unknown prompt: {name} in category {category}")

        info = registry[category][name].copy()

        # Add custom status
        custom = self.custom_prompts.get(category, {}).get(name)
        info["is_custom"] = custom is not None
        info["custom_content"] = custom
        info["current_content"] = custom if custom is not None else info["template"]

        return info

    def save_prompt(self, category: str, name: str, content: str) -> None:
        """
        Save a custom prompt.

        Args:
            category: Prompt category
            name: Prompt name within the category
            content: The custom prompt content

        Raises:
            ValueError: If category or name is not valid
        """
        registry = self._get_default_prompts_registry()

        if category not in registry:
            raise ValueError(f"Unknown category: {category}")

        if name not in registry[category]:
            raise ValueError(f"Unknown prompt: {name} in category {category}")

        # Ensure category exists in custom prompts
        if category not in self.custom_prompts:
            self.custom_prompts[category] = {}

        # Save the custom prompt
        self.custom_prompts[category][name] = content
        self._save_custom_prompts()

    def revert_prompt(self, category: str, name: str) -> None:
        """
        Remove custom override, reverting to default.

        Args:
            category: Prompt category
            name: Prompt name within the category
        """
        if category in self.custom_prompts and name in self.custom_prompts[category]:
            del self.custom_prompts[category][name]
            self._save_custom_prompts()

    def list_all_prompts(self) -> dict[str, list[dict[str, Any]]]:
        """
        Returns all prompt categories with names and custom status.

        Returns:
            Dict mapping category -> list of prompt info dicts
            Each prompt info has: key, name, description, is_custom
        """
        registry = self._get_default_prompts_registry()
        result: dict[str, list[dict[str, Any]]] = {}

        for category, prompts in registry.items():
            result[category] = []
            for key, info in prompts.items():
                custom = self.custom_prompts.get(category, {}).get(key)
                result[category].append({
                    "key": key,
                    "name": info["name"],
                    "description": info["description"],
                    "is_custom": custom is not None,
                    "variable_count": len(info.get("variables", []))
                })

        return result

    def get_prompt_variables(self, category: str, name: str) -> list[str]:
        """
        Extract {variable} placeholders from a prompt.

        Args:
            category: Prompt category
            name: Prompt name within the category

        Returns:
            List of variable names (e.g., ["{passwords}", "{accounts}"])
        """
        registry = self._get_default_prompts_registry()

        if category not in registry or name not in registry[category]:
            return []

        return registry[category][name].get("variables", [])

    def validate_prompt(self, content: str, expected_vars: list[str]) -> dict[str, Any]:
        """
        Check if a prompt uses expected variables.

        Args:
            content: The prompt content to validate
            expected_vars: List of expected variable placeholders

        Returns:
            Dict with: valid (bool), missing_vars, extra_vars, warnings
        """
        actual_vars = self._extract_variables(content)

        # Compare sets (strip braces for comparison)
        expected_set = set(v.strip("{}") for v in expected_vars)
        actual_set = set(v.strip("{}") for v in actual_vars)

        missing = expected_set - actual_set
        extra = actual_set - expected_set

        warnings: list[str] = []
        if missing:
            warnings.append(f"Missing expected variables: {', '.join(missing)}")
        if extra:
            warnings.append(f"Additional variables used: {', '.join(extra)}")

        return {
            "valid": len(missing) == 0,
            "missing_vars": list(missing),
            "extra_vars": list(extra),
            "warnings": warnings
        }

    def get_custom_prompts_count(self) -> dict[str, int]:
        """Get count of custom prompts per category."""
        counts: dict[str, int] = {}
        for category, prompts in self.custom_prompts.items():
            counts[category] = sum(1 for v in prompts.values() if v is not None)
        return counts

    def export_custom_prompts(self) -> str:
        """Export custom prompts as JSON string."""
        data = {
            "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "prompts": self.custom_prompts
        }
        return json.dumps(data, indent=2)

    def import_custom_prompts(self, json_str: str, merge: bool = True) -> dict[str, Any]:
        """
        Import custom prompts from JSON string.

        Args:
            json_str: JSON string with prompts to import
            merge: If True, merge with existing. If False, replace all.

        Returns:
            Dict with: success (bool), imported_count, errors
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            return {"success": False, "imported_count": 0, "errors": [str(e)]}

        prompts = data.get("prompts", {})
        registry = self._get_default_prompts_registry()

        imported = 0
        errors: list[str] = []

        for category, category_prompts in prompts.items():
            if category not in registry:
                errors.append(f"Unknown category: {category}")
                continue

            if not merge:
                self.custom_prompts[category] = {}
            elif category not in self.custom_prompts:
                self.custom_prompts[category] = {}

            for name, content in category_prompts.items():
                if name not in registry[category]:
                    errors.append(f"Unknown prompt: {category}/{name}")
                    continue

                if content is not None:
                    self.custom_prompts[category][name] = content
                    imported += 1

        self._save_custom_prompts()

        return {
            "success": len(errors) == 0,
            "imported_count": imported,
            "errors": errors
        }


# Convenience function for getting the singleton manager
_manager_instance: PromptManager | None = None

def get_prompt_manager() -> PromptManager:
    """Get the singleton PromptManager instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = PromptManager()
    return _manager_instance
